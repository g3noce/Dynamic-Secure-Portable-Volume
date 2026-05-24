mod crypto;
mod os;
mod protocol;
mod storage;
mod ui;
mod utils;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use dav_server::DavHandler;
use dav_server::body::Body as DavBody;
use dav_server::memls::MemLs;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::signal;

use zeroize::Zeroize;

use crate::protocol::auth::BasicAuth;
use crate::protocol::webdav::WebDavFS;
use crate::storage::cache::FileCache;

const AUTH_REALM: &str = r#"Basic realm="DSPV""#;
/// Cap per-request body size at 4 GiB. Anything larger from a local client is
/// treated as adversarial. Chunked requests without `Content-Length` are still
/// admitted (the WebDAV layer streams them) but cannot exceed what the disk
/// holds; future hardening could enforce this at the chunk level too.
const MAX_REQUEST_BODY_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn unauthorized_response() -> Response<DavBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", AUTH_REALM)
        .body(DavBody::empty())
        .expect("static 401 response must build")
}

fn payload_too_large_response() -> Response<DavBody> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(DavBody::empty())
        .expect("static 413 response must build")
}

/// Return `Some(len)` only when the client supplied a parseable `Content-Length`
/// header. Missing or malformed headers fall back to streaming (already bounded
/// by WebDAV-layer chunked reads).
fn declared_body_size(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get(hyper::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
}

#[derive(Parser)]
#[command(name = "dspv")]
#[command(about = "Dynamic Secure Portable Volume - WebDAV server with on-the-fly encryption")]
struct Cli {
    /// Physical folder where encrypted files are stored
    #[arg(default_value = "./secure_volume")]
    path: String,

    /// Port for the WebDAV server
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("====================================================");
    println!("  Dynamic Secure Portable Volume (WebDAV Server)    ");
    println!("====================================================\n");

    let cli = Cli::parse();
    let physical_root = cli.path;
    let port = cli.port;

    if !std::path::Path::new(&physical_root).exists() {
        std::fs::create_dir_all(&physical_root)?;
        println!("[+] Physical folder created: {}", physical_root);
    }

    let mut password = rpassword::prompt_password("Volume encryption key: ")?;
    if password.trim().is_empty() {
        eprintln!(
            "[!] WARNING: empty password — your vault is effectively unprotected. \
             Anyone with read access to the meta file can derive the same master key."
        );
    }
    // The trimmed view borrows from `password`; we keep ownership so we can
    // zeroize the original allocation after the KDF has consumed it.
    let unlock_result = crate::storage::vault::VaultManager::unlock_or_create(
        &physical_root,
        password.trim(),
    );
    password.zeroize();

    println!("[*] Unlocking volume...");

    let master_key = match unlock_result {
        Ok(key) => key,
        Err(e) => {
            eprintln!("\n[!] ERROR: {}", e);
            std::process::exit(1);
        }
    };

    let file_cache = Arc::new(FileCache::new());
    let dav_fs = WebDavFS::new(&physical_root, master_key, file_cache.clone());

    let dav_server = DavHandler::builder()
        .filesystem(Box::new(dav_fs))
        .locksystem(MemLs::new())
        .build_handler();

    let basic_auth = Arc::new(BasicAuth::generate());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;

    println!("\n[+] Server online at http://127.0.0.1:{}/", port);
    println!("[+] WebDAV credentials (provide to your file manager):");
    println!("    user:     {}", basic_auth.username());
    println!("    password: {}", basic_auth.password());
    println!("[*] Press CTRL+C to exit cleanly.");

    if let Err(e) = crate::os::open_connection(port) {
        eprintln!("[!] Note: {}", e);
    }

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let io = TokioIo::new(stream);
                        let dav_server_clone = dav_server.clone();

                        let auth_clone = basic_auth.clone();
                        tokio::task::spawn(async move {
                            let service = service_fn(move |req| {
                                let dav_server_clone = dav_server_clone.clone();
                                let auth_clone = auth_clone.clone();
                                async move {
                                    // Reject oversized payloads before auth so a
                                    // malicious client can't tie up the blocking
                                    // pool just to be rejected at the WebDAV
                                    // layer. Auth still gates everything else.
                                    if let Some(len) = declared_body_size(req.headers())
                                        && len > MAX_REQUEST_BODY_BYTES
                                    {
                                        return Ok::<_, Infallible>(payload_too_large_response());
                                    }
                                    let authorized = req
                                        .headers()
                                        .get(hyper::header::AUTHORIZATION)
                                        .map(|h| auth_clone.verify(h.as_bytes()))
                                        .unwrap_or(false);
                                    if authorized {
                                        Ok::<_, Infallible>(dav_server_clone.handle(req).await)
                                    } else {
                                        Ok::<_, Infallible>(unauthorized_response())
                                    }
                                }
                            });

                            // Slowloris defense: drop connections that haven't
                            // completed their request line + headers within 30s.
                            // `header_read_timeout` panics unless a Timer is
                            // installed on the builder — hyper 1.x is runtime
                            // agnostic, so we wire the tokio one explicitly.
                            let conn = http1::Builder::new()
                                .timer(TokioTimer::new())
                                .header_read_timeout(Duration::from_secs(30))
                                .serve_connection(io, service);
                            if let Err(err) = conn.await {
                                eprintln!("[!] Connection error: {:?}", err);
                            }
                        });
                    }
                    Err(e) => eprintln!("[!] Acceptance error: {}", e),
                }
            }
            _ = signal::ctrl_c() => {
                println!("\n[!] Shutdown requested.");

                println!("[*] Closing network connection...");
                let _ = crate::os::close_connection(port);

                println!("[*] Finalizing file synchronization...");
                file_cache.flush_all();

                break;
            }
        }
    }

    println!("[+] Volume disconnected and RAM purged.");
    Ok(())
}
