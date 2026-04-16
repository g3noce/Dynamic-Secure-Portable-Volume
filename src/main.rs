mod crypto;
mod os;
mod protocol;
mod storage;
mod ui;
mod utils;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use dav_server::DavHandler;
use dav_server::memls::MemLs;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::signal;

use crate::crypto::cipher::AuthenticatedChunkCipher;
use crate::protocol::webdav::WebDavFS;
use crate::storage::cache::FileCache;

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

    let password = rpassword::prompt_password("Volume encryption key: ")?;
    let password = password.trim();

    println!("[*] Unlocking volume...");

    let master_key =
        match crate::storage::vault::VaultManager::unlock_or_create(&physical_root, password) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("\n[!] ERROR: {}", e);
                std::process::exit(1);
            }
        };

    let file_cache = Arc::new(FileCache::new(200));

    let cipher = crate::crypto::cipher::ChaChaPolyCipher::new(master_key.clone());
    let index_manager = match crate::storage::index::IndexManager::load_or_create(
        std::path::Path::new(&physical_root),
        &cipher,
    ) {
        Ok(idx) => Arc::new(std::sync::Mutex::new(idx)),
        Err(e) => {
            eprintln!("\n[!] Index ERROR: {}", e);
            std::process::exit(1);
        }
    };

    let dav_fs = WebDavFS::new(
        &physical_root,
        master_key,
        file_cache.clone(),
        index_manager.clone(),
    );

    let dav_server = DavHandler::builder()
        .filesystem(Box::new(dav_fs))
        .locksystem(MemLs::new())
        .build_handler();

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;

    println!("\n[+] Server online at http://127.0.0.1:{}/", port);
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

                        tokio::task::spawn(async move {
                            let service = service_fn(move |req| {
                                let dav_server_clone = dav_server_clone.clone();
                                async move { Ok::<_, Infallible>(dav_server_clone.handle(req).await) }
                            });

                            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
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

                println!("[*] Saving file index...");
                if let Ok(guard) = index_manager.lock()
                    && let Err(e) = guard.save(&cipher)
                {
                    eprintln!("[!] Failed to save index: {}", e);
                }

                break;
            }
        }
    }

    println!("[+] Volume disconnected and RAM purged.");
    Ok(())
}
