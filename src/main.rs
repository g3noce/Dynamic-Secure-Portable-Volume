mod crypto;
mod os;
mod protocol;
mod storage;
mod ui;
mod utils;

use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use dav_server::DavHandler;
use dav_server::memls::MemLs;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::signal;

use crate::protocol::webdav::WebDavFS;
use crate::storage::cache::FileCache;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("====================================================");
    println!("  Dynamic Secure Portable Volume (WebDAV Server)    ");
    println!("====================================================\n");

    let args: Vec<String> = env::args().collect();
    let physical_root = if args.len() > 1 {
        args[1].clone()
    } else {
        "./secure_volume".to_string()
    };

    if !std::path::Path::new(&physical_root).exists() {
        std::fs::create_dir_all(&physical_root)?;
        println!("[+] Dossier physique créé : {}", physical_root);
    }

    let password = rpassword::prompt_password("Clé de chiffrement du volume : ")?;
    let password = password.trim();

    println!("[*] Déverrouillage du volume...");

    let master_key =
        match crate::storage::vault::VaultManager::unlock_or_create(&physical_root, password) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("\n[!] ERREUR : {}", e);
                std::process::exit(1);
            }
        };

    let file_cache = Arc::new(FileCache::new());
    let dav_fs = WebDavFS::new(&physical_root, master_key, file_cache.clone());

    let dav_server = DavHandler::builder()
        .filesystem(Box::new(dav_fs))
        .locksystem(MemLs::new())
        .build_handler();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await?;

    println!("\n[+] Serveur en ligne sur http://127.0.0.1:8080/");
    println!("[*] Appuyez sur CTRL+C pour quitter proprement.");

    // Déclenchement de la connexion réseau (Asynchrone)
    tokio::task::spawn(async {
        // Pause d'une seconde pour s'assurer que le serveur est prêt
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        println!("[*] Ouverture de la connexion réseau...");

        if let Err(e) = crate::os::open_connection(8080) {
            eprintln!("[!] Note : {}", e);
        }
    });

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
                                eprintln!("[!] Erreur connexion : {:?}", err);
                            }
                        });
                    }
                    Err(e) => eprintln!("[!] Erreur acceptation : {}", e),
                }
            }
            _ = signal::ctrl_c() => {
                println!("\n[!] Arrêt demandé.");

                println!("[*] Fermeture de la connexion réseau...");
                let _ = crate::os::close_connection(8080);

                println!("[*] Synchronisation finale des fichiers en cours...");
                file_cache.flush_all();

                break;
            }
        }
    }

    println!("[+] Volume déconnecté et RAM purgée.");
    Ok(())
}
