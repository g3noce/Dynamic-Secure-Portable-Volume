mod crypto;
mod os;
mod protocol;
mod storage;
mod ui;
mod utils;

use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;

use dav_server::DavHandler;
use dav_server::memls::MemLs;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::protocol::webdav::WebDavFS;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("====================================================");
    println!("  Dynamic Secure Portable Volume (WebDAV Server)    ");
    println!("====================================================\n");

    // 1. Définir le chemin du dossier physique à protéger
    // Pour l'instant, on prend le dossier courant ou un dossier passé en argument
    let args: Vec<String> = env::args().collect();
    let physical_root = if args.len() > 1 {
        args[1].clone()
    } else {
        "./secure_volume".to_string()
    };

    // Création du dossier s'il n'existe pas encore
    if !std::path::Path::new(&physical_root).exists() {
        std::fs::create_dir_all(&physical_root)?;
        println!("[+] Dossier physique créé : {}", physical_root);
    } else {
        println!("[*] Dossier physique cible : {}", physical_root);
    }

    // 2. Saisie du mot de passe (En texte clair pour le dev, à remplacer par rpassword plus tard)
    let password =
        rpassword::prompt_password("Veuillez entrer la clé de chiffrement du volume : ")?;
    let password = password.trim();

    println!("[*] Dérivation de la clé cryptographique en cours (Argon2)...");

    let master_key =
        match crate::storage::vault::VaultManager::unlock_or_create(&physical_root, password) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("\n[!] ACCÈS REFUSÉ : {}", e);
                eprintln!("[!] Le serveur ne démarrera pas pour protéger vos données.");
                std::process::exit(1); // Quitte proprement avec un code d'erreur
            }
        };

    println!("[+] Clé générée et sécurisée en RAM.");

    // 3. Initialisation du Virtual File System WebDAV
    let dav_fs = WebDavFS::new(&physical_root, master_key);

    // 4. Construction du DavHandler avec le Lock System
    let dav_server = DavHandler::builder()
        .filesystem(Box::new(dav_fs))
        .locksystem(MemLs::new())
        .build_handler();

    // 5. Configuration et Démarrage du serveur Hyper 1.0
    // On écoute uniquement sur localhost (127.0.0.1) pour des raisons de sécurité ("Zéro-Admin")
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await?;

    println!("\n====================================================");
    println!("[SUCCESS] Le serveur WebDAV est en ligne !");
    println!("          Connectez-vous via votre OS sur :");
    println!("          http://127.0.0.1:8080/");
    println!("          (Appuyez sur CTRL+C pour quitter et effacer la RAM)");
    println!("====================================================\n");

    // Boucle asynchrone pour accepter les connexions WebDAV entrantes
    loop {
        let (stream, _client_addr) = listener.accept().await?;

        // Encapsulation compatible avec Hyper 1.0
        let io = TokioIo::new(stream);
        let dav_server_clone = dav_server.clone();

        // On lance chaque connexion dans un thread léger (Task) Tokio
        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let dav_server_clone = dav_server_clone.clone();
                async move {
                    // On délègue totalement le traitement de la requête à dav-server
                    Ok::<_, Infallible>(dav_server_clone.handle(req).await)
                }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("[!] Erreur lors du traitement de la connexion : {:?}", err);
            }
        });
    }
}
