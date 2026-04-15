use std::process::{Command, Stdio};

pub fn open_connection(port: u16) -> Result<(), String> {
    println!("\n[i] Pour accéder au volume sous macOS, ouvrez un nouveau terminal et tapez :");
    println!("    open webdav://127.0.0.1:{}/", port);
    Ok(())
}

pub fn close_connection(_port: u16) -> Result<(), String> {
    // Nettoyage automatique silencieux à l'arrêt
    let _ = Command::new("diskutil")
        .args(["unmount", "force", "/Volumes/127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}
