use std::process::{Command, Stdio};

pub fn open_connection(port: u16) -> Result<(), String> {
    println!("\n[i] Pour accéder au volume, ouvrez un nouveau terminal et tapez :");
    println!("    gio mount dav://127.0.0.1:{}/", port);
    println!("    xdg-open dav://127.0.0.1:{}/", port);
    Ok(())
}

pub fn close_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);
    // Le démontage automatique à la fermeture fonctionne bien et nettoie le système
    let _ = Command::new("gio")
        .args(["mount", "-u", &dav_url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}
