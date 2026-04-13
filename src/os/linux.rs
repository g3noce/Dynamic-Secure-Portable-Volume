use std::process::Command;

pub fn open_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);

    // On tente le montage via gio (GVfs)
    let _ = Command::new("gio").args(["mount", &dav_url]).output();

    // On ouvre l'explorateur de fichiers par défaut (Nautilus, Dolphin, etc.)
    Command::new("xdg-open")
        .arg(&dav_url)
        .spawn()
        .map_err(|e| format!("Erreur xdg-open : {}", e))?;
    Ok(())
}

pub fn close_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);
    let _ = Command::new("gio").args(["mount", "-u", &dav_url]).output();
    Ok(())
}
