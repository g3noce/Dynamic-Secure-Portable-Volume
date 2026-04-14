use std::process::Command;

pub fn open_connection(port: u16) -> Result<(), String> {
    // On utilise webdav:// pour forcer l'ouverture via le Finder et non Safari
    let url = format!("webdav://127.0.0.1:{}/", port);

    Command::new("open")
        .arg(&url)
        .spawn()
        .map_err(|e| format!("Erreur Open macOS : {}", e))?;

    Ok(())
}

pub fn close_connection(_port: u16) -> Result<(), String> {
    // Le Finder montera le volume sous l'IP par défaut.
    // On garde le démontage forcé pour fermer la connexion.
    let _ = Command::new("diskutil")
        .args(["unmount", "force", "/Volumes/127.0.0.1"])
        .output();
    Ok(())
}
