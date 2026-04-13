use std::process::Command;

pub fn open_connection(port: u16) -> Result<(), String> {
    let url = format!("http://127.0.0.1:{}/", port);
    // 'open' sur une URL WebDAV monte le volume dans /Volumes/ et l'ouvre
    Command::new("open")
        .arg(&url)
        .spawn()
        .map_err(|e| format!("Erreur Open macOS : {}", e))?;
    Ok(())
}

pub fn close_connection(_port: u16) -> Result<(), String> {
    // macOS monte par défaut avec le nom de l'IP
    let _ = Command::new("diskutil")
        .args(["unmount", "force", "/Volumes/127.0.0.1"])
        .output();
    Ok(())
}
