use std::process::Command;

pub fn open_connection(port: u16) -> Result<(), String> {
    // Le protocole dav:// indique au gestionnaire de fichiers de s'en occuper
    let dav_url = format!("dav://127.0.0.1:{}/", port);

    Command::new("xdg-open")
        .arg(&dav_url)
        .spawn()
        .map_err(|e| format!("Erreur xdg-open : {}", e))?;

    Ok(())
}

pub fn close_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);
    // Même si l'explorateur a fait le montage, gio peut le démonter proprement
    let _ = Command::new("gio").args(["mount", "-u", &dav_url]).output();
    Ok(())
}
