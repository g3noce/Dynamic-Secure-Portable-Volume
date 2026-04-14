use std::process::Command;

pub fn open_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);

    let _ = Command::new("gio")
        .args(["mount", &dav_url])
        .output()
        .map_err(|e| format!("Erreur d'exécution de gio mount : {}", e))?;

    Command::new("xdg-open")
        .arg(&dav_url)
        .spawn()
        .map_err(|e| format!("Erreur xdg-open : {}", e))?;

    Ok(())
}

pub fn close_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);

    // On démonte proprement le volume à la fermeture
    let _ = Command::new("gio").args(["mount", "-u", &dav_url]).output();

    Ok(())
}
