use std::process::{Command, Stdio};

pub fn open_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);

    let _ = Command::new("gio")
        .args(["mount", &dav_url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("Erreur d'exécution de gio mount : {}", e))?;

    Command::new("xdg-open")
        .arg(&dav_url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Erreur xdg-open : {}", e))?;

    Ok(())
}

pub fn close_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);

    let _ = Command::new("gio")
        .args(["mount", "-u", &dav_url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    Ok(())
}
