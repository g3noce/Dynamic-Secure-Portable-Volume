use std::process::Command;

pub fn open_connection(port: u16) -> Result<(), String> {
    let unc_path = format!(r"\\127.0.0.1@{}\DavWWWRoot", port);
    Command::new("explorer")
        .arg(&unc_path)
        .spawn()
        .map_err(|e| format!("Explorer Error: {}", e))?;
    Ok(())
}

pub fn close_connection(port: u16) -> Result<(), String> {
    let unc_path = format!(r"\\127.0.0.1@{}\DavWWWRoot", port);
    let output = Command::new("net")
        .args(["use", &unc_path, "/delete", "/y"])
        .output()
        .map_err(|e| format!("Net Use Error: {}", e))?;

    if output.status.success() || String::from_utf8_lossy(&output.stderr).contains("2250") {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}
