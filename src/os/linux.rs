use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

pub fn open_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);
    let mut is_ready = false;

    for _ in 0..5 {
        let mount_status = Command::new("gio")
            .args(["mount", &dav_url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if let Ok(status) = mount_status {
            if status.success() {
                is_ready = true;
                break;
            }
        }

        let info_status = Command::new("gio")
            .args(["info", &dav_url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if let Ok(status) = info_status {
            if status.success() {
                is_ready = true;
                break;
            }
        }

        thread::sleep(Duration::from_millis(500));
    }

    if !is_ready {
        return Err(
            "Le système n'a pas pu monter le volume réseau après plusieurs tentatives.".to_string(),
        );
    }

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
