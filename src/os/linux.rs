use std::process::{Command, Stdio};

pub fn open_connection(port: u16) -> Result<(), String> {
    println!("\n[i] To access the volume, open a new terminal and type:");
    println!("    gio mount dav://127.0.0.1:{}/", port);
    println!("    xdg-open dav://127.0.0.1:{}/", port);
    Ok(())
}

pub fn close_connection(port: u16) -> Result<(), String> {
    let dav_url = format!("dav://127.0.0.1:{}/", port);
    // Automatic unmounting on closure works well and cleans the system
    let _ = Command::new("gio")
        .args(["mount", "-u", &dav_url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}
