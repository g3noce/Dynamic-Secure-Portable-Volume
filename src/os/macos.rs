use std::process::{Command, Stdio};

pub fn open_connection(port: u16) -> Result<(), String> {
    println!("\n[i] To access the volume on macOS, open a new terminal and type:");
    println!("    open webdav://127.0.0.1:{}/", port);
    Ok(())
}

pub fn close_connection(_port: u16) -> Result<(), String> {
    // Silent automatic cleanup on shutdown
    let _ = Command::new("diskutil")
        .args(["unmount", "force", "/Volumes/127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}
