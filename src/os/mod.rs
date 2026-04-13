pub mod linux;
pub mod macos;
pub mod windows;

/// Ouvre l'explorateur de fichiers sur l'adresse du serveur
pub fn open_connection(port: u16) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    return windows::open_connection(port);

    #[cfg(target_os = "macos")]
    return macos::open_connection(port);

    #[cfg(target_os = "linux")]
    return linux::open_connection(port);

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    Err("Système d'exploitation non supporté.".to_string())
}

/// Ferme ou purge la connexion réseau
pub fn close_connection(port: u16) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    return windows::close_connection(port);

    #[cfg(target_os = "macos")]
    return macos::close_connection(port);

    #[cfg(target_os = "linux")]
    return linux::close_connection(port);

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    Ok(())
}
