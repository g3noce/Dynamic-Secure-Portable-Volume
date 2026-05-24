use std::fmt;

#[derive(Debug)]
pub enum VaultError {
    KdfFailedCreate,
    EncryptVerifyFailed,
    InvalidMagic,
    KdfFailedUnlock,
    DecryptVerifyFailed,
    WrongPassword,
    MetaTampered,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            VaultError::KdfFailedCreate => ("create_new", "KDF failed"),
            VaultError::EncryptVerifyFailed => {
                ("create_new", "failed to encrypt verification block")
            }
            VaultError::InvalidMagic => ("unlock_existing", "corrupt or invalid meta file"),
            VaultError::KdfFailedUnlock => ("unlock_existing", "KDF failed"),
            VaultError::DecryptVerifyFailed => {
                ("unlock_existing", "failed to decrypt verification block")
            }
            VaultError::WrongPassword => ("unlock_existing", "incorrect password"),
            VaultError::MetaTampered => (
                "unlock_existing",
                "vault metadata has been tampered with (HMAC mismatch)",
            ),
        };
        write!(f, "mod: vault, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for VaultError {}
