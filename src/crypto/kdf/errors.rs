use std::fmt;

#[derive(Debug)]
pub enum KdfError {
    DerivationFailed,
    InvalidParameters,
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cause = match self {
            KdfError::DerivationFailed => "Argon2 internal hashing failed",
            KdfError::InvalidParameters => "Argon2 configuration parameters rejected",
        };
        write!(f, "mod: kdf, function: derive_key, cause: {}", cause)
    }
}

impl std::error::Error for KdfError {}
