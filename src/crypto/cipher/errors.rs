use std::fmt;

#[derive(Debug)]
pub enum CipherError {
    InitializationFailed,
    AlignmentError,
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cause = match self {
            CipherError::InitializationFailed => "invalid key size (must be 64) or IV (must be 16)",
            CipherError::AlignmentError => "data is not a multiple of 16 bytes",
        };
        write!(
            f,
            "mod: cipher, function: chunk_processing, cause: {}",
            cause
        )
    }
}

impl std::error::Error for CipherError {}
