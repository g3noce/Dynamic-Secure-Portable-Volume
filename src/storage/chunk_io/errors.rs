use std::fmt;

#[derive(Debug)]
pub enum ChunkIoError {
    InitReadOnly,
    XtsDecryptionFailed,
    RmwDecryptionFailed,
    RmwEncryptionFailed,
    MacVerificationFailed,
    MacKeyMissing,
}

impl fmt::Display for ChunkIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            ChunkIoError::InitReadOnly => ("open", "cannot initialize a header in read-only mode"),
            ChunkIoError::XtsDecryptionFailed => ("read_chunk", "XTS decryption failed"),
            ChunkIoError::RmwDecryptionFailed => ("write_chunk", "RMW decryption failed"),
            ChunkIoError::RmwEncryptionFailed => ("write_chunk", "RMW encryption failed"),
            ChunkIoError::MacVerificationFailed => (
                "open",
                "file integrity check failed: the encrypted data has been tampered with or the wrong key was used",
            ),
            ChunkIoError::MacKeyMissing => (
                "open",
                "internal error: MAC key must be supplied (length < 32 bytes)",
            ),
        };
        write!(f, "mod: chunk_io, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for ChunkIoError {}
