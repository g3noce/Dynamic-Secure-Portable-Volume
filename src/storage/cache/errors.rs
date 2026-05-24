use std::fmt;

#[derive(Debug)]
pub enum CacheError {
    FileOpenFailed,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            CacheError::FileOpenFailed => {
                ("get_or_open", "failed to open or create encrypted file")
            }
        };
        write!(f, "mod: cache, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for CacheError {}
