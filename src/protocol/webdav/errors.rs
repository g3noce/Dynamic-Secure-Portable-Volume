use std::fmt;

#[derive(Debug)]
pub enum WebDavError {
    LockFailed(&'static str),
    WriteChunkFailed,
    ReadChunkFailed,
    FlushFailed,
    CacheOpenFailed,
    MetadataFailed,
    ReadDirFailed,
    CreateDirFailed,
    RemoveFileFailed,
    RemoveDirFailed,
    RenameFailed,
    CopySrcOpenFailed,
    CopyDstOpenFailed,
    CopyReadWriteFailed,
    QuotaFailed,
}

impl fmt::Display for WebDavError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            WebDavError::LockFailed(f_name) => (*f_name, "unable to lock the shared file"),
            WebDavError::WriteChunkFailed => ("write_bytes", "failed to write encrypted chunk"),
            WebDavError::ReadChunkFailed => ("read_bytes", "failed to read encrypted chunk"),
            WebDavError::FlushFailed => ("flush", "failed to flush to disk"),
            WebDavError::CacheOpenFailed => ("open", "failed to open or create via cache"),
            WebDavError::MetadataFailed => ("metadata", "failed to retrieve OS metadata"),
            WebDavError::ReadDirFailed => ("read_dir", "failed to read directory contents"),
            WebDavError::CreateDirFailed => ("create_dir", "failed to create directory"),
            WebDavError::RemoveFileFailed => ("remove_file", "failed to remove physical file"),
            WebDavError::RemoveDirFailed => ("remove_dir", "failed to remove physical directory"),
            WebDavError::RenameFailed => ("rename", "failed to rename on disk"),
            WebDavError::CopySrcOpenFailed => ("copy", "unable to open source file"),
            WebDavError::CopyDstOpenFailed => ("copy", "unable to create target file"),
            WebDavError::CopyReadWriteFailed => ("copy", "failed during chunk read/write"),
            WebDavError::QuotaFailed => ("get_quota", "failed to calculate available disk space"),
        };
        write!(f, "mod: webdav, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for WebDavError {}
