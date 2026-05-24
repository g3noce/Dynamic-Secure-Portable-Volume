use std::fs;
use std::io::{self, Read, Seek};
use std::path::Path;
use std::time::SystemTime;

use dav_server::fs::{DavDirEntry, DavMetaData, FsResult};
use futures_util::future::BoxFuture;

use crate::storage::cache::FileCache;
use crate::storage::header::{HEADER_SIZE, LOGICAL_SIZE_OFFSET};

#[derive(Debug, Clone)]
pub struct WebDavMetaData {
    pub(super) logical_size: u64,
    pub(super) is_dir: bool,
    pub(super) modified: SystemTime,
}

impl WebDavMetaData {
    /// Resolve metadata for `phys_path`. For files, looks at the in-memory cache first,
    /// then falls back to reading the physical header bytes from disk.
    pub fn resolve(phys_path: &Path, metadata: fs::Metadata, cache: &FileCache) -> Self {
        let is_dir = metadata.is_dir();
        let mut logical_size = 0;

        if !is_dir {
            if let Some(cached_file) = cache.get_cached(phys_path) {
                if let Ok(guard) = cached_file.lock() {
                    logical_size = guard.logical_size().unwrap_or(0);
                }
            } else if metadata.len() >= HEADER_SIZE
                && let Ok(mut f) = fs::File::open(phys_path)
                && f.seek(io::SeekFrom::Start(LOGICAL_SIZE_OFFSET)).is_ok()
            {
                let mut buf = [0u8; 8];
                if f.read_exact(&mut buf).is_ok() {
                    logical_size = u64::from_le_bytes(buf);
                }
            }
        }

        Self {
            logical_size,
            is_dir,
            modified: metadata.modified().unwrap_or_else(|_| SystemTime::now()),
        }
    }
}

impl DavMetaData for WebDavMetaData {
    fn len(&self) -> u64 {
        self.logical_size
    }
    fn modified(&self) -> FsResult<SystemTime> {
        Ok(self.modified)
    }
    fn is_dir(&self) -> bool {
        self.is_dir
    }
    fn created(&self) -> FsResult<SystemTime> {
        Ok(self.modified)
    }
}

pub struct WebDavDirEntry {
    pub(super) name: String,
    pub(super) metadata: WebDavMetaData,
}

impl DavDirEntry for WebDavDirEntry {
    fn name(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }
    fn metadata(&self) -> BoxFuture<'_, FsResult<Box<dyn DavMetaData>>> {
        let meta = self.metadata.clone();
        Box::pin(async move { Ok(Box::new(meta) as Box<dyn DavMetaData>) })
    }
}
