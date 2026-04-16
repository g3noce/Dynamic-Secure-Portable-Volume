use std::fmt;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsResult, OpenOptions, ReadDirMeta,
};
use futures_util::future::BoxFuture;
use futures_util::stream;

use crate::crypto::cipher::Aes256XtsCipher;
use crate::crypto::cipher::ChunkCipher;
use crate::storage::cache::FileCache;
use crate::storage::chunk_io::EncryptedFile;
use crate::storage::header::{HEADER_SIZE, LOGICAL_SIZE_OFFSET};
use crate::utils::memory::SecureKey;

// --- ADDITION: Structured enumeration for custom errors ---
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
// ----------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WebDavMetaData {
    logical_size: u64,
    is_dir: bool,
    modified: SystemTime,
}

impl WebDavMetaData {
    fn resolve(phys_path: &Path, metadata: fs::Metadata, cache: &FileCache) -> Self {
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
    name: String,
    metadata: WebDavMetaData,
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

pub struct WebDavFile {
    inner: Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>,
    pos: u64,
}

impl std::fmt::Debug for WebDavFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavFile")
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl DavFile for WebDavFile {
    fn metadata(&mut self) -> BoxFuture<'_, FsResult<Box<dyn DavMetaData>>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (size, modified) = tokio::task::spawn_blocking(move || {
                let guard = inner.lock().unwrap();
                let s = guard.logical_size().unwrap_or(0);
                let m = guard
                    .metadata()
                    .and_then(|meta| meta.modified())
                    .unwrap_or_else(|_| SystemTime::now());
                (s, m)
            })
            .await
            .unwrap();

            Ok(Box::new(WebDavMetaData {
                logical_size: size,
                is_dir: false,
                modified,
            }) as Box<dyn DavMetaData>)
        })
    }

    fn write_buf(&mut self, mut buf: Box<dyn bytes::Buf + Send>) -> BoxFuture<'_, FsResult<()>> {
        let bytes = buf.copy_to_bytes(buf.remaining());
        self.write_bytes(bytes)
    }

    fn write_bytes(&mut self, buf: Bytes) -> BoxFuture<'_, FsResult<()>> {
        let inner = self.inner.clone();
        let offset = self.pos;
        let data_vec = buf.to_vec();

        Box::pin(async move {
            let len = data_vec.len() as u64;

            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                let mut guard = inner
                    .lock()
                    .map_err(|_| WebDavError::LockFailed("write_bytes"))?;
                guard
                    .write_chunk(offset, &data_vec)
                    .map_err(|_| WebDavError::WriteChunkFailed)?;
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::WriteChunkFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e); // Logging the formatted error
                FsError::GeneralFailure
            })?;

            self.pos += len;
            Ok(())
        })
    }

    fn read_bytes(&mut self, count: usize) -> BoxFuture<'_, FsResult<Bytes>> {
        let inner = self.inner.clone();
        let offset = self.pos;

        Box::pin(async move {
            let secure_buf = tokio::task::spawn_blocking(move || -> Result<_, WebDavError> {
                let mut guard = inner
                    .lock()
                    .map_err(|_| WebDavError::LockFailed("read_bytes"))?;
                guard
                    .read_chunk(offset, count)
                    .map_err(|_| WebDavError::ReadChunkFailed)
            })
            .await
            .map_err(|_| WebDavError::ReadChunkFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })?;

            let b = Bytes::copy_from_slice(&secure_buf.0);
            self.pos += b.len() as u64;
            Ok(b)
        })
    }

    fn seek(&mut self, pos: SeekFrom) -> BoxFuture<'_, FsResult<u64>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let size = tokio::task::spawn_blocking(move || {
                let guard = inner.lock().unwrap();
                guard.logical_size().unwrap_or(0)
            })
            .await
            .unwrap();

            match pos {
                SeekFrom::Start(p) => self.pos = p,
                SeekFrom::End(p) => {
                    if p < 0 {
                        self.pos = size.saturating_sub(p.unsigned_abs());
                    } else {
                        self.pos = size + p as u64;
                    }
                }
                SeekFrom::Current(p) => {
                    if p < 0 {
                        self.pos = self.pos.saturating_sub(p.unsigned_abs());
                    } else {
                        self.pos += p as u64;
                    }
                }
            }
            Ok(self.pos)
        })
    }

    fn flush(&mut self) -> BoxFuture<'_, FsResult<()>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                let mut guard = inner.lock().map_err(|_| WebDavError::LockFailed("flush"))?;
                guard.flush().map_err(|_| WebDavError::FlushFailed)?;
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::FlushFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })?;

            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct WebDavFS {
    physical_root: PathBuf,
    master_key: SecureKey,
    cache: Arc<FileCache>,
}

impl WebDavFS {
    pub fn new<P: AsRef<Path>>(
        physical_root: P,
        master_key: SecureKey,
        cache: Arc<FileCache>,
    ) -> Self {
        Self {
            physical_root: physical_root.as_ref().to_path_buf(),
            master_key,
            cache,
        }
    }
    fn physical_path(&self, dav_path: &DavPath) -> PathBuf {
        self.physical_root.join(dav_path.as_rel_ospath())
    }
}

impl DavFileSystem for WebDavFS {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> BoxFuture<'a, FsResult<Box<dyn DavFile>>> {
        let phys_path = self.physical_path(path);
        let master_key = self.master_key.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            if phys_path.is_dir() {
                return Err(FsError::Forbidden);
            }

            let write_access = options.write || options.append || options.truncate;

            let shared_file = tokio::task::spawn_blocking(move || -> Result<_, WebDavError> {
                cache
                    .get_or_open(
                        &phys_path,
                        Aes256XtsCipher::new(master_key),
                        options.truncate,
                        write_access,
                    )
                    .map_err(|_| WebDavError::CacheOpenFailed)
            })
            .await
            .map_err(|_| WebDavError::CacheOpenFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::NotFound
            })?;

            let initial_pos = if options.append {
                shared_file.lock().unwrap().logical_size().unwrap_or(0)
            } else {
                0
            };

            Ok(Box::new(WebDavFile {
                inner: shared_file,
                pos: initial_pos,
            }) as Box<dyn DavFile>)
        })
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<Box<dyn DavMetaData>>> {
        let phys_path = self.physical_path(path);
        let cache = self.cache.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<Box<dyn DavMetaData>, WebDavError> {
                match fs::metadata(&phys_path) {
                    Ok(meta) => {
                        Ok(Box::new(WebDavMetaData::resolve(&phys_path, meta, &cache)) as _)
                    }
                    Err(_) => Err(WebDavError::MetadataFailed),
                }
            })
            .await
            .map_err(|_| WebDavError::MetadataFailed)
            .and_then(|res| res)
            .map_err(|_| {
                // We do not log Metadata errors because WebDAV constantly checks if a file
                // exists or not (NotFound is expected), this would spam the console unnecessarily.
                FsError::NotFound
            })
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> BoxFuture<
        'a,
        FsResult<
            std::pin::Pin<Box<dyn stream::Stream<Item = FsResult<Box<dyn DavDirEntry>>> + Send>>,
        >,
    > {
        let phys_path = self.physical_path(path);
        let cache = self.cache.clone();

        Box::pin(async move {
            let entries = tokio::task::spawn_blocking(
                move || -> Result<Vec<Box<dyn DavDirEntry>>, WebDavError> {
                    let mut results: Vec<Box<dyn DavDirEntry>> = Vec::new();
                    let read_dir = match fs::read_dir(&phys_path) {
                        Ok(dir) => dir,
                        Err(_) => return Err(WebDavError::ReadDirFailed),
                    };

                    for entry in read_dir.flatten() {
                        if let Ok(meta) = entry.metadata() {
                            let name = entry.file_name().to_string_lossy().to_string();
                            if name == "dspv.meta" || name.starts_with('.') {
                                continue;
                            }

                            results.push(Box::new(WebDavDirEntry {
                                name,
                                metadata: WebDavMetaData::resolve(&entry.path(), meta, &cache),
                            }) as Box<dyn DavDirEntry>);
                        }
                    }
                    Ok(results)
                },
            )
            .await
            .map_err(|_| WebDavError::ReadDirFailed)
            .and_then(|res| res)
            .map_err(|_| FsError::NotFound)?; // Ditto, no logging to avoid spam

            let s = stream::iter(entries.into_iter().map(Ok));
            Ok(Box::pin(s) as _)
        })
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let phys_path = self.physical_path(path);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                fs::create_dir(&phys_path).map_err(|_| WebDavError::CreateDirFailed)?;
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::CreateDirFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })
        })
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let phys_path = self.physical_path(path);
        let cache = self.cache.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                cache.remove(&phys_path);
                fs::remove_file(&phys_path).map_err(|_| WebDavError::RemoveFileFailed)?;
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::RemoveFileFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })
        })
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let phys_path = self.physical_path(path);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                fs::remove_dir(&phys_path).map_err(|_| WebDavError::RemoveDirFailed)?;
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::RemoveDirFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })
        })
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let from_path = self.physical_path(from);
        let to_path = self.physical_path(to);
        let cache = self.cache.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                cache.remove(&from_path);
                fs::rename(from_path, to_path).map_err(|_| WebDavError::RenameFailed)?;
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::RenameFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })
        })
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let from_path = self.physical_path(from);
        let to_path = self.physical_path(to);
        let master_key = self.master_key.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                let cipher_src = Aes256XtsCipher::new(master_key.clone());
                let cipher_dst = Aes256XtsCipher::new(master_key);

                let mut src_file = EncryptedFile::open(&from_path, cipher_src, false, false)
                    .map_err(|_| WebDavError::CopySrcOpenFailed)?;
                let logical_size = src_file
                    .logical_size()
                    .map_err(|_| WebDavError::CopyReadWriteFailed)?;

                let mut dst_file = EncryptedFile::open(&to_path, cipher_dst, true, true)
                    .map_err(|_| WebDavError::CopyDstOpenFailed)?;

                let chunk_size: usize = 64 * 1024;
                let mut offset: u64 = 0;

                while offset < logical_size {
                    let remaining = (logical_size - offset) as usize;
                    let current_chunk_size = remaining.min(chunk_size);

                    let secure_buf = src_file
                        .read_chunk(offset, current_chunk_size)
                        .map_err(|_| WebDavError::CopyReadWriteFailed)?;
                    dst_file
                        .write_chunk(offset, &secure_buf.0)
                        .map_err(|_| WebDavError::CopyReadWriteFailed)?;
                    offset += current_chunk_size as u64;
                }
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::CopyReadWriteFailed) // Arbitrary for JoinError
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })
        })
    }

    fn get_quota(&self) -> BoxFuture<'_, FsResult<(u64, Option<u64>)>> {
        let phys_root = self.physical_root.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(u64, Option<u64>), WebDavError> {
                let total_space = fs4::total_space(&phys_root).unwrap_or(0);
                let available_space = fs4::available_space(&phys_root).unwrap_or(0);
                Ok((
                    total_space.saturating_sub(available_space),
                    Some(total_space),
                ))
            })
            .await
            .map_err(|_| WebDavError::QuotaFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })
        })
    }
}

// ------------------------------------------------------------
// 5. WebDAV Integration Tests
// ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dav_server::fs::OpenOptions;
    use std::fs;

    // --- Helper ---
    fn setup_test_env(dir_name: &str) -> (WebDavFS, SecureKey) {
        let _ = fs::remove_dir_all(dir_name);
        fs::create_dir_all(dir_name).unwrap();
        let master_key = SecureKey(vec![0x42; 64]);
        let cache = std::sync::Arc::new(crate::storage::cache::FileCache::new());
        (
            WebDavFS::new(dir_name, master_key.clone(), cache),
            master_key,
        )
    }

    /// TEST 1: Full lifecycle of a file (Creation, I/O, Append, Truncate, Seek, Windows Behavior)
    #[tokio::test]
    async fn test_webdav_file_lifecycle_and_io() {
        let root = "test_io";
        let (dav_fs, _) = setup_test_env(root);
        let path = DavPath::new("/lifecycle.enc").unwrap();

        // 1. Creation and initial write
        {
            let mut f = dav_fs
                .open(
                    &path,
                    OpenOptions {
                        create: true,
                        write: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            f.write_bytes(Bytes::from("Hello")).await.unwrap();
        }

        // 2. Append Mode (Verify that the offset resumes at the end without overwriting)
        {
            let mut f = dav_fs
                .open(
                    &path,
                    OpenOptions {
                        append: true,
                        write: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            f.write_bytes(Bytes::from(" World")).await.unwrap();
        }

        // 3. Read and Seek (Global verification + Windows OS Simulation)
        {
            let mut f = dav_fs
                .open(
                    &path,
                    OpenOptions {
                        read: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                f.metadata().await.unwrap().len(),
                11,
                "Logical size should be 11 after appending"
            );

            f.seek(SeekFrom::Start(0)).await.unwrap();
            assert_eq!(
                f.read_bytes(11).await.unwrap().as_ref(),
                b"Hello World",
                "The decrypted content is incorrect"
            );

            // Validation of relative Seeks and Seeks from the end
            assert_eq!(f.seek(SeekFrom::End(-5)).await.unwrap(), 6);
            assert_eq!(f.seek(SeekFrom::Current(2)).await.unwrap(), 8);
            assert!(f.flush().await.is_ok());
        }

        // 4. Truncate Mode (Overwrites old data)
        {
            let mut f = dav_fs
                .open(
                    &path,
                    OpenOptions {
                        truncate: true,
                        write: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            f.write_bytes(Bytes::from("NEW")).await.unwrap();
        }

        assert_eq!(
            dav_fs.metadata(&path).await.unwrap().len(),
            3,
            "Truncate did not reset the logical size"
        );

        let _ = fs::remove_dir_all(root);
    }

    /// TEST 2: Manipulating the file tree (Filtered listing, Renaming, Copying, Deletion)
    #[tokio::test]
    async fn test_webdav_fs_operations() {
        let root = "test_fs_ops";
        let (dav_fs, _) = setup_test_env(root);

        let p_vis = DavPath::new("/visible.enc").unwrap();

        // CORRECTION 1: Clean creation via WebDAV to generate the FileHeader (32 bytes)
        {
            let mut f = dav_fs
                .open(
                    &p_vis,
                    OpenOptions {
                        create: true,
                        write: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            f.write_bytes(Bytes::from("test")).await.unwrap();
        }

        // The hidden file can be created physically because we're just testing that it's ignored by read_dir
        fs::File::create(PathBuf::from(root).join(".hidden")).unwrap();

        // 2. Filtering during listing
        let root_path = DavPath::new("/").unwrap();
        let entries = dav_fs
            .read_dir(&root_path, ReadDirMeta::None)
            .await
            .unwrap();
        let names: Vec<String> = stream::StreamExt::collect::<Vec<_>>(entries)
            .await
            .into_iter()
            .map(|e| String::from_utf8(e.unwrap().name()).unwrap())
            .collect();

        assert!(names.contains(&"visible.enc".to_string()));
        assert!(
            !names.contains(&".hidden".to_string()),
            "Hidden files must be ignored"
        );

        // 3. Copying and Renaming
        let p_copy = DavPath::new("/copy.enc").unwrap();
        let p_rename = DavPath::new("/rename.enc").unwrap();

        dav_fs.copy(&p_vis, &p_copy).await.unwrap();
        assert!(
            fs::metadata(PathBuf::from(root).join("copy.enc")).is_ok(),
            "Copy failed"
        );

        dav_fs.rename(&p_copy, &p_rename).await.unwrap();
        assert!(
            fs::metadata(PathBuf::from(root).join("copy.enc")).is_err(),
            "The old file still exists post-rename"
        );
        assert!(
            fs::metadata(PathBuf::from(root).join("rename.enc")).is_ok(),
            "The new file does not exist"
        );

        // 4. Deletion
        dav_fs.remove_file(&p_vis).await.unwrap();
        dav_fs.remove_file(&p_rename).await.unwrap();
        assert!(fs::metadata(PathBuf::from(root).join("visible.enc")).is_err());

        let d_dir = DavPath::new("/dir").unwrap();
        dav_fs.create_dir(&d_dir).await.unwrap();
        dav_fs.remove_dir(&d_dir).await.unwrap();
        assert!(fs::metadata(PathBuf::from(root).join("dir")).is_err());

        let _ = fs::remove_dir_all(root);
    }

    /// TEST 3: Metadata Resolution (RAM Cache vs Physical Header) and OS Quota
    #[tokio::test]
    async fn test_webdav_metadata_cache_and_quota() {
        let root = "test_meta_quota";
        let (dav_fs, _) = setup_test_env(root);
        let path = DavPath::new("/cache_test.enc").unwrap();
        let phys_path = PathBuf::from(root).join("cache_test.enc");

        // 1. Testing the RAM Cache (File locked and not flushed)
        {
            let mut file = dav_fs
                .open(
                    &path,
                    OpenOptions {
                        create: true,
                        write: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            file.write_bytes(Bytes::from("Data")).await.unwrap();

            // The I/O file is still open, metadata should be intercepted from the RAM cache
            assert_eq!(
                dav_fs.metadata(&path).await.unwrap().len(),
                4,
                "Resolution did not use the RAM cache"
            );
        } // file is dropped here (flush and OS close guaranteed)

        // CORRECTION 2: Explicit eviction from the RAM cache to force the system to re-read the disk
        dav_fs.cache.remove(&phys_path);

        // 2. Testing the I/O Fallback (Emulating an existing file read from the physical header)
        let mut f = fs::OpenOptions::new().write(true).open(&phys_path).unwrap();

        // We forge a FileHeader with a fake logical size to prove it is indeed read from the disk
        let mut header = crate::storage::header::FileHeader::generate_new();
        header.logical_size = 999;
        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        header.write_to(&mut f).unwrap();
        drop(f); // Explicitly releasing the OS lock

        assert_eq!(
            dav_fs.metadata(&path).await.unwrap().len(),
            999,
            "The size was not read from the physical FileHeader"
        );

        // 3. Testing the OS Quota
        let quota_result = dav_fs.get_quota().await;
        assert!(quota_result.is_ok(), "The OS quota API failed");

        let (used, total) = quota_result.unwrap();
        assert!(total.unwrap() > 0, "The total disk size cannot be 0");
        assert!(
            used <= total.unwrap(),
            "Used space cannot exceed total space"
        );

        let _ = fs::remove_dir_all(root);
    }
}
