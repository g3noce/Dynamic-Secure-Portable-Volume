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

use crate::crypto::cipher::{AuthenticatedChunkCipher, ChaChaPolyCipher};
use crate::storage::cache::FileCache;
use crate::storage::chunk_io::EncryptedFile;
use crate::storage::header::{HEADER_SIZE, LOGICAL_SIZE_OFFSET};
use crate::storage::index::IndexManager;
use crate::utils::memory::SecureKey;

#[derive(Debug)]
pub enum WebDavError {
    Lock(&'static str),
    WriteChunk,
    ReadChunk,
    Flush,
    CacheOpen,
    Metadata,
    ReadDir,
    CreateDir,
    RemoveFile,
    RemoveDir,
    Rename,
    CopySrcOpen,
    CopyDstOpen,
    CopyReadWrite,
    Quota,
    IndexUpdate,
}

impl fmt::Display for WebDavError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            WebDavError::Lock(f_name) => (*f_name, "unable to lock the shared file"),
            WebDavError::WriteChunk => ("write_bytes", "failed to write encrypted chunk"),
            WebDavError::ReadChunk => ("read_bytes", "failed to read encrypted chunk"),
            WebDavError::Flush => ("flush", "failed to flush to disk"),
            WebDavError::CacheOpen => ("open", "failed to open or create via cache"),
            WebDavError::Metadata => ("metadata", "failed to retrieve OS metadata"),
            WebDavError::ReadDir => ("read_dir", "failed to read directory contents"),
            WebDavError::CreateDir => ("create_dir", "failed to create directory"),
            WebDavError::RemoveFile => ("remove_file", "failed to remove physical file"),
            WebDavError::RemoveDir => ("remove_dir", "failed to remove physical directory"),
            WebDavError::Rename => ("rename", "failed to rename on disk"),
            WebDavError::CopySrcOpen => ("copy", "unable to open source file"),
            WebDavError::CopyDstOpen => ("copy", "unable to create target file"),
            WebDavError::CopyReadWrite => ("copy", "failed during chunk read/write"),
            WebDavError::Quota => ("get_quota", "failed to calculate available disk space"),
            WebDavError::IndexUpdate => ("index", "failed to update or save the file index"),
        };
        write!(f, "mod: webdav, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for WebDavError {}

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
    inner: Arc<Mutex<EncryptedFile<ChaChaPolyCipher>>>,
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
                let mut guard = inner.lock().map_err(|_| WebDavError::Lock("write_bytes"))?;
                guard
                    .write_chunk(offset, &data_vec)
                    .map_err(|_| WebDavError::WriteChunk)?;
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::WriteChunk)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
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
                let mut guard = inner.lock().map_err(|_| WebDavError::Lock("read_bytes"))?;
                guard
                    .read_chunk(offset, count)
                    .map_err(|_| WebDavError::ReadChunk)
            })
            .await
            .map_err(|_| WebDavError::ReadChunk)
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
                let mut guard = inner.lock().map_err(|_| WebDavError::Lock("flush"))?;
                guard.flush().map_err(|_| WebDavError::Flush)?;
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::Flush)
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
    index: Arc<Mutex<IndexManager>>,
}

impl WebDavFS {
    pub fn new<P: AsRef<Path>>(
        physical_root: P,
        master_key: SecureKey,
        cache: Arc<FileCache>,
        index: Arc<Mutex<IndexManager>>,
    ) -> Self {
        Self {
            physical_root: physical_root.as_ref().to_path_buf(),
            master_key,
            cache,
            index,
        }
    }

    fn get_physical_path(&self, dav_path: &DavPath) -> Option<PathBuf> {
        let logical_path = dav_path.as_rel_ospath();
        let guard = self.index.lock().ok()?;
        guard.get_physical_path(logical_path, &self.physical_root)
    }
}

impl DavFileSystem for WebDavFS {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> BoxFuture<'a, FsResult<Box<dyn DavFile>>> {
        let dav_path = path.clone();
        let master_key = self.master_key.clone();
        let cache = self.cache.clone();
        let index = self.index.clone();
        let physical_root = self.physical_root.clone();

        Box::pin(async move {
            let logical_path = dav_path.as_rel_ospath().to_path_buf();

            let phys_path = tokio::task::spawn_blocking(move || -> Result<PathBuf, WebDavError> {
                let mut guard = index.lock().map_err(|_| WebDavError::Lock("open_index"))?;

                match guard.get_physical_path(&logical_path, &physical_root) {
                    Some(p) => Ok(p),
                    None => {
                        if options.create {
                            guard.add_entry(logical_path.clone(), false);
                            guard
                                .save(&ChaChaPolyCipher::new(master_key.clone()))
                                .map_err(|_| WebDavError::IndexUpdate)?;
                            guard
                                .get_physical_path(&logical_path, &physical_root)
                                .ok_or(WebDavError::IndexUpdate)
                        } else {
                            Err(WebDavError::Metadata)
                        }
                    }
                }
            })
            .await
            .map_err(|_| FsError::NotFound)
            .and_then(|res| res.map_err(|_| FsError::NotFound))?;

            if phys_path.is_dir() {
                return Err(FsError::Forbidden);
            }

            let write_access = options.write || options.append || options.truncate;
            let cipher = ChaChaPolyCipher::new(self.master_key.clone());

            let shared_file = tokio::task::spawn_blocking(move || -> Result<_, WebDavError> {
                cache
                    .get_or_open(&phys_path, cipher, options.truncate, write_access)
                    .map_err(|_| WebDavError::CacheOpen)
            })
            .await
            .map_err(|_| FsError::NotFound)
            .and_then(|res| res.map_err(|_| FsError::NotFound))?;

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
        let phys_path = self.get_physical_path(path);
        let cache = self.cache.clone();

        Box::pin(async move {
            let p = phys_path.ok_or(FsError::NotFound)?;
            tokio::task::spawn_blocking(move || -> Result<Box<dyn DavMetaData>, WebDavError> {
                match fs::metadata(&p) {
                    Ok(meta) => Ok(Box::new(WebDavMetaData::resolve(&p, meta, &cache)) as _),
                    Err(_) => Err(WebDavError::Metadata),
                }
            })
            .await
            .map_err(|_| FsError::NotFound)
            .and_then(|res| res.map_err(|_| FsError::NotFound))
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
        let dav_path = path.clone();
        let index = self.index.clone();
        let cache = self.cache.clone();
        let physical_root = self.physical_root.clone();

        Box::pin(async move {
            let logical_parent = dav_path.as_rel_ospath().to_path_buf();

            let entries = tokio::task::spawn_blocking(
                move || -> Result<Vec<Box<dyn DavDirEntry>>, WebDavError> {
                    let guard = index.lock().map_err(|_| WebDavError::Lock("read_dir"))?;
                    if logical_parent != Path::new("")
                        && logical_parent != Path::new("/")
                        && !guard.index.entries.contains_key(&logical_parent)
                    {
                        return Err(WebDavError::ReadDir);
                    }

                    let mut results = Vec::new();
                    for (p_path, entry) in &guard.index.entries {
                        if p_path.parent() == Some(logical_parent.as_path()) {
                            let full_phys = physical_root.join(&entry.physical_id);
                            if let Ok(meta) = fs::metadata(&full_phys) {
                                let name = p_path
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .into_owned();
                                results.push(Box::new(WebDavDirEntry {
                                    name,
                                    metadata: WebDavMetaData::resolve(&full_phys, meta, &cache),
                                })
                                    as Box<dyn DavDirEntry>);
                            }
                        }
                    }
                    Ok(results)
                },
            )
            .await
            .map_err(|_| FsError::NotFound)
            .and_then(|res| res.map_err(|_| FsError::NotFound))?;

            Ok(Box::pin(stream::iter(entries.into_iter().map(Ok))) as _)
        })
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let dav_path = path.clone();
        let index = self.index.clone();
        let master_key = self.master_key.clone();
        let physical_root = self.physical_root.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                let mut guard = index.lock().map_err(|_| WebDavError::Lock("create_dir"))?;
                let logical_path = dav_path.as_rel_ospath().to_path_buf();

                let id = guard.add_entry(logical_path, true);
                let phys_path = physical_root.join(id);

                fs::create_dir(&phys_path).map_err(|_| WebDavError::CreateDir)?;
                guard
                    .save(&ChaChaPolyCipher::new(master_key))
                    .map_err(|_| WebDavError::IndexUpdate)?;
                Ok(())
            })
            .await
            .map_err(|_| FsError::GeneralFailure)
            .and_then(|res| res.map_err(|_| FsError::GeneralFailure))
        })
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let dav_path = path.clone();
        let index = self.index.clone();
        let cache = self.cache.clone();
        let master_key = self.master_key.clone();
        let physical_root = self.physical_root.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                let mut guard = index.lock().map_err(|_| WebDavError::Lock("remove_file"))?;
                let logical_path = dav_path.as_rel_ospath().to_path_buf();

                if let Some(entry) = guard.remove_entry(&logical_path) {
                    let phys_path = physical_root.join(&entry.physical_id);
                    cache.remove(&phys_path);
                    fs::remove_file(&phys_path).map_err(|_| WebDavError::RemoveFile)?;
                    guard
                        .save(&ChaChaPolyCipher::new(master_key))
                        .map_err(|_| WebDavError::IndexUpdate)?;
                }
                Ok(())
            })
            .await
            .map_err(|_| FsError::GeneralFailure)
            .and_then(|res| res.map_err(|_| FsError::GeneralFailure))
        })
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let dav_path = path.clone();
        let index = self.index.clone();
        let master_key = self.master_key.clone();
        let physical_root = self.physical_root.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                let mut guard = index.lock().map_err(|_| WebDavError::Lock("remove_dir"))?;
                let logical_path = dav_path.as_rel_ospath().to_path_buf();

                if let Some(entry) = guard.remove_entry(&logical_path) {
                    let phys_path = physical_root.join(&entry.physical_id);
                    fs::remove_dir(&phys_path).map_err(|_| WebDavError::RemoveDir)?;
                    guard
                        .save(&ChaChaPolyCipher::new(master_key))
                        .map_err(|_| WebDavError::IndexUpdate)?;
                }
                Ok(())
            })
            .await
            .map_err(|_| FsError::GeneralFailure)
            .and_then(|res| res.map_err(|_| FsError::GeneralFailure))
        })
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let from_path = from.clone();
        let to_path = to.clone();
        let index = self.index.clone();
        let master_key = self.master_key.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                let mut guard = index.lock().map_err(|_| WebDavError::Lock("rename"))?;
                let logical_from = from_path.as_rel_ospath().to_path_buf();
                let logical_to = to_path.as_rel_ospath().to_path_buf();

                let mut moves = Vec::new();
                for (path, entry) in guard.index.entries.iter() {
                    if let Ok(stripped) = path.strip_prefix(&logical_from) {
                        let new_path = logical_to.join(stripped);
                        moves.push((path.clone(), new_path, entry.clone()));
                    }
                }

                if moves.is_empty() {
                    return Err(WebDavError::Rename);
                }

                for (old_path, new_path, entry) in moves {
                    guard.index.entries.remove(&old_path);
                    guard.index.entries.insert(new_path, entry);
                }

                guard
                    .save(&ChaChaPolyCipher::new(master_key))
                    .map_err(|_| WebDavError::IndexUpdate)?;

                Ok(())
            })
            .await
            .map_err(|_| FsError::GeneralFailure)
            .and_then(|res| res.map_err(|_| FsError::GeneralFailure))
        })
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let from_path = from.clone();
        let to_path = to.clone();
        let index = self.index.clone();
        let cache = self.cache.clone();
        let master_key = self.master_key.clone();
        let physical_root = self.physical_root.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                let logical_from = from_path.as_rel_ospath().to_path_buf();
                let logical_to = to_path.as_rel_ospath().to_path_buf();

                let mut items_to_copy = Vec::new();
                {
                    let guard = index.lock().map_err(|_| WebDavError::Lock("copy"))?;
                    for (path, entry) in guard.index.entries.iter() {
                        if let Ok(stripped) = path.strip_prefix(&logical_from) {
                            let new_path = logical_to.join(stripped);
                            items_to_copy.push((path.clone(), new_path, entry.clone()));
                        }
                    }
                }

                if items_to_copy.is_empty() {
                    return Err(WebDavError::CopySrcOpen);
                }

                for (_old_path, new_path, old_entry) in items_to_copy {
                    let new_phys_id;
                    {
                        let mut guard = index.lock().map_err(|_| WebDavError::Lock("copy"))?;
                        new_phys_id = guard.add_entry(new_path, old_entry.is_dir);
                    }

                    if !old_entry.is_dir {
                        let src_phys = physical_root.join(&old_entry.physical_id);
                        let dst_phys = physical_root.join(&new_phys_id);

                        let cipher_src = ChaChaPolyCipher::new(master_key.clone());
                        let cipher_dst = ChaChaPolyCipher::new(master_key.clone());

                        let src_file = cache
                            .get_or_open(&src_phys, cipher_src, false, false)
                            .map_err(|_| WebDavError::CopySrcOpen)?;
                        let dst_file = cache
                            .get_or_open(&dst_phys, cipher_dst, true, true)
                            .map_err(|_| WebDavError::CopyDstOpen)?;

                        let mut src_guard =
                            src_file.lock().map_err(|_| WebDavError::Lock("copy_src"))?;
                        let mut dst_guard =
                            dst_file.lock().map_err(|_| WebDavError::Lock("copy_dst"))?;

                        let logical_size = src_guard.logical_size().unwrap_or(0);
                        let mut offset = 0;
                        let chunk_size = 65536;

                        while offset < logical_size {
                            let read_len =
                                std::cmp::min(chunk_size, (logical_size - offset) as usize);
                            let data = src_guard
                                .read_chunk(offset, read_len)
                                .map_err(|_| WebDavError::CopyReadWrite)?;
                            dst_guard
                                .write_chunk(offset, &data.0)
                                .map_err(|_| WebDavError::CopyReadWrite)?;
                            offset += read_len as u64;
                        }
                        dst_guard.flush().map_err(|_| WebDavError::Flush)?;
                    } else {
                        let dst_phys = physical_root.join(&new_phys_id);
                        fs::create_dir_all(&dst_phys).map_err(|_| WebDavError::CopyDstOpen)?;
                    }
                }

                let guard = index.lock().map_err(|_| WebDavError::Lock("copy"))?;
                guard
                    .save(&ChaChaPolyCipher::new(master_key))
                    .map_err(|_| WebDavError::IndexUpdate)?;

                Ok(())
            })
            .await
            .map_err(|_| FsError::GeneralFailure)
            .and_then(|res| res.map_err(|_| FsError::GeneralFailure))
        })
    }

    fn get_quota(&self) -> BoxFuture<'_, FsResult<(u64, Option<u64>)>> {
        let phys_root = self.physical_root.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(u64, Option<u64>), WebDavError> {
                let total_space = fs4::total_space(&phys_root).map_err(|_| WebDavError::Quota)?;
                let available_space =
                    fs4::available_space(&phys_root).map_err(|_| WebDavError::Quota)?;
                Ok((
                    total_space.saturating_sub(available_space),
                    Some(total_space),
                ))
            })
            .await
            .map_err(|_| FsError::GeneralFailure)
            .and_then(|res| res.map_err(|_| FsError::GeneralFailure))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use dav_server::fs::OpenOptions;
    use futures_util::StreamExt;
    use std::fs;

    // --- Helper ---
    // Creates an isolated environment with its own cache and index manager
    fn setup_test_env(dir_name: &str) -> WebDavFS {
        let _ = fs::remove_dir_all(dir_name);
        fs::create_dir_all(dir_name).expect("Failed to create test dir");

        let master_key = SecureKey(vec![0x42; 32]);
        let cache = Arc::new(FileCache::new(200));

        let cipher = ChaChaPolyCipher::new(master_key.clone());
        let index = Arc::new(Mutex::new(
            IndexManager::load_or_create(Path::new(dir_name), &cipher).unwrap(),
        ));

        WebDavFS::new(dir_name, master_key, cache, index)
    }

    /// TEST 1: File Data Lifecycle (Create, Write, Append, Seek, Read)
    /// Validates that chunk IO and encryption wrappers behave correctly as a DAV file.
    #[tokio::test]
    async fn test_webdav_io_lifecycle() {
        let root = "test_dav_io";
        let dav_fs = setup_test_env(root);
        let path = DavPath::new("/document.txt").unwrap();

        // 1. Create & Initial Write
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
        f.flush().await.unwrap();

        // 2. Append Mode
        let mut f_app = dav_fs
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
        f_app.write_bytes(Bytes::from(" World")).await.unwrap();
        f_app.flush().await.unwrap();

        // 3. Read & Seek Validations
        let mut f_read = dav_fs
            .open(
                &path,
                OpenOptions {
                    read: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let meta = f_read.metadata().await.unwrap();
        assert_eq!(meta.len(), 11, "Logical size should be 11 bytes");

        let full_data = f_read.read_bytes(11).await.unwrap();
        assert_eq!(full_data.as_ref(), b"Hello World");

        // Test seeking from end
        f_read.seek(SeekFrom::End(-5)).await.unwrap();
        let end_data = f_read.read_bytes(5).await.unwrap();
        assert_eq!(end_data.as_ref(), b"World");

        let _ = fs::remove_dir_all(root);
    }

    /// TEST 2: Filesystem Operations (Directories, Copy, Rename, Remove)
    /// Validates the IndexManager correctly maps logical operations to physical storage.
    #[tokio::test]
    async fn test_webdav_filesystem_operations() {
        let root = "test_dav_ops";
        let dav_fs = setup_test_env(root);

        let d_path = DavPath::new("/folder").unwrap();
        let f_path1 = DavPath::new("/folder/file1.txt").unwrap();
        let f_path2 = DavPath::new("/folder/file2.txt").unwrap();
        let f_renamed = DavPath::new("/folder/renamed.txt").unwrap();

        // 1. Create Directory and a File inside it
        dav_fs.create_dir(&d_path).await.unwrap();
        let mut f = dav_fs
            .open(
                &f_path1,
                OpenOptions {
                    create: true,
                    write: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        f.write_bytes(Bytes::from("Data")).await.unwrap();
        f.flush().await.unwrap();

        // 2. Read Directory (Ensure Index resolves it)
        let entries_stream = dav_fs.read_dir(&d_path, ReadDirMeta::None).await.unwrap();
        let entries: Vec<_> = entries_stream.collect().await;

        assert_eq!(entries.len(), 1);
        let name = String::from_utf8(entries[0].as_ref().unwrap().name()).unwrap();
        assert_eq!(name, "file1.txt");

        // 3. Copy & Rename
        dav_fs.copy(&f_path1, &f_path2).await.expect("Copy failed");
        dav_fs
            .rename(&f_path2, &f_renamed)
            .await
            .expect("Rename failed");

        // Verify logical existence of copied/renamed file
        let meta = dav_fs
            .metadata(&f_renamed)
            .await
            .expect("Renamed file not found");
        assert_eq!(meta.len(), 4, "Copied file data should persist");
        assert!(
            dav_fs.metadata(&f_path2).await.is_err(),
            "Old name should not exist"
        );

        // 4. Deletion
        dav_fs.remove_file(&f_renamed).await.unwrap();
        dav_fs.remove_file(&f_path1).await.unwrap();
        dav_fs.remove_dir(&d_path).await.unwrap();

        // Ensure everything is cleaned up
        assert!(dav_fs.metadata(&d_path).await.is_err());

        let _ = fs::remove_dir_all(root);
    }

    /// TEST 3: Quota
    /// Sanity check to ensure disk space querying functions cleanly without panicking.
    #[tokio::test]
    async fn test_webdav_quota_fetch() {
        let root = "test_dav_quota";
        let dav_fs = setup_test_env(root);

        let quota_result = dav_fs.get_quota().await;
        assert!(quota_result.is_ok(), "Quota fetch should succeed");

        let (used, total) = quota_result.unwrap();
        assert!(total.is_some(), "Total space should be available");
        assert!(
            used <= total.unwrap(),
            "Used space cannot exceed total space"
        );

        let _ = fs::remove_dir_all(root);
    }
}
