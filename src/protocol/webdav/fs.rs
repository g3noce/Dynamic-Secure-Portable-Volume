use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use std::time::SystemTime;

use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, DavProp, FsError, FsFuture, FsResult,
    OpenOptions, ReadDirMeta,
};
use futures_util::future::BoxFuture;
use futures_util::stream;
use hyper::http::StatusCode;

use crate::crypto::cipher::{Aes256XtsCipher, ChunkCipher};
use crate::protocol::webdav::errors::WebDavError;
use crate::protocol::webdav::file::WebDavFile;
use crate::protocol::webdav::guard::is_forbidden;
use crate::protocol::webdav::metadata::{WebDavDirEntry, WebDavMetaData};
use crate::storage::cache::FileCache;
use crate::storage::chunk_io::EncryptedFile;
use crate::utils::memory::SecureKey;

#[derive(Clone)]
pub struct WebDavFS {
    physical_root: PathBuf,
    master_key: SecureKey,
    pub(super) cache: Arc<FileCache>,
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

    /// Stable byte representation of a DAV path, used as the HMAC AAD so that
    /// renaming or swapping ciphertext between paths is detected.
    /// We normalize to forward-slash UTF-8 — DAV paths are URL-style — so the
    /// AAD is platform-independent across Windows/macOS/Linux.
    fn mac_aad_for(dav_path: &DavPath) -> Vec<u8> {
        dav_path
            .as_rel_ospath()
            .to_string_lossy()
            .replace('\\', "/")
            .into_bytes()
    }
}

impl DavFileSystem for WebDavFS {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> BoxFuture<'a, FsResult<Box<dyn DavFile>>> {
        if is_forbidden(path) {
            return Box::pin(async { Err(FsError::NotFound) });
        }
        let phys_path = self.physical_path(path);
        let mac_aad = Self::mac_aad_for(path);
        let master_key = self.master_key.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            if phys_path.is_dir() {
                return Err(FsError::Forbidden);
            }

            let write_access = options.write || options.append || options.truncate;

            let shared_file = tokio::task::spawn_blocking(move || -> Result<_, WebDavError> {
                let (xts_key, mac_key) = master_key.split_xts_mac();
                cache
                    .get_or_open(
                        &phys_path,
                        Aes256XtsCipher::new(xts_key),
                        mac_key,
                        mac_aad,
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

            Ok(Box::new(WebDavFile {
                inner: shared_file,
                pos: 0,
                append: options.append,
            }) as Box<dyn DavFile>)
        })
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<Box<dyn DavMetaData>>> {
        if is_forbidden(path) {
            return Box::pin(async { Err(FsError::NotFound) });
        }
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
                // No logging: WebDAV constantly probes existence (NotFound is expected)
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
        if is_forbidden(path) {
            return Box::pin(async { Err(FsError::NotFound) });
        }
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
            .map_err(|_| FsError::NotFound)?;

            let s = stream::iter(entries.into_iter().map(Ok));
            Ok(Box::pin(s) as _)
        })
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        if is_forbidden(path) {
            return Box::pin(async { Err(FsError::Forbidden) });
        }
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
        if is_forbidden(path) {
            return Box::pin(async { Err(FsError::NotFound) });
        }
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
        if is_forbidden(path) {
            return Box::pin(async { Err(FsError::NotFound) });
        }
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
        if is_forbidden(from) || is_forbidden(to) {
            return Box::pin(async { Err(FsError::Forbidden) });
        }
        let from_path = self.physical_path(from);
        let to_path = self.physical_path(to);
        let from_aad = Self::mac_aad_for(from);
        let to_aad = Self::mac_aad_for(to);
        let master_key = self.master_key.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                // Evict any cached handle on either side so the rename + re-MAC
                // sequence below works against a clean state.
                cache.remove(&from_path);
                cache.remove(&to_path);

                // Step 1 — only re-MAC if there's an actual file (not a dir)
                // AND its current tag verifies under `from_aad`. Without this
                // check, an attacker who has already tampered with `from_path`
                // could trick us into stamping a fresh, valid MAC over their
                // garbage when the user renames.
                let is_regular_file = fs::metadata(&from_path)
                    .map(|m| m.is_file())
                    .unwrap_or(false);

                if is_regular_file {
                    let (xts_key, mac_key) = master_key.split_xts_mac();
                    let cipher = Aes256XtsCipher::new(xts_key);
                    // The Drop of this handle is best-effort write-back. We
                    // explicitly drop it before fs::rename so the OS handle is
                    // released on Windows (where rename of an open file fails).
                    let verified = EncryptedFile::open(
                        &from_path, cipher, mac_key, from_aad,
                        /*truncate=*/false,
                        /*write_access=*/false,
                    )
                    .map_err(|_| WebDavError::RenameFailed)?;
                    drop(verified);
                }

                // Step 2 — move the bytes.
                fs::rename(&from_path, &to_path).map_err(|_| WebDavError::RenameFailed)?;

                // Step 3 — rebind the MAC tag to the new AAD. Safe to use
                // `open_unverified` here because step 1 just proved the file
                // was authentic under its old AAD.
                if is_regular_file {
                    let (xts_key, mac_key) = master_key.split_xts_mac();
                    let cipher = Aes256XtsCipher::new(xts_key);
                    let mut renamed = EncryptedFile::open_unverified(
                        &to_path,
                        cipher,
                        mac_key,
                        to_aad,
                    )
                    .map_err(|_| WebDavError::RenameFailed)?;
                    renamed.flush().map_err(|_| WebDavError::RenameFailed)?;
                }

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
        if is_forbidden(from) || is_forbidden(to) {
            return Box::pin(async { Err(FsError::Forbidden) });
        }
        let from_path = self.physical_path(from);
        let to_path = self.physical_path(to);
        // RFC 4918 §9.8.3 : source et destination identiques → interdit.
        // Sans ce garde, le truncate de la destination viderait le fichier
        // source avant que la boucle de copie puisse lire quoi que ce soit.
        if from_path == to_path {
            return Box::pin(async { Err(FsError::Forbidden) });
        }
        let from_aad = Self::mac_aad_for(from);
        let to_aad = Self::mac_aad_for(to);
        let master_key = self.master_key.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || -> Result<(), WebDavError> {
                let (xts_key, mac_key) = master_key.split_xts_mac();

                // Both handles go through the FileCache so we always see the
                // freshest in-memory state (and don't trip MAC verification on
                // a still-dirty source).
                let src_handle = cache
                    .get_or_open(
                        &from_path,
                        Aes256XtsCipher::new(xts_key.clone()),
                        mac_key.clone(),
                        from_aad,
                        false,
                        false,
                    )
                    .map_err(|_| WebDavError::CopySrcOpenFailed)?;
                let dst_handle = cache
                    .get_or_open(
                        &to_path,
                        Aes256XtsCipher::new(xts_key),
                        mac_key,
                        to_aad,
                        true,
                        true,
                    )
                    .map_err(|_| WebDavError::CopyDstOpenFailed)?;

                let logical_size = src_handle
                    .lock()
                    .map_err(|_| WebDavError::LockFailed("copy_src"))?
                    .logical_size()
                    .map_err(|_| WebDavError::CopyReadWriteFailed)?;

                let chunk_size: usize = 64 * 1024;
                let mut offset: u64 = 0;

                while offset < logical_size {
                    let remaining = (logical_size - offset) as usize;
                    let current_chunk_size = remaining.min(chunk_size);

                    let secure_buf = {
                        let mut guard = src_handle
                            .lock()
                            .map_err(|_| WebDavError::LockFailed("copy_src"))?;
                        guard
                            .read_chunk(offset, current_chunk_size)
                            .map_err(|_| WebDavError::CopyReadWriteFailed)?
                    };
                    {
                        let mut guard = dst_handle
                            .lock()
                            .map_err(|_| WebDavError::LockFailed("copy_dst"))?;
                        guard
                            .write_chunk(offset, &secure_buf.0)
                            .map_err(|_| WebDavError::CopyReadWriteFailed)?;
                    }
                    offset += current_chunk_size as u64;
                }

                // Flush the destination so the MAC tag is persisted before we
                // return success to the WebDAV client.
                dst_handle
                    .lock()
                    .map_err(|_| WebDavError::LockFailed("copy_dst"))?
                    .flush()
                    .map_err(|_| WebDavError::CopyReadWriteFailed)?;
                Ok(())
            })
            .await
            .map_err(|_| WebDavError::CopyReadWriteFailed)
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

    // -----------------------------------------------------------------------
    // WebDAV property hooks.
    //
    // We don't persist custom (dead) DAV properties — the underlying storage
    // is a chunk-encrypted file format, not a metadata store. But the default
    // `FsError::NotImplemented` answer makes clients like Nautilus pop up
    // "operation not supported" after a successful PUT/COPY (they typically
    // PROPPATCH the timestamp right after writing). Returning success-with-
    // empty satisfies those clients without lying about persistence.
    // -----------------------------------------------------------------------

    fn have_props<'a>(
        &'a self,
        _path: &'a DavPath,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async { false })
    }

    fn patch_props<'a>(
        &'a self,
        _path: &'a DavPath,
        patch: Vec<(bool, DavProp)>,
    ) -> FsFuture<'a, Vec<(StatusCode, DavProp)>> {
        // Acknowledge every requested patch with HTTP 200. We don't actually
        // store anything: a subsequent PROPFIND will return only live props.
        Box::pin(async move {
            Ok(patch
                .into_iter()
                .map(|(_set, prop)| (StatusCode::OK, prop))
                .collect())
        })
    }

    fn get_props<'a>(
        &'a self,
        _path: &'a DavPath,
        _do_content: bool,
    ) -> FsFuture<'a, Vec<DavProp>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn get_prop<'a>(&'a self, _path: &'a DavPath, _prop: DavProp) -> FsFuture<'a, Vec<u8>> {
        Box::pin(async { Err(FsError::NotFound) })
    }

    fn set_modified<'a>(&'a self, _path: &'a DavPath, _tm: SystemTime) -> FsFuture<'a, ()> {
        // Linux file managers call this to preserve the mtime of a pasted file.
        // We can't change the on-disk mtime without exposing the host fs to the
        // client (the encrypted blob has its own bookkeeping), so we accept the
        // call silently — better than panicking the paste UI with a fake error.
        Box::pin(async { Ok(()) })
    }
}
