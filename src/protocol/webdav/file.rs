use std::io::SeekFrom;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bytes::Bytes;
use dav_server::fs::{DavFile, DavMetaData, FsError, FsResult};
use futures_util::future::BoxFuture;

use crate::crypto::cipher::Aes256XtsCipher;
use crate::protocol::webdav::errors::WebDavError;
use crate::protocol::webdav::metadata::WebDavMetaData;
use crate::storage::chunk_io::EncryptedFile;

pub struct WebDavFile {
    pub(super) inner: Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>,
    pub(super) pos: u64,
    /// Quand true, chaque écriture va systématiquement en fin de fichier au
    /// moment de l'appel (logical_size()), indépendamment de self.pos. Cela
    /// empêche deux handles append ouverts simultanément de capturer la même
    /// position initiale et de s'écraser mutuellement.
    pub(super) append: bool,
}

impl std::fmt::Debug for WebDavFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDavFile")
            .field("pos", &self.pos)
            .field("append", &self.append)
            .finish_non_exhaustive()
    }
}

impl DavFile for WebDavFile {
    fn metadata(&mut self) -> BoxFuture<'_, FsResult<Box<dyn DavMetaData>>> {
        let inner = self.inner.clone();
        Box::pin(async move {
            let (size, modified) = tokio::task::spawn_blocking(move || -> Result<_, WebDavError> {
                let guard = inner
                    .lock()
                    .map_err(|_| WebDavError::LockFailed("metadata"))?;
                let s = guard.logical_size().unwrap_or(0);
                let m = guard
                    .metadata()
                    .and_then(|meta| meta.modified())
                    .unwrap_or_else(|_| SystemTime::now());
                Ok((s, m))
            })
            .await
            .map_err(|_| WebDavError::MetadataFailed)
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })?;

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
        let append = self.append;
        let data_vec = buf.to_vec();

        Box::pin(async move {
            let len = data_vec.len() as u64;

            // Retourne l'offset réel utilisé pour l'écriture afin de mettre
            // à jour self.pos correctement (utile en mode append).
            let actual_offset =
                tokio::task::spawn_blocking(move || -> Result<u64, WebDavError> {
                    let mut guard = inner
                        .lock()
                        .map_err(|_| WebDavError::LockFailed("write_bytes"))?;
                    // En mode append, l'offset est la taille logique courante
                    // mesurée à l'intérieur du verrou : deux handles concurrents
                    // obtiennent ainsi des positions distinctes même s'ils ont
                    // été ouverts avant toute écriture.
                    let write_at = if append {
                        guard
                            .logical_size()
                            .map_err(|_| WebDavError::WriteChunkFailed)?
                    } else {
                        offset
                    };
                    guard
                        .write_chunk(write_at, &data_vec)
                        .map_err(|_| WebDavError::WriteChunkFailed)?;
                    Ok(write_at)
                })
                .await
                .map_err(|_| WebDavError::WriteChunkFailed)
                .and_then(|res| res)
                .map_err(|e| {
                    eprintln!("{}", e);
                    FsError::GeneralFailure
                })?;

            self.pos = actual_offset + len;
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
            let size = tokio::task::spawn_blocking(move || -> Result<u64, WebDavError> {
                let guard = inner
                    .lock()
                    .map_err(|_| WebDavError::LockFailed("seek"))?;
                Ok(guard.logical_size().unwrap_or(0))
            })
            .await
            .map_err(|_| WebDavError::LockFailed("seek"))
            .and_then(|res| res)
            .map_err(|e| {
                eprintln!("{}", e);
                FsError::GeneralFailure
            })?;

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
