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

// --- AJOUT : Énumération structurée pour les erreurs personnalisées ---
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
            WebDavError::LockFailed(f_name) => {
                (*f_name, "impossible de verrouiller le fichier partagé")
            }
            WebDavError::WriteChunkFailed => ("write_bytes", "échec d'écriture du chunk chiffré"),
            WebDavError::ReadChunkFailed => ("read_bytes", "échec de lecture du chunk chiffré"),
            WebDavError::FlushFailed => ("flush", "échec du vidage sur disque"),
            WebDavError::CacheOpenFailed => ("open", "échec d'ouverture ou création via le cache"),
            WebDavError::MetadataFailed => ("metadata", "échec de récupération des métadonnées OS"),
            WebDavError::ReadDirFailed => ("read_dir", "échec de lecture du contenu du dossier"),
            WebDavError::CreateDirFailed => ("create_dir", "échec de création du dossier"),
            WebDavError::RemoveFileFailed => {
                ("remove_file", "échec de suppression du fichier physique")
            }
            WebDavError::RemoveDirFailed => {
                ("remove_dir", "échec de suppression du dossier physique")
            }
            WebDavError::RenameFailed => ("rename", "échec du renommage sur le disque"),
            WebDavError::CopySrcOpenFailed => ("copy", "impossible d'ouvrir le fichier source"),
            WebDavError::CopyDstOpenFailed => ("copy", "impossible de créer le fichier cible"),
            WebDavError::CopyReadWriteFailed => {
                ("copy", "échec lors de la lecture/écriture des chunks")
            }
            WebDavError::QuotaFailed => {
                ("get_quota", "échec de calcul de l'espace disque disponible")
            }
        };
        write!(f, "mod : webdav , fonction : {} , cause : {}", func, cause)
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
                eprintln!("{}", e); // Journalisation de l'erreur formatée
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
                // On ne loggue pas les erreurs Metadata car WebDAV vérifie constamment si un fichier
                // existe ou non (NotFound attendu), cela spammerait la console inutilement.
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
            .map_err(|_| FsError::NotFound)?; // Idem, pas de log pour éviter le spam

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
            .map_err(|_| WebDavError::CopyReadWriteFailed) // Arbitraire pour JoinError
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
// 5. Tests d'intégration WebDAV
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

    /// TEST 1 : Cycle de vie complet d'un fichier (Création, I/O, Append, Truncate, Seek, Comportement Windows)
    #[tokio::test]
    async fn test_webdav_file_lifecycle_and_io() {
        let root = "test_io";
        let (dav_fs, _) = setup_test_env(root);
        let path = DavPath::new("/lifecycle.enc").unwrap();

        // 1. Création et écriture initiale
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

        // 2. Mode Append (Vérifie que l'offset reprend à la fin sans écraser)
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

        // 3. Lecture et Seek (Vérification globale + Simulation OS Windows)
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
                "La taille logique doit être de 11 après l'append"
            );

            f.seek(SeekFrom::Start(0)).await.unwrap();
            assert_eq!(
                f.read_bytes(11).await.unwrap().as_ref(),
                b"Hello World",
                "Le contenu déchiffré est erroné"
            );

            // Validation des Seek relatifs et par la fin
            assert_eq!(f.seek(SeekFrom::End(-5)).await.unwrap(), 6);
            assert_eq!(f.seek(SeekFrom::Current(2)).await.unwrap(), 8);
            assert!(f.flush().await.is_ok());
        }

        // 4. Mode Truncate (Écrase les anciennes données)
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
            "Le Truncate n'a pas réinitialisé la taille logique"
        );

        let _ = fs::remove_dir_all(root);
    }

    /// TEST 2 : Manipulation de l'arbre de fichiers (Listage filtré, Renommage, Copie, Suppression)
    #[tokio::test]
    async fn test_webdav_fs_operations() {
        let root = "test_fs_ops";
        let (dav_fs, _) = setup_test_env(root);

        let p_vis = DavPath::new("/visible.enc").unwrap();

        // CORRECTION 1 : Création propre via WebDAV pour générer le FileHeader (32 octets)
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

        // Le fichier caché peut être créé physiquement car on teste juste qu'il est ignoré par read_dir
        fs::File::create(PathBuf::from(root).join(".hidden")).unwrap();

        // 2. Filtrage au listage
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
            "Les fichiers cachés doivent être ignorés"
        );

        // 3. Copie et Renommage
        let p_copy = DavPath::new("/copy.enc").unwrap();
        let p_rename = DavPath::new("/rename.enc").unwrap();

        dav_fs.copy(&p_vis, &p_copy).await.unwrap();
        assert!(
            fs::metadata(PathBuf::from(root).join("copy.enc")).is_ok(),
            "Copie échouée"
        );

        dav_fs.rename(&p_copy, &p_rename).await.unwrap();
        assert!(
            fs::metadata(PathBuf::from(root).join("copy.enc")).is_err(),
            "L'ancien fichier post-renommage existe toujours"
        );
        assert!(
            fs::metadata(PathBuf::from(root).join("rename.enc")).is_ok(),
            "Le nouveau fichier n'existe pas"
        );

        // 4. Suppression
        dav_fs.remove_file(&p_vis).await.unwrap();
        dav_fs.remove_file(&p_rename).await.unwrap();
        assert!(fs::metadata(PathBuf::from(root).join("visible.enc")).is_err());

        let d_dir = DavPath::new("/dir").unwrap();
        dav_fs.create_dir(&d_dir).await.unwrap();
        dav_fs.remove_dir(&d_dir).await.unwrap();
        assert!(fs::metadata(PathBuf::from(root).join("dir")).is_err());

        let _ = fs::remove_dir_all(root);
    }

    /// TEST 3 : Résolution des Métadonnées (Cache RAM vs Header Physique) et Quota OS
    #[tokio::test]
    async fn test_webdav_metadata_cache_and_quota() {
        let root = "test_meta_quota";
        let (dav_fs, _) = setup_test_env(root);
        let path = DavPath::new("/cache_test.enc").unwrap();
        let phys_path = PathBuf::from(root).join("cache_test.enc");

        // 1. Test du Cache RAM (Fichier verrouillé et non flushé)
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

            // Le fichier I/O est toujours ouvert, les métadonnées doivent être interceptées depuis le cache RAM
            assert_eq!(
                dav_fs.metadata(&path).await.unwrap().len(),
                4,
                "La résolution n'a pas utilisé le cache RAM"
            );
        } // file est drop ici (flush et fermeture OS garantis)

        // CORRECTION 2 : Éviction explicite du cache RAM pour obliger le système à relire le disque
        dav_fs.cache.remove(&phys_path);

        // 2. Test du Fallback I/O (Émulation d'un fichier existant lu depuis le header physique)
        let mut f = fs::OpenOptions::new().write(true).open(&phys_path).unwrap();

        // On forge un FileHeader avec une fausse taille logique pour prouver qu'il est bien lu sur le disque
        let mut header = crate::storage::header::FileHeader::generate_new();
        header.logical_size = 999;
        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        header.write_to(&mut f).unwrap();
        drop(f); // Relâchement explicite du lock OS

        assert_eq!(
            dav_fs.metadata(&path).await.unwrap().len(),
            999,
            "La taille n'a pas été lue depuis le FileHeader physique"
        );

        // 3. Test du Quota OS
        let quota_result = dav_fs.get_quota().await;
        assert!(quota_result.is_ok(), "L'API de quota OS a échoué");

        let (used, total) = quota_result.unwrap();
        assert!(
            total.unwrap() > 0,
            "La taille totale du disque ne peut pas être de 0"
        );
        assert!(
            used <= total.unwrap(),
            "L'espace utilisé ne peut pas dépasser l'espace total"
        );

        let _ = fs::remove_dir_all(root);
    }
}
