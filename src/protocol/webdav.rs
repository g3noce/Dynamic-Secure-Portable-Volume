//! Intégration WebDAV pour exposer un volume chiffré via le protocole DAV.
//! Utilise la crate `dav-server` (v0.11.0) et mappe dynamiquement un dossier physique.

use std::fs;
use std::io::{self, SeekFrom};
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

use crate::crypto::cipher::{Aes256CtrCipher, ChunkCipher};
use crate::storage::chunk_io::EncryptedFile;
use crate::storage::header::HEADER_SIZE;
use crate::utils::memory::SecureKey;

// ------------------------------------------------------------
// 1. Métadonnées (Fichiers et Dossiers)
// ------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WebDavMetaData {
    logical_size: u64,
    is_dir: bool,
    modified: SystemTime,
}

impl WebDavMetaData {
    fn from_physical(metadata: fs::Metadata) -> Self {
        let is_dir = metadata.is_dir();
        let physical_size = metadata.len();
        let logical_size = if is_dir {
            0
        } else {
            physical_size.saturating_sub(HEADER_SIZE)
        };

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

// ------------------------------------------------------------
// 2. Entrée de répertoire
// ------------------------------------------------------------

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

// ------------------------------------------------------------
// 3. Fichier Virtuel Chiffré (Wrapper Stateful)
// ------------------------------------------------------------

pub struct WebDavFile {
    inner: Arc<Mutex<EncryptedFile<Aes256CtrCipher>>>,
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
            let result = tokio::task::spawn_blocking(move || {
                let mut guard = match inner.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        eprintln!(
                            "[!] Avertissement : Récupération d'un Mutex empoisonné sur un fichier."
                        );
                        poisoned.into_inner()
                    }
                };
                guard.write_chunk(offset, &data_vec)
            })
            .await
            .map_err(|_| FsError::GeneralFailure)?;

            match result {
                Ok(_) => {
                    self.pos += len;
                    Ok(())
                }
                Err(e) => {
                    eprintln!("[!] Erreur I/O physique lors de l'écriture : {}", e);
                    Err(FsError::GeneralFailure)
                }
            }
        })
    }

    fn read_bytes(&mut self, count: usize) -> BoxFuture<'_, FsResult<Bytes>> {
        let inner = self.inner.clone();
        let offset = self.pos;

        Box::pin(async move {
            let result = tokio::task::spawn_blocking(move || {
                let mut guard = inner.lock().unwrap();
                guard.read_chunk(offset, count)
            })
            .await
            .map_err(|_| FsError::GeneralFailure)?;

            match result {
                Ok(secure_buf) => {
                    let b = Bytes::copy_from_slice(&secure_buf.0);
                    self.pos += b.len() as u64;
                    Ok(b)
                }
                Err(_) => Err(FsError::GeneralFailure),
            }
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
        Box::pin(async move { Ok(()) })
    }
}

// ------------------------------------------------------------
// 4. Système de fichiers WebDAV Dynamique
// ------------------------------------------------------------

#[derive(Clone)]
pub struct WebDavFS {
    physical_root: PathBuf,
    master_key: SecureKey,
}

impl WebDavFS {
    pub fn new<P: AsRef<Path>>(physical_root: P, master_key: SecureKey) -> Self {
        Self {
            physical_root: physical_root.as_ref().to_path_buf(),
            master_key,
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

        Box::pin(async move {
            if phys_path.is_dir() {
                return Err(FsError::Forbidden);
            }

            // On ne tronque QUE si l'option truncate est explicitement à true
            let should_truncate = options.truncate;
            let write_access = options.write || options.append || options.truncate;
            let master_key = self.master_key.clone();

            let result: io::Result<EncryptedFile<Aes256CtrCipher>> =
                tokio::task::spawn_blocking(move || {
                    EncryptedFile::open(
                        &phys_path,
                        Aes256CtrCipher::new(master_key),
                        should_truncate,
                        write_access,
                    )
                })
                .await
                .map_err(|_| FsError::GeneralFailure)?;

            match result {
                Ok(enc_file) => Ok(Box::new(WebDavFile {
                    inner: Arc::new(Mutex::new(enc_file)),
                    pos: 0,
                }) as Box<dyn DavFile>),
                Err(_) => Err(FsError::NotFound),
            }
        })
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<Box<dyn DavMetaData>>> {
        let phys_path = self.physical_path(path);
        Box::pin(async move {
            match fs::metadata(&phys_path) {
                Ok(meta) => {
                    Ok(Box::new(WebDavMetaData::from_physical(meta)) as Box<dyn DavMetaData>)
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        Err(FsError::NotFound)
                    } else {
                        Err(FsError::GeneralFailure)
                    }
                }
            }
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
        Box::pin(async move {
            let mut entries: Vec<Box<dyn DavDirEntry>> = Vec::new();

            let read_dir = match fs::read_dir(&phys_path) {
                Ok(dir) => dir,
                Err(_) => return Err(FsError::NotFound),
            };

            for entry in read_dir.flatten() {
                if let Ok(meta) = entry.metadata() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name == "dspv.meta" || name.starts_with('.') {
                        continue;
                    }

                    entries.push(Box::new(WebDavDirEntry {
                        name,
                        metadata: WebDavMetaData::from_physical(meta),
                    }) as Box<dyn DavDirEntry>);
                }
            }

            let s = stream::iter(entries.into_iter().map(Ok));
            Ok(Box::pin(s)
                as std::pin::Pin<
                    Box<dyn stream::Stream<Item = FsResult<Box<dyn DavDirEntry>>> + Send>,
                >)
        })
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let phys_path = self.physical_path(path);
        Box::pin(async move { fs::create_dir(&phys_path).map_err(|_| FsError::GeneralFailure) })
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let phys_path = self.physical_path(path);
        Box::pin(async move { fs::remove_file(&phys_path).map_err(|_| FsError::GeneralFailure) })
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let phys_path = self.physical_path(path);
        Box::pin(async move { fs::remove_dir(&phys_path).map_err(|_| FsError::GeneralFailure) })
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let from_path = self.physical_path(from);
        let to_path = self.physical_path(to);

        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                fs::rename(from_path, to_path).map_err(|_| FsError::GeneralFailure)
            })
            .await
            .map_err(|_| FsError::GeneralFailure)?
        })
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> BoxFuture<'a, FsResult<()>> {
        let from_path = self.physical_path(from);
        let to_path = self.physical_path(to);
        let master_key = self.master_key.clone();

        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                // 1. Instancier les chiffreurs (un pour la lecture, un pour l'écriture)
                // Note : On clone la clé sécurisée (SecureKey), ce qui est sûr car elle sera zeroizée au drop.
                let cipher_src = Aes256CtrCipher::new(master_key.clone());
                let cipher_dst = Aes256CtrCipher::new(master_key);

                // 2. Ouvrir le fichier source (truncate = false pour lire l'en-tête existant, write_access = false)
                let mut src_file = EncryptedFile::open(&from_path, cipher_src, false, false)
                    .map_err(|_| FsError::NotFound)?;

                // 3. Récupérer la taille logique pour borner la copie
                let logical_size = src_file
                    .logical_size()
                    .map_err(|_| FsError::GeneralFailure)?;

                // 4. Ouvrir/Créer le fichier de destination
                // CRITIQUE : truncate = true force la génération d'un NOUVEAU FileHeader avec un nouvel IV
                // write_access = true car on va copier des données dedans
                let mut dst_file = EncryptedFile::open(&to_path, cipher_dst, true, true)
                    .map_err(|_| FsError::GeneralFailure)?;

                // 5. Streaming par blocs (Chunking) pour préserver la RAM
                let chunk_size: usize = 64 * 1024; // 64 Ko par itération (compromis idéal vitesse/mémoire)
                let mut offset: u64 = 0;

                while offset < logical_size {
                    let remaining = (logical_size - offset) as usize;
                    let current_chunk_size = remaining.min(chunk_size);

                    // Lecture et déchiffrement (le résultat atterrit dans un SecureBuffer)
                    let secure_buf = src_file
                        .read_chunk(offset, current_chunk_size)
                        .map_err(|_| FsError::GeneralFailure)?;

                    // Chiffrement et écriture avec le nouvel IV
                    dst_file
                        .write_chunk(offset, &secure_buf.0)
                        .map_err(|_| FsError::GeneralFailure)?;

                    offset += current_chunk_size as u64;
                }

                Ok(())
            })
            .await
            .map_err(|_| FsError::GeneralFailure)?
        })
    }

    fn get_quota(&self) -> BoxFuture<'_, FsResult<(u64, Option<u64>)>> {
        // On clone le chemin physique pour pouvoir le déplacer dans le thread bloquant
        let phys_root = self.physical_root.clone();

        Box::pin(async move {
            let result = tokio::task::spawn_blocking(move || {
                // fs4 interroge l'OS (Windows/macOS/Linux) pour obtenir l'espace réel
                // du disque hébergeant le dossier physique.
                let total_space = fs4::total_space(&phys_root).unwrap_or(0);
                let available_space = fs4::available_space(&phys_root).unwrap_or(0);

                // Le quota utilisé est calculé par déduction
                let used_space = total_space.saturating_sub(available_space);

                (used_space, Some(total_space))
            })
            .await
            .map_err(|e| {
                eprintln!("[!] Erreur de thread lors du calcul du quota : {}", e);
                FsError::GeneralFailure
            })?;

            Ok(result)
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
    use std::io::Write;

    // --- Helper ---
    fn setup_test_env(dir_name: &str) -> (WebDavFS, SecureKey) {
        let _ = fs::remove_dir_all(dir_name);
        fs::create_dir_all(dir_name).unwrap();
        let master_key = SecureKey(vec![0x42; 32]);
        let dav_fs = WebDavFS::new(dir_name, master_key.clone());
        (dav_fs, master_key)
    }

    // 1. Test des métadonnées (Calcul Taille Logique vs Physique)
    #[tokio::test]
    async fn test_metadata_logic() {
        let root = "test_meta";
        let (dav_fs, _) = setup_test_env(root);
        let path = DavPath::new("/file.enc").unwrap();

        // Création physique d'un fichier avec en-tête + 10 octets
        let phys_path = PathBuf::from(root).join("file.enc");
        let mut f = fs::File::create(&phys_path).unwrap();
        f.write_all(&[0u8; (HEADER_SIZE + 10) as usize]).unwrap();

        let meta = dav_fs.metadata(&path).await.unwrap();
        assert_eq!(
            meta.len(),
            10,
            "La taille logique doit être TaillePhysique - HEADER_SIZE"
        );
        assert!(!meta.is_dir());

        let _ = fs::remove_dir_all(root);
    }

    // 2. Test du Seek (Start, Current, End)
    #[tokio::test]
    async fn test_file_seek_logic() {
        let root = "test_seek";
        let (dav_fs, _) = setup_test_env(root);
        let path = DavPath::new("/seek.enc").unwrap();

        let mut file = dav_fs
            .open(
                &path,
                OpenOptions {
                    read: true,
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        // On écrit 20 octets
        file.write_bytes(Bytes::from(vec![0u8; 20])).await.unwrap();

        // Test Seek Start
        assert_eq!(file.seek(SeekFrom::Start(5)).await.unwrap(), 5);

        // Test Seek Current
        assert_eq!(file.seek(SeekFrom::Current(2)).await.unwrap(), 7);
        assert_eq!(file.seek(SeekFrom::Current(-3)).await.unwrap(), 4);

        // Test Seek End
        assert_eq!(file.seek(SeekFrom::End(-5)).await.unwrap(), 15);

        let _ = fs::remove_dir_all(root);
    }

    // 3. Test du Listage (Filtrage des fichiers cachés)
    #[tokio::test]
    async fn test_fs_list_filtering() {
        let root = "test_list";
        let _ = fs::remove_dir_all(root);
        fs::create_dir_all(root).unwrap();

        // Création d'un fichier normal et d'un fichier caché
        fs::File::create(PathBuf::from(root).join("visible.enc")).unwrap();
        fs::File::create(PathBuf::from(root).join(".hidden")).unwrap();

        let dav_fs = WebDavFS::new(root, SecureKey(vec![0; 32]));
        let entries = dav_fs
            .read_dir(&DavPath::new("/").unwrap(), ReadDirMeta::None)
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
            "Les fichiers commençant par '.' doivent être ignorés"
        );

        let _ = fs::remove_dir_all(root);
    }

    // 4. Test Rename (Déplacement physique)
    #[tokio::test]
    async fn test_fs_rename() {
        let root = "test_rename";
        let (dav_fs, _) = setup_test_env(root);
        let p1 = DavPath::new("/old.enc").unwrap();
        let p2 = DavPath::new("/new.enc").unwrap();

        fs::File::create(PathBuf::from(root).join("old.enc")).unwrap();
        dav_fs.rename(&p1, &p2).await.unwrap();

        assert!(fs::metadata(PathBuf::from(root).join("new.enc")).is_ok());
        assert!(fs::metadata(PathBuf::from(root).join("old.enc")).is_err());

        let _ = fs::remove_dir_all(root);
    }

    // 5. Test Copy (Duplication physique)
    #[tokio::test]
    async fn test_fs_copy() {
        let root = "test_copy";
        let (dav_fs, _) = setup_test_env(root);
        let p1 = DavPath::new("/src.enc").unwrap();
        let p2 = DavPath::new("/dst.enc").unwrap();

        // Création d'un vrai fichier chiffré via WebDAV pour générer l'en-tête (Header)
        {
            let mut f = dav_fs
                .open(
                    &p1,
                    OpenOptions {
                        create: true,
                        truncate: true,
                        write: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            f.write_bytes(Bytes::from("données de test")).await.unwrap();
        } // Le fichier est fermé (drop) ici
        dav_fs.copy(&p1, &p2).await.unwrap();

        assert!(fs::metadata(PathBuf::from(root).join("src.enc")).is_ok());
        assert!(fs::metadata(PathBuf::from(root).join("dst.enc")).is_ok());

        let _ = fs::remove_dir_all(root);
    }

    // 6. Test de suppression (Fichier et Dossier)
    #[tokio::test]
    async fn test_fs_deletion() {
        let root = "test_del";
        let (dav_fs, _) = setup_test_env(root);

        // Dossier
        let d = DavPath::new("/dir").unwrap();
        dav_fs.create_dir(&d).await.unwrap();
        dav_fs.remove_dir(&d).await.unwrap();
        assert!(fs::metadata(PathBuf::from(root).join("dir")).is_err());

        // Fichier
        let f = DavPath::new("/file.enc").unwrap();
        fs::File::create(PathBuf::from(root).join("file.enc")).unwrap();
        dav_fs.remove_file(&f).await.unwrap();
        assert!(fs::metadata(PathBuf::from(root).join("file.enc")).is_err());

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_webdav_windows_behavior_simulation() {
        let root = "test_windows_sim";
        let (dav_fs, _) = setup_test_env(root);

        let file_path = DavPath::new("/win_test.txt").unwrap();
        let content = b"Donnees secretes 123";

        // 1. SIMULATION CRÉATION (Windows fait souvent un open avec truncate)
        {
            let opts = OpenOptions {
                create: true,
                truncate: true,
                write: true,
                ..Default::default()
            };
            let mut file = dav_fs.open(&file_path, opts).await.unwrap();
            file.write_bytes(Bytes::copy_from_slice(content))
                .await
                .unwrap();
            // Le fichier est DROP ici (fermé)
        }

        // 2. SIMULATION LECTURE (Windows rouvre le fichier sans truncate)
        {
            let opts = OpenOptions {
                read: true,
                write: false,
                ..Default::default()
            };
            let mut file = dav_fs.open(&file_path, opts).await.unwrap();

            // On vérifie d'abord les métadonnées (Windows le fait toujours avant de lire)
            let meta = file.metadata().await.unwrap();
            assert_eq!(
                meta.len(),
                content.len() as u64,
                "La taille lue par l'OS est erronée !"
            );

            // Lecture réelle
            file.seek(io::SeekFrom::Start(0)).await.unwrap();
            let data = file.read_bytes(content.len()).await.unwrap();
            assert_eq!(
                data.as_ref(),
                content,
                "Le contenu déchiffré est vide ou incorrect !"
            );
        }

        let _ = fs::remove_dir_all(root);
    }
}
