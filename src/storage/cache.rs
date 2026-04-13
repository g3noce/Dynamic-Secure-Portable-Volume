use dashmap::DashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::crypto::cipher::Aes256XtsCipher;
use crate::storage::chunk_io::EncryptedFile;

pub struct FileCache {
    entries: DashMap<PathBuf, Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>>,
}

impl FileCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub fn get_or_open(
        &self,
        path: &Path,
        cipher: Aes256XtsCipher,
        truncate: bool,
        write_access: bool,
    ) -> io::Result<Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>> {
        let path_buf = path.to_path_buf();

        if truncate {
            self.entries.remove(&path_buf);
        }

        if let Some(entry) = self.entries.get(&path_buf) {
            return Ok(entry.value().clone());
        }

        let file = EncryptedFile::open(path, cipher, truncate, write_access)?;
        let shared_file = Arc::new(Mutex::new(file));

        self.entries.insert(path_buf.clone(), shared_file.clone());

        Ok(shared_file)
    }

    pub fn get_cached(&self, path: &Path) -> Option<Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>> {
        self.entries.get(path).map(|entry| entry.value().clone())
    }

    pub fn remove(&self, path: &Path) {
        self.entries.remove(path);
    }

    pub fn flush_all(&self) {
        for entry in self.entries.iter() {
            if let Ok(mut file) = entry.value().lock() {
                let _ = file.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use std::thread;

    use crate::crypto::cipher::{Aes256XtsCipher, ChunkCipher};
    use crate::utils::memory::SecureKey;

    // --- Helper ---
    // Génère un chiffreur factice valide pour les tests I/O
    fn dummy_cipher() -> Aes256XtsCipher {
        Aes256XtsCipher::new(SecureKey(vec![0x42; 64]))
    }

    /// TEST 1 : Vérification de la mécanique de Singleton (Égalité des pointeurs)
    /// L'OS peut demander à ouvrir le même fichier 10 fois. Le cache DOIT renvoyer
    /// exactement la même instance mémoire pour éviter la corruption (Access Denied).
    #[test]
    fn test_cache_singleton_behavior() {
        let cache = FileCache::new();
        let path = PathBuf::from("test_cache_singleton.enc");
        let _ = fs::remove_file(&path);

        // Première ouverture
        let file1 = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .expect("Échec ouverture 1");

        // Deuxième ouverture du MÊME fichier (sans truncate)
        let file2 = cache
            .get_or_open(&path, dummy_cipher(), false, true)
            .expect("Échec ouverture 2");

        // ASSERTION CRITIQUE : file1 et file2 DOIVENT pointer vers la même adresse mémoire
        assert!(
            Arc::ptr_eq(&file1, &file2),
            "FAIL: Le cache a créé deux instances distinctes pour le même fichier !"
        );

        // Il ne doit y avoir qu'une seule entrée dans le DashMap
        assert_eq!(cache.entries.len(), 1);

        let _ = fs::remove_file(&path);
    }

    /// TEST 2 : Comportement du mode Truncate (Éviction forcée)
    /// Si Windows demande d'écraser un fichier (Truncate), le cache doit détruire
    /// l'ancienne référence en RAM et en rouvrir une nouvelle propre.
    #[test]
    fn test_cache_truncate_forces_eviction() {
        let cache = FileCache::new();
        let path = PathBuf::from("test_cache_truncate.enc");
        let _ = fs::remove_file(&path);

        let file_old = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .unwrap();

        // On rouvre le fichier avec `truncate = true`
        let file_new = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .unwrap();

        // ASSERTION CRITIQUE : les pointeurs doivent être DIFFÉRENTS cette fois-ci
        assert!(
            !Arc::ptr_eq(&file_old, &file_new),
            "FAIL: Le mode truncate n'a pas évincé l'ancienne instance du cache !"
        );

        let _ = fs::remove_file(&path);
    }

    /// TEST 3 : Cycle de vie passif (get_cached) et suppression (remove)
    #[test]
    fn test_cache_passive_read_and_remove() {
        let cache = FileCache::new();
        let path = PathBuf::from("test_cache_lifecycle.enc");
        let _ = fs::remove_file(&path);

        // 1. Avant création, le cache doit renvoyer None sans I/O
        assert!(cache.get_cached(&path).is_none());

        // 2. Création
        let _ = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .unwrap();

        // 3. get_cached doit maintenant renvoyer Some (le fichier est en RAM)
        assert!(
            cache.get_cached(&path).is_some(),
            "FAIL: get_cached n'a pas trouvé le fichier fraîchement créé"
        );

        // 4. Suppression explicite
        cache.remove(&path);
        assert!(
            cache.get_cached(&path).is_none(),
            "FAIL: remove() n'a pas purgé le fichier du cache"
        );

        let _ = fs::remove_file(&path);
    }

    /// TEST 4 : Résistance à la concurrence massive (Race Conditions)
    /// Simule un explorateur de fichiers agressif (ex: macOS Finder) qui lance
    /// 20 threads simultanés pour lire le même fichier.
    #[test]
    fn test_cache_heavy_concurrency() {
        let cache = Arc::new(FileCache::new());
        let path = Arc::new(PathBuf::from("test_cache_concurrent.enc"));

        // Initialisation propre
        let _ = fs::remove_file(path.as_ref());
        let _ = cache
            .get_or_open(path.as_ref(), dummy_cipher(), true, true)
            .unwrap();

        let mut handles = vec![];

        // Lancement de 20 threads qui tentent d'accéder au même fichier
        for _ in 0..20 {
            let cache_clone = cache.clone();
            let path_clone = path.clone();

            handles.push(thread::spawn(move || {
                cache_clone
                    .get_or_open(path_clone.as_ref(), dummy_cipher(), false, true)
                    .unwrap()
            }));
        }

        // Récupération de tous les pointeurs
        let mut resolved_arcs = vec![];
        for handle in handles {
            resolved_arcs.push(handle.join().unwrap());
        }

        // ASSERTION CRITIQUE : Les 20 threads doivent partager EXACTEMENT le même pointeur Arc.
        // Si DashMap est mal utilisé, cela créerait des doublons.
        let reference_arc = &resolved_arcs[0];
        for arc in resolved_arcs.iter().skip(1) {
            assert!(
                Arc::ptr_eq(reference_arc, arc),
                "FAIL: Race condition détectée ! Plusieurs instances créées en parallèle."
            );
        }

        // Le DashMap final ne doit toujours contenir qu'une seule entrée logique.
        assert_eq!(cache.entries.len(), 1);

        let _ = fs::remove_file(path.as_ref());
    }

    /// TEST 5 : Sécurité du Flush global à l'extinction du serveur
    #[test]
    fn test_cache_flush_all() {
        let cache = FileCache::new();
        let path1 = PathBuf::from("test_flush_1.enc");
        let path2 = PathBuf::from("test_flush_2.enc");
        let _ = fs::remove_file(&path1);
        let _ = fs::remove_file(&path2);

        let _ = cache
            .get_or_open(&path1, dummy_cipher(), true, true)
            .unwrap();
        let _ = cache
            .get_or_open(&path2, dummy_cipher(), true, true)
            .unwrap();

        // Ne doit ni paniquer, ni créer de deadlock (verrouillage croisé)
        cache.flush_all();

        let _ = fs::remove_file(&path1);
        let _ = fs::remove_file(&path2);
    }
}
