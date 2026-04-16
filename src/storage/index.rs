use crate::crypto::cipher::{AuthenticatedChunkCipher, ChaChaPolyCipher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IndexEntry {
    pub physical_id: String,
    pub is_dir: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub struct FileIndex {
    pub entries: HashMap<PathBuf, IndexEntry>,
}

pub struct IndexManager {
    pub index: FileIndex,
    pub path: PathBuf,
}

impl IndexManager {
    pub fn load_or_create(root: &Path, cipher: &ChaChaPolyCipher) -> io::Result<Self> {
        let index_path = root.join("index.db");
        if !index_path.exists() {
            return Ok(Self {
                index: FileIndex::default(),
                path: index_path,
            });
        }

        let mut file = std::fs::File::open(&index_path)?;
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)?;

        let clear_data = cipher
            .decrypt_chunk(&[0u8; 16], u64::MAX, &encrypted_data)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Index corruption"))?;

        let index: FileIndex = serde_json::from_slice(&clear_data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Self {
            index,
            path: index_path,
        })
    }

    pub fn save(&self, cipher: &ChaChaPolyCipher) -> io::Result<()> {
        let clear_data = serde_json::to_vec(&self.index).map_err(io::Error::other)?;

        let encrypted_data = cipher
            .encrypt_chunk(&[0u8; 16], u64::MAX, &clear_data)
            .map_err(|_| io::Error::other("Encryption failed"))?;

        let mut file = std::fs::File::create(&self.path)?;
        file.write_all(&encrypted_data)?;
        Ok(())
    }

    pub fn get_physical_path(&self, logical_path: &Path, root: &Path) -> Option<PathBuf> {
        if logical_path == Path::new("/") || logical_path == Path::new("") {
            return Some(root.to_path_buf());
        }
        self.index
            .entries
            .get(logical_path)
            .map(|e| root.join(&e.physical_id))
    }

    pub fn add_entry(&mut self, logical_path: PathBuf, is_dir: bool) -> String {
        let id = Uuid::new_v4().to_string();
        self.index.entries.insert(
            logical_path,
            IndexEntry {
                physical_id: id.clone(),
                is_dir,
            },
        );
        id
    }

    pub fn remove_entry(&mut self, logical_path: &Path) -> Option<IndexEntry> {
        self.index.entries.remove(logical_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::memory::SecureKey;
    use std::fs;

    // --- Helper ---
    // Manages an isolated temporary directory for index database testing
    struct TestEnv {
        pub root: PathBuf,
    }

    impl TestEnv {
        fn new(dir_name: &str) -> Self {
            let root = PathBuf::from(dir_name);
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn cipher(&self) -> ChaChaPolyCipher {
            ChaChaPolyCipher::new(SecureKey(vec![0x42; 32]))
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// TEST 1: In-Memory Operations & Root Handling
    /// Verifies adding, removing, and resolving logical paths to physical UUIDs.
    #[test]
    fn test_index_in_memory_crud() {
        let env = TestEnv::new("test_index_crud");
        let mut manager = IndexManager::load_or_create(&env.root, &env.cipher()).unwrap();

        let logical_file = PathBuf::from("documents/secret.txt");
        let logical_dir = PathBuf::from("documents");

        // 1. Add Entries
        let file_id = manager.add_entry(logical_file.clone(), false);
        let dir_id = manager.add_entry(logical_dir.clone(), true);

        assert!(!file_id.is_empty());
        assert_ne!(file_id, dir_id, "UUIDs must be unique");

        // 2. Resolve Paths
        let phys_file = manager.get_physical_path(&logical_file, &env.root).unwrap();
        assert_eq!(phys_file, env.root.join(&file_id));

        // 3. Special Case: Root resolution
        let root_phys = manager
            .get_physical_path(Path::new("/"), &env.root)
            .unwrap();
        assert_eq!(
            root_phys, env.root,
            "The logical root must map directly to the physical root"
        );

        // 4. Remove Entry
        let removed = manager.remove_entry(&logical_file);
        assert!(removed.is_some());
        assert!(!removed.unwrap().is_dir);
        assert!(manager
            .get_physical_path(&logical_file, &env.root)
            .is_none());
    }

    /// TEST 2: Encryption and Persistence Lifecycle
    /// Ensures the index can safely be serialized, encrypted to disk, and fully restored.
    #[test]
    fn test_index_persistence_lifecycle() {
        let env = TestEnv::new("test_index_persistence");
        let logical_path = PathBuf::from("persisted_file.bin");
        let generated_id;

        // Phase 1: Create and Save
        {
            let mut manager = IndexManager::load_or_create(&env.root, &env.cipher()).unwrap();
            generated_id = manager.add_entry(logical_path.clone(), false);
            manager
                .save(&env.cipher())
                .expect("Failed to save encrypted index");
        } // Manager is dropped here

        assert!(
            env.root.join("index.db").exists(),
            "The database file must be created on disk"
        );

        // Phase 2: Load and Verify
        {
            let manager2 = IndexManager::load_or_create(&env.root, &env.cipher()).unwrap();

            let restored_entry = manager2
                .index
                .entries
                .get(&logical_path)
                .expect("Entry was lost during save/load");
            assert_eq!(
                restored_entry.physical_id, generated_id,
                "Physical UUID mismatch after restore"
            );
            assert!(!restored_entry.is_dir);
        }
    }

    /// TEST 3: Database Tampering Resilience
    /// Ensures that an externally modified or corrupted `index.db` will not be parsed
    /// and will cleanly throw an IO Error due to MAC validation failure.
    #[test]
    fn test_index_tamper_rejection() {
        use std::io::Seek; // Import requis pour pouvoir utiliser .seek()

        let env = TestEnv::new("test_index_tamper");

        // Setup a valid saved database
        let mut manager = IndexManager::load_or_create(&env.root, &env.cipher()).unwrap();
        manager.add_entry(PathBuf::from("test"), false);
        manager.save(&env.cipher()).unwrap();

        // Tamper with the physical file (simulate disk corruption or malicious edit)
        let db_path = env.root.join("index.db");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&db_path)
            .unwrap();
        // Seek past the 24-byte nonce to alter the actual ciphertext/MAC
        file.seek(std::io::SeekFrom::Start(30)).unwrap();
        file.write_all(&[0xFF]).unwrap();
        drop(file);

        // Attempt to load the tampered database
        let result = IndexManager::load_or_create(&env.root, &env.cipher());

        assert!(
            result.is_err(),
            "CRITICAL: The index manager loaded a tampered database without failing!"
        );

        assert_eq!(
            result.err().unwrap().kind(),
            std::io::ErrorKind::InvalidData,
            "Tampered data must map to an InvalidData IO error"
        );
    }
}
