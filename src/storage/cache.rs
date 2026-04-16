use dashmap::DashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::crypto::cipher::Aes256XtsCipher;
use crate::storage::chunk_io::EncryptedFile;

// --- ADDITION: Structured enum for custom errors ---
#[derive(Debug)]
pub enum CacheError {
    FileOpenFailed,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            CacheError::FileOpenFailed => {
                ("get_or_open", "failed to open or create encrypted file")
            }
        };
        write!(f, "mod: cache, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for CacheError {}
// ----------------------------------------------------------------------

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

        let file = EncryptedFile::open(path, cipher, truncate, write_access)
            .map_err(|e| io::Error::new(e.kind(), CacheError::FileOpenFailed))?;

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
    // Generates a valid dummy cipher for I/O tests
    fn dummy_cipher() -> Aes256XtsCipher {
        Aes256XtsCipher::new(SecureKey(vec![0x42; 64]))
    }

    /// TEST 1: Verifying Singleton mechanics (Pointer equality)
    /// The OS might request to open the same file 10 times. The cache MUST return
    /// the exact same memory instance to avoid corruption (Access Denied).
    #[test]
    fn test_cache_singleton_behavior() {
        let cache = FileCache::new();
        let path = PathBuf::from("test_cache_singleton.enc");
        let _ = fs::remove_file(&path);

        // First open
        let file1 = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .expect("Open failed 1");

        // Second open of the SAME file (without truncate)
        let file2 = cache
            .get_or_open(&path, dummy_cipher(), false, true)
            .expect("Open failed 2");

        // CRITICAL ASSERTION: file1 and file2 MUST point to the same memory address
        assert!(
            Arc::ptr_eq(&file1, &file2),
            "FAIL: The cache created two distinct instances for the same file!"
        );

        // There should be only one entry in the DashMap
        assert_eq!(cache.entries.len(), 1);

        let _ = fs::remove_file(&path);
    }

    /// TEST 2: Truncate mode behavior (Forced eviction)
    /// If Windows requests to overwrite a file (Truncate), the cache must destroy
    /// the old reference in RAM and open a fresh new one.
    #[test]
    fn test_cache_truncate_forces_eviction() {
        let cache = FileCache::new();
        let path = PathBuf::from("test_cache_truncate.enc");
        let _ = fs::remove_file(&path);

        let file_old = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .unwrap();

        // Reopen the file with `truncate = true`
        let file_new = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .unwrap();

        // CRITICAL ASSERTION: the pointers must be DIFFERENT this time
        assert!(
            !Arc::ptr_eq(&file_old, &file_new),
            "FAIL: Truncate mode did not evict the old instance from the cache!"
        );

        let _ = fs::remove_file(&path);
    }

    /// TEST 3: Passive lifecycle (get_cached) and removal (remove)
    #[test]
    fn test_cache_passive_read_and_remove() {
        let cache = FileCache::new();
        let path = PathBuf::from("test_cache_lifecycle.enc");
        let _ = fs::remove_file(&path);

        // 1. Before creation, the cache should return None without I/O
        assert!(cache.get_cached(&path).is_none());

        // 2. Creation
        let _ = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .unwrap();

        // 3. get_cached should now return Some (the file is in RAM)
        assert!(
            cache.get_cached(&path).is_some(),
            "FAIL: get_cached did not find the freshly created file"
        );

        // 4. Explicit removal
        cache.remove(&path);
        assert!(
            cache.get_cached(&path).is_none(),
            "FAIL: remove() did not purge the file from the cache"
        );

        let _ = fs::remove_file(&path);
    }

    /// TEST 4: Resistance to massive concurrency (Race Conditions)
    /// Simulates an aggressive file explorer (e.g., macOS Finder) launching
    /// 20 simultaneous threads to read the same file.
    #[test]
    fn test_cache_heavy_concurrency() {
        let cache = Arc::new(FileCache::new());
        let path = Arc::new(PathBuf::from("test_cache_concurrent.enc"));

        // Clean initialization
        let _ = fs::remove_file(path.as_ref());
        let _ = cache
            .get_or_open(path.as_ref(), dummy_cipher(), true, true)
            .unwrap();

        let mut handles = vec![];

        // Launch 20 threads trying to access the same file
        for _ in 0..20 {
            let cache_clone = cache.clone();
            let path_clone = path.clone();

            handles.push(thread::spawn(move || {
                cache_clone
                    .get_or_open(path_clone.as_ref(), dummy_cipher(), false, true)
                    .unwrap()
            }));
        }

        // Retrieve all pointers
        let mut resolved_arcs = vec![];
        for handle in handles {
            resolved_arcs.push(handle.join().unwrap());
        }

        // CRITICAL ASSERTION: All 20 threads must share EXACTLY the same Arc pointer.
        // If DashMap is misused, this would create duplicates.
        let reference_arc = &resolved_arcs[0];
        for arc in resolved_arcs.iter().skip(1) {
            assert!(
                Arc::ptr_eq(reference_arc, arc),
                "FAIL: Race condition detected! Multiple instances created in parallel."
            );
        }

        // The final DashMap must still contain only one logical entry.
        assert_eq!(cache.entries.len(), 1);

        let _ = fs::remove_file(path.as_ref());
    }

    /// TEST 5: Safety of global Flush on server shutdown
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

        // Must not panic, nor create a deadlock (cross-locking)
        cache.flush_all();

        let _ = fs::remove_file(&path1);
        let _ = fs::remove_file(&path2);
    }
}
