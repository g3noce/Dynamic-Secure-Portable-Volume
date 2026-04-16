use dashmap::DashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::crypto::cipher::ChaChaPolyCipher;
use crate::storage::chunk_io::EncryptedFile;

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

struct CacheEntry {
    file: Arc<Mutex<EncryptedFile<ChaChaPolyCipher>>>,
    last_accessed: Instant,
}

pub struct FileCache {
    entries: DashMap<PathBuf, CacheEntry>,
    max_capacity: usize,
}

impl FileCache {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            entries: DashMap::new(),
            max_capacity,
        }
    }

    pub fn get_or_open(
        &self,
        path: &Path,
        cipher: ChaChaPolyCipher,
        truncate: bool,
        write_access: bool,
    ) -> io::Result<Arc<Mutex<EncryptedFile<ChaChaPolyCipher>>>> {
        let path_buf = path.to_path_buf();

        if truncate {
            self.entries.remove(&path_buf);
        }

        if let Some(mut entry) = self.entries.get_mut(&path_buf) {
            entry.last_accessed = Instant::now();
            return Ok(entry.file.clone());
        }

        if self.entries.len() >= self.max_capacity {
            self.evict_oldest();
        }

        let file = EncryptedFile::open(path, cipher, truncate, write_access)
            .map_err(|e| io::Error::new(e.kind(), CacheError::FileOpenFailed))?;

        let shared_file = Arc::new(Mutex::new(file));

        self.entries.insert(
            path_buf.clone(),
            CacheEntry {
                file: shared_file.clone(),
                last_accessed: Instant::now(),
            },
        );

        Ok(shared_file)
    }

    pub fn get_cached(&self, path: &Path) -> Option<Arc<Mutex<EncryptedFile<ChaChaPolyCipher>>>> {
        if let Some(mut entry) = self.entries.get_mut(path) {
            entry.last_accessed = Instant::now();
            Some(entry.file.clone())
        } else {
            None
        }
    }

    pub fn remove(&self, path: &Path) {
        self.entries.remove(path);
    }

    pub fn flush_all(&self) {
        for entry in self.entries.iter() {
            if let Ok(mut file) = entry.value().file.lock() {
                let _ = file.flush();
            }
        }
    }

    fn evict_oldest(&self) {
        let mut oldest_path = None;
        let mut oldest_time = None;

        for entry in self.entries.iter() {
            let time = entry.value().last_accessed;
            if oldest_time.is_none_or(|t| time < t) {
                oldest_time = Some(time);
                oldest_path = Some(entry.key().clone());
            }
        }

        if let Some(path) = oldest_path
            && let Some((_, entry)) = self.entries.remove(&path)
            && let Ok(mut file) = entry.file.lock()
        {
            let _ = file.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use crate::crypto::cipher::{AuthenticatedChunkCipher, ChaChaPolyCipher};
    use crate::utils::memory::SecureKey;

    // --- Helper ---
    fn dummy_cipher() -> ChaChaPolyCipher {
        ChaChaPolyCipher::new(SecureKey(vec![0x42; 32]))
    }

    /// TEST 1: Singleton behavior and Truncation replacement
    /// Ensures we don't open multiple file descriptors for the same path,
    /// unless explicitly truncated.
    #[test]
    fn test_cache_singleton_and_truncate() {
        let cache = FileCache::new(10);
        let path = PathBuf::from("test_cache_singleton.enc");
        let _ = fs::remove_file(&path);

        // First open
        let file1 = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .unwrap();

        // Second open (should return the exact same Arc)
        let file2 = cache
            .get_or_open(&path, dummy_cipher(), false, true)
            .unwrap();
        assert!(
            Arc::ptr_eq(&file1, &file2),
            "Cache should return the same instance for the same path"
        );

        // Third open with truncate (should evict and create a new instance)
        let file_truncated = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .unwrap();
        assert!(
            !Arc::ptr_eq(&file1, &file_truncated),
            "Truncate must replace the cached instance"
        );

        let _ = fs::remove_file(&path);
    }

    /// TEST 2: Least Recently Used (LRU) Eviction
    /// Verifies that the cache correctly drops the oldest accessed file when capacity is reached.
    #[test]
    fn test_cache_capacity_eviction() {
        let cache = FileCache::new(2); // Strict capacity of 2
        let p1 = PathBuf::from("evict_1.enc");
        let p2 = PathBuf::from("evict_2.enc");
        let p3 = PathBuf::from("evict_3.enc");

        let _ = fs::remove_file(&p1);
        let _ = fs::remove_file(&p2);
        let _ = fs::remove_file(&p3);

        let _ = cache.get_or_open(&p1, dummy_cipher(), true, true).unwrap();
        thread::sleep(Duration::from_millis(10)); // Ensure distinct timestamps

        let _ = cache.get_or_open(&p2, dummy_cipher(), true, true).unwrap();

        // Touch p1 again so p2 becomes the oldest
        let _ = cache.get_cached(&p1).unwrap();
        thread::sleep(Duration::from_millis(10));

        // Opening p3 should evict p2, as p1 was just accessed
        let _ = cache.get_or_open(&p3, dummy_cipher(), true, true).unwrap();

        assert!(
            cache.get_cached(&p1).is_some(),
            "p1 should still be cached (recently accessed)"
        );
        assert!(
            cache.get_cached(&p2).is_none(),
            "p2 should be evicted (oldest)"
        );
        assert!(
            cache.get_cached(&p3).is_some(),
            "p3 should be cached (newest)"
        );

        let _ = fs::remove_file(&p1);
        let _ = fs::remove_file(&p2);
        let _ = fs::remove_file(&p3);
    }

    /// TEST 3: Lifecycle, explicit removal, and flushing
    #[test]
    fn test_cache_lifecycle_and_flush() {
        let cache = FileCache::new(5);
        let path = PathBuf::from("test_lifecycle.enc");
        let _ = fs::remove_file(&path);

        assert!(cache.get_cached(&path).is_none());

        let _ = cache
            .get_or_open(&path, dummy_cipher(), true, true)
            .unwrap();
        assert!(cache.get_cached(&path).is_some());

        // Ensure global flush executes without panicking or deadlocking
        cache.flush_all();

        cache.remove(&path);
        assert!(
            cache.get_cached(&path).is_none(),
            "Explicit remove should purge the file"
        );

        let _ = fs::remove_file(&path);
    }

    /// TEST 4: Heavy Concurrency
    /// Proves the DashMap usage safely prevents race conditions during parallel access.
    #[test]
    fn test_cache_heavy_concurrency() {
        let cache = Arc::new(FileCache::new(10));
        let path = Arc::new(PathBuf::from("test_concurrent.enc"));
        let _ = fs::remove_file(path.as_ref());

        // Pre-initialize the file
        let _ = cache
            .get_or_open(path.as_ref(), dummy_cipher(), true, true)
            .unwrap();

        let mut handles = vec![];

        for _ in 0..20 {
            let cache_clone = cache.clone();
            let path_clone = path.clone();

            handles.push(thread::spawn(move || {
                cache_clone
                    .get_or_open(path_clone.as_ref(), dummy_cipher(), false, true)
                    .unwrap()
            }));
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Ensure all 20 threads received the exact same underlying Arc<Mutex<EncryptedFile>>
        let reference_arc = &results[0];
        for res in results.iter().skip(1) {
            assert!(
                Arc::ptr_eq(reference_arc, res),
                "Race condition detected: Multiple instances spawned concurrently"
            );
        }

        assert_eq!(cache.entries.len(), 1, "Cache should only contain 1 entry");

        let _ = fs::remove_file(path.as_ref());
    }
}
