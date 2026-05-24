use dashmap::DashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::cipher::Aes256XtsCipher;
use crate::storage::cache::errors::CacheError;
use crate::storage::chunk_io::EncryptedFile;
use crate::utils::memory::SecureKey;

/// Entries idle for more than this duration are dropped on the next access.
const IDLE_TIMEOUT_SECS: u64 = 300;
/// Minimum spacing between two sweeps, so heavy traffic doesn't pay the scan cost.
const SWEEP_INTERVAL_SECS: u64 = 30;

#[derive(Clone)]
pub(super) struct CacheEntry {
    pub(super) file: Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>,
    /// Whether the underlying `File` handle was opened with write access.
    /// A read-only handle cannot serve later write requests, so the entry must
    /// be evicted and reopened in that case.
    pub(super) writable: bool,
    /// Unix-epoch seconds of the last `get_or_open` hit. Used by `sweep_idle`.
    last_access: Arc<AtomicU64>,
}

impl CacheEntry {
    fn new(file: Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>, writable: bool) -> Self {
        Self {
            file,
            writable,
            last_access: Arc::new(AtomicU64::new(now_secs())),
        }
    }

    fn touch(&self) {
        self.last_access.store(now_secs(), Ordering::Relaxed);
    }

    fn idle_for(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_access.load(Ordering::Relaxed))
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct FileCache {
    pub(super) entries: DashMap<PathBuf, CacheEntry>,
    /// Per-path serialization lock for the cold-create path. We hold this
    /// instead of a DashMap bucket lock so that `EncryptedFile::open` (which
    /// streams the whole file to verify the MAC) doesn't block accesses to
    /// other paths that happen to hash to the same shard.
    pub(super) creation_locks: DashMap<PathBuf, Arc<Mutex<()>>>,
    last_sweep: AtomicU64,
}

impl Default for FileCache {
    fn default() -> Self {
        Self::new()
    }
}

impl FileCache {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            creation_locks: DashMap::new(),
            last_sweep: AtomicU64::new(now_secs()),
        }
    }

    /// Fast read-only probe — returns the cached entry if it can satisfy the
    /// requested access mode without re-opening.
    fn try_reuse(
        &self,
        path: &Path,
        write_access: bool,
    ) -> Option<Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>> {
        let entry = self.entries.get(path)?;
        if !write_access || entry.writable {
            entry.touch();
            Some(entry.file.clone())
        } else {
            None
        }
    }

    pub fn get_or_open(
        &self,
        path: &Path,
        cipher: Aes256XtsCipher,
        mac_key: SecureKey,
        mac_aad: Vec<u8>,
        truncate: bool,
        write_access: bool,
    ) -> io::Result<Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>> {
        self.maybe_sweep();

        let path_buf = path.to_path_buf();

        if truncate {
            // Poisonner le handle existant avant de l'évincer : un lecteur
            // encore en vie qui lirait après le truncate obtiendrait du chiffré
            // sous un nouvel IV et produirait du garbage silencieux. En le
            // marquant poisoned ici (dans le verrou du Mutex), sa prochaine
            // opération I/O retourne une erreur explicite.
            if let Some((_, old_entry)) = self.entries.remove(&path_buf) {
                if let Ok(mut old_file) = old_entry.file.lock() {
                    old_file.poison();
                }
            }
        }

        // Phase 1 — optimistic check: if the cached entry already satisfies us,
        // return it without taking any creation lock. Hot path: zero contention
        // across paths/shards.
        if !truncate
            && let Some(file) = self.try_reuse(&path_buf, write_access)
        {
            return Ok(file);
        }

        // Phase 2 — acquire (or mint) the per-path creation lock. Holding this
        // serializes concurrent first-opens of the same path while leaving
        // every other path untouched.
        let creation_lock = self
            .creation_locks
            .entry(path_buf.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _create_guard = creation_lock
            .lock()
            .map_err(|_| io::Error::other(CacheError::FileOpenFailed))?;

        // Phase 3 — re-check inside the per-path critical section. Another
        // thread that was racing us may have populated the cache while we
        // were waiting for the lock.
        if !truncate
            && let Some(file) = self.try_reuse(&path_buf, write_access)
        {
            return Ok(file);
        }

        // Cached entry exists but can't satisfy the requested access (read-only
        // entry vs write request): evict it before recreating.
        if self.entries.contains_key(&path_buf) {
            self.entries.remove(&path_buf);
        }

        // Phase 4 — perform the actual (potentially slow) MAC-verified open.
        // The DashMap is unlocked here, so other paths/shards proceed freely.
        let file = EncryptedFile::open(path, cipher, mac_key, mac_aad, truncate, write_access)
            .map_err(|e| io::Error::new(e.kind(), CacheError::FileOpenFailed))?;
        let shared_file = Arc::new(Mutex::new(file));

        // Phase 5 — publish to the cache. A simple `insert` is fine because we
        // hold the per-path creation lock; no other thread can be inserting at
        // the same key concurrently.
        self.entries.insert(
            path_buf,
            CacheEntry::new(shared_file.clone(), write_access),
        );

        Ok(shared_file)
    }

    pub fn get_cached(&self, path: &Path) -> Option<Arc<Mutex<EncryptedFile<Aes256XtsCipher>>>> {
        self.entries.get(path).map(|entry| {
            entry.touch();
            entry.file.clone()
        })
    }

    pub fn remove(&self, path: &Path) {
        self.entries.remove(path);
        // Drop the creation lock too. Any thread currently holding a clone of
        // the Arc keeps the underlying Mutex alive; we just sever the map's
        // reference so subsequent reopens mint a fresh lock.
        self.creation_locks.remove(path);
    }

    pub fn flush_all(&self) {
        for entry in self.entries.iter() {
            if let Ok(mut file) = entry.value().file.lock() {
                let _ = file.flush();
            }
        }
    }

    /// Drop cache entries whose last access is older than `IDLE_TIMEOUT_SECS`.
    /// The underlying `EncryptedFile` stays alive as long as someone else holds
    /// the `Arc` returned by `get_or_open`; we only release the cache's own
    /// reference (and the OS file handle once everyone is done).
    fn maybe_sweep(&self) {
        let now = now_secs();
        let last = self.last_sweep.load(Ordering::Relaxed);
        if now.saturating_sub(last) < SWEEP_INTERVAL_SECS {
            return;
        }
        // Best-effort CAS: if two threads race here, only one performs the sweep.
        if self
            .last_sweep
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.sweep_idle(now);
    }

    fn sweep_idle(&self, now: u64) {
        let stale: Vec<PathBuf> = self
            .entries
            .iter()
            .filter(|e| e.value().idle_for(now) >= IDLE_TIMEOUT_SECS)
            .map(|e| e.key().clone())
            .collect();

        for path in stale {
            if let Some((_, entry)) = self.entries.remove(&path)
                && let Ok(mut file) = entry.file.lock()
            {
                let _ = file.flush();
            }
            // Garbage-collect the per-path creation lock alongside the entry.
            self.creation_locks.remove(&path);
        }
    }

    /// Test-only helper: force an eviction pass.
    #[cfg(test)]
    pub(super) fn force_sweep(&self) {
        self.sweep_idle(now_secs() + IDLE_TIMEOUT_SECS + 1);
    }
}
