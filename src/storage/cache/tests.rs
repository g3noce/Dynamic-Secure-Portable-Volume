use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use crate::crypto::cipher::{Aes256XtsCipher, ChunkCipher};
use crate::utils::memory::SecureKey;

fn dummy_cipher() -> Aes256XtsCipher {
    Aes256XtsCipher::new(SecureKey(vec![0x42; 64]))
}

fn dummy_mac_key() -> SecureKey {
    SecureKey(vec![0xA5; 32])
}

fn dummy_aad() -> Vec<u8> {
    b"cache-test-aad".to_vec()
}

/// TEST 1: Verifying Singleton mechanics (Pointer equality)
#[test]
fn test_cache_singleton_behavior() {
    let cache = FileCache::new();
    let path = PathBuf::from("test_cache_singleton.enc");
    let _ = fs::remove_file(&path);

    let file1 = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), true, true)
        .expect("Open failed 1");

    let file2 = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), false, true)
        .expect("Open failed 2");

    assert!(
        Arc::ptr_eq(&file1, &file2),
        "FAIL: The cache created two distinct instances for the same file!"
    );

    assert_eq!(cache.entries.len(), 1);

    let _ = fs::remove_file(&path);
}

/// TEST 2: Truncate mode behavior (Forced eviction)
#[test]
fn test_cache_truncate_forces_eviction() {
    let cache = FileCache::new();
    let path = PathBuf::from("test_cache_truncate.enc");
    let _ = fs::remove_file(&path);

    let file_old = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), true, true)
        .unwrap();

    let file_new = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), true, true)
        .unwrap();

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

    assert!(cache.get_cached(&path).is_none());

    let _ = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), true, true)
        .unwrap();

    assert!(
        cache.get_cached(&path).is_some(),
        "FAIL: get_cached did not find the freshly created file"
    );

    cache.remove(&path);
    assert!(
        cache.get_cached(&path).is_none(),
        "FAIL: remove() did not purge the file from the cache"
    );

    let _ = fs::remove_file(&path);
}

/// TEST 4 (P1): Per-path creation locks must NOT serialize unrelated paths.
///
/// Both threads spin in `get_or_open` while a `Barrier` makes them call into
/// the cache at the same instant. Each thread inserts after `EncryptedFile::open`
/// returns, so we infer "did they run concurrently" by checking that both
/// finished — if the implementation had a shared lock, one would block waiting
/// on the other but both still finish, so we additionally probe the
/// `creation_locks` map after the race to ensure each path got its own lock
/// (which is impossible if a single global lock were used).
#[test]
fn test_cache_cold_opens_use_per_path_locks() {
    use std::sync::Barrier;

    let cache = Arc::new(FileCache::new());
    let path_a = Arc::new(PathBuf::from("test_cache_per_path_a.enc"));
    let path_b = Arc::new(PathBuf::from("test_cache_per_path_b.enc"));
    let _ = fs::remove_file(path_a.as_ref());
    let _ = fs::remove_file(path_b.as_ref());

    let barrier = Arc::new(Barrier::new(2));

    let cache_a = cache.clone();
    let path_a_t = path_a.clone();
    let barrier_a = barrier.clone();
    let h_a = thread::spawn(move || {
        barrier_a.wait();
        cache_a
            .get_or_open(
                path_a_t.as_ref(),
                dummy_cipher(),
                dummy_mac_key(),
                dummy_aad(),
                true,
                true,
            )
            .unwrap();
    });
    let cache_b = cache.clone();
    let path_b_t = path_b.clone();
    let barrier_b = barrier.clone();
    let h_b = thread::spawn(move || {
        barrier_b.wait();
        cache_b
            .get_or_open(
                path_b_t.as_ref(),
                dummy_cipher(),
                dummy_mac_key(),
                dummy_aad(),
                true,
                true,
            )
            .unwrap();
    });
    h_a.join().unwrap();
    h_b.join().unwrap();

    // Each distinct path must have minted its own creation lock. With a single
    // shared lock this map would contain at most one entry.
    assert!(
        cache.creation_locks.len() >= 2,
        "Both paths should have their own creation lock (got {})",
        cache.creation_locks.len()
    );
    assert_eq!(
        cache.entries.len(),
        2,
        "Both paths should be cached after parallel cold-opens"
    );

    let _ = fs::remove_file(path_a.as_ref());
    let _ = fs::remove_file(path_b.as_ref());
}

/// TEST 5 (P0): Cold-path race — many threads race to open the SAME fresh
/// path at the same time. Before the entry()-based fix, threads could each
/// create their own EncryptedFile and clobber each other; now they must all
/// converge on a single Arc.
#[test]
fn test_cache_cold_path_race_produces_single_instance() {
    let cache = Arc::new(FileCache::new());
    let path = Arc::new(PathBuf::from("test_cache_cold_race.enc"));
    let _ = fs::remove_file(path.as_ref());

    // Synchronize all threads at a barrier so the race window is widened.
    use std::sync::Barrier;
    let barrier = Arc::new(Barrier::new(32));

    let mut handles = vec![];
    for _ in 0..32 {
        let cache = cache.clone();
        let path = path.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            cache
                .get_or_open(path.as_ref(), dummy_cipher(), dummy_mac_key(), dummy_aad(), false, true)
                .unwrap()
        }));
    }

    let resolved: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let reference = &resolved[0];
    for arc in resolved.iter().skip(1) {
        assert!(
            Arc::ptr_eq(reference, arc),
            "FAIL: cold-path race produced multiple EncryptedFile instances; cache split-brain."
        );
    }
    assert_eq!(
        cache.entries.len(),
        1,
        "FAIL: cold-path race left more than one cache entry for the same path."
    );

    let _ = fs::remove_file(path.as_ref());
}

/// TEST 5: Resistance to massive concurrency (Race Conditions)
#[test]
fn test_cache_heavy_concurrency() {
    let cache = Arc::new(FileCache::new());
    let path = Arc::new(PathBuf::from("test_cache_concurrent.enc"));

    let _ = fs::remove_file(path.as_ref());
    let _ = cache
        .get_or_open(path.as_ref(), dummy_cipher(), dummy_mac_key(), dummy_aad(), true, true)
        .unwrap();

    let mut handles = vec![];

    for _ in 0..20 {
        let cache_clone = cache.clone();
        let path_clone = path.clone();

        handles.push(thread::spawn(move || {
            cache_clone
                .get_or_open(path_clone.as_ref(), dummy_cipher(), dummy_mac_key(), dummy_aad(), false, true)
                .unwrap()
        }));
    }

    let mut resolved_arcs = vec![];
    for handle in handles {
        resolved_arcs.push(handle.join().unwrap());
    }

    let reference_arc = &resolved_arcs[0];
    for arc in resolved_arcs.iter().skip(1) {
        assert!(
            Arc::ptr_eq(reference_arc, arc),
            "FAIL: Race condition detected! Multiple instances created in parallel."
        );
    }

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
        .get_or_open(&path1, dummy_cipher(), dummy_mac_key(), dummy_aad(), true, true)
        .unwrap();
    let _ = cache
        .get_or_open(&path2, dummy_cipher(), dummy_mac_key(), dummy_aad(), true, true)
        .unwrap();

    cache.flush_all();

    let _ = fs::remove_file(&path1);
    let _ = fs::remove_file(&path2);
}

/// TEST 6 (P1): Idle sweep evicts entries past the timeout but keeps the file
/// alive for any caller still holding an `Arc`.
#[test]
fn test_cache_idle_eviction_releases_cache_slot() {
    let cache = FileCache::new();
    let path = PathBuf::from("test_cache_idle.enc");
    let _ = fs::remove_file(&path);

    let handle = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), true, true)
        .unwrap();
    assert_eq!(cache.entries.len(), 1);

    // Caller still holds `handle` — sweep must drop the cache entry but keep
    // the file usable via the outstanding Arc.
    cache.force_sweep();
    assert_eq!(
        cache.entries.len(),
        0,
        "Idle sweep failed to release the cache slot"
    );
    assert!(
        Arc::strong_count(&handle) >= 1,
        "Outstanding handle was destroyed by sweep"
    );

    // A subsequent open re-populates the cache (cold path).
    let _ = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), false, true)
        .unwrap();
    assert_eq!(cache.entries.len(), 1);

    let _ = fs::remove_file(&path);
}

/// TEST 7 (P1): If a file is first cached read-only, a later write request must
/// evict and reopen with write access so writes actually reach the disk.
#[test]
fn test_cache_promotes_readonly_to_writable() {
    let cache = FileCache::new();
    let path = PathBuf::from("test_cache_promote.enc");
    let _ = fs::remove_file(&path);

    // Bootstrap a file that actually exists on disk so the read-only open succeeds.
    {
        let _ = cache
            .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), true, true)
            .unwrap();
        cache.remove(&path);
    }

    let ro = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), false, false)
        .unwrap();
    let rw = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), false, true)
        .unwrap();

    assert!(
        !Arc::ptr_eq(&ro, &rw),
        "FAIL: write request reused a read-only cached handle; writes would silently fail on the OS handle"
    );

    // A subsequent read request should now reuse the writable handle.
    let ro2 = cache
        .get_or_open(&path, dummy_cipher(), dummy_mac_key(), dummy_aad(), false, false)
        .unwrap();
    assert!(
        Arc::ptr_eq(&rw, &ro2),
        "Writable cached entry must serve subsequent read-only requests"
    );

    let _ = fs::remove_file(&path);
}
