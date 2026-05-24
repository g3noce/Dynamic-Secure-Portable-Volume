//! Tests for the WebDAV filesystem layer. Split into:
//!
//! - `io`       — end-to-end read/write/seek/append/truncate lifecycle
//! - `fs_ops`   — directory listing, copy, rename, delete
//! - `metadata` — metadata resolution (RAM cache vs physical header) + quota
//! - `security` — `dspv.meta` filtering, swap-attack detection, rename re-MAC

use super::*;
use std::fs;
use std::sync::Arc;

use crate::storage::cache::FileCache;
use crate::utils::memory::SecureKey;

mod bugs;
mod fs_ops;
mod io;
mod metadata;
mod security;

/// Build a fresh `WebDavFS` rooted at `dir_name`. Returns the master key as
/// well so a few tests that need direct access to it can re-use it.
pub(super) fn setup_test_env(dir_name: &str) -> (WebDavFS, SecureKey) {
    let _ = fs::remove_dir_all(dir_name);
    fs::create_dir_all(dir_name).unwrap();
    // 96 bytes: first 64 → AES-XTS halves, last 32 → HMAC key.
    let mut master_key_bytes = vec![0x42u8; 64];
    master_key_bytes.extend_from_slice(&[0xA5u8; 32]);
    let master_key = SecureKey(master_key_bytes);
    let cache = Arc::new(FileCache::new());
    (
        WebDavFS::new(dir_name, master_key.clone(), cache),
        master_key,
    )
}
