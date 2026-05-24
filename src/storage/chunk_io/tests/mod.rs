//! Test module for `EncryptedFile`. Shared fixtures live here; the actual
//! `#[test]` functions are grouped by concern in sibling files:
//!
//! - `io`        — read/write/seek/truncate semantics
//! - `integrity` — HMAC verification, tampering detection, swap attack

use super::*;
use crate::crypto::cipher::{Aes256XtsCipher, ChunkCipher};
use crate::utils::memory::SecureKey;
use std::fs;

mod integrity;
mod io;

pub(super) fn dummy_xts_key() -> SecureKey {
    SecureKey(vec![0x42; 64])
}

pub(super) fn dummy_mac_key() -> SecureKey {
    SecureKey(vec![0xA5; 32])
}

pub(super) fn dummy_aad(path: &str) -> Vec<u8> {
    path.as_bytes().to_vec()
}

pub(super) fn setup_test_file(path: &str) -> EncryptedFile<Aes256XtsCipher> {
    let _ = fs::remove_file(path);
    EncryptedFile::open(
        path,
        Aes256XtsCipher::new(dummy_xts_key()),
        dummy_mac_key(),
        dummy_aad(path),
        true,
        true,
    )
    .unwrap()
}
