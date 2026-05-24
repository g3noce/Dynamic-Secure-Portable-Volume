//! HMAC-based integrity tests: roundtrip, tampering detection, swap attack.

use super::super::*;
use super::{dummy_aad, dummy_mac_key, dummy_xts_key};
use crate::crypto::cipher::{Aes256XtsCipher, ChunkCipher};
use crate::storage::header::HEADER_SIZE;
use crate::utils::memory::SecureKey;
use std::fs;

/// A file written, closed, then reopened with the same keys must pass MAC
/// verification and yield the original plaintext.
#[test]
fn test_chunk_io_mac_roundtrip() {
    let path = "test_mac_roundtrip.enc";
    let _ = fs::remove_file(path);

    {
        let mut f = EncryptedFile::open(
            path,
            Aes256XtsCipher::new(dummy_xts_key()),
            dummy_mac_key(),
            dummy_aad(path),
            true,
            true,
        )
        .unwrap();
        f.write_chunk(0, b"trusted payload").unwrap();
        f.flush().unwrap();
    }

    let mut f = EncryptedFile::open(
        path,
        Aes256XtsCipher::new(dummy_xts_key()),
        dummy_mac_key(),
        dummy_aad(path),
        false,
        false,
    )
    .unwrap();
    let result = f.read_chunk(0, 15).unwrap();
    assert_eq!(result.0.as_slice(), b"trusted payload");

    let _ = fs::remove_file(path);
}

/// Flipping one ciphertext byte on disk must make a subsequent open fail —
/// XTS alone cannot detect this kind of tampering.
#[test]
fn test_chunk_io_mac_detects_ciphertext_tampering() {
    let path = "test_mac_tamper.enc";
    let _ = fs::remove_file(path);

    {
        let mut f = EncryptedFile::open(
            path,
            Aes256XtsCipher::new(dummy_xts_key()),
            dummy_mac_key(),
            dummy_aad(path),
            true,
            true,
        )
        .unwrap();
        f.write_chunk(0, &[b'X'; 256]).unwrap();
        f.flush().unwrap();
    }

    // Flip a single byte in the ciphertext region (past the 64-byte header).
    {
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut handle = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        handle.seek(SeekFrom::Start(HEADER_SIZE + 8)).unwrap();
        let mut byte = [0u8; 1];
        handle.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x01;
        handle.seek(SeekFrom::Start(HEADER_SIZE + 8)).unwrap();
        handle.write_all(&byte).unwrap();
    }

    let result = EncryptedFile::open(
        path,
        Aes256XtsCipher::new(dummy_xts_key()),
        dummy_mac_key(),
        dummy_aad(path),
        false,
        false,
    );
    assert!(
        result.is_err(),
        "CRITICAL: ciphertext tampering went undetected by the MAC layer"
    );

    let _ = fs::remove_file(path);
}

/// Flipping the on-disk IV must also fail integrity, since the IV is part of
/// the MAC input.
#[test]
fn test_chunk_io_mac_detects_iv_tampering() {
    let path = "test_mac_iv_tamper.enc";
    let _ = fs::remove_file(path);

    {
        let mut f = EncryptedFile::open(
            path,
            Aes256XtsCipher::new(dummy_xts_key()),
            dummy_mac_key(),
            dummy_aad(path),
            true,
            true,
        )
        .unwrap();
        f.write_chunk(0, b"hello").unwrap();
        f.flush().unwrap();
    }

    {
        use std::io::{Seek, SeekFrom, Write};
        let mut handle = fs::OpenOptions::new().write(true).open(path).unwrap();
        handle.seek(SeekFrom::Start(0)).unwrap();
        handle.write_all(&[0xFF; 16]).unwrap();
    }

    let result = EncryptedFile::open(
        path,
        Aes256XtsCipher::new(dummy_xts_key()),
        dummy_mac_key(),
        dummy_aad(path),
        false,
        false,
    );
    assert!(
        result.is_err(),
        "CRITICAL: IV tampering bypassed the MAC check"
    );

    let _ = fs::remove_file(path);
}

/// Using the wrong MAC key on a valid file must fail integrity.
#[test]
fn test_chunk_io_mac_wrong_key_rejected() {
    let path = "test_mac_wrong_key.enc";
    let _ = fs::remove_file(path);

    {
        let mut f = EncryptedFile::open(
            path,
            Aes256XtsCipher::new(dummy_xts_key()),
            dummy_mac_key(),
            dummy_aad(path),
            true,
            true,
        )
        .unwrap();
        f.write_chunk(0, b"data").unwrap();
        f.flush().unwrap();
    }

    let wrong_mac = SecureKey(vec![0xDE; 32]);
    let result = EncryptedFile::open(
        path,
        Aes256XtsCipher::new(dummy_xts_key()),
        wrong_mac,
        dummy_aad(path),
        false,
        false,
    );
    assert!(
        result.is_err(),
        "Wrong MAC key must be rejected by integrity check"
    );

    let _ = fs::remove_file(path);
}

/// P0: Swapping two encrypted files on disk must be detected. Before
/// path-binding, content-only MAC let both files still verify after a swap.
#[test]
fn test_chunk_io_mac_detects_file_swap() {
    let path_a = "test_mac_swap_a.enc";
    let path_b = "test_mac_swap_b.enc";
    let _ = fs::remove_file(path_a);
    let _ = fs::remove_file(path_b);

    {
        let mut fa = EncryptedFile::open(
            path_a,
            Aes256XtsCipher::new(dummy_xts_key()),
            dummy_mac_key(),
            dummy_aad(path_a),
            true,
            true,
        )
        .unwrap();
        fa.write_chunk(0, b"secret-A").unwrap();
        fa.flush().unwrap();

        let mut fb = EncryptedFile::open(
            path_b,
            Aes256XtsCipher::new(dummy_xts_key()),
            dummy_mac_key(),
            dummy_aad(path_b),
            true,
            true,
        )
        .unwrap();
        fb.write_chunk(0, b"secret-B").unwrap();
        fb.flush().unwrap();
    }

    // Adversary swaps the two on-disk blobs.
    let tmp = "test_mac_swap_tmp.enc";
    fs::rename(path_a, tmp).unwrap();
    fs::rename(path_b, path_a).unwrap();
    fs::rename(tmp, path_b).unwrap();

    let open_a = EncryptedFile::open(
        path_a,
        Aes256XtsCipher::new(dummy_xts_key()),
        dummy_mac_key(),
        dummy_aad(path_a),
        false,
        false,
    );
    let open_b = EncryptedFile::open(
        path_b,
        Aes256XtsCipher::new(dummy_xts_key()),
        dummy_mac_key(),
        dummy_aad(path_b),
        false,
        false,
    );
    assert!(
        open_a.is_err(),
        "CRITICAL: file-swap attack went undetected at path_a"
    );
    assert!(
        open_b.is_err(),
        "CRITICAL: file-swap attack went undetected at path_b"
    );

    let _ = fs::remove_file(path_a);
    let _ = fs::remove_file(path_b);
}
