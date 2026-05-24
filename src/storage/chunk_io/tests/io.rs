use super::super::*;
use super::{dummy_aad, dummy_mac_key, dummy_xts_key, setup_test_file};
use crate::crypto::cipher::{Aes256XtsCipher, ChunkCipher};
use crate::storage::header::HEADER_SIZE;
use std::fs;

#[test]
fn test_encrypted_file_readonly_not_found() {
    let result = EncryptedFile::open(
        "does_not_exist.enc",
        Aes256XtsCipher::new(dummy_xts_key()),
        dummy_mac_key(),
        dummy_aad("does_not_exist.enc"),
        false,
        false,
    );
    assert!(
        result.is_err(),
        "Opening a non-existent file in read-only mode should fail"
    );
}

#[test]
fn test_encrypted_file_metadata() {
    let path = "test_metadata.enc";
    let mut enc_file = setup_test_file(path);
    enc_file.write_chunk(0, b"metadata test").unwrap();
    let meta = enc_file.metadata().unwrap();
    assert!(meta.is_file());
    assert!(
        meta.len() > HEADER_SIZE,
        "The physical size must include the header and data"
    );
    let _ = fs::remove_file(path);
}

/// RMW straddling multiple cryptographic blocks
#[test]
fn test_chunk_io_cross_block_rmw() {
    let path = "test_cross_block.enc";
    let mut enc_file = setup_test_file(path);

    let initial_data = [b'A'; 32];
    enc_file.write_chunk(0, &initial_data).unwrap();

    let inject_data = b"0123456789";
    enc_file.write_chunk(14, inject_data).unwrap();

    let result = enc_file.read_chunk(0, 32).unwrap();

    let mut expected = [b'A'; 32];
    expected[14..24].copy_from_slice(b"0123456789");

    assert_eq!(
        result.0.as_slice(),
        expected,
        "CRITICAL: The Read-Modify-Write operation corrupted data at XTS block boundaries!"
    );

    let _ = fs::remove_file(path);
}

/// EOF (End Of File) boundary security
#[test]
fn test_chunk_io_eof_read_behavior() {
    let path = "test_eof.enc";
    let mut enc_file = setup_test_file(path);

    enc_file.write_chunk(0, b"Hello").unwrap();
    assert_eq!(enc_file.logical_size().unwrap(), 5);

    let result = enc_file.read_chunk(0, 20).unwrap();

    assert_eq!(
        result.0.len(),
        5,
        "CRITICAL: The reader returned hidden cryptographic XTS padding or memory garbage!"
    );
    assert_eq!(result.0.as_slice(), b"Hello");

    let oob_result = enc_file.read_chunk(10, 5).unwrap();
    assert_eq!(
        oob_result.0.len(),
        0,
        "Reading outside the logical file must return 0 bytes."
    );

    let _ = fs::remove_file(path);
}

/// Behavior against zero-length I/O
#[test]
fn test_chunk_io_zero_length_operations() {
    let path = "test_zero_len.enc";
    let mut enc_file = setup_test_file(path);

    enc_file.write_chunk(0, b"Data").unwrap();

    enc_file.write_chunk(2, &[]).unwrap();
    assert_eq!(
        enc_file.logical_size().unwrap(),
        4,
        "The empty write modified the logical size!"
    );

    let result = enc_file.read_chunk(1, 0).unwrap();
    assert_eq!(result.0.len(), 0, "The empty read returned data!");

    let _ = fs::remove_file(path);
}

/// Truncate must rotate the IV.
#[test]
fn test_chunk_io_truncate_and_iv_rotation() {
    let path = "test_truncate_iv.enc";

    let mut file1 = EncryptedFile::open(
        path,
        Aes256XtsCipher::new(dummy_xts_key()),
        dummy_mac_key(),
        dummy_aad(path),
        true,
        true,
    )
    .unwrap();
    file1.write_chunk(0, b"Old confidential data").unwrap();
    let iv1 = file1.header_iv();
    drop(file1);

    let file2 = EncryptedFile::open(
        path,
        Aes256XtsCipher::new(dummy_xts_key()),
        dummy_mac_key(),
        dummy_aad(path),
        true,
        true,
    )
    .unwrap();
    let iv2 = file2.header_iv();

    assert_eq!(
        file2.logical_size().unwrap(),
        0,
        "Truncate did not set the logical size to zero"
    );
    assert_ne!(
        iv1, iv2,
        "CRITICAL: Cryptographic flaw! The IV was not renewed during truncate."
    );

    let _ = fs::remove_file(path);
}

/// Very large block arithmetic (memory stress test).
#[test]
fn test_chunk_io_large_file_multiple_chunks() {
    let path = "test_large_chunks.enc";
    let mut enc_file = setup_test_file(path);

    let payload: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

    enc_file.write_chunk(0, &payload).unwrap();
    assert_eq!(enc_file.logical_size().unwrap(), 10000);

    let result = enc_file.read_chunk(0, 10000).unwrap();
    assert_eq!(result.0.len(), 10000);
    assert_eq!(
        result.0.as_slice(),
        payload.as_slice(),
        "Writing a large buffer was corrupted"
    );

    let _ = fs::remove_file(path);
}
