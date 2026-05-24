use super::*;
use crate::crypto::mac::MAC_TAG_SIZE;
use std::io::{self, Cursor};

#[test]
fn test_header_generate_new() {
    let header1 = FileHeader::generate_new();
    let header2 = FileHeader::generate_new();

    assert_eq!(header1.logical_size, 0);
    assert_eq!(header1.reserved, [0u8; 8]);
    assert_eq!(
        header1.mac_tag, [0u8; MAC_TAG_SIZE],
        "Freshly generated header must start with zeroed MAC tag"
    );
    assert_ne!(header1.iv, header2.iv, "The IV must be random");
}

#[test]
fn test_header_generation_and_io() {
    let header = FileHeader {
        iv: [0x42; 16],
        logical_size: 1337,
        reserved: [0u8; 8],
        mac_tag: [0xCC; MAC_TAG_SIZE],
    };
    let mut buffer = Vec::new();
    header.write_to(&mut buffer).unwrap();
    assert_eq!(buffer.len(), HEADER_SIZE as usize);

    let mut cursor = Cursor::new(buffer);
    let read_header = FileHeader::read_from(&mut cursor).unwrap();
    assert_eq!(header.iv, read_header.iv);
    assert_eq!(header.logical_size, read_header.logical_size);
    assert_eq!(header.mac_tag, read_header.mac_tag);
}

/// TEST 1: Corrupted or incomplete file (Short Read)
#[test]
fn test_header_short_read_prevents_panic() {
    // 40 bytes is enough to cover IV+size+reserved but not the MAC tag —
    // exercises the new ReadMacTagFailed path while keeping prior coverage.
    let buffer = vec![0u8; 40];
    let mut cursor = Cursor::new(buffer);

    let result = FileHeader::read_from(&mut cursor);

    assert!(
        result.is_err(),
        "CRITICAL: The reader accepted an incomplete header without triggering an error!"
    );
    assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof,
        "The returned error must be exactly UnexpectedEof to be properly handled by chunk_io"
    );
}

/// TEST 2: Cross-Platform Stability (Endianness)
#[test]
fn test_header_endianness_crossplatform_guarantee() {
    let mut header = FileHeader::generate_new();
    header.logical_size = 0x1122334455667788;

    let mut buffer = Vec::new();
    header.write_to(&mut buffer).unwrap();

    let size_bytes = &buffer[16..24];
    let expected_bytes: [u8; 8] = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

    assert_eq!(
        size_bytes, &expected_bytes,
        "CRITICAL: Serialization is not strictly Little Endian. The volume will be corrupted across architectures!"
    );
}

/// TEST 3: Physical offsets stability (Binary Layout)
#[test]
fn test_header_binary_layout_strictness() {
    let mut buffer = Vec::new();
    let header = FileHeader {
        iv: [0xFF; 16],
        logical_size: 255,
        reserved: [0xAA; 8],
        mac_tag: [0x55; MAC_TAG_SIZE],
    };
    header.write_to(&mut buffer).unwrap();

    assert_eq!(buffer.len(), 64, "The header must be EXACTLY 64 bytes");
    assert_eq!(
        &buffer[0..16],
        &[0xFF; 16],
        "The IV was shifted from its original physical offset"
    );
    assert_eq!(
        &buffer[16..24],
        &[0xFF, 0, 0, 0, 0, 0, 0, 0],
        "The logical size is no longer at offset 16"
    );
    assert_eq!(
        &buffer[24..32],
        &[0xAA; 8],
        "The reserved area is not aligned right after the size field"
    );
    assert_eq!(
        &buffer[32..64],
        &[0x55; MAC_TAG_SIZE],
        "The MAC tag must occupy the second half of the header"
    );
}

#[test]
fn test_header_plaintext_bytes_match_serialized_prefix() {
    let header = FileHeader {
        iv: [0x12; 16],
        logical_size: 0xDEAD_BEEF,
        reserved: [0xCD; 8],
        mac_tag: [0x99; MAC_TAG_SIZE], // must NOT appear in plaintext_bytes
    };

    let mut serialized = Vec::new();
    header.write_to(&mut serialized).unwrap();

    let plaintext = header.plaintext_bytes();
    assert_eq!(
        &serialized[..HEADER_PLAINTEXT_SIZE as usize],
        &plaintext,
        "plaintext_bytes must equal the first {HEADER_PLAINTEXT_SIZE} bytes of the serialized header"
    );
}
