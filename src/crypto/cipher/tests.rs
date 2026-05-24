use super::*;
use crate::utils::memory::SecureKey;

fn dummy_cipher() -> Aes256XtsCipher {
    Aes256XtsCipher::new(SecureKey(vec![0x42; 64]))
}

fn dummy_iv() -> [u8; 16] {
    [0xAA; 16]
}

#[test]
fn test_aes256_xts_chunk_basic() {
    let cipher = dummy_cipher();
    let iv = dummy_iv();

    let original_data = b"Hello world!1234This is 32 bytes";
    let mut data = original_data.to_vec();

    cipher.encrypt_chunk(&iv, 0, &mut data).unwrap();
    assert_ne!(original_data.as_slice(), data.as_slice());

    cipher.decrypt_chunk(&iv, 0, &mut data).unwrap();
    assert_eq!(original_data.as_slice(), data.as_slice());
}

#[test]
fn test_cipher_initialization_error() {
    let cipher = Aes256XtsCipher::new(SecureKey(vec![0x42; 32])); // Key too short
    let mut data = vec![0u8; 16];

    let result = cipher.encrypt_chunk(&dummy_iv(), 0, &mut data);
    assert!(matches!(result, Err(CipherError::InitializationFailed)));
}

#[test]
fn test_cipher_alignment_error() {
    let cipher = dummy_cipher();
    let mut unaligned_data = vec![0u8; 15];

    let result = cipher.encrypt_chunk(&dummy_iv(), 0, &mut unaligned_data);
    assert!(matches!(result, Err(CipherError::AlignmentError)));
}

/// TEST 1: The fingerprint must change depending on the position (Offset/Tweak)
#[test]
fn test_cipher_offset_dependence() {
    let cipher = dummy_cipher();
    let iv = dummy_iv();
    let payload = [b'A'; 16];

    let mut data_at_offset_0 = payload;
    cipher.encrypt_chunk(&iv, 0, &mut data_at_offset_0).unwrap();

    let mut data_at_offset_16 = payload;
    cipher
        .encrypt_chunk(&iv, 16, &mut data_at_offset_16)
        .unwrap();

    assert_ne!(
        data_at_offset_0, data_at_offset_16,
        "CRITICAL: AES-XTS produced the same ciphertext for two different offsets. The sector_index calculation is faulty."
    );
}

/// TEST 2: The fingerprint must change depending on the IV (Renewal)
#[test]
fn test_cipher_iv_dependence() {
    let cipher = dummy_cipher();
    let payload = [b'B'; 16];

    let iv1 = [0x11; 16];
    let mut data_iv1 = payload;
    cipher.encrypt_chunk(&iv1, 0, &mut data_iv1).unwrap();

    let iv2 = [0x22; 16];
    let mut data_iv2 = payload;
    cipher.encrypt_chunk(&iv2, 0, &mut data_iv2).unwrap();

    assert_ne!(
        data_iv1, data_iv2,
        "CRITICAL: Changing the IV did not alter the cryptographic signature."
    );
}

/// TEST 3: Consistency between global and fragmented encryption (Streaming)
#[test]
fn test_cipher_cross_chunk_equivalence() {
    let cipher = dummy_cipher();
    let iv = dummy_iv();
    let payload = [b'C'; 32];

    let mut monolithic_data = payload;
    cipher.encrypt_chunk(&iv, 0, &mut monolithic_data).unwrap();

    let mut fragmented_data = payload;
    let (part1, part2) = fragmented_data.split_at_mut(16);

    cipher.encrypt_chunk(&iv, 0, part1).unwrap();
    cipher.encrypt_chunk(&iv, 16, part2).unwrap();

    assert_eq!(
        monolithic_data, fragmented_data,
        "CRITICAL: Stream encryption (chunking) breaks the XTS structure. Blocks do not align correctly."
    );
}

/// TEST 4: Sector isolation and Avalanche Effect (Bit-flipping attack)
#[test]
fn test_cipher_sector_isolation_and_avalanche() {
    let cipher = dummy_cipher();
    let iv = dummy_iv();

    let original_data = [b'D'; 32];
    let mut data = original_data;

    cipher.encrypt_chunk(&iv, 0, &mut data).unwrap();
    data[5] ^= 0b0000_0001;
    cipher.decrypt_chunk(&iv, 0, &mut data).unwrap();

    assert_ne!(
        &data[0..16],
        &original_data[0..16],
        "CRITICAL: The avalanche effect did not occur on the corrupted sector."
    );

    assert_eq!(
        &data[16..32],
        &original_data[16..32],
        "CRITICAL: Corruption of one sector spilled over to the adjacent sector. XTS isolation is broken."
    );
}

/// TEST 5: Resistance to extreme limits (Integer Overflow)
#[test]
fn test_cipher_extreme_offset_wrapping() {
    let cipher = dummy_cipher();
    let iv = [0xFF; 16];
    let mut data = [b'E'; 16];

    let extreme_offset = u64::MAX - 15;
    let result = cipher.encrypt_chunk(&iv, extreme_offset, &mut data);
    assert!(
        result.is_ok(),
        "The sector_index calculation panicked when facing an extreme offset."
    );
}
