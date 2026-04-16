use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::fmt;

use crate::utils::memory::SecureKey;

#[derive(Debug)]
pub enum CipherError {
    AuthenticationFailed,
    EncryptionFailed,
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cause = match self {
            CipherError::AuthenticationFailed => {
                "MAC verification failed (data corrupted or tampered)"
            }
            CipherError::EncryptionFailed => "encryption process failed",
        };
        write!(
            f,
            "mod: cipher, function: chunk_processing, cause: {}",
            cause
        )
    }
}

impl std::error::Error for CipherError {}

pub trait AuthenticatedChunkCipher {
    fn new(key: SecureKey) -> Self;

    fn encrypt_chunk(
        &self,
        file_iv: &[u8; 16],
        chunk_index: u64,
        clear_data: &[u8],
    ) -> Result<Vec<u8>, CipherError>;

    fn decrypt_chunk(
        &self,
        file_iv: &[u8; 16],
        chunk_index: u64,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, CipherError>;
}

pub struct ChaChaPolyCipher {
    cipher: XChaCha20Poly1305,
}

impl AuthenticatedChunkCipher for ChaChaPolyCipher {
    fn new(key: SecureKey) -> Self {
        let mut k = [0u8; 32];
        let copy_len = std::cmp::min(key.0.len(), 32);
        k[..copy_len].copy_from_slice(&key.0[..copy_len]);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&k));
        Self { cipher }
    }

    fn encrypt_chunk(
        &self,
        file_iv: &[u8; 16],
        chunk_index: u64,
        clear_data: &[u8],
    ) -> Result<Vec<u8>, CipherError> {
        use chacha20poly1305::aead::Payload;
        use rand::Rng;

        let mut nonce_bytes = [0u8; 24];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let mut aad = Vec::with_capacity(24);
        aad.extend_from_slice(file_iv);
        aad.extend_from_slice(&chunk_index.to_le_bytes());

        let payload = Payload {
            msg: clear_data,
            aad: &aad,
        };

        let mut encrypted = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|_| CipherError::EncryptionFailed)?;

        let mut result = nonce_bytes.to_vec();
        result.append(&mut encrypted);
        Ok(result)
    }

    fn decrypt_chunk(
        &self,
        file_iv: &[u8; 16],
        chunk_index: u64,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, CipherError> {
        use chacha20poly1305::aead::Payload;

        if encrypted_data.len() < 40 {
            return Err(CipherError::AuthenticationFailed);
        }

        let nonce = XNonce::from_slice(&encrypted_data[0..24]);
        let actual_ciphertext = &encrypted_data[24..];

        let mut aad = Vec::with_capacity(24);
        aad.extend_from_slice(file_iv);
        aad.extend_from_slice(&chunk_index.to_le_bytes());

        let payload = Payload {
            msg: actual_ciphertext,
            aad: &aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| CipherError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::memory::SecureKey;

    fn setup_cipher() -> ChaChaPolyCipher {
        ChaChaPolyCipher::new(SecureKey(vec![0u8; 32]))
    }

    #[test]
    fn test_encrypt_decrypt_cycle() {
        let cipher = setup_cipher();
        let file_iv = [0u8; 16];
        let chunk_index = 42u64;
        let data = b"Sensitive data to encrypt";

        // Success cycle
        let encrypted = cipher
            .encrypt_chunk(&file_iv, chunk_index, data)
            .expect("Encryption failed");
        let decrypted = cipher
            .decrypt_chunk(&file_iv, chunk_index, &encrypted)
            .expect("Decryption failed");

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_integrity_failure_on_tamper() {
        let cipher = setup_cipher();
        let file_iv = [0u8; 16];
        let mut encrypted = cipher.encrypt_chunk(&file_iv, 0, b"data").unwrap();

        // Tamper with the ciphertext part (after 24 bytes of nonce)
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0xFF;

        let result = cipher.decrypt_chunk(&file_iv, 0, &encrypted);
        assert!(matches!(result, Err(CipherError::AuthenticationFailed)));
    }

    #[test]
    fn test_wrong_context_failure() {
        let cipher = setup_cipher();
        let file_iv = [0u8; 16];
        let encrypted = cipher.encrypt_chunk(&file_iv, 1, b"data").unwrap();

        // Decrypting with wrong chunk_index must fail (AAD mismatch)
        let result = cipher.decrypt_chunk(&file_iv, 2, &encrypted);
        assert!(matches!(result, Err(CipherError::AuthenticationFailed)));
    }

    #[test]
    fn test_invalid_input_length() {
        let cipher = setup_cipher();
        let tiny_data = vec![0u8; 39]; // Minimum is 40 (24 nonce + 16 tag)
        let result = cipher.decrypt_chunk(&[0u8; 16], 0, &tiny_data);
        assert!(matches!(result, Err(CipherError::AuthenticationFailed)));
    }
}
