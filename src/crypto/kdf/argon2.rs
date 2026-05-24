use argon2::{Algorithm, Argon2, Params, Version};

use crate::crypto::kdf::errors::KdfError;
use crate::utils::memory::SecureKey;

pub trait KeyDerivation {
    fn derive_key(password: &str, salt: &[u8]) -> Result<SecureKey, KdfError>;
}

pub struct Argon2Kdf;

/// Total bytes emitted by the KDF.
/// - 0..64  → AES-256-XTS key material (two 256-bit halves)
/// - 64..96 → HMAC-SHA256 authentication key
pub const DERIVED_KEY_SIZE: usize = 96;

impl KeyDerivation for Argon2Kdf {
    fn derive_key(password: &str, salt: &[u8]) -> Result<SecureKey, KdfError> {
        let params = Params::new(65536, 3, 4, Some(DERIVED_KEY_SIZE))
            .map_err(|_| KdfError::InvalidParameters)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key_m = vec![0u8; DERIVED_KEY_SIZE];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_m)
            .map_err(|_| KdfError::DerivationFailed)?;

        Ok(SecureKey(key_m))
    }
}
