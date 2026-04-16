use crate::utils::memory::SecureKey;
use argon2::{Algorithm, Argon2, Params, Version};
use std::fmt;

#[derive(Debug)]
pub enum KdfError {
    DerivationFailed,
    InvalidParameters,
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cause = match self {
            KdfError::DerivationFailed => "Argon2 internal hashing failed",
            KdfError::InvalidParameters => "Argon2 configuration parameters rejected",
        };
        write!(f, "mod: kdf, function: derive_key, cause: {}", cause)
    }
}

impl std::error::Error for KdfError {}

pub trait KeyDerivation {
    fn derive_key_with_params(
        password: &str,
        salt: &[u8],
        iterations: u32,
        memory: u32,
        parallelism: u32,
    ) -> Result<SecureKey, KdfError>;
}

pub struct Argon2Kdf;

impl KeyDerivation for Argon2Kdf {
    fn derive_key_with_params(
        password: &str,
        salt: &[u8],
        iterations: u32,
        memory: u32,
        parallelism: u32,
    ) -> Result<SecureKey, KdfError> {
        let params = Params::new(memory, iterations, parallelism, Some(32))
            .map_err(|_| KdfError::InvalidParameters)?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key_m = vec![0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_m)
            .map_err(|_| KdfError::DerivationFailed)?;

        Ok(SecureKey(key_m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MEM: u32 = 4096; // 4MB for fast tests
    const TEST_ITER: u32 = 1;
    const TEST_PAR: u32 = 1;

    #[test]
    fn test_derivation_determinism() {
        let pwd = "password123";
        let salt = b"static_salt_8bytes"; // Min 8 bytes

        let key1 =
            Argon2Kdf::derive_key_with_params(pwd, salt, TEST_ITER, TEST_MEM, TEST_PAR).unwrap();
        let key2 =
            Argon2Kdf::derive_key_with_params(pwd, salt, TEST_ITER, TEST_MEM, TEST_PAR).unwrap();

        assert_eq!(key1.0.len(), 32);
        assert_eq!(key1.0, key2.0, "KDF must be deterministic");
    }

    #[test]
    fn test_avalanche_effect() {
        let salt = b"standard_salt";
        let key1 = Argon2Kdf::derive_key_with_params("pass1", salt, TEST_ITER, TEST_MEM, TEST_PAR)
            .unwrap();
        let key2 = Argon2Kdf::derive_key_with_params("pass2", salt, TEST_ITER, TEST_MEM, TEST_PAR)
            .unwrap();

        assert_ne!(
            key1.0, key2.0,
            "Different passwords must produce different keys"
        );
    }

    #[test]
    fn test_salt_uniqueness() {
        let pwd = "password";
        let key1 =
            Argon2Kdf::derive_key_with_params(pwd, b"salt_alpha", TEST_ITER, TEST_MEM, TEST_PAR)
                .unwrap();
        let key2 =
            Argon2Kdf::derive_key_with_params(pwd, b"salt_bravo", TEST_ITER, TEST_MEM, TEST_PAR)
                .unwrap();

        assert_ne!(
            key1.0, key2.0,
            "Different salts must produce different keys"
        );
    }

    #[test]
    fn test_invalid_argon2_parameters() {
        let pwd = "password";

        // Test 1: Salt too short (< 8 bytes)
        let short_salt = b"short";
        let res1 =
            Argon2Kdf::derive_key_with_params(pwd, short_salt, TEST_ITER, TEST_MEM, TEST_PAR);
        assert!(res1.is_err(), "Should fail if salt < 8 bytes");

        // Test 2: Invalid memory (too low for Argon2 standard)
        let res2 = Argon2Kdf::derive_key_with_params(pwd, b"valid_salt", 1, 1, 1);
        assert!(
            res2.is_err(),
            "Should fail with insufficient memory parameter"
        );
    }
}
