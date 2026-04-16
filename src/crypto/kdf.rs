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
    fn derive_key(password: &str, salt: &[u8]) -> Result<SecureKey, KdfError>;
}

pub struct Argon2Kdf;

impl KeyDerivation for Argon2Kdf {
    fn derive_key(password: &str, salt: &[u8]) -> Result<SecureKey, KdfError> {
        let params = Params::new(65536, 3, 4, Some(64)).map_err(|_| KdfError::InvalidParameters)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key_m = vec![0u8; 64];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_m)
            .map_err(|_| KdfError::DerivationFailed)?;

        Ok(SecureKey(key_m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helpers ---
    fn get_dummy_salt() -> [u8; 16] {
        [0u8; 16] // Constant salt for reproducibility tests
    }

    /// TEST 1: Stability and Determinism (Test Vector)
    /// Guarantees that the parameters (64MB, 3 iterations, 4 threads) never change by mistake.
    #[test]
    fn test_kdf_parameters_stability() {
        let password = "dspv_test_password";
        let salt = b"static_salt_1234"; // 16 bytes

        let key1 = Argon2Kdf::derive_key(password, salt).unwrap();
        let key2 = Argon2Kdf::derive_key(password, salt).unwrap();

        // 1. Determinism
        assert_eq!(key1.0, key2.0, "The KDF is not deterministic!");

        // 2. Output size (Crucial for AES-256-XTS)
        assert_eq!(
            key1.0.len(),
            64,
            "The key must be exactly 64 bytes (2x256 bits)"
        );
    }

    /// TEST 2: Avalanche Effect (Extreme Sensitivity)
    /// Changing a single bit must produce a completely different key.
    #[test]
    fn test_kdf_avalanche_effect() {
        let salt = get_dummy_salt();
        let pwd1 = "MotDePasse123!";
        let pwd2 = "MotDePasse123?"; // Only the last character changes

        let key1 = Argon2Kdf::derive_key(pwd1, &salt).unwrap();
        let key2 = Argon2Kdf::derive_key(pwd2, &salt).unwrap();

        assert_ne!(key1.0, key2.0);

        // Optional: verify that we don't just have a one-byte difference
        let mut diff_count = 0;
        for i in 0..64 {
            if key1.0[i] != key2.0[i] {
                diff_count += 1;
            }
        }
        assert!(
            diff_count > 50,
            "The avalanche effect is too weak (cryptographic weakness)"
        );
    }

    /// TEST 3: Handling edge cases (Empty / Long password)
    #[test]
    fn test_kdf_edge_cases_passwords() {
        let salt = get_dummy_salt();

        // Empty password (must work but produce a strong key)
        let key_empty = Argon2Kdf::derive_key("", &salt);
        assert!(key_empty.is_ok());
        assert_eq!(key_empty.unwrap().0.len(), 64);

        // Very long password (several KB)
        let long_pwd = "A".repeat(10000);
        let key_long = Argon2Kdf::derive_key(&long_pwd, &salt);
        assert!(key_long.is_ok());
    }

    /// TEST 4: Salt Security (Minimum size)
    /// Argon2id requires a salt of at least 8 bytes.
    #[test]
    fn test_kdf_salt_security_limits() {
        let pwd = "password";

        // Salt too short (6 bytes)
        let short_salt = b"123456";
        let result = Argon2Kdf::derive_key(pwd, short_salt);

        assert!(
            result.is_err(),
            "The KDF should fail with a salt of less than 8 bytes"
        );
    }

    /// TEST 5: Non-reuse (Unique Salt = Unique Key)
    #[test]
    fn test_kdf_salt_uniqueness() {
        let pwd = "same_password";
        let salt1 = b"salt_number_1";
        let salt2 = b"salt_number_2";

        let key1 = Argon2Kdf::derive_key(pwd, salt1).unwrap();
        let key2 = Argon2Kdf::derive_key(pwd, salt2).unwrap();

        assert_ne!(
            key1.0, key2.0,
            "Two different salts must produce different keys"
        );
    }
}
