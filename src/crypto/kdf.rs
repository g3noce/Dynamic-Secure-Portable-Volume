use crate::utils::memory::SecureKey;
use argon2::{Algorithm, Argon2, Params, Version};

#[derive(Debug)]
pub enum KdfError {
    DerivationFailed,
    InvalidParameters,
}

pub trait KeyDerivation {
    /// Génère une clé sécurisée à partir d'un mot de passe et d'un sel.
    fn derive_key(password: &str, salt: &[u8]) -> Result<SecureKey, KdfError>;
}

pub struct Argon2Kdf;

impl KeyDerivation for Argon2Kdf {
    fn derive_key(password: &str, salt: &[u8]) -> Result<SecureKey, KdfError> {
        // Paramètres recommandés (approx) : m=64MB, t=3, p=4
        let params = Params::new(65536, 3, 4, Some(32)).map_err(|_| KdfError::InvalidParameters)?;
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

    #[test]
    fn test_derive_key_success() {
        let password = "super_secret_password";
        let salt = b"random_salt_1234";

        let key1 = Argon2Kdf::derive_key(password, salt).expect("Key derivation failed");
        assert_eq!(key1.0.len(), 32);

        // Same password and salt should yield the same key
        let key2 = Argon2Kdf::derive_key(password, salt).expect("Key derivation failed");
        assert_eq!(
            key1.0, key2.0,
            "Same password and salt should yield the same key"
        );

        // Different salt should yield a different key
        let salt2 = b"different_salt__";
        let key3 = Argon2Kdf::derive_key(password, salt2).expect("Key derivation failed");
        assert_ne!(
            key1.0, key3.0,
            "Different salt should yield a different key"
        );

        // Different password should yield a different key
        let key4 =
            Argon2Kdf::derive_key("different_password", salt).expect("Key derivation failed");
        assert_ne!(
            key1.0, key4.0,
            "Different password should yield a different key"
        );
    }
}
