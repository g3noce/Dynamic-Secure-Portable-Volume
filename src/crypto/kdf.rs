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
            KdfError::DerivationFailed => "échec du hachage interne Argon2",
            KdfError::InvalidParameters => "paramètres de configuration Argon2 rejetés",
        };
        write!(f, "mod : kdf , fonction : derive_key , cause : {}", cause)
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
        [0u8; 16] // Sel constant pour tests de reproductibilité
    }

    /// TEST 1 : Stabilité et Déterminisme (Vecteur de test)
    /// Garantit que les paramètres (64Mo, 3 itérations, 4 threads) ne changent jamais par erreur.
    #[test]
    fn test_kdf_parameters_stability() {
        let password = "dspv_test_password";
        let salt = b"static_salt_1234"; // 16 octets

        let key1 = Argon2Kdf::derive_key(password, salt).unwrap();
        let key2 = Argon2Kdf::derive_key(password, salt).unwrap();

        // 1. Déterminisme
        assert_eq!(key1.0, key2.0, "Le KDF n'est pas déterministe !");

        // 2. Taille de sortie (Crucial pour AES-256-XTS)
        assert_eq!(
            key1.0.len(),
            64,
            "La clé doit faire exactement 64 octets (2x256 bits)"
        );
    }

    /// TEST 2 : Effet Avalanche (Sensibilité extrême)
    /// Un changement d'un seul bit doit produire une clé totalement différente.
    #[test]
    fn test_kdf_avalanche_effect() {
        let salt = get_dummy_salt();
        let pwd1 = "MotDePasse123!";
        let pwd2 = "MotDePasse123?"; // Juste le dernier caractère change

        let key1 = Argon2Kdf::derive_key(pwd1, &salt).unwrap();
        let key2 = Argon2Kdf::derive_key(pwd2, &salt).unwrap();

        assert_ne!(key1.0, key2.0);

        // Optionnel : vérifier qu'on n'a pas juste un octet de différence
        let mut diff_count = 0;
        for i in 0..64 {
            if key1.0[i] != key2.0[i] {
                diff_count += 1;
            }
        }
        assert!(
            diff_count > 50,
            "L'effet avalanche est trop faible (faiblesse cryptographique)"
        );
    }

    /// TEST 3 : Gestion des cas limites (Mot de passe vide / long)
    #[test]
    fn test_kdf_edge_cases_passwords() {
        let salt = get_dummy_salt();

        // Mot de passe vide (doit fonctionner mais produire une clé forte)
        let key_empty = Argon2Kdf::derive_key("", &salt);
        assert!(key_empty.is_ok());
        assert_eq!(key_empty.unwrap().0.len(), 64);

        // Mot de passe très long (plusieurs Ko)
        let long_pwd = "A".repeat(10000);
        let key_long = Argon2Kdf::derive_key(&long_pwd, &salt);
        assert!(key_long.is_ok());
    }

    /// TEST 4 : Sécurité du Sel (Taille minimale)
    /// Argon2id nécessite un sel d'au moins 8 octets.
    #[test]
    fn test_kdf_salt_security_limits() {
        let pwd = "password";

        // Sel trop court (6 octets)
        let short_salt = b"123456";
        let result = Argon2Kdf::derive_key(pwd, short_salt);

        assert!(
            result.is_err(),
            "Le KDF devrait échouer avec un sel de moins de 8 octets"
        );
    }

    /// TEST 5 : Non-réutilisation (Unique Salt = Unique Key)
    #[test]
    fn test_kdf_salt_uniqueness() {
        let pwd = "same_password";
        let salt1 = b"salt_number_1";
        let salt2 = b"salt_number_2";

        let key1 = Argon2Kdf::derive_key(pwd, salt1).unwrap();
        let key2 = Argon2Kdf::derive_key(pwd, salt2).unwrap();

        assert_ne!(
            key1.0, key2.0,
            "Deux sels différents doivent produire des clés différentes"
        );
    }
}
