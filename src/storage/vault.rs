use rand::Rng;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use crate::crypto::cipher::{Aes256XtsCipher, ChunkCipher};
use crate::crypto::kdf::{Argon2Kdf, KeyDerivation};
use crate::utils::memory::SecureKey;

const VAULT_MAGIC: &[u8; 4] = b"DSPM";
const SALT_SIZE: usize = 32;
const VERIFY_BLOCK_SIZE: usize = 32;

// --- AJOUT : Énumération structurée pour les erreurs personnalisées ---
#[derive(Debug)]
pub enum VaultError {
    KdfFailedCreate,
    EncryptVerifyFailed,
    InvalidMagic,
    KdfFailedUnlock,
    DecryptVerifyFailed,
    WrongPassword,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            VaultError::KdfFailedCreate => ("create_new", "échec KDF"),
            VaultError::EncryptVerifyFailed => {
                ("create_new", "échec du chiffrement du bloc de vérification")
            }
            VaultError::InvalidMagic => ("unlock_existing", "fichier meta corrompu ou invalide"),
            VaultError::KdfFailedUnlock => ("unlock_existing", "échec KDF"),
            VaultError::DecryptVerifyFailed => (
                "unlock_existing",
                "échec du déchiffrement du bloc de vérification",
            ),
            VaultError::WrongPassword => ("unlock_existing", "mot de passe incorrect"),
        };
        write!(f, "mod : vault , fonction : {} , cause : {}", func, cause)
    }
}

impl std::error::Error for VaultError {}
// ----------------------------------------------------------------------

pub struct VaultManager;

impl VaultManager {
    pub fn unlock_or_create<P: AsRef<Path>>(
        physical_root: P,
        password: &str,
    ) -> io::Result<SecureKey> {
        let meta_path = physical_root.as_ref().join("dspv.meta");

        if meta_path.exists() {
            Self::unlock_existing(&meta_path, password)
        } else {
            Self::create_new(&meta_path, password)
        }
    }

    fn create_new(meta_path: &Path, password: &str) -> io::Result<SecureKey> {
        let mut salt = [0u8; SALT_SIZE];
        rand::rng().fill_bytes(&mut salt);

        let master_key = Argon2Kdf::derive_key(password, &salt)
            .map_err(|_| io::Error::other(VaultError::KdfFailedCreate))?;

        let mut verify_block = [0u8; VERIFY_BLOCK_SIZE];
        let meta_iv = [0u8; 16];
        let cipher = Aes256XtsCipher::new(master_key.clone());

        cipher
            .encrypt_chunk(&meta_iv, 0, &mut verify_block)
            .map_err(|_| io::Error::other(VaultError::EncryptVerifyFailed))?;

        let mut file = File::create(meta_path)?;
        file.write_all(VAULT_MAGIC)?;
        file.write_all(&salt)?;
        file.write_all(&verify_block)?;
        file.flush()?;

        Ok(master_key)
    }

    fn unlock_existing(meta_path: &Path, password: &str) -> io::Result<SecureKey> {
        let mut file = File::open(meta_path)?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != VAULT_MAGIC {
            return Err(io::Error::other(VaultError::InvalidMagic));
        }

        let mut salt = [0u8; SALT_SIZE];
        file.read_exact(&mut salt)?;

        let mut verify_block = [0u8; VERIFY_BLOCK_SIZE];
        file.read_exact(&mut verify_block)?;

        let master_key = Argon2Kdf::derive_key(password, &salt)
            .map_err(|_| io::Error::other(VaultError::KdfFailedUnlock))?;

        let cipher = Aes256XtsCipher::new(master_key.clone());
        let meta_iv = [0u8; 16];

        cipher
            .decrypt_chunk(&meta_iv, 0, &mut verify_block)
            .map_err(|_| io::Error::other(VaultError::DecryptVerifyFailed))?;

        if verify_block != [0u8; VERIFY_BLOCK_SIZE] {
            return Err(io::Error::other(VaultError::WrongPassword));
        }

        Ok(master_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::{Seek, SeekFrom};

    // --- Helper ---
    fn setup_test_env(name: &str) -> String {
        let _ = fs::remove_dir_all(name);
        fs::create_dir_all(name).unwrap();
        name.to_string()
    }

    fn teardown_test_env(name: &str) {
        let _ = fs::remove_dir_all(name);
    }

    /// TEST 1 : Le cycle de vie normal (Création et Déverrouillage valide)
    #[test]
    fn test_vault_lifecycle_success() {
        let root = setup_test_env("test_vault_lifecycle");
        let password = "super_secure_password_123!";

        // 1. Création
        let key_1 = VaultManager::unlock_or_create(&root, password).expect("Création échouée");
        assert!(Path::new(&root).join("dspv.meta").exists());

        // 2. Déverrouillage
        let key_2 = VaultManager::unlock_or_create(&root, password).expect("Déverrouillage échoué");

        // La clé en RAM doit être strictement identique
        assert_eq!(key_1.0, key_2.0, "Les clés dérivées ne correspondent pas !");

        teardown_test_env(&root);
    }

    /// TEST 2 : Le rejet stricte d'un mauvais mot de passe
    #[test]
    fn test_vault_wrong_password() {
        let root = setup_test_env("test_vault_wrong_pwd");

        VaultManager::unlock_or_create(&root, "good_password").unwrap();
        let result = VaultManager::unlock_or_create(&root, "bad_password");

        assert!(
            result.is_err(),
            "CRITICAL: Le système a accepté un mauvais mot de passe !"
        );
        // MODIFICATION ICI : Adaptation à ta nouvelle convention de message d'erreur
        assert_eq!(
            result.unwrap_err().to_string(),
            "mod : vault , fonction : unlock_existing , cause : mot de passe incorrect"
        );

        teardown_test_env(&root);
    }

    /// TEST 3 : Résilience face à un fichier tronqué (Short Read)
    /// Empêche le programme de paniquer si le fichier meta fait moins de 68 octets.
    #[test]
    fn test_vault_truncated_file_no_panic() {
        let root = setup_test_env("test_vault_truncated");
        let meta_path = Path::new(&root).join("dspv.meta");

        // On forge un fichier avec seulement le Magic Number et un bout de sel (10 octets au total)
        let mut file = File::create(&meta_path).unwrap();
        file.write_all(b"DSPM").unwrap();
        file.write_all(&[0x42; 6]).unwrap();
        drop(file);

        let result = VaultManager::unlock_or_create(&root, "password");

        assert!(
            result.is_err(),
            "Le système doit rejeter un fichier tronqué"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
            "L'erreur doit être UnexpectedEof (fin de fichier prématurée), pas un crash système"
        );

        teardown_test_env(&root);
    }

    /// TEST 4 : Tentative de falsification du Sel (Salt Tampering)
    /// Modifier 1 seul octet du sel doit altérer le résultat du KDF et rejeter l'accès.
    #[test]
    fn test_vault_salt_tampering() {
        let root = setup_test_env("test_vault_salt_tamper");
        let meta_path = Path::new(&root).join("dspv.meta");
        let password = "password";

        VaultManager::unlock_or_create(&root, password).unwrap();

        // Ouverture en mode modification binaire
        let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();

        // Le sel commence à l'offset 4 (après "DSPM"). On modifie l'octet à l'offset 10.
        file.seek(SeekFrom::Start(10)).unwrap();
        file.write_all(&[0xFF]).unwrap();
        drop(file);

        let result = VaultManager::unlock_or_create(&root, password);

        assert!(
            result.is_err(),
            "CRITICAL: La modification du sel n'a pas invalidé le coffre !"
        );

        teardown_test_env(&root);
    }

    /// TEST 5 : Tentative de falsification du bloc de vérification chiffré
    /// Si un attaquant modifie la signature chiffrée, le déchiffrement donnera
    /// un résultat différent de [0; 32] et l'accès doit être bloqué.
    #[test]
    fn test_vault_verify_block_tampering() {
        let root = setup_test_env("test_vault_block_tamper");
        let meta_path = Path::new(&root).join("dspv.meta");
        let password = "password";

        VaultManager::unlock_or_create(&root, password).unwrap();

        let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();

        // Le bloc de vérification commence à l'offset 36 (4 Magic + 32 Sel).
        file.seek(SeekFrom::Start(40)).unwrap();
        file.write_all(&[0xFF]).unwrap();
        drop(file);

        let result = VaultManager::unlock_or_create(&root, password);

        assert!(
            result.is_err(),
            "CRITICAL: Le coffre s'est ouvert malgré un bloc de vérification corrompu !"
        );

        teardown_test_env(&root);
    }

    /// TEST 6 : Gestion d'un mot de passe vide
    /// Vérifie que l'algorithme KDF (Argon2) est capable d'ingérer une chaîne vide proprement.
    #[test]
    fn test_vault_empty_password_handling() {
        let root = setup_test_env("test_vault_empty_pwd");

        let result_create = VaultManager::unlock_or_create(&root, "");
        assert!(
            result_create.is_ok(),
            "Le système doit pouvoir gérer un mot de passe vide sans planter"
        );

        let result_unlock = VaultManager::unlock_or_create(&root, "");
        assert!(
            result_unlock.is_ok(),
            "Le système doit pouvoir déverrouiller avec un mot de passe vide"
        );

        teardown_test_env(&root);
    }
}
