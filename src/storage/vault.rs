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

// --- ADDITION: Structured enum for custom errors ---
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
            VaultError::KdfFailedCreate => ("create_new", "KDF failed"),
            VaultError::EncryptVerifyFailed => {
                ("create_new", "failed to encrypt verification block")
            }
            VaultError::InvalidMagic => ("unlock_existing", "corrupt or invalid meta file"),
            VaultError::KdfFailedUnlock => ("unlock_existing", "KDF failed"),
            VaultError::DecryptVerifyFailed => {
                ("unlock_existing", "failed to decrypt verification block")
            }
            VaultError::WrongPassword => ("unlock_existing", "incorrect password"),
        };
        write!(f, "mod: vault, function: {}, cause: {}", func, cause)
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

    /// TEST 1: Normal lifecycle (Valid creation and unlock)
    #[test]
    fn test_vault_lifecycle_success() {
        let root = setup_test_env("test_vault_lifecycle");
        let password = "super_secure_password_123!";

        // 1. Creation
        let key_1 = VaultManager::unlock_or_create(&root, password).expect("Creation failed");
        assert!(Path::new(&root).join("dspv.meta").exists());

        // 2. Unlock
        let key_2 = VaultManager::unlock_or_create(&root, password).expect("Unlock failed");

        // The key in RAM must be strictly identical
        assert_eq!(key_1.0, key_2.0, "Derived keys do not match!");

        teardown_test_env(&root);
    }

    /// TEST 2: Strict rejection of a wrong password
    #[test]
    fn test_vault_wrong_password() {
        let root = setup_test_env("test_vault_wrong_pwd");

        VaultManager::unlock_or_create(&root, "good_password").unwrap();
        let result = VaultManager::unlock_or_create(&root, "bad_password");

        assert!(
            result.is_err(),
            "CRITICAL: The system accepted a wrong password!"
        );
        // MODIFICATION HERE: Adapted to the new error message convention
        assert_eq!(
            result.unwrap_err().to_string(),
            "mod: vault, function: unlock_existing, cause: incorrect password"
        );

        teardown_test_env(&root);
    }

    /// TEST 3: Resilience against a truncated file (Short Read)
    /// Prevents the program from panicking if the meta file is less than 68 bytes.
    #[test]
    fn test_vault_truncated_file_no_panic() {
        let root = setup_test_env("test_vault_truncated");
        let meta_path = Path::new(&root).join("dspv.meta");

        // Forge a file with only the Magic Number and part of the salt (10 bytes total)
        let mut file = File::create(&meta_path).unwrap();
        file.write_all(b"DSPM").unwrap();
        file.write_all(&[0x42; 6]).unwrap();
        drop(file);

        let result = VaultManager::unlock_or_create(&root, "password");

        assert!(result.is_err(), "The system must reject a truncated file");
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
            "The error must be UnexpectedEof (premature end of file), not a system crash"
        );

        teardown_test_env(&root);
    }

    /// TEST 4: Attempted Salt Tampering
    /// Modifying even 1 byte of the salt should alter the KDF result and reject access.
    #[test]
    fn test_vault_salt_tampering() {
        let root = setup_test_env("test_vault_salt_tamper");
        let meta_path = Path::new(&root).join("dspv.meta");
        let password = "password";

        VaultManager::unlock_or_create(&root, password).unwrap();

        // Open in binary write mode
        let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();

        // The salt starts at offset 4 (after "DSPM"). We modify the byte at offset 10.
        file.seek(SeekFrom::Start(10)).unwrap();
        file.write_all(&[0xFF]).unwrap();
        drop(file);

        let result = VaultManager::unlock_or_create(&root, password);

        assert!(
            result.is_err(),
            "CRITICAL: Tampering with the salt did not invalidate the vault!"
        );

        teardown_test_env(&root);
    }

    /// TEST 5: Attempted verification block tampering
    /// If an attacker modifies the encrypted signature, decryption will yield
    /// a result different from [0; 32] and access must be blocked.
    #[test]
    fn test_vault_verify_block_tampering() {
        let root = setup_test_env("test_vault_block_tamper");
        let meta_path = Path::new(&root).join("dspv.meta");
        let password = "password";

        VaultManager::unlock_or_create(&root, password).unwrap();

        let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();

        // The verification block starts at offset 36 (4 Magic + 32 Salt).
        file.seek(SeekFrom::Start(40)).unwrap();
        file.write_all(&[0xFF]).unwrap();
        drop(file);

        let result = VaultManager::unlock_or_create(&root, password);

        assert!(
            result.is_err(),
            "CRITICAL: The vault opened despite a corrupted verification block!"
        );

        teardown_test_env(&root);
    }

    /// TEST 6: Handling an empty password
    /// Verifies that the KDF algorithm (Argon2) can cleanly ingest an empty string.
    #[test]
    fn test_vault_empty_password_handling() {
        let root = setup_test_env("test_vault_empty_pwd");

        let result_create = VaultManager::unlock_or_create(&root, "");
        assert!(
            result_create.is_ok(),
            "The system must handle an empty password without crashing"
        );

        let result_unlock = VaultManager::unlock_or_create(&root, "");
        assert!(
            result_unlock.is_ok(),
            "The system must unlock with an empty password"
        );

        teardown_test_env(&root);
    }
}
