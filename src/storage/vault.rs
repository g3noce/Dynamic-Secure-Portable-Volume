use rand::Rng;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use crate::crypto::cipher::{AuthenticatedChunkCipher, ChaChaPolyCipher};
use crate::crypto::kdf::{Argon2Kdf, KeyDerivation};
use crate::utils::memory::SecureKey;

const VAULT_MAGIC: &[u8; 4] = b"DSPM";
const SALT_SIZE: usize = 32;
const ARGON2_PARAMS_SIZE: usize = 12;
const VERIFY_BLOCK_SIZE: usize = 72;

#[derive(Debug)]
pub enum VaultError {
    KdfFailedCreate,
    EncryptVerifyFailed,
    InvalidMagic,
    KdfFailedUnlock,
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
            VaultError::WrongPassword => ("unlock_existing", "incorrect password or corrupted MAC"),
        };
        write!(f, "mod: vault, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for VaultError {}

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

        let iterations: u32 = 3;
        let memory: u32 = 65536;
        let parallelism: u32 = 4;

        let master_key =
            Argon2Kdf::derive_key_with_params(password, &salt, iterations, memory, parallelism)
                .map_err(|_| io::Error::other(VaultError::KdfFailedCreate))?;

        let verify_clear = [0u8; 32];
        let meta_iv = [0u8; 16];
        let cipher = ChaChaPolyCipher::new(master_key.clone());

        let encrypted_verify = cipher
            .encrypt_chunk(&meta_iv, 0, &verify_clear)
            .map_err(|_| io::Error::other(VaultError::EncryptVerifyFailed))?;

        let mut file = File::create(meta_path)?;
        file.write_all(VAULT_MAGIC)?;
        file.write_all(&salt)?;
        file.write_all(&iterations.to_le_bytes())?;
        file.write_all(&memory.to_le_bytes())?;
        file.write_all(&parallelism.to_le_bytes())?;
        file.write_all(&encrypted_verify)?;
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

        let mut params = [0u8; ARGON2_PARAMS_SIZE];
        file.read_exact(&mut params)?;

        let iterations = u32::from_le_bytes(params[0..4].try_into().unwrap());
        let memory = u32::from_le_bytes(params[4..8].try_into().unwrap());
        let parallelism = u32::from_le_bytes(params[8..12].try_into().unwrap());

        let mut verify_block = [0u8; VERIFY_BLOCK_SIZE];
        file.read_exact(&mut verify_block)?;

        let master_key =
            Argon2Kdf::derive_key_with_params(password, &salt, iterations, memory, parallelism)
                .map_err(|_| io::Error::other(VaultError::KdfFailedUnlock))?;

        let cipher = ChaChaPolyCipher::new(master_key.clone());
        let meta_iv = [0u8; 16];

        cipher
            .decrypt_chunk(&meta_iv, 0, &verify_block)
            .map_err(|_| io::Error::other(VaultError::WrongPassword))?;

        Ok(master_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::{Seek, SeekFrom};
    use std::path::PathBuf;

    // --- Helper ---
    // Automates isolated environment setup and guarantees cleanup even on test panics.
    struct TestEnv {
        root: PathBuf,
    }

    impl TestEnv {
        fn new(name: &str) -> Self {
            let root = PathBuf::from(name);
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// TEST 1: Creation and Legitimate Unlocking
    /// Covers initial creation, subsequent unlocking, and edge cases like empty passwords.
    #[test]
    fn test_vault_lifecycle() {
        let env = TestEnv::new("test_vault_lifecycle");
        let pwd = "secure_password_123!";

        // 1. Initial Creation
        let key_create = VaultManager::unlock_or_create(&env.root, pwd).expect("Creation failed");
        assert!(
            env.root.join("dspv.meta").exists(),
            "Meta file was not created"
        );

        // 2. Successful Unlock
        let key_unlock = VaultManager::unlock_or_create(&env.root, pwd).expect("Unlock failed");
        assert_eq!(
            key_create.0, key_unlock.0,
            "Derived keys must match on successful unlock"
        );

        // 3. Edge Case: Empty Password
        let env_empty = TestEnv::new("test_vault_empty_pwd");
        let key_empty_1 = VaultManager::unlock_or_create(&env_empty.root, "").unwrap();
        let key_empty_2 = VaultManager::unlock_or_create(&env_empty.root, "").unwrap();
        assert_eq!(
            key_empty_1.0, key_empty_2.0,
            "Empty password handling failed"
        );
    }

    /// TEST 2: Rejection Mechanisms (Bad Password & Corrupted File)
    /// Validates the system gracefully denies access without panicking.
    #[test]
    fn test_vault_rejections() {
        let env = TestEnv::new("test_vault_rejections");
        let pwd = "good_password";

        VaultManager::unlock_or_create(&env.root, pwd).unwrap();

        // 1. Wrong Password
        let result_bad_pwd = VaultManager::unlock_or_create(&env.root, "bad_password");
        assert!(
            matches!(
                result_bad_pwd
                    .unwrap_err()
                    .into_inner()
                    .unwrap()
                    .downcast_ref::<VaultError>(),
                Some(VaultError::WrongPassword)
            ),
            "System must specifically reject invalid passwords with WrongPassword error"
        );

        // 2. Truncated File (Simulating OS interruption or physical corruption)
        let meta_path = env.root.join("dspv.meta");
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&meta_path)
            .unwrap();
        file.write_all(b"DSP").unwrap(); // Missing 1 byte of magic + everything else
        drop(file);

        let result_trunc = VaultManager::unlock_or_create(&env.root, pwd);
        assert_eq!(
            result_trunc.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
            "Truncated files must yield an UnexpectedEof error, not a crash"
        );
    }

    /// TEST 3: Cryptographic Anti-Tampering Validation
    /// Ensures modifications to the salt, KDF parameters, or ciphertext block reject the unlock.
    #[test]
    fn test_vault_tamper_resistance() {
        let env = TestEnv::new("test_vault_tamper");
        let pwd = "tamper_test_pwd";
        let meta_path = env.root.join("dspv.meta");

        // Base implementation to be tampered with
        VaultManager::unlock_or_create(&env.root, pwd).unwrap();

        // 1. Tamper with the Verify Block (Starts at offset: 4 Magic + 32 Salt + 12 Params = 48)
        let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();
        file.seek(SeekFrom::Start(50)).unwrap();
        file.write_all(&[0xFF]).unwrap();
        drop(file);

        assert!(
            VaultManager::unlock_or_create(&env.root, pwd).is_err(),
            "CRITICAL: Vault opened despite a corrupted MAC in the verification block!"
        );

        // Reset for next check
        let _ = fs::remove_file(&meta_path);
        VaultManager::unlock_or_create(&env.root, pwd).unwrap();

        // 2. Tamper with the Salt (Starts at offset: 4)
        let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();
        file.seek(SeekFrom::Start(10)).unwrap();
        file.write_all(&[0x00]).unwrap();
        drop(file);

        assert!(
            VaultManager::unlock_or_create(&env.root, pwd).is_err(),
            "CRITICAL: Salt modification must invalidate the derived key!"
        );

        // Reset for next check
        let _ = fs::remove_file(&meta_path);
        VaultManager::unlock_or_create(&env.root, pwd).unwrap();

        // 3. Tamper with Argon2 Parameters (Starts at offset: 36)
        let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();
        file.seek(SeekFrom::Start(36)).unwrap(); // Altering the iteration count
        file.write_all(&[0x01]).unwrap();
        drop(file);

        assert!(
            VaultManager::unlock_or_create(&env.root, pwd).is_err(),
            "CRITICAL: Modifying KDF parameters must fail the unlock process!"
        );
    }
}
