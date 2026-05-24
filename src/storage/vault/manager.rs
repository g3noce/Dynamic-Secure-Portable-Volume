use rand::Rng;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use subtle::ConstantTimeEq;

use crate::crypto::cipher::{Aes256XtsCipher, ChunkCipher};
use crate::crypto::kdf::{Argon2Kdf, KeyDerivation};
use crate::crypto::mac::{self, MAC_KEY_SIZE, MAC_TAG_SIZE};
use crate::storage::vault::errors::VaultError;
use crate::utils::memory::SecureKey;

pub(super) const VAULT_MAGIC: &[u8; 4] = b"DSPM";
pub(super) const SALT_SIZE: usize = 32;
pub(super) const VERIFY_BLOCK_SIZE: usize = 32;

/// dspv.meta v2 layout:
/// - bytes  0..4    : magic "DSPM"
/// - bytes  4..36   : 32-byte random salt (feeds Argon2)
/// - bytes 36..68   : 32-byte XTS-encrypted verify block (proves password)
/// - bytes 68..100  : 32-byte HMAC-SHA256 of bytes 0..68
///
/// The HMAC defends against salt or verify-block tampering: without it, an
/// attacker who flipped a salt byte caused the user to derive a wrong master
/// key, which then cascaded into MAC failures on every encrypted file. The tag
/// uses the same MAC key as per-file integrity (last 32 bytes of the Argon2
/// output) so no extra KDF round is needed.
const META_PRE_MAC_SIZE: usize = VAULT_MAGIC.len() + SALT_SIZE + VERIFY_BLOCK_SIZE;

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

        // Compute the meta HMAC over the freshly built pre-MAC region.
        let mut pre_mac = Vec::with_capacity(META_PRE_MAC_SIZE);
        pre_mac.extend_from_slice(VAULT_MAGIC);
        pre_mac.extend_from_slice(&salt);
        pre_mac.extend_from_slice(&verify_block);
        let tag = mac::compute(&master_key.0[64..64 + MAC_KEY_SIZE], &pre_mac);

        let mut file = File::create(meta_path)?;
        file.write_all(&pre_mac)?;
        file.write_all(&tag)?;
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

        let mut stored_tag = [0u8; MAC_TAG_SIZE];
        file.read_exact(&mut stored_tag)?;

        let master_key = Argon2Kdf::derive_key(password, &salt)
            .map_err(|_| io::Error::other(VaultError::KdfFailedUnlock))?;

        // Step 1: verify the meta HMAC. A mismatch here means EITHER the
        // password is wrong (the derived MAC key won't reproduce the stored
        // tag) OR the file was tampered with. We don't disambiguate the two
        // — that would leak whether the salt is authentic to an attacker who
        // can read the file but not produce a valid MAC.
        let mut pre_mac = Vec::with_capacity(META_PRE_MAC_SIZE);
        pre_mac.extend_from_slice(&magic);
        pre_mac.extend_from_slice(&salt);
        pre_mac.extend_from_slice(&verify_block);
        let expected_tag = mac::compute(&master_key.0[64..64 + MAC_KEY_SIZE], &pre_mac);
        if !mac::verify(&stored_tag, &expected_tag) {
            // Use a generic "wrong password" message so an attacker can't tell
            // their tampering attempt apart from a normal user typo.
            return Err(io::Error::other(VaultError::WrongPassword));
        }

        // Step 2: defense-in-depth — verify the XTS-encrypted block still
        // decrypts to zeroes. This is redundant after a valid HMAC but cheap.
        let cipher = Aes256XtsCipher::new(master_key.clone());
        let meta_iv = [0u8; 16];

        cipher
            .decrypt_chunk(&meta_iv, 0, &mut verify_block)
            .map_err(|_| io::Error::other(VaultError::DecryptVerifyFailed))?;

        let zero = [0u8; VERIFY_BLOCK_SIZE];
        // P3.6: constant-time compare. The contents would be effectively
        // random under a wrong key so timing-side channels can't meaningfully
        // leak here, but best practice still applies.
        if !bool::from(verify_block.ct_eq(&zero)) {
            return Err(io::Error::other(VaultError::MetaTampered));
        }

        Ok(master_key)
    }
}
