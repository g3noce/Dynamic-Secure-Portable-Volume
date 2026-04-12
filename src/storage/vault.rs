// storage/vault.rs
use rand::Rng;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use crate::crypto::cipher::{Aes256CtrCipher, ChunkCipher};
use crate::crypto::kdf::{Argon2Kdf, KeyDerivation};
use crate::utils::memory::SecureKey;

const VAULT_MAGIC: &[u8; 4] = b"DSPM";
const SALT_SIZE: usize = 32;
const VERIFY_BLOCK_SIZE: usize = 32;

pub struct VaultManager;

impl VaultManager {
    /// Initialise un nouveau volume ou déverrouille un volume existant
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

        // Dérivation de la clé
        let master_key =
            Argon2Kdf::derive_key(password, &salt).map_err(|_| io::Error::other("Échec KDF"))?;

        // Création du bloc de vérification (32 octets de zéros chiffrés avec un IV fixe pour la meta)
        let mut verify_block = [0u8; VERIFY_BLOCK_SIZE];
        let meta_iv = [0u8; 16]; // IV statique uniquement pour le bloc de vérification
        let cipher = Aes256CtrCipher::new(master_key.clone());

        cipher
            .process_chunk(&meta_iv, 0, &mut verify_block)
            .map_err(|_| io::Error::other("Échec chiffrement bloc vérification"))?;

        // Écriture du fichier meta
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
            return Err(io::Error::other("Fichier meta corrompu ou invalide"));
        }

        let mut salt = [0u8; SALT_SIZE];
        file.read_exact(&mut salt)?;

        let mut verify_block = [0u8; VERIFY_BLOCK_SIZE];
        file.read_exact(&mut verify_block)?;

        // Dérivation avec le sel lu
        let master_key =
            Argon2Kdf::derive_key(password, &salt).map_err(|_| io::Error::other("Échec KDF"))?;

        // Tentative de déchiffrement du bloc de vérification
        let cipher = Aes256CtrCipher::new(master_key.clone());
        let meta_iv = [0u8; 16];

        cipher
            .process_chunk(&meta_iv, 0, &mut verify_block)
            .map_err(|_| io::Error::other("Échec déchiffrement bloc vérification"))?;

        // Vérification : le bloc déchiffré doit contenir uniquement des zéros
        if verify_block != [0u8; VERIFY_BLOCK_SIZE] {
            return Err(io::Error::other("Mot de passe incorrect"));
        }

        Ok(master_key)
    }
}
