use crate::utils::memory::SecureKey;
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Debug)]
pub enum CipherError {
    //InvalidLength,
    InitializationFailed,
}

pub trait ChunkCipher {
    /// Instancie le chiffreur avec la clé (qui restera en mémoire sécurisée)
    fn new(key: SecureKey) -> Self;

    /// Déchiffre (ou chiffre, car XOR) un bloc de données à un offset donné.
    /// L'offset est absolu par rapport au fichier d'origine.
    fn process_chunk(
        &self,
        file_iv: &[u8],
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), CipherError>;
}

pub struct Aes256CtrCipher {
    key: SecureKey,
}

impl ChunkCipher for Aes256CtrCipher {
    fn new(key: SecureKey) -> Self {
        Self { key }
    }

    fn process_chunk(
        &self,
        file_iv: &[u8],
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), CipherError> {
        if self.key.0.len() != 32 {
            return Err(CipherError::InitializationFailed);
        }
        if file_iv.len() != 16 {
            return Err(CipherError::InitializationFailed);
        }

        let mut cipher = Aes256Ctr::new(
            self.key
                .0
                .as_slice()
                .try_into()
                .map_err(|_| CipherError::InitializationFailed)?,
            file_iv
                .try_into()
                .map_err(|_| CipherError::InitializationFailed)?,
        );

        // Seek to the absolute offset
        cipher.seek(offset);

        // Encrypt/Decrypt
        cipher.apply_keystream(data);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::memory::SecureKey;
    use rand::Rng;

    #[test]
    fn test_aes256_ctr_chunk() {
        let mut key_bytes = [0u8; 32];
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut key_bytes);
        rand::rng().fill_bytes(&mut iv);

        let cipher = super::Aes256CtrCipher::new(SecureKey(key_bytes.to_vec()));

        let original_data =
            b"Hello world, this is a test string that will be encrypted and decrypted by chunks.";
        let mut data_to_encrypt = original_data.to_vec();

        // Encrypt whole at offset 0
        cipher.process_chunk(&iv, 0, &mut data_to_encrypt).unwrap();

        assert_ne!(original_data.as_slice(), data_to_encrypt.as_slice());

        // Decrypt whole at offset 0
        let mut data_to_decrypt = data_to_encrypt.clone();
        cipher.process_chunk(&iv, 0, &mut data_to_decrypt).unwrap();
        assert_eq!(original_data.as_slice(), data_to_decrypt.as_slice());

        // Decrypt a specific chunk
        let offset: u64 = 13;
        let chunk_len = 4;
        let mut chunk = data_to_encrypt[offset as usize..(offset as usize + chunk_len)].to_vec();

        cipher.process_chunk(&iv, offset, &mut chunk).unwrap();

        assert_eq!(
            &original_data[offset as usize..(offset as usize + chunk_len)],
            chunk.as_slice()
        );
    }
}
