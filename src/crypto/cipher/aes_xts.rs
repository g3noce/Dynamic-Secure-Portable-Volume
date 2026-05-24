use aes::Aes256;
use aes::cipher::KeyInit;
use xts_mode::{Xts128, get_tweak_default};

use crate::crypto::cipher::errors::CipherError;
use crate::utils::memory::SecureKey;

pub trait ChunkCipher {
    fn new(key: SecureKey) -> Self;

    fn encrypt_chunk(
        &self,
        file_iv: &[u8],
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), CipherError>;

    fn decrypt_chunk(
        &self,
        file_iv: &[u8],
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), CipherError>;
}

pub struct Aes256XtsCipher {
    key: SecureKey,
}

impl ChunkCipher for Aes256XtsCipher {
    fn new(key: SecureKey) -> Self {
        Self { key }
    }

    fn encrypt_chunk(
        &self,
        file_iv: &[u8],
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), CipherError> {
        if self.key.0.len() < 64 || file_iv.len() != 16 {
            return Err(CipherError::InitializationFailed);
        }
        if !data.len().is_multiple_of(16) {
            return Err(CipherError::AlignmentError);
        }

        let key1: [u8; 32] = self.key.0[0..32].try_into().unwrap();
        let key2: [u8; 32] = self.key.0[32..64].try_into().unwrap();

        let cipher_1 = Aes256::new(&key1.into());
        let cipher_2 = Aes256::new(&key2.into());
        let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);

        let sector_index =
            ((offset / 16) as u128).wrapping_add(u128::from_le_bytes(file_iv.try_into().unwrap()));

        xts.encrypt_area(data, 16, sector_index, get_tweak_default);
        Ok(())
    }

    fn decrypt_chunk(
        &self,
        file_iv: &[u8],
        offset: u64,
        data: &mut [u8],
    ) -> Result<(), CipherError> {
        if self.key.0.len() < 64 || file_iv.len() != 16 {
            return Err(CipherError::InitializationFailed);
        }
        if !data.len().is_multiple_of(16) {
            return Err(CipherError::AlignmentError);
        }

        let key1: [u8; 32] = self.key.0[0..32].try_into().unwrap();
        let key2: [u8; 32] = self.key.0[32..64].try_into().unwrap();

        let cipher_1 = Aes256::new(&key1.into());
        let cipher_2 = Aes256::new(&key2.into());
        let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);

        let sector_index =
            ((offset / 16) as u128).wrapping_add(u128::from_le_bytes(file_iv.try_into().unwrap()));

        xts.decrypt_area(data, 16, sector_index, get_tweak_default);
        Ok(())
    }
}
