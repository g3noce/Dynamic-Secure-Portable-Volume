use crate::utils::memory::SecureKey;
use aes::cipher::KeyInit;
use aes::Aes256;
use xts_mode::{get_tweak_default, Xts128};

#[derive(Debug)]
pub enum CipherError {
    InitializationFailed,
    AlignmentError,
}

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
        if self.key.0.len() != 64 || file_iv.len() != 16 {
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
        if self.key.0.len() != 64 || file_iv.len() != 16 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::memory::SecureKey;

    // --- Helper ---
    fn dummy_cipher() -> Aes256XtsCipher {
        Aes256XtsCipher::new(SecureKey(vec![0x42; 64]))
    }

    fn dummy_iv() -> [u8; 16] {
        [0xAA; 16]
    }

    // ----------------------------------------------------------------
    // TESTS EXISTANTS (Mécanique de base)
    // ----------------------------------------------------------------

    #[test]
    fn test_aes256_xts_chunk_basic() {
        let cipher = dummy_cipher();
        let iv = dummy_iv();

        let original_data = b"Hello world!1234This is 32 bytes";
        let mut data = original_data.to_vec();

        cipher.encrypt_chunk(&iv, 0, &mut data).unwrap();
        assert_ne!(original_data.as_slice(), data.as_slice());

        cipher.decrypt_chunk(&iv, 0, &mut data).unwrap();
        assert_eq!(original_data.as_slice(), data.as_slice());
    }

    #[test]
    fn test_cipher_initialization_error() {
        let cipher = Aes256XtsCipher::new(SecureKey(vec![0x42; 32])); // Clé trop courte
        let mut data = vec![0u8; 16];

        let result = cipher.encrypt_chunk(&dummy_iv(), 0, &mut data);
        assert!(matches!(result, Err(CipherError::InitializationFailed)));
    }

    #[test]
    fn test_cipher_alignment_error() {
        let cipher = dummy_cipher();
        let mut unaligned_data = vec![0u8; 15]; // Non multiple de 16

        let result = cipher.encrypt_chunk(&dummy_iv(), 0, &mut unaligned_data);
        assert!(matches!(result, Err(CipherError::AlignmentError)));
    }

    // ----------------------------------------------------------------
    // TESTS CRITIQUES (Propriétés Cryptographiques)
    // ----------------------------------------------------------------

    /// TEST 1 : L'empreinte doit changer selon la position (Offset/Tweak)
    #[test]
    fn test_cipher_offset_dependence() {
        let cipher = dummy_cipher();
        let iv = dummy_iv();
        let payload = [b'A'; 16];

        let mut data_at_offset_0 = payload;
        cipher.encrypt_chunk(&iv, 0, &mut data_at_offset_0).unwrap();

        let mut data_at_offset_16 = payload;
        cipher
            .encrypt_chunk(&iv, 16, &mut data_at_offset_16)
            .unwrap();

        assert_ne!(
            data_at_offset_0, data_at_offset_16,
            "CRITICAL: L'AES-XTS a produit le même chiffré pour deux offsets différents. Le calcul du sector_index est défaillant."
        );
    }

    /// TEST 2 : L'empreinte doit changer selon l'IV (Renouvellement)
    #[test]
    fn test_cipher_iv_dependence() {
        let cipher = dummy_cipher();
        let payload = [b'B'; 16];

        let iv1 = [0x11; 16];
        let mut data_iv1 = payload;
        cipher.encrypt_chunk(&iv1, 0, &mut data_iv1).unwrap();

        let iv2 = [0x22; 16];
        let mut data_iv2 = payload;
        cipher.encrypt_chunk(&iv2, 0, &mut data_iv2).unwrap();

        assert_ne!(
            data_iv1, data_iv2,
            "CRITICAL: Le changement d'IV n'a pas modifié la signature cryptographique."
        );
    }

    /// TEST 3 : Cohérence entre le chiffrement global et fragmenté (Streaming)
    #[test]
    fn test_cipher_cross_chunk_equivalence() {
        let cipher = dummy_cipher();
        let iv = dummy_iv();
        let payload = [b'C'; 32]; // 2 blocs stricts

        // Chiffrement d'un seul bloc de 32 octets
        let mut monolithic_data = payload;
        cipher.encrypt_chunk(&iv, 0, &mut monolithic_data).unwrap();

        // Chiffrement fragmenté : deux appels de 16 octets
        let mut fragmented_data = payload;
        let (part1, part2) = fragmented_data.split_at_mut(16);

        cipher.encrypt_chunk(&iv, 0, part1).unwrap();
        cipher.encrypt_chunk(&iv, 16, part2).unwrap();

        assert_eq!(
            monolithic_data, fragmented_data,
            "CRITICAL: Le chiffrement en flux (chunking) casse la structure XTS. Les blocs ne s'alignent pas correctement."
        );
    }

    /// TEST 4 : Isolation des secteurs et Effet Avalanche (Bit-flipping attack)
    #[test]
    fn test_cipher_sector_isolation_and_avalanche() {
        let cipher = dummy_cipher();
        let iv = dummy_iv();

        let original_data = [b'D'; 32];
        let mut data = original_data;

        // 1. On chiffre les 32 octets
        cipher.encrypt_chunk(&iv, 0, &mut data).unwrap();

        // 2. L'attaquant corrompt un seul bit dans le premier secteur (offset 5)
        data[5] ^= 0b0000_0001;

        // 3. On déchiffre le tout
        cipher.decrypt_chunk(&iv, 0, &mut data).unwrap();

        // 4. Vérification de l'effet Avalanche : Le premier secteur (0-15) doit être totalement détruit
        assert_ne!(
            &data[0..16],
            &original_data[0..16],
            "CRITICAL: L'effet avalanche n'a pas eu lieu sur le secteur corrompu."
        );

        // 5. Vérification de l'isolation : Le second secteur (16-31) doit être intact
        assert_eq!(
            &data[16..32],
            &original_data[16..32],
            "CRITICAL: La corruption d'un secteur a débordé sur le secteur adjacent. L'isolation XTS est brisée."
        );
    }

    /// TEST 5 : Résistance aux limites extrêmes (Integer Overflow)
    #[test]
    fn test_cipher_extreme_offset_wrapping() {
        let cipher = dummy_cipher();
        let iv = [0xFF; 16]; // Pousse l'addition interne du `sector_index` dans ses limites
        let mut data = [b'E'; 16];

        // Un offset immense proche de la limite du type
        let extreme_offset = u64::MAX - 15;

        // Le wrapping_add ne doit pas faire paniquer le thread
        let result = cipher.encrypt_chunk(&iv, extreme_offset, &mut data);
        assert!(
            result.is_ok(),
            "Le calcul du sector_index a paniqué face à un offset extrême."
        );
    }
}
