use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::cipher::ChunkCipher;
use crate::storage::header::{FileHeader, HEADER_SIZE, LOGICAL_SIZE_OFFSET};
use crate::utils::memory::SecureBuffer;

const XTS_BLOCK_SIZE: u64 = 16;

pub struct EncryptedFile<C: ChunkCipher> {
    file: File,
    cipher: C,
    header: FileHeader,
}

impl<C: ChunkCipher> EncryptedFile<C> {
    pub fn open<P: AsRef<Path>>(
        path: P,
        cipher: C,
        truncate: bool,
        write_access: bool,
    ) -> io::Result<Self> {
        let path_ref = path.as_ref();
        let mut opts = OpenOptions::new();
        opts.read(true);

        if write_access {
            opts.write(true).create(true).truncate(false);
        }

        let mut file = opts.open(path_ref)?;
        let metadata = file.metadata()?;

        let header = if metadata.len() == 0 || truncate {
            if !write_access {
                return Err(io::Error::other(
                    "Impossible d'initialiser un header en mode lecture seule",
                ));
            }
            file.set_len(0)?;
            let new_header = FileHeader::generate_new();
            new_header.write_to(&mut file)?;
            new_header
        } else {
            FileHeader::read_from(&mut file)?
        };

        Ok(Self {
            file,
            cipher,
            header,
        })
    }

    pub fn read_chunk(&mut self, logical_offset: u64, size: usize) -> io::Result<SecureBuffer> {
        if size == 0 {
            return Ok(SecureBuffer(vec![]));
        }

        let align_start = (logical_offset / XTS_BLOCK_SIZE) * XTS_BLOCK_SIZE;
        let end_offset = logical_offset + size as u64;
        let align_end = end_offset.div_ceil(XTS_BLOCK_SIZE) * XTS_BLOCK_SIZE;
        let aligned_size = (align_end - align_start) as usize;

        let physical_offset = HEADER_SIZE + align_start;
        self.file.seek(SeekFrom::Start(physical_offset))?;

        let mut block_buffer = SecureBuffer(vec![0u8; aligned_size]);
        let bytes_read = self.file.read(&mut block_buffer.0)?;

        if bytes_read == 0 {
            return Ok(SecureBuffer(vec![]));
        }

        let valid_crypt_size = (bytes_read / XTS_BLOCK_SIZE as usize) * XTS_BLOCK_SIZE as usize;
        if valid_crypt_size > 0 {
            self.cipher
                .decrypt_chunk(
                    &self.header.iv,
                    align_start,
                    &mut block_buffer.0[..valid_crypt_size],
                )
                .map_err(|_| io::Error::other("Échec du déchiffrement XTS"))?;
        }

        let relative_start = (logical_offset - align_start) as usize;
        let max_logical_available =
            self.header.logical_size.saturating_sub(logical_offset) as usize;
        let available_data = valid_crypt_size.saturating_sub(relative_start);

        let copy_len = std::cmp::min(size, std::cmp::min(available_data, max_logical_available));

        let mut final_buffer = SecureBuffer(vec![0u8; copy_len]);
        if copy_len > 0 {
            final_buffer
                .0
                .copy_from_slice(&block_buffer.0[relative_start..(relative_start + copy_len)]);
        }

        Ok(final_buffer)
    }

    pub fn write_chunk(&mut self, logical_offset: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let align_start = (logical_offset / XTS_BLOCK_SIZE) * XTS_BLOCK_SIZE;
        let end_offset = logical_offset + data.len() as u64;
        let align_end = end_offset.div_ceil(XTS_BLOCK_SIZE) * XTS_BLOCK_SIZE;
        let aligned_size = (align_end - align_start) as usize;

        let mut block_buffer = SecureBuffer(vec![0u8; aligned_size]);
        let physical_data_size = self.file.metadata()?.len().saturating_sub(HEADER_SIZE);

        if align_start < physical_data_size {
            let physical_offset = HEADER_SIZE + align_start;
            self.file.seek(SeekFrom::Start(physical_offset))?;

            let max_read =
                std::cmp::min(aligned_size as u64, physical_data_size - align_start) as usize;
            let mut temp_buf = vec![0u8; max_read];
            let bytes_read = self.file.read(&mut temp_buf)?;

            let valid_blocks_size =
                (bytes_read / XTS_BLOCK_SIZE as usize) * XTS_BLOCK_SIZE as usize;
            block_buffer.0[..valid_blocks_size].copy_from_slice(&temp_buf[..valid_blocks_size]);

            if valid_blocks_size > 0 {
                self.cipher
                    .decrypt_chunk(
                        &self.header.iv,
                        align_start,
                        &mut block_buffer.0[..valid_blocks_size],
                    )
                    .map_err(|_| io::Error::other("Échec déchiffrement RMW"))?;
            }
        }

        let relative_start = (logical_offset - align_start) as usize;
        block_buffer.0[relative_start..(relative_start + data.len())].copy_from_slice(data);

        self.cipher
            .encrypt_chunk(&self.header.iv, align_start, &mut block_buffer.0)
            .map_err(|_| io::Error::other("Échec chiffrement RMW"))?;

        let physical_offset = HEADER_SIZE + align_start;
        self.file.seek(SeekFrom::Start(physical_offset))?;
        self.file.write_all(&block_buffer.0)?;

        let new_logical_end = logical_offset + data.len() as u64;

        if new_logical_end > self.header.logical_size {
            self.header.logical_size = new_logical_end;
            self.file.seek(SeekFrom::Start(LOGICAL_SIZE_OFFSET))?;
            self.file
                .write_all(&self.header.logical_size.to_le_bytes())?;
        }

        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    pub fn logical_size(&self) -> io::Result<u64> {
        Ok(self.header.logical_size)
    }

    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::Aes256XtsCipher;
    use crate::utils::memory::SecureKey;
    use std::fs;

    // --- Helper ---
    fn setup_test_file(path: &str) -> EncryptedFile<Aes256XtsCipher> {
        let _ = fs::remove_file(path);
        let key = SecureKey(vec![0x42; 64]);
        EncryptedFile::open(path, Aes256XtsCipher::new(key), true, true).unwrap()
    }

    // ----------------------------------------------------------------
    // TESTS EXISTANTS (Basiques)
    // ----------------------------------------------------------------
    #[test]
    fn test_encrypted_file_readonly_not_found() {
        let key = SecureKey(vec![0x42; 64]);
        let result = EncryptedFile::open(
            "does_not_exist.enc",
            Aes256XtsCipher::new(key),
            false,
            false,
        );
        assert!(
            result.is_err(),
            "L'ouverture d'un fichier inexistant en lecture seule doit échouer"
        );
    }

    #[test]
    fn test_encrypted_file_metadata() {
        let path = "test_metadata.enc";
        let mut enc_file = setup_test_file(path);
        enc_file.write_chunk(0, b"metadata test").unwrap();
        let meta = enc_file.metadata().unwrap();
        assert!(meta.is_file());
        assert!(
            meta.len() > HEADER_SIZE,
            "La taille physique doit inclure l'en-tête et les données"
        );
        let _ = fs::remove_file(path);
    }

    // ----------------------------------------------------------------
    // TESTS CRITIQUES (Nouveaux - Extrême Robustesse)
    // ----------------------------------------------------------------

    /// TEST 1 : RMW à cheval sur plusieurs blocs cryptographiques
    /// Vérifie que si on écrit de l'octet 10 à 25 (chevauchement sur les blocs 0 et 1),
    /// le système déchiffre les deux blocs, modifie le milieu, et rechiffre sans corrompre les extrémités.
    #[test]
    fn test_chunk_io_cross_block_rmw() {
        let path = "test_cross_block.enc";
        let mut enc_file = setup_test_file(path);

        // 1. On initialise 2 blocs complets (32 octets) avec des 'A'
        let initial_data = [b'A'; 32];
        enc_file.write_chunk(0, &initial_data).unwrap();

        // 2. Écriture DÉSALIGNÉE de 10 octets commençant à l'offset 14 (finit à 24)
        // Bloc 0 : de 0 à 15 (touché à la fin)
        // Bloc 1 : de 16 à 31 (touché au début)
        let inject_data = b"0123456789";
        enc_file.write_chunk(14, inject_data).unwrap();

        // 3. Lecture et vérification globale
        let result = enc_file.read_chunk(0, 32).unwrap();

        let mut expected = [b'A'; 32];
        expected[14..24].copy_from_slice(b"0123456789");

        assert_eq!(
            result.0.as_slice(),
            expected,
            "CRITICAL: L'écriture Read-Modify-Write a corrompu les données aux limites de blocs XTS !"
        );

        let _ = fs::remove_file(path);
    }

    /// TEST 2 : Sécurité de la frontière EOF (End Of File)
    /// Empêche le client de lire la "poubelle" (padding) générée par le chiffrement de bloc.
    #[test]
    fn test_chunk_io_eof_read_behavior() {
        let path = "test_eof.enc";
        let mut enc_file = setup_test_file(path);

        // On écrit 5 octets. Physique = 16 octets (1 bloc paddé avec des zéros chiffrés)
        enc_file.write_chunk(0, b"Hello").unwrap();
        assert_eq!(enc_file.logical_size().unwrap(), 5);

        // Tentative de lecture de 20 octets (débordement)
        let result = enc_file.read_chunk(0, 20).unwrap();

        assert_eq!(
            result.0.len(),
            5,
            "CRITICAL: Le lecteur a retourné le padding cryptographique caché de XTS ou des déchets mémoire !"
        );
        assert_eq!(result.0.as_slice(), b"Hello");

        // Tentative de lecture purement hors limites
        let oob_result = enc_file.read_chunk(10, 5).unwrap();
        assert_eq!(
            oob_result.0.len(),
            0,
            "Une lecture hors du fichier logique doit renvoyer 0 octet."
        );

        let _ = fs::remove_file(path);
    }

    /// TEST 3 : Comportement face aux I/O de taille Zéro
    /// L'OS (surtout Linux/macOS) fait parfois des appels "vides" pour tester les accès.
    #[test]
    fn test_chunk_io_zero_length_operations() {
        let path = "test_zero_len.enc";
        let mut enc_file = setup_test_file(path);

        enc_file.write_chunk(0, b"Data").unwrap();

        // Écriture vide
        enc_file.write_chunk(2, &[]).unwrap();
        assert_eq!(
            enc_file.logical_size().unwrap(),
            4,
            "L'écriture vide a modifié la taille logique !"
        );

        // Lecture vide
        let result = enc_file.read_chunk(1, 0).unwrap();
        assert_eq!(result.0.len(), 0, "La lecture vide a renvoyé des données !");

        let _ = fs::remove_file(path);
    }

    /// TEST 4 : Truncate et Sécurité Cryptographique (Rotation de l'IV)
    /// Écraser un fichier DOIT générer un nouveau IV, sinon l'AES-XTS perd toute sa force.
    #[test]
    fn test_chunk_io_truncate_and_iv_rotation() {
        let path = "test_truncate_iv.enc";
        let key = SecureKey(vec![0x42; 64]);

        // 1. Première vie du fichier
        let mut file1 =
            EncryptedFile::open(path, Aes256XtsCipher::new(key.clone()), true, true).unwrap();
        file1
            .write_chunk(0, b"Anciennes donnees confidentielles")
            .unwrap();
        let iv1 = file1.header.iv;
        drop(file1);

        // 2. Seconde vie du fichier (Truncate par l'OS)
        let file2 = EncryptedFile::open(path, Aes256XtsCipher::new(key), true, true).unwrap();
        let iv2 = file2.header.iv;

        assert_eq!(
            file2.logical_size().unwrap(),
            0,
            "Truncate n'a pas mis la taille logique à zéro"
        );
        assert_ne!(
            iv1, iv2,
            "CRITICAL: Faille cryptographique ! L'IV n'a pas été renouvelé lors du truncate."
        );

        let _ = fs::remove_file(path);
    }

    /// TEST 5 : Arithmétique des très grands blocs (Stress Test Mémoire)
    #[test]
    fn test_chunk_io_large_file_multiple_chunks() {
        let path = "test_large_chunks.enc";
        let mut enc_file = setup_test_file(path);

        // Payload de 10 000 octets (ni aligné sur 16, ni un multiple parfait)
        let payload: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        // On écrit tout d'un coup
        enc_file.write_chunk(0, &payload).unwrap();
        assert_eq!(enc_file.logical_size().unwrap(), 10000);

        // On relit le tout
        let result = enc_file.read_chunk(0, 10000).unwrap();
        assert_eq!(result.0.len(), 10000);
        assert_eq!(
            result.0.as_slice(),
            payload.as_slice(),
            "L'écriture d'un gros buffer a été corrompue"
        );

        let _ = fs::remove_file(path);
    }
}
