use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::cipher::ChunkCipher;
use crate::utils::memory::SecureBuffer;
// IMPORT de notre module header
use crate::storage::header::{FileHeader, HEADER_SIZE};

/// Gère les opérations d'entrée/sortie sur un fichier chiffré physique.
/// Conçu spécifiquement pour le streaming WebDAV (lectures/écritures par petits blocs).
pub struct EncryptedFile<C: ChunkCipher> {
    file: File,
    cipher: C,
    header: FileHeader,
}

impl<C: ChunkCipher> EncryptedFile<C> {
    /// Ouvre un fichier chiffré existant ou initialise un nouveau conteneur vide.
    /// `write_access` détermine si l'on demande à l'OS un accès exclusif ou partagé.
    pub fn open<P: AsRef<Path>>(
        path: P,
        cipher: C,
        truncate: bool,
        write_access: bool,
    ) -> io::Result<Self> {
        let path_ref = path.as_ref();

        let mut opts = OpenOptions::new();
        opts.read(true);

        // CRITIQUE : On ne demande les droits d'écriture que si le client WebDAV le veut.
        // Cela permet à de multiples processus OS de lire le fichier en même temps.
        if write_access {
            opts.write(true).create(true).truncate(false);
        }

        let mut file = opts.open(path_ref)?;
        let metadata = file.metadata()?;

        // On initialise l'en-tête seulement si :
        // 1. Le fichier est nouveau (taille 0)
        // 2. Ou si l'utilisateur a explicitement demandé de tronquer le fichier
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
            // Sinon, on lit l'en-tête existant
            FileHeader::read_from(&mut file)?
        };

        Ok(Self {
            file,
            cipher,
            header,
        })
    }

    /// Lit et déchiffre un bloc de données à un offset LOGIQUE donné.
    pub fn read_chunk(&mut self, logical_offset: u64, size: usize) -> io::Result<SecureBuffer> {
        let physical_offset = HEADER_SIZE + logical_offset;
        self.file.seek(SeekFrom::Start(physical_offset))?;

        let mut buffer = SecureBuffer(vec![0u8; size]);
        let bytes_read = self.file.read(&mut buffer.0)?;

        buffer.0.truncate(bytes_read);

        if bytes_read > 0 {
            self.cipher
                .process_chunk(&self.header.iv, logical_offset, &mut buffer.0)
                .map_err(|_| io::Error::other("Échec du déchiffrement à la volée"))?;
        }

        Ok(buffer)
    }

    /// Chiffre et écrit un bloc de données à un offset LOGIQUE donné.
    pub fn write_chunk(&mut self, logical_offset: u64, data: &[u8]) -> io::Result<()> {
        let current_logical_size = self.logical_size()?;

        // --- GESTION DES SPARSE FILES (Remplissage des trous) ---
        // Si l'OS demande à écrire au-delà de la fin actuelle du fichier
        if logical_offset > current_logical_size {
            let gap_size = logical_offset - current_logical_size;
            let mut gap_offset = current_logical_size;

            // On limite la taille du buffer pour ne pas exploser la RAM
            // si l'OS demande un saut de 2 Go. (64 Ko par itération)
            let chunk_size: u64 = 64 * 1024;

            // On se place à la fin physique actuelle
            self.file
                .seek(SeekFrom::Start(HEADER_SIZE + current_logical_size))?;

            let mut remaining = gap_size;
            while remaining > 0 {
                let current_chunk_size = std::cmp::min(remaining, chunk_size) as usize;

                // 1. Créer un buffer de zéros de la taille du chunk
                let mut zero_buffer = SecureBuffer(vec![0u8; current_chunk_size]);

                // 2. Chiffrer ces zéros avec l'offset logique correct pour maintenir la continuité AES-CTR
                self.cipher
                    .process_chunk(&self.header.iv, gap_offset, &mut zero_buffer.0)
                    .map_err(|_| {
                        io::Error::other("Échec du chiffrement du remplissage (sparse file)")
                    })?;

                // 3. Écrire physiquement sur le disque
                self.file.write_all(&zero_buffer.0)?;

                gap_offset += current_chunk_size as u64;
                remaining -= current_chunk_size as u64;
            }
        }

        // --- ÉCRITURE DES DONNÉES DEMANDÉES ---
        let mut buffer = SecureBuffer(data.to_vec());

        self.cipher
            .process_chunk(&self.header.iv, logical_offset, &mut buffer.0)
            .map_err(|_| io::Error::other("Échec du chiffrement à la volée"))?;

        let physical_offset = HEADER_SIZE + logical_offset;
        self.file.seek(SeekFrom::Start(physical_offset))?;

        self.file.write_all(&buffer.0)?;
        self.file.flush()?;

        Ok(())
    }

    /// Retourne la taille logique du fichier (taille du fichier clair simulé).
    pub fn logical_size(&self) -> io::Result<u64> {
        let physical_size = self.file.metadata()?.len();
        if physical_size >= HEADER_SIZE {
            Ok(physical_size - HEADER_SIZE)
        } else {
            Ok(0)
        }
    }

    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::Aes256CtrCipher;
    use crate::utils::memory::SecureKey;
    use std::fs;

    #[test]
    fn test_webdav_streaming_scenario_with_header() {
        let key = SecureKey(vec![0x42; 32]);
        let test_file_path = "test_streaming_scenario_final.enc";

        let _ = fs::remove_file(test_file_path);

        // --- ÉTAPE 1 : Création ---
        // L'IV n'est plus passé manuellement, FileHeader::generate_new() s'en charge.
        let mut enc_file = EncryptedFile::open(
            test_file_path,
            Aes256CtrCipher::new(key.clone()),
            true,
            true,
        )
        .expect("Échec de la création du fichier");

        assert_eq!(
            enc_file.logical_size().unwrap(),
            0,
            "Le fichier logique doit être vide au départ."
        );

        // --- ÉTAPE 2 : Streaming ---
        let chunk1 = b"Bonjour, ceci "; // 14 octets
        let chunk2 = b"est un test de "; // 15 octets
        let chunk3 = b"streaming OS."; // 13 octets

        enc_file.write_chunk(0, chunk1).unwrap();
        enc_file.write_chunk(14, chunk2).unwrap();
        enc_file.write_chunk(29, chunk3).unwrap();

        assert_eq!(enc_file.logical_size().unwrap(), 42);

        // --- ÉTAPE 3 : Fermeture et Réouverture ---
        // On détruit l'instance en mémoire pour forcer une réouverture depuis le disque
        drop(enc_file);

        // On ouvre le fichier existant en lecture seule (create/truncate: false, write_access: false).
        let mut read_file =
            EncryptedFile::open(test_file_path, Aes256CtrCipher::new(key), false, false)
                .expect("Échec de la réouverture du fichier");

        let read_offset = 21;
        let read_size = 4;
        let read_buffer = read_file.read_chunk(read_offset, read_size).unwrap();

        // Si le mot "test" est bien déchiffré, cela prouve que le programme a correctement lu l'IV dans l'en-tête !
        assert_eq!(read_buffer.0.as_slice(), b"test");

        let _ = fs::remove_file(test_file_path);
    }
}
