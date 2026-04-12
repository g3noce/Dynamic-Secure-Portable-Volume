use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
// CORRECTION ICI : On importe le trait Rng
use rand::Rng;

/// Signature unique pour identifier les fichiers de notre application (Dynamic Secure Portable Volume).
/// "DSPV" en ASCII.
pub const MAGIC_NUMBER: [u8; 4] = [0x44, 0x53, 0x50, 0x56];

/// La taille totale de l'en-tête (Magic Number + IV).
/// 4 octets (Magic) + 16 octets (IV) = 20 octets.
pub const HEADER_SIZE: u64 = 20;

#[derive(Debug, Clone, PartialEq)]
pub struct FileHeader {
    pub iv: [u8; 16],
}

impl FileHeader {
    /// Génère un nouvel en-tête avec un IV aléatoire sécurisé.
    pub fn generate_new() -> Self {
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut iv);
        Self { iv }
    }

    /// Écrit l'en-tête (Magic Number + IV) au tout début d'un fichier.
    pub fn write_to(&self, file: &mut File) -> io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&MAGIC_NUMBER)?;
        file.write_all(&self.iv)?;
        file.flush()?;
        Ok(())
    }

    /// Lit et valide l'en-tête d'un fichier existant.
    pub fn read_from(file: &mut File) -> io::Result<Self> {
        file.seek(SeekFrom::Start(0))?;

        // 1. Vérification de la signature (Magic Number)
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;

        if magic != MAGIC_NUMBER {
            return Err(io::Error::other(
                "Fichier invalide : signature DSPV manquante ou corrompue.",
            ));
        }

        // 2. Lecture du Vecteur d'Initialisation (IV)
        let mut iv = [0u8; 16];
        file.read_exact(&mut iv)?;

        Ok(Self { iv })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    #[test]
    fn test_header_generation_and_io() {
        let test_file = "test_header.enc";
        let _ = std::fs::remove_file(test_file);

        let original_header = FileHeader::generate_new();

        {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(test_file)
                .unwrap();

            original_header.write_to(&mut file).unwrap();
        }

        {
            let mut file = OpenOptions::new().read(true).open(test_file).unwrap();
            let read_header = FileHeader::read_from(&mut file).unwrap();

            assert_eq!(
                original_header, read_header,
                "L'IV lu doit correspondre à l'IV écrit"
            );
        }

        let _ = std::fs::remove_file(test_file);
    }
}
