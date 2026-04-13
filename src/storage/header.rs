use rand::Rng;
use std::io::{self, Read, Write};

pub const HEADER_SIZE: u64 = 32;
// L'IV fait 16 octets, donc la taille logique commence exactement à l'octet 16.
pub const LOGICAL_SIZE_OFFSET: u64 = 16;

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub iv: [u8; 16],
    pub logical_size: u64,
    pub reserved: [u8; 8],
}

impl FileHeader {
    pub fn generate_new() -> Self {
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut iv);
        Self {
            iv,
            logical_size: 0,
            reserved: [0u8; 8],
        }
    }

    pub fn read_from<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut iv = [0u8; 16];
        reader.read_exact(&mut iv)?;

        let mut size_bytes = [0u8; 8];
        reader.read_exact(&mut size_bytes)?;

        let mut reserved = [0u8; 8];
        reader.read_exact(&mut reserved)?;

        Ok(Self {
            iv,
            logical_size: u64::from_le_bytes(size_bytes),
            reserved,
        })
    }

    pub fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.iv)?;
        writer.write_all(&self.logical_size.to_le_bytes())?;
        writer.write_all(&self.reserved)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    // ----------------------------------------------------------------
    // TESTS EXISTANTS (Fonctionnalité de base)
    // ----------------------------------------------------------------

    #[test]
    fn test_header_generate_new() {
        let header1 = FileHeader::generate_new();
        let header2 = FileHeader::generate_new();

        assert_eq!(header1.logical_size, 0);
        assert_eq!(header1.reserved, [0u8; 8]);
        assert_ne!(header1.iv, header2.iv, "L'IV doit être aléatoire");
    }

    #[test]
    fn test_header_generation_and_io() {
        let header = FileHeader {
            iv: [0x42; 16],
            logical_size: 1337,
            reserved: [0u8; 8],
        };
        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();
        assert_eq!(buffer.len(), HEADER_SIZE as usize);

        let mut cursor = Cursor::new(buffer);
        let read_header = FileHeader::read_from(&mut cursor).unwrap();
        assert_eq!(header.iv, read_header.iv);
        assert_eq!(header.logical_size, read_header.logical_size);
    }

    // ----------------------------------------------------------------
    // TESTS CRITIQUES (Résilience Extrême)
    // ----------------------------------------------------------------

    /// TEST 1 : Fichier corrompu ou incomplet (Short Read)
    /// Un explorateur natif peut parfois créer un fichier de 0 octet ou l'interrompre.
    #[test]
    fn test_header_short_read_prevents_panic() {
        // Un buffer de 20 octets (IV lu, mais la taille logique est coupée en plein milieu)
        let buffer = vec![0u8; 20];
        let mut cursor = Cursor::new(buffer);

        let result = FileHeader::read_from(&mut cursor);

        assert!(
            result.is_err(),
            "CRITICAL: Le lecteur a accepté un header incomplet sans déclencher d'erreur !"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
            "L'erreur renvoyée doit être exactement UnexpectedEof pour être gérée proprement par chunk_io"
        );
    }

    /// TEST 2 : Stabilité Cross-Platform (Endianness)
    /// Si le volume est monté sur une architecture Big Endian vs Little Endian,
    /// la taille logique ne doit pas être altérée.
    #[test]
    fn test_header_endianness_crossplatform_guarantee() {
        let mut header = FileHeader::generate_new();
        // Valeur hexadécimale asymétrique pour repérer facilement l'ordre des octets
        header.logical_size = 0x1122334455667788;

        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();

        // L'offset 16 correspond à `logical_size`.
        // L'appel `to_le_bytes` exige que le byte de poids faible (0x88) soit le premier écrit.
        let size_bytes = &buffer[16..24];
        let expected_bytes: [u8; 8] = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

        assert_eq!(
            size_bytes, &expected_bytes,
            "CRITICAL: La sérialisation n'est pas en Little Endian strict. Le volume sera corrompu d'une architecture à l'autre !"
        );
    }

    /// TEST 3 : Stabilité des offsets physiques (Layout Binaire)
    /// Empêche une future modification du code d'inverser par erreur
    /// la position de la taille et de l'IV dans le fichier physique.
    #[test]
    fn test_header_binary_layout_strictness() {
        let mut buffer = Vec::new();
        let header = FileHeader {
            iv: [0xFF; 16],
            logical_size: 255, // 0x00000000000000FF (255)
            reserved: [0xAA; 8],
        };
        header.write_to(&mut buffer).unwrap();

        // 1. Vérification de la taille totale dictée par AES-XTS
        assert_eq!(
            buffer.len(),
            32,
            "Le header doit faire EXACTEMENT 32 octets"
        );

        // 2. L'IV doit occuper le premier bloc de 16 octets (offset 0 à 15)
        assert_eq!(
            &buffer[0..16],
            &[0xFF; 16],
            "L'IV a été décalé de son offset physique d'origine"
        );

        // 3. La taille doit occuper l'offset défini par LOGICAL_SIZE_OFFSET (16 à 23)
        assert_eq!(
            &buffer[16..24],
            &[0xFF, 0, 0, 0, 0, 0, 0, 0],
            "La taille logique n'est plus à l'offset 16"
        );

        // 4. Les octets réservés pour s'aligner sur 32 (offset 24 à 31)
        assert_eq!(
            &buffer[24..32],
            &[0xAA; 8],
            "La zone réservée n'est pas alignée à la fin du header"
        );
    }
}
