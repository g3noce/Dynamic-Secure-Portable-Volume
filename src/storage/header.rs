use rand::Rng;
use std::fmt;
use std::io::{self, Read, Write};

pub const HEADER_SIZE: u64 = 32;
// The IV is 16 bytes, so the logical size starts exactly at byte 16.
pub const LOGICAL_SIZE_OFFSET: u64 = 16;

// --- ADDITION: Structured enum for custom errors ---
#[derive(Debug)]
pub enum HeaderError {
    ReadIvFailed,
    ReadSizeFailed,
    ReadReservedFailed,
    WriteIvFailed,
    WriteSizeFailed,
    WriteReservedFailed,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            HeaderError::ReadIvFailed => ("read_from", "failed to read IV"),
            HeaderError::ReadSizeFailed => ("read_from", "failed to read logical size"),
            HeaderError::ReadReservedFailed => ("read_from", "failed to read reserved area"),
            HeaderError::WriteIvFailed => ("write_to", "failed to write IV"),
            HeaderError::WriteSizeFailed => ("write_to", "failed to write logical size"),
            HeaderError::WriteReservedFailed => ("write_to", "failed to write reserved area"),
        };
        write!(f, "mod: header, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for HeaderError {}
// ----------------------------------------------------------------------

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
        reader
            .read_exact(&mut iv)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::ReadIvFailed))?;

        let mut size_bytes = [0u8; 8];
        reader
            .read_exact(&mut size_bytes)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::ReadSizeFailed))?;

        let mut reserved = [0u8; 8];
        reader
            .read_exact(&mut reserved)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::ReadReservedFailed))?;

        Ok(Self {
            iv,
            logical_size: u64::from_le_bytes(size_bytes),
            reserved,
        })
    }

    pub fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer
            .write_all(&self.iv)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::WriteIvFailed))?;
        writer
            .write_all(&self.logical_size.to_le_bytes())
            .map_err(|e| io::Error::new(e.kind(), HeaderError::WriteSizeFailed))?;
        writer
            .write_all(&self.reserved)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::WriteReservedFailed))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    // ----------------------------------------------------------------
    // EXISTING TESTS (Basic Functionality)
    // ----------------------------------------------------------------

    #[test]
    fn test_header_generate_new() {
        let header1 = FileHeader::generate_new();
        let header2 = FileHeader::generate_new();

        assert_eq!(header1.logical_size, 0);
        assert_eq!(header1.reserved, [0u8; 8]);
        assert_ne!(header1.iv, header2.iv, "The IV must be random");
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
    // CRITICAL TESTS (Extreme Resilience)
    // ----------------------------------------------------------------

    /// TEST 1: Corrupted or incomplete file (Short Read)
    /// A native explorer can sometimes create a 0-byte file or interrupt it.
    #[test]
    fn test_header_short_read_prevents_panic() {
        // A 20-byte buffer (IV read, but logical size is cut in the middle)
        let buffer = vec![0u8; 20];
        let mut cursor = Cursor::new(buffer);

        let result = FileHeader::read_from(&mut cursor);

        assert!(
            result.is_err(),
            "CRITICAL: The reader accepted an incomplete header without triggering an error!"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof,
            "The returned error must be exactly UnexpectedEof to be properly handled by chunk_io"
        );
    }

    /// TEST 2: Cross-Platform Stability (Endianness)
    /// If the volume is mounted on a Big Endian vs Little Endian architecture,
    /// the logical size must not be altered.
    #[test]
    fn test_header_endianness_crossplatform_guarantee() {
        let mut header = FileHeader::generate_new();
        // Asymmetrical hexadecimal value to easily spot byte order
        header.logical_size = 0x1122334455667788;

        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();

        // Offset 16 corresponds to `logical_size`.
        // The `to_le_bytes` call requires the least significant byte (0x88) to be written first.
        let size_bytes = &buffer[16..24];
        let expected_bytes: [u8; 8] = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

        assert_eq!(
            size_bytes, &expected_bytes,
            "CRITICAL: Serialization is not strictly Little Endian. The volume will be corrupted across architectures!"
        );
    }

    /// TEST 3: Physical offsets stability (Binary Layout)
    /// Prevents a future code modification from mistakenly swapping
    /// the position of the size and the IV in the physical file.
    #[test]
    fn test_header_binary_layout_strictness() {
        let mut buffer = Vec::new();
        let header = FileHeader {
            iv: [0xFF; 16],
            logical_size: 255, // 0x00000000000000FF (255)
            reserved: [0xAA; 8],
        };
        header.write_to(&mut buffer).unwrap();

        // 1. Check total size dictated by AES-XTS
        assert_eq!(buffer.len(), 32, "The header must be EXACTLY 32 bytes");

        // 2. The IV must occupy the first 16-byte block (offset 0 to 15)
        assert_eq!(
            &buffer[0..16],
            &[0xFF; 16],
            "The IV was shifted from its original physical offset"
        );

        // 3. The size must occupy the offset defined by LOGICAL_SIZE_OFFSET (16 to 23)
        assert_eq!(
            &buffer[16..24],
            &[0xFF, 0, 0, 0, 0, 0, 0, 0],
            "The logical size is no longer at offset 16"
        );

        // 4. Reserved bytes to align to 32 (offset 24 to 31)
        assert_eq!(
            &buffer[24..32],
            &[0xAA; 8],
            "The reserved area is not aligned at the end of the header"
        );
    }
}
