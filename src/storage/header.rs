use rand::Rng;
use std::fmt;
use std::io::{self, Read, Write};

pub const HEADER_SIZE: u64 = 32;
pub const LOGICAL_SIZE_OFFSET: u64 = 16;

#[derive(Debug)]
pub enum HeaderError {
    ReadIv,
    ReadSize,
    ReadReserved,
    WriteIv,
    WriteSize,
    WriteReserved,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            HeaderError::ReadIv => ("read_from", "failed to read IV"),
            HeaderError::ReadSize => ("read_from", "failed to read logical size"),
            HeaderError::ReadReserved => ("read_from", "failed to read reserved area"),
            HeaderError::WriteIv => ("write_to", "failed to write IV"),
            HeaderError::WriteSize => ("write_to", "failed to write logical size"),
            HeaderError::WriteReserved => ("write_to", "failed to write reserved area"),
        };
        write!(f, "mod: header, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for HeaderError {}

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
            .map_err(|e| io::Error::new(e.kind(), HeaderError::ReadIv))?;

        let mut size_bytes = [0u8; 8];
        reader
            .read_exact(&mut size_bytes)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::ReadSize))?;

        let mut reserved = [0u8; 8];
        reader
            .read_exact(&mut reserved)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::ReadReserved))?;

        Ok(Self {
            iv,
            logical_size: u64::from_le_bytes(size_bytes),
            reserved,
        })
    }

    pub fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer
            .write_all(&self.iv)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::WriteIv))?;
        writer
            .write_all(&self.logical_size.to_le_bytes())
            .map_err(|e| io::Error::new(e.kind(), HeaderError::WriteSize))?;
        writer
            .write_all(&self.reserved)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::WriteReserved))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, ErrorKind};

    /// TEST 1: Full Lifecycle & Consistency
    /// Ensures headers can be generated, written to a buffer, and correctly restored.
    #[test]
    fn test_header_lifecycle() {
        let header = FileHeader::generate_new();
        assert_eq!(
            header.logical_size, 0,
            "New headers must start with 0 logical size"
        );
        assert_eq!(header.reserved, [0u8; 8], "Reserved space must be zeroed");

        // Write to buffer
        let mut buffer = Vec::new();
        header
            .write_to(&mut buffer)
            .expect("Writing header to buffer failed");
        assert_eq!(
            buffer.len(),
            HEADER_SIZE as usize,
            "Buffer size must match HEADER_SIZE"
        );

        // Read back from buffer
        let mut cursor = Cursor::new(buffer);
        let recovered = FileHeader::read_from(&mut cursor).expect("Reading header failed");

        assert_eq!(
            header.iv, recovered.iv,
            "Recovered IV does not match original"
        );
        assert_eq!(
            header.logical_size, recovered.logical_size,
            "Recovered size does not match"
        );
    }

    /// TEST 2: Strict Binary Layout & Endianness
    /// Guarantees the 32-byte layout is exact: IV (16) + LE Size (8) + Reserved (8).
    /// This ensures cross-platform compatibility (Little-Endian strictness).
    #[test]
    fn test_binary_layout_and_endianness() {
        let header = FileHeader {
            iv: [0xAA; 16],
            logical_size: 0x1122334455667788, // Asymmetric pattern to verify byte order
            reserved: [0xBB; 8],
        };

        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();

        // Verify exact physical offsets
        assert_eq!(&buffer[0..16], &[0xAA; 16], "IV is misplaced");

        // Verify strict Little Endian serialization at LOGICAL_SIZE_OFFSET
        let expected_size: [u8; 8] = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        assert_eq!(
            &buffer[16..24],
            &expected_size,
            "Logical size is not properly Little-Endian"
        );

        // Verify reserved space offset
        assert_eq!(&buffer[24..32], &[0xBB; 8], "Reserved space is misplaced");
    }

    /// TEST 3: Hardware Failure Resilience (Incomplete Reads)
    /// Ensures reading from a corrupted, abruptly truncated file is handled gracefully
    /// and returns the proper custom error context.
    #[test]
    fn test_incomplete_read_handling() {
        // Simulate a corrupted file with only 20 bytes (Full IV, partial size)
        let buffer = vec![0u8; 20];
        let mut cursor = Cursor::new(buffer);

        let result = FileHeader::read_from(&mut cursor);

        assert!(result.is_err(), "Reader must reject incomplete headers");

        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            ErrorKind::UnexpectedEof,
            "Must trigger an EOF error"
        );

        // Verify the custom inner error maps properly to our `HeaderError`
        let inner_err_str = err.into_inner().unwrap().to_string();
        assert!(
            inner_err_str.contains("failed to read logical size"),
            "Custom error context is missing or incorrect"
        );
    }
}
