use rand::Rng;
use std::io::{self, Read, Write};

use crate::crypto::mac::MAC_TAG_SIZE;
use crate::storage::header::errors::HeaderError;

/// Header layout (little-endian, fixed positions):
/// - bytes 0..16:  random IV (per-file, regenerated on truncate)
/// - bytes 16..24: logical (plaintext) file size
/// - bytes 24..32: reserved (zero today, version / flags tomorrow)
/// - bytes 32..64: HMAC-SHA256 tag covering bytes 0..32 || all ciphertext
///
/// HEADER_SIZE was 32 before v0.2; growing to 64 is intentional and incompatible
/// with vaults created by older versions.
pub const HEADER_SIZE: u64 = 64;
/// Plaintext metadata (everything except the MAC tag) feeds the HMAC input.
pub const HEADER_PLAINTEXT_SIZE: u64 = 32;
/// The IV is 16 bytes, so the logical size starts exactly at byte 16.
pub const LOGICAL_SIZE_OFFSET: u64 = 16;
/// MAC tag occupies the second half of the header.
pub const MAC_TAG_OFFSET: u64 = 32;

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub iv: [u8; 16],
    pub logical_size: u64,
    pub reserved: [u8; 8],
    pub mac_tag: [u8; MAC_TAG_SIZE],
}

impl FileHeader {
    pub fn generate_new() -> Self {
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut iv);
        Self {
            iv,
            logical_size: 0,
            reserved: [0u8; 8],
            mac_tag: [0u8; MAC_TAG_SIZE],
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

        let mut mac_tag = [0u8; MAC_TAG_SIZE];
        reader
            .read_exact(&mut mac_tag)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::ReadMacTagFailed))?;

        Ok(Self {
            iv,
            logical_size: u64::from_le_bytes(size_bytes),
            reserved,
            mac_tag,
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
        writer
            .write_all(&self.mac_tag)
            .map_err(|e| io::Error::new(e.kind(), HeaderError::WriteMacTagFailed))?;
        Ok(())
    }

    /// Serialize the plaintext-covered portion of the header (everything but the
    /// MAC tag itself). This buffer is the prefix that feeds the HMAC builder.
    pub fn plaintext_bytes(&self) -> [u8; HEADER_PLAINTEXT_SIZE as usize] {
        let mut buf = [0u8; HEADER_PLAINTEXT_SIZE as usize];
        buf[0..16].copy_from_slice(&self.iv);
        buf[16..24].copy_from_slice(&self.logical_size.to_le_bytes());
        buf[24..32].copy_from_slice(&self.reserved);
        buf
    }
}
