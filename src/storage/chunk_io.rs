use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::cipher::ChunkCipher;
use crate::storage::header::{FileHeader, HEADER_SIZE, LOGICAL_SIZE_OFFSET};
use crate::utils::memory::SecureBuffer;

const XTS_BLOCK_SIZE: u64 = 16;

// --- ADDITION: Structured enum for custom errors ---
#[derive(Debug)]
pub enum ChunkIoError {
    InitReadOnly,
    XtsDecryptionFailed,
    RmwDecryptionFailed,
    RmwEncryptionFailed,
}

impl fmt::Display for ChunkIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            ChunkIoError::InitReadOnly => ("open", "cannot initialize a header in read-only mode"),
            ChunkIoError::XtsDecryptionFailed => ("read_chunk", "XTS decryption failed"),
            ChunkIoError::RmwDecryptionFailed => ("write_chunk", "RMW decryption failed"),
            ChunkIoError::RmwEncryptionFailed => ("write_chunk", "RMW encryption failed"),
        };
        write!(f, "mod: chunk_io, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for ChunkIoError {}
// ----------------------------------------------------------------------

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
                return Err(io::Error::other(ChunkIoError::InitReadOnly));
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
                .map_err(|_| io::Error::other(ChunkIoError::XtsDecryptionFailed))?;
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
                    .map_err(|_| io::Error::other(ChunkIoError::RmwDecryptionFailed))?;
            }
        }

        let relative_start = (logical_offset - align_start) as usize;
        block_buffer.0[relative_start..(relative_start + data.len())].copy_from_slice(data);

        self.cipher
            .encrypt_chunk(&self.header.iv, align_start, &mut block_buffer.0)
            .map_err(|_| io::Error::other(ChunkIoError::RmwEncryptionFailed))?;

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
    // EXISTING TESTS (Basics)
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
            "Opening a non-existent file in read-only mode should fail"
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
            "The physical size must include the header and data"
        );
        let _ = fs::remove_file(path);
    }

    // ----------------------------------------------------------------
    // CRITICAL TESTS (New - Extreme Robustness)
    // ----------------------------------------------------------------

    /// TEST 1: RMW straddling multiple cryptographic blocks
    /// Verifies that if we write from byte 10 to 25 (overlapping blocks 0 and 1),
    /// the system decrypts both blocks, modifies the middle, and re-encrypts without corrupting the edges.
    #[test]
    fn test_chunk_io_cross_block_rmw() {
        let path = "test_cross_block.enc";
        let mut enc_file = setup_test_file(path);

        // 1. Initialize 2 complete blocks (32 bytes) with 'A's
        let initial_data = [b'A'; 32];
        enc_file.write_chunk(0, &initial_data).unwrap();

        // 2. UNALIGNED write of 10 bytes starting at offset 14 (ends at 24)
        // Block 0: from 0 to 15 (touched at the end)
        // Block 1: from 16 to 31 (touched at the beginning)
        let inject_data = b"0123456789";
        enc_file.write_chunk(14, inject_data).unwrap();

        // 3. Read and global verification
        let result = enc_file.read_chunk(0, 32).unwrap();

        let mut expected = [b'A'; 32];
        expected[14..24].copy_from_slice(b"0123456789");

        assert_eq!(
            result.0.as_slice(),
            expected,
            "CRITICAL: The Read-Modify-Write operation corrupted data at XTS block boundaries!"
        );

        let _ = fs::remove_file(path);
    }

    /// TEST 2: EOF (End Of File) boundary security
    /// Prevents the client from reading the "garbage" (padding) generated by block encryption.
    #[test]
    fn test_chunk_io_eof_read_behavior() {
        let path = "test_eof.enc";
        let mut enc_file = setup_test_file(path);

        // We write 5 bytes. Physical = 16 bytes (1 block padded with encrypted zeros)
        enc_file.write_chunk(0, b"Hello").unwrap();
        assert_eq!(enc_file.logical_size().unwrap(), 5);

        // Attempt to read 20 bytes (overflow)
        let result = enc_file.read_chunk(0, 20).unwrap();

        assert_eq!(
            result.0.len(),
            5,
            "CRITICAL: The reader returned hidden cryptographic XTS padding or memory garbage!"
        );
        assert_eq!(result.0.as_slice(), b"Hello");

        // Attempt pure out-of-bounds read
        let oob_result = enc_file.read_chunk(10, 5).unwrap();
        assert_eq!(
            oob_result.0.len(),
            0,
            "Reading outside the logical file must return 0 bytes."
        );

        let _ = fs::remove_file(path);
    }

    /// TEST 3: Behavior against Zero-length I/O
    /// The OS (especially Linux/macOS) sometimes makes "empty" calls to test access.
    #[test]
    fn test_chunk_io_zero_length_operations() {
        let path = "test_zero_len.enc";
        let mut enc_file = setup_test_file(path);

        enc_file.write_chunk(0, b"Data").unwrap();

        // Empty write
        enc_file.write_chunk(2, &[]).unwrap();
        assert_eq!(
            enc_file.logical_size().unwrap(),
            4,
            "The empty write modified the logical size!"
        );

        // Empty read
        let result = enc_file.read_chunk(1, 0).unwrap();
        assert_eq!(result.0.len(), 0, "The empty read returned data!");

        let _ = fs::remove_file(path);
    }

    /// TEST 4: Truncate and Cryptographic Security (IV Rotation)
    /// Overwriting a file MUST generate a new IV, otherwise AES-XTS loses all its strength.
    #[test]
    fn test_chunk_io_truncate_and_iv_rotation() {
        let path = "test_truncate_iv.enc";
        let key = SecureKey(vec![0x42; 64]);

        // 1. First life of the file
        let mut file1 =
            EncryptedFile::open(path, Aes256XtsCipher::new(key.clone()), true, true).unwrap();
        file1.write_chunk(0, b"Old confidential data").unwrap();
        let iv1 = file1.header.iv;
        drop(file1);

        // 2. Second life of the file (Truncate by OS)
        let file2 = EncryptedFile::open(path, Aes256XtsCipher::new(key), true, true).unwrap();
        let iv2 = file2.header.iv;

        assert_eq!(
            file2.logical_size().unwrap(),
            0,
            "Truncate did not set the logical size to zero"
        );
        assert_ne!(
            iv1, iv2,
            "CRITICAL: Cryptographic flaw! The IV was not renewed during truncate."
        );

        let _ = fs::remove_file(path);
    }

    /// TEST 5: Very large block arithmetic (Memory Stress Test)
    #[test]
    fn test_chunk_io_large_file_multiple_chunks() {
        let path = "test_large_chunks.enc";
        let mut enc_file = setup_test_file(path);

        // Payload of 10,000 bytes (neither aligned to 16, nor a perfect multiple)
        let payload: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        // We write everything at once
        enc_file.write_chunk(0, &payload).unwrap();
        assert_eq!(enc_file.logical_size().unwrap(), 10000);

        // We read it all back
        let result = enc_file.read_chunk(0, 10000).unwrap();
        assert_eq!(result.0.len(), 10000);
        assert_eq!(
            result.0.as_slice(),
            payload.as_slice(),
            "Writing a large buffer was corrupted"
        );

        let _ = fs::remove_file(path);
    }
}
