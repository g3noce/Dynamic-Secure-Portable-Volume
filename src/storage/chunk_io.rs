use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::cipher::AuthenticatedChunkCipher;
use crate::storage::header::{FileHeader, HEADER_SIZE, LOGICAL_SIZE_OFFSET};
use crate::utils::memory::SecureBuffer;

pub const CHUNK_LOGICAL_SIZE: u64 = 65536;
pub const MAC_SIZE: u64 = 40;
pub const CHUNK_PHYSICAL_SIZE: u64 = CHUNK_LOGICAL_SIZE + MAC_SIZE;

#[derive(Debug)]
pub enum ChunkIoError {
    InitReadOnly,
    AuthenticationFailed,
    EncryptionFailed,
}

impl fmt::Display for ChunkIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (func, cause) = match self {
            ChunkIoError::InitReadOnly => ("open", "cannot initialize a header in read-only mode"),
            ChunkIoError::AuthenticationFailed => {
                ("read/write", "data authentication (MAC) failed")
            }
            ChunkIoError::EncryptionFailed => ("write_chunk", "AEAD encryption failed"),
        };
        write!(f, "mod: chunk_io, function: {}, cause: {}", func, cause)
    }
}

impl std::error::Error for ChunkIoError {}

pub struct EncryptedFile<C: AuthenticatedChunkCipher> {
    file: File,
    cipher: C,
    header: FileHeader,
}

impl<C: AuthenticatedChunkCipher> EncryptedFile<C> {
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

        let max_logical_available = self.header.logical_size.saturating_sub(logical_offset);
        if max_logical_available == 0 {
            return Ok(SecureBuffer(vec![]));
        }
        let read_size = std::cmp::min(size as u64, max_logical_available) as usize;

        let mut result_buffer = Vec::with_capacity(read_size);
        let mut current_offset = logical_offset;
        let end_offset = logical_offset + read_size as u64;

        while current_offset < end_offset {
            let chunk_index = current_offset / CHUNK_LOGICAL_SIZE;
            let offset_in_chunk = (current_offset % CHUNK_LOGICAL_SIZE) as usize;

            let remaining_in_request = (end_offset - current_offset) as usize;
            let remaining_in_chunk = CHUNK_LOGICAL_SIZE as usize - offset_in_chunk;
            let bytes_to_read_from_this_chunk =
                std::cmp::min(remaining_in_request, remaining_in_chunk);

            let physical_offset = HEADER_SIZE + (chunk_index * CHUNK_PHYSICAL_SIZE);
            self.file.seek(SeekFrom::Start(physical_offset))?;

            let mut physical_buffer = vec![0u8; CHUNK_PHYSICAL_SIZE as usize];
            let bytes_read = self.file.read(&mut physical_buffer)?;

            let clear_chunk = if bytes_read > 0 {
                physical_buffer.truncate(bytes_read);
                self.cipher
                    .decrypt_chunk(&self.header.iv, chunk_index, &physical_buffer)
                    .map_err(|_| io::Error::other(ChunkIoError::AuthenticationFailed))?
            } else {
                return Err(io::Error::other(ChunkIoError::AuthenticationFailed));
            };

            if offset_in_chunk + bytes_to_read_from_this_chunk > clear_chunk.len() {
                return Err(io::Error::other(ChunkIoError::AuthenticationFailed));
            }

            result_buffer.extend_from_slice(
                &clear_chunk[offset_in_chunk..(offset_in_chunk + bytes_to_read_from_this_chunk)],
            );
            current_offset += bytes_to_read_from_this_chunk as u64;
        }

        Ok(SecureBuffer(result_buffer))
    }

    pub fn write_chunk(&mut self, logical_offset: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut current_offset = logical_offset;
        let end_offset = logical_offset + data.len() as u64;
        let mut data_cursor = 0;

        while current_offset < end_offset {
            let chunk_index = current_offset / CHUNK_LOGICAL_SIZE;
            let offset_in_chunk = (current_offset % CHUNK_LOGICAL_SIZE) as usize;

            let remaining_in_request = data.len() - data_cursor;
            let remaining_in_chunk = CHUNK_LOGICAL_SIZE as usize - offset_in_chunk;
            let bytes_to_write_to_this_chunk =
                std::cmp::min(remaining_in_request, remaining_in_chunk);

            let mut clear_chunk = vec![0u8; CHUNK_LOGICAL_SIZE as usize];

            let physical_offset = HEADER_SIZE + (chunk_index * CHUNK_PHYSICAL_SIZE);

            if offset_in_chunk > 0 || bytes_to_write_to_this_chunk < CHUNK_LOGICAL_SIZE as usize {
                self.file.seek(SeekFrom::Start(physical_offset))?;
                let mut physical_buffer = vec![0u8; CHUNK_PHYSICAL_SIZE as usize];
                let bytes_read = self.file.read(&mut physical_buffer)?;

                if bytes_read > 0 {
                    physical_buffer.truncate(bytes_read);
                    let decrypted = self
                        .cipher
                        .decrypt_chunk(&self.header.iv, chunk_index, &physical_buffer)
                        .map_err(|_| io::Error::other(ChunkIoError::AuthenticationFailed))?;

                    clear_chunk[..decrypted.len()].copy_from_slice(&decrypted);
                }
            }

            clear_chunk[offset_in_chunk..(offset_in_chunk + bytes_to_write_to_this_chunk)]
                .copy_from_slice(&data[data_cursor..(data_cursor + bytes_to_write_to_this_chunk)]);

            let encrypted_chunk = self
                .cipher
                .encrypt_chunk(&self.header.iv, chunk_index, &clear_chunk)
                .map_err(|_| io::Error::other(ChunkIoError::EncryptionFailed))?;

            self.file.seek(SeekFrom::Start(physical_offset))?;
            self.file.write_all(&encrypted_chunk)?;

            current_offset += bytes_to_write_to_this_chunk as u64;
            data_cursor += bytes_to_write_to_this_chunk;
        }

        if end_offset > self.header.logical_size {
            self.header.logical_size = end_offset;
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
    use crate::crypto::cipher::ChaChaPolyCipher;
    use crate::utils::memory::SecureKey;
    use std::fs;

    // --- Helper ---
    // Automates setup and ensures physical file cleanup even if tests panic.
    struct TestEnv {
        path: &'static str,
    }

    impl TestEnv {
        fn new(path: &'static str) -> Self {
            let _ = fs::remove_file(path);
            Self { path }
        }
        fn get_file(&self, truncate: bool) -> EncryptedFile<ChaChaPolyCipher> {
            let key = SecureKey(vec![0x42; 32]);
            EncryptedFile::open(self.path, ChaChaPolyCipher::new(key), truncate, true).unwrap()
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.path);
        }
    }

    /// TEST 1: Basic I/O, EOF limitations, and Zero-length handling
    #[test]
    fn test_basic_io_and_eof() {
        let env = TestEnv::new("test_basic_io.enc");
        let mut f = env.get_file(true);

        // Standard Write
        f.write_chunk(0, b"HelloWorld").unwrap();
        assert_eq!(f.logical_size().unwrap(), 10);

        // Normal Read
        assert_eq!(f.read_chunk(0, 5).unwrap().0, b"Hello");

        // EOF Overshoot (Requesting 20 bytes when only 5 remain)
        assert_eq!(f.read_chunk(5, 20).unwrap().0, b"World");

        // Out-of-bounds Read
        assert_eq!(f.read_chunk(50, 10).unwrap().0.len(), 0);

        // Zero-length operations (Should not crash or alter size)
        f.write_chunk(2, &[]).unwrap();
        assert_eq!(f.logical_size().unwrap(), 10);
    }

    /// TEST 2: Complex Read-Modify-Write (RMW) and Chunk Boundaries
    /// Verifies overwriting existing data and crossing the 64KB logical chunk boundary.
    #[test]
    fn test_cross_chunk_rmw() {
        let env = TestEnv::new("test_cross_chunk.enc");
        let mut f = env.get_file(true);

        // 1. Target the exact boundary (65536)
        let offset = CHUNK_LOGICAL_SIZE - 4;

        // Write 8 bytes (4 in Chunk 0, 4 in Chunk 1)
        f.write_chunk(offset, b"1234ABCD").unwrap();

        // 2. Read back across the boundary
        assert_eq!(f.read_chunk(offset, 8).unwrap().0, b"1234ABCD");

        // 3. Partial Overwrite (RMW inside a chunk)
        f.write_chunk(offset + 2, b"XX").unwrap(); // Changes "34" to "XX"
        assert_eq!(f.read_chunk(offset, 8).unwrap().0, b"12XXABCD");
    }

    /// TEST 3: Multi-Chunk Memory Stress Test
    /// Proves the arithmetic works for operations spanning many chunks.
    #[test]
    fn test_large_payload() {
        let env = TestEnv::new("test_large_payload.enc");
        let mut f = env.get_file(true);

        // 150 KB spans across 3 chunks
        let payload: Vec<u8> = (0..150_000).map(|i| (i % 256) as u8).collect();

        f.write_chunk(0, &payload).unwrap();
        assert_eq!(f.logical_size().unwrap(), 150_000);

        let read_back = f.read_chunk(0, 150_000).unwrap();
        assert_eq!(
            read_back.0, payload,
            "Large multi-chunk read/write corrupted"
        );
    }

    /// TEST 4: Security - Truncation IV Rotation & MAC Tampering
    #[test]
    fn test_security_constraints() {
        let env = TestEnv::new("test_security.enc");

        // 1. Check IV Rotation on Truncate
        let iv1 = {
            let mut f = env.get_file(true);
            f.write_chunk(0, b"Data").unwrap();
            f.header.iv
        };
        let iv2 = env.get_file(true).header.iv;
        assert_ne!(
            iv1, iv2,
            "IV must rotate on file truncation to prevent nonce reuse"
        );

        // 2. Check Tamper Resistance (MAC Rejection)
        let mut f = env.get_file(true);
        f.write_chunk(0, b"Sensitive Data").unwrap();
        drop(f); // Flush to disk

        // Simulate physical corruption
        let mut physical_file = std::fs::OpenOptions::new()
            .write(true)
            .open(env.path)
            .unwrap();
        physical_file
            .seek(std::io::SeekFrom::Start(HEADER_SIZE + 10))
            .unwrap();
        physical_file.write_all(&[0xFF]).unwrap();
        drop(physical_file);

        // Attempt to read corrupted data
        let mut compromised = env.get_file(false);
        let result = compromised.read_chunk(0, 14);

        assert!(
            matches!(
                result
                    .unwrap_err()
                    .into_inner()
                    .unwrap()
                    .downcast_ref::<ChunkIoError>(),
                Some(ChunkIoError::AuthenticationFailed)
            ),
            "Tampered data bypassed MAC verification"
        );
    }
}
