use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::cipher::ChunkCipher;
use crate::crypto::mac::{self, MAC_KEY_SIZE, MAC_TAG_SIZE, MacBuilder};
use crate::storage::chunk_io::errors::ChunkIoError;
use crate::storage::header::{FileHeader, HEADER_SIZE, LOGICAL_SIZE_OFFSET, MAC_TAG_OFFSET};
use crate::utils::memory::{SecureBuffer, SecureKey};

const XTS_BLOCK_SIZE: u64 = 16;
/// How much ciphertext we pull off disk per loop iteration while (re)computing
/// the file-wide HMAC. Sized to fit comfortably in L1 without too many syscalls.
const MAC_STREAM_CHUNK: usize = 64 * 1024;

pub struct EncryptedFile<C: ChunkCipher> {
    file: File,
    cipher: C,
    header: FileHeader,
    mac_key: SecureKey,
    /// Additional authenticated data prepended to the HMAC input — typically
    /// the vault-relative path of this file. Binding the path into the MAC
    /// prevents swap/rename attacks (an attacker who moves ciphertext between
    /// paths can no longer make either side verify).
    mac_aad: Vec<u8>,
    /// True when the on-disk MAC tag is known to be stale (writes happened
    /// since the last `flush()` or `open()` verification).
    dirty: bool,
    /// Once true, this file is in an integrity-compromised state and refuses
    /// further reads/writes. Set when we detect a MAC mismatch.
    poisoned: bool,
}

impl<C: ChunkCipher> EncryptedFile<C> {
    /// Open or create an encrypted file.
    ///
    /// `mac_key` must carry at least `MAC_KEY_SIZE` (32) bytes — typically the
    /// last 32 bytes of the Argon2-derived master key.
    ///
    /// `mac_aad` is mixed into every HMAC computation for this file. Callers
    /// should pass a stable, path-derived identifier (e.g. the vault-relative
    /// path) so that two files with identical ciphertext at different paths
    /// produce different tags.
    pub fn open<P: AsRef<Path>>(
        path: P,
        cipher: C,
        mac_key: SecureKey,
        mac_aad: Vec<u8>,
        truncate: bool,
        write_access: bool,
    ) -> io::Result<Self> {
        if mac_key.0.len() < MAC_KEY_SIZE {
            return Err(io::Error::other(ChunkIoError::MacKeyMissing));
        }

        let path_ref = path.as_ref();
        let mut opts = OpenOptions::new();
        opts.read(true);

        if write_access {
            opts.write(true).create(true).truncate(false);
        }

        let mut file = opts.open(path_ref)?;
        let metadata = file.metadata()?;
        let is_fresh = metadata.len() == 0 || truncate;

        let header = if is_fresh {
            if !write_access {
                return Err(io::Error::other(ChunkIoError::InitReadOnly));
            }
            file.set_len(0)?;
            let new_header = FileHeader::generate_new();
            new_header.write_to(&mut file)?;
            // No ciphertext yet → compute and persist the initial MAC right away
            // so that a later read-only open finds a valid tag.
            let mut this = Self {
                file,
                cipher,
                header: new_header,
                mac_key,
                mac_aad,
                dirty: true,
                poisoned: false,
            };
            this.recompute_and_write_tag()?;
            return Ok(this);
        } else {
            FileHeader::read_from(&mut file)?
        };

        let mut this = Self {
            file,
            cipher,
            header,
            mac_key,
            mac_aad,
            dirty: false,
            poisoned: false,
        };

        this.verify_integrity()?;
        Ok(this)
    }

    /// Open an existing file without integrity verification, then mark it
    /// dirty so the next `flush()` writes a fresh tag.
    ///
    /// **Only safe for the rename re-MAC path**: after a `fs::rename`, the
    /// stored tag is bound to the old path and would not verify under the new
    /// AAD. The caller is responsible for invoking `flush()` immediately after
    /// to persist a correct tag.
    pub fn open_unverified<P: AsRef<Path>>(
        path: P,
        cipher: C,
        mac_key: SecureKey,
        mac_aad: Vec<u8>,
    ) -> io::Result<Self> {
        if mac_key.0.len() < MAC_KEY_SIZE {
            return Err(io::Error::other(ChunkIoError::MacKeyMissing));
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(path.as_ref())?;
        let header = FileHeader::read_from(&mut file)?;

        Ok(Self {
            file,
            cipher,
            header,
            mac_key,
            mac_aad,
            dirty: true,
            poisoned: false,
        })
    }

    /// Stream the on-disk ciphertext, compute the HMAC, and check it against
    /// the tag stored in the header. Called once at open-time.
    fn verify_integrity(&mut self) -> io::Result<()> {
        let computed = self.compute_current_mac()?;
        if !mac::verify(&self.header.mac_tag, &computed) {
            self.poisoned = true;
            return Err(io::Error::other(ChunkIoError::MacVerificationFailed));
        }
        Ok(())
    }

    /// Build the HMAC of (mac_aad_len || mac_aad || plaintext header bytes ||
    /// ciphertext on disk). The 4-byte length prefix on `mac_aad` removes any
    /// ambiguity between context and header bytes when concatenated.
    /// Seeks the file cursor; callers that care about position must restore it.
    fn compute_current_mac(&mut self) -> io::Result<[u8; MAC_TAG_SIZE]> {
        let mut builder = MacBuilder::new(&self.mac_key.0[..MAC_KEY_SIZE]);
        let aad_len = u32::try_from(self.mac_aad.len()).unwrap_or(u32::MAX);
        builder.update(&aad_len.to_le_bytes());
        builder.update(&self.mac_aad);
        builder.update(&self.header.plaintext_bytes());

        let phys_len = self.file.metadata()?.len();
        let cipher_len = phys_len.saturating_sub(HEADER_SIZE);

        if cipher_len > 0 {
            self.file.seek(SeekFrom::Start(HEADER_SIZE))?;
            let mut remaining = cipher_len;
            let mut buf = vec![0u8; MAC_STREAM_CHUNK];
            while remaining > 0 {
                let want = std::cmp::min(remaining as usize, buf.len());
                let read = self.file.read(&mut buf[..want])?;
                if read == 0 {
                    // File shrank under us between metadata() and read(); stop
                    // gracefully — the resulting tag will simply not match if
                    // there's foul play.
                    break;
                }
                builder.update(&buf[..read]);
                remaining -= read as u64;
            }
        }

        Ok(builder.finalize())
    }

    fn recompute_and_write_tag(&mut self) -> io::Result<()> {
        let tag = self.compute_current_mac()?;
        self.header.mac_tag = tag;
        self.file.seek(SeekFrom::Start(MAC_TAG_OFFSET))?;
        self.file.write_all(&self.header.mac_tag)?;
        self.dirty = false;
        Ok(())
    }

    fn ensure_usable(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(ChunkIoError::MacVerificationFailed));
        }
        Ok(())
    }

    pub fn read_chunk(&mut self, logical_offset: u64, size: usize) -> io::Result<SecureBuffer> {
        self.ensure_usable()?;

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
        self.ensure_usable()?;

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

        self.dirty = true;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        if self.dirty {
            self.recompute_and_write_tag()?;
        }
        self.file.flush()
    }

    pub fn logical_size(&self) -> io::Result<u64> {
        Ok(self.header.logical_size)
    }

    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata()
    }

    /// Invalide ce handle de façon permanente.
    ///
    /// Appelé par le `FileCache` lorsqu'un truncate évince une entrée : tout
    /// lecteur encore en vie qui tenterait de lire obtiendrait du chiffré sous
    /// un nouvel IV, impossible à déchiffrer correctement avec l'ancien. En
    /// posant `poisoned = true` ici, la prochaine opération I/O sur ce handle
    /// retourne `MacVerificationFailed` au lieu de silencieusement renvoyer
    /// des données corrompues.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    #[cfg(test)]
    pub(super) fn header_iv(&self) -> [u8; 16] {
        self.header.iv
    }
}

impl<C: ChunkCipher> Drop for EncryptedFile<C> {
    fn drop(&mut self) {
        // Best-effort: persist the MAC tag if the file was modified. We can't
        // surface errors from Drop, so failures here are silent — `flush()`
        // called by callers in nominal shutdown paths is what we rely on for
        // strong guarantees.
        if self.dirty && !self.poisoned {
            let _ = self.recompute_and_write_tag();
            let _ = self.file.flush();
        }
    }
}
