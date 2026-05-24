//! HMAC-SHA256 wrapper used to authenticate the contents of each encrypted file.
//!
//! AES-XTS provides confidentiality and limits the damage of a single-byte flip
//! to a 16-byte sector, but it cannot detect tampering. This module supplies the
//! integrity guarantee: every file carries a 32-byte tag covering its plaintext
//! header bytes (excluding the tag slot itself) plus the full ciphertext.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const MAC_TAG_SIZE: usize = 32;
pub const MAC_KEY_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Compute the 32-byte HMAC-SHA256 tag of `data` under `key`.
/// Currently only exercised by the test suite; kept as a public helper for any
/// future callsite that needs a one-shot MAC (e.g. small headers/metadata).
#[allow(dead_code)]
pub fn compute(key: &[u8], data: &[u8]) -> [u8; MAC_TAG_SIZE] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; MAC_TAG_SIZE];
    tag.copy_from_slice(&out);
    tag
}

/// Incremental builder for the case where the ciphertext can't fit in RAM.
pub struct MacBuilder {
    inner: HmacSha256,
}

impl MacBuilder {
    pub fn new(key: &[u8]) -> Self {
        Self {
            inner: HmacSha256::new_from_slice(key).expect("HMAC accepts any key length"),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; MAC_TAG_SIZE] {
        let out = self.inner.finalize().into_bytes();
        let mut tag = [0u8; MAC_TAG_SIZE];
        tag.copy_from_slice(&out);
        tag
    }
}

/// Constant-time tag comparison.
pub fn verify(expected: &[u8; MAC_TAG_SIZE], candidate: &[u8; MAC_TAG_SIZE]) -> bool {
    expected.ct_eq(candidate).into()
}

#[cfg(test)]
mod tests;
