use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of leading bytes of a master key consumed by the AES-256-XTS cipher.
pub const XTS_KEY_BYTES: usize = 64;

/// Represents a cryptographic key that self-destructs (zeroize)
/// when it goes out of scope (drop).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey(pub Vec<u8>);

impl SecureKey {
    /// Split the master key derived by Argon2 into the AES-XTS half and the
    /// HMAC half. Returns `(xts_key, mac_key)`. Both are clones — the original
    /// master key keeps its zeroize-on-drop guarantee.
    pub fn split_xts_mac(&self) -> (SecureKey, SecureKey) {
        let xts = SecureKey(self.0[..XTS_KEY_BYTES].to_vec());
        let mac = SecureKey(self.0[XTS_KEY_BYTES..].to_vec());
        (xts, mac)
    }
}

impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // We NEVER reveal the content of the key in logs or panics
        write!(f, "SecureKey([CENSORED])")
    }
}

/// Secure buffer for plaintext data read or written.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer(pub Vec<u8>);

impl fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBuffer({} bytes)", self.0.len())
    }
}
