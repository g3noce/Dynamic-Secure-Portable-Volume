use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Represents a cryptographic key that self-destructs (zeroize)
/// when it goes out of scope (drop).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey(pub Vec<u8>);

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
