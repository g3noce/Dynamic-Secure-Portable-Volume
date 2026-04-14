use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Représente une clé cryptographique qui s'auto-détruit (zeroize)
/// lorsqu'elle sort de la portée (drop).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey(pub Vec<u8>);

impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // On ne révèle JAMAIS le contenu de la clé dans les logs ou les panics
        write!(f, "SecureKey([CENSURÉ])")
    }
}

/// Buffer sécurisé pour les données en clair lues ou écrites.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer(pub Vec<u8>);

impl fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBuffer({} bytes)", self.0.len())
    }
}
