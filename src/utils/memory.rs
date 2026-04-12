use zeroize::{Zeroize, ZeroizeOnDrop};

/// Représente une clé cryptographique qui s'auto-détruit (zeroize)
/// lorsqu'elle sort de la portée (drop).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey(pub Vec<u8>);

/// Buffer sécurisé pour les données en clair lues ou écrites.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer(pub Vec<u8>);
