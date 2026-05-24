mod aes_xts;
pub mod errors;

pub use aes_xts::{Aes256XtsCipher, ChunkCipher};

#[cfg(test)]
pub use errors::CipherError;

#[cfg(test)]
mod tests;
