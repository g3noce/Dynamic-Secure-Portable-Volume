mod argon2;
pub mod errors;

pub use argon2::{Argon2Kdf, KeyDerivation};
// Exposed for tests (and any future consumer that needs the exact KDF output length).
#[allow(unused_imports)]
pub use argon2::DERIVED_KEY_SIZE;

#[cfg(test)]
mod tests;
