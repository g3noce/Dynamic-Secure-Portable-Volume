pub mod errors;
mod file_header;

pub use file_header::{FileHeader, HEADER_SIZE, LOGICAL_SIZE_OFFSET, MAC_TAG_OFFSET};
// Exposed for tests that pin the binary layout invariants.
#[allow(unused_imports)]
pub use file_header::HEADER_PLAINTEXT_SIZE;

#[cfg(test)]
mod tests;
