use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::Rng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HTTP Basic auth credentials generated at server startup.
///
/// The expected `Authorization` header value (`Basic <base64(user:pass)>`) is
/// pre-computed so each request only needs a constant-time byte compare.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BasicAuth {
    username: String,
    password: String,
    expected_header: Vec<u8>,
}

impl BasicAuth {
    /// Generate fresh credentials. Password is 24 base64 chars (~144 bits).
    pub fn generate() -> Self {
        let mut raw = [0u8; 18];
        rand::rng().fill_bytes(&mut raw);
        let password = STANDARD.encode(raw);
        let username = "dspv".to_string();
        let expected_header = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", username, password))
        )
        .into_bytes();

        Self {
            username,
            password,
            expected_header,
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    /// Constant-time check of an incoming `Authorization` header value.
    pub fn verify(&self, header_value: &[u8]) -> bool {
        if header_value.len() != self.expected_header.len() {
            return false;
        }
        header_value.ct_eq(&self.expected_header).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_auth_verify_matches_generated_header() {
        let auth = BasicAuth::generate();
        let header = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", auth.username(), auth.password()))
        );
        assert!(auth.verify(header.as_bytes()));
    }

    #[test]
    fn test_basic_auth_rejects_wrong_password() {
        let auth = BasicAuth::generate();
        let bad = format!(
            "Basic {}",
            STANDARD.encode(format!("{}:wrong", auth.username()))
        );
        assert!(!auth.verify(bad.as_bytes()));
    }

    #[test]
    fn test_basic_auth_rejects_empty_and_garbage() {
        let auth = BasicAuth::generate();
        assert!(!auth.verify(b""));
        assert!(!auth.verify(b"Basic"));
        assert!(!auth.verify(b"Bearer xyz"));
    }

    #[test]
    fn test_basic_auth_credentials_are_unique() {
        let a = BasicAuth::generate();
        let b = BasicAuth::generate();
        assert_ne!(
            a.password(),
            b.password(),
            "Two consecutive generations must not collide"
        );
    }
}
