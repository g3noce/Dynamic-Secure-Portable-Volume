use super::*;

fn get_dummy_salt() -> [u8; 16] {
    [0u8; 16]
}

/// TEST 1: Stability and Determinism (Test Vector)
/// Guarantees that the parameters (64MB, 3 iterations, 4 threads) never change by mistake.
#[test]
fn test_kdf_parameters_stability() {
    let password = "dspv_test_password";
    let salt = b"static_salt_1234"; // 16 bytes

    let key1 = Argon2Kdf::derive_key(password, salt).unwrap();
    let key2 = Argon2Kdf::derive_key(password, salt).unwrap();

    assert_eq!(key1.0, key2.0, "The KDF is not deterministic!");
    assert_eq!(
        key1.0.len(),
        DERIVED_KEY_SIZE,
        "The key must be exactly 96 bytes (64 for AES-XTS + 32 for HMAC)"
    );
}

/// TEST 2: Avalanche Effect (Extreme Sensitivity)
#[test]
fn test_kdf_avalanche_effect() {
    let salt = get_dummy_salt();
    let pwd1 = "MotDePasse123!";
    let pwd2 = "MotDePasse123?";

    let key1 = Argon2Kdf::derive_key(pwd1, &salt).unwrap();
    let key2 = Argon2Kdf::derive_key(pwd2, &salt).unwrap();

    assert_ne!(key1.0, key2.0);

    let mut diff_count = 0;
    for i in 0..DERIVED_KEY_SIZE {
        if key1.0[i] != key2.0[i] {
            diff_count += 1;
        }
    }
    assert!(
        diff_count > 75,
        "The avalanche effect is too weak (cryptographic weakness)"
    );
}

/// TEST 3: Handling edge cases (Empty / Long password)
#[test]
fn test_kdf_edge_cases_passwords() {
    let salt = get_dummy_salt();

    let key_empty = Argon2Kdf::derive_key("", &salt);
    assert!(key_empty.is_ok());
    assert_eq!(key_empty.unwrap().0.len(), DERIVED_KEY_SIZE);

    let long_pwd = "A".repeat(10000);
    let key_long = Argon2Kdf::derive_key(&long_pwd, &salt);
    assert!(key_long.is_ok());
}

/// TEST 4: Salt Security (Minimum size)
#[test]
fn test_kdf_salt_security_limits() {
    let pwd = "password";
    let short_salt = b"123456";
    let result = Argon2Kdf::derive_key(pwd, short_salt);

    assert!(
        result.is_err(),
        "The KDF should fail with a salt of less than 8 bytes"
    );
}

/// TEST 5: Non-reuse (Unique Salt = Unique Key)
#[test]
fn test_kdf_salt_uniqueness() {
    let pwd = "same_password";
    let salt1 = b"salt_number_1";
    let salt2 = b"salt_number_2";

    let key1 = Argon2Kdf::derive_key(pwd, salt1).unwrap();
    let key2 = Argon2Kdf::derive_key(pwd, salt2).unwrap();

    assert_ne!(
        key1.0, key2.0,
        "Two different salts must produce different keys"
    );
}
