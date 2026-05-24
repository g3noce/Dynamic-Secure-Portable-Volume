use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

fn setup_test_env(name: &str) -> String {
    let _ = fs::remove_dir_all(name);
    fs::create_dir_all(name).unwrap();
    name.to_string()
}

fn teardown_test_env(name: &str) {
    let _ = fs::remove_dir_all(name);
}

/// TEST 1: Normal lifecycle (Valid creation and unlock)
#[test]
fn test_vault_lifecycle_success() {
    let root = setup_test_env("test_vault_lifecycle");
    let password = "super_secure_password_123!";

    let key_1 = VaultManager::unlock_or_create(&root, password).expect("Creation failed");
    assert!(Path::new(&root).join("dspv.meta").exists());

    let key_2 = VaultManager::unlock_or_create(&root, password).expect("Unlock failed");

    assert_eq!(key_1.0, key_2.0, "Derived keys do not match!");

    teardown_test_env(&root);
}

/// TEST 2: Strict rejection of a wrong password
#[test]
fn test_vault_wrong_password() {
    let root = setup_test_env("test_vault_wrong_pwd");

    VaultManager::unlock_or_create(&root, "good_password").unwrap();
    let result = VaultManager::unlock_or_create(&root, "bad_password");

    assert!(
        result.is_err(),
        "CRITICAL: The system accepted a wrong password!"
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "mod: vault, function: unlock_existing, cause: incorrect password"
    );

    teardown_test_env(&root);
}

/// TEST 3: Resilience against a truncated file (Short Read)
#[test]
fn test_vault_truncated_file_no_panic() {
    let root = setup_test_env("test_vault_truncated");
    let meta_path = Path::new(&root).join("dspv.meta");

    let mut file = File::create(&meta_path).unwrap();
    file.write_all(b"DSPM").unwrap();
    file.write_all(&[0x42; 6]).unwrap();
    drop(file);

    let result = VaultManager::unlock_or_create(&root, "password");

    assert!(result.is_err(), "The system must reject a truncated file");
    assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof,
        "The error must be UnexpectedEof (premature end of file), not a system crash"
    );

    teardown_test_env(&root);
}

/// TEST 4: Attempted Salt Tampering
#[test]
fn test_vault_salt_tampering() {
    let root = setup_test_env("test_vault_salt_tamper");
    let meta_path = Path::new(&root).join("dspv.meta");
    let password = "password";

    VaultManager::unlock_or_create(&root, password).unwrap();

    let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();
    file.seek(SeekFrom::Start(10)).unwrap();
    file.write_all(&[0xFF]).unwrap();
    drop(file);

    let result = VaultManager::unlock_or_create(&root, password);

    assert!(
        result.is_err(),
        "CRITICAL: Tampering with the salt did not invalidate the vault!"
    );

    teardown_test_env(&root);
}

/// TEST 5: Attempted verification block tampering
#[test]
fn test_vault_verify_block_tampering() {
    let root = setup_test_env("test_vault_block_tamper");
    let meta_path = Path::new(&root).join("dspv.meta");
    let password = "password";

    VaultManager::unlock_or_create(&root, password).unwrap();

    let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();
    file.seek(SeekFrom::Start(40)).unwrap();
    file.write_all(&[0xFF]).unwrap();
    drop(file);

    let result = VaultManager::unlock_or_create(&root, password);

    assert!(
        result.is_err(),
        "CRITICAL: The vault opened despite a corrupted verification block!"
    );

    teardown_test_env(&root);
}

/// TEST 6 (P2): Meta HMAC tampering must be rejected as WrongPassword
/// (indistinguishable from a wrong-password attempt, by design).
#[test]
fn test_vault_meta_hmac_tampering() {
    let root = setup_test_env("test_vault_meta_hmac");
    let meta_path = Path::new(&root).join("dspv.meta");
    let password = "password";

    VaultManager::unlock_or_create(&root, password).unwrap();

    // The MAC tag occupies bytes 68..100. Flip a byte inside it.
    let mut file = OpenOptions::new().write(true).open(&meta_path).unwrap();
    file.seek(SeekFrom::Start(70)).unwrap();
    file.write_all(&[0xFF]).unwrap();
    drop(file);

    let result = VaultManager::unlock_or_create(&root, password);
    assert!(
        result.is_err(),
        "CRITICAL: meta HMAC tampering was accepted"
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "mod: vault, function: unlock_existing, cause: incorrect password",
        "Meta tampering must surface as WrongPassword to avoid leaking info to the attacker"
    );

    teardown_test_env(&root);
}

/// TEST 7: Handling an empty password
#[test]
fn test_vault_empty_password_handling() {
    let root = setup_test_env("test_vault_empty_pwd");

    let result_create = VaultManager::unlock_or_create(&root, "");
    assert!(
        result_create.is_ok(),
        "The system must handle an empty password without crashing"
    );

    let result_unlock = VaultManager::unlock_or_create(&root, "");
    assert!(
        result_unlock.is_ok(),
        "The system must unlock with an empty password"
    );

    teardown_test_env(&root);
}
