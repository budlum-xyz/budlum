//! Regression tests for V3 root key derivation refusing NUL-embedded or
//! oversized passphrases and non-recovery validator suites while preserving
//! standard BIP39 vectors.

use budlum_core::crypto::key_derivation::{KdfError, RootSecret};
use budlum_core::crypto::scheme::SuiteId;

#[test]
fn root_secret_refuses_nul_or_oversized_passphrases_and_non_user_suites() {
    // Embedded NUL truncates across C/JNI/FFI wallet bridges and must be refused.
    assert!(
        RootSecret::derive(&[0x42; 32], "pass\0word").is_err(),
        "passphrase containing embedded NUL byte must be refused"
    );
    // Oversized passphrase (> 1024 bytes) must be refused before NFKD heap expansion.
    let huge = "a".repeat(2_048);
    assert!(
        RootSecret::derive(&[0x42; 32], &huge).is_err(),
        "oversized passphrase must be refused"
    );

    // Non-user suite lacking a recovery scheme (SuiteId::VALIDATOR) must fail with KdfError::Suite.
    let root = RootSecret::derive(&[0x42; 32], "valid-passphrase").expect("valid root");
    assert_eq!(
        root.user_account_for_suite(SuiteId::VALIDATOR, 0, 0).err(),
        Some(KdfError::Suite(SuiteId::VALIDATOR))
    );

    // Official BIP39 zero-entropy vector ("abandon" x 23 + "art") continues to derive cleanly.
    assert!(RootSecret::derive(&[0u8; 32], "").is_ok());
}
