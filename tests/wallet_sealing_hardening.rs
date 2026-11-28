//! Regression tests for wallet sealing password/iteration bounds, exact
//! ciphertext size checks, zero chain-id refusal, and sender-mismatch guards.

use budlum_core::core::address::Address;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::wallet::{
    bind_signing_chain_id, KeyFile, SigningKey, WalletError, MAX_KDF_ITERATIONS,
};

#[test]
fn wallet_refuses_zero_chain_id_short_seal_password_and_out_of_range_iterations() {
    assert!(
        bind_signing_chain_id(0, 0).is_err(),
        "chain_id 0 is never a valid replay domain and must be refused"
    );

    let entropy = [0x5A; 32];
    assert!(
        matches!(
            KeyFile::seal(&entropy, "", 100),
            Err(WalletError::Format(_))
        ),
        "KeyFile::seal must refuse empty passwords"
    );
    assert!(
        matches!(
            KeyFile::seal(&entropy, "short7!", 100),
            Err(WalletError::Format(_))
        ),
        "KeyFile::seal must enforce the 8-character password floor"
    );
    assert!(
        matches!(
            KeyFile::seal(&entropy, "strong-password-123", 0),
            Err(WalletError::Format(_))
        ),
        "KeyFile::seal must refuse iterations == 0 instead of silently downgrading to 1"
    );
    assert!(
        matches!(
            KeyFile::seal(&entropy, "strong-password-123", MAX_KDF_ITERATIONS + 1),
            Err(WalletError::Format(_))
        ),
        "KeyFile::seal must refuse iterations > MAX_KDF_ITERATIONS so sealed files remain openable"
    );

    // Oversized ciphertext (beyond 32B entropy + 16B Poly1305 tag = 48B) must fail Format check.
    let mut valid = KeyFile::seal(&entropy, "strong-password-123", 100).expect("valid seal");
    valid.ciphertext = "aa".repeat(128);
    assert!(
        matches!(
            valid.open("strong-password-123"),
            Err(WalletError::Format(_))
        ),
        "oversized ciphertext must fail Format check before PBKDF2 work"
    );
}

#[test]
fn signing_key_refuses_spoofed_sender_or_zero_chain_id_transaction() {
    let sk = SigningKey::from_entropy(&[0x33; 32], true).expect("legacy V5 key");
    let mut wrong_sender_tx = Transaction::new_with_chain_id(
        Address::from([0xFF; 32]),
        Address::from([0x22; 32]),
        100,
        10,
        0,
        Vec::new(),
        45_261,
        TransactionType::Transfer,
    );
    assert!(
        sk.sign(&mut wrong_sender_tx).is_err(),
        "SigningKey::sign must refuse a transaction whose `from` mismatches the key's address"
    );

    let mut zero_chain_tx = Transaction::new_with_chain_id(
        sk.address(),
        Address::from([0x22; 32]),
        100,
        10,
        0,
        Vec::new(),
        0,
        TransactionType::Transfer,
    );
    assert!(
        sk.sign(&mut zero_chain_tx).is_err(),
        "SigningKey::sign must refuse chain_id == 0"
    );
}
