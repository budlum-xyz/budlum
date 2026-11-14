//! Wallet safety tests: mnemonic generation, key derivation, keyfile
//! seal/open round-trip, and entropy quality.

use crate::wallet::{
    entropy_from_mnemonic, generate_entropy, mnemonic_from_entropy, KeyFile,
    DEFAULT_KDF_ITERATIONS, MNEMONIC_WORDS,
};

#[test]
fn mnemonic_is_24_words() {
    assert_eq!(MNEMONIC_WORDS, 24);
}

#[test]
fn kdf_iterations_at_least_100k() {
    const { assert!(DEFAULT_KDF_ITERATIONS >= 100_000) };
}

#[test]
fn mnemonic_round_trips_through_entropy() {
    let entropy = generate_entropy();
    let mnemonic = mnemonic_from_entropy(&entropy);
    let recovered = entropy_from_mnemonic(&mnemonic).expect("valid mnemonic");
    assert_eq!(entropy, recovered);
}

#[test]
fn mnemonic_has_correct_word_count() {
    let entropy = generate_entropy();
    let mnemonic = mnemonic_from_entropy(&entropy);
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), MNEMONIC_WORDS);
}

#[test]
fn different_entropy_different_mnemonic() {
    let m1 = mnemonic_from_entropy(&[1u8; 32]);
    let m2 = mnemonic_from_entropy(&[2u8; 32]);
    assert_ne!(m1, m2);
}

#[test]
fn keyfile_seal_open_round_trip() {
    let entropy = generate_entropy();
    let password = "testnet-password-2026";
    let keyfile = KeyFile::seal(&entropy, password, 1_000).expect("seal");
    let opened = keyfile.open(password).expect("open");
    assert_eq!(entropy, opened);
}

#[test]
fn keyfile_wrong_password_fails() {
    let entropy = generate_entropy();
    let keyfile = KeyFile::seal(&entropy, "correct", 1_000).expect("seal");
    assert!(keyfile.open("wrong").is_err());
}

#[test]
fn generated_entropy_is_32_bytes() {
    let e = generate_entropy();
    assert_eq!(e.len(), 32);
}

#[test]
fn two_generated_entropies_differ() {
    let e1 = generate_entropy();
    let e2 = generate_entropy();
    assert_ne!(e1, e2, "entropy generator returned identical values");
}

#[test]
fn invalid_mnemonic_rejected() {
    assert!(entropy_from_mnemonic("not a valid mnemonic").is_err());
}

#[test]
fn empty_mnemonic_rejected() {
    assert!(entropy_from_mnemonic("").is_err());
}
