//! The operator key (section 7.9.6): generated from host entropy, signing
//! what the node's verifier accepts, sealed by the platform vault and checked
//! when it is opened.

use std::error::Error;

use budlum_mobile_core::crypto::{ctx, pq};
use budlum_mobile_core::{
    KeyVault, OperatorKey, SealedOperatorKey, VaultError, OPERATOR_KEY_LABEL, OPERATOR_KEY_SCHEME,
};
use zeroize::Zeroizing;

const ENTROPY: [u8; 32] = [7; 32];
const NO_RND: [u8; 32] = [0; 32];

/// A stand-in for the platform cipher: the context is stored in front of the
/// ciphertext and must match on open, the way AES-GCM authenticates its
/// associated data; the secret is masked so it never appears in clear.
struct MaskVault;

impl KeyVault for MaskVault {
    fn seal(&self, secret: &[u8], context: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut sealed = context.len().to_le_bytes().to_vec();
        sealed.extend_from_slice(context);
        sealed.extend(secret.iter().map(|byte| byte ^ 0xA5));
        Ok(sealed)
    }

    fn open(&self, sealed: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut header = context.len().to_le_bytes().to_vec();
        header.extend_from_slice(context);
        match sealed.strip_prefix(header.as_slice()) {
            Some(body) => Ok(Zeroizing::new(
                body.iter().map(|byte| byte ^ 0xA5).collect(),
            )),
            None => Err(VaultError {
                reason: "authentication failed".to_owned(),
            }),
        }
    }
}

/// A vault that answers every open with fixed bytes.
struct FixedVault(Vec<u8>);

impl KeyVault for FixedVault {
    fn seal(&self, _secret: &[u8], _context: &[u8]) -> Result<Vec<u8>, VaultError> {
        Ok(self.0.clone())
    }

    fn open(&self, _sealed: &[u8], _context: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Ok(Zeroizing::new(self.0.clone()))
    }
}

/// A vault that refuses everything, like a key store after the platform key
/// was invalidated.
struct LockedVault;

impl KeyVault for LockedVault {
    fn seal(&self, _secret: &[u8], _context: &[u8]) -> Result<Vec<u8>, VaultError> {
        Err(VaultError {
            reason: "key invalidated".to_owned(),
        })
    }

    fn open(&self, _sealed: &[u8], _context: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Err(VaultError {
            reason: "key invalidated".to_owned(),
        })
    }
}

fn code<T: std::fmt::Debug>(result: Result<T, budlum_mobile_core::CoreError>) -> &'static str {
    match result {
        Err(error) => error.code,
        Ok(value) => panic!("expected a refusal, got {value:?}"),
    }
}

#[test]
fn operator_key_signs_what_the_node_verifies() -> Result<(), Box<dyn Error>> {
    let key = OperatorKey::from_entropy(ENTROPY)?;
    assert_eq!(
        key.public_key().len(),
        pq::public_key_len(OPERATOR_KEY_SCHEME)?
    );

    let signature = key.sign(ctx::TX_V8, b"duty", &NO_RND)?;
    pq::verify(
        OPERATOR_KEY_SCHEME,
        key.public_key(),
        b"duty",
        ctx::TX_V8,
        &signature,
    )?;
    assert!(pq::verify(
        OPERATOR_KEY_SCHEME,
        key.public_key(),
        b"dutz",
        ctx::TX_V8,
        &signature
    )
    .is_err());
    assert!(pq::verify(
        OPERATOR_KEY_SCHEME,
        key.public_key(),
        b"duty",
        ctx::TX_V7,
        &signature
    )
    .is_err());

    // The same entropy is the same key; other entropy is another key.
    assert_eq!(
        OperatorKey::from_entropy(ENTROPY)?.public_key(),
        key.public_key()
    );
    assert_ne!(
        OperatorKey::from_entropy([8; 32])?.public_key(),
        key.public_key()
    );
    Ok(())
}

#[test]
fn operator_key_refuses_an_empty_context() -> Result<(), Box<dyn Error>> {
    let key = OperatorKey::from_entropy(ENTROPY)?;
    assert_eq!(
        code(key.sign(b"", b"duty", &NO_RND)),
        "mobile_operator_sign"
    );
    Ok(())
}

#[test]
fn operator_key_round_trips_through_the_vault() -> Result<(), Box<dyn Error>> {
    let key = OperatorKey::from_entropy(ENTROPY)?;
    let sealed = key.seal(&MaskVault)?;
    assert_eq!(sealed.public_key, key.public_key());
    assert!(!sealed
        .sealed_seed
        .windows(ENTROPY.len())
        .any(|window| window == ENTROPY));
    assert!(sealed
        .sealed_seed
        .windows(OPERATOR_KEY_LABEL.len())
        .any(|w| w == OPERATOR_KEY_LABEL));

    let opened = OperatorKey::open(&MaskVault, &sealed)?;
    assert_eq!(opened.public_key(), key.public_key());
    let signature = opened.sign(ctx::TX_V8, b"duty", &NO_RND)?;
    pq::verify(
        OPERATOR_KEY_SCHEME,
        key.public_key(),
        b"duty",
        ctx::TX_V8,
        &signature,
    )?;
    Ok(())
}

#[test]
fn operator_key_open_is_bound_to_the_public_key() -> Result<(), Box<dyn Error>> {
    let sealed = OperatorKey::from_entropy(ENTROPY)?.seal(&MaskVault)?;
    let other = OperatorKey::from_entropy([8; 32])?;
    let swapped = SealedOperatorKey {
        public_key: other.public_key().to_vec(),
        sealed_seed: sealed.sealed_seed,
    };
    assert_eq!(
        code(OperatorKey::open(&MaskVault, &swapped)),
        "mobile_key_vault"
    );
    Ok(())
}

#[test]
fn operator_key_refuses_a_vault_that_returns_another_seed() -> Result<(), Box<dyn Error>> {
    let sealed = OperatorKey::from_entropy(ENTROPY)?.seal(&MaskVault)?;
    let lying = FixedVault(vec![8; 32]);
    assert_eq!(
        code(OperatorKey::open(&lying, &sealed)),
        "mobile_operator_key_mismatch"
    );
    let short = FixedVault(vec![7; 31]);
    assert_eq!(
        code(OperatorKey::open(&short, &sealed)),
        "mobile_operator_key_sealed"
    );
    Ok(())
}

#[test]
fn operator_key_reports_a_vault_refusal() -> Result<(), Box<dyn Error>> {
    let key = OperatorKey::from_entropy(ENTROPY)?;
    assert_eq!(code(key.seal(&LockedVault)), "mobile_key_vault");
    let sealed = key.seal(&MaskVault)?;
    assert_eq!(
        code(OperatorKey::open(&LockedVault, &sealed)),
        "mobile_key_vault"
    );
    Ok(())
}

#[test]
fn operator_key_debug_output_holds_no_secret() -> Result<(), Box<dyn Error>> {
    let key = OperatorKey::from_entropy(ENTROPY)?;
    let shown = format!("{key:?}");
    assert!(shown.starts_with("OperatorKey"));
    assert!(!shown.contains("7, 7"));
    Ok(())
}
