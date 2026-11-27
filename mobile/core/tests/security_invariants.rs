//! Security regression tests for `budlum-mobile-core`:
//! 1. `OperatorKey::from_entropy` refuses all-zero entropy and `OperatorKey::open`
//!    refuses empty sealed payloads or all-zero seeds returned by a vault.
//! 2. `MobileLightClient::new` refuses `chain_id == 0`, and `advance` refuses
//!    non-canonical `block_hash` or `state_root`.

use budlum_mobile_core::{
    KeyVault, MobileLightClient, OperatorKey, SealedOperatorKey, TrustedCheckpoint, VaultError,
    VerifiedCheckpoint,
};
use zeroize::Zeroizing;

struct StaticVault(Vec<u8>);

impl KeyVault for StaticVault {
    fn seal(&self, secret: &[u8], _context: &[u8]) -> Result<Vec<u8>, VaultError> {
        Ok(secret.to_vec())
    }
    fn open(&self, _sealed: &[u8], _context: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Ok(Zeroizing::new(self.0.clone()))
    }
}

#[test]
fn operator_key_refuses_zero_entropy_and_empty_sealed_records() {
    let err = OperatorKey::from_entropy([0u8; 32])
        .expect_err("all-zero operator key entropy must fail closed");
    assert_eq!(err.code, "mobile_operator_entropy_zero");

    // Opening an empty sealed record must fail before trusting vault output.
    let vault = StaticVault(vec![1u8; 32]);
    let empty_sealed = SealedOperatorKey {
        public_key: Vec::new(),
        sealed_seed: vec![1u8; 32],
    };
    let err_empty = OperatorKey::open(&vault, &empty_sealed)
        .expect_err("empty public_key in SealedOperatorKey must fail closed");
    assert_eq!(err_empty.code, "mobile_operator_key_sealed");

    // A vault returning an all-zero seed must be refused.
    let zero_vault = StaticVault(vec![0u8; 32]);
    let key = OperatorKey::from_entropy([7u8; 32]).expect("non-zero entropy succeeds");
    let sealed = SealedOperatorKey {
        public_key: key.public_key().to_vec(),
        sealed_seed: vec![9u8; 32],
    };
    let err_zero_open = OperatorKey::open(&zero_vault, &sealed)
        .expect_err("vault returning all-zero seed must fail closed");
    assert_eq!(err_zero_open.code, "mobile_operator_entropy_zero");
}

#[test]
fn mobile_light_client_refuses_zero_chain_id_and_non_canonical_advance() {
    let trusted = TrustedCheckpoint {
        height: 10,
        block_hash: "aa".repeat(32),
        set_hash: "bb".repeat(32),
    };
    assert!(
        MobileLightClient::new(trusted.clone(), 0).is_err(),
        "chain_id 0 must be refused by MobileLightClient::new"
    );

    let mut client = MobileLightClient::new(trusted.clone(), 45_261).expect("valid bootstrap");
    let bad_verified = VerifiedCheckpoint {
        height: 20,
        block_hash: "NOT-A-CANONICAL-HASH".into(),
        set_hash: trusted.set_hash.clone(),
        epoch: 2,
        state_root: "cc".repeat(32),
    };
    assert!(
        client.advance(&bad_verified).is_err(),
        "advance must refuse non-canonical block_hash"
    );
    assert_eq!(
        client.trusted().height,
        10,
        "refused advance must not mutate trusted"
    );

    let bad_state_root = VerifiedCheckpoint {
        height: 20,
        block_hash: "dd".repeat(32),
        set_hash: trusted.set_hash,
        epoch: 2,
        state_root: String::new(),
    };
    assert!(
        client.advance(&bad_state_root).is_err(),
        "advance must refuse non-canonical state_root"
    );
}
