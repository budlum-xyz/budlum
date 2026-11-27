//! Regression tests for Address V3 multisig leaf key-length enforcement and
//! multisig address owner/threshold/duplicate/zero-recovery guards.

use budlum_core::crypto::address_v3::{
    multisig_address_v3, multisig_owner_leaf, MAX_MULTISIG_OWNERS,
};
use budlum_core::crypto::scheme::SuiteId;

#[test]
fn address_v3_multisig_enforces_key_lengths_owner_bounds_and_nonzero_threshold() {
    // 1. multisig_owner_leaf must refuse wrong-length or empty PQ / Ed25519 keys.
    assert!(
        multisig_owner_leaf(SuiteId::USER, &[], &[0x22; 32]).is_err(),
        "empty PQ public key must be refused by multisig_owner_leaf"
    );
    assert!(
        multisig_owner_leaf(SuiteId::USER, &[0x11; 2592], &[0x22; 16]).is_err(),
        "16-byte truncated Ed25519 key must be refused by multisig_owner_leaf"
    );

    let leaf_a =
        multisig_owner_leaf(SuiteId::USER, &[0x11; 2592], &[0x22; 32]).expect("valid leaf a");
    let rec = [0x55; 32];

    // 2. Empty owner list, threshold == 0, duplicate leaves, > MAX_MULTISIG_OWNERS, and zero recovery_digest must fail.
    assert!(
        multisig_address_v3(SuiteId::USER, &[], 1, &rec).is_err(),
        "empty owner_leaves must be refused"
    );
    assert!(
        multisig_address_v3(SuiteId::USER, &[leaf_a], 0, &rec).is_err(),
        "threshold == 0 must be refused"
    );
    assert!(
        multisig_address_v3(SuiteId::USER, &[leaf_a, leaf_a], 2, &rec).is_err(),
        "duplicate owner leaves must be refused"
    );
    assert!(
        multisig_address_v3(SuiteId::USER, &[leaf_a], 1, &[0u8; 32]).is_err(),
        "all-zero recovery_digest must be refused"
    );

    let too_many: Vec<[u8; 32]> = (1..=(MAX_MULTISIG_OWNERS + 1))
        .map(|i| {
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            b
        })
        .collect();
    assert!(
        multisig_address_v3(SuiteId::USER, &too_many, 2, &rec).is_err(),
        "owner_leaves exceeding MAX_MULTISIG_OWNERS must be refused"
    );
}
