//! Regression tests for composite signature zero-seed/zero-key refusals and
//! finality committee zero-address exclusion and permutation invariance.

use budlum_core::core::address::Address;
use budlum_core::crypto::composite::{CompositeKeypair, CompositePublicKey};
use budlum_core::crypto::scheme::SuiteId;
use budlum_core::validators::committee::{CommitteeParams, CommitteeTable};

#[test]
fn composite_refuses_all_zero_seeds_and_all_zero_public_key_halves() {
    assert!(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0u8; 32], &[0x11; 32]).is_err(),
        "all-zero PQ seed must be refused"
    );
    assert!(
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x11; 32], &[0u8; 32]).is_err(),
        "all-zero Ed25519 seed must be refused"
    );

    let valid_kp = CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x21; 32], &[0x22; 32])
        .expect("valid non-zero seeds");
    let mut bad_pub = valid_kp.public_key().expect("public key");
    bad_pub.ed = [0u8; 32];
    let encoded_zero_ed = bad_pub.encode();
    assert!(
        CompositePublicKey::decode(&encoded_zero_ed).is_err(),
        "all-zero Ed25519 identity point must be refused by CompositePublicKey::decode"
    );
}

#[test]
fn committee_derive_excludes_zero_address_and_is_strictly_order_independent() {
    let a = Address::from([0x01; 32]);
    let b = Address::from([0x02; 32]);
    let c = Address::from([0x03; 32]);
    let d = Address::from([0x04; 32]);
    let rnd = [0x77; 32];
    let params = CommitteeParams::default();

    // 1. Address::zero() must never receive a seat or standby entry.
    let with_zero = CommitteeTable::derive(
        1,
        10,
        &rnd,
        &[
            (Address::zero(), 10_000),
            (a, 1_000),
            (b, 1_000),
            (c, 1_000),
            (d, 1_000),
        ],
        &params,
    );
    assert!(
        with_zero.seats_of(&Address::zero()).is_empty(),
        "Address::zero() must never be assigned finality committee seats"
    );
    for seat in &with_zero.seats {
        assert!(
            !seat.standbys.contains(&Address::zero()),
            "Address::zero() must never appear in seat standby lists"
        );
    }

    // 2. Reordering duplicate-address entries must yield the exact same CommitteeTable.
    let order_1 = [(a, 100), (a, 900), (b, 500), (c, 500), (d, 500)];
    let order_2 = [(a, 900), (a, 100), (d, 500), (c, 500), (b, 500)];
    let t1 = CommitteeTable::derive(2, 20, &rnd, &order_1, &params);
    let t2 = CommitteeTable::derive(2, 20, &rnd, &order_2, &params);
    assert_eq!(
        t1, t2,
        "CommitteeTable::derive must be strictly invariant to input slice ordering"
    );
}
