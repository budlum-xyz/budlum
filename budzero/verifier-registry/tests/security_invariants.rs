//! Security regression tests for `verifier-registry`:
//! 1. Zero address cannot register or be upserted (cannot create unslashable members).
//! 2. `upsert_stake` enforces the same maximum stake ceiling as `register` and `add_stake`.
//! 3. `DoubleSign` rejects empty block hashes (including bare `"0x"`) and height 0.
//! 4. `slash_from_report` deduplicates `SlashingProof::Other` across distinct reporters.

use verifier_registry::address::Address;
use verifier_registry::evidence::{EvidenceError, SlashingProof, SlashingReport};
use verifier_registry::registry::{RegistryError, VerifierRegistry};
use verifier_registry::role::roles;

#[test]
fn zero_address_and_overflow_stake_are_refused_in_register_and_upsert() {
    let mut reg = VerifierRegistry::new();
    let err = reg
        .register(Address::zero(), roles::RELAYER, 5_000, 1)
        .expect_err("zero address must not register as an unslashable member");
    assert_eq!(err, RegistryError::ZeroAddress);

    // upsert_stake must also refuse Address::zero().
    reg.upsert_stake(Address::zero(), roles::RELAYER, 5_000, 1);
    assert!(
        reg.get(&Address::zero(), roles::RELAYER).is_none(),
        "upsert_stake must never insert Address::zero()"
    );

    // upsert_stake must never accept stakes above the protocol ceiling (10^18).
    let alice = Address::from([0x11u8; 32]);
    reg.upsert_stake(alice, roles::RELAYER, u64::MAX, 1);
    assert!(
        reg.get(&alice, roles::RELAYER).is_none(),
        "upsert_stake must refuse oversized stake above ceiling"
    );

    reg.register(alice, roles::RELAYER, 5_000, 1)
        .expect("honest register");
    reg.upsert_stake(alice, roles::RELAYER, u64::MAX, 2);
    assert_eq!(
        reg.get(&alice, roles::RELAYER).expect("exists").stake,
        5_000,
        "upsert_stake must not raise an active bond above the ceiling"
    );
}

#[test]
fn double_sign_refuses_empty_block_hash_and_zero_height() {
    let offender = Address::from([0x22u8; 32]);
    for (height, h1, h2) in [
        (1, "", "aa"),
        (1, "0x", "aa"),
        (1, "aa", "   "),
        (0, "aa", "bb"),
    ] {
        let report = SlashingReport::new(
            offender,
            roles::VALIDATOR,
            SlashingProof::DoubleSign {
                height,
                block_hash_1: h1.into(),
                block_hash_2: h2.into(),
                signature_1: vec![1; 32],
                signature_2: vec![2; 32],
            },
            None,
        );
        assert!(
            matches!(
                report.validate_shape(),
                Err(EvidenceError::NonConflictingHashes | EvidenceError::EmptyBlockHash)
            ),
            "invalid double-sign (height={height}, h1={h1:?}, h2={h2:?}) must fail shape validation"
        );
    }
}

#[test]
fn other_offence_deduplication_ignores_reporter_swap() {
    let mut reg = VerifierRegistry::new();
    let offender = Address::from([0x33u8; 32]);
    reg.register(offender, roles::RELAYER, 10_000, 1)
        .expect("register");

    let rep_a = SlashingReport::consensus_invalid_relay_proof(
        offender,
        "bad-proof-xyz".into(),
        Some(Address::from([0xA1u8; 32])),
    );
    let rep_b = SlashingReport::consensus_invalid_relay_proof(
        offender,
        "bad-proof-xyz".into(),
        Some(Address::from([0xB2u8; 32])),
    );

    let first = reg.slash_from_report(&rep_a).expect("first slash");
    assert!(first.is_some());
    assert_eq!(reg.slashing_history().len(), 1);

    // Offender exits after serving the slash and re-registers with a fresh bond.
    let release = reg
        .begin_unbonding(offender, roles::RELAYER, 2)
        .expect("begin unbonding");
    let _ = reg
        .withdraw(offender, roles::RELAYER, release)
        .expect("withdraw");
    reg.register(offender, roles::RELAYER, 10_000, release + 1)
        .expect("re-register with fresh stake");

    // Replaying the exact same Other offence with a different reporter must
    // deduplicate and NOT slash the fresh bond a second time.
    let second = reg.slash_from_report(&rep_b).expect("second report");
    assert!(
        second.is_none(),
        "same Other offence submitted by another reporter must be deduplicated"
    );
    assert_eq!(reg.slashing_history().len(), 1);
    assert_eq!(
        reg.get(&offender, roles::RELAYER).expect("active").stake,
        10_000
    );
}
