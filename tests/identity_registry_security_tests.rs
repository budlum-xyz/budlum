//! End-to-end security tests for IdentityRegistry & IdentityRecord invariants:
//! - Guardian recovery enforces MAX_IDENTITY_METHODS ceiling (no unbounded growth)
//! - Guardian recovery forbids key resurrection of revoked keys and zero new_key
//! - IdentityRecord::validate forbids zero subject, zero guardian, and zero key_id
//! - IdentityRegistry::is_empty reflects non-empty retired subjects folded into root()

use budlum_core::core::address::Address;
use budlum_core::domain::ConsensusKind;
use budlum_core::registry::identity::{
    IdentityError, IdentityOp, IdentityRecord, IdentityRegistry, MethodKind, VerificationMethod,
    MAX_IDENTITY_METHODS,
};

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

#[test]
fn guardian_recovery_enforces_max_methods_and_forbids_revoked_key_resurrection_and_zero_key() {
    let mut reg = IdentityRegistry::new();
    let subject = addr(1);
    let g1 = addr(2);
    let g2 = addr(3);
    let initial_key = [0x11u8; 32];

    let record = IdentityRecord::new(
        subject,
        vec![VerificationMethod::new(initial_key, MethodKind::MlDsa87)],
        vec![g1, g2],
        2,
    )
    .expect("valid initial record");
    reg.apply(&ConsensusKind::PoA, IdentityOp::Register { record }, 10)
        .expect("register");

    // Zero new_key MUST be rejected fail-closed.
    let zero_err = reg
        .guardian_recovery(subject, [0u8; 32], &[g1, g2], 20)
        .expect_err("all-zero new_key must be refused");
    assert!(matches!(zero_err, IdentityError::BadApproval(_)));

    // First legitimate recovery rotates initial_key -> key_2.
    let key_2 = [0x22u8; 32];
    reg.guardian_recovery(subject, key_2, &[g1, g2], 20)
        .expect("first recovery succeeds");

    // Resurrecting the previously revoked initial_key MUST be refused fail-closed!
    let resurrect_err = reg
        .guardian_recovery(subject, initial_key, &[g1, g2], 30)
        .expect_err("previously revoked key_id must never be resurrected via guardian recovery");
    assert!(matches!(
        resurrect_err,
        IdentityError::DuplicateKeyId { .. }
    ));

    // Fill up to MAX_IDENTITY_METHODS (already have 2 methods: initial_key + key_2).
    for idx in 2..MAX_IDENTITY_METHODS {
        let mut next_key = [0u8; 32];
        next_key[0] = 0x80;
        next_key[1] = u8::try_from(idx).expect("fits u8");
        reg.guardian_recovery(subject, next_key, &[g1, g2], 30 + idx as u64)
            .expect("recovery within MAX_IDENTITY_METHODS succeeds");
    }
    assert_eq!(
        reg.record(&subject).expect("rec").methods.len(),
        MAX_IDENTITY_METHODS
    );

    // Next recovery exceeding MAX_IDENTITY_METHODS MUST fail closed without mutating record!
    let overflow_err = reg
        .guardian_recovery(subject, [0xEE; 32], &[g1, g2], 500)
        .expect_err("guardian recovery must enforce MAX_IDENTITY_METHODS ceiling");
    assert!(matches!(overflow_err, IdentityError::TooMany { .. }));
    assert_eq!(
        reg.record(&subject).expect("rec").methods.len(),
        MAX_IDENTITY_METHODS
    );
    // And the resulting record must still satisfy IdentityRecord::validate()!
    reg.record(&subject)
        .expect("rec")
        .validate()
        .expect("recovered record must remain structurally valid");
}

#[test]
fn identity_record_rejects_zero_subject_zero_guardian_and_zero_key_id() {
    // Zero subject MUST be refused.
    assert!(IdentityRecord::new(
        Address::zero(),
        vec![VerificationMethod::new([0x11; 32], MethodKind::MlDsa87)],
        vec![addr(2)],
        1,
    )
    .is_err());

    // Zero guardian MUST be refused.
    assert!(IdentityRecord::new(
        addr(1),
        vec![VerificationMethod::new([0x11; 32], MethodKind::MlDsa87)],
        vec![Address::zero()],
        1,
    )
    .is_err());

    // Zero key_id MUST be refused.
    assert!(IdentityRecord::new(
        addr(1),
        vec![VerificationMethod::new([0u8; 32], MethodKind::MlDsa87)],
        vec![addr(2)],
        1,
    )
    .is_err());
}

#[test]
fn identity_registry_with_only_retired_subjects_is_not_reported_empty() {
    // Deserialize a registry whose records/credentials/revoked are empty but retired is non-empty
    // (the exact state after reclaiming dead records), and verify is_empty() disagrees with empty root.
    let mut reg = IdentityRegistry::new();
    let empty_root = reg.root();
    assert!(reg.is_empty());

    let subject_hex = hex::encode([0x77u8; 32]);
    let json = format!(
        r#"{{"records":{{}},"credentials":{{}},"revoked":[],"retired":["{subject_hex}"]}}"#
    );
    reg = serde_json::from_str(&json).expect("deserialize retired-only registry");
    assert_ne!(
        reg.root(),
        empty_root,
        "retired subjects change the registry root"
    );
    assert!(
        !reg.is_empty(),
        "registry with non-empty retired set MUST NOT report is_empty() == true"
    );
}
