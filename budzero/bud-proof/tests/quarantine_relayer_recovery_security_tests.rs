//! Security regression tests for `bud-proof::{quarantine, canonical_recovery, relayer}`:
//! 1. `QuarantineLedger::ban` upgrades a non-severe ban to severe so a
//!    subsequent non-canonical flood cannot evict it, and `from_text` refuses
//!    non-canonical hex or silently overflowing files.
//! 2. `canonical_recovery::reconcile` never elects an all-zero `[0u8; 32]` pin.
//! 3. `CanonicalRelayReport::verify_report_sig` refuses embedded NUL bytes in
//!    NUL-terminated string fields and status/alarm contradictions.

use bud_proof::canonical_recovery::{reconcile, Reconciliation};
use bud_proof::quarantine::{QuarantineLedger, QuarantineReason};
use bud_proof::relayer::{
    AlarmCode, AlarmDetail, CanonicalRelayReport, ProofFingerprint, RelayStatus,
    RELAY_SCHEMA_VERSION,
};
use tiny_keccak::{Hasher, Keccak};

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(bytes);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

#[test]
fn quarantine_upgrades_non_severe_ban_to_severe_and_from_text_is_strict() {
    let mut ledger = QuarantineLedger::new();
    let target = [0xAAu8; 32];

    // First banned as non-severe, then triggers a severe TransferViolation.
    ledger.ban(target, QuarantineReason::NonCanonicalProgram);
    ledger.ban(target, QuarantineReason::TransferViolation);
    assert_eq!(
        ledger.entry(&target).map(|e| e.reason),
        Some(QuarantineReason::TransferViolation),
        "severe offence must upgrade an earlier non-severe ban"
    );

    // Flooding 4,100 non-canonical bans MUST NOT evict the upgraded severe ban.
    for i in 1u64..=4_100 {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        ledger.ban(h, QuarantineReason::NonCanonicalProgram);
    }
    assert!(
        ledger.is_banned(&target),
        "upgraded severe ban must survive a non-canonical eviction flood"
    );

    // Uppercase hex or duplicate entries in persisted text must fail closed.
    let upper = format!("{} 1\n", "AA".repeat(32));
    assert!(
        QuarantineLedger::from_text(&upper).is_err(),
        "non-canonical uppercase hex must be refused by from_text"
    );
    let dup = format!("{} 1\n{} 1\n", "bb".repeat(32), "bb".repeat(32));
    assert!(
        QuarantineLedger::from_text(&dup).is_err(),
        "duplicate program hash lines must be refused by from_text"
    );
}

#[test]
fn canonical_recovery_reconcile_never_elects_all_zero_pin() {
    let zero = [0u8; 32];
    assert_eq!(
        reconcile(&[zero, zero, zero, zero]),
        Reconciliation::Split,
        "all-zero uninitialized pins must fail closed as Split, never Unanimous"
    );
    let real = [0x11u8; 32];
    assert_eq!(
        reconcile(&[zero, zero, zero, real]),
        Reconciliation::Split,
        "majority of all-zero pins must never elect [0; 32]"
    );
}

#[test]
fn relay_report_verify_refuses_embedded_nul_collision_and_status_alarm_mismatch() {
    let mut report = CanonicalRelayReport {
        schema_version: RELAY_SCHEMA_VERSION,
        status: RelayStatus::Ok,
        verified_at_unix: 1_700_000_000,
        program_hash: [0x11; 32],
        is_canonical: true,
        canonical_set_digest: [0x22; 32],
        proof: ProofFingerprint {
            proof_format_version: 1,
            backend: "a\0b".into(),
            p3_version: "c".into(),
            fri_params_id: "fri-1".into(),
            degree_bits: 10,
            public_inputs_hash: [0x33; 32],
            proof_bytes_len: 128,
        },
        alarm: None,
        report_sig: [0u8; 32],
    };
    report.report_sig = keccak256(&report.canonical_payload());
    assert!(
        !report.verify_report_sig(),
        "embedded NUL byte in NUL-terminated backend field must fail verify_report_sig"
    );

    // Contradictory Ok status carrying Some(alarm) must fail even with matching hash.
    let mut bad_status = CanonicalRelayReport {
        proof: ProofFingerprint {
            backend: "plonky3".into(),
            p3_version: "0.8.0".into(),
            ..report.proof
        },
        alarm: Some(AlarmDetail {
            code: AlarmCode::InvalidProof,
            detail: "contradiction".into(),
        }),
        ..report
    };
    bad_status.report_sig = keccak256(&bad_status.canonical_payload());
    assert!(
        !bad_status.verify_report_sig(),
        "RelayStatus::Ok with Some(alarm) must fail verify_report_sig"
    );
}
