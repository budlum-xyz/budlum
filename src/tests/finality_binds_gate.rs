//! Contract tests for the binds seal: a finality row must carry, and seal,
//! the traces of the proof it attests.
//!
//! The rule under test is one sentence: a row can only seal what its own
//! proof proves. `compose` re-derives both traces from the row's guarantee
//! and refuses any row whose sealed bytes disagree, in every bucket. The gate
//! then refuses any row whose proof binds less than the roots the route reads.
//!
//! Two walls guard the same claim (a transaction-only proof cannot license a
//! state or event read), and both are measured separately:
//!
//! - **compose wall**: such a row cannot be composed into an `Established`
//!   bucket at all (`AttestationUnbound`), so a certificate is never minted;
//! - **gate wall**: the same row composed as `Pending` is refused by
//!   `check_certificate_value_gate` through the verdict, and a row that
//!   reaches the gate with a narrow bind set is refused by `BindsUnproven`.

use crate::cross_domain::external::sentry::ConsensusSentry;
use crate::crypto::facts::QuantumClass;
use crate::settlement::domains::CommitmentAttestation;
use crate::settlement::finality_gate::{check_certificate_value_gate, ValueGate, ValueGateRefusal};
use crate::settlement::finality_policy::{
    enforce_binds, enforce_quantum_posture, enforce_root, QuantumPosturePolicy, BINDS_EVENT_ROOT,
    BINDS_PARENT, BINDS_STATE_ROOT, BINDS_TX_ROOT, BINDS_VALUE_ROUTE,
};
use crate::settlement::universal_finality::{
    compose, trace_record_binds, trace_record_quantum_posture, DomainFinalityEntry,
    FinalityComposeError, FinalityGuarantee, FinalityPendingReason, FinalityReversibility,
    FinalityVerdict, FINALITY_BINDS_ALL,
};

const CHECKPOINT: u64 = 900;

fn guarantee_with(attestation: CommitmentAttestation, posture: QuantumClass) -> FinalityGuarantee {
    FinalityGuarantee {
        reversibility: FinalityReversibility::ProbabilisticWork { confirmations: 6 },
        quantum_posture: posture,
        attestation,
        slashable_backing: false,
        fault_tolerance_bps: 4_999,
    }
}

/// A row whose sealed traces are honestly derived from its own guarantee.
fn honest_row(
    domain_id: u32,
    guarantee: FinalityGuarantee,
    verdict: FinalityVerdict,
) -> DomainFinalityEntry {
    DomainFinalityEntry {
        domain_id,
        height: 500 + u64::from(domain_id),
        checkpoint_height: CHECKPOINT,
        state_root: [0x11; 32],
        adapter_id: "pow-header-v1".to_owned(),
        adapter_version: 1,
        finality_proof_hash: [0x22; 32],
        guarantee_backing_hash: [0x33; 32],
        bond_atoms: 10_000_000,
        binds: trace_record_binds(&guarantee.attestation),
        posture_trace: trace_record_quantum_posture(guarantee.quantum_posture),
        guarantee,
        verdict,
    }
}

fn full_guarantee() -> FinalityGuarantee {
    guarantee_with(FINALITY_BINDS_ALL, QuantumClass::Hash)
}

fn empty_sentry() -> ConsensusSentry {
    ConsensusSentry::new()
}

// ---------------------------------------------------------------------------
// 1. The seal exists and is exact.
// ---------------------------------------------------------------------------

#[test]
fn row_digest_seals_both_traces() {
    let row = honest_row(1, full_guarantee(), FinalityVerdict::Established);
    let base = row.row_digest();

    let mut changed_binds = row.clone();
    changed_binds.binds = trace_record_binds(&BINDS_STATE_ROOT);
    assert_ne!(
        changed_binds.row_digest(),
        base,
        "changing the sealed binds trace must change the row digest"
    );

    let mut changed_posture = row.clone();
    changed_posture.posture_trace = trace_record_quantum_posture(QuantumClass::Classical);
    assert_ne!(
        changed_posture.row_digest(),
        base,
        "changing the sealed posture trace must change the row digest"
    );
}

#[test]
fn trace_records_are_distinct_per_root_and_per_posture() {
    let masks = [
        BINDS_STATE_ROOT,
        BINDS_TX_ROOT,
        BINDS_EVENT_ROOT,
        BINDS_PARENT,
        BINDS_VALUE_ROUTE,
        CommitmentAttestation {
            state_root: false,
            tx_root: false,
            event_root: false,
            parent: false,
        },
    ];
    let mut seen = std::collections::BTreeSet::new();
    for mask in masks {
        assert!(
            seen.insert(trace_record_binds(&mask)),
            "two different bind sets produced the same trace"
        );
    }
    let postures = [
        QuantumClass::Classical,
        QuantumClass::Lattice,
        QuantumClass::Hash,
    ];
    let mut posture_traces = std::collections::BTreeSet::new();
    for posture in postures {
        assert!(
            posture_traces.insert(trace_record_quantum_posture(posture)),
            "two postures produced the same trace"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. compose refuses a row whose seal disagrees with its proof.
// ---------------------------------------------------------------------------

#[test]
fn compose_refuses_a_row_sealing_a_wider_bind_than_its_proof() {
    // The row's guarantee binds only the state root, but its sealed trace
    // claims the whole route. That is the forgery this slice closes.
    let narrow = guarantee_with(BINDS_STATE_ROOT, QuantumClass::Hash);
    let mut row = honest_row(
        7,
        narrow,
        FinalityVerdict::Pending {
            reason: FinalityPendingReason::AttestationUnbound,
        },
    );
    row.binds = trace_record_binds(&BINDS_VALUE_ROUTE);

    assert_eq!(
        compose(&[row]),
        Err(FinalityComposeError::BindsMismatch { domain_id: 7 })
    );
}

#[test]
fn compose_refuses_a_fake_posture_trace() {
    let row_guarantee = guarantee_with(FINALITY_BINDS_ALL, QuantumClass::Classical);
    let mut row = honest_row(9, row_guarantee, FinalityVerdict::Established);
    // Claim a lattice-grade seal over a classical key.
    row.posture_trace = trace_record_quantum_posture(QuantumClass::Lattice);

    assert_eq!(
        compose(&[row]),
        Err(FinalityComposeError::BindsMismatch { domain_id: 9 })
    );
}

#[test]
fn the_mismatch_check_runs_in_every_bucket_not_only_established() {
    // A Refuted row is about to be dropped from Established anyway; it must
    // still not carry a seal its proof cannot produce. Otherwise a relayer
    // could smuggle a wider claim through a row nobody looks at twice.
    for verdict in [
        FinalityVerdict::Refuted { code: 3 },
        FinalityVerdict::Pending {
            reason: FinalityPendingReason::EvidenceMissing,
        },
    ] {
        let mut row = honest_row(11, full_guarantee(), verdict);
        row.binds = trace_record_binds(&BINDS_PARENT);
        assert_eq!(
            compose(&[row]),
            Err(FinalityComposeError::BindsMismatch { domain_id: 11 })
        );
    }
}

// ---------------------------------------------------------------------------
// 3. The two walls for "a narrow proof cannot license a wide read".
// ---------------------------------------------------------------------------

#[test]
fn compose_wall_refuses_an_established_row_that_binds_less_than_everything() {
    let narrow = guarantee_with(BINDS_STATE_ROOT.union(BINDS_TX_ROOT), QuantumClass::Hash);
    let row = honest_row(21, narrow, FinalityVerdict::Established);
    assert_eq!(
        compose(&[row]),
        Err(FinalityComposeError::AttestationUnbound { domain_id: 21 })
    );
}

#[test]
fn gate_wall_refuses_a_narrow_row_composed_as_pending() {
    // The same narrow proof, this time honestly composed as Pending. The gate
    // refuses it through the verdict, before any route math runs.
    let narrow = guarantee_with(BINDS_STATE_ROOT.union(BINDS_TX_ROOT), QuantumClass::Hash);
    let cert = compose(&[honest_row(
        21,
        narrow,
        FinalityVerdict::Pending {
            reason: FinalityPendingReason::AttestationUnbound,
        },
    )])
    .expect("pending-only certificate composes");

    assert_eq!(
        check_certificate_value_gate(&cert, &empty_sentry(), ValueGate::BridgeMint, 21, None),
        Err(ValueGateRefusal::DomainPending {
            domain_id: 21,
            reason: FinalityPendingReason::AttestationUnbound,
        })
    );
}

// ---------------------------------------------------------------------------
// 4. Gate order: each refusal names the earliest failing condition.
// ---------------------------------------------------------------------------

#[test]
fn gate_refuses_a_narrow_established_row_at_the_binds_check() {
    // Established + full fault tolerance + positive root, but the proof binds
    // only the state root. The gate must name the binds check, not the route.
    let narrow = guarantee_with(BINDS_STATE_ROOT, QuantumClass::Hash);
    // `compose` would refuse this row at the compose wall, so build the
    // certificate the way only a forged exporter could: mutate after compose.
    let mut cert = compose(&[honest_row(
        31,
        full_guarantee(),
        FinalityVerdict::Established,
    )])
    .expect("full row composes");
    cert.established[0].guarantee = narrow;
    cert.established[0].binds = trace_record_binds(&narrow.attestation);
    cert.established[0].posture_trace = trace_record_quantum_posture(narrow.quantum_posture);

    // The bitset is not tampered, only the row is internally inconsistent with
    // its own attestation: re-composing from the row keeps the seal honest,
    // so the gate is what refuses - exactly the wall this test measures.
    let refusal =
        check_certificate_value_gate(&cert, &empty_sentry(), ValueGate::BridgeMint, 31, None)
            .expect_err("a proof binding only the state root must not move value");
    assert!(
        matches!(
            refusal,
            ValueGateRefusal::BindsUnproven { domain_id: 31, .. }
        ),
        "expected BindsUnproven, got {refusal:?}"
    );
}

#[test]
fn gate_refuses_a_classical_posture_at_the_posture_check() {
    let classical = guarantee_with(FINALITY_BINDS_ALL, QuantumClass::Classical);
    let cert = compose(&[honest_row(41, classical, FinalityVerdict::Established)])
        .expect("full binds, classical posture composes");
    let refusal = check_certificate_value_gate(
        &cert,
        &empty_sentry(),
        ValueGate::UniversalPayment,
        41,
        None,
    )
    .expect_err("a classical posture must not move value");
    assert!(
        matches!(
            refusal,
            ValueGateRefusal::QuantumPostureInsufficient {
                domain_id: 41,
                observed: "CLASSICAL",
                ..
            }
        ),
        "expected QuantumPostureInsufficient, got {refusal:?}"
    );
}

#[test]
fn gate_refuses_a_zero_root_row_before_anything_else() {
    let mut row = honest_row(51, full_guarantee(), FinalityVerdict::Established);
    row.state_root = [0u8; 32];
    // A zero-root row cannot be composed as Established through the normal
    // path only if the registry says so; here compose accepts it (compose
    // checks binds, not roots), so the gate's root check is the single guard.
    let cert = compose(&[row]).expect("compose accepts binds-consistent rows");
    assert_eq!(
        check_certificate_value_gate(&cert, &empty_sentry(), ValueGate::BridgeMint, 51, None),
        Err(ValueGateRefusal::DomainPending {
            domain_id: 51,
            reason: FinalityPendingReason::EvidenceMissing,
        })
    );
}

#[test]
fn a_fully_attested_established_row_still_passes() {
    let cert = compose(&[honest_row(
        61,
        full_guarantee(),
        FinalityVerdict::Established,
    )])
    .expect("full row composes");
    let verdict =
        check_certificate_value_gate(&cert, &empty_sentry(), ValueGate::BridgeMint, 61, None)
            .expect("a full, hash-postured, established row must pass");
    assert_eq!(verdict.gate, ValueGate::BridgeMint);
    assert!(verdict.safe_value_outflow_ceiling_atoms > 0);
}

// ---------------------------------------------------------------------------
// 5. The policy floor itself.
// ---------------------------------------------------------------------------

#[test]
fn policy_helpers_refuse_the_three_failures_and_admit_the_good_row() {
    assert!(enforce_root([0u8; 32]).is_err());
    assert!(enforce_root([1u8; 32]).is_ok());
    assert!(enforce_binds(&FINALITY_BINDS_ALL, BINDS_VALUE_ROUTE).is_ok());
    assert_eq!(
        enforce_binds(&BINDS_STATE_ROOT, BINDS_VALUE_ROUTE),
        Err(BINDS_VALUE_ROUTE)
    );
    assert!(enforce_quantum_posture(
        QuantumClass::Hash,
        QuantumPosturePolicy::AtLeast(QuantumClass::Lattice)
    )
    .is_ok());
    assert!(enforce_quantum_posture(
        QuantumClass::Classical,
        QuantumPosturePolicy::AtLeast(QuantumClass::Lattice)
    )
    .is_err());
}

#[test]
fn verify_integrity_inherits_the_seal_because_it_recomposes() {
    let cert = compose(&[honest_row(
        71,
        full_guarantee(),
        FinalityVerdict::Established,
    )])
    .expect("full row composes");
    cert.verify_integrity()
        .expect("honest certificate verifies");

    let mut forged = cert.clone();
    forged.established[0].guarantee.attestation = BINDS_STATE_ROOT;
    // The seal no longer matches the mutated guarantee: recomposition inside
    // `verify_integrity` must refuse it even before comparing roots.
    assert_eq!(
        forged.verify_integrity(),
        Err(FinalityComposeError::BindsMismatch { domain_id: 71 })
    );
}
