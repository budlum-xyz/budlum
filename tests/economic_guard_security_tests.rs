//! End-to-end security tests for BridgeEconomicGuard:
//! - Monotonic rolling-window enforcement (stale height cannot reset consumed outflow)
//! - GlobalFinalityCertificate integrity verification before admitting bridge flow
//! - Zero-bond certificate row weakest-link enforcement (strict 0 ceiling)
//! - Permanent replay protection for the freezing contradiction evidence digest
//! - Preservation of prover bond and slashing trail on FrozenByContradiction domains

use budlum_core::core::address::Address;
use budlum_core::cross_domain::economic_guard::{
    contradiction_statement_bytes, effective_ceiling_from_certificate_row, BridgeEconomicGuard,
    ContradictionEvidence, DomainCeilingPolicy, EconomicGuardError, GUARD_REPLAY_EPOCH_BLOCKS,
    GUARD_REPLAY_RETENTION_EPOCHS,
};
use budlum_core::cross_domain::external::{ProverBond, SecurityBacking};
use budlum_core::crypto::facts::{ObservedScheme, QuantumClass};
use budlum_core::crypto::primitives::{KeyPair, PqKeyPair};
use budlum_core::settlement::universal_finality::{
    compose, DomainFinalityEntry, FinalityGuarantee, FinalityReversibility, FinalityVerdict,
    FINALITY_BINDS_ALL,
};

fn slashable_policy(window_blocks: u64) -> DomainCeilingPolicy {
    DomainCeilingPolicy {
        backing: SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Secp256k1,
            signers: 4,
            required: 3,
            total_weight: 300_000,
            slashable: true,
        },
        stake_haircut_bps: 3_333,
        window_blocks,
        ..DomainCeilingPolicy::default()
    }
}

fn make_cert_entry(
    domain_id: u32,
    bond_atoms: u128,
    verdict: FinalityVerdict,
) -> DomainFinalityEntry {
    DomainFinalityEntry {
        domain_id,
        height: 12,
        checkpoint_height: 50,
        state_root: [0x11; 32],
        adapter_id: "cometbft-v1".to_owned(),
        adapter_version: 1,
        finality_proof_hash: [0x22; 32],
        guarantee_backing_hash: [0x33; 32],
        bond_atoms,
        guarantee: FinalityGuarantee {
            reversibility: FinalityReversibility::DeterministicQuorum,
            quantum_posture: QuantumClass::Hash,
            attestation: FINALITY_BINDS_ALL,
            slashable_backing: true,
            fault_tolerance_bps: 3_333,
        },
        verdict,
    }
}

#[test]
fn backwards_window_height_cannot_reset_consumed_bridge_outflow() {
    let mut guard = BridgeEconomicGuard::new();
    let domain_id = 701u32;
    guard
        .configure_domain(domain_id, slashable_policy(100), None)
        .expect("configure");

    // Exhaust the full window ceiling (~99_990 atoms) at window 1 (height 150).
    guard
        .check_and_record_flow(domain_id, 99_990, 150)
        .expect("window 1 flow fits ceiling");
    assert!(matches!(
        guard.check_and_record_flow(domain_id, 1, 151),
        Err(EconomicGuardError::CeilingExceeded { .. })
    ));

    // A stale/backwards height in window 0 (height 50) MUST fail closed instead of
    // resetting window_used_atoms to 0 and permitting double-drain.
    let stale_err = guard
        .check_and_record_flow(domain_id, 50_000, 50)
        .expect_err("stale backwards window height must be refused");
    assert!(matches!(stale_err, EconomicGuardError::InvalidEvidence(_)));

    // Window 1 consumption must remain intact after the refused stale height.
    assert!(matches!(
        guard.check_and_record_flow(domain_id, 1, 152),
        Err(EconomicGuardError::CeilingExceeded { .. })
    ));
}

#[test]
fn forged_finality_certificate_is_rejected_before_admitting_bridge_flow() {
    let mut guard = BridgeEconomicGuard::new();
    let domain_id = 702u32;
    guard
        .configure_domain(domain_id, slashable_policy(100), None)
        .expect("configure");

    // Build an authentic Refuted certificate, then forge its entry verdict to Established
    // without recomputing the certificate integrity root/digest.
    let mut forged = compose(&[make_cert_entry(
        domain_id,
        300_000,
        FinalityVerdict::Refuted { code: 7 },
    )])
    .expect("compose refuted cert");
    // Forge an Established row onto a Refuted certificate without matching integrity digest.
    forged.refuted.clear();
    forged.established.push(make_cert_entry(
        domain_id,
        300_000,
        FinalityVerdict::Established,
    ));

    let err = guard
        .check_and_record_flow_with_certificate(domain_id, 1_000, 50, &forged)
        .expect_err("forged finality certificate with tampered verdict must be refused");
    assert!(matches!(err, EconomicGuardError::InvalidEvidence(_)));
}

#[test]
fn zero_bond_certificate_row_enforces_zero_ceiling_instead_of_opening_policy_cap() {
    let mut guard = BridgeEconomicGuard::new();
    let domain_id = 703u32;
    guard
        .configure_domain(domain_id, slashable_policy(100), None)
        .expect("configure");

    let zero_bond_cert = compose(&[make_cert_entry(domain_id, 0, FinalityVerdict::Established)])
        .expect("compose zero-bond cert");
    let proof = zero_bond_cert
        .prove_domain(domain_id)
        .expect("proof for domain");
    let rec = guard.record(domain_id).expect("record");

    assert_eq!(
        effective_ceiling_from_certificate_row(rec, &proof.entry),
        0,
        "zero-bond certificate row must yield strict 0 ceiling"
    );
    assert!(matches!(
        guard.check_and_record_flow_with_certificate(domain_id, 1, 50, &zero_bond_cert),
        Err(EconomicGuardError::CeilingExceeded {
            ceiling_atoms: 0,
            ..
        })
    ));
}

#[test]
fn freezing_contradiction_cannot_be_replayed_after_epoch_pruning_and_frozen_bond_cannot_be_wiped() {
    let ed_kp = KeyPair::from_seed(&[0x51; 32]).expect("ed25519");
    let pq_kp = PqKeyPair::generate();
    let prover_addr = Address::from([0x61; 32]);
    let mut guard = BridgeEconomicGuard::new();
    let domain_id = 704u32;

    let policy = DomainCeilingPolicy {
        prover_ed25519_pubkey: Some(ed_kp.public_key_bytes()),
        prover_pq_pubkey: pq_kp.public_key_bytes().to_vec(),
        ..slashable_policy(100)
    };
    let bond = ProverBond {
        prover: prover_addr,
        bond_atoms: 1_000_000,
        ceiling_atoms: 1_000_000,
        slashed_atoms: 0,
        accepted: 0,
        refused: 0,
        slashings: Vec::new(),
    };
    guard
        .configure_domain(domain_id, policy.clone(), Some(bond))
        .expect("configure with bond");

    let root_a = [0xAA; 32];
    let root_b = [0xBB; 32];
    let stmt_a = contradiction_statement_bytes(domain_id, 99, &root_a);
    let stmt_b = contradiction_statement_bytes(domain_id, 99, &root_b);
    let evidence = ContradictionEvidence::SignedProverDoubleRoot {
        domain_height: 99,
        state_root_a: root_a,
        ed25519_sig_a: ed_kp.sign(&stmt_a).to_vec(),
        pq_sig_a: pq_kp
            .sign(budlum_core::crypto::ctx::CROSS_DOMAIN_V1, &stmt_a)
            .expect("pq sign a"),
        state_root_b: root_b,
        ed25519_sig_b: ed_kp.sign(&stmt_b).to_vec(),
        pq_sig_b: pq_kp
            .sign(budlum_core::crypto::ctx::CROSS_DOMAIN_V1, &stmt_b)
            .expect("pq sign b"),
    };

    // First contradiction at epoch 1 freezes the domain and slashes the bond.
    let outcome = guard
        .submit_contradiction(domain_id, &evidence, Address::from([0x77; 32]), 1_000)
        .expect("first contradiction freezes domain");
    assert_eq!(outcome.slashed_bond_atoms, 1_000_000);

    // Policy reconfiguration MUST NOT erase a frozen domain's slashed prover_bond audit trail.
    let wipe_err = guard
        .configure_domain(domain_id, policy, None)
        .expect_err("wiping prover_bond on a frozen domain must fail closed");
    assert!(matches!(wipe_err, EconomicGuardError::DomainFrozen { .. }));
    assert!(guard.record(domain_id).expect("rec").prover_bond.is_some());

    // Advance past the replay retention window (epoch 1 -> epoch 7) so epoch-1 replay entries
    // are pruned, then try replaying the exact same freezing contradiction evidence.
    let later_height =
        GUARD_REPLAY_EPOCH_BLOCKS.saturating_mul(GUARD_REPLAY_RETENTION_EPOCHS.saturating_add(3));
    let replay_err = guard
        .submit_contradiction(
            domain_id,
            &evidence,
            Address::from([0x88; 32]),
            later_height,
        )
        .expect_err("freezing contradiction evidence MUST NEVER replay after epoch pruning");
    assert!(matches!(
        replay_err,
        EconomicGuardError::DuplicateEvidence(_)
    ));
}
