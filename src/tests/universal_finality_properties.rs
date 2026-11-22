//! Property, invariant, and refutation tests for the Universal Finality Layer.
//!
//! Covers:
//! - Order-independent composition and Merkle inclusion proof soundness on
//!   [`GlobalFinalityCertificate`].
//! - Non-blocking three-valued buckets (`Established` / `Pending` / `Refuted`)
//!   and fail-closed rejection of unbound or zero-fault-tolerance established rows.
//! - Semilattice laws (commutativity, associativity, idempotence, monotonicity)
//!   for [`FinalityGuarantee::meet`].
//! - Carrier idle-fee escalation upper bound below slashing penalty and
//!   economic honesty invariant ([`DomainEconomics::carrier_reward_for_idle`]).
//! - Slashable backing and cross-domain outflow conservation on
//!   [`EconomicSecurityBound`].
//! - Admin-keyless invariant on the on-chain external finality verifier
//!   contracts under `contracts/`.

use crate::cross_domain::external::prover::{
    honesty_is_cheaper, ChallengeReward, DomainEconomics, ProverFee,
};
use crate::crypto::facts::QuantumClass;
use crate::settlement::domains::CommitmentAttestation;
use crate::settlement::universal_finality::{
    compose, DomainFinalityEntry, EconomicSecurityBound, FinalityBucket, FinalityGuarantee,
    FinalityPendingReason, FinalityReversibility, FinalityVerdict,
};

fn sample_entry(
    domain_id: u32,
    checkpoint_height: u64,
    guarantee: FinalityGuarantee,
    verdict: FinalityVerdict,
) -> DomainFinalityEntry {
    let tag = u8::try_from(domain_id & 0xff).unwrap_or(0xaa);
    DomainFinalityEntry {
        domain_id,
        height: 1_000 + u64::from(domain_id),
        checkpoint_height,
        state_root: [tag; 32],
        adapter_id: format!("adapter-{domain_id}"),
        adapter_version: 1,
        finality_proof_hash: [tag.wrapping_add(1); 32],
        guarantee_backing_hash: [tag.wrapping_add(2); 32],
        bond_atoms: 1_000_000_000,
        guarantee,
        verdict,
    }
}

#[test]
fn global_finality_certificate_is_order_independent_and_rejects_tampered_inclusion_proofs() {
    let hub = FinalityGuarantee::settlement_hub();
    let e1 = sample_entry(101, 500, hub, FinalityVerdict::Established);
    let e2 = sample_entry(
        202,
        500,
        hub,
        FinalityVerdict::Pending {
            reason: FinalityPendingReason::EvidenceMissing,
        },
    );
    let e3 = sample_entry(303, 500, hub, FinalityVerdict::Established);
    let e4 = sample_entry(404, 500, hub, FinalityVerdict::Refuted { code: 7 });

    let cert_a = compose(&[e1.clone(), e2.clone(), e3.clone(), e4.clone()]).expect("compose a");
    let cert_b = compose(&[e4, e3, e1, e2]).expect("compose b");

    assert_eq!(cert_a.established_root, cert_b.established_root);
    assert_eq!(cert_a.pending_root, cert_b.pending_root);
    assert_eq!(cert_a.refuted_root, cert_b.refuted_root);
    assert_eq!(cert_a.certificate_digest, cert_b.certificate_digest);
    cert_a.verify_integrity().expect("integrity valid");

    for domain_id in [101u32, 202, 303, 404] {
        let proof = cert_a
            .prove_domain(domain_id)
            .expect("registered domain must yield inclusion proof");
        assert!(proof.verify(&cert_a.bucket_root(proof.bucket)));

        let wrong_bucket = match proof.bucket {
            FinalityBucket::Established => FinalityBucket::Pending,
            FinalityBucket::Pending => FinalityBucket::Refuted,
            FinalityBucket::Refuted => FinalityBucket::Established,
        };
        assert!(
            !proof.verify(&cert_a.bucket_root(wrong_bucket)),
            "inclusion proof must fail against another bucket root"
        );

        let mut tampered_proof = proof.clone();
        tampered_proof.entry.state_root[0] ^= 0xff;
        assert!(
            !tampered_proof.verify(&cert_a.bucket_root(proof.bucket)),
            "tampered entry state_root must invalidate inclusion proof"
        );
    }

    assert!(cert_a.prove_domain(999).is_none());

    let mut tampered_cert = cert_a;
    tampered_cert.established_root[0] ^= 0x01;
    assert!(tampered_cert.verify_integrity().is_err());
}

#[test]
fn global_finality_certificate_is_non_blocking_across_pending_and_refuted_domains() {
    let hub = FinalityGuarantee::settlement_hub();
    let ok_a = sample_entry(11, 777, hub, FinalityVerdict::Established);
    let ok_b = sample_entry(22, 777, hub, FinalityVerdict::Established);
    let stalled = sample_entry(
        33,
        777,
        hub,
        FinalityVerdict::Pending {
            reason: FinalityPendingReason::RuleNotSatisfied,
        },
    );
    let disputed = sample_entry(44, 777, hub, FinalityVerdict::Refuted { code: 404 });

    let cert = compose(&[ok_a, ok_b, stalled, disputed]).expect("non-blocking compose");
    assert_eq!(cert.established_count, 2);
    assert_eq!(cert.pending_count, 1);
    assert_eq!(cert.refuted_count, 1);
    assert_eq!(cert.guarantee, Some(hub));

    let pending_proof = cert.prove_domain(33).expect("pending proof");
    assert_eq!(pending_proof.bucket, FinalityBucket::Pending);
    assert_eq!(
        pending_proof.entry.verdict,
        FinalityVerdict::Pending {
            reason: FinalityPendingReason::RuleNotSatisfied
        }
    );

    let refuted_proof = cert.prove_domain(44).expect("refuted proof");
    assert_eq!(refuted_proof.bucket, FinalityBucket::Refuted);
    assert_eq!(
        refuted_proof.entry.verdict,
        FinalityVerdict::Refuted { code: 404 }
    );

    // An Established row missing state_root attestation must fail closed.
    let mut unbound = hub;
    unbound.attestation = CommitmentAttestation {
        state_root: false,
        tx_root: true,
        event_root: true,
        parent: true,
    };
    let bad_attestation = sample_entry(55, 777, unbound, FinalityVerdict::Established);
    assert!(compose(&[bad_attestation]).is_err());

    // An Established row with zero fault tolerance must fail closed.
    let mut zero_ft = hub;
    zero_ft.fault_tolerance_bps = 0;
    let bad_ft = sample_entry(66, 777, zero_ft, FinalityVerdict::Established);
    assert!(compose(&[bad_ft]).is_err());
}

#[test]
fn weakest_link_guarantee_meet_is_commutative_associative_and_monotonic() {
    let hub = FinalityGuarantee::settlement_hub();
    let pow_classical = FinalityGuarantee {
        reversibility: FinalityReversibility::ProbabilisticWork { confirmations: 6 },
        quantum_posture: QuantumClass::Classical,
        attestation: CommitmentAttestation {
            state_root: true,
            tx_root: true,
            event_root: false,
            parent: true,
        },
        slashable_backing: false,
        fault_tolerance_bps: 2_500,
    };
    let da_hash = FinalityGuarantee {
        reversibility: FinalityReversibility::DataAvailabilitySampled { min_samples: 64 },
        quantum_posture: QuantumClass::Hash,
        attestation: CommitmentAttestation {
            state_root: true,
            tx_root: false,
            event_root: true,
            parent: true,
        },
        slashable_backing: true,
        fault_tolerance_bps: 3_333,
    };

    // Commutativity
    assert_eq!(hub.meet(&pow_classical), pow_classical.meet(&hub));
    assert_eq!(pow_classical.meet(&da_hash), da_hash.meet(&pow_classical));

    // Associativity
    assert_eq!(
        hub.meet(&pow_classical).meet(&da_hash),
        hub.meet(&pow_classical.meet(&da_hash))
    );

    // Idempotence
    assert_eq!(hub.meet(&hub), hub);
    assert_eq!(pow_classical.meet(&pow_classical), pow_classical);

    // Monotonic weakening across all security axes
    let combined = hub.meet(&pow_classical).meet(&da_hash);
    assert!(!combined.slashable_backing);
    assert_eq!(combined.fault_tolerance_bps, 2_500);
    assert_eq!(combined.quantum_posture, QuantumClass::Classical);
    assert!(!combined.attestation.tx_root);
    assert!(!combined.attestation.event_root);
}

#[test]
fn carrier_idle_escalation_remains_strictly_below_slashing_penalty_and_honesty_is_cheaper() {
    let economics = DomainEconomics {
        routing_ceiling_atoms: 1_000_000,
        fee: ProverFee {
            base_atoms: 1_000,
            value_bps: 15,
        },
        challenge: ChallengeReward {
            bps_of_slash: 5_000,
            floor_atoms: 500,
        },
        unbonding_heights: 1_000,
    };

    let routed = economics.routing_ceiling_atoms;
    let penalty = economics.penalty_for(routed, economics.required_bond_atoms());
    assert!(penalty > 0);
    assert!(honesty_is_cheaper(&economics, routed));

    let samples = [0u64, 10, 100, 500, 2_000, 50_000, u64::MAX];
    let mut prev = 0u128;
    for idle in samples {
        let reward = economics.carrier_reward_for_idle(routed, idle);
        assert!(
            reward >= prev,
            "carrier idle reward must be non-decreasing across idle heights"
        );
        assert!(
            reward < penalty,
            "escalated carrier reward ({reward}) must stay strictly below slashing penalty ({penalty})"
        );
        prev = reward;
    }
}

#[test]
fn economic_security_bound_enforces_slashable_backing_and_outflow_conservation() {
    let hub = FinalityGuarantee::settlement_hub();
    let bond = 300_000_000u128;
    let ceiling = 50_000_000u128;

    let bound = EconomicSecurityBound::derive(&hub, bond, ceiling);
    assert!(bound.corruption_cost_atoms > 0);
    assert!(bound.safe_value_outflow_ceiling_atoms <= ceiling);
    assert!(bound.safe_value_outflow_ceiling_atoms <= bound.corruption_cost_atoms);

    // Zero outflow and overflow must be rejected fail-closed.
    assert!(bound.check_value_outflow_conservation(0, 0).is_err());
    assert!(bound
        .check_value_outflow_conservation(u128::MAX, 1)
        .is_err());
    assert!(bound
        .check_value_outflow_conservation(0, bound.safe_value_outflow_ceiling_atoms + 1)
        .is_err());

    let next = bound
        .check_value_outflow_conservation(1_000, 4_000)
        .expect("within safe outflow ceiling");
    assert_eq!(next, 5_000);

    // Without slashable backing, corruption cost must drop to 0.
    let mut unbacked = hub;
    unbacked.slashable_backing = false;
    let unbacked_bound = EconomicSecurityBound::derive(&unbacked, bond, ceiling);
    assert_eq!(unbacked_bound.corruption_cost_atoms, 0);
}

#[test]
fn finality_verifier_contracts_carry_no_privileged_admin_or_owner_doors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("contracts");
    let contracts = [
        "external-domain/BudlumFinalityVerifier.sol",
        "object-layer/BudlumFinalityVerifier.sol",
        "lib/BudlumHash.sol",
        "lib/BudlumStateReader.sol",
    ];
    let forbidden = [
        "onlyOwner",
        "Ownable",
        "transferOwnership",
        "setAdmin",
        "onlyAdmin",
        "upgradeTo(",
    ];

    for rel in contracts {
        let path = root.join(rel);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("expected finality contract {}: {err}", path.display()));
        for needle in forbidden {
            assert!(
                !source.contains(needle),
                "finality contract {rel} must remain admin-keyless; found `{needle}`"
            );
        }
    }
}
