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

#[test]
fn unified_asset_id_agrees_across_bridge_object_layer_uer_and_payment_router_with_caip19_check() {
    use crate::cross_domain::bridge::AssetId as BridgeAssetId;
    use crate::execution::uer::UniversalExecutionReceipt;
    use crate::object_layer::ids::AssetId as ObjectAssetId;
    use crate::unification::payment_router::universal_asset_id;

    let domain = 42u32;
    let local = b"eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    let from_bridge = BridgeAssetId::for_domain(domain, local);
    let from_object = ObjectAssetId::universal_bridge_id(domain, local);
    let from_uer = UniversalExecutionReceipt::universal_asset_id(domain, local);
    let from_router = universal_asset_id(domain, local);

    assert_eq!(from_bridge, from_object);
    assert_eq!(from_bridge, from_uer);
    assert_eq!(*from_bridge.as_bytes(), from_router);
    assert!(from_bridge.is_namespaced_for(domain));
    assert_eq!(from_bridge.namespace_domain(), domain);

    // Cross-domain collision is impossible by construction.
    assert_ne!(
        universal_asset_id(domain, local),
        universal_asset_id(domain + 1, local)
    );

    // CAIP-19 grammar checks (valid fungible + NFT + fail-closed rejections).
    assert!(ObjectAssetId::is_valid_caip19(
        "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    ));
    assert!(ObjectAssetId::is_valid_caip19(
        "eip155:1/erc721:0x06012c8cf97bead5deae237070f9587f8e7a266d/771769"
    ));
    assert!(!ObjectAssetId::is_valid_caip19(""));
    assert!(!ObjectAssetId::is_valid_caip19("eip155:1"));
    assert!(!ObjectAssetId::is_valid_caip19("EIP155:1/erc20:0xabc"));
    assert!(!ObjectAssetId::is_valid_caip19(
        "eip155:1/erc20:0xabc/1/extra"
    ));
}

#[test]
fn asset_equivalence_class_selects_cheapest_proven_member_and_enforces_supply_conservation() {
    use crate::unification::payment_router::{
        universal_asset_id, verify_split_tender_supply_conservation, AssetEquivalenceClass,
        AssetEquivalenceMember, SplitTenderLeg, UniversalPaymentReceipt,
    };

    let cheap_unproven = AssetEquivalenceMember {
        domain_id: 1,
        asset_id: universal_asset_id(1, b"USDC"),
        symbol: String::from("USDC"),
        fee_bps: 1,
        available_liquidity: 10_000_000,
        provenance_proof_root: [0x11; 32],
        finality_proven: false,
    };
    let zero_root_unproven = AssetEquivalenceMember {
        domain_id: 2,
        asset_id: universal_asset_id(2, b"USDC"),
        symbol: String::from("USDC"),
        fee_bps: 2,
        available_liquidity: 10_000_000,
        provenance_proof_root: [0u8; 32],
        finality_proven: true,
    };
    let expensive_proven = AssetEquivalenceMember {
        domain_id: 3,
        asset_id: universal_asset_id(3, b"USDC"),
        symbol: String::from("USDC"),
        fee_bps: 25,
        available_liquidity: 5_000_000,
        provenance_proof_root: [0x33; 32],
        finality_proven: true,
    };
    let cheapest_proven = AssetEquivalenceMember {
        domain_id: 4,
        asset_id: universal_asset_id(4, b"USDC"),
        symbol: String::from("USDC"),
        fee_bps: 10,
        available_liquidity: 2_000_000,
        provenance_proof_root: [0x44; 32],
        finality_proven: true,
    };

    let eq = AssetEquivalenceClass::new(
        String::from("USDC"),
        vec![
            cheap_unproven,
            zero_root_unproven,
            expensive_proven,
            cheapest_proven,
        ],
    )
    .expect("equivalence class");

    // Order-independent selection skips unproven and zero-root entries.
    let picked = eq
        .select_cheapest_proven(1_000_000)
        .expect("cheapest proven");
    assert_eq!(picked.domain_id, 4);
    assert_eq!(picked.fee_bps, 10);

    // Larger amount falls back to the proven member with sufficient liquidity.
    let large = eq.select_cheapest_proven(3_000_000).expect("larger proven");
    assert_eq!(large.domain_id, 3);

    // Request exceeding all proven liquidity fails closed.
    assert!(eq.select_cheapest_proven(9_000_000).is_err());

    let receipt = UniversalPaymentReceipt {
        intent_id: [0xaa; 32],
        target_domain: 4,
        target_asset_id: universal_asset_id(4, b"USDC"),
        target_amount_delivered: 1_000,
        legs: vec![
            SplitTenderLeg {
                source_domain: 1,
                source_asset_id: universal_asset_id(1, b"USDC"),
                source_symbol: String::from("USDC"),
                source_debited: 605,
                target_delivered: 600,
                fee_bps: 10,
                direct_same_domain: false,
                quote_id: Some([0xbb; 32]),
            },
            SplitTenderLeg {
                source_domain: 4,
                source_asset_id: universal_asset_id(4, b"USDC"),
                source_symbol: String::from("USDC"),
                source_debited: 400,
                target_delivered: 400,
                fee_bps: 0,
                direct_same_domain: true,
                quote_id: None,
            },
        ],
        legs_merkle_root: [0xcc; 32],
        pos_auth_code: None,
        receipt_hash: [0xdd; 32],
    };

    verify_split_tender_supply_conservation(&receipt, 1_005, 1_000, 5)
        .expect("exact supply conservation passes");
    assert!(
        verify_split_tender_supply_conservation(&receipt, 1_005, 1_001, 5).is_err(),
        "inflationary delivery must fail conservation"
    );
    assert!(
        verify_split_tender_supply_conservation(&receipt, u128::MAX, u128::MAX, 1).is_err(),
        "overflow must fail conservation"
    );
}

#[test]
fn output_composer_attested_verifies_uer_batch_synchronous_steps_and_rejects_forged_outputs() {
    use crate::core::hash::calculate_hash_bytes;
    use crate::execution::uer::{
        compute_uer_batch_root, prove_uer_inclusion, UerStatus, UniversalExecutionReceipt,
        UER_VERSION_V1,
    };
    use crate::unification::output_composer::{
        AtomicityClass, CanonicalValue, NormalizedMachineOutput, OutputBinding, OutputComposer,
        OutputCompositionPlan, OutputSelector, StepReceiptAttestation,
    };
    use budlum_uel_abi::EeId;
    use std::collections::BTreeMap;

    let evm_return = b"evm-swap-result".to_vec();
    let wasm_return = b"wasm-settle-ok".to_vec();

    let mut evm_vals = BTreeMap::new();
    evm_vals.insert(String::from("amount"), CanonicalValue::U128(500));
    let evm_step = NormalizedMachineOutput::from_evm(
        "evm_leg",
        1,
        true,
        50_000,
        evm_return.clone(),
        &[],
        evm_vals,
    )
    .expect("evm step");

    let mut wasm_vals = BTreeMap::new();
    wasm_vals.insert(String::from("in_amount"), CanonicalValue::U128(500));
    let wasm_step = NormalizedMachineOutput::from_wasm(
        "wasm_leg",
        1,
        true,
        40_000,
        wasm_return.clone(),
        Vec::new(),
        wasm_vals,
    )
    .expect("wasm step");

    let r0 = UniversalExecutionReceipt {
        version: UER_VERSION_V1,
        chain_id: 1,
        block_height: 42,
        tx_index: 0,
        tx_hash: [0x11; 32],
        origin_ee: EeId::EVM.0,
        status: UerStatus::Success,
        gas_used_bgu: evm_step.gas_used_bgu,
        burned_attos: 100,
        security_pool_attos: 50,
        proposer_tip_attos: 10,
        output_digest: calculate_hash_bytes(&evm_return),
        contract_address: None,
        logs_commitment: [0x22; 32],
        post_execution_root: [0x33; 32],
        zk_trace_commitment: None,
    };
    let r1 = UniversalExecutionReceipt {
        version: UER_VERSION_V1,
        chain_id: 1,
        block_height: 42,
        tx_index: 1,
        tx_hash: [0x44; 32],
        origin_ee: EeId::WASM.0,
        status: UerStatus::Success,
        gas_used_bgu: wasm_step.gas_used_bgu,
        burned_attos: 80,
        security_pool_attos: 40,
        proposer_tip_attos: 10,
        output_digest: calculate_hash_bytes(&wasm_return),
        contract_address: None,
        logs_commitment: [0x55; 32],
        post_execution_root: [0x66; 32],
        zk_trace_commitment: None,
    };

    let receipts = [r0, r1];
    let batch_root = compute_uer_batch_root(&receipts).expect("uer batch root");
    let p0 = prove_uer_inclusion(&receipts, 0).expect("proof 0");
    let p1 = prove_uer_inclusion(&receipts, 1).expect("proof 1");

    let plan = OutputCompositionPlan {
        plan_id: String::from("sync-evm-wasm-v1"),
        steps: vec![evm_step.clone(), wasm_step.clone()],
        bindings: vec![OutputBinding {
            from_step: String::from("evm_leg"),
            selector: OutputSelector::TypedField {
                key: String::from("amount"),
            },
            to_step: String::from("wasm_leg"),
            target_input: String::from("in_amount"),
            enforce_match: true,
        }],
    };

    let mut attestations = BTreeMap::new();
    attestations.insert(
        String::from("evm_leg"),
        StepReceiptAttestation::UerBatch {
            inclusion: p0.clone(),
            batch_root,
        },
    );
    attestations.insert(
        String::from("wasm_leg"),
        StepReceiptAttestation::UerBatch {
            inclusion: p1.clone(),
            batch_root,
        },
    );

    let attested = OutputComposer::compose_attested(
        &plan,
        AtomicityClass::SingleBlockSynchronous,
        &attestations,
    )
    .expect("synchronous UER-attested composition must succeed");
    assert_eq!(attested.atomicity, AtomicityClass::SingleBlockSynchronous);
    assert_ne!(attested.attestation_root, [0u8; 32]);

    // Tampering with return_data without matching UER receipt fails closed.
    let mut forged_plan = plan.clone();
    if let Some(first) = forged_plan.steps.first_mut() {
        first.return_data.push(0xff);
    }
    assert!(
        OutputComposer::compose_attested(
            &forged_plan,
            AtomicityClass::SingleBlockSynchronous,
            &attestations,
        )
        .is_err(),
        "forged return_data disagreeing with UER output_digest must be rejected"
    );

    // Missing attestation fails closed.
    let mut partial = BTreeMap::new();
    partial.insert(
        String::from("evm_leg"),
        StepReceiptAttestation::UerBatch {
            inclusion: p0,
            batch_root,
        },
    );
    assert!(OutputComposer::compose_attested(
        &plan,
        AtomicityClass::SingleBlockSynchronous,
        &partial
    )
    .is_err());
}

#[test]
fn output_composer_attested_enforces_external_two_phase_and_compensating_async_classes() {
    use crate::unification::output_composer::{
        build_external_step_receipt_proof, build_external_step_receipt_root, AtomicityClass,
        CanonicalValue, NormalizedMachineOutput, OutputComposer, OutputCompositionPlan,
        StepReceiptAttestation,
    };
    use std::collections::BTreeMap;

    let mut vals_a = BTreeMap::new();
    vals_a.insert(String::from("out"), CanonicalValue::U128(10));
    let step_a = NormalizedMachineOutput::from_evm(
        "eth_step",
        10,
        true,
        30_000,
        b"eth-ok".to_vec(),
        &[],
        vals_a,
    )
    .expect("step a");

    let mut vals_b = BTreeMap::new();
    vals_b.insert(String::from("out"), CanonicalValue::U128(10));
    let step_b = NormalizedMachineOutput::from_wasm(
        "cosmos_step",
        20,
        true,
        30_000,
        b"cosmos-ok".to_vec(),
        Vec::new(),
        vals_b,
    )
    .expect("step b");

    let leaves_a = [step_a.artifact_hash(), [0x99; 32]];
    let root_a = build_external_step_receipt_root(&leaves_a);
    let proof_a = build_external_step_receipt_proof(&leaves_a, 0).expect("proof a");

    let leaves_b = [[0x88; 32], step_b.artifact_hash()];
    let root_b = build_external_step_receipt_root(&leaves_b);
    let proof_b = build_external_step_receipt_proof(&leaves_b, 1).expect("proof b");

    let plan = OutputCompositionPlan {
        plan_id: String::from("cross-domain-2pc-v1"),
        steps: vec![step_a, step_b],
        bindings: Vec::new(),
    };

    let mut two_phase = BTreeMap::new();
    two_phase.insert(
        String::from("eth_step"),
        StepReceiptAttestation::ExternalDomainMerkle {
            domain_id: 10,
            finality_root: root_a,
            leaf_index: 0,
            leaf_count: leaves_a.len(),
            proof: proof_a.clone(),
            compensation_commitment: None,
        },
    );
    two_phase.insert(
        String::from("cosmos_step"),
        StepReceiptAttestation::ExternalDomainMerkle {
            domain_id: 20,
            finality_root: root_b,
            leaf_index: 1,
            leaf_count: leaves_b.len(),
            proof: proof_b.clone(),
            compensation_commitment: None,
        },
    );

    // External Merkle proofs cannot claim SingleBlockSynchronous atomicity.
    assert!(OutputComposer::compose_attested(
        &plan,
        AtomicityClass::SingleBlockSynchronous,
        &two_phase
    )
    .is_err());

    // FinalityBoundTwoPhase succeeds.
    let res_2pc =
        OutputComposer::compose_attested(&plan, AtomicityClass::FinalityBoundTwoPhase, &two_phase)
            .expect("two-phase external attestation passes");
    assert_eq!(res_2pc.atomicity, AtomicityClass::FinalityBoundTwoPhase);

    // CompensatingAsync rejects missing compensation_commitment.
    assert!(
        OutputComposer::compose_attested(&plan, AtomicityClass::CompensatingAsync, &two_phase)
            .is_err()
    );

    // With explicit non-zero compensation commitments, CompensatingAsync succeeds.
    let mut comp = BTreeMap::new();
    comp.insert(
        String::from("eth_step"),
        StepReceiptAttestation::ExternalDomainMerkle {
            domain_id: 10,
            finality_root: root_a,
            leaf_index: 0,
            leaf_count: leaves_a.len(),
            proof: proof_a,
            compensation_commitment: Some([0xaa; 32]),
        },
    );
    comp.insert(
        String::from("cosmos_step"),
        StepReceiptAttestation::ExternalDomainMerkle {
            domain_id: 20,
            finality_root: root_b,
            leaf_index: 1,
            leaf_count: leaves_b.len(),
            proof: proof_b,
            compensation_commitment: Some([0xbb; 32]),
        },
    );
    let res_async =
        OutputComposer::compose_attested(&plan, AtomicityClass::CompensatingAsync, &comp)
            .expect("compensating async passes");
    assert_eq!(res_async.atomicity, AtomicityClass::CompensatingAsync);
    assert_ne!(res_2pc.attestation_root, res_async.attestation_root);
}

#[test]
fn payment_status_report_enforces_three_tier_monotonicity_and_merchant_thresholds() {
    use crate::unification::payment_router::{
        DeliveredPaymentProof, FinalizedPaymentProof, GuaranteedPaymentProof,
        PaymentCompletionLevel, PaymentStatusReport,
    };

    let mut report = PaymentStatusReport {
        intent_id: [0x11; 32],
        guaranteed: Some(GuaranteedPaymentProof {
            block_height: 100,
            escrow_commitment: [0x22; 32],
            solver_bond_commitment: [0x33; 32],
        }),
        finalized: None,
        delivered: None,
    };
    report.validate().expect("guaranteed tier valid");
    assert_eq!(
        report.highest_level(),
        Some(PaymentCompletionLevel::Guaranteed)
    );
    assert!(report.meets_threshold(PaymentCompletionLevel::Guaranteed));
    assert!(!report.meets_threshold(PaymentCompletionLevel::Finalized));
    assert!(!report.meets_threshold(PaymentCompletionLevel::Delivered));

    // Skipping Finalized directly to Delivered must fail closed.
    let mut skipped = report.clone();
    skipped.delivered = Some(DeliveredPaymentProof {
        target_domain: 1,
        delivery_proof_root: [0x44; 32],
        merchant_receipt_hash: [0x55; 32],
    });
    assert!(skipped.validate().is_err());
    assert!(!skipped.meets_threshold(PaymentCompletionLevel::Guaranteed));

    report.finalized = Some(FinalizedPaymentProof {
        checkpoint_height: 105,
        finality_certificate_digest: [0x66; 32],
    });
    assert!(report.meets_threshold(PaymentCompletionLevel::Finalized));
    assert!(!report.meets_threshold(PaymentCompletionLevel::Delivered));

    report.delivered = Some(DeliveredPaymentProof {
        target_domain: 1,
        delivery_proof_root: [0x44; 32],
        merchant_receipt_hash: [0x55; 32],
    });
    report.validate().expect("all three tiers valid");
    assert!(report.meets_threshold(PaymentCompletionLevel::Delivered));
}

#[test]
fn preauthorized_spend_account_verifies_pq_hybrid_offline_vouchers_and_blocks_replay_or_overcap() {
    use crate::crypto::composite::CompositeKeypair;
    use crate::crypto::pq::ML_DSA_SEED_LEN;
    use crate::crypto::scheme::SuiteId;
    use crate::unification::payment_router::{
        PreauthorizedSpendAccount, SignedOfflineVoucher, OFFLINE_VOUCHER_CTX,
    };
    use std::collections::BTreeSet;

    let payer_kp =
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x31; ML_DSA_SEED_LEN], &[0x42; 32])
            .expect("composite keypair");
    let payer_pk = payer_kp.public_key().expect("public key").encode();

    let mut account = PreauthorizedSpendAccount {
        account_id: [0xaa; 32],
        payer_composite_pubkey: payer_pk,
        asset_id: [0xbb; 32],
        spend_cap_atoms: 1_000,
        spent_atoms: 0,
        valid_until_unix_secs: 2_000,
        used_nonces: BTreeSet::new(),
    };

    let sign_voucher = |nonce: u64, amount: u128| -> SignedOfflineVoucher {
        let mut v = SignedOfflineVoucher {
            account_id: account.account_id,
            voucher_nonce: nonce,
            merchant_id: [0xcc; 32],
            amount_atoms: amount,
            valid_until_unix_secs: 1_900,
            signature: Vec::new(),
        };
        let digest = v.signing_payload();
        let sig = payer_kp
            .sign(OFFLINE_VOUCHER_CTX, &digest, &[0x55; 32])
            .expect("sign voucher");
        v.signature = sig.encode();
        v
    };

    let v1 = sign_voucher(1, 400);
    let v2 = sign_voucher(2, 500);
    v1.verify_offline(&account, 1_500)
        .expect("offline verification succeeds without network");
    v2.verify_offline(&account, 1_500)
        .expect("second offline voucher verifies");

    // Tampered amount must invalidate the PQ-hybrid signature.
    let mut forged = v1.clone();
    forged.amount_atoms = 401;
    assert!(forged.verify_offline(&account, 1_500).is_err());

    // Batch exceeding spend_cap_atoms must fail atomically without mutating state.
    let v3_overcap = sign_voucher(3, 200);
    assert!(account
        .settle_voucher_batch(&[v1.clone(), v2.clone(), v3_overcap], 1_500)
        .is_err());
    assert_eq!(account.spent_atoms, 0);
    assert!(account.used_nonces.is_empty());

    // Valid batch settles atomically.
    let settled = account
        .settle_voucher_batch(&[v1.clone(), v2], 1_500)
        .expect("batch settles");
    assert_eq!(settled, 900);
    assert_eq!(account.spent_atoms, 900);

    // Replaying an already-settled voucher nonce fails closed.
    assert!(account.settle_voucher_batch(&[v1], 1_500).is_err());
}

#[test]
fn canonical_payment_request_uri_roundtrips_and_refund_registry_blocks_double_refund() {
    use crate::unification::payment_router::{
        universal_asset_id, RefundIntent, RefundRegistry, UniversalPaymentReceipt,
        UniversalPaymentRequestUri,
    };

    let req = UniversalPaymentRequestUri {
        version: 1,
        recipient: [0x12; 32],
        target_domain: 1,
        target_asset_id: universal_asset_id(1, b"USDC"),
        target_amount: 25_000_000,
        invoice_digest: [0x34; 32],
        deadline_unix_secs: 1_800_000_000,
        callback_ref: Some(String::from("pos-terminal-01")),
    };
    let encoded = req.encode_canonical().expect("encode canonical URI");
    let decoded = UniversalPaymentRequestUri::decode_canonical(&encoded).expect("decode URI");
    assert_eq!(req, decoded);
    assert_eq!(req.request_digest(), decoded.request_digest());

    // Non-canonical query ordering or unknown keys must fail closed.
    assert!(UniversalPaymentRequestUri::decode_canonical("budlum:pay/v2?amount=1").is_err());
    assert!(UniversalPaymentRequestUri::decode_canonical(&format!("{encoded}&evil=1")).is_err());

    let receipt = UniversalPaymentReceipt {
        intent_id: [0x55; 32],
        target_domain: 1,
        target_asset_id: universal_asset_id(1, b"USDC"),
        target_amount_delivered: 25_000_000,
        legs: Vec::new(),
        legs_merkle_root: [0x66; 32],
        pos_auth_code: Some(String::from("BDLM12345678")),
        receipt_hash: [0x77; 32],
    };
    let refund = RefundIntent {
        original_intent_id: receipt.intent_id,
        original_receipt_hash: receipt.receipt_hash,
        merchant_id: [0x12; 32],
        refund_recipient: [0x88; 32],
        refund_amount: 25_000_000,
        reason_code: 1,
    };

    let mut registry = RefundRegistry::default();
    let mut over_refund = refund.clone();
    over_refund.refund_amount = 25_000_001;
    assert!(registry.record_refund(&receipt, &over_refund).is_err());

    let rid = registry
        .record_refund(&receipt, &refund)
        .expect("first refund accepted");
    assert_eq!(rid, refund.refund_id());

    // Second refund against the same settled payment receipt must be rejected.
    assert!(registry.record_refund(&receipt, &refund).is_err());
}

#[test]
fn storage_fabric_verifies_external_domain_proofs_and_blocks_strength_inflation() {
    use crate::unification::storage_fabric::{
        build_storage_domain_commitment_root, build_storage_domain_inclusion_proof,
        storage_domain_commitment_leaf, StorageNetworkKind, StorageReplica, StorageReplicaProof,
        UnifiedContentRecord, UnifiedStorageFabric, VerificationStrength,
    };

    let payload = b"budlum-decentralized-web3-object-v1".to_vec();
    let record = UnifiedContentRecord::from_bytes(&payload, "application/octet-stream");
    let digest = record.sha3_256_digest;
    let sha256 = record.sha256_digest;

    let mut fabric = UnifiedStorageFabric::new();
    fabric.register_object(record).expect("register object");

    // 1. Arweave external domain Merkle proof verifies cleanly.
    let ar_locator = String::from("bNbA3TEQVL60xlgCcqdz4ZPHFZ711cZ3hmkpGttDt_U");
    let ar_domain = StorageNetworkKind::Arweave.default_domain_id();
    let ar_leaf = storage_domain_commitment_leaf(
        StorageNetworkKind::Arweave,
        ar_domain,
        &digest,
        &sha256,
        &ar_locator,
    );
    let leaves = [ar_leaf, [0x77; 32]];
    let ar_root = build_storage_domain_commitment_root(&leaves);
    let ar_proof = build_storage_domain_inclusion_proof(&leaves, 0).expect("arweave proof");

    let ar_replica = StorageReplica {
        network: StorageNetworkKind::Arweave,
        domain_id: ar_domain,
        native_locator: ar_locator,
        verification: VerificationStrength::MerkleRoot,
        available: true,
        latency_ms: 30,
    };
    fabric
        .verify_and_attach_replica(
            &digest,
            ar_replica.clone(),
            &StorageReplicaProof::ExternalDomainMerkle {
                domain_id: ar_domain,
                finalized_state_root: ar_root,
                leaf_index: 0,
                leaf_count: leaves.len(),
                proof: ar_proof.clone(),
            },
        )
        .expect("verified Arweave Merkle replica accepted");

    // Tampered root must fail closed.
    let mut bad_root = ar_root;
    bad_root[0] ^= 0xff;
    assert!(fabric
        .verify_and_attach_replica(
            &digest,
            ar_replica,
            &StorageReplicaProof::ExternalDomainMerkle {
                domain_id: ar_domain,
                finalized_state_root: bad_root,
                leaf_index: 0,
                leaf_count: leaves.len(),
                proof: ar_proof,
            },
        )
        .is_err());

    // 2. Storj cannot claim on-chain ExternalDomainMerkle or inflate above AttestedDeal.
    assert!(!StorageNetworkKind::Storj.supports_domain_state_proof());
    assert!(!StorageNetworkKind::Ipfs.supports_domain_state_proof());
    assert!(StorageNetworkKind::Filecoin.supports_domain_state_proof());
    assert!(StorageNetworkKind::Walrus.supports_domain_state_proof());

    let storj_inflated = StorageReplica {
        network: StorageNetworkKind::Storj,
        domain_id: StorageNetworkKind::Storj.default_domain_id(),
        native_locator: String::from("bucket-01-object-abc"),
        verification: VerificationStrength::MerkleRoot,
        available: true,
        latency_ms: 45,
    };
    assert!(fabric
        .verify_and_attach_replica(
            &digest,
            storj_inflated,
            &StorageReplicaProof::DeclaredDealOnly {
                deal_commitment: [0x22; 32],
            },
        )
        .is_err());

    // 3. IPFS preimage verification accepts exact payload and rejects tampered bytes.
    let ipfs_replica = StorageReplica {
        network: StorageNetworkKind::Ipfs,
        domain_id: StorageNetworkKind::Ipfs.default_domain_id(),
        native_locator: String::from("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"),
        verification: VerificationStrength::CryptographicHash,
        available: true,
        latency_ms: 20,
    };
    assert!(fabric
        .verify_and_attach_replica(
            &digest,
            ipfs_replica.clone(),
            &StorageReplicaProof::ContentHashPreimage {
                payload: b"wrong-bytes".to_vec(),
            },
        )
        .is_err());
    fabric
        .verify_and_attach_replica(
            &digest,
            ipfs_replica,
            &StorageReplicaProof::ContentHashPreimage { payload },
        )
        .expect("exact IPFS payload preimage accepted");

    // 4. B.U.D. 3.0 custody proof yields ErasureVerified and rejects non-Bud3 networks.
    let bud3_replica = StorageReplica {
        network: StorageNetworkKind::Bud3,
        domain_id: StorageNetworkKind::Bud3.default_domain_id(),
        native_locator: String::from("chunk-manifest-0001"),
        verification: VerificationStrength::ErasureVerified,
        available: true,
        latency_ms: 10,
    };
    fabric
        .verify_and_attach_replica(
            &digest,
            bud3_replica,
            &StorageReplicaProof::Bud3Custody {
                data_shards: 4,
                parity_shards: 2,
                custody_merkle_root: [0x99; 32],
            },
        )
        .expect("valid B.U.D. 3.0 custody proof accepted");
}

#[test]
fn oracle_free_proof_carrying_liquidation_enforces_state_root_proofs_close_factor_and_multi_domain_legs(
) {
    use crate::settlement::liquidation_proof::{
        build_reserve_inclusion_proof, build_reserve_state_root,
        execute_proven_cross_domain_liquidation, prove_position_health, reserve_observation_leaf,
        AmmReserveSnapshot, CollateralLegSpec, CrossDomainLiquidationParams, LiquidationPosition,
        ProvenReserveObservation, LIQ_BONUS_MAX_BPS,
    };
    use std::collections::BTreeMap;

    let amm_domain = 10u32;
    let debt_domain = 1u32;
    let mut certified_roots = BTreeMap::new();
    let mut observations = Vec::new();

    // Three monotonically ascending epochs with AMM reserve price Y/X = 2.0
    for (epoch, rx, ry) in [
        (10u64, 1_000u128, 2_000u128),
        (11, 1_000, 2_000),
        (12, 1_000, 2_000),
    ] {
        let leaf = reserve_observation_leaf(amm_domain, epoch, rx, ry);
        let leaves = [leaf, [u8::try_from(epoch).unwrap_or(1); 32]];
        let root = build_reserve_state_root(&leaves);
        let proof = build_reserve_inclusion_proof(&leaves, 0).expect("reserve proof");
        certified_roots.insert((amm_domain, epoch), root);
        observations.push(ProvenReserveObservation {
            domain_id: amm_domain,
            snapshot: AmmReserveSnapshot {
                state_root: root,
                epoch,
                reserve_x: rx,
                reserve_y: ry,
                proof,
            },
            leaf_index: 0,
            leaf_count: leaves.len(),
        });
    }

    // Debt=1_000 X (worth 2_000 Y at price 2.0), Collateral=2_500 Y -> health = 12_500 bps (< 15_000 threshold).
    let unhealthy = LiquidationPosition {
        position_id: 7,
        debt_x: 1_000,
        collateral_y: 2_500,
        maintenance_threshold_bps: 15_000,
    };
    let health = prove_position_health(&unhealthy, debt_domain, &certified_roots, &observations)
        .expect("proof-carrying health succeeds");
    assert!(health.liquidatable);
    assert_eq!(health.health_bps, 12_500);
    assert_ne!(health.health_proof_digest, [0u8; 32]);

    // Forged AMM reserve snapshot fails Merkle proof verification fail-closed.
    let mut forged_obs = observations.clone();
    if let Some(first) = forged_obs.first_mut() {
        first.snapshot.reserve_y = 9_999;
    }
    assert!(
        prove_position_health(&unhealthy, debt_domain, &certified_roots, &forged_obs).is_err(),
        "forged AMM reserve must fail state-root Merkle proof"
    );

    // Collateral spread across domains B (20) and C (30).
    let legs = vec![
        CollateralLegSpec {
            domain_id: 30,
            asset_id: [0x30; 32],
            custody_or_remote_root: [0xaa; 32],
            available_y: 1_500,
        },
        CollateralLegSpec {
            domain_id: 20,
            asset_id: [0x20; 32],
            custody_or_remote_root: [0xbb; 32],
            available_y: 1_000,
        },
    ];

    // Exceeding close factor (>50% of 1_000 = 500) or bonus cap (>1500 bps) fails closed.
    assert!(execute_proven_cross_domain_liquidation(
        &unhealthy,
        &certified_roots,
        &observations,
        &legs,
        &CrossDomainLiquidationParams {
            debt_domain_id: debt_domain,
            repay_debt_x: 501,
            bonus_bps: 500,
            delivery_proof_root: [0xdd; 32],
        },
    )
    .is_err());
    assert!(execute_proven_cross_domain_liquidation(
        &unhealthy,
        &certified_roots,
        &observations,
        &legs,
        &CrossDomainLiquidationParams {
            debt_domain_id: debt_domain,
            repay_debt_x: 500,
            bonus_bps: LIQ_BONUS_MAX_BPS + 1,
            delivery_proof_root: [0xdd; 32],
        },
    )
    .is_err());
    // Missing delivery proof root fails closed.
    assert!(execute_proven_cross_domain_liquidation(
        &unhealthy,
        &certified_roots,
        &observations,
        &legs,
        &CrossDomainLiquidationParams {
            debt_domain_id: debt_domain,
            repay_debt_x: 500,
            bonus_bps: 500,
            delivery_proof_root: [0u8; 32],
        },
    )
    .is_err());

    // Valid partial liquidation (500 X repaid @ price 2.0 + 5% bonus = 1_050 Y seized across domain 20 then 30).
    let res = execute_proven_cross_domain_liquidation(
        &unhealthy,
        &certified_roots,
        &observations,
        &legs,
        &CrossDomainLiquidationParams {
            debt_domain_id: debt_domain,
            repay_debt_x: 500,
            bonus_bps: 500,
            delivery_proof_root: [0xdd; 32],
        },
    )
    .expect("valid cross-domain partial liquidation");
    assert_eq!(res.debt_repaid_x, 500);
    assert_eq!(res.seized_legs.len(), 2);
    let total_seized: u128 = res.seized_legs.iter().map(|l| l.seized_y).sum();
    assert_eq!(total_seized, 1_050);

    // Healthy position (collateral 4_000 Y -> health 20_000 bps > 15_000 bps) must be refused.
    let healthy = LiquidationPosition {
        position_id: 8,
        debt_x: 1_000,
        collateral_y: 4_000,
        maintenance_threshold_bps: 15_000,
    };
    let healthy_legs = vec![CollateralLegSpec {
        domain_id: 20,
        asset_id: [0x20; 32],
        custody_or_remote_root: [0xbb; 32],
        available_y: 4_000,
    }];
    assert!(execute_proven_cross_domain_liquidation(
        &healthy,
        &certified_roots,
        &observations,
        &healthy_legs,
        &CrossDomainLiquidationParams {
            debt_domain_id: debt_domain,
            repay_debt_x: 200,
            bonus_bps: 500,
            delivery_proof_root: [0xdd; 32],
        },
    )
    .is_err());
}

#[test]
fn identity_profile_linked_account_requires_ownership_signature_or_external_domain_proof() {
    use crate::core::address::Address;
    use crate::crypto::composite::CompositeKeypair;
    use crate::crypto::pq::ML_DSA_SEED_LEN;
    use crate::crypto::scheme::SuiteId;
    use crate::wallet::identity_profile::{
        build_external_attestation_proof, build_external_attestation_root,
        evaluate_linked_account_evidence, external_attestation_leaf, AccountOwnershipProof,
        EvidenceStatus, LinkedAccountClaim, IDENTITY_ADDR_LINK_CTX,
    };

    let kp =
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x61; ML_DSA_SEED_LEN], &[0x72; 32])
            .expect("keypair");
    let pk = kp.public_key().expect("pk");
    let owned_addr = Address::from(pk.ed);

    let claim = LinkedAccountClaim {
        subject_name: String::from("alice.bud"),
        target_domain: 1,
        account_label: String::from("budlum-main"),
        linked_address_bytes: owned_addr.as_bytes().to_vec(),
    };

    // 1. Unproven text record is NEVER Verified.
    let raw_card =
        evaluate_linked_account_evidence(&claim, &AccountOwnershipProof::UnprovenTextRecord);
    assert_eq!(raw_card.status, EvidenceStatus::Unverified);
    raw_card.validate().expect("unverified card validates");

    // 2. Valid PQ-hybrid signature from the address owner yields Verified.
    let digest = claim.binding_digest();
    let sig = kp
        .sign(IDENTITY_ADDR_LINK_CTX, &digest, &[0x88; 32])
        .expect("sign");
    let verified_card = evaluate_linked_account_evidence(
        &claim,
        &AccountOwnershipProof::BudlumCompositeSignature {
            composite_pubkey: pk.encode(),
            signature: sig.encode(),
        },
    );
    assert_eq!(verified_card.status, EvidenceStatus::Verified);
    verified_card.validate().expect("verified card validates");

    // Wrong subject_name invalidates the ownership proof fail-closed.
    let mut stolen_claim = claim.clone();
    stolen_claim.subject_name = String::from("mallory.bud");
    let rejected_card = evaluate_linked_account_evidence(
        &stolen_claim,
        &AccountOwnershipProof::BudlumCompositeSignature {
            composite_pubkey: pk.encode(),
            signature: sig.encode(),
        },
    );
    assert_eq!(rejected_card.status, EvidenceStatus::Unverified);

    // 3. External-domain attestation verified via finalized Merkle inclusion proof.
    let eth_claim = LinkedAccountClaim {
        subject_name: String::from("alice.bud"),
        target_domain: 10,
        account_label: String::from("eth-eas"),
        linked_address_bytes: vec![0xab; 20],
    };
    let att_digest = [0xee; 32];
    let leaf = external_attestation_leaf(&eth_claim, &att_digest);
    let leaves = [leaf, [0x44; 32]];
    let root = build_external_attestation_root(&leaves);
    let proof = build_external_attestation_proof(&leaves, 0).expect("attestation proof");

    let ext_card = evaluate_linked_account_evidence(
        &eth_claim,
        &AccountOwnershipProof::ExternalDomainAttestation {
            domain_id: 10,
            finalized_state_root: root,
            attestation_digest: att_digest,
            leaf_index: 0,
            leaf_count: leaves.len(),
            proof: proof.clone(),
        },
    );
    assert_eq!(ext_card.status, EvidenceStatus::Verified);
    ext_card
        .validate()
        .expect("external verified card validates");

    let mut bad_root = root;
    bad_root[0] ^= 0xff;
    let bad_ext = evaluate_linked_account_evidence(
        &eth_claim,
        &AccountOwnershipProof::ExternalDomainAttestation {
            domain_id: 10,
            finalized_state_root: bad_root,
            attestation_digest: att_digest,
            leaf_index: 0,
            leaf_count: leaves.len(),
            proof,
        },
    );
    assert_eq!(bad_ext.status, EvidenceStatus::Unverified);
}

#[test]
fn ens_proof_resolver_and_multichain_bud_address_bindings_verify_without_rpc_trust() {
    use crate::core::address::Address;
    use crate::cross_domain::evm::mpt;
    use crate::cross_domain::evm::rlp::{self, Item};
    use crate::crypto::composite::CompositeKeypair;
    use crate::crypto::pq::ML_DSA_SEED_LEN;
    use crate::crypto::scheme::SuiteId;
    use crate::unification::name_resolver::{
        ens_mapping_slot, ens_namehash, ens_registry_resolver_slot,
        multichain_address_binding_digest, verify_ens_resolution, AddressSignaturePosture,
        EnsResolutionProof, MultiChainAddressProof, MultiChainNameRecord, MULTICHAIN_ADDR_BIND_CTX,
    };

    // 1. Official EIP-137 vector for "eth"
    let eth_node = ens_namehash("eth").expect("eth namehash");
    assert_eq!(
        hex::encode(eth_node),
        "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
    );
    assert!(ens_namehash("").is_err());
    assert!(ens_namehash("ALICE.eth").is_err());
    assert!(ens_namehash("a..eth").is_err());

    let name = "alice.eth";
    let node = ens_namehash(name).expect("alice.eth namehash");

    // Pick two Ethereum contract addresses whose keccak256 account keys start with
    // distinct first nibbles so they sit cleanly under a 17-item Yellow Paper branch root.
    let registry_addr = [0x11u8; 20];
    let reg_key = mpt::keccak256(&registry_addr);
    let reg_nibbles = mpt::to_nibbles(&reg_key);
    let reg_first = reg_nibbles.first().copied().expect("reg first nibble");

    let mut resolver_addr = [0x22u8; 20];
    for candidate in 1u8..=255 {
        let addr = [candidate; 20];
        let k = mpt::keccak256(&addr);
        let nibs = mpt::to_nibbles(&k);
        if nibs.first().copied() != Some(reg_first) && addr != registry_addr {
            resolver_addr = addr;
            break;
        }
    }
    let res_key = mpt::keccak256(&resolver_addr);
    let res_nibbles = mpt::to_nibbles(&res_key);
    let res_first = res_nibbles.first().copied().expect("res first nibble");
    assert_ne!(reg_first, res_first);

    let target_eth_addr = [0xab_u8; 20];
    let trim_leading_zeros = |bytes: &[u8]| -> Vec<u8> {
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        bytes.get(start..).unwrap_or(&[]).to_vec()
    };

    // Build ENS Registry storage trie: records[node].resolver = resolver_addr
    let resolver_slot = ens_registry_resolver_slot(&node, 0);
    let resolver_slot_key = mpt::keccak256(&resolver_slot);
    let resolver_slot_leaf = rlp::encode(&Item::List(vec![
        Item::String(mpt::hp_encode(&mpt::to_nibbles(&resolver_slot_key), true)),
        Item::String(rlp::encode(&Item::String(trim_leading_zeros(
            &resolver_addr,
        )))),
    ]));
    let registry_storage_root = mpt::keccak256(&resolver_slot_leaf);

    // Build Resolver storage trie: addr[node] = target_eth_addr
    let addr_slot = ens_mapping_slot(&node, 0);
    let addr_slot_key = mpt::keccak256(&addr_slot);
    let addr_slot_leaf = rlp::encode(&Item::List(vec![
        Item::String(mpt::hp_encode(&mpt::to_nibbles(&addr_slot_key), true)),
        Item::String(rlp::encode(&Item::String(trim_leading_zeros(
            &target_eth_addr,
        )))),
    ]));
    let resolver_storage_root = mpt::keccak256(&addr_slot_leaf);

    let encode_account = |storage_root: [u8; 32], code_tag: u8| -> Vec<u8> {
        rlp::encode(&Item::List(vec![
            Item::String(rlp::encode_uint_bytes(1)),
            Item::String(Vec::new()),
            Item::String(storage_root.to_vec()),
            Item::String(mpt::keccak256(&[code_tag]).to_vec()),
        ]))
    };

    let reg_leaf = rlp::encode(&Item::List(vec![
        Item::String(mpt::hp_encode(
            reg_nibbles.get(1..).expect("reg suffix"),
            true,
        )),
        Item::String(encode_account(registry_storage_root, 1)),
    ]));
    let res_leaf = rlp::encode(&Item::List(vec![
        Item::String(mpt::hp_encode(
            res_nibbles.get(1..).expect("res suffix"),
            true,
        )),
        Item::String(encode_account(resolver_storage_root, 2)),
    ]));
    let reg_leaf_hash = mpt::keccak256(&reg_leaf);
    let res_leaf_hash = mpt::keccak256(&res_leaf);

    let mut branch_items = vec![Item::String(Vec::new()); 17];
    if let Some(slot) = branch_items.get_mut(usize::from(reg_first)) {
        *slot = Item::String(reg_leaf_hash.to_vec());
    }
    if let Some(slot) = branch_items.get_mut(usize::from(res_first)) {
        *slot = Item::String(res_leaf_hash.to_vec());
    }
    let branch_node = rlp::encode(&Item::List(branch_items));
    let finalized_eth_state_root = mpt::keccak256(&branch_node);

    let ens_proof = EnsResolutionProof {
        name: String::from(name),
        registry_address: registry_addr,
        records_mapping_slot: 0,
        resolver_addr_mapping_slot: 0,
        registry_account_proof: vec![branch_node.clone(), reg_leaf],
        resolver_slot_proof: vec![resolver_slot_leaf],
        resolver_account_proof: vec![branch_node, res_leaf],
        addr_slot_proof: vec![addr_slot_leaf],
    };

    let verified =
        verify_ens_resolution(&finalized_eth_state_root, &ens_proof).expect("ENS proof verifies");
    assert_eq!(verified.node, node);
    assert_eq!(verified.resolver_address, resolver_addr);
    assert_eq!(verified.resolved_address, target_eth_addr);

    // Tampered state root fails closed.
    let mut bad_root = finalized_eth_state_root;
    bad_root[0] ^= 0x01;
    assert!(verify_ens_resolution(&bad_root, &ens_proof).is_err());

    // 2. Multi-chain `.bud` record binds both PQ-hybrid Budlum address and Classical ENS address.
    let mut record = MultiChainNameRecord::new(String::from("alice.bud")).expect("valid bud name");
    let kp =
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x81; ML_DSA_SEED_LEN], &[0x92; 32])
            .expect("composite keypair");
    let pk = kp.public_key().expect("pk");
    let bud_addr = Address::from(pk.ed);
    let digest = multichain_address_binding_digest("alice.bud", 1, bud_addr.as_bytes());
    let sig = kp
        .sign(MULTICHAIN_ADDR_BIND_CTX, &digest, &[0x77; 32])
        .expect("sign");

    let pq_binding = record
        .bind_verified_address(
            1,
            bud_addr.as_bytes().to_vec(),
            &MultiChainAddressProof::BudlumComposite {
                composite_pubkey: pk.encode(),
                signature: sig.encode(),
            },
        )
        .expect("PQ address binding succeeds");
    assert_eq!(
        pq_binding.posture,
        AddressSignaturePosture::PostQuantumHybrid
    );

    // Attempting to bind an unowned Budlum address fails closed.
    assert!(record
        .bind_verified_address(
            1,
            vec![0xff; 32],
            &MultiChainAddressProof::BudlumComposite {
                composite_pubkey: pk.encode(),
                signature: sig.encode(),
            },
        )
        .is_err());

    // Binding the verified ENS address succeeds and is explicitly labelled ClassicalExternal.
    let eth_binding = record
        .bind_verified_address(
            10,
            target_eth_addr.to_vec(),
            &MultiChainAddressProof::ExternalEnsProof {
                finalized_eth_state_root,
                proof: Box::new(ens_proof),
            },
        )
        .expect("ENS classical binding succeeds");
    assert_eq!(
        eth_binding.posture,
        AddressSignaturePosture::ClassicalExternal
    );
}

#[test]
fn evm_migration_deployment_roots_bind_to_finalized_beacon_and_header_anchors() {
    use crate::execution::coordinator::migration::{
        begin_import_attested, verify_deployment_anchor, verify_deployment_attested,
        DeploymentHeaderAnchor, DeploymentProof, DeploymentProofError, MigrationAuthorization,
        MigrationRequest,
    };
    use sha2::{Digest, Sha256};

    fn sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(left);
        h.update(right);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn build_ssz_tree_and_branch(
        leaves: &[[u8; 32]],
        leaf_idx: usize,
    ) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut level = leaves.to_vec();
        let mut idx = leaf_idx;
        let mut branch = Vec::new();
        while level.len() > 1 {
            let sibling_idx = idx ^ 1;
            if let Some(sib) = level.get(sibling_idx).copied() {
                branch.push(sib);
            }
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                if let (Some(l), Some(r)) = (pair.first(), pair.get(1)) {
                    next.push(sha256_pair(l, r));
                }
            }
            level = next;
            idx /= 2;
        }
        let root = level.first().copied().unwrap_or([0u8; 32]);
        (root, branch)
    }

    let deployment_block: u64 = 19_420_000;
    let tx_root = [0x11u8; 32];
    let rc_root = [0x22u8; 32];
    let mut block_num_chunk = [0u8; 32];
    {
        let (low, _) = block_num_chunk.split_at_mut(8);
        low.copy_from_slice(&deployment_block.to_le_bytes());
    }

    // Build 32-leaf ExecutionPayloadHeader tree (depth 5):
    // leaf 3 = receipts_root (gindex 803), leaf 6 = block_number (gindex 806),
    // leaf 13 = transactions_root (gindex 813).
    let mut payload_leaves = vec![[0u8; 32]; 32];
    if let Some(slot) = payload_leaves.get_mut(3) {
        *slot = rc_root;
    }
    if let Some(slot) = payload_leaves.get_mut(6) {
        *slot = block_num_chunk;
    }
    if let Some(slot) = payload_leaves.get_mut(13) {
        *slot = tx_root;
    }
    let (payload_root, mut rc_branch) = build_ssz_tree_and_branch(&payload_leaves, 3);
    let (_, mut bn_branch) = build_ssz_tree_and_branch(&payload_leaves, 6);
    let (_, mut tx_branch) = build_ssz_tree_and_branch(&payload_leaves, 13);

    // Embed ExecutionPayloadHeader at BeaconBlockBody leaf 9 (gindex 25 = 16 + 9, depth 4).
    let mut body_leaves = vec![[0u8; 32]; 16];
    if let Some(slot) = body_leaves.get_mut(9) {
        *slot = payload_root;
    }
    let (beacon_body_root, body_branch) = build_ssz_tree_and_branch(&body_leaves, 9);
    rc_branch.extend_from_slice(&body_branch);
    bn_branch.extend_from_slice(&body_branch);
    tx_branch.extend_from_slice(&body_branch);

    let proof = DeploymentProof {
        deployment_block,
        transaction_index: 0,
        transaction: vec![0x02, 0xc0],
        transaction_proof: vec![],
        transactions_root: tx_root,
        receipt_proof: vec![],
        receipts_root: rc_root,
    };

    let beacon_anchor = DeploymentHeaderAnchor::BeaconBodyBranches {
        beacon_body_root,
        block_number_branch: bn_branch,
        transactions_root_branch: tx_branch,
        receipts_root_branch: rc_branch,
    };
    verify_deployment_anchor(&proof, &beacon_anchor).expect(
        "finalized Beacon SSZ branches must anchor block, transactions_root, and receipts_root",
    );

    // Tampered transactions_root fails closed against the finalized Beacon body root.
    let mut forged_tx_root = proof.clone();
    forged_tx_root.transactions_root = [0x99u8; 32];
    assert!(matches!(
        verify_deployment_anchor(&forged_tx_root, &beacon_anchor),
        Err(DeploymentProofError::BeaconFieldBranchFailed(_))
    ));

    // Tampered receipts_root fails closed.
    let mut forged_rc_root = proof.clone();
    forged_rc_root.receipts_root = [0x88u8; 32];
    assert!(matches!(
        verify_deployment_anchor(&forged_rc_root, &beacon_anchor),
        Err(DeploymentProofError::BeaconFieldBranchFailed(_))
    ));

    // AttestedRoots rejects mismatched or zero roots.
    let attested_anchor = DeploymentHeaderAnchor::AttestedRoots {
        attested_block: deployment_block,
        transactions_root: tx_root,
        receipts_root: rc_root,
    };
    verify_deployment_anchor(&proof, &attested_anchor).expect("matching attested roots pass");
    assert!(matches!(
        verify_deployment_attested(&forged_tx_root, 1, &attested_anchor),
        Err(DeploymentProofError::TransactionsRootMismatch)
    ));
    let mut zero_root_proof = proof.clone();
    zero_root_proof.transactions_root = [0u8; 32];
    assert!(matches!(
        verify_deployment_anchor(&zero_root_proof, &attested_anchor),
        Err(DeploymentProofError::ZeroRoot)
    ));

    // begin_import_attested refuses an unanchored forged transactions_root before processing.
    let forged_req = MigrationRequest {
        source_domain: "ethereum".to_string(),
        source_chain_id: 1,
        source_block: deployment_block + 10,
        state_root: [0x33u8; 32],
        deployment: forged_tx_root,
        authorization: MigrationAuthorization {
            contract: [0x44u8; 20],
            budlum_chain_id: 7777,
            source_block: deployment_block + 10,
            state_root: [0x33u8; 32],
            code_hash: [0x55u8; 32],
            signature: vec![0u8; 65],
        },
        account_proof: vec![],
        code: vec![0x60, 0x00],
        occupied: false,
    };
    assert!(begin_import_attested(forged_req, 7777, &attested_anchor).is_err());
}

#[test]
fn account_abstraction_fee_sponsorship_session_caps_and_timelocked_recovery() {
    use crate::account_abstraction::{
        recovery_approval_digest, recovery_cancel_digest, session_spend_digest,
        AccountAbstractionError, FeeSponsorAuthorization, FeeSponsorRegistry, FeeSponsorTerms,
        GuardianRecoveryApproval, SessionDelegation, SessionDelegationParams,
        SessionDelegationRegistry, SessionKeyPosture, SessionSpendRequest, SocialRecoveryPolicy,
        TimelockedRecoveryRegistry, MAX_CLASSICAL_HARDWARE_SESSION_CAP,
        RECOVERY_APPROVAL_DOMAIN_TAG, RECOVERY_CANCEL_DOMAIN_TAG, SESSION_SPEND_DOMAIN_TAG,
    };
    use crate::core::address::Address;
    use crate::crypto::composite::CompositeKeypair;
    use crate::crypto::ml_dsa::ML_DSA_SEED_LEN;
    use crate::crypto::suites::SuiteId;

    let sponsor_kp =
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x31; ML_DSA_SEED_LEN], &[0x32; 32])
            .expect("sponsor keypair");
    let sender = Address::from([0x41; 32]);
    let tx_hash = [0x51; 32];
    let other_tx_hash = [0x52; 32];

    // 1. Gasless fee sponsorship: bound to exact tx_hash & chain_id, single-use.
    let grant = FeeSponsorAuthorization::sign(
        &sponsor_kp,
        FeeSponsorTerms {
            chain_id: 7777,
            tx_hash,
            sender,
            max_fee_bud: 5_000,
            expiry_epoch: 100,
            sponsor_nonce: 1,
        },
        &[0x11; 32],
    )
    .expect("fee sponsor sign");

    let mut sponsor_reg = FeeSponsorRegistry::default();
    // Transplanting sponsor signature onto a different tx_hash fails closed.
    assert_eq!(
        sponsor_reg.consume(&grant, 7777, &other_tx_hash, 1_000, 50),
        Err(AccountAbstractionError::TxHashMismatch)
    );
    // Fee exceeding sponsored max fails closed.
    assert_eq!(
        sponsor_reg.consume(&grant, 7777, &tx_hash, 5_001, 50),
        Err(AccountAbstractionError::FeeExceedsSponsoredCap {
            actual: 5_001,
            max: 5_000
        })
    );
    let grant_id = sponsor_reg
        .consume(&grant, 7777, &tx_hash, 1_200, 50)
        .expect("valid sponsor grant consumed");
    assert!(sponsor_reg.is_consumed(&grant_id));
    assert_eq!(
        sponsor_reg.consume(&grant, 7777, &tx_hash, 1_200, 50),
        Err(AccountAbstractionError::SponsorAuthorizationAlreadyConsumed)
    );

    // 2. Bounded session delegation (PQ session + hardware-capped classical guard).
    let master_kp =
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x61; ML_DSA_SEED_LEN], &[0x63; 32])
            .expect("master keypair");
    let session_kp =
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x62; ML_DSA_SEED_LEN], &[0x64; 32])
            .expect("session keypair");
    let master_pk_bytes = master_kp.public_key().expect("master pk").encode();
    let session_pk_bytes = session_kp.public_key().expect("session pk").encode();
    let merchant = Address::from([0x71; 32]);
    let stranger = Address::from([0x72; 32]);

    // Unbounded classical hardware session exceeding MAX_CLASSICAL_HARDWARE_SESSION_CAP fails closed.
    assert!(matches!(
        SessionDelegation::sign(
            &master_kp,
            SessionDelegationParams {
                chain_id: 7777,
                session_key: SessionKeyPosture::HardwareClassicalCapped {
                    evm_address: [0xaa; 20],
                },
                total_spend_cap: MAX_CLASSICAL_HARDWARE_SESSION_CAP + 1,
                per_tx_cap: 1_000,
                allowed_recipients: vec![merchant],
                not_before_epoch: 10,
                expiry_epoch: 20,
                delegation_nonce: 1,
            },
            &[0x12; 32],
        ),
        Err(AccountAbstractionError::ClassicalHardwareCapExceeded { .. })
    ));

    let delegation = SessionDelegation::sign(
        &master_kp,
        SessionDelegationParams {
            chain_id: 7777,
            session_key: SessionKeyPosture::PostQuantumComposite {
                composite_pubkey: session_pk_bytes,
            },
            total_spend_cap: 1_000,
            per_tx_cap: 600,
            allowed_recipients: vec![merchant],
            not_before_epoch: 10,
            expiry_epoch: 20,
            delegation_nonce: 2,
        },
        &[0x13; 32],
    )
    .expect("session delegation");

    let mut session_reg = SessionDelegationRegistry::default();
    let del_id = session_reg
        .register(delegation, 7777)
        .expect("register session");

    let spend1 = SessionSpendRequest {
        delegation_id: del_id,
        chain_id: 7777,
        recipient: merchant,
        amount: 600,
        spend_nonce: 1,
        current_epoch: 15,
    };
    let sig1 = session_kp
        .sign(
            SESSION_SPEND_DOMAIN_TAG,
            &session_spend_digest(&del_id, 7777, &merchant, 600, 1),
            &[0x14; 32],
        )
        .expect("sign spend1")
        .encode();
    assert_eq!(session_reg.authorize_spend(&spend1, &sig1), Ok(400));
    // Disallowed recipient rejected.
    let bad_recip = SessionSpendRequest {
        recipient: stranger,
        spend_nonce: 2,
        amount: 100,
        ..spend1.clone()
    };
    assert_eq!(
        session_reg.authorize_spend(&bad_recip, &sig1),
        Err(AccountAbstractionError::RecipientNotAllowed)
    );
    // Exceeding remaining cap (400) rejected.
    let over_cap = SessionSpendRequest {
        amount: 401,
        spend_nonce: 3,
        ..spend1.clone()
    };
    assert_eq!(
        session_reg.authorize_spend(&over_cap, &sig1),
        Err(AccountAbstractionError::AmountExceedsRemainingCap {
            amount: 401,
            remaining: 400
        })
    );
    // Expired epoch rejected.
    let expired = SessionSpendRequest {
        current_epoch: 21,
        amount: 100,
        spend_nonce: 4,
        ..spend1
    };
    assert!(matches!(
        session_reg.authorize_spend(&expired, &sig1),
        Err(AccountAbstractionError::SessionNotActive { .. })
    ));
    session_reg.revoke(&del_id).expect("revoke session");

    // 3. Timelocked, owner-cancellable social recovery (zero admin backdoor).
    let g1 =
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x81; ML_DSA_SEED_LEN], &[0x91; 32])
            .expect("g1");
    let g2 =
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x82; ML_DSA_SEED_LEN], &[0x92; 32])
            .expect("g2");
    let new_owner =
        CompositeKeypair::from_seeds(SuiteId::VALIDATOR, &[0x83; ML_DSA_SEED_LEN], &[0x93; 32])
            .expect("new owner");
    let g1_pk = g1.public_key().expect("g1 pk").encode();
    let g2_pk = g2.public_key().expect("g2 pk").encode();
    let new_owner_pk = new_owner.public_key().expect("new owner pk").encode();
    let policy = SocialRecoveryPolicy {
        chain_id: 7777,
        current_owner_pubkey: master_pk_bytes,
        guardians: vec![g1_pk.clone(), g2_pk.clone()],
        threshold: 2,
        delay_epochs: 5,
    };
    let rec_digest = recovery_approval_digest(7777, &policy.current_owner_pubkey, &new_owner_pk, 1);
    let approvals = vec![
        GuardianRecoveryApproval {
            guardian_pubkey: g1_pk.clone(),
            signature: g1
                .sign(RECOVERY_APPROVAL_DOMAIN_TAG, &rec_digest, &[0x21; 32])
                .expect("g1 sign")
                .encode(),
        },
        GuardianRecoveryApproval {
            guardian_pubkey: g2_pk.clone(),
            signature: g2
                .sign(RECOVERY_APPROVAL_DOMAIN_TAG, &rec_digest, &[0x22; 32])
                .expect("g2 sign")
                .encode(),
        },
    ];
    let mut rec_reg = TimelockedRecoveryRegistry::default();
    let rec_id = rec_reg
        .initiate(policy.clone(), new_owner_pk.clone(), 1, &approvals, 100)
        .expect("initiate recovery");
    // Finalizing before timelock window expires fails closed.
    assert!(matches!(
        rec_reg.finalize(&rec_id, 104),
        Err(AccountAbstractionError::RecoveryWindowStillOpen { .. })
    ));
    // Owner cancels inside the window; subsequent finalization fails permanently.
    let cancel_sig = master_kp
        .sign(
            RECOVERY_CANCEL_DOMAIN_TAG,
            &recovery_cancel_digest(&rec_id, 7777),
            &[0x23; 32],
        )
        .expect("cancel sign")
        .encode();
    rec_reg
        .cancel_by_owner(&rec_id, &cancel_sig)
        .expect("owner cancels");
    assert_eq!(
        rec_reg.finalize(&rec_id, 200),
        Err(AccountAbstractionError::RecoveryCancelled)
    );

    // Second recovery (nonce 2) uncancelled activates cleanly after window.
    let rec2_digest =
        recovery_approval_digest(7777, &policy.current_owner_pubkey, &new_owner_pk, 2);
    let approvals2 = vec![
        GuardianRecoveryApproval {
            guardian_pubkey: g1_pk,
            signature: g1
                .sign(RECOVERY_APPROVAL_DOMAIN_TAG, &rec2_digest, &[0x24; 32])
                .expect("g1 sign2")
                .encode(),
        },
        GuardianRecoveryApproval {
            guardian_pubkey: g2_pk,
            signature: g2
                .sign(RECOVERY_APPROVAL_DOMAIN_TAG, &rec2_digest, &[0x25; 32])
                .expect("g2 sign2")
                .encode(),
        },
    ];
    let rec2_id = rec_reg
        .initiate(policy, new_owner_pk.clone(), 2, &approvals2, 300)
        .expect("initiate recovery 2");
    let activated = rec_reg
        .finalize(&rec2_id, 305)
        .expect("finalize after timelock");
    assert_eq!(activated, new_owner_pk);
}
