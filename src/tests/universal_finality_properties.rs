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
            expected_value: Some(CanonicalValue::U128(500)),
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
