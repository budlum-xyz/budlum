use budlum_core::aggregation::backend::{AggBackend, TickCtx};
use budlum_core::aggregation::domain_finality::{
    compile_domain_transition, derive_transition_state_root, domain_transition_claim,
    prove_domain_transition, ClaimedDomainFinalityAdapter,
};
use budlum_core::aggregation::frame::FrameLimits;
use budlum_core::aggregation::object::derive_claim;
use budlum_core::aggregation::params::AggParams;
use budlum_core::aggregation::pool::PoolItem;
use budlum_core::aggregation::programs::prog_claim::{verify_vm_proof, StarkProofObject};
use budlum_core::aggregation::stark::{StarkBackend, STARK_PARAMETER_SET};
use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::cross_domain::external::IntakeState;
use budlum_core::crypto::facts::QuantumClass;
use budlum_core::crypto::scheme::SchemeStatusRegistry;
use budlum_core::domain::finality_adapter::{hash_finality_proof, FinalityProof};
use budlum_core::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, RootScheme,
};
use budlum_core::domain::VerifiedDomainCommitment;
use budlum_core::settlement::domains::{execute_settlement_tx, SettlementTx, SettlementTxContext};
use budlum_core::settlement::universal_finality::{
    FinalityBucket, FinalityReversibility, FinalityVerdict,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

fn some<T>(opt: Option<T>, msg: &str) -> T {
    match opt {
        Some(v) => v,
        None => panic!("{msg}"),
    }
}

fn zk_claimed_domain(
    domain_id: u32,
    domain_chain_id: u64,
    program_hash: [u8; 32],
    prev_hash: [u8; 32],
) -> ConsensusDomain {
    ConsensusDomain {
        id: domain_id,
        kind: ConsensusKind::Zk,
        status: DomainStatus::Active,
        domain_chain_id,
        operator: Some(Address::from([0x10; 32])),
        operator_bond: budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND,
        config_hash: [0xA1; 32],
        validator_set_hash: [0xB1; 32],
        finality_adapter: "agg-claimed-program-finality".into(),
        min_confirmations: 1,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height: 10,
        last_committed_hash: prev_hash,
        pow_parameters: None,
        zk_program_allowlist: vec![program_hash],
        plugin_code_hash: None,
        genesis_state_root: [0x01; 32],
    }
}

#[test]
fn k2e_claimed_domain_finality_certifies_proven_row_only_with_verified_claim_prog_and_builds_ulp_proof(
) {
    let claim_domain = 45_262u32;
    let chain_id = 45_262u64;
    let domain_id = 77u32;
    let ext_chain_id = 42_161u64;
    let prev_height = 10u64;
    let prev_state_root = [0x11; 32];
    let prev_block_hash = [0x10; 32];
    let batch_digest = [0x55; 32];

    // 1. Compile the canonical BudVM domain-transition program and prove a real
    //    state-transition STARK (`ObjectKind::StarkProof` -> `Claim::Prog`).
    let compiled = must(
        compile_domain_transition(domain_id, ext_chain_id),
        "compile domain transition",
    );
    let program_hash = compiled.program_hash;
    let domain = zk_claimed_domain(domain_id, ext_chain_id, program_hash, prev_block_hash);

    let derived_root = derive_transition_state_root(
        domain_id,
        ext_chain_id,
        prev_height,
        11,
        &prev_state_root,
        &batch_digest,
    );
    let mut commitment = DomainCommitment {
        domain_id,
        domain_height: 11,
        domain_block_hash: [0x12; 32],
        parent_domain_block_hash: prev_block_hash,
        state_root: derived_root,
        tx_root: [0x31; 32],
        event_root: [0x32; 32],
        finality_proof_hash: [0u8; 32],
        consensus_kind: ConsensusKind::Zk,
        validator_set_hash: [0xB1; 32],
        timestamp_ms: 1_700_000_000_000,
        sequence: 1,
        producer: None,
        state_updates: BTreeMap::new(),
    };

    let stark_obj = must(
        prove_domain_transition(
            &compiled,
            &domain,
            prev_height,
            &prev_state_root,
            &commitment,
            &batch_digest,
            claim_domain,
        ),
        "real BudVM/Plonky3 domain-transition STARK proves",
    );
    let encoded = must(stark_obj.encode(), "encode StarkProofObject");
    let decoded = must(
        StarkProofObject::decode(&encoded),
        "decode StarkProofObject",
    );
    let expected_claim = domain_transition_claim(
        program_hash,
        &domain,
        prev_height,
        &prev_state_root,
        &commitment,
    );
    assert_eq!(
        verify_vm_proof(claim_domain, &decoded),
        Ok(expected_claim.clone())
    );

    let registry = SchemeStatusRegistry::genesis();
    let params = AggParams::default();
    let backend = StarkBackend::new(
        registry.clone(),
        FrameLimits::from(&params),
        STARK_PARAMETER_SET,
    );
    let env = must(stark_obj.to_envelope(claim_domain, [0xEE; 32]), "envelope");
    let claim = must(derive_claim(&registry, &env), "derive_claim");
    assert_eq!(claim, expected_claim);
    let claim_digest = claim.digest(claim_domain);

    let tick_ctx = must(
        TickCtx::from_seed(claim_domain, Zeroizing::new([0xB1; 32])),
        "tick ctx",
    );
    let frame = must(
        backend.prove_tick(
            &tick_ctx,
            &[PoolItem {
                envelope: env,
                claim,
            }],
        ),
        "prove real MasterProof tick",
    );

    let proof = FinalityProof::AggregatedProg {
        program_hash,
        prev_height,
        prev_state_root,
        claim_digest,
    };
    commitment.finality_proof_hash = must(hash_finality_proof(&proof), "hash proof");

    // 2. Setup live AccountState with bonded relayer, bonded segment aggregator, and domain.
    let mut state = AccountState::new();
    let relayer = Address::from([0x22; 32]);
    must(
        state
            .registry
            .register_relayer(relayer, budlum_core::registry::MIN_REGISTRATION_STAKE, 0),
        "register relayer",
    );
    let agg_floor = budlum_core::core::chain_config::Network::Devnet
        .min_stake()
        .max(state.registry.params().min_stake);
    for seg in &frame.segments {
        state.add_validator_with_floor(seg.aggregator, agg_floor, agg_floor);
    }
    must(
        state.settlement.domains.restore_persisted(domain),
        "register domain",
    );
    state.settlement.claimed_domain_finality = ClaimedDomainFinalityAdapter::new(claim_domain);
    state
        .settlement
        .claimed_domain_finality
        .register_domain_program(domain_id, program_hash);
    state
        .settlement
        .claimed_domain_finality
        .record_finalized_tip(domain_id, prev_height, prev_state_root);

    // 3. T-E.2 NEGATIVE: Before Claim::Prog is admitted in a verified MasterProof,
    //    SettlementTx::SubmitCommitment MUST fail closed and the certificate
    //    cannot mark the row CryptographicValidity ("proven").
    let ctx = SettlementTxContext {
        sender: relayer,
        chain_id,
        fee: 0,
        bls: IntakeState::production_bls,
    };
    let submit_tx = SettlementTx::SubmitCommitment(Box::new(VerifiedDomainCommitment {
        commitment: commitment.clone(),
        proof,
    }));
    assert!(
        execute_settlement_tx(&mut state, &ctx, &submit_tx).is_err(),
        "AggregatedProg without admitted MasterProof Claim::Prog must fail closed"
    );

    let uncertified_cert = some(
        state.settlement.universal_finality_certificate(100),
        "certificate builds",
    );
    let uncertified_row = some(uncertified_cert.prove_domain(domain_id), "row present");
    assert_ne!(
        uncertified_row.entry.guarantee.reversibility,
        FinalityReversibility::CryptographicValidity,
        "row without verified Claim::Prog must NOT be labeled CryptographicValidity"
    );

    // 4. Admit the real StarkBackend MasterProof into SettlementRegistries, then
    //    finalize the commitment via live SettlementTx::SubmitCommitment.
    let state_snapshot = state.clone();
    let added = must(
        state
            .settlement
            .claimed_domain_finality
            .admit_verified_frame(&state_snapshot, &backend, &frame),
        "verified MasterProof admits Claim::Prog",
    );
    assert_eq!(added, 1);

    let root_before = state.settlement.root();
    must(
        execute_settlement_tx(&mut state, &ctx, &submit_tx),
        "live SettlementTx::SubmitCommitment finalizes ZK domain via MasterProof Claim::Prog",
    );
    assert_ne!(state.settlement.root(), root_before);
    assert!(state
        .settlement
        .claimed_domain_finality
        .has_certified_claim(domain_id, 11, derived_root));

    // 5. T-E.1 + T-E.2 + T-E.6: Compose Universal Finality Certificate, verify
    //    integrity, confirm the row is Established + CryptographicValidity +
    //    QuantumClass::Hash ("proven"), and verify its ULP-1 inclusion proof.
    let cert = some(
        state.settlement.universal_finality_certificate(100),
        "certificate builds",
    );
    assert_eq!(cert.verify_integrity(), Ok(()));
    assert_eq!(cert.established_count, 1);

    let row_proof = some(cert.prove_domain(domain_id), "ULP-1 row proof");
    assert_eq!(row_proof.bucket, FinalityBucket::Established);
    assert_eq!(row_proof.entry.verdict, FinalityVerdict::Established);
    assert_eq!(
        row_proof.entry.guarantee.reversibility,
        FinalityReversibility::CryptographicValidity
    );
    assert_eq!(
        row_proof.entry.guarantee.quantum_posture,
        QuantumClass::Hash
    );
    assert!(row_proof.verify(&cert.established_root));
}
