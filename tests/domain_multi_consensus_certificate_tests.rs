//! End-to-end heterogeneous multi-consensus domain settlement, global finality
//! certificate verification, and `ULP-1` recursive STARK light-proof tests.
//!
//! Exercises five fundamentally distinct consensus families (`PoW`, `BFT`, `DAG`,
//! `PoH`, and `PoSpace`) through signed in-block settlement door execution,
//! checkpoint `GlobalFinalityCertificate` Merkle inclusion verification, unified
//! `ULP-1` 128-bit Plonky3 STARK light-client proof generation/opening, and
//! adversarial mutation + economic outflow conservation checks.

use budlum_core::aggregation::universal_light_proof::{
    compile_ulp_program, open_universal_light_proof, open_universal_light_proof_with_snapshots,
    prove_ulp_domain_inclusion, prove_universal_light_proof, ulp_expected_settlement_epoch,
    UlpDomainKind, UlpDomainSnapshot,
};
use budlum_core::chain::finality::{
    pop_signing_message, sign_bls_pop, ValidatorEntry, ValidatorSetSnapshot,
};
use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::cross_domain::external::IntakeState;
use budlum_core::crypto::composite::{CompositeError, CompositeKeypair};
use budlum_core::crypto::facts::{ObservedScheme, QuantumClass};
use budlum_core::crypto::pq::{ml_dsa_public_key, ML_DSA_SEED_LEN};
use budlum_core::crypto::primitives::{BlsKeypair, PqKeyPair};
use budlum_core::crypto::scheme::{SchemeId, SchemeStatusRegistry, SuiteId};
use budlum_core::domain::finality_adapter::{poa_pq_authority_set_hash, PoAAuthorityKey};
use budlum_core::domain::producer::{
    build_bft_commitment, build_dag_commitment, build_poh_commitment, build_pospace_commitment,
    build_pow_commitment, mine_pospace_block_hash, BftMember, PowBlockContent, PowChainSpec,
    QuorumBlockSpec,
};
use budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND;
use budlum_core::domain::{
    default_domain, ConsensusDomain, ConsensusKind, DomainId, FinalityProof, PoWDomainParameters,
    POW_HEADER_CHAIN_ADAPTER,
};
use budlum_core::registry::role::roles::RELAYER;
use budlum_core::settlement::domains::{
    execute_settlement_tx, SettlementTx, SettlementTxContext, SettlementTxError,
};
use budlum_core::settlement::universal_finality::{
    compose, compose_cross_domain_route, DomainFinalityEntry, EconomicSecurityBound,
    FinalityGuarantee, FinalityPendingReason, FinalityReversibility, FinalityVerdict,
    FINALITY_BINDS_ALL,
};

const HUB_CHAIN_ID: u64 = 45_262;
const HUB_DOMAIN_ID: DomainId = 45_262;
const FEE_ATOMS: u64 = 1_000;
const CHECKPOINT_HEIGHT: u64 = 100;

fn tx_ctx(sender: Address) -> SettlementTxContext {
    SettlementTxContext {
        sender,
        chain_id: HUB_CHAIN_ID,
        fee: FEE_ATOMS,
        bls: IntakeState::production_bls,
    }
}

fn composite_authorities(
    count: u8,
) -> Result<(Vec<CompositeKeypair>, Vec<PoAAuthorityKey>), CompositeError> {
    let keypairs = (0..count)
        .map(|i| {
            CompositeKeypair::from_seeds(
                SuiteId::VALIDATOR,
                &[i + 0x31; ML_DSA_SEED_LEN],
                &[i + 0x71; 32],
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let authorities = keypairs
        .iter()
        .map(|kp| {
            let public = kp.public_key()?;
            Ok(PoAAuthorityKey {
                authority: Address::from(public.ed),
                public_key: public.encode(),
            })
        })
        .collect::<Result<Vec<_>, CompositeError>>()?;
    Ok((keypairs, authorities))
}

fn register_funded_domain(
    state: &mut AccountState,
    operator: Address,
    mut domain: ConsensusDomain,
) -> Result<(), SettlementTxError> {
    domain.operator = Some(operator);
    domain.operator_bond = MIN_DOMAIN_OPERATOR_BOND.max(100_000);
    domain.last_committed_height = 0;
    domain.last_committed_hash = [0u8; 32];
    execute_settlement_tx(
        state,
        &tx_ctx(operator),
        &SettlementTx::RegisterDomain(Box::new(domain)),
    )
}

#[test]
fn five_consensus_families_settle_into_one_certificate_and_ulp_stark_bundle() {
    let mut state = AccountState::default();
    state.current_block_height = CHECKPOINT_HEIGHT;

    let operator = Address::from([0xA1; 32]);
    let relayer = Address::from([0xB2; 32]);
    state.get_or_create(&operator).balance = 50_000_000_000;
    state.get_or_create(&relayer).balance = 50_000_000_000;
    let min_relayer_stake = state.registry.params().min_stake.max(10_000);
    state
        .registry
        .register(relayer, RELAYER, min_relayer_stake, 0)
        .unwrap();

    // 1. Domain 101: Nakamoto PoW header chain (`pow-header-chain`)
    let mut pow_domain =
        default_domain(101, ConsensusKind::PoW, 9_101, POW_HEADER_CHAIN_ADAPTER, 2);
    pow_domain.operator = Some(operator);
    pow_domain.operator_bond = MIN_DOMAIN_OPERATOR_BOND.max(100_000);
    pow_domain.config_hash = [0x11; 32];
    pow_domain.pow_parameters = Some(PoWDomainParameters {
        min_difficulty_bits: 1,
        max_difficulty_bits: 16,
        min_cumulative_work: 4,
        max_headers: 8,
    });
    register_funded_domain(&mut state, operator, pow_domain).unwrap();
    let pow_registered = state.settlement.domains.get(101).unwrap().clone();
    let pow_built = build_pow_commitment(&PowChainSpec {
        domain: pow_registered.clone(),
        parent_hash: [0u8; 32],
        height: 1,
        difficulty_bits: 1,
        sequence: 0,
        producer: Some(operator),
        blocks: vec![
            PowBlockContent {
                timestamp_ms: 1_700_000_001_000,
                state_root: [0x21; 32],
                tx_root: [0x22; 32],
                event_root: [0x23; 32],
            },
            PowBlockContent {
                timestamp_ms: 1_700_000_002_000,
                state_root: [0x24; 32],
                tx_root: [0x25; 32],
                event_root: [0x26; 32],
            },
        ],
    })
    .unwrap();

    // 2. Domain 102: Hybrid BLS12-381 + ML-DSA-65 BFT quorum (`bft-quorum-commit`)
    let bft_chain_id = 9_102u64;
    let bft_members: Vec<BftMember> = (0..4u8)
        .map(|i| {
            let bls = BlsKeypair::from_seed(&[i + 0x10; 64]).unwrap();
            let pq_seed = [i + 0x50; ML_DSA_SEED_LEN];
            let pq_pub = ml_dsa_public_key(SchemeId::ML_DSA_65, &pq_seed).unwrap();
            let pq = PqKeyPair::from_bytes(&pq_pub, &pq_seed).unwrap();
            let address = Address::from([i + 0x80; 32]);
            let pop = sign_bls_pop(
                &bls.secret_key,
                &pop_signing_message(bft_chain_id, &address, &bls.public_key),
            );
            let entry = ValidatorEntry {
                address,
                stake: 100,
                bls_public_key: bls.public_key.clone(),
                pop_signature: pop,
                pq_public_key: pq_pub,
            };
            BftMember {
                entry,
                bls,
                pq: Some(pq),
            }
        })
        .collect();
    let bft_snapshot =
        ValidatorSetSnapshot::new(1, bft_members.iter().map(|m| m.entry.clone()).collect());
    let bft_vset_hash: [u8; 32] = hex::decode(&bft_snapshot.set_hash)
        .unwrap()
        .try_into()
        .unwrap();
    let mut bft_domain = default_domain(
        102,
        ConsensusKind::Bft,
        bft_chain_id,
        "bft-quorum-commit",
        1,
    );
    bft_domain.validator_set_hash = bft_vset_hash;
    bft_domain.config_hash = [0x12; 32];
    register_funded_domain(&mut state, operator, bft_domain).unwrap();
    let bft_registered = state.settlement.domains.get(102).unwrap().clone();
    let bft_built = build_bft_commitment(
        &QuorumBlockSpec {
            domain: bft_registered.clone(),
            parent_hash: [0u8; 32],
            block_hash: [0x31; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_003_000,
            producer: Some(operator),
            state_root: [0x32; 32],
            tx_root: [0x33; 32],
            event_root: [0x34; 32],
        },
        bft_chain_id,
        1,
        0,
        &bft_members,
        &[0, 1, 2],
    )
    .unwrap();

    // Shared composite authority pool for DAG, PoH, and PoSpace structural families
    let (comp_keys, comp_authorities) = composite_authorities(4).unwrap();

    // 3. Domain 103: Post-quantum causal DAG (`dag-tip-vote-v1`)
    let mut dag_domain = default_domain(103, ConsensusKind::Dag, 9_103, "dag-tip-vote-v1", 1);
    dag_domain.config_hash = [0x13; 32];
    dag_domain.validator_set_hash =
        poa_pq_authority_set_hash(&dag_domain, &comp_authorities).unwrap();
    register_funded_domain(&mut state, operator, dag_domain).unwrap();
    let dag_registered = state.settlement.domains.get(103).unwrap().clone();
    let dag_built = build_dag_commitment(
        &QuorumBlockSpec {
            domain: dag_registered.clone(),
            parent_hash: [0u8; 32],
            block_hash: [0x41; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_004_000,
            producer: Some(comp_authorities[0].authority),
            state_root: [0x42; 32],
            tx_root: [0x43; 32],
            event_root: [0x44; 32],
        },
        7,
        &comp_authorities,
        &comp_keys[..3],
    )
    .unwrap();

    // 4. Domain 104: Post-quantum sequential PoH ladder (`poh-hash-chain-v1`)
    let mut poh_domain = default_domain(104, ConsensusKind::Poh, 9_104, "poh-hash-chain-v1", 1);
    poh_domain.config_hash = [0x14; 32];
    poh_domain.validator_set_hash =
        poa_pq_authority_set_hash(&poh_domain, &comp_authorities).unwrap();
    register_funded_domain(&mut state, operator, poh_domain).unwrap();
    let poh_registered = state.settlement.domains.get(104).unwrap().clone();
    let poh_built = build_poh_commitment(
        &QuorumBlockSpec {
            domain: poh_registered.clone(),
            parent_hash: [0u8; 32],
            block_hash: [0x51; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_005_000,
            producer: Some(comp_authorities[0].authority),
            state_root: [0x52; 32],
            tx_root: [0x53; 32],
            event_root: [0x54; 32],
        },
        [0x50; 32],
        16,
        &comp_authorities,
        &comp_keys[..3],
    )
    .unwrap();

    // 5. Domain 105: Post-quantum PoSpace plot quality + quorum (`pospace-plot-v1`)
    let mut pospace_domain =
        default_domain(105, ConsensusKind::Pospace, 9_105, "pospace-plot-v1", 1);
    pospace_domain.config_hash = [0x15; 32];
    pospace_domain.validator_set_hash =
        poa_pq_authority_set_hash(&pospace_domain, &comp_authorities).unwrap();
    register_funded_domain(&mut state, operator, pospace_domain).unwrap();
    let pospace_registered = state.settlement.domains.get(105).unwrap().clone();
    let mut pospace_spec = QuorumBlockSpec {
        domain: pospace_registered.clone(),
        parent_hash: [0u8; 32],
        block_hash: [0x61; 32],
        height: 1,
        sequence: 0,
        timestamp_ms: 1_700_000_006_000,
        producer: Some(comp_authorities[0].authority),
        state_root: [0x62; 32],
        tx_root: [0x63; 32],
        event_root: [0x64; 32],
    };
    mine_pospace_block_hash(&mut pospace_spec, &comp_authorities[0].authority).unwrap();
    let pospace_built =
        build_pospace_commitment(&pospace_spec, 0, &comp_authorities, &comp_keys[..3]).unwrap();

    // Adversarial pre-submission check: mutating 1 bit in each structural family's
    // proof must be rejected fail-closed by `execute_settlement_tx` without mutating
    // `state.settlement.root()`.
    let root_before_adversarial = state.settlement.root();

    let mut forged_dag = dag_built.clone();
    if let FinalityProof::DagPq { ref mut round, .. } = forged_dag.proof {
        *round = round.saturating_add(1);
    }
    assert!(execute_settlement_tx(
        &mut state,
        &tx_ctx(relayer),
        &SettlementTx::SubmitCommitment(Box::new(forged_dag)),
    )
    .is_err());
    assert_eq!(state.settlement.root(), root_before_adversarial);

    let mut forged_poh = poh_built.clone();
    if let FinalityProof::PohPq { ref mut chain, .. } = forged_poh.proof {
        chain[1][0] ^= 0x01;
    }
    assert!(execute_settlement_tx(
        &mut state,
        &tx_ctx(relayer),
        &SettlementTx::SubmitCommitment(Box::new(forged_poh)),
    )
    .is_err());
    assert_eq!(state.settlement.root(), root_before_adversarial);

    let mut forged_pospace = pospace_built.clone();
    if let FinalityProof::PospacePq {
        ref mut plot_id, ..
    } = forged_pospace.proof
    {
        plot_id[0] ^= 0x01;
    }
    assert!(execute_settlement_tx(
        &mut state,
        &tx_ctx(relayer),
        &SettlementTx::SubmitCommitment(Box::new(forged_pospace)),
    )
    .is_err());
    assert_eq!(state.settlement.root(), root_before_adversarial);

    // Submit all 5 valid commitments through the in-block settlement door.
    for verified in [
        pow_built.clone(),
        bft_built.clone(),
        dag_built.clone(),
        poh_built.clone(),
        pospace_built.clone(),
    ] {
        execute_settlement_tx(
            &mut state,
            &tx_ctx(relayer),
            &SettlementTx::SubmitCommitment(Box::new(verified)),
        )
        .unwrap();
    }

    for id in 101u32..=105 {
        let dom = state.settlement.domains.get(id).unwrap();
        assert_eq!(
            dom.last_committed_height, 1,
            "domain {id} must advance to height 1"
        );
        assert_ne!(dom.last_committed_hash, [0u8; 32]);
    }
    assert_eq!(state.settlement.domains.observed(101).quantum_class(), None);
    for id in 102u32..=105 {
        let facts = state.settlement.domains.observed(id);
        assert!(
            facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)) > 0,
            "domain {id} must record verified ML-DSA-65 post-quantum signatures"
        );
        // Conjunctive hybrid `BLS12-381 + ML-DSA-65` and `Ed25519 + ML-DSA-65`
        // require breaking both halves simultaneously, so `quantum_class()` is
        // `Lattice` while individual primitive counts remain observable.
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Lattice));
    }

    // State-derived GlobalFinalityCertificate covers all 5 registered domains under
    // one canonical Keccak-256 certificate_digest with verifiable Merkle inclusion.
    let state_cert = state
        .settlement
        .universal_finality_certificate(CHECKPOINT_HEIGHT)
        .expect("five active domains produce a checkpoint certificate");
    state_cert.verify_integrity().unwrap();
    assert_eq!(
        state
            .settlement
            .finality_certificate_root(CHECKPOINT_HEIGHT),
        Some(state_cert.certificate_digest)
    );
    let total_rows =
        state_cert.established.len() + state_cert.pending.len() + state_cert.refuted.len();
    assert_eq!(total_rows, 5);
    for id in 101u32..=105 {
        let proof = state_cert
            .prove_domain(id)
            .unwrap_or_else(|| panic!("domain {id} missing from GlobalFinalityCertificate"));
        let bucket_root = state_cert.bucket_root(proof.bucket);
        assert!(
            proof.verify(&bucket_root),
            "domain {id} Merkle inclusion proof must verify against its bucket root"
        );
    }

    // Proof-level composition (`FinalityGuarantee::for_proof`): structural DagPq,
    // PohPq, PospacePq, and PoW header-chain all satisfy FINALITY_BINDS_ALL -> Established,
    // while block-hash-only BftPq remains honestly classified as AttestationUnbound.
    let proof_pairs = [
        (101u32, &pow_registered, &pow_built),
        (102u32, &bft_registered, &bft_built),
        (103u32, &dag_registered, &dag_built),
        (104u32, &poh_registered, &poh_built),
        (105u32, &pospace_registered, &pospace_built),
    ];
    let mut proof_entries = Vec::with_capacity(proof_pairs.len());
    for (id, dom, verified) in proof_pairs {
        let guarantee = FinalityGuarantee::for_proof(dom, &verified.proof, true);
        let verdict =
            if guarantee.attestation == FINALITY_BINDS_ALL && guarantee.fault_tolerance_bps > 0 {
                FinalityVerdict::Established
            } else {
                FinalityVerdict::Pending {
                    reason: FinalityPendingReason::AttestationUnbound,
                }
            };
        let backing_hash = if dom.validator_set_hash != [0u8; 32] {
            dom.validator_set_hash
        } else {
            dom.config_hash
        };
        proof_entries.push(DomainFinalityEntry {
            domain_id: id,
            height: verified.commitment.domain_height,
            checkpoint_height: CHECKPOINT_HEIGHT,
            state_root: verified.commitment.state_root,
            adapter_id: dom.finality_adapter.clone(),
            adapter_version: 1,
            finality_proof_hash: verified.commitment.finality_proof_hash,
            guarantee_backing_hash: backing_hash,
            bond_atoms: u128::from(dom.operator_bond),
            guarantee,
            verdict,
        });
    }
    let proof_cert = compose(&proof_entries).unwrap();
    proof_cert.verify_integrity().unwrap();
    assert_eq!(
        proof_cert
            .established
            .iter()
            .map(|e| e.domain_id)
            .collect::<Vec<_>>(),
        vec![101, 103, 104, 105]
    );
    assert_eq!(
        proof_cert
            .pending
            .iter()
            .map(|e| e.domain_id)
            .collect::<Vec<_>>(),
        vec![102]
    );

    // Unified ULP-1 128-bit Plonky3 STARK light-client proof over all 5 families:
    // BitcoinSpv (101), TendermintBft (102), DagBft (103), SimplexBft (104), PoSpaceVdf (105).
    let hub_ulp_root = state
        .settlement
        .ulp_domains_root()
        .expect("five committed domains produce a canonical ULP Poseidon root");
    let snapshots = [
        UlpDomainSnapshot {
            domain_id: 101,
            external_chain_id: pow_registered.domain_chain_id,
            kind: UlpDomainKind::BitcoinSpv,
            prev_height: 0,
            finalized_height: 1,
            state_root: pow_built.commitment.state_root,
            event_root: pow_built.commitment.event_root,
            anchor_hash: pow_registered.config_hash,
            security_weight: pow_registered.operator_bond,
            pq_attested: false,
            outflow_bps: 0,
        },
        UlpDomainSnapshot {
            domain_id: 102,
            external_chain_id: bft_registered.domain_chain_id,
            kind: UlpDomainKind::TendermintBft,
            prev_height: 0,
            finalized_height: 1,
            state_root: bft_built.commitment.state_root,
            event_root: bft_built.commitment.event_root,
            anchor_hash: bft_registered.validator_set_hash,
            security_weight: bft_registered.operator_bond,
            pq_attested: true,
            outflow_bps: 0,
        },
        UlpDomainSnapshot {
            domain_id: 103,
            external_chain_id: dag_registered.domain_chain_id,
            kind: UlpDomainKind::DagBft,
            prev_height: 0,
            finalized_height: 1,
            state_root: dag_built.commitment.state_root,
            event_root: dag_built.commitment.event_root,
            anchor_hash: dag_registered.validator_set_hash,
            security_weight: dag_registered.operator_bond,
            pq_attested: true,
            outflow_bps: 0,
        },
        UlpDomainSnapshot {
            domain_id: 104,
            external_chain_id: poh_registered.domain_chain_id,
            kind: UlpDomainKind::SimplexBft,
            prev_height: 0,
            finalized_height: 1,
            state_root: poh_built.commitment.state_root,
            event_root: poh_built.commitment.event_root,
            anchor_hash: poh_registered.validator_set_hash,
            security_weight: poh_registered.operator_bond,
            pq_attested: true,
            outflow_bps: 0,
        },
        UlpDomainSnapshot {
            domain_id: 105,
            external_chain_id: pospace_registered.domain_chain_id,
            kind: UlpDomainKind::PoSpaceVdf,
            prev_height: 0,
            finalized_height: 1,
            state_root: pospace_built.commitment.state_root,
            event_root: pospace_built.commitment.event_root,
            anchor_hash: pospace_registered.validator_set_hash,
            security_weight: pospace_registered.operator_bond,
            pq_attested: true,
            outflow_bps: 0,
        },
    ];

    let program = compile_ulp_program(HUB_DOMAIN_ID, snapshots.len()).unwrap();
    let settlement_epoch = ulp_expected_settlement_epoch(HUB_CHAIN_ID, CHECKPOINT_HEIGHT);
    let hub_checkpoint_root = state_cert.certificate_digest;
    let aggregator_seed = [0x77; 32];
    let registry = SchemeStatusRegistry::genesis();

    let (bundle, sorted_snapshots, metrics) = prove_universal_light_proof(
        &program,
        settlement_epoch,
        hub_checkpoint_root,
        &snapshots,
        &aggregator_seed,
        1,
        &registry,
    )
    .unwrap();

    assert_eq!(bundle.domains_merkle_root, hub_ulp_root);
    assert_eq!(bundle.domain_count, 5);
    assert_eq!(
        sorted_snapshots.iter().filter(|s| s.pq_attested).count(),
        4,
        "all four hybrid PQ quorum domains (102..=105) carry pq_attested=true while signatureless PoW (101) remains false"
    );
    assert!(!bundle.all_pq_attested);
    assert!(metrics.master_frame_bytes > 0);
    assert!(metrics.verify_stark_tx_bytes > 0);

    let verified_with_snapshots = open_universal_light_proof_with_snapshots(
        &bundle,
        &program.program_hash,
        HUB_DOMAIN_ID,
        &hub_checkpoint_root,
        settlement_epoch,
        &snapshots,
        &registry,
    )
    .unwrap();
    let verified_succinct = open_universal_light_proof(
        &bundle,
        &program.program_hash,
        HUB_DOMAIN_ID,
        &hub_checkpoint_root,
        settlement_epoch,
        &registry,
    )
    .unwrap();
    assert_eq!(verified_with_snapshots, verified_succinct);
    assert_eq!(verified_succinct.domains_merkle_root, hub_ulp_root);

    for snap in &sorted_snapshots {
        let inclusion = prove_ulp_domain_inclusion(&sorted_snapshots, snap.domain_id).unwrap();
        inclusion
            .verify(snap, &verified_succinct.domains_merkle_root)
            .unwrap();
    }

    // Adversarial ULP-1 tamper check: mutating 1 bit of the checkpoint anchor or
    // Merkle root must fail closed during STARK bundle verification.
    let mut wrong_anchor = hub_checkpoint_root;
    wrong_anchor[0] ^= 0x80;
    assert!(open_universal_light_proof(
        &bundle,
        &program.program_hash,
        HUB_DOMAIN_ID,
        &wrong_anchor,
        settlement_epoch,
        &registry,
    )
    .is_err());

    let mut tampered_bundle = bundle.clone();
    tampered_bundle.domains_merkle_root[0] ^= 0x01;
    assert!(open_universal_light_proof(
        &tampered_bundle,
        &program.program_hash,
        HUB_DOMAIN_ID,
        &hub_checkpoint_root,
        settlement_epoch,
        &registry,
    )
    .is_err());

    // Economic security & weakest-link route composition across heterogeneous families.
    let pow_guarantee = FinalityGuarantee::for_proof(&pow_registered, &pow_built.proof, true);
    let dag_guarantee = FinalityGuarantee::for_proof(&dag_registered, &dag_built.proof, true);
    let hub_guarantee = FinalityGuarantee::settlement_hub();

    let route = compose_cross_domain_route(&pow_guarantee, &hub_guarantee, &dag_guarantee);
    assert!(matches!(
        route.bottleneck_reversibility,
        FinalityReversibility::ProbabilisticWork { confirmations: 2 }
    ));
    assert_eq!(route.bottleneck_quantum_posture, QuantumClass::Lattice);
    assert!(!route.end_to_end_slashable);
    assert!(!route.source_admits_value_transfer);

    let pow_econ = EconomicSecurityBound::derive(&pow_guarantee, 1_000_000, 500_000);
    assert_eq!(pow_econ.corruption_cost_atoms, 0);
    assert_eq!(pow_econ.safe_value_outflow_ceiling_atoms, 0);
    assert!(pow_econ.check_value_outflow_conservation(0, 1).is_err());

    let hub_econ = EconomicSecurityBound::derive(&hub_guarantee, 1_000_000, 500_000);
    assert_eq!(hub_econ.corruption_cost_atoms, 333_300);
    assert_eq!(hub_econ.safe_value_outflow_ceiling_atoms, 333_300);
    assert_eq!(
        hub_econ
            .check_value_outflow_conservation(100_000, 200_000)
            .unwrap(),
        300_000
    );
    assert!(hub_econ
        .check_value_outflow_conservation(200_000, 200_000)
        .is_err());

    let state_cert_bytes = bincode::serialize(&state_cert).unwrap().len();
    let proof_cert_bytes = bincode::serialize(&proof_cert).unwrap().len();
    eprintln!(
        "MEASURED_MULTI_CONSENSUS: state_cert_bytes={state_cert_bytes} proof_cert_bytes={proof_cert_bytes} stark_object_bytes={} pcs_object_bytes={} verify_stark_tx_bytes={} master_frame_bytes={} vm_trace_steps={} prove_ms={}",
        metrics.stark_object_bytes,
        metrics.pcs_object_bytes,
        metrics.verify_stark_tx_bytes,
        metrics.master_frame_bytes,
        metrics.vm_trace_steps,
        metrics.prove_ms,
    );
}
