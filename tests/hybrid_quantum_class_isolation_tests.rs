//! End-to-end regression suite for post-quantum hybrid finality classification,
//! Frost Alarm (`Isolate` / `Zemheri`) survival of `ML-DSA-65` hybrid domains,
//! `ULP-1` `pq_attested` preservation, and fail-closed downgrade when any
//! classical-only proof enters a domain's history.

use budlum_core::chain::finality::{
    pop_signing_message, sign_bls_pop, ValidatorEntry, ValidatorSetSnapshot,
};
use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::cross_domain::external::IntakeState;
use budlum_core::crypto::composite::CompositeKeypair;
use budlum_core::crypto::facts::{CryptoFacts, ObservedScheme, QuantumClass};
use budlum_core::crypto::pq::{ml_dsa_public_key, ML_DSA_SEED_LEN};
use budlum_core::crypto::primitives::{BlsKeypair, PqKeyPair};
use budlum_core::crypto::scheme::{SchemeId, SuiteId};
use budlum_core::domain::finality_adapter::{poa_pq_authority_set_hash, PoAAuthorityKey};
use budlum_core::domain::producer::{
    build_bft_commitment, build_dag_commitment, build_poa_commitment, build_poh_commitment,
    build_pospace_commitment, build_pow_commitment, mine_pospace_block_hash, BftMember,
    PowBlockContent, PowChainSpec, QuorumBlockSpec,
};
use budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND;
use budlum_core::domain::{
    default_domain, ConsensusDomain, ConsensusKind, DomainStatus, FinalityProof,
    PoWDomainParameters, POW_HEADER_CHAIN_ADAPTER,
};
use budlum_core::registry::role::roles::RELAYER;
use budlum_core::security::alarm_effects::{apply_to_state, classical_intake, ClassicalIntake};
use budlum_core::security::quantum_canary::{AlarmLevel, CanaryBook, CanaryId};
use budlum_core::settlement::domains::{execute_settlement_tx, SettlementTx, SettlementTxContext};

const MAINNET_CHAIN_ID: u64 = 45_262;
const TESTNET_CHAIN_ID: u64 = 1_338;
const FEE_ATOMS: u64 = 1_000;

fn tx_ctx(sender: Address, chain_id: u64) -> SettlementTxContext {
    SettlementTxContext {
        sender,
        chain_id,
        fee: FEE_ATOMS,
        bls: IntakeState::production_bls,
    }
}

fn composite_authorities(count: u8, seed_tag: u8) -> (Vec<CompositeKeypair>, Vec<PoAAuthorityKey>) {
    let keypairs: Vec<CompositeKeypair> = (0..count)
        .map(|i| {
            CompositeKeypair::from_seeds(
                SuiteId::VALIDATOR,
                &[i.wrapping_add(seed_tag); ML_DSA_SEED_LEN],
                &[i.wrapping_add(seed_tag).wrapping_add(0x40); 32],
            )
            .unwrap()
        })
        .collect();
    let authorities = keypairs
        .iter()
        .map(|kp| {
            let public = kp.public_key().unwrap();
            PoAAuthorityKey {
                authority: Address::from(public.ed),
                public_key: public.encode(),
            }
        })
        .collect();
    (keypairs, authorities)
}

fn bft_members(chain_id: u64, with_pq: bool, seed_base: u8) -> (Vec<BftMember>, [u8; 32]) {
    let members: Vec<BftMember> = (0..4u8)
        .map(|i| {
            let bls = BlsKeypair::from_seed(&[i.wrapping_add(seed_base); 64]).unwrap();
            let pq_seed = [i.wrapping_add(seed_base).wrapping_add(0x30); ML_DSA_SEED_LEN];
            let (pq_pub, pq_pair) = if with_pq {
                let pk = ml_dsa_public_key(SchemeId::ML_DSA_65, &pq_seed).unwrap();
                let kp = PqKeyPair::from_bytes(&pk, &pq_seed).unwrap();
                (pk, Some(kp))
            } else {
                (Vec::new(), None)
            };
            let address = Address::from([i.wrapping_add(seed_base).wrapping_add(0x60); 32]);
            let pop = sign_bls_pop(
                &bls.secret_key,
                &pop_signing_message(chain_id, &address, &bls.public_key),
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
                pq: pq_pair,
            }
        })
        .collect();
    let snapshot = ValidatorSetSnapshot::new(1, members.iter().map(|m| m.entry.clone()).collect());
    let set_hash: [u8; 32] = hex::decode(&snapshot.set_hash).unwrap().try_into().unwrap();
    (members, set_hash)
}

fn register_funded_domain(
    state: &mut AccountState,
    operator: Address,
    chain_id: u64,
    mut domain: ConsensusDomain,
) {
    domain.operator = Some(operator);
    domain.operator_bond = MIN_DOMAIN_OPERATOR_BOND.max(100_000);
    domain.last_committed_height = 0;
    domain.last_committed_hash = [0u8; 32];
    execute_settlement_tx(
        state,
        &tx_ctx(operator, chain_id),
        &SettlementTx::RegisterDomain(Box::new(domain)),
    )
    .unwrap();
}

fn trigger_canary_alarm(state: &mut AccountState, canary: CanaryId) {
    let claimer = [0x77u8; 32];
    let code = canary.code();
    let book: CanaryBook = serde_json::from_value(serde_json::json!({
        "pending": [],
        "solved": [[code, 1u64, claimer, 2u64]]
    }))
    .unwrap();
    state.settlement.quantum = book;
}

#[test]
fn mainnet_hybrid_pq_domains_report_lattice_and_survive_frost_alarm_isolate() {
    let mut state = AccountState::default();
    state.current_block_height = 50;

    let operator = Address::from([0xA1; 32]);
    let relayer = Address::from([0xB2; 32]);
    state.get_or_create(&operator).balance = 50_000_000_000;
    state.get_or_create(&relayer).balance = 50_000_000_000;
    let min_relayer_stake = state.registry.params().min_stake.max(10_000);
    state
        .registry
        .register(relayer, RELAYER, min_relayer_stake, 0)
        .unwrap();

    // 1. Domain 101: PoW (`Hash`)
    let mut pow_domain =
        default_domain(101, ConsensusKind::PoW, 9_101, POW_HEADER_CHAIN_ADAPTER, 2);
    pow_domain.config_hash = [0x11; 32];
    pow_domain.pow_parameters = Some(PoWDomainParameters {
        min_difficulty_bits: 1,
        max_difficulty_bits: 16,
        min_cumulative_work: 4,
        max_headers: 8,
    });
    register_funded_domain(&mut state, operator, MAINNET_CHAIN_ID, pow_domain);
    let pow_reg = state.settlement.domains.get(101).unwrap().clone();
    let pow_built = build_pow_commitment(&PowChainSpec {
        domain: pow_reg,
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

    // 2. Domain 102: BftPq (`BLS12-381 + ML-DSA-65` -> `Lattice`)
    let bft_chain_id = 9_102u64;
    let (bft_mems, bft_vset) = bft_members(bft_chain_id, true, 0x10);
    let mut bft_domain = default_domain(
        102,
        ConsensusKind::Bft,
        bft_chain_id,
        "bft-quorum-commit",
        1,
    );
    bft_domain.validator_set_hash = bft_vset;
    register_funded_domain(&mut state, operator, MAINNET_CHAIN_ID, bft_domain);
    let bft_reg = state.settlement.domains.get(102).unwrap().clone();
    let bft_built = build_bft_commitment(
        &QuorumBlockSpec {
            domain: bft_reg,
            parent_hash: [0u8; 32],
            block_hash: [0x31; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_003_000,
            producer: Some(bft_mems[0].entry.address),
            state_root: [0x32; 32],
            tx_root: [0x33; 32],
            event_root: [0x34; 32],
        },
        bft_chain_id,
        1,
        0,
        &bft_mems,
        &[0, 1, 2],
    )
    .unwrap();
    assert!(matches!(bft_built.proof, FinalityProof::BftPq { .. }));

    // Shared composite validator-suite (`Ed25519 + ML-DSA-65`) quorum for PoAPq/DagPq/PohPq/PospacePq
    let (comp_keys, comp_auths) = composite_authorities(4, 0x31);

    // 3. Domain 103: DagPq (`Ed25519 + ML-DSA-65` -> `Lattice`)
    let mut dag_domain = default_domain(103, ConsensusKind::Dag, 9_103, "dag-tip-vote-v1", 1);
    dag_domain.validator_set_hash = poa_pq_authority_set_hash(&dag_domain, &comp_auths).unwrap();
    register_funded_domain(&mut state, operator, MAINNET_CHAIN_ID, dag_domain);
    let dag_reg = state.settlement.domains.get(103).unwrap().clone();
    let dag_built = build_dag_commitment(
        &QuorumBlockSpec {
            domain: dag_reg,
            parent_hash: [0u8; 32],
            block_hash: [0x41; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_004_000,
            producer: Some(comp_auths[0].authority),
            state_root: [0x42; 32],
            tx_root: [0x43; 32],
            event_root: [0x44; 32],
        },
        3,
        &comp_auths,
        &comp_keys[..3],
    )
    .unwrap();

    // 4. Domain 104: PohPq (`Ed25519 + ML-DSA-65` -> `Lattice`)
    let mut poh_domain = default_domain(104, ConsensusKind::Poh, 9_104, "poh-hash-chain-v1", 1);
    poh_domain.validator_set_hash = poa_pq_authority_set_hash(&poh_domain, &comp_auths).unwrap();
    register_funded_domain(&mut state, operator, MAINNET_CHAIN_ID, poh_domain);
    let poh_reg = state.settlement.domains.get(104).unwrap().clone();
    let poh_built = build_poh_commitment(
        &QuorumBlockSpec {
            domain: poh_reg,
            parent_hash: [0u8; 32],
            block_hash: [0x51; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_005_000,
            producer: Some(comp_auths[0].authority),
            state_root: [0x52; 32],
            tx_root: [0x53; 32],
            event_root: [0x54; 32],
        },
        [0x50; 32],
        12,
        &comp_auths,
        &comp_keys[..3],
    )
    .unwrap();

    // 5. Domain 105: PospacePq (`Ed25519 + ML-DSA-65` -> `Lattice`)
    let mut pospace_domain =
        default_domain(105, ConsensusKind::Pospace, 9_105, "pospace-plot-v1", 1);
    pospace_domain.config_hash = [0x15; 32];
    pospace_domain.validator_set_hash =
        poa_pq_authority_set_hash(&pospace_domain, &comp_auths).unwrap();
    register_funded_domain(&mut state, operator, MAINNET_CHAIN_ID, pospace_domain);
    let pospace_reg = state.settlement.domains.get(105).unwrap().clone();
    let mut pospace_spec = QuorumBlockSpec {
        domain: pospace_reg,
        parent_hash: [0u8; 32],
        block_hash: [0x61; 32],
        height: 1,
        sequence: 0,
        timestamp_ms: 1_700_000_006_000,
        producer: Some(comp_auths[0].authority),
        state_root: [0x62; 32],
        tx_root: [0x63; 32],
        event_root: [0x64; 32],
    };
    mine_pospace_block_hash(&mut pospace_spec, &comp_auths[0].authority).unwrap();
    let pospace_built =
        build_pospace_commitment(&pospace_spec, 0, &comp_auths, &comp_keys[..3]).unwrap();

    // 6. Domain 106: PoAPq (`Ed25519 + ML-DSA-65` -> `Lattice`)
    let mut poa_domain = default_domain(106, ConsensusKind::PoA, 9_106, "poa-authority-quorum", 1);
    poa_domain.validator_set_hash = poa_pq_authority_set_hash(&poa_domain, &comp_auths).unwrap();
    register_funded_domain(&mut state, operator, MAINNET_CHAIN_ID, poa_domain);
    let poa_reg = state.settlement.domains.get(106).unwrap().clone();
    let poa_built = build_poa_commitment(
        &QuorumBlockSpec {
            domain: poa_reg,
            parent_hash: [0u8; 32],
            block_hash: [0x71; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_007_000,
            producer: Some(comp_auths[0].authority),
            state_root: [0x72; 32],
            tx_root: [0x73; 32],
            event_root: [0x74; 32],
        },
        &comp_auths,
        &comp_keys[..3],
    )
    .unwrap();

    for verified in [
        pow_built,
        bft_built,
        dag_built,
        poh_built,
        pospace_built,
        poa_built,
    ] {
        execute_settlement_tx(
            &mut state,
            &tx_ctx(relayer, MAINNET_CHAIN_ID),
            &SettlementTx::SubmitCommitment(Box::new(verified)),
        )
        .unwrap();
    }

    // Trigger Frost Alarm Isolate (`Zemheri`) via solved `EccK1` canary FIRST to
    // prove whether `apply_to_state` falsely freezes mainnet hybrid PQ domains:
    trigger_canary_alarm(&mut state, CanaryId::EccK1);
    assert_eq!(
        state.settlement.quantum.alarm().level(),
        AlarmLevel::Isolate
    );
    assert_eq!(
        classical_intake(state.settlement.quantum.alarm()),
        ClassicalIntake::Stopped
    );

    let report = apply_to_state(&mut state);
    assert!(
        report.domains_frozen.is_empty(),
        "Frost Alarm Isolate must NOT freeze hybrid PQ or Hash domains, froze: {:?}",
        report.domains_frozen
    );
    for id in [101u32, 102, 103, 104, 105, 106] {
        assert_eq!(
            state.settlement.domains.get(id).map(|d| d.status),
            Some(DomainStatus::Active),
            "domain {id} must remain Active under Zemheri"
        );
    }

    // Individual primitive counts remain visible on every hybrid domain alongside `Lattice` class.
    let bft_facts = state.settlement.domains.observed(102);
    assert_eq!(
        bft_facts.count(ObservedScheme::Scheme(SchemeId::BLS12381_MINSIG)),
        1
    );
    assert_eq!(
        bft_facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)),
        1
    );
    assert_eq!(bft_facts.quantum_class(), Some(QuantumClass::Lattice));

    for id in [103u32, 104, 105, 106] {
        let facts = state.settlement.domains.observed(id);
        assert_eq!(
            facts.count(ObservedScheme::Scheme(SchemeId::ED25519)),
            1,
            "domain {id} must report Ed25519 count"
        );
        assert_eq!(
            facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)),
            1,
            "domain {id} must report ML-DSA-65 count"
        );
        assert_eq!(
            facts.quantum_class(),
            Some(QuantumClass::Lattice),
            "hybrid PQ domain {id} requires breaking BOTH Ed25519 and ML-DSA-65"
        );
    }

    // Every entry in `GlobalFinalityCertificate` on mainnet PQ/Hash domains must
    // preserve non-Classical `quantum_posture` (`Lattice` or `Hash`).
    let cert = state
        .settlement
        .universal_finality_certificate(50)
        .expect("six active domains produce a checkpoint certificate");
    for entry in cert
        .established
        .iter()
        .chain(cert.pending.iter())
        .chain(cert.refuted.iter())
    {
        assert_ne!(
            entry.guarantee.quantum_posture,
            QuantumClass::Classical,
            "mainnet PQ/Hash domain {} must not downgrade quantum_posture to Classical: {:?}",
            entry.domain_id,
            entry.guarantee
        );
    }
}

#[test]
fn classical_and_downgraded_domains_freeze_under_isolate_while_pure_hybrid_survives() {
    let mut state = AccountState::default();
    state.current_block_height = 60;

    let operator = Address::from([0xC1; 32]);
    let relayer = Address::from([0xD2; 32]);
    state.get_or_create(&operator).balance = 50_000_000_000;
    state.get_or_create(&relayer).balance = 50_000_000_000;
    let min_relayer_stake = state.registry.params().min_stake.max(10_000);
    state
        .registry
        .register(relayer, RELAYER, min_relayer_stake, 0)
        .unwrap();

    // Domain 201: Classical-only BFT (`pq: None` -> `FinalityProof::Bft`)
    let (classic_mems, classic_vset) = bft_members(9_201, false, 0x11);
    let mut classic_domain = default_domain(201, ConsensusKind::Bft, 9_201, "bft-quorum-commit", 1);
    classic_domain.validator_set_hash = classic_vset;
    register_funded_domain(&mut state, operator, TESTNET_CHAIN_ID, classic_domain);
    let classic_reg = state.settlement.domains.get(201).unwrap().clone();
    let classic_built = build_bft_commitment(
        &QuorumBlockSpec {
            domain: classic_reg,
            parent_hash: [0u8; 32],
            block_hash: [0x81; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_010_000,
            producer: Some(classic_mems[0].entry.address),
            state_root: [0x82; 32],
            tx_root: [0x83; 32],
            event_root: [0x84; 32],
        },
        9_201,
        1,
        0,
        &classic_mems,
        &[0, 1, 2],
    )
    .unwrap();
    assert!(matches!(classic_built.proof, FinalityProof::Bft { .. }));

    // Domain 202: Pure hybrid PQ BFT (`BftPq` only)
    let (pure_pq_mems, pure_pq_vset) = bft_members(9_202, true, 0x22);
    let mut pure_pq_domain = default_domain(202, ConsensusKind::Bft, 9_202, "bft-quorum-commit", 1);
    pure_pq_domain.validator_set_hash = pure_pq_vset;
    register_funded_domain(&mut state, operator, TESTNET_CHAIN_ID, pure_pq_domain);
    let pure_pq_reg = state.settlement.domains.get(202).unwrap().clone();
    let pure_pq_built = build_bft_commitment(
        &QuorumBlockSpec {
            domain: pure_pq_reg,
            parent_hash: [0u8; 32],
            block_hash: [0x91; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_011_000,
            producer: Some(pure_pq_mems[0].entry.address),
            state_root: [0x92; 32],
            tx_root: [0x93; 32],
            event_root: [0x94; 32],
        },
        9_202,
        1,
        0,
        &pure_pq_mems,
        &[0, 1, 2],
    )
    .unwrap();

    // Domain 203: Accepts `BftPq` at height 1, then downgrades by accepting classical `Bft` at height 2!
    let (mixed_pq_mems, mixed_vset) = bft_members(9_203, true, 0x33);
    let mut mixed_domain = default_domain(203, ConsensusKind::Bft, 9_203, "bft-quorum-commit", 1);
    mixed_domain.validator_set_hash = mixed_vset;
    register_funded_domain(&mut state, operator, TESTNET_CHAIN_ID, mixed_domain);
    let mixed_reg = state.settlement.domains.get(203).unwrap().clone();
    let mixed_h1 = build_bft_commitment(
        &QuorumBlockSpec {
            domain: mixed_reg.clone(),
            parent_hash: [0u8; 32],
            block_hash: [0xA1; 32],
            height: 1,
            sequence: 0,
            timestamp_ms: 1_700_000_012_000,
            producer: Some(mixed_pq_mems[0].entry.address),
            state_root: [0xA2; 32],
            tx_root: [0xA3; 32],
            event_root: [0xA4; 32],
        },
        9_203,
        1,
        0,
        &mixed_pq_mems,
        &[0, 1, 2],
    )
    .unwrap();
    // Strip PQ signing keys for height 2 while preserving identical validator entries (`set_hash`)
    let mixed_classic_at_h2: Vec<BftMember> = mixed_pq_mems
        .iter()
        .map(|m| BftMember {
            entry: m.entry.clone(),
            bls: BlsKeypair {
                secret_key: m.bls.secret_key.clone(),
                public_key: m.bls.public_key.clone(),
            },
            pq: None,
        })
        .collect();
    let mixed_h2 = build_bft_commitment(
        &QuorumBlockSpec {
            domain: mixed_reg,
            parent_hash: [0xA1; 32],
            block_hash: [0xA5; 32],
            height: 2,
            sequence: 1,
            timestamp_ms: 1_700_000_013_000,
            producer: Some(mixed_pq_mems[0].entry.address),
            state_root: [0xA6; 32],
            tx_root: [0xA7; 32],
            event_root: [0xA8; 32],
        },
        9_203,
        1,
        1,
        &mixed_classic_at_h2,
        &[0, 1, 2],
    )
    .unwrap();
    assert!(matches!(mixed_h2.proof, FinalityProof::Bft { .. }));

    for verified in [classic_built, pure_pq_built, mixed_h1] {
        execute_settlement_tx(
            &mut state,
            &tx_ctx(relayer, TESTNET_CHAIN_ID),
            &SettlementTx::SubmitCommitment(Box::new(verified)),
        )
        .unwrap();
    }
    // After height 1 (`BftPq`), domain 203 is Lattice:
    assert_eq!(
        state.settlement.domains.observed(203).quantum_class(),
        Some(QuantumClass::Lattice)
    );
    // After height 2 (`FinalityProof::Bft` without PQ signatures), domain 203 drops fail-closed to Classical!
    execute_settlement_tx(
        &mut state,
        &tx_ctx(relayer, TESTNET_CHAIN_ID),
        &SettlementTx::SubmitCommitment(Box::new(mixed_h2)),
    )
    .unwrap();
    assert_eq!(
        state.settlement.domains.observed(201).quantum_class(),
        Some(QuantumClass::Classical)
    );
    assert_eq!(
        state.settlement.domains.observed(202).quantum_class(),
        Some(QuantumClass::Lattice)
    );
    assert_eq!(
        state.settlement.domains.observed(203).quantum_class(),
        Some(QuantumClass::Classical)
    );

    trigger_canary_alarm(&mut state, CanaryId::EccK1);
    let report = apply_to_state(&mut state);
    assert_eq!(
        report.domains_frozen,
        vec![201, 203],
        "classical (201) and downgraded (203) domains must freeze while pure hybrid PQ (202) stays Active"
    );
    assert_eq!(
        state.settlement.domains.get(202).map(|d| d.status),
        Some(DomainStatus::Active)
    );
    assert_eq!(
        state.settlement.domains.get(201).map(|d| d.status),
        Some(DomainStatus::Frozen)
    );
    assert_eq!(
        state.settlement.domains.get(203).map(|d| d.status),
        Some(DomainStatus::Frozen)
    );

    // Wire stability check: existing `ObservedScheme` indices 0, 1, 2 keep exact bincode tags.
    for (expected_tag, scheme) in [
        (0u32, ObservedScheme::Scheme(SchemeId::ED25519)),
        (1u32, ObservedScheme::Secp256k1),
        (
            2u32,
            ObservedScheme::Proof(budlum_core::crypto::facts::AssumptionClass::Hash),
        ),
    ] {
        let mut facts = CryptoFacts::new();
        facts.record(scheme);
        let encoded = bincode::serialize(&scheme).unwrap();
        let tag = u32::from_le_bytes(encoded[..4].try_into().unwrap());
        assert_eq!(tag, expected_tag);
    }
}
