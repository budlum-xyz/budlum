use budlum_core::core::account::{AccountState, PendingDomainUnfreeze};
use budlum_core::core::address::Address;
use budlum_core::core::chain_config::Network;
use budlum_core::core::transaction::ExternalChain;
use budlum_core::cross_domain::external::IntakeState;
use budlum_core::crypto::facts::{AssumptionClass, CryptoFacts, ObservedScheme, QuantumClass};
use budlum_core::crypto::scheme::SchemeId;
use budlum_core::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, PoWDomainParameters, RootScheme,
};
use budlum_core::relayer::{
    check_quantum_leg_posture, PolicyEnvelope, RelayerActionKind, RelayerIntentTx, SolverBid,
    UserIntent,
};
use budlum_core::security::quantum_canary::{AlarmLevel, CanaryBook, CanaryId};
use budlum_core::settlement::domains::{
    apply_domain_unfreezes, execute_settlement_tx, SettlementTx, SettlementTxContext,
};

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

fn make_domain(id: u32, status: DomainStatus) -> ConsensusDomain {
    ConsensusDomain {
        id,
        kind: ConsensusKind::PoW,
        status,
        domain_chain_id: 70_000 + u64::from(id),
        operator: Some(Address::from([0x10; 32])),
        operator_bond: budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND,
        config_hash: [0xA1; 32],
        validator_set_hash: [0xB1; 32],
        finality_adapter: "pow-header-chain-v1".into(),
        min_confirmations: 6,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height: 10,
        last_committed_hash: [0x10; 32],
        pow_parameters: Some(PoWDomainParameters {
            min_difficulty_bits: 16,
            max_difficulty_bits: 80,
            min_cumulative_work: 6 * (1u128 << 16),
            max_headers: 64,
        }),
        zk_program_allowlist: Vec::new(),
        plugin_code_hash: None,
        genesis_state_root: [0x01; 32],
    }
}

fn insert_verified_commitment(state: &mut AccountState, domain_id: u32) {
    must(
        state.settlement.commitments.insert(DomainCommitment {
            domain_id,
            domain_height: 10,
            domain_block_hash: [0x10; 32],
            parent_domain_block_hash: [0x01; 32],
            state_root: [0xCD; 32],
            tx_root: [0xDE; 32],
            event_root: [0xEF; 32],
            finality_proof_hash: [0x77; 32],
            consensus_kind: ConsensusKind::PoW,
            validator_set_hash: [0xB1; 32],
            timestamp_ms: 1_700_000_000_000,
            sequence: 1,
            producer: Some(Address::from([0x10; 32])),
            state_updates: std::collections::BTreeMap::new(),
        }),
        "insert verified commitment",
    );
}

fn make_policy(owner: Address, allowed_domains: Vec<u32>, max_fee: u64) -> PolicyEnvelope {
    PolicyEnvelope {
        owner,
        session_key: Some(Address::from([0x44; 32])),
        spending_cap: max_fee,
        allowed_domains,
        requires_multisig: false,
        requires_hsm: false,
        expires_at_block: 10_000,
    }
}

fn tripped_canary_book(id: CanaryId) -> CanaryBook {
    let claimer = [0x99u8; 32];
    let json = serde_json::json!({
        "pending": [],
        "solved": [[id.code(), 5u64, claimer.to_vec(), 25u64]]
    });
    must(
        serde_json::from_value(json),
        "deserialize tripped CanaryBook",
    )
}

#[test]
fn k4j_oj3_intent_id_binds_chain_id_and_refuses_testnet_to_mainnet_replay() {
    let owner = Address::from([0x11; 32]);
    let emitter = Address::from([0x22; 32]);
    let target_domain = ExternalChain::Ethereum.domain_id();
    let policy = make_policy(owner, vec![1, target_domain], 1_000);

    let testnet_chain = Network::Testnet.chain_id().value();
    let mainnet_chain = Network::Mainnet.chain_id().value();
    assert_ne!(testnet_chain, mainnet_chain);

    let testnet_intent = UserIntent::new(
        owner,
        1,
        target_domain,
        RelayerActionKind::ExternalTransaction {
            chain: ExternalChain::Ethereum,
            target_address: "0x00000000000000000000000000000000000000aa".into(),
            payload_hash: [0x77; 32],
        },
        500,
        200,
        1,
        policy.policy_hash(),
        emitter,
    )
    .with_chain_id(testnet_chain);

    let mainnet_intent = testnet_intent.clone().with_chain_id(mainnet_chain);
    assert_ne!(
        testnet_intent.intent_id, mainnet_intent.intent_id,
        "changing chain_id MUST change intent_id"
    );
    assert!(testnet_intent.verify_id());

    // Live SettlementTx::RelayerIntent on Mainnet MUST reject a Testnet-bound intent.
    let mut mainnet_state = AccountState::new();
    mainnet_state.current_block_height = 10;
    mainnet_state.get_or_create(&owner).balance = 10_000;
    let mainnet_ctx = SettlementTxContext {
        sender: owner,
        chain_id: mainnet_chain,
        fee: 0,
        bls: IntakeState::production_bls,
    };
    let replay_tx = SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Open {
        intent: Box::new(testnet_intent.clone()),
        policy: Box::new(policy),
    }));
    assert!(
        execute_settlement_tx(&mut mainnet_state, &mainnet_ctx, &replay_tx).is_err(),
        "testnet-bound intent MUST fail closed on mainnet"
    );
    assert!(mainnet_state.settlement.relayer_policy.is_empty());

    // Control: the same intent succeeds on its own chain_id (Testnet).
    let mut testnet_state = AccountState::new();
    testnet_state.current_block_height = 10;
    testnet_state.get_or_create(&owner).balance = 10_000;
    let testnet_ctx = SettlementTxContext {
        sender: owner,
        chain_id: testnet_chain,
        fee: 0,
        bls: IntakeState::production_bls,
    };
    must(
        execute_settlement_tx(&mut testnet_state, &testnet_ctx, &replay_tx),
        "intent accepted on matching chain_id",
    );
    assert!(testnet_state
        .settlement
        .relayer_policy
        .intents
        .contains_key(&testnet_intent.intent_id));
}

#[test]
fn k4j_oj4_frozen_domain_suspends_intent_expiry_and_extends_solver_grace_without_slashing() {
    let owner = Address::from([0x11; 32]);
    let solver = Address::from([0x33; 32]);
    let emitter = Address::from([0x22; 32]);
    let source_domain = 10u32;
    let target_domain = ExternalChain::Ethereum.domain_id();
    let policy = make_policy(owner, vec![source_domain, target_domain], 1_000);
    let chain_id = Network::Testnet.chain_id().value();

    let mut state = AccountState::new();
    state.current_block_height = 10;
    state.get_or_create(&owner).balance = 10_000;
    must(
        state
            .registry
            .register_relayer(solver, budlum_core::registry::MIN_REGISTRATION_STAKE, 0),
        "register solver",
    );
    must(
        state
            .settlement
            .domains
            .restore_persisted(make_domain(source_domain, DomainStatus::Active)),
        "register source domain",
    );
    insert_verified_commitment(&mut state, source_domain);

    let intent = UserIntent::new(
        owner,
        source_domain,
        target_domain,
        RelayerActionKind::ExternalTransaction {
            chain: ExternalChain::Ethereum,
            target_address: "0x00000000000000000000000000000000000000bb".into(),
            payload_hash: [0x88; 32],
        },
        500,
        100, // original deadline at block 100
        1,
        policy.policy_hash(),
        emitter,
    )
    .with_chain_id(chain_id);
    let intent_id = intent.intent_id;

    let owner_ctx = SettlementTxContext {
        sender: owner,
        chain_id,
        fee: 0,
        bls: IntakeState::production_bls,
    };
    let solver_ctx = SettlementTxContext {
        sender: solver,
        chain_id,
        fee: 0,
        bls: IntakeState::production_bls,
    };

    must(
        execute_settlement_tx(
            &mut state,
            &owner_ctx,
            &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Open {
                intent: Box::new(intent),
                policy: Box::new(policy),
            })),
        ),
        "submit intent",
    );
    must(
        execute_settlement_tx(
            &mut state,
            &solver_ctx,
            &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Bid(Box::new(SolverBid {
                intent_id,
                relayer: solver,
                quoted_fee: 400,
                proof_commitment: [0x55; 32],
                bond: 500,
                expires_at_block: 110,
            })))),
        ),
        "submit solver bid",
    );
    must(
        execute_settlement_tx(
            &mut state,
            &owner_ctx,
            &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Award { intent_id, solver })),
        ),
        "award solver",
    );

    // Source domain freezes at block 50.
    state.current_block_height = 50;
    must(
        state
            .settlement
            .domains
            .set_status(source_domain, DomainStatus::Frozen),
        "freeze source domain",
    );
    state
        .settlement
        .relayer_policy
        .record_domain_freeze(source_domain, 50);

    // At block 120 (past original deadline 100), expiry MUST fail closed while
    // source domain is frozen and solver's stake MUST NOT be slashed.
    state.current_block_height = 120;
    let stake_before = state
        .registry
        .get(&solver, budlum_core::registry::role::roles::RELAYER)
        .map_or(0, |r| r.stake);
    assert!(
        execute_settlement_tx(
            &mut state,
            &owner_ctx,
            &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Expire { intent_id })),
        )
        .is_err(),
        "frozen domain must suspend intent expiry so honest solver is not slashed"
    );
    let stake_after = state
        .registry
        .get(&solver, budlum_core::registry::role::roles::RELAYER)
        .map_or(0, |r| r.stake);
    assert_eq!(stake_before, stake_after);

    // Governance unfreezes source domain at block 150 -> 100 blocks of freeze grace!
    // Effective deadline extends from 100 -> 200; bid expiry extends from 110 -> 210.
    state.current_block_height = 150;
    let unfrozen = apply_domain_unfreezes(
        &mut state,
        &[PendingDomainUnfreeze {
            domain_id: source_domain,
            expected_validator_set_hash: [0xB1; 32],
            justification_hash: [0xCC; 32],
        }],
    );
    assert_eq!(unfrozen, vec![source_domain]);

    // Still protected at block 180 (< extended deadline 200): expiry refused,
    // and solver can still settle cleanly inside the extended grace window!
    state.current_block_height = 180;
    assert!(
        state
            .settlement
            .relayer_policy
            .expire_intent(intent_id, 180)
            .is_err(),
        "intent must remain protected during post-unfreeze grace window"
    );
    let settled = must(
        state
            .settlement
            .relayer_policy
            .settle_intent(intent_id, solver, 400, 180),
        "honest solver settles cleanly within freeze-extended grace window",
    );
    assert_eq!(settled.relayer, solver);
    assert_eq!(settled.paid_fee, 400);
}

#[test]
fn k4j_oj5_quantum_canary_alarm_closes_classical_legs_while_pq_legs_continue_settling() {
    let owner = Address::from([0x11; 32]);
    let emitter = Address::from([0x22; 32]);
    let chain_id = Network::Testnet.chain_id().value();

    let classical_domain = 201u32;
    let pq_domain = 202u32;

    let mut state = AccountState::new();
    state.current_block_height = 30;
    state.get_or_create(&owner).balance = 20_000;

    must(
        state
            .settlement
            .domains
            .restore_persisted(make_domain(classical_domain, DomainStatus::Active)),
        "register classical domain",
    );
    insert_verified_commitment(&mut state, classical_domain);
    let mut classical_facts = CryptoFacts::new();
    classical_facts.record(ObservedScheme::Scheme(SchemeId::ED25519));
    state
        .settlement
        .domains
        .record_observed(classical_domain, &classical_facts);

    must(
        state
            .settlement
            .domains
            .restore_persisted(make_domain(pq_domain, DomainStatus::Active)),
        "register pq domain",
    );
    insert_verified_commitment(&mut state, pq_domain);
    let mut pq_facts = CryptoFacts::new();
    pq_facts.record(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
    pq_facts.record(ObservedScheme::Proof(AssumptionClass::Hash));
    state
        .settlement
        .domains
        .record_observed(pq_domain, &pq_facts);

    // Trip Ecc224 canary -> AlarmLevel::Restrict.
    state.settlement.quantum = tripped_canary_book(CanaryId::Ecc224);
    assert_eq!(
        state.settlement.quantum.alarm().level(),
        AlarmLevel::Restrict
    );
    assert!(
        check_quantum_leg_posture(state.settlement.quantum.alarm(), QuantumClass::Classical)
            .is_err()
    );
    assert!(
        check_quantum_leg_posture(state.settlement.quantum.alarm(), QuantumClass::Lattice).is_ok()
    );
    assert!(
        check_quantum_leg_posture(state.settlement.quantum.alarm(), QuantumClass::Hash).is_ok()
    );

    let ctx = SettlementTxContext {
        sender: owner,
        chain_id,
        fee: 0,
        bls: IntakeState::production_bls,
    };

    // Classical-backed target leg MUST fail closed under canary alarm.
    let classical_policy = make_policy(owner, vec![pq_domain, classical_domain], 1_000);
    let classical_intent = UserIntent::new(
        owner,
        pq_domain,
        classical_domain,
        RelayerActionKind::ExternalTransaction {
            chain: ExternalChain::Ethereum,
            target_address: "0x00000000000000000000000000000000000000cc".into(),
            payload_hash: [0xAA; 32],
        },
        300,
        200,
        1,
        classical_policy.policy_hash(),
        emitter,
    )
    .with_chain_id(chain_id);
    assert!(
        execute_settlement_tx(
            &mut state,
            &ctx,
            &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Open {
                intent: Box::new(classical_intent),
                policy: Box::new(classical_policy),
            })),
        )
        .is_err(),
        "classical-backed payment leg MUST be refused under quantum canary Restrict alarm"
    );

    // Pure post-quantum leg MUST continue succeeding under the same classical curve alarm!
    let pq_policy = make_policy(owner, vec![1, pq_domain], 1_000);
    let pq_intent = UserIntent::new(
        owner,
        1,
        pq_domain,
        RelayerActionKind::ExternalTransaction {
            chain: ExternalChain::Ethereum,
            target_address: "0x00000000000000000000000000000000000000dd".into(),
            payload_hash: [0xBB; 32],
        },
        300,
        200,
        2,
        pq_policy.policy_hash(),
        emitter,
    )
    .with_chain_id(chain_id);
    let pq_id = pq_intent.intent_id;
    must(
        execute_settlement_tx(
            &mut state,
            &ctx,
            &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Open {
                intent: Box::new(pq_intent),
                policy: Box::new(pq_policy),
            })),
        ),
        "post-quantum payment leg MUST stay open during classical curve canary alarm",
    );
    assert!(state.settlement.relayer_policy.intents.contains_key(&pq_id));
}
