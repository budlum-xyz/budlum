use bincode::Options;
use budlum_core::core::account::AccountState;
use budlum_core::core::address::Address;
use budlum_core::core::chain_config::Network;
use budlum_core::core::transaction::{ExternalChain, RelayerExternalResult};
use budlum_core::cross_domain::event_tree::MerkleProof;
use budlum_core::cross_domain::external::IntakeState;
use budlum_core::cross_domain::message::{
    CrossDomainMessage, CrossDomainMessageParams, MessageKind,
};
use budlum_core::domain::types::{
    ConsensusDomain, ConsensusKind, DomainCommitment, DomainStatus, PoWDomainParameters, RootScheme,
};
use budlum_core::registry::role::roles;
use budlum_core::relayer::policy::INTENT_EXECUTED_KIND;
use budlum_core::relayer::{
    PolicyEnvelope, RelayerActionKind, RelayerIntentTx, SolverBid, UserIntent,
};
use budlum_core::settlement::domains::{
    execute_settlement_tx, SettlementTx, SettlementTxContext, SettlementTxError,
};
use budlum_core::settlement::universal_finality::{EconomicSecurityBound, FinalityVerdict};

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

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn ctx(sender: Address) -> SettlementTxContext {
    SettlementTxContext {
        sender,
        fee: 0,
        chain_id: Network::Testnet.chain_id().value(),
        bls: IntakeState::production_bls,
    }
}

fn make_policy(owner: Address, allowed_domains: Vec<u32>, spending_cap: u64) -> PolicyEnvelope {
    PolicyEnvelope {
        owner,
        session_key: None,
        spending_cap,
        allowed_domains,
        requires_multisig: false,
        requires_hsm: false,
        expires_at_block: 10_000,
    }
}

fn make_intent(
    owner: Address,
    emitter: Address,
    chain: ExternalChain,
    payload_hash: [u8; 32],
    replay_nonce: u64,
    max_fee: u64,
    deadline_block: u64,
) -> (UserIntent, PolicyEnvelope) {
    let source_domain = 1u32;
    let policy = make_policy(
        owner,
        vec![source_domain, chain.domain_id()],
        max_fee.saturating_mul(10),
    );
    let intent = UserIntent::new(
        owner,
        source_domain,
        chain.domain_id(),
        RelayerActionKind::ExternalTransaction {
            chain,
            target_address: "0x00000000000000000000000000000000000000aa".into(),
            payload_hash,
        },
        max_fee,
        deadline_block,
        replay_nonce,
        policy.policy_hash(),
        emitter,
    )
    .with_chain_id(Network::Testnet.chain_id().value());
    (intent, policy)
}

fn make_anchored_result(
    chain: ExternalChain,
    tx_hash: &str,
    intent: &UserIntent,
    relayer: Address,
    payload_hash: [u8; 32],
    nonce: u64,
) -> (RelayerExternalResult, [u8; 32]) {
    let message = CrossDomainMessage::new_correlated(
        CrossDomainMessageParams {
            source_domain: chain.domain_id(),
            target_domain: intent.source_domain,
            source_height: 10,
            event_index: 0,
            nonce,
            sender: intent.expected_emitter,
            recipient: relayer,
            payload_hash,
            kind: MessageKind::Custom(INTENT_EXECUTED_KIND.to_vec()),
            expiry_height: 0,
        },
        intent.intent_id,
    );
    let mut result = RelayerExternalResult {
        chain,
        tx_hash: tx_hash.to_owned(),
        success: true,
        external_state_root: [0u8; 32],
        receipt_proof: Vec::new(),
        message: Some(message),
    };
    let leaf = result.result_leaf();
    let proof = MerkleProof {
        leaf,
        index: 0,
        siblings: Vec::new(),
    };
    let proof_bytes = must(
        bincode::options().with_fixint_encoding().serialize(&proof),
        "serialize merkle proof",
    );
    result.external_state_root = leaf;
    result.receipt_proof = proof_bytes;
    (result, leaf)
}

fn make_domain(
    id: u32,
    bond: u64,
    last_committed_height: u64,
    last_committed_hash: [u8; 32],
) -> ConsensusDomain {
    ConsensusDomain {
        id,
        kind: ConsensusKind::PoW,
        status: DomainStatus::Active,
        domain_chain_id: 70_000 + u64::from(id),
        operator: Some(addr(0xD1)),
        operator_bond: bond,
        config_hash: [0xA1; 32],
        validator_set_hash: [0xB1; 32],
        finality_adapter: "pow-header-chain-v1".into(),
        min_confirmations: 6,
        bridge_enabled: true,
        block_hash_scheme: RootScheme::Sha256,
        state_root_scheme: RootScheme::Sha256,
        tx_root_scheme: RootScheme::Sha256,
        last_committed_height,
        last_committed_hash,
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

#[test]
fn k4c_oc7_same_external_transfer_cannot_close_two_separate_intents() {
    let mut state = AccountState::new();
    state.current_block_height = 10;
    let owner = addr(0xA1);
    let solver = addr(0xB2);
    let emitter = addr(0xC3);
    state.get_or_create(&owner).balance = 10_000_000;
    state.get_or_create(&solver).balance = 10_000_000;
    let min_stake = state.registry.params().min_stake.max(10_000);
    must(
        state
            .registry
            .register(solver, roles::RELAYER, min_stake, 1),
        "register relayer",
    );

    let chain = ExternalChain::Ethereum;
    let payload_1 = [0x11; 32];
    let payload_2 = [0x22; 32];
    let (intent_1, policy_1) = make_intent(owner, emitter, chain, payload_1, 1, 50_000, 100);
    let (intent_2, policy_2) = make_intent(owner, emitter, chain, payload_2, 2, 50_000, 100);

    for (intent, policy) in [(&intent_1, &policy_1), (&intent_2, &policy_2)] {
        must(
            execute_settlement_tx(
                &mut state,
                &ctx(owner),
                &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Open {
                    intent: Box::new(intent.clone()),
                    policy: Box::new(policy.clone()),
                })),
            ),
            "open intent",
        );
        let bid = SolverBid {
            intent_id: intent.intent_id,
            relayer: solver,
            quoted_fee: 40_000,
            proof_commitment: [0x55; 32],
            bond: 10_000,
            expires_at_block: 100,
        };
        must(
            execute_settlement_tx(
                &mut state,
                &ctx(solver),
                &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Bid(Box::new(bid)))),
            ),
            "bid intent",
        );
        must(
            execute_settlement_tx(
                &mut state,
                &ctx(owner),
                &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Award {
                    intent_id: intent.intent_id,
                    solver,
                })),
            ),
            "award intent",
        );
    }

    // Both proofs reference the EXACT same external transfer tx_hash on Ethereum!
    let shared_tx_hash = "0xdeadbeef00000000000000000000000000000000000000000000000000000042";
    let (result_1, root_1) =
        make_anchored_result(chain, shared_tx_hash, &intent_1, solver, payload_1, 1);
    state.external_roots.insert(chain.domain_id(), root_1);

    // First intent settles cleanly and consumes (Ethereum, shared_tx_hash).
    must(
        execute_settlement_tx(
            &mut state,
            &ctx(solver),
            &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Settle {
                intent_id: intent_1.intent_id,
                paid_fee: 40_000,
                result: Box::new(result_1),
            })),
        ),
        "first intent settles with shared transfer",
    );

    // Anchor a second root carrying a valid proof for intent_2 using a non-canonical
    // spelling of the EXACT SAME tx_hash (uppercase + missing 0x prefix + whitespace)
    // to verify canonicalization closes the "0xAABB" vs "0xaabb" vs "aabb" bypass!
    let variant_tx_hash = "DEADBEEF00000000000000000000000000000000000000000000000000000042";
    let (result_2, root_2) =
        make_anchored_result(chain, variant_tx_hash, &intent_2, solver, payload_2, 2);
    state.external_roots.insert(chain.domain_id(), root_2);
    let solver_bal_before = state.get_balance(&solver);
    let escrow_2_before = state
        .settlement
        .relayer_policy
        .escrowed_amount(&intent_2.intent_id);

    // O-C.7: Reusing the same external transfer (even with case/prefix variation) MUST fail closed!
    let replay_err = execute_settlement_tx(
        &mut state,
        &ctx(solver),
        &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Settle {
            intent_id: intent_2.intent_id,
            paid_fee: 40_000,
            result: Box::new(result_2),
        })),
    );
    assert!(
        matches!(replay_err, Err(SettlementTxError::Refused(ref m)) if m.contains("already consumed")),
        "reused external transfer (including case/0x variant) must be refused: {replay_err:?}"
    );
    assert_eq!(state.get_balance(&solver), solver_bal_before);
    assert_eq!(
        state
            .settlement
            .relayer_policy
            .escrowed_amount(&intent_2.intent_id),
        escrow_2_before
    );
}

#[test]
fn k4c_oc10_refuses_pending_domain_leg_and_enforces_certificate_outflow_ceiling() {
    let owner = addr(0xA2);
    let emitter = addr(0xC4);
    let eth_domain_id = ExternalChain::Ethereum.domain_id();
    let bond = budlum_core::domain::registry::MIN_DOMAIN_OPERATOR_BOND;

    // 1. Domain with no finalized commitment yet -> universal finality certificate row is Pending.
    let mut pending_state = AccountState::new();
    pending_state.current_block_height = 20;
    pending_state.get_or_create(&owner).balance = bond.saturating_mul(10);
    must(
        pending_state
            .settlement
            .domains
            .register(make_domain(eth_domain_id, bond, 0, [0u8; 32])),
        "register pending domain",
    );
    let cert = some(
        pending_state
            .settlement
            .universal_finality_certificate(pending_state.current_block_height),
        "certificate exists for pending domain",
    );
    let row = some(cert.prove_domain(eth_domain_id), "pending domain row");
    assert!(
        matches!(row.entry.verdict, FinalityVerdict::Pending { .. }),
        "fresh domain with no commitment must be Pending"
    );

    let (pending_intent, pending_policy) = make_intent(
        owner,
        emitter,
        ExternalChain::Ethereum,
        [0x33; 32],
        1,
        1_000,
        100,
    );
    let owner_bal_before = pending_state.get_balance(&owner);
    let pending_res = execute_settlement_tx(
        &mut pending_state,
        &ctx(owner),
        &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Open {
            intent: Box::new(pending_intent),
            policy: Box::new(pending_policy),
        })),
    );
    assert!(
        matches!(pending_res, Err(SettlementTxError::Refused(ref m)) if m.contains("pending domain")),
        "Pending domain leg must be refused: {pending_res:?}"
    );
    assert_eq!(pending_state.get_balance(&owner), owner_bal_before);

    // 2. Established bonded domain -> derive exact economic outflow ceiling from certificate row.
    let mut est_state = AccountState::new();
    est_state.current_block_height = 20;
    est_state.get_or_create(&owner).balance = bond.saturating_mul(10);
    let tip_hash = [0xAB; 32];
    must(
        est_state
            .settlement
            .domains
            .register(make_domain(eth_domain_id, bond, 10, tip_hash)),
        "register established domain",
    );
    must(
        est_state.settlement.commitments.insert(DomainCommitment {
            domain_id: eth_domain_id,
            domain_height: 10,
            domain_block_hash: tip_hash,
            parent_domain_block_hash: [0x01; 32],
            state_root: [0xCD; 32],
            tx_root: [0xDE; 32],
            event_root: [0xEF; 32],
            finality_proof_hash: [0x77; 32],
            consensus_kind: ConsensusKind::PoW,
            validator_set_hash: [0xB1; 32],
            timestamp_ms: 1_700_000_000_000,
            sequence: 1,
            producer: Some(addr(0xD1)),
            state_updates: std::collections::BTreeMap::new(),
        }),
        "insert verified commitment",
    );

    let cert2 = some(
        est_state
            .settlement
            .universal_finality_certificate(est_state.current_block_height),
        "established certificate",
    );
    let row2 = some(cert2.prove_domain(eth_domain_id), "established row");
    assert_eq!(row2.entry.verdict, FinalityVerdict::Established);
    let econ = EconomicSecurityBound::derive(
        &row2.entry.guarantee,
        row2.entry.bond_atoms,
        row2.entry.bond_atoms,
    );
    assert!(econ.safe_value_outflow_ceiling_atoms > 0);
    let ceiling_u64 = u64::try_from(econ.safe_value_outflow_ceiling_atoms).unwrap_or(u64::MAX);

    // Intent WITHIN ceiling opens cleanly!
    let (ok_intent, ok_policy) = make_intent(
        owner,
        emitter,
        ExternalChain::Ethereum,
        [0x44; 32],
        2,
        ceiling_u64.min(10_000),
        100,
    );
    must(
        execute_settlement_tx(
            &mut est_state,
            &ctx(owner),
            &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Open {
                intent: Box::new(ok_intent),
                policy: Box::new(ok_policy),
            })),
        ),
        "intent within economic ceiling accepted",
    );

    // Intent EXCEEDING ceiling MUST fail closed with zero state mutation!
    let over_fee = ceiling_u64.saturating_add(1);
    let (over_intent, over_policy) = make_intent(
        owner,
        emitter,
        ExternalChain::Ethereum,
        [0x55; 32],
        3,
        over_fee,
        100,
    );
    let bal_before_over = est_state.get_balance(&owner);
    let over_res = execute_settlement_tx(
        &mut est_state,
        &ctx(owner),
        &SettlementTx::RelayerIntent(Box::new(RelayerIntentTx::Open {
            intent: Box::new(over_intent),
            policy: Box::new(over_policy),
        })),
    );
    assert!(
        matches!(over_res, Err(SettlementTxError::Refused(ref m)) if m.contains("economic outflow ceiling")),
        "intent exceeding domain economic outflow ceiling must fail closed: {over_res:?}"
    );
    assert_eq!(est_state.get_balance(&owner), bal_before_over);
}
