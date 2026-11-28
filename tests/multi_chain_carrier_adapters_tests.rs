//! End-to-end integration tests for multi-chain `ChainAdapter` families
//! (Bitcoin SPV, Cosmos ICS-23/IAVL, Solana bank hash), multi-source carrier
//! quorum admission, and deterministic integer carrier economics.

use budlum_core::core::transaction::ExternalChain;
use budlum_core::cross_domain::carrier_quorum::{
    compute_carrier_reward, evaluate_carrier_quorum, CarrierAttestationOutcome,
    CarrierEndpointObservation, CarrierQuorumError, CarrierRewardPolicy, MultiSourceQuorumPolicy,
};
use budlum_core::cross_domain::chain_adapter::{AdapterError, AdapterRegistry, ChainAdapter};
use budlum_core::cross_domain::external::bitcoin_spv::sha256d;
use budlum_core::cross_domain::multi_chain_adapters::{
    assemble_bitcoin_spv_observation, assemble_cosmos_ics23_observation,
    assemble_solana_bank_observation, compute_cosmos_receipt_tx_hash, compute_ics23_existence_root,
    compute_solana_account_leaf, compute_solana_bank_commitment, compute_solana_merkle_root,
    compute_solana_tx_leaf, BitcoinSpvChainAdapter, BitcoinSpvReceiptProof,
    CosmosIcs23ChainAdapter, CosmosIcs23ReceiptProof, Ics23InnerOp, SolanaAccountReceiptProof,
    SolanaBankChainAdapter, COSMOS_DEFAULT_CHAIN_DOMAIN_ID,
};

#[test]
fn bitcoin_spv_adapter_verifies_real_inclusion_and_rejects_cves_and_forgeries() {
    // Unanchored or low-confirmation adapter MUST fail check_fit_for_relay on registration.
    let mut reg = AdapterRegistry::new();
    let unanchored = BitcoinSpvChainAdapter::new(None, 6);
    assert!(matches!(
        reg.register(Box::new(unanchored)),
        Err(AdapterError::Other(_))
    ));
    let low_conf = BitcoinSpvChainAdapter::new(Some([0x11; 32]), 5);
    assert!(matches!(
        reg.register(Box::new(low_conf)),
        Err(AdapterError::Other(_))
    ));

    // Build a valid 2-leaf Bitcoin block Merkle tree (coinbase at 0, payment tx at 1).
    let coinbase_tx = vec![0x01u8; 80];
    let payment_tx = vec![0x02u8; 112]; // != 64 bytes
    let coinbase_txid = sha256d(&coinbase_tx);
    let payment_txid = sha256d(&payment_tx);
    let mut pair = [0u8; 64];
    pair[..32].copy_from_slice(&coinbase_txid);
    pair[32..].copy_from_slice(&payment_txid);
    let merkle_root = sha256d(&pair);

    let adapter = BitcoinSpvChainAdapter::new(Some(merkle_root), 6);
    reg.register(Box::new(adapter))
        .expect("anchored Bitcoin SPV adapter registers");

    let proof = BitcoinSpvReceiptProof {
        stripped_tx: payment_tx.clone(),
        tx_index: 1,
        branch: vec![coinbase_txid],
        confirmations: 6,
        expect_coinbase: false,
    };
    let obs = assemble_bitcoin_spv_observation(&proof, merkle_root).expect("assemble BTC obs");
    reg.verify_observation_for_chain(&obs)
        .expect("valid Bitcoin SPV observation verifies");

    // CVE-2017-12842: 64-byte stripped tx MUST be rejected even if Merkle branch matches!
    let tx64 = vec![0x44u8; 64];
    let tx64_id = sha256d(&tx64);
    let mut pair64 = [0u8; 64];
    pair64[..32].copy_from_slice(&coinbase_txid);
    pair64[32..].copy_from_slice(&tx64_id);
    let root64 = sha256d(&pair64);
    let mut reg64 = AdapterRegistry::new();
    reg64
        .register(Box::new(BitcoinSpvChainAdapter::new(Some(root64), 6)))
        .expect("register");
    let cve_proof = BitcoinSpvReceiptProof {
        stripped_tx: tx64,
        tx_index: 1,
        branch: vec![coinbase_txid],
        confirmations: 6,
        expect_coinbase: false,
    };
    let cve_obs = assemble_bitcoin_spv_observation(&cve_proof, root64).expect("assemble");
    assert!(matches!(
        reg64.verify_observation_for_chain(&cve_obs),
        Err(AdapterError::ProofVerificationFailed(_))
    ));

    // CVE-2012-2459: duplicate right-sibling txid MUST be rejected.
    let mut dup_pair = [0u8; 64];
    dup_pair[..32].copy_from_slice(&payment_txid);
    dup_pair[32..].copy_from_slice(&payment_txid);
    let dup_root = sha256d(&dup_pair);
    let mut reg_dup = AdapterRegistry::new();
    reg_dup
        .register(Box::new(BitcoinSpvChainAdapter::new(Some(dup_root), 6)))
        .expect("register");
    let dup_proof = BitcoinSpvReceiptProof {
        stripped_tx: payment_tx,
        tx_index: 0,
        branch: vec![payment_txid],
        confirmations: 6,
        expect_coinbase: true,
    };
    let dup_obs = assemble_bitcoin_spv_observation(&dup_proof, dup_root).expect("assemble");
    assert!(matches!(
        reg_dup.verify_observation_for_chain(&dup_obs),
        Err(AdapterError::ProofVerificationFailed(_))
    ));

    // Insufficient confirmations MUST be rejected.
    let low_conf_proof = BitcoinSpvReceiptProof {
        confirmations: 5,
        ..proof.clone()
    };
    let low_obs = assemble_bitcoin_spv_observation(&low_conf_proof, merkle_root).expect("assemble");
    assert!(matches!(
        reg.verify_observation_for_chain(&low_obs),
        Err(AdapterError::ProofVerificationFailed(_))
    ));

    // Mismatched tx_hash substitution MUST be rejected.
    let mut substituted = obs;
    substituted.tx_hash = hex::encode([0xFFu8; 32]);
    assert!(matches!(
        reg.verify_observation_for_chain(&substituted),
        Err(AdapterError::ProofVerificationFailed(_))
    ));
}

#[test]
fn cosmos_ics23_adapter_verifies_iavl_inclusion_and_enforces_store_prefix() {
    let mut reg = AdapterRegistry::new();
    assert!(matches!(
        reg.register(Box::new(CosmosIcs23ChainAdapter::new(
            COSMOS_DEFAULT_CHAIN_DOMAIN_ID,
            Vec::new(),
            Some([0x11; 32]),
        ))),
        Err(AdapterError::Other(_))
    ));

    let proof = CosmosIcs23ReceiptProof {
        store_key: b"ibc/commitments/ports/transfer/channels/channel-0/sequences/42".to_vec(),
        value: b"commitment_payload_bytes".to_vec(),
        iavl_height: 0,
        iavl_version: 100,
        iavl_size: 1,
        inner_ops: vec![Ics23InnerOp {
            prefix: vec![0x02, 0x04, 0x10],
            suffix: vec![0xAA; 32],
        }],
    };
    let app_hash = compute_ics23_existence_root(&proof).expect("compute ICS-23 root");
    let adapter = CosmosIcs23ChainAdapter::new(
        COSMOS_DEFAULT_CHAIN_DOMAIN_ID,
        b"ibc/".to_vec(),
        Some(app_hash),
    );
    reg.register(Box::new(adapter))
        .expect("anchored Cosmos adapter registers");

    let obs = assemble_cosmos_ics23_observation(COSMOS_DEFAULT_CHAIN_DOMAIN_ID, &proof, app_hash)
        .expect("assemble Cosmos obs");
    assert_eq!(
        obs.tx_hash,
        hex::encode(compute_cosmos_receipt_tx_hash(&proof))
    );
    reg.verify_observation_for_chain(&obs)
        .expect("valid Cosmos ICS-23 observation verifies");

    // Cross-module key confusion (key outside store_prefix `ibc/`) MUST be rejected.
    let wrong_prefix_proof = CosmosIcs23ReceiptProof {
        store_key: b"bank/balances/cosmos1attacker".to_vec(),
        ..proof.clone()
    };
    let wrong_root = compute_ics23_existence_root(&wrong_prefix_proof).expect("root");
    let mut reg_prefix = AdapterRegistry::new();
    reg_prefix
        .register(Box::new(CosmosIcs23ChainAdapter::new(
            COSMOS_DEFAULT_CHAIN_DOMAIN_ID,
            b"ibc/".to_vec(),
            Some(wrong_root),
        )))
        .expect("register");
    let wrong_obs = assemble_cosmos_ics23_observation(
        COSMOS_DEFAULT_CHAIN_DOMAIN_ID,
        &wrong_prefix_proof,
        wrong_root,
    )
    .expect("assemble");
    assert!(matches!(
        reg_prefix.verify_observation_for_chain(&wrong_obs),
        Err(AdapterError::ProofVerificationFailed(_))
    ));

    // Tampered value breaking ICS-23 root MUST be rejected.
    let mut tampered_proof = proof;
    tampered_proof.value = b"forged_payload".to_vec();
    let tampered_obs = assemble_cosmos_ics23_observation(
        COSMOS_DEFAULT_CHAIN_DOMAIN_ID,
        &tampered_proof,
        app_hash,
    )
    .expect("assemble tampered");
    assert!(matches!(
        reg.verify_observation_for_chain(&tampered_obs),
        Err(AdapterError::ProofVerificationFailed(_))
    ));
}

#[test]
fn solana_bank_adapter_verifies_bank_commitment_account_and_tx_proofs() {
    let slot = 250_000_000u64;
    let parent_bank_hash = [0x10; 32];
    let account_pubkey = [0x22; 32];
    let account_data_hash = [0x33; 32];
    let lamports = 9_500_000_000u64;
    let tx_sig_hash = [0x44; 32];

    let acct_leaf = compute_solana_account_leaf(&account_pubkey, &account_data_hash, lamports);
    let acct_sib = ([0x55; 32], true);
    let accounts_delta_root = compute_solana_merkle_root(&acct_leaf, &[acct_sib]);

    let tx_leaf = compute_solana_tx_leaf(&tx_sig_hash, slot);
    let tx_sib = ([0x66; 32], false);
    let tx_root = compute_solana_merkle_root(&tx_leaf, &[tx_sib]);

    let bank_hash =
        compute_solana_bank_commitment(&parent_bank_hash, &accounts_delta_root, &tx_root, slot);

    let mut reg = AdapterRegistry::new();
    // Zero anchor MUST fail registration.
    assert!(matches!(
        reg.register(Box::new(SolanaBankChainAdapter::new(
            Some([0u8; 32]),
            Some(accounts_delta_root),
            Some(tx_root),
            slot,
        ))),
        Err(AdapterError::Other(_))
    ));

    let adapter = SolanaBankChainAdapter::new(
        Some(bank_hash),
        Some(accounts_delta_root),
        Some(tx_root),
        slot,
    );
    assert_eq!(adapter.chain_type(), ExternalChain::Solana);
    reg.register(Box::new(adapter))
        .expect("anchored Solana adapter registers");

    let proof = SolanaAccountReceiptProof {
        slot,
        parent_bank_hash,
        account_pubkey,
        account_data_hash,
        lamports,
        account_branch: vec![acct_sib],
        tx_signature_hash: tx_sig_hash,
        tx_branch: vec![tx_sib],
    };
    let obs = assemble_solana_bank_observation(&proof, bank_hash).expect("assemble SOL obs");
    reg.verify_observation_for_chain(&obs)
        .expect("valid Solana bank-hash observation verifies");

    // Stale slot (< min_confirmed_slot) MUST be rejected.
    let mut stale_reg = AdapterRegistry::new();
    stale_reg
        .register(Box::new(SolanaBankChainAdapter::new(
            Some(bank_hash),
            Some(accounts_delta_root),
            Some(tx_root),
            slot + 1,
        )))
        .expect("register");
    assert!(matches!(
        stale_reg.verify_observation_for_chain(&obs),
        Err(AdapterError::ProofVerificationFailed(_))
    ));

    // Tampered lamports MUST fail account Merkle check.
    let mut bad_lamports = proof;
    bad_lamports.lamports += 1;
    let bad_obs = assemble_solana_bank_observation(&bad_lamports, bank_hash).expect("assemble");
    assert!(matches!(
        reg.verify_observation_for_chain(&bad_obs),
        Err(AdapterError::ProofVerificationFailed(_))
    ));
}

#[test]
fn multi_source_carrier_quorum_blocks_single_and_lying_rpc_sources() {
    // Policy with < 2 independent endpoints MUST fail closed.
    let bad_policy = MultiSourceQuorumPolicy {
        min_independent_endpoints: 1,
        max_height_skew: 4,
    };
    let obs_a = CarrierEndpointObservation {
        endpoint_id: "rpc-alpha".into(),
        domain_id: 1,
        block_height: 1000,
        state_root: [0xAA; 32],
        evidence_digest: [0x11; 32],
    };
    assert!(matches!(
        evaluate_carrier_quorum(&bad_policy, std::slice::from_ref(&obs_a)),
        Err(CarrierQuorumError::InvalidPolicy(_))
    ));

    let policy = MultiSourceQuorumPolicy {
        min_independent_endpoints: 2,
        max_height_skew: 4,
    };

    // 1 honest vs 1 lying RPC MUST fail closed (never submit invalid tx!).
    let obs_liar = CarrierEndpointObservation {
        endpoint_id: "rpc-liar".into(),
        domain_id: 1,
        block_height: 1000,
        state_root: [0xBB; 32],
        evidence_digest: [0x22; 32],
    };
    assert!(matches!(
        evaluate_carrier_quorum(&policy, &[obs_a.clone(), obs_liar.clone()]),
        Err(CarrierQuorumError::ConflictingSources { .. })
    ));

    // Duplicate endpoint spoofing (same endpoint_id twice) MUST fail closed.
    assert!(matches!(
        evaluate_carrier_quorum(&policy, &[obs_a.clone(), obs_a.clone()]),
        Err(CarrierQuorumError::DuplicateEndpoint(_))
    ));

    // 2 vs 2 tie (meets min_independent_endpoints=2 but lacks strict majority) MUST fail closed!
    let obs_b = CarrierEndpointObservation {
        endpoint_id: "rpc-beta".into(),
        ..obs_a.clone()
    };
    let obs_liar2 = CarrierEndpointObservation {
        endpoint_id: "rpc-liar-2".into(),
        ..obs_liar.clone()
    };
    assert!(matches!(
        evaluate_carrier_quorum(
            &policy,
            &[obs_a.clone(), obs_b.clone(), obs_liar.clone(), obs_liar2]
        ),
        Err(CarrierQuorumError::ConflictingSources { .. })
    ));

    // 2 honest vs 1 lying RPC -> quorum passes (2 >= 2 and 2*2 > 3) and identifies the liar!
    let decision = evaluate_carrier_quorum(&policy, &[obs_a.clone(), obs_b.clone(), obs_liar])
        .expect("2-of-3 honest majority reaches quorum");
    assert_eq!(decision.block_height, 1000);
    assert_eq!(decision.state_root, [0xAA; 32]);
    assert_eq!(decision.agreeing_endpoints.len(), 2);
    assert_eq!(decision.dissenting_endpoints, vec!["rpc-liar".to_string()]);

    // Excessive height skew across endpoints MUST fail closed.
    let obs_far = CarrierEndpointObservation {
        endpoint_id: "rpc-stale".into(),
        block_height: 990,
        ..obs_a.clone()
    };
    assert!(matches!(
        evaluate_carrier_quorum(&policy, &[obs_a, obs_b, obs_far]),
        Err(CarrierQuorumError::HeightSkewExceeded { .. })
    ));
}

#[test]
fn carrier_economics_pays_zero_for_lies_and_escalates_for_idle_domains() {
    let policy = CarrierRewardPolicy {
        base_reward_atoms: 1_000_000,
        target_freshness_blocks: 10,
        escalation_step_blocks: 10,
        escalation_bps_per_step: 2_500, // +25% per 10 overdue blocks
        max_multiplier_bps: 40_000,     // 4.0x cap
        domain_bond_share_bps: 6_000,   // 60% from domain bond, 40% from route fees
    };

    // Lying / rejected attestation strictly yields ZERO reward.
    let lie = compute_carrier_reward(&policy, CarrierAttestationOutcome::RejectedOrFalse)
        .expect("rejected outcome computes zero");
    assert_eq!(lie.total_payout, 0);
    assert_eq!(lie.domain_bond_draw, 0);
    assert_eq!(lie.route_fee_draw, 0);
    assert_eq!(lie.multiplier_bps, 0);

    // Timely attestation (blocks_since_last_attestation <= 10) -> 1.0x (1_000_000 atoms).
    let timely = compute_carrier_reward(
        &policy,
        CarrierAttestationOutcome::Accepted {
            blocks_since_last_attestation: 10,
            available_domain_bond: 10_000_000,
            available_route_fee_pool: 10_000_000,
        },
    )
    .expect("timely reward");
    assert_eq!(timely.multiplier_bps, 10_000);
    assert_eq!(timely.domain_bond_draw, 600_000);
    assert_eq!(timely.route_fee_draw, 400_000);
    assert_eq!(timely.total_payout, 1_000_000);

    // Idle domain (1 step overdue: 11..=20 blocks) -> 1.25x (1_250_000 atoms).
    let idle_1 = compute_carrier_reward(
        &policy,
        CarrierAttestationOutcome::Accepted {
            blocks_since_last_attestation: 15,
            available_domain_bond: 10_000_000,
            available_route_fee_pool: 10_000_000,
        },
    )
    .expect("idle step 1");
    assert_eq!(idle_1.multiplier_bps, 12_500);
    assert!(idle_1.total_payout > timely.total_payout);

    // Deeply idle domain (200 blocks overdue) -> capped at max_multiplier_bps (4.0x = 4_000_000).
    let idle_cap = compute_carrier_reward(
        &policy,
        CarrierAttestationOutcome::Accepted {
            blocks_since_last_attestation: 210,
            available_domain_bond: 10_000_000,
            available_route_fee_pool: 10_000_000,
        },
    )
    .expect("idle capped");
    assert_eq!(idle_cap.multiplier_bps, 40_000);
    assert_eq!(idle_cap.total_payout, 4_000_000);

    // Pool-bounded: NEVER mints beyond available bond + route fees.
    let bounded = compute_carrier_reward(
        &policy,
        CarrierAttestationOutcome::Accepted {
            blocks_since_last_attestation: 210,
            available_domain_bond: 500_000,
            available_route_fee_pool: 300_000,
        },
    )
    .expect("bounded payout");
    assert_eq!(bounded.domain_bond_draw, 500_000);
    assert_eq!(bounded.route_fee_draw, 300_000);
    assert_eq!(bounded.total_payout, 800_000);
}
