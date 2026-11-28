//! End-to-end success and refusal coverage for the BNS, bridge transaction-door,
//! external evidence encoding / EVM verification / relayer planning, and role
//! registry JSON-RPC surfaces.

use crate::bns::{MAX_DURATION, MIN_DURATION};
use crate::chain::blockchain::Blockchain;
use crate::chain::chain_actor::{ChainActor, ChainHandle};
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::{ExternalChain, Transaction, TransactionType};
use crate::cross_domain::event_tree::{DomainEvent, DomainEventKind, MerkleProof};
use crate::cross_domain::external::evm_hybrid::{
    EvmHybridProof, EvmPrecompiles, MessageBinding, MlDsaVariant,
};
use crate::cross_domain::external::intake::{AdapterSpec, IntakeState, RegistrationRequest};
use crate::cross_domain::external::spec::{RawConsensusEvidence, VerificationPolicy};
use crate::cross_domain::external::tendermint::{
    validator_address_of, validator_set_commitment, vote_sign_bytes, PinnedTendermintAnchor,
    TendermintCommitEvidence, TendermintSignature, TendermintValidator,
    EVIDENCE_VERSION as TM_EVIDENCE_VERSION,
};
use crate::cross_domain::external::VersionPolicy;
use crate::crypto::primitives::{KeyPair, PqKeyPair};
use crate::network::node::Node;
use crate::rpc::api::BudlumApiServer;
use crate::rpc::server::{RpcMode, RpcSecurityConfig, RpcServer};
use std::sync::Arc;

const TEST_CHAIN_ID: u64 = 45_262;

fn setup_with_blockchain(blockchain: Blockchain) -> (RpcServer, ChainHandle) {
    let (chain_actor, chain) = ChainActor::new(blockchain);
    tokio::spawn(Box::pin(async move {
        chain_actor.run().await;
    }));
    let node_struct = Node::new(chain.clone()).expect("node initialization");
    let node_client = node_struct.get_client();
    (
        RpcServer::with_security_and_mode(
            chain.clone(),
            node_client,
            RpcSecurityConfig::operator_default(),
            RpcMode::Operator,
        ),
        chain,
    )
}

fn setup() -> (RpcServer, ChainHandle) {
    let consensus = Arc::new(PoWEngine::new(0));
    let blockchain = Blockchain::new(consensus, None, TEST_CHAIN_ID, None);
    setup_with_blockchain(blockchain)
}

#[tokio::test]
async fn bns_prepare_and_resolve_endpoints_answer_valid_requests_and_refuse_malformed_inputs() {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, TEST_CHAIN_ID, None);
    let alice = Address::from([0xA1; 32]);
    let bob = Address::from([0xB2; 32]);
    let sub_owner = Address::from([0xC3; 32]);
    bc.state
        .bns_registry
        .register("atlas.bud".to_string(), alice, 0, MIN_DURATION)
        .expect("register atlas.bud");
    bc.state
        .bns_registry
        .register_subdomain("atlas.bud", "docs".to_string(), sub_owner, &alice, 0)
        .expect("register docs.atlas.bud");

    let (server, _chain) = setup_with_blockchain(bc);
    let alice_hex = format!("0x{}", alice.to_hex());
    let bob_hex = format!("0x{}", bob.to_hex());
    let sub_hex = format!("0x{}", sub_owner.to_hex());

    // 1. bud_bnsPrepareRegisterSubdomain: success against live parent + refusals.
    let sub_prep = server
        .bns_prepare_register_subdomain("atlas.bud".to_string(), "api".to_string(), sub_hex.clone())
        .await
        .expect("prepare register subdomain for live parent");
    assert!(sub_prep["tx_template"].is_object());
    let bad_parent = server
        .bns_prepare_register_subdomain("missing.bud".to_string(), "api".to_string(), sub_hex)
        .await
        .unwrap_err();
    assert_eq!(bad_parent.code(), -32602);
    let zero_sub = server
        .bns_prepare_register_subdomain(
            "atlas.bud".to_string(),
            "api".to_string(),
            format!("0x{}", Address::zero().to_hex()),
        )
        .await
        .unwrap_err();
    assert_eq!(zero_sub.code(), -32602);

    // 2. bud_bnsPrepareRenew: success in [MIN_DURATION, MAX_DURATION] + out-of-range refusal.
    let renew_ok = server
        .bns_prepare_renew("atlas.bud".to_string(), alice_hex.clone(), MIN_DURATION)
        .await
        .expect("prepare renew for valid duration");
    assert_eq!(renew_ok["name"].as_str(), Some("atlas.bud"));
    assert_eq!(renew_ok["duration"].as_u64(), Some(MIN_DURATION));
    assert!(renew_ok["tx_template"].is_object());
    let renew_bad = server
        .bns_prepare_renew(
            "atlas.bud".to_string(),
            alice_hex.clone(),
            MAX_DURATION.saturating_add(1),
        )
        .await
        .unwrap_err();
    assert_eq!(renew_bad.code(), -32602);

    // 3. bud_bnsPrepareSetStorage: success with 32-byte root.
    let root_hex = format!("0x{}", hex::encode([0x55u8; 32]));
    let storage_ok = server
        .bns_prepare_set_storage(
            "atlas.bud".to_string(),
            alice_hex.clone(),
            root_hex.clone(),
            7,
        )
        .await
        .expect("prepare set storage");
    assert_eq!(storage_ok["storage_root"].as_str(), Some(root_hex.as_str()));
    assert_eq!(storage_ok["storage_domain_id"].as_u64(), Some(7));
    assert!(storage_ok["tx_template"].is_object());

    // 4. bud_bnsPrepareSetSubdomainContent: success clearing content (None) + non-null template.
    let sub_content_ok = server
        .bns_prepare_set_subdomain_content(
            "atlas.bud".to_string(),
            "docs".to_string(),
            alice_hex.clone(),
            None,
        )
        .await
        .expect("prepare subdomain content clear");
    assert_eq!(sub_content_ok["parent"].as_str(), Some("atlas.bud"));
    assert_eq!(sub_content_ok["sub_label"].as_str(), Some("docs"));
    assert!(sub_content_ok["content"].is_null());
    assert!(sub_content_ok["tx_template"].is_object());

    // 5. bud_bnsPrepareTransfer: success to non-zero recipient + refusal on zero recipient.
    let transfer_ok = server
        .bns_prepare_transfer("atlas.bud".to_string(), alice_hex.clone(), bob_hex.clone())
        .await
        .expect("prepare BNS transfer");
    assert_eq!(transfer_ok["name"].as_str(), Some("atlas.bud"));
    assert_eq!(transfer_ok["new_owner"].as_str(), Some(bob_hex.as_str()));
    assert!(transfer_ok["tx_template"].is_object());
    let transfer_zero = server
        .bns_prepare_transfer(
            "atlas.bud".to_string(),
            alice_hex,
            format!("0x{}", Address::zero().to_hex()),
        )
        .await
        .unwrap_err();
    assert_eq!(transfer_zero.code(), -32602);

    // 6. bud_bnsResolveSubdomainContent: success (null when unset) + refusal on invalid label.
    let sub_resolved = server
        .bns_resolve_subdomain_content("atlas.bud".to_string(), "docs".to_string())
        .await
        .expect("resolve valid subdomain content");
    assert!(sub_resolved.is_null());
    let sub_bad = server
        .bns_resolve_subdomain_content("INVALID".to_string(), "docs".to_string())
        .await
        .unwrap_err();
    assert_eq!(sub_bad.code(), -32602);

    // 7. Protocol-level JSON-RPC parameter refusals on BNS read endpoints.
    let module = server.into_rpc();
    let resolve_err = module
        .call::<_, serde_json::Value>("bud_bnsResolve", [42u64])
        .await
        .unwrap_err();
    assert!(
        resolve_err.to_string().contains("-32602") || resolve_err.to_string().contains("Invalid")
    );
    let resolve_full_err = module
        .call::<_, serde_json::Value>("bud_bnsResolveFull", [42u64])
        .await
        .unwrap_err();
    assert!(
        resolve_full_err.to_string().contains("-32602")
            || resolve_full_err.to_string().contains("Invalid")
    );
    let resolve_sub_err = module
        .call::<_, serde_json::Value>("bud_bnsResolveSubdomain", [42u64])
        .await
        .unwrap_err();
    assert!(
        resolve_sub_err.to_string().contains("-32602")
            || resolve_sub_err.to_string().contains("Invalid")
    );
}

#[tokio::test]
async fn retired_bridge_mutation_rpcs_refuse_and_leave_bridge_root_unchanged() {
    let (server, chain) = setup();
    let root_before = chain.get_state_root(0).await;

    let dummy_event = DomainEvent {
        domain_id: 1,
        domain_height: 1,
        event_index: 0,
        kind: DomainEventKind::Custom(b"noop".to_vec()),
        emitter: Address::zero(),
        message: None,
        payload_hash: [0x11u8; 32],
    };
    let dummy_proof = MerkleProof {
        leaf: [0x11u8; 32],
        siblings: Vec::new(),
        index: 0,
    };

    let burn_id = [0x21u8; 32];
    let burn_ev_id = [0x22u8; 32];
    let unlock_id = [0x23u8; 32];
    let eth_dest = [0x33u8; 20];
    let relayer_addr = Address::from([0x44u8; 32]);

    let burn_err = server.burn_bridge_transfer(burn_id, 1).await.unwrap_err();
    assert_eq!(burn_err.code(), -32602);

    let burn_ev_err = server
        .burn_bridge_transfer_with_event(burn_ev_id, 1, 10, 0, 100, eth_dest)
        .await
        .unwrap_err();
    assert_eq!(burn_ev_err.code(), -32602);

    let mint_err = server
        .mint_bridge_transfer(
            1,
            10,
            0,
            None,
            dummy_event.clone(),
            dummy_proof.clone(),
            relayer_addr,
        )
        .await
        .unwrap_err();
    assert_eq!(mint_err.code(), -32602);

    let unlock_err = server
        .unlock_bridge_transfer(unlock_id, 1)
        .await
        .unwrap_err();
    assert_eq!(unlock_err.code(), -32602);

    let unlock_ver_err = server
        .unlock_bridge_transfer_verified(1, 10, 0, None, dummy_event, dummy_proof)
        .await
        .unwrap_err();
    assert_eq!(unlock_ver_err.code(), -32602);

    assert_eq!(
        chain.get_state_root(0).await,
        root_before,
        "refused legacy bridge RPC calls must never mutate chain state"
    );
}

#[tokio::test]
async fn encoding_evm_planner_relayer_and_probe_replay_endpoints_succeed_and_refuse() {
    // Seed a real governance-pinned Tendermint external domain so
    // bud_replayExternalProbes verifies its live golden commit and fault probes.
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, TEST_CHAIN_ID, None);

    let tm_key = KeyPair::from_seed(&[0x31u8; 32]).expect("tm keypair");
    let val_addr = validator_address_of(&tm_key.public_key_bytes());
    let validators = vec![TendermintValidator {
        address: val_addr,
        public_key: tm_key.public_key_bytes(),
        voting_power: 1_000,
    }];
    let valset_hash = validator_set_commitment(&validators);
    let app_hash = [0x42u8; 32];
    let parts_hash = [0x33u8; 32];
    let mut commit = TendermintCommitEvidence {
        chain_id: "probe-chain-1".to_string(),
        height: 50,
        round: 0,
        block_hash: [0u8; 32],
        parts_total: 1,
        parts_hash,
        version_block: 11,
        last_block_hash: [0x11; 32],
        last_parts_total: 1,
        last_parts_hash: [0x12; 32],
        last_commit_hash: [0x22; 32],
        data_hash: [0x34; 32],
        validators_hash: valset_hash,
        next_validators_hash: valset_hash,
        consensus_hash: [0x55; 32],
        app_hash,
        last_results_hash: [0x66; 32],
        evidence_hash: [0x77; 32],
        proposer_address: val_addr,
        commit_time: 1_700_000_000,
        commit_time_nanos: 0,
        validators,
        signatures: Vec::new(),
    };
    commit.block_hash = commit.header_hash();
    let sign_bytes = vote_sign_bytes(
        "probe-chain-1",
        50,
        0,
        &commit.block_hash,
        1,
        &parts_hash,
        (1_700_000_000, 0),
    );
    commit.signatures = vec![TendermintSignature {
        address: val_addr,
        timestamp_seconds: 1_700_000_000,
        timestamp_nanos: 0,
        signature: tm_key.sign(&sign_bytes).to_vec(),
    }];
    let tm_payload = bincode::serialize(&commit).expect("serialize Tendermint commit");
    bc.state.settlement.external_intake.pin_tendermint_anchor(
        "probe-net",
        PinnedTendermintAnchor {
            chain_id: "probe-chain-1".to_string(),
            validator_set_hash: valset_hash,
        },
    );
    let spec = AdapterSpec::TendermintCommit {
        network: "probe-net".to_string(),
        chain_id: "probe-chain-1".to_string(),
        validator_set_hash: Some(valset_hash),
    };
    let adapter_id = spec.build(None, None).descriptor().id;
    let economics = IntakeState::conservative_economics(1_000_000);
    let bond_atoms = economics.required_bond_atoms();
    let poster = Address::from([0x7A; 32]);
    let domain_key = bc
        .state
        .settlement
        .external_intake
        .register_domain(
            RegistrationRequest {
                golden: RawConsensusEvidence {
                    adapter: adapter_id,
                    evidence_version: TM_EVIDENCE_VERSION,
                    network: "probe-net".to_string(),
                    payload: tm_payload.clone(),
                    declared_height: 50,
                    declared_root: app_hash,
                    submitter: poster,
                },
                versions: VersionPolicy::single(adapter_id, TM_EVIDENCE_VERSION, 0),
                economics,
                policy: VerificationPolicy::strict(1_700_000_005),
                bond_atoms,
                poster,
                spec,
            },
            None,
        )
        .expect("register pinned Tendermint external domain");

    let (server, _chain) = setup_with_blockchain(bc);

    // 1. bud_encodeCrossVmCall: verified canonical encoding success.
    let cross_vm_ok = server
        .encode_cross_vm_call(serde_json::json!({
            "source_domain": 3,
            "target_domain": 7,
            "source_language": "solidity",
            "target_language": "move",
            "method": "router::settle",
            "args": [{"name": "amount", "value": {"kind": "u128", "value": 9_000}}],
            "nonce": 17,
        }))
        .await
        .expect("encode valid cross-VM call");
    assert_eq!(cross_vm_ok["target_encoding"].as_str(), Some("bcs_le"));

    // 2. bud_encodeExternalEvidence: success on raw Tendermint payload + refusal without version.
    let encode_ok_req = serde_json::json!({
        "payload_hex": format!("0x{}", hex::encode(&tm_payload)),
        "adapter_name": "tendermint-commit-v1",
        "network": "probe-net",
        "evidence_version": TM_EVIDENCE_VERSION,
        "declared_height": 50,
        "declared_root_hex": format!("0x{}", hex::encode(app_hash)),
        "submitter": format!("0x{}", poster.to_hex()),
    });
    let encoded_ok = server
        .encode_external_evidence(encode_ok_req)
        .await
        .expect("encode external consensus evidence");
    assert!(encoded_ok.is_object());
    let encode_bad_req = serde_json::json!({
        "payload_hex": "0xdeadbeef",
        "adapter_name": "tendermint-commit-v1",
        "network": "probe-net",
        "declared_height": 50,
        "declared_root_hex": format!("0x{}", hex::encode(app_hash)),
        "submitter": format!("0x{}", poster.to_hex()),
    });
    let encoded_bad = server
        .encode_external_evidence(encode_bad_req)
        .await
        .unwrap_err();
    assert_eq!(encoded_bad.code(), -32602);

    // 3. bud_planEvmVerification: success with full precompile capabilities + refusal on zero chain_id.
    let pq = PqKeyPair::generate();
    let pq_sig = pq
        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, b"evm-hybrid-plan")
        .expect("sign ML-DSA-65");
    let valid_proof = EvmHybridProof {
        chain_id: TEST_CHAIN_ID,
        epoch: 1,
        height: 120,
        state_root: [0xAB; 32],
        g1_hashed_message: vec![0x01; 128],
        g2_aggregate_pubkey: vec![0x02; 256],
        g1_generator: vec![0x03; 128],
        g2_negated_signature: vec![0x04; 256],
        ml_dsa_public_key: pq.public_key_bytes().to_vec(),
        ml_dsa_signature: pq_sig,
        ml_dsa_variant: MlDsaVariant::Fips204,
        message_binding: MessageBinding::ZkCircuit,
        calldata_zero_bytes: 64,
        calldata_nonzero_bytes: 512,
    };
    let caps = EvmPrecompiles {
        bls_pairing: true,
        ml_dsa_fips: true,
        ml_dsa_eth: false,
    };
    let plan_ok = server
        .plan_evm_verification(serde_json::json!({
            "capabilities": caps,
            "proof": valid_proof,
            "challenge_window": 100,
        }))
        .await
        .expect("plan hybrid EVM verification");
    assert!(plan_ok.is_object());

    let mut zero_chain_proof = valid_proof;
    zero_chain_proof.chain_id = 0;
    let plan_bad = server
        .plan_evm_verification(serde_json::json!({
            "capabilities": caps,
            "proof": zero_chain_proof,
            "challenge_window": 100,
        }))
        .await
        .unwrap_err();
    assert_eq!(plan_bad.code(), -32602);

    // 4. bud_relayerPrepareExternalTx: success + refusal on malformed payload hex.
    let sender_hex = format!("0x{}", Address::from([0x51; 32]).to_hex());
    let relayer_ok = server
        .relayer_prepare_external_tx(
            sender_hex.clone(),
            ExternalChain::Ethereum,
            "0x1111111111111111111111111111111111111111".to_string(),
            "0xabcdef01".to_string(),
        )
        .await
        .expect("prepare external relayer tx");
    assert!(relayer_ok.is_object());
    let relayer_bad = server
        .relayer_prepare_external_tx(
            sender_hex,
            ExternalChain::Ethereum,
            "0x1111111111111111111111111111111111111111".to_string(),
            "0xnot-hex".to_string(),
        )
        .await
        .unwrap_err();
    assert_eq!(relayer_bad.code(), -32602);

    // 5. bud_replayExternalProbes: success on registered domain + refusal on unknown key.
    let key_hex = format!("0x{}", hex::encode(domain_key.0));
    let probes_ok = server
        .replay_external_probes(key_hex)
        .await
        .expect("replay fault probes for registered domain");
    assert_eq!(probes_ok["goldenVerified"].as_bool(), Some(true));
    assert_eq!(probes_ok["wouldPassAdmission"].as_bool(), Some(true));
    let unknown_key = format!("0x{}", hex::encode([0xEEu8; 32]));
    let probes_bad = server
        .replay_external_probes(unknown_key)
        .await
        .unwrap_err();
    assert_eq!(probes_bad.code(), -32602);
}

#[tokio::test]
async fn role_registry_endpoints_accept_signed_stake_and_refuse_retired_or_invalid_calls() {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, TEST_CHAIN_ID, None);

    let staker_ed = KeyPair::from_seed(&[0x51u8; 32]).expect("staker keypair");
    let staker_addr = Address::from(staker_ed.public_key_bytes());
    let min_stake = bc.state.registry.params().min_stake.max(10_000_000);
    bc.state.add_balance(
        &staker_addr,
        min_stake.saturating_mul(4).saturating_add(1_000_000),
    );

    let (server, chain) = setup_with_blockchain(bc);
    let base_fee = chain.get_base_fee().await;

    // 1. bud_registryRegister: refuse Transfer tx, accept signed Stake tx.
    let mut wrong_kind = Transaction::new_with_chain_id(
        staker_addr,
        Address::zero(),
        1_000,
        base_fee.max(10_000),
        0,
        Vec::new(),
        TEST_CHAIN_ID,
        TransactionType::Transfer,
    );
    wrong_kind.sign(&staker_ed);
    let reg_bad = server.registry_register(wrong_kind).await.unwrap_err();
    assert_eq!(reg_bad.code(), -32602);

    let mut stake_tx = Transaction::new_with_chain_id(
        staker_addr,
        Address::zero(),
        min_stake,
        base_fee.max(10_000),
        0,
        Vec::new(),
        TEST_CHAIN_ID,
        TransactionType::Stake,
    );
    stake_tx.sign(&staker_ed);
    let reg_ok = server
        .registry_register(stake_tx)
        .await
        .expect("accept signed Stake transaction through bud_registryRegister");
    assert!(reg_ok.is_object() || reg_ok.is_string());

    // 2. Retired bond mutation helpers fail closed without mutating consensus state.
    let root_before = chain.get_state_root(0).await;
    let staker_hex = format!("0x{}", staker_addr.to_hex());
    let unbond_err = server
        .registry_begin_role_bond_unbonding(staker_hex.clone(), 3)
        .await
        .unwrap_err();
    assert_eq!(unbond_err.code(), -32602);
    let withdraw_err = server
        .registry_withdraw_role_bond(staker_hex, 3)
        .await
        .unwrap_err();
    assert_eq!(withdraw_err.code(), -32602);
    assert_eq!(chain.get_state_root(0).await, root_before);

    // 3. bud_registryActiveMembers refuses negative role_id over JSON-RPC.
    let module = server.into_rpc();
    let active_bad = module
        .call::<_, serde_json::Value>("bud_registryActiveMembers", [-1i64])
        .await
        .unwrap_err();
    assert!(
        active_bad.to_string().contains("-32602") || active_bad.to_string().contains("Invalid")
    );
}
