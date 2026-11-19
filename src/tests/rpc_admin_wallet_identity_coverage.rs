//! End-to-end success and refusal coverage for operator administration, sentry
//! rotation, chain/settlement/external-domain queries, transaction bundles,
//! gateway rendering, identity profiles, market/hub template builders, and
//! local Garden creation JSON-RPC endpoints.

use crate::bns::MIN_DURATION;
use crate::chain::blockchain::Blockchain;
use crate::chain::chain_actor::{ChainActor, ChainHandle};
use crate::consensus::pow::PoWEngine;
use crate::consensus::qc::{QcFaultProof, QcProofKind};
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::core::tx_bundle::TxBundle;
use crate::cross_domain::external::ethereum::{build_deneb_update_payload, PinnedCommittee};
use crate::cross_domain::external::intake::{AdapterSpec, IntakeState, RegistrationRequest};
use crate::cross_domain::external::spec::{RawConsensusEvidence, VerificationPolicy};
use crate::cross_domain::external::tendermint::{
    validator_address_of, validator_set_commitment, vote_sign_bytes, PinnedTendermintAnchor,
    TendermintCommitEvidence, TendermintSignature, TendermintValidator,
    EVIDENCE_VERSION as TM_EVIDENCE_VERSION,
};
use crate::cross_domain::external::VersionPolicy;
use crate::crypto::key_derivation::RootSecret;
use crate::crypto::primitives::KeyPair;
use crate::crypto::scheme::SchemeStatusRegistry;
use crate::domain::types::DomainId;
use crate::garden::GardenOptions;
use crate::network::node::Node;
use crate::network::sentry::{SentryConfig, SentryPolicy};
use crate::registry::evidence::{SlashingProof, SlashingReport};
use crate::registry::role::roles;
use crate::registry::PresentationReceipt;
use crate::rpc::api::BudlumApiServer;
use crate::rpc::server::{RpcMode, RpcSecurityConfig, RpcServer};
use crate::storage::generated::{generate_content, ContentSource};
use crate::storage::manifest::ShardRef;
use crate::storage::render::{render_id, RenderFormat};
use crate::storage::ContentId;
use libp2p::PeerId;
use serde_json::Value;
use std::sync::Arc;

const TEST_CHAIN_ID: u64 = 45_262;

fn spawn_rpc(blockchain: Blockchain, mode: RpcMode) -> (RpcServer, ChainHandle) {
    let (actor, chain) = ChainActor::new(blockchain);
    tokio::spawn(Box::pin(async move {
        actor.run().await;
    }));
    let node = Node::new(chain.clone()).expect("node initialization");
    let client = node.get_client();
    let security = match mode {
        RpcMode::Operator => RpcSecurityConfig::operator_default(),
        RpcMode::Public => RpcSecurityConfig::default(),
    };
    (
        RpcServer::with_security_and_mode(chain.clone(), client, security, mode),
        chain,
    )
}

fn fresh_blockchain() -> Blockchain {
    let consensus = Arc::new(PoWEngine::new(0));
    Blockchain::new(consensus, None, TEST_CHAIN_ID, None)
}

#[tokio::test]
async fn operator_peer_ban_sentry_prune_snapshot_and_garden_endpoints_enforce_boundaries() {
    let bc = fresh_blockchain();
    let (actor, chain) = ChainActor::new(bc);
    tokio::spawn(Box::pin(async move {
        actor.run().await;
    }));

    let initial_sentry = PeerId::random();
    let rotated_sentry = PeerId::random();
    let initial_addr = format!("/ip4/127.0.0.1/tcp/41001/p2p/{initial_sentry}");
    let rotated_addr = format!("/ip4/127.0.0.1/tcp/41002/p2p/{rotated_sentry}");
    let policy = SentryPolicy::from_config(&SentryConfig {
        role: "validator".to_string(),
        sentry_peers: vec![initial_addr],
        allowed_private_cidrs: vec!["127.0.0.1/32".to_string()],
        ..Default::default()
    })
    .expect("validator sentry policy");

    let mut node = Node::new(chain.clone())
        .expect("node initialization")
        .with_sentry_policy(policy);
    let client = node.get_client();
    let node_task = tokio::spawn(async move {
        node.run().await;
    });

    let op_server = RpcServer::with_security_and_mode(
        chain.clone(),
        client.clone(),
        RpcSecurityConfig::operator_default(),
        RpcMode::Operator,
    );
    let pub_server = RpcServer::with_security_and_mode(
        chain.clone(),
        client,
        RpcSecurityConfig::default(),
        RpcMode::Public,
    );

    // 1. Peer ban / list / unban round-trip + malformed/public refusals.
    let target_peer = PeerId::random().to_string();
    let ban_ok = op_server
        .admin_ban_peer(target_peer.clone())
        .await
        .expect("operator bans valid peer id");
    assert_eq!(ban_ok["banned"].as_str(), Some(target_peer.as_str()));

    let listed = op_server
        .admin_list_banned_peers()
        .await
        .expect("operator lists banned peers");
    let peers = listed["bannedPeers"].as_array().expect("bannedPeers array");
    assert!(
        peers
            .iter()
            .any(|p| p.as_str() == Some(target_peer.as_str())),
        "banned peer must appear in list: {listed}"
    );

    let unban_ok = op_server
        .admin_unban_peer(target_peer.clone())
        .await
        .expect("operator unbans peer id");
    assert_eq!(unban_ok["unbanned"].as_str(), Some(target_peer.as_str()));

    let listed_after = op_server
        .admin_list_banned_peers()
        .await
        .expect("list banned peers after unban");
    assert!(
        !listed_after["bannedPeers"]
            .as_array()
            .expect("bannedPeers array")
            .iter()
            .any(|p| p.as_str() == Some(target_peer.as_str())),
        "unbanned peer must be cleared: {listed_after}"
    );

    let unban_pub_err = pub_server.admin_unban_peer(target_peer).await.unwrap_err();
    assert_eq!(unban_pub_err.code(), -32004);

    let unban_bad_err = op_server
        .admin_unban_peer("not-a-peer-id".to_string())
        .await
        .unwrap_err();
    assert_eq!(unban_bad_err.code(), -32602);

    // 2. Sentry status & live sentry list update.
    let sentry_before = op_server
        .admin_sentry_status()
        .await
        .expect("operator queries sentry status");
    assert_eq!(sentry_before["role"], "shielded_validator");

    let update_ok = op_server
        .admin_update_sentries(vec![rotated_addr])
        .await
        .expect("operator rotates sentry peer");
    assert_eq!(
        update_ok["activeSentries"][0].as_str(),
        Some(rotated_sentry.to_string().as_str())
    );
    assert_eq!(
        update_ok["removed"][0].as_str(),
        Some(initial_sentry.to_string().as_str())
    );
    assert_eq!(
        update_ok["added"][0]["peerId"].as_str(),
        Some(rotated_sentry.to_string().as_str())
    );

    // 3. Prune status & manual prune trigger.
    let prune_info = op_server
        .prune_status()
        .await
        .expect("prune status returns object");
    assert!(prune_info.is_object());

    let prune_run = op_server
        .request_prune(Some(64))
        .await
        .expect("operator runs bounded prune");
    assert!(prune_run.is_object());

    // 4. State snapshot: genesis success on Operator + Public/missing refusals.
    let snap_ok = op_server
        .get_state_snapshot(Some(0))
        .await
        .expect("operator reads genesis state snapshot");
    assert!(snap_ok.is_object());

    let snap_pub_err = pub_server.get_state_snapshot(Some(0)).await.unwrap_err();
    assert_eq!(snap_pub_err.code(), -32004);

    let snap_missing = op_server
        .get_state_snapshot(Some(999_999))
        .await
        .expect("out-of-range snapshot height returns JSON null");
    assert!(snap_missing.is_null());

    // 5. Local Garden creation on Operator listener + clean leave.
    let garden_opts = GardenOptions {
        listen: Some("/ip4/127.0.0.1/tcp/0".to_string()),
        round_ms: Some(200),
        presence_interval_ms: Some(200),
        host_timeout_ms: Some(1_500),
        suspend_after_ms: Some(3_000),
        ..GardenOptions::default()
    };
    let created = op_server
        .garden_create(
            "Operator Room".to_string(),
            "host".to_string(),
            Some(garden_opts),
        )
        .await
        .expect("operator creates local Garden");
    assert!(created.is_object());
    let _ = op_server.garden_leave().await;

    node_task.abort();
}

#[tokio::test]
async fn settlement_app_binding_external_domain_and_ethereum_inspect_endpoints_round_trip() {
    let mut bc = fresh_blockchain();

    // Register a Tendermint external domain so profile/status/quorum queries hit live state.
    let tm_key = KeyPair::from_seed(&[0x37u8; 32]).expect("generate validator key");
    let pub_bytes = tm_key.public_key_bytes();
    let val_addr = validator_address_of(&pub_bytes);
    let validators = vec![TendermintValidator {
        address: val_addr,
        public_key: pub_bytes,
        voting_power: 1_000,
    }];
    let valset_hash = validator_set_commitment(&validators);
    let app_hash = [0x24u8; 32];
    let parts_hash = [0x33u8; 32];
    let mut commit = TendermintCommitEvidence {
        chain_id: "coverage-chain-1".to_string(),
        height: 42,
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
        "coverage-chain-1",
        commit.height,
        commit.round,
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
        "coverage-net",
        PinnedTendermintAnchor {
            chain_id: "coverage-chain-1".to_string(),
            validator_set_hash: valset_hash,
        },
    );
    let spec = AdapterSpec::TendermintCommit {
        network: "coverage-net".to_string(),
        chain_id: "coverage-chain-1".to_string(),
        validator_set_hash: Some(valset_hash),
    };
    let adapter_id = spec.build(None, None).descriptor().id;
    let economics = IntakeState::conservative_economics(1_000_000);
    let bond_atoms = economics.required_bond_atoms();
    let poster = Address::from([0x7B; 32]);
    let domain_key = bc
        .state
        .settlement
        .external_intake
        .register_domain(
            RegistrationRequest {
                golden: RawConsensusEvidence {
                    adapter: adapter_id,
                    evidence_version: TM_EVIDENCE_VERSION,
                    network: "coverage-net".to_string(),
                    payload: tm_payload,
                    declared_height: commit.height,
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
        .expect("register external domain");
    let domain_key_hex = format!("0x{}", hex::encode(domain_key.0));

    // Bond a second prover, install a 2-of-2 strict quorum policy, and submit
    // the first signed commit at height 43 so quorum-round queries observe a
    // live open round.
    let second_prover = Address::from([0x7C; 32]);
    bc.state
        .settlement
        .external_intake
        .bond_prover(&domain_key, second_prover, bond_atoms)
        .expect("bond second prover");
    bc.state
        .settlement
        .external_intake
        .set_quorum_policy(
            &domain_key,
            crate::cross_domain::external::QuorumPolicy::strict(2, 2),
        )
        .expect("install 2-of-2 quorum policy");
    let next_height = commit.height + 1;
    let mut round_commit = commit.clone();
    round_commit.height = next_height;
    round_commit.last_block_hash = commit.block_hash;
    round_commit.app_hash = [0x25u8; 32];
    round_commit.commit_time = 1_700_000_004;
    round_commit.signatures.clear();
    round_commit.block_hash = round_commit.header_hash();
    let round_sign_bytes = vote_sign_bytes(
        "coverage-chain-1",
        next_height,
        0,
        &round_commit.block_hash,
        1,
        &parts_hash,
        (1_700_000_004, 0),
    );
    round_commit.signatures = vec![TendermintSignature {
        address: val_addr,
        timestamp_seconds: 1_700_000_004,
        timestamp_nanos: 0,
        signature: tm_key.sign(&round_sign_bytes).to_vec(),
    }];
    let round_payload = bincode::serialize(&round_commit).expect("serialize height-43 commit");
    let _ = bc.state.settlement.external_intake.submit_evidence(
        &RawConsensusEvidence {
            adapter: adapter_id,
            evidence_version: TM_EVIDENCE_VERSION,
            network: "coverage-net".to_string(),
            payload: round_payload,
            declared_height: next_height,
            declared_root: round_commit.app_hash,
            submitter: poster,
        },
        None,
    );

    // Register an AppBinding application row.
    let origin_app = b"coverage-app-v1".to_vec();
    let manifest_hash = [0x5A; 32];
    bc.state
        .settlement
        .app_binding
        .register(7, origin_app.clone(), manifest_hash, 0)
        .expect("register app-binding application");
    let app_id = crate::settlement::app_binding::app_binding_id(7, &origin_app);
    let app_id_hex = format!("0x{}", hex::encode(app_id));

    let (server, chain) = spawn_rpc(bc, RpcMode::Operator);
    let sealed = chain
        .seal_global_header()
        .await
        .expect("seal genesis global header");
    assert_eq!(sealed.global_height, 0);

    // 1. bud_getGlobalHeaderProof: valid root at height 0 + unknown root refusal.
    let hdr_proof = server
        .get_global_header_proof("domainRegistryRoot".to_string(), 0)
        .await
        .expect("global header proof for domainRegistryRoot");
    assert_eq!(hdr_proof["root"], "domainRegistryRoot");
    assert!(hdr_proof["value"].is_string());

    let bad_root = server
        .get_global_header_proof("nonexistentRootField".to_string(), 0)
        .await
        .unwrap_err();
    assert_eq!(bad_root.code(), -32602);

    // 2. bud_appBindingPaymentProof & bud_getAppBindingApplication.
    let app_ok = server
        .get_app_binding_application(app_id_hex)
        .await
        .expect("registered app-binding application returned");
    assert!(!app_ok.is_null());

    let app_bad = server
        .get_app_binding_application("0x1234".to_string())
        .await
        .unwrap_err();
    assert_eq!(app_bad.code(), -32602);

    let pay_null = server
        .app_binding_payment_proof(format!("0x{}", "11".repeat(32)))
        .await
        .expect("unknown payment id returns JSON null cleanly");
    assert!(pay_null.is_null());

    let pay_bad = server
        .app_binding_payment_proof("not-32-byte-hex".to_string())
        .await
        .unwrap_err();
    assert_eq!(pay_bad.code(), -32602);

    // 3. bud_getRelayerIntent & bud_getCrossDomainMessage.
    let intent_res = server
        .get_relayer_intent(format!("0x{}", "22".repeat(32)))
        .await
        .expect("relayer intent lookup succeeds for valid 32-byte id");
    assert!(intent_res.is_null() || intent_res.is_object());

    let intent_bad = server
        .get_relayer_intent("0xdead".to_string())
        .await
        .unwrap_err();
    assert_eq!(intent_bad.code(), -32602);

    let xdm_bad = server
        .get_cross_domain_message("0xbeef".to_string())
        .await
        .unwrap_err();
    assert_eq!(xdm_bad.code(), -32602);

    // 4. bud_getExternalDomainProfile, Status, QuorumRound, QuorumRounds.
    let ext_profile = server
        .get_external_domain_profile(domain_key_hex.clone())
        .await
        .expect("external domain profile returns registered domain");
    assert!(!ext_profile.is_null());

    let ext_profile_bad = server
        .get_external_domain_profile("bad-hex".to_string())
        .await
        .unwrap_err();
    assert_eq!(ext_profile_bad.code(), -32602);

    let ext_status = server
        .get_external_domain_status(domain_key_hex.clone())
        .await
        .expect("external domain status returns registered domain");
    assert!(!ext_status.is_null());

    let ext_status_bad = server
        .get_external_domain_status("bad-hex".to_string())
        .await
        .unwrap_err();
    assert_eq!(ext_status_bad.code(), -32602);

    let q_round = server
        .get_external_quorum_round(domain_key_hex.clone(), next_height)
        .await
        .expect("quorum round query returns active open round");
    assert!(q_round.is_object());

    let q_round_missing = server
        .get_external_quorum_round(domain_key_hex.clone(), commit.height)
        .await
        .unwrap_err();
    assert_eq!(q_round_missing.code(), -32602);

    let q_round_bad = server
        .get_external_quorum_round("0x01".to_string(), next_height)
        .await
        .unwrap_err();
    assert_eq!(q_round_bad.code(), -32602);

    let q_rounds = server
        .get_external_quorum_rounds(domain_key_hex)
        .await
        .expect("quorum rounds query returns structured object");
    assert_eq!(
        q_rounds["rounds"].as_array().map(Vec::len),
        Some(1),
        "expected 1 retained quorum round: {q_rounds}"
    );

    let q_rounds_bad = server
        .get_external_quorum_rounds("0x01".to_string())
        .await
        .unwrap_err();
    assert_eq!(q_rounds_bad.code(), -32602);

    // 5. bud_inspectEthereumUpdate: valid Deneb light-client payload + truncated refusal.
    let committee = PinnedCommittee {
        period: 4,
        aggregate_pubkey: vec![0xAA; 48],
        next_committee_root: [0xBB; 32],
    };
    let mut bits = [0u8; 64];
    bits.fill(0xFF);
    let eth_payload =
        build_deneb_update_payload(128, 160, 4, &committee, &[0xCC; 96], &bits, [0xDD; 32]);
    let inspected = server
        .inspect_ethereum_update(format!("0x{}", hex::encode(&eth_payload)))
        .await
        .expect("inspect well-formed Deneb update payload");
    assert_eq!(inspected["finalizedSlot"], 128);
    assert_eq!(inspected["attestedSlot"], 160);
    assert_eq!(inspected["participation"]["signers"], 512);
    assert_eq!(inspected["participation"]["hasSupermajority"], true);

    let eth_bad = server
        .inspect_ethereum_update("0xdeadbeef".to_string())
        .await
        .unwrap_err();
    assert_eq!(eth_bad.code(), -32602);

    // 6. bud_getDomainInfo & bud_getSovereignTemplate: direct success + refusal.
    let dom_ok = server
        .get_domain_info(0)
        .await
        .expect("settlement hub domain info returns object");
    assert!(dom_ok.is_object());

    let dom_missing = server.get_domain_info(u32::MAX - 1).await;
    if let Ok(v) = dom_missing {
        assert!(v.is_null() || v.is_object());
    }

    let sov_id: DomainId = 0;
    let sov_ok = server
        .get_sovereign_template(sov_id)
        .await
        .expect("sovereign template query returns clean JSON value");
    assert!(sov_ok.is_null() || sov_ok.is_object());

    // Wire-level JSON-RPC parameter validation for typed numeric/domain methods.
    let module = server.into_rpc();
    let dom_err = module
        .call::<_, Value>("bud_getDomainInfo", ["not-a-domain-id"])
        .await
        .unwrap_err();
    assert!(dom_err.to_string().contains("-32602") || dom_err.to_string().contains("Invalid"));

    let sov_err = module
        .call::<_, Value>("bud_getSovereignTemplate", ["not-a-domain-id"])
        .await
        .unwrap_err();
    assert!(sov_err.to_string().contains("-32602") || sov_err.to_string().contains("Invalid"));
}

#[tokio::test]
async fn wallet_gateway_passport_market_hub_and_bundle_endpoints_cover_success_and_refusal() {
    let mut bc = fresh_blockchain();

    // Fund a post-quantum composite account so its signed TxBundle is admitted atomically.
    let acct = RootSecret::derive(&[0x39; 32], "")
        .expect("derive root secret")
        .user_account(0, 0)
        .expect("derive user account");
    let sender_addr = Address::from(acct.address);
    let sender_hex = format!("0x{}", sender_addr.to_hex());
    let recipient = Address::from([0x55; 32]);
    bc.state
        .try_mint_balance(&sender_addr, 50_000_000)
        .expect("fund composite account");

    // Register a BNS name bound to a deterministic generated Avatar object so
    // gateway fetch/render and identity profile/proof-bundle endpoints execute end-to-end.
    let seed = vec![7u8; 32];
    let source: ContentSource = serde_json::from_value(serde_json::json!({
        "Generated": {
            "generator": "Avatar",
            "seed": seed,
            "output_len": 1024u32,
            "step_budget": 8000u64
        }
    }))
    .expect("deserialize deterministic Avatar descriptor");
    let ContentSource::Generated(ref avatar_spec) = source else {
        panic!("expected Generated variant");
    };
    let expected_avatar = generate_content(avatar_spec).expect("run deterministic Avatar spec");
    let shard = ShardRef::from_bytes(0, &expected_avatar);
    let base_entry = serde_json::from_value(serde_json::json!({
        "manifest_id": ContentId([0u8; 32]),
        "total_size": expected_avatar.len() as u64,
        "shard_count": 1u32,
        "shards": [shard],
    }))
    .expect("deserialize base storage entry");
    let mut tmp_map = std::mem::take(&mut bc.state.storage_registry.manifests);
    tmp_map.insert(ContentId([0u8; 32]), base_entry);
    let entry = tmp_map
        .remove(&ContentId([0u8; 32]))
        .expect("pop base entry")
        .with_source(source);
    let manifest_cid = entry.manifest_id;
    tmp_map.insert(manifest_cid, entry);
    bc.state.storage_registry.manifests = tmp_map;

    bc.state
        .bns_registry
        .register("studio.bud".to_string(), sender_addr, 0, MIN_DURATION)
        .expect("register studio.bud");
    bc.state
        .bns_registry
        .set_storage("studio.bud", sender_addr, manifest_cid.0, 0, 0)
        .expect("bind studio.bud to content root");

    let (server, chain) = spawn_rpc(bc, RpcMode::Operator);

    // 1. bud_getAccountProof.
    let acct_proof = server
        .get_account_proof(sender_hex.clone())
        .await
        .expect("account Merkle proof resolves funded sender");
    assert!(acct_proof.is_object());

    // 2. bud_gatewayFetchContent & bud_gatewayRenderContent.
    let fetched_hex = server
        .gateway_fetch_content("studio.bud".to_string())
        .await
        .expect("gateway regenerates and verifies studio.bud bytes");
    assert_eq!(fetched_hex, hex::encode(&expected_avatar));

    let fetch_missing = server
        .gateway_fetch_content("unregistered-name.bud".to_string())
        .await
        .unwrap_err();
    assert_eq!(fetch_missing.code(), -32000);

    let rendered = server
        .gateway_render_content("studio.bud".to_string(), "svg".to_string())
        .await
        .expect("gateway renders studio.bud into deterministic SVG");
    let svg_bytes =
        hex::decode(rendered["bytes"].as_str().expect("hex svg bytes")).expect("valid svg hex");
    assert!(svg_bytes.starts_with(b"<svg"));
    assert_eq!(
        rendered["renderId"].as_str(),
        Some(hex::encode(render_id(&RenderFormat::Svg, &svg_bytes)).as_str())
    );

    let render_bad_fmt = server
        .gateway_render_content("studio.bud".to_string(), "bmp:64".to_string())
        .await
        .unwrap_err();
    assert_eq!(render_bad_fmt.code(), -32602);

    // 3. bud_passportGetProfile & bud_passportGetProofBundle.
    let profile = server
        .passport_get_profile("studio.bud".to_string())
        .await
        .expect("identity profile resolves studio.bud");
    assert!(profile.is_object());

    let profile_bad = server
        .passport_get_profile("INVALID NAME!".to_string())
        .await
        .unwrap_err();
    assert_eq!(profile_bad.code(), -32602);

    let proof_bundle = server
        .passport_get_proof_bundle("studio.bud".to_string())
        .await
        .expect("identity proof bundle builds for studio.bud");
    assert!(proof_bundle.is_object());

    let bundle_bad_name = server
        .passport_get_proof_bundle("INVALID NAME!".to_string())
        .await
        .unwrap_err();
    assert_eq!(bundle_bad_name.code(), -32602);

    // 4. bud_marketPrepareOffer, bud_marketPreparePurchase, bud_hubPrepareRegister.
    let cid_hex = format!("0x{}", hex::encode(manifest_cid.0));
    let offer_ok = server
        .market_prepare_offer(sender_hex.clone(), cid_hex.clone(), 2_500)
        .await
        .expect("market offer template builds");
    assert!(offer_ok["tx_template"].is_object());

    let offer_bad = server
        .market_prepare_offer(sender_hex.clone(), "0x1234".to_string(), 2_500)
        .await
        .unwrap_err();
    assert_eq!(offer_bad.code(), -32602);

    let purchase_ok = server
        .market_prepare_purchase(sender_hex.clone(), 1)
        .await
        .expect("market purchase template builds");
    assert!(purchase_ok["tx_template"].is_object());

    let purchase_bad = server
        .market_prepare_purchase("bad-buyer".to_string(), 1)
        .await
        .unwrap_err();
    assert_eq!(purchase_bad.code(), -32602);

    // 5. bud_sendTxBundle: atomic post-quantum bundle admission + tampered refusal.
    let make_leg = |nonce: u64, amount: u64| {
        Transaction::new_with_chain_id(
            Address::zero(),
            recipient,
            amount,
            1_000,
            nonce,
            Vec::new(),
            TEST_CHAIN_ID,
            TransactionType::Transfer,
        )
    };
    let registry = SchemeStatusRegistry::genesis();
    let mut bad_bundle = TxBundle::sign(
        &registry,
        &acct.signing,
        &acct.recovery_public_key,
        vec![make_leg(0, 100), make_leg(1, 200)],
        &[0x11; 32],
    )
    .expect("sign test bundle");
    bad_bundle.members[1].amount = 999_999;
    let bundle_err = server.send_tx_bundle(bad_bundle).await.unwrap_err();
    assert_eq!(bundle_err.code(), -32602);
    assert_eq!(
        chain.get_mempool_size().await,
        0,
        "tampered bundle must leave mempool untouched"
    );

    let good_bundle = TxBundle::sign(
        &registry,
        &acct.signing,
        &acct.recovery_public_key,
        vec![make_leg(0, 250)],
        &[0x22; 32],
    )
    .expect("sign valid bundle");
    let admitted = server
        .send_tx_bundle(good_bundle)
        .await
        .expect("valid atomic bundle admitted to pool");
    assert_eq!(admitted.len(), 1);
    assert_eq!(chain.get_mempool_size().await, 1);

    // 6. bud_atlasGetWalletContext & bud_hubPrepareRegister over the JSON-RPC module.
    let module = server.into_rpc();
    let wallet_ctx = module
        .call::<_, Value>("bud_atlasGetWalletContext", [sender_hex.clone()])
        .await
        .expect("wallet context resolves funded sender");
    assert!(wallet_ctx.is_object());

    let wallet_bad = module
        .call::<_, Value>("bud_atlasGetWalletContext", ["not-an-address"])
        .await
        .unwrap_err();
    assert!(
        wallet_bad.to_string().contains("-32602") || wallet_bad.to_string().contains("Invalid")
    );

    let hub_ok = module
        .call::<_, Value>(
            "bud_hubPrepareRegister",
            [
                sender_hex.as_str(),
                "Studio Directory",
                "Infrastructure",
                "https://studio.example",
                cid_hex.as_str(),
            ],
        )
        .await
        .expect("hub register template builds");
    assert!(hub_ok["tx_template"].is_object());

    let hub_bad = module
        .call::<_, Value>(
            "bud_hubPrepareRegister",
            [
                "invalid-dev",
                "Studio Directory",
                "Infrastructure",
                "https://studio.example",
                cid_hex.as_str(),
            ],
        )
        .await
        .unwrap_err();
    assert!(hub_bad.to_string().contains("-32602") || hub_bad.to_string().contains("Invalid"));
}

#[tokio::test]
async fn identity_fault_slashing_and_chain_query_endpoints_refuse_malformed_requests() {
    let (server, _chain) = spawn_rpc(fresh_blockchain(), RpcMode::Operator);

    // 1. Direct handler refusals on identity, QC fault proof, and slashing report doors.
    let cred_err = server
        .identity_credential("not-a-32-byte-credential-id".to_string())
        .await
        .unwrap_err();
    assert_eq!(cred_err.code(), -32602);

    let receipt = PresentationReceipt {
        requester: Address::from([0x11; 32]),
        subject: Address::from([0x22; 32]),
        document_digest: [0x33; 32],
        epoch: 0,
        entries: Vec::new(),
        subject_public_key: Vec::new(),
        signature: Vec::new(),
    };
    let pres_err = server
        .identity_verify_presentation(receipt, "bad-requester-hex".to_string(), "0x00".to_string())
        .await
        .unwrap_err();
    assert_eq!(pres_err.code(), -32602);

    let qc_proof = QcFaultProof {
        version: 99,
        epoch: 0,
        checkpoint_height: 0,
        checkpoint_hash: "00".repeat(32),
        validator_index: 0,
        validator_address: Address::from([0x44; 32]).to_hex(),
        kind: QcProofKind::InvalidDilithiumV1 {
            pq_signature: vec![0u8; 8],
            merkle_proof: Vec::new(),
            leaf_index: 0,
        },
    };
    let qc_err = server.submit_qc_fault_proof(qc_proof).await.unwrap_err();
    assert_eq!(qc_err.code(), -32602);

    let slash_report = SlashingReport::new(
        Address::from([0x66; 32]),
        roles::VALIDATOR,
        SlashingProof::Liveness {
            window_start_epoch: 0,
            window_end_epoch: 1,
            missed: 10,
            expected: 10,
        },
        Some(Address::from([0x77; 32])),
    );
    let slash_err = server
        .submit_slashing_report(slash_report)
        .await
        .unwrap_err();
    assert_eq!(slash_err.code(), -32602);

    // 2. Wire-level JSON-RPC parameter refusals on total read/precheck methods.
    let module = server.into_rpc();
    fn is_invalid_params(err: &impl std::fmt::Display) -> bool {
        let msg = err.to_string();
        msg.contains("-32602") || msg.contains("Invalid")
    }

    let blk_hash_err = module
        .call::<_, Value>("bud_getBlockByHash", [123u64])
        .await
        .unwrap_err();
    assert!(is_invalid_params(&blk_hash_err), "{blk_hash_err}");

    let blk_num_err = module
        .call::<_, Value>("bud_getBlockByNumber", ["not-a-height"])
        .await
        .unwrap_err();
    assert!(is_invalid_params(&blk_num_err), "{blk_num_err}");

    let gh_err = module
        .call::<_, Value>("bud_getGlobalHeader", ["not-a-height"])
        .await
        .unwrap_err();
    assert!(is_invalid_params(&gh_err), "{gh_err}");

    let tx_hash_err = module
        .call::<_, Value>("bud_getTransactionByHash", [123u64])
        .await
        .unwrap_err();
    assert!(is_invalid_params(&tx_hash_err), "{tx_hash_err}");

    let rcpt_err = module
        .call::<_, Value>("bud_getTransactionReceipt", [123u64])
        .await
        .unwrap_err();
    assert!(is_invalid_params(&rcpt_err), "{rcpt_err}");

    let del_err = module
        .call::<_, Value>("bud_getValidatorDelegations", ["not-an-address"])
        .await
        .unwrap_err();
    assert!(is_invalid_params(&del_err), "{del_err}");

    let val_err = module
        .call::<_, Value>("bud_validatorProfile", ["not-an-address"])
        .await
        .unwrap_err();
    assert!(is_invalid_params(&val_err), "{val_err}");

    let precheck_err = module
        .call::<_, Value>("bud_txPrecheck", ["not-a-transaction"])
        .await
        .unwrap_err();
    assert!(is_invalid_params(&precheck_err), "{precheck_err}");
}
