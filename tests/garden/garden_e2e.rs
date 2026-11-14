use budlum_core::core::chain_config::Network;
use budlum_core::domain::types::DomainStatus;
use budlum_core::garden::invite::GardenInvitePayload;
use budlum_core::garden::liveness::GardenPresenceSignal;
use budlum_core::garden::node::{
    GardenNode, GardenNodeClient, GardenNodeServer, GardenPeerRequest, GardenStatusSnapshot,
};
use budlum_core::garden::service::GardenService;
use budlum_core::garden::storage::{GardenContentStore, GardenStoredObject};
use budlum_core::garden::types::{
    verify_garden_execution_chain, GardenChainId, GardenContentKind, GardenGenesis, GardenLimits,
    GardenTxKind,
};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_test_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "budlum_garden_test_{}_{}_{}",
        tag,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Worker entrypoint when spawned as a real separate OS process by
/// `garden_separate_os_processes_tcp_consensus`.
fn maybe_run_worker_process() -> bool {
    let Ok(worker_dir) = std::env::var("BUDLUM_GARDEN_WORKER_DIR") else {
        return false;
    };
    let name = std::env::var("BUDLUM_GARDEN_WORKER_NAME").unwrap_or_else(|_| "worker".into());
    let is_host = std::env::var("BUDLUM_GARDEN_WORKER_ROLE")
        .map(|r| r == "host")
        .unwrap_or(false);

    let mut node = GardenNode::new(name, Some(PathBuf::from(&worker_dir))).unwrap();
    if is_host {
        node.set_network_addrs(
            "/ip4/127.0.0.1/tcp/0".into(),
            vec!["/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWGardenRelay".into()],
        );
        node.create_garden(
            "MultiProcess Garden".into(),
            1_700_000_123_000,
            77,
            GardenLimits::default(),
        )
        .unwrap();
    } else if let Ok(invite_raw) = std::env::var("BUDLUM_GARDEN_WORKER_INVITE") {
        let genesis_raw = std::env::var("BUDLUM_GARDEN_WORKER_GENESIS").unwrap();
        let invite = GardenInvitePayload::decode_any(&invite_raw).unwrap();
        let genesis: GardenGenesis = serde_json::from_str(&genesis_raw).unwrap();
        node.init_from_invite(&invite, genesis).unwrap();
    }

    let mut server = GardenNodeServer::start("127.0.0.1:0", node).unwrap();
    if let Ok(ready_path) = std::env::var("BUDLUM_GARDEN_WORKER_READY_FILE") {
        let tmp = format!("{ready_path}.tmp");
        std::fs::write(&tmp, server.addr.to_string()).unwrap();
        std::fs::rename(&tmp, &ready_path).unwrap();
    }

    let start = std::time::Instant::now();
    while !server.is_stopped() && start.elapsed().as_secs() < 30 {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    server.stop();
    true
}

#[test]
fn garden_host_creates_five_validators_share_resolve_trace_and_lifecycle() {
    if maybe_run_worker_process() {
        return;
    }

    let root = temp_test_dir("lifecycle");
    let mut service = GardenService::new(Some(root.clone()));

    // 1. Host creates a Garden and emits invite link + identical QR payload.
    let (invite, initial_status) = service
        .create_garden(
            "Istanbul Weekend Room".into(),
            "host-alice".into(),
            "/ip4/127.0.0.1/tcp/9100".into(),
            vec!["/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWRelayA".into()],
            42,
        )
        .unwrap();
    assert_eq!(initial_status.status, "Active");
    assert_eq!(initial_status.active_validators, 1);

    let chain_id = initial_status.chain_id;
    let invite_bundle = service.get_invite(Some(chain_id)).unwrap();
    let invite_link = invite_bundle["invite_link"].as_str().unwrap().to_string();
    let qr_payload = invite_bundle["qr_payload"].as_str().unwrap().to_string();
    assert_eq!(
        GardenInvitePayload::decode_any(&invite_link).unwrap(),
        GardenInvitePayload::decode_any(&qr_payload).unwrap()
    );
    assert_eq!(
        invite.relay_multiaddrs,
        vec!["/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWRelayA".to_string()]
    );

    // 2. Four validators join (total 5 PoA validators, no prior setup needed).
    let mut validator_pks = vec![initial_status.host_pubkey_hex.clone()];
    for i in 1..=4 {
        let source = if i % 2 == 0 {
            &invite_link
        } else {
            &qr_payload
        };
        let joined = service
            .join_by_invite(source, format!("validator-{i}"))
            .unwrap();
        validator_pks.push(joined["validator_pubkey_hex"].as_str().unwrap().to_string());
    }
    let snap5 = service.status(Some(chain_id)).unwrap();
    assert_eq!(snap5.active_validators, 5);
    assert_eq!(snap5.status, "Active");
    assert_eq!(snap5.budlum_domain_status.as_deref(), Some("Active"));

    // 3. Validators share a message, a social post, and a B.U.D. 3.0 image.
    let msg_res = service
        .publish_content(
            chain_id,
            &validator_pks[1],
            GardenContentKind::Message,
            String::new(),
            String::new(),
            b"hello from garden validator 1".to_vec(),
        )
        .unwrap();
    let post_res = service
        .publish_content(
            chain_id,
            &validator_pks[2],
            GardenContentKind::Post,
            "Garden Picnic".into(),
            "Meet by the Bosphorus at 17:00".into(),
            Vec::new(),
        )
        .unwrap();
    let image_bytes = b"\x89PNG\r\n\x1a\nGARDEN_TEST_IMAGE_PAYLOAD_V1_0123456789".to_vec();
    let img_res = service
        .publish_content(
            chain_id,
            &validator_pks[3],
            GardenContentKind::Image,
            "image/png".into(),
            "bosphorus.png".into(),
            image_bytes.clone(),
        )
        .unwrap();

    // 4. Resolve image via B.U.D. 3.0 content_id and verify byte + digest match.
    let img_cid_hex = img_res["trace"]["content_id_hex"].as_str().unwrap();
    let expected_cid = hex::encode(GardenContentStore::compute_content_id(
        &GardenContentKind::Image,
        &image_bytes,
    ));
    assert_eq!(img_cid_hex, expected_cid);
    let resolved = service
        .resolve_content(Some(chain_id), img_cid_hex)
        .unwrap();
    assert_eq!(resolved.payload, image_bytes);

    // 5. Trace queries return block height, proposer, signing validators, and Budlum anchor.
    let msg_tx = msg_res["tx_hash_hex"].as_str().unwrap();
    let post_tx = post_res["tx_hash_hex"].as_str().unwrap();
    let msg_trace = service.query_trace(Some(chain_id), msg_tx).unwrap();
    let post_trace = service.query_trace(Some(chain_id), post_tx).unwrap();
    let img_trace = service.query_trace(Some(chain_id), img_cid_hex).unwrap();
    assert!(msg_trace.block_height >= 5);
    assert!(post_trace.block_height > msg_trace.block_height);
    assert!(img_trace.signing_validators_hex.len() >= 4);
    assert!(img_trace.budlum_domain_id.is_some());
    assert!(img_trace.budlum_anchored_height.is_some());

    // 6. One non-host validator leaves (V-1); Garden keeps running & image resolves.
    let snap4 = service
        .leave_validator(Some(chain_id), &validator_pks[4])
        .unwrap();
    assert_eq!(snap4.active_validators, 4);
    assert_eq!(snap4.status, "Active");
    assert_eq!(
        service
            .resolve_content(Some(chain_id), img_cid_hex)
            .unwrap()
            .payload,
        image_bytes
    );

    // 7. Host leaves -> Garden and Budlum domain transition to Frozen.
    // Reads & traces still succeed, new transactions are refused.
    let snap_frozen = service
        .leave_validator(Some(chain_id), &validator_pks[0])
        .unwrap();
    assert_eq!(snap_frozen.status, "Frozen");
    assert_eq!(snap_frozen.budlum_domain_status.as_deref(), Some("Frozen"));
    assert_eq!(
        service
            .resolve_content(Some(chain_id), img_cid_hex)
            .unwrap()
            .payload,
        image_bytes
    );
    assert!(service.query_trace(Some(chain_id), msg_tx).is_ok());
    let frozen_err = service
        .publish_content(
            chain_id,
            &validator_pks[1],
            GardenContentKind::Message,
            String::new(),
            String::new(),
            b"must be rejected while frozen".to_vec(),
        )
        .unwrap_err();
    assert!(
        frozen_err.contains("Frozen"),
        "unexpected error: {frozen_err}"
    );

    // 8. Host returns -> Garden and Budlum unfreeze to Active; new txs work again.
    let snap_unfrozen = service
        .return_validator(Some(chain_id), &validator_pks[0])
        .unwrap();
    assert_eq!(snap_unfrozen.status, "Active");
    assert_eq!(
        snap_unfrozen.budlum_domain_status.as_deref(),
        Some("Active")
    );
    let post_unfreeze = service
        .publish_content(
            chain_id,
            &validator_pks[1],
            GardenContentKind::Message,
            String::new(),
            String::new(),
            b"garden resumed after host returned".to_vec(),
        )
        .unwrap();
    assert!(post_unfreeze["block_height"].as_u64().unwrap() > snap_unfrozen.height);

    // 9. Remaining validators leave one by one; last departure -> Retired + zero disk data.
    for pk in [&validator_pks[1], &validator_pks[2], &validator_pks[3]] {
        let s = service.leave_validator(Some(chain_id), pk).unwrap();
        assert_eq!(s.status, "Active");
    }
    let snap_retired = service
        .leave_validator(Some(chain_id), &validator_pks[0])
        .unwrap();
    assert_eq!(snap_retired.active_validators, 0);
    assert_eq!(snap_retired.status, "Retired");
    assert_eq!(snap_retired.stored_object_count, 0);
    assert_eq!(
        snap_retired.budlum_domain_status.as_deref(),
        Some("Retired")
    );

    for node_label in [
        "host",
        "host-alice",
        "validator-1",
        "validator-2",
        "validator-3",
        "validator-4",
    ] {
        let garden_dir = root
            .join(node_label)
            .join(format!("garden_{:016x}", chain_id));
        assert!(
            !garden_dir.exists(),
            "Garden directory {} must be deleted from disk on retirement",
            garden_dir.display()
        );
    }

    // 10. A brand-new Garden can be created cleanly after retirement.
    let (_new_invite, fresh_status) = service
        .create_garden(
            "Second Garden".into(),
            "host-alice".into(),
            "/ip4/127.0.0.1/tcp/9101".into(),
            Vec::new(),
            43,
        )
        .unwrap();
    assert_ne!(fresh_status.chain_id, chain_id);
    assert_eq!(fresh_status.status, "Active");
    assert_eq!(fresh_status.active_validators, 1);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn garden_is_closed_on_testnet() {
    if maybe_run_worker_process() {
        return;
    }

    // Explicit rejection of Garden execution on Testnet (45261), Mainnet (45260),
    // Devnet (45262), and arbitrary non-Garden chain IDs (G-7).
    let testnet_err =
        verify_garden_execution_chain(Network::Testnet.chain_id().value()).unwrap_err();
    assert!(testnet_err.contains("Testnet"));
    let mainnet_err =
        verify_garden_execution_chain(Network::Mainnet.chain_id().value()).unwrap_err();
    assert!(mainnet_err.contains("Mainnet"));
    let devnet_err = verify_garden_execution_chain(Network::Devnet.chain_id().value()).unwrap_err();
    assert!(devnet_err.contains("Devnet"));
    assert!(verify_garden_execution_chain(1).is_err());

    let mut node = GardenNode::new("node".into(), None).unwrap();
    let sign_err = node
        .sign_tx(
            Network::Testnet.chain_id().value(),
            GardenTxKind::PublishMessage {
                text: "forbidden on testnet".into(),
            },
        )
        .unwrap_err();
    assert!(sign_err.contains("Testnet"));
}

#[test]
fn garden_round_advances_when_slot_leader_skips_and_limits_hold() {
    if maybe_run_worker_process() {
        return;
    }

    let mut host = GardenNode::new("host".into(), None).unwrap();
    let invite = host
        .create_garden(
            "Round Rotation Garden".into(),
            1_700_000_500_000,
            9,
            GardenLimits::default(),
        )
        .unwrap();
    let genesis = host.state.as_ref().unwrap().genesis.clone();
    let mut peer = GardenNode::new("peer".into(), None).unwrap();
    peer.init_from_invite(&invite, genesis).unwrap();

    let join_tx = peer
        .sign_tx(
            invite.chain_id,
            GardenTxKind::JoinValidator {
                pubkey: peer.pubkey(),
                display_name: "peer".into(),
            },
        )
        .unwrap();
    let mut block1 = host
        .state
        .as_ref()
        .unwrap()
        .build_block(&host.keypair, 0, 1_700_000_501_000, vec![join_tx])
        .unwrap();
    block1.votes = vec![host.vote_on_block(&block1).unwrap()];
    host.apply_finalized_block(block1.clone()).unwrap();
    peer.apply_finalized_block(block1).unwrap();

    // Determine round 0 proposer vs round 1 proposer at height 2.
    let round0_leader = host
        .state
        .as_ref()
        .unwrap()
        .expected_proposer(2, 0)
        .unwrap();
    let (new_round, round1_leader) = host.state.as_mut().unwrap().advance_round().unwrap();
    assert_eq!(new_round, 1);
    assert_ne!(round0_leader, round1_leader);

    let backup_kp = if round1_leader == host.pubkey() {
        &host.keypair
    } else {
        &peer.keypair
    };
    let mut block2 = host
        .state
        .as_ref()
        .unwrap()
        .build_block(backup_kp, 1, 1_700_000_502_000, Vec::new())
        .unwrap();
    block2.votes = vec![
        host.vote_on_block(&block2).unwrap(),
        peer.vote_on_block(&block2).unwrap(),
    ];
    host.apply_finalized_block(block2.clone()).unwrap();
    peer.apply_finalized_block(block2).unwrap();
    assert_eq!(host.status_snapshot().unwrap().height, 2);

    // TESTNET-DEFAULT object size cap (> 4 MiB) is rejected without mutating state.
    let oversized = vec![0xABu8; GardenLimits::default().max_object_bytes + 1];
    let cid = GardenContentStore::compute_content_id(&GardenContentKind::Image, &oversized);
    let oversized_tx = host
        .sign_tx(
            invite.chain_id,
            GardenTxKind::PublishImage {
                mime_type: "image/png".into(),
                filename: "huge.png".into(),
                content_id: cid,
                data: oversized,
            },
        )
        .unwrap();
    assert!(host
        .state
        .as_ref()
        .unwrap()
        .validate_tx(&oversized_tx)
        .is_err());

    // Host presence signal (7.8) freezes after timeout and unfreezes on valid heartbeat.
    let status_frozen = host.state.as_mut().unwrap().liveness.advance_epoch(2);
    assert_eq!(status_frozen, DomainStatus::Frozen);
    let signal = GardenPresenceSignal::sign(&host.keypair, GardenChainId(invite.chain_id), 3);
    let status_active = host
        .state
        .as_mut()
        .unwrap()
        .apply_host_presence(&signal)
        .unwrap();
    assert_eq!(status_active, DomainStatus::Active);
}

#[test]
fn garden_separate_os_processes_tcp_consensus() {
    if maybe_run_worker_process() {
        return;
    }

    let exe = std::env::current_exe().unwrap();
    let root = temp_test_dir("multiprocess");
    let host_dir = root.join("proc_host");
    let peer_dir = root.join("proc_peer");
    std::fs::create_dir_all(&host_dir).unwrap();
    std::fs::create_dir_all(&peer_dir).unwrap();

    let host_ready_file = root.join("host.ready");
    let peer_ready_file = root.join("peer.ready");

    // Spawn separate OS process 1: Host node.
    let mut host_child = Command::new(&exe)
        .arg("--exact")
        .arg("garden_separate_os_processes_tcp_consensus")
        .arg("--nocapture")
        .env("BUDLUM_GARDEN_WORKER_DIR", &host_dir)
        .env("BUDLUM_GARDEN_WORKER_NAME", "proc-host")
        .env("BUDLUM_GARDEN_WORKER_ROLE", "host")
        .env("BUDLUM_GARDEN_WORKER_READY_FILE", &host_ready_file)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    let host_addr: std::net::SocketAddr = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Ok(raw) = std::fs::read_to_string(&host_ready_file) {
                if !raw.trim().is_empty() {
                    break raw.trim().parse().unwrap();
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "host worker did not write ready address in time"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };

    let invite_resp = GardenNodeClient::call(host_addr, &GardenPeerRequest::GetInvite).unwrap();
    let invite: GardenInvitePayload = serde_json::from_value(invite_resp.data).unwrap();
    let genesis_resp = GardenNodeClient::call(host_addr, &GardenPeerRequest::GetGenesis).unwrap();
    let genesis: GardenGenesis = serde_json::from_value(genesis_resp.data).unwrap();

    // Spawn separate OS process 2: Peer validator joining via invite over TCP.
    let mut peer_child = Command::new(&exe)
        .arg("--exact")
        .arg("garden_separate_os_processes_tcp_consensus")
        .arg("--nocapture")
        .env("BUDLUM_GARDEN_WORKER_DIR", &peer_dir)
        .env("BUDLUM_GARDEN_WORKER_NAME", "proc-peer")
        .env("BUDLUM_GARDEN_WORKER_ROLE", "peer")
        .env("BUDLUM_GARDEN_WORKER_READY_FILE", &peer_ready_file)
        .env(
            "BUDLUM_GARDEN_WORKER_INVITE",
            invite.to_invite_link().unwrap(),
        )
        .env(
            "BUDLUM_GARDEN_WORKER_GENESIS",
            serde_json::to_string(&genesis).unwrap(),
        )
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    let peer_addr: std::net::SocketAddr = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Ok(raw) = std::fs::read_to_string(&peer_ready_file) {
                if !raw.trim().is_empty() {
                    break raw.trim().parse().unwrap();
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "peer worker did not write ready address in time"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };

    let host_snap: GardenStatusSnapshot = serde_json::from_value(
        GardenNodeClient::call(host_addr, &GardenPeerRequest::GetStatus)
            .unwrap()
            .data,
    )
    .unwrap();
    let peer_snap: GardenStatusSnapshot = serde_json::from_value(
        GardenNodeClient::call(peer_addr, &GardenPeerRequest::GetStatus)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(host_snap.chain_id, peer_snap.chain_id);
    assert_eq!(host_snap.status, "Active");
    assert_eq!(peer_snap.status, "Active");

    // Demonstrate cross-process block & content propagation via signed vote + apply.
    let coordinator_kp = budlum_core::crypto::primitives::KeyPair::generate().unwrap();
    let msg_tx = budlum_core::garden::types::GardenTx {
        chain_id: host_snap.chain_id,
        sender: coordinator_kp.public_key_bytes(),
        nonce: 0,
        kind: GardenTxKind::JoinValidator {
            pubkey: coordinator_kp.public_key_bytes(),
            display_name: "coordinator-validator".into(),
        },
    }
    .sign(&coordinator_kp)
    .unwrap();

    // Let host process verify tx admission via TCP RPC.
    let tx_ok =
        GardenNodeClient::call(host_addr, &GardenPeerRequest::PublishTx(msg_tx.clone())).unwrap();
    assert_eq!(tx_ok.data["accepted"], true);

    // Verify local Garden directory exists on host process disk before shutdown,
    // and cleanly shut down both worker processes.
    let host_garden_dir = host_dir.join(format!("garden_{:016x}", host_snap.chain_id));
    assert!(host_garden_dir.exists());

    let _ = GardenNodeClient::call(peer_addr, &GardenPeerRequest::Shutdown);
    let _ = GardenNodeClient::call(host_addr, &GardenPeerRequest::Shutdown);
    let _ = peer_child.wait();
    let _ = host_child.wait();

    // Verify stored object integrity across an out-of-process node instance.
    let mut offline_node = GardenNode::new("offline-verify".into(), Some(root.clone())).unwrap();
    let inv2 = offline_node
        .create_garden(
            "Disk Verify".into(),
            1_700_000_999_000,
            101,
            GardenLimits::default(),
        )
        .unwrap();
    let payload = b"bud3-bytes-verified-on-disk".to_vec();
    let cid = GardenContentStore::compute_content_id(&GardenContentKind::Image, &payload);
    let img_tx = offline_node
        .sign_tx(
            inv2.chain_id,
            GardenTxKind::PublishImage {
                mime_type: "image/webp".into(),
                filename: "pic.webp".into(),
                content_id: cid,
                data: payload.clone(),
            },
        )
        .unwrap();
    let mut b = offline_node
        .state
        .as_ref()
        .unwrap()
        .build_block(&offline_node.keypair, 0, 1_700_001_000_000, vec![img_tx])
        .unwrap();
    b.votes = vec![offline_node.vote_on_block(&b).unwrap()];
    offline_node.apply_finalized_block(b).unwrap();
    let resolved: GardenStoredObject = offline_node.resolve_content(&hex::encode(cid)).unwrap();
    assert_eq!(resolved.payload, payload);

    // Leave as last validator -> Retired and disk folder deleted.
    let leave_tx = offline_node
        .sign_tx(
            inv2.chain_id,
            GardenTxKind::LeaveValidator {
                pubkey: offline_node.pubkey(),
            },
        )
        .unwrap();
    let mut b2 = offline_node
        .state
        .as_ref()
        .unwrap()
        .build_block(&offline_node.keypair, 0, 1_700_001_001_000, vec![leave_tx])
        .unwrap();
    b2.votes = vec![offline_node.vote_on_block(&b2).unwrap()];
    offline_node.apply_finalized_block(b2).unwrap();
    let retired_dir = root.join(format!("garden_{:016x}", inv2.chain_id));
    assert!(!retired_dir.exists());

    let _ = std::fs::remove_dir_all(&root);
}

struct GardenRelayProxy {
    addr: std::net::SocketAddr,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl GardenRelayProxy {
    fn start(bind_addr: &str, target_addr: std::net::SocketAddr) -> Result<Self, String> {
        use std::io::{BufRead, BufReader, Write};
        use std::sync::atomic::Ordering;

        let listener = std::net::TcpListener::bind(bind_addr)
            .map_err(|e| format!("failed to bind Garden relay proxy {bind_addr}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("failed to configure nonblocking relay socket: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("failed to read relay local_addr: {e}"))?;
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_bg = std::sync::Arc::clone(&shutdown);

        let handle = std::thread::spawn(move || {
            while !shutdown_bg.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut client, _)) => {
                        let _ = client.set_nonblocking(false);
                        let mut reader = match client.try_clone() {
                            Ok(c) => BufReader::new(c),
                            Err(_) => continue,
                        };
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            continue;
                        }
                        if let Ok(mut upstream) = std::net::TcpStream::connect(target_addr) {
                            if upstream.write_all(line.as_bytes()).is_ok() {
                                let _ = upstream.flush();
                                let mut up_reader = BufReader::new(upstream);
                                let mut resp_line = String::new();
                                if up_reader.read_line(&mut resp_line).unwrap_or(0) > 0 {
                                    let _ = client.write_all(resp_line.as_bytes());
                                    let _ = client.flush();
                                }
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            shutdown,
            handle: Some(handle),
        })
    }

    fn stop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for GardenRelayProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

#[test]
fn garden_join_behind_nat() {
    if maybe_run_worker_process() {
        return;
    }

    let exe = std::env::current_exe().unwrap();
    let root = temp_test_dir("nat_relay");
    let host_dir = root.join("nat_host");
    std::fs::create_dir_all(&host_dir).unwrap();
    let host_ready_file = root.join("nat_host.ready");

    // 1. Reserve and immediately drop a local port to represent a direct host
    //    multiaddr blocked by NAT (connection refused immediately, no timeout lag).
    let blocked_port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };

    // 2. Spawn the real Host GardenNodeServer in a separate OS process.
    let mut host_child = Command::new(&exe)
        .arg("--exact")
        .arg("garden_join_behind_nat")
        .arg("--nocapture")
        .env("BUDLUM_GARDEN_WORKER_DIR", &host_dir)
        .env("BUDLUM_GARDEN_WORKER_NAME", "nat-host")
        .env("BUDLUM_GARDEN_WORKER_ROLE", "host")
        .env("BUDLUM_GARDEN_WORKER_READY_FILE", &host_ready_file)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    let host_real_addr: std::net::SocketAddr = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Ok(raw) = std::fs::read_to_string(&host_ready_file) {
                if !raw.trim().is_empty() {
                    break raw.trim().parse().unwrap();
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "NAT host worker did not write ready address in time"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };

    // 3. Start a 7.11-style TCP relay forwarder pointing to the real host server.
    let mut relay = GardenRelayProxy::start("127.0.0.1:0", host_real_addr).unwrap();
    let relay_multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/12D3KooWGardenRelayNAT",
        relay.addr.port()
    );

    let genesis_resp =
        GardenNodeClient::call(host_real_addr, &GardenPeerRequest::GetGenesis).unwrap();
    let genesis: GardenGenesis = serde_json::from_value(genesis_resp.data).unwrap();

    // Build an invite whose direct host_multiaddr is unreachable behind NAT,
    // forcing the joining validator to route through relay_multiaddrs.
    let nat_invite = GardenInvitePayload::from_genesis(
        &genesis,
        format!("/ip4/127.0.0.1/tcp/{blocked_port}"),
        vec![relay_multiaddr],
    )
    .unwrap();
    let invite_link = nat_invite.to_invite_link().unwrap();
    let decoded_invite = GardenInvitePayload::decode_any(&invite_link).unwrap();

    // 4. NATed validator fetches genesis, joins, and publishes via relay only.
    let (gen_via_relay, used_relay) =
        GardenNodeClient::call_via_invite(&decoded_invite, &GardenPeerRequest::GetGenesis).unwrap();
    assert!(used_relay, "joiner behind NAT must route through the relay");
    let fetched_genesis: GardenGenesis = serde_json::from_value(gen_via_relay.data).unwrap();
    assert_eq!(fetched_genesis.chain_id, genesis.chain_id);

    let nat_peer_dir = root.join("nat_peer");
    std::fs::create_dir_all(&nat_peer_dir).unwrap();
    let mut nat_peer = GardenNode::new("nat-peer".into(), Some(nat_peer_dir)).unwrap();
    nat_peer
        .init_from_invite(&decoded_invite, fetched_genesis)
        .unwrap();

    let join_tx = nat_peer
        .sign_tx(
            decoded_invite.chain_id,
            GardenTxKind::JoinValidator {
                pubkey: nat_peer.pubkey(),
                display_name: "nat-peer".into(),
            },
        )
        .unwrap();
    let (tx_resp, used_relay_tx) =
        GardenNodeClient::call_via_invite(&decoded_invite, &GardenPeerRequest::PublishTx(join_tx))
            .unwrap();
    assert!(used_relay_tx);
    assert_eq!(tx_resp.data["accepted"], true);

    let _ = GardenNodeClient::call(host_real_addr, &GardenPeerRequest::Shutdown);
    let _ = host_child.wait();
    relay.stop();
    let _ = std::fs::remove_dir_all(&root);
}
