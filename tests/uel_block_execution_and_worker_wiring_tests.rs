//! Integration tests for live multi-VM UEL block execution, `UER-1` receipt
//! commitments, wire roundtrip, and external Unix-socket worker registration.

use budlum_core::chain::blockchain::Blockchain;
use budlum_core::chain::genesis::GenesisConfig;
use budlum_core::consensus::poa::{PoAConfig, PoAEngine};
use budlum_core::consensus::ConsensusEngine;
use budlum_core::core::address::Address;
use budlum_core::core::block::{Block, BlockHeader};
use budlum_core::core::hash::hash_fields_bytes;
use budlum_core::crypto::primitives::KeyPair;
use budlum_core::execution::coordinator::gas::MIN_UEL_BASE_FEE_ATTOS;
use budlum_core::execution::coordinator::{UelAction, UelTx, UelTxAuth, WorkerSocketSpec};
use budlum_core::network::proto_conversions::pb;
use budlum_core::persistence::db::Storage;
use budlum_uel_abi::{
    BlockContext, CodeInfo, EeCall, EeCallKind, EeFault, EeId, EeOutcome, EeQuery, EeRefusal,
    ExecutionEnvironment, HostApi, HostRead, Namespace, OutcomeStatus, RefusalCode,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static SOCK_SEQ: AtomicU64 = AtomicU64::new(1);

fn make_poa_pair(
    chain_id: u64,
    sender: Address,
) -> (
    KeyPair,
    Address,
    Blockchain,
    Blockchain,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let authority_keys = KeyPair::generate().unwrap();
    let authority = Address::from(authority_keys.public_key_bytes());
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let genesis_ts = now_ms.saturating_sub(60_000);

    let mut genesis = GenesisConfig::new(chain_id);
    genesis.timestamp = genesis_ts;
    genesis.block_reward = 0;
    genesis.poa_authorities = vec![authority];
    genesis.allocations = vec![(sender, 10_000_000), (authority, 10_000_000)];

    let genesis_hash = genesis.build_genesis_block().hash;

    let dir_p = tempfile::tempdir().unwrap();
    let store_p = Storage::new(dir_p.path().to_str().unwrap()).unwrap();
    let poa_cfg = PoAConfig::default();
    let engine_p = Arc::new(PoAEngine::new(
        poa_cfg.clone(),
        Some(authority_keys.clone()),
    ));
    engine_p.note_block_seen(&genesis_hash, genesis_ts);
    let producer = Blockchain::new_with_genesis(
        engine_p,
        Some(store_p),
        chain_id,
        None,
        Some(genesis.clone()),
    );

    let dir_v = tempfile::tempdir().unwrap();
    let store_v = Storage::new(dir_v.path().to_str().unwrap()).unwrap();
    let engine_v = Arc::new(PoAEngine::new(poa_cfg, None));
    engine_v.note_block_seen(&genesis_hash, genesis_ts);
    let validator =
        Blockchain::new_with_genesis(engine_v, Some(store_v), chain_id, None, Some(genesis));

    (authority_keys, authority, producer, validator, dir_p, dir_v)
}

fn signed_uel_tx(
    chain_id: u64,
    seed: &[u8; 32],
    nonce: u64,
    ee: EeId,
    action: UelAction,
    gas_limit_bgu: u64,
    tag: u8,
) -> UelTx {
    let sender = UelTx::signer_address_from_seed(seed).unwrap();
    let mut tx_hash = [0u8; 32];
    tx_hash[0] = tag;
    tx_hash[1] = ee.0;
    tx_hash[2..10].copy_from_slice(&nonce.to_le_bytes());
    UelTx {
        tx_hash,
        sender,
        nonce,
        ee,
        action,
        value_attos: 0,
        gas_limit_bgu,
        max_fee_per_bgu_attos: MIN_UEL_BASE_FEE_ATTOS * 4,
        max_priority_fee_per_bgu_attos: 500,
        auth: UelTxAuth::default(),
    }
    .signed_with_seed(chain_id, seed)
    .unwrap()
}

#[test]
fn block_production_and_validation_execute_uel_envelopes_and_commit_uer_and_execution_roots() {
    let chain_id = 45262;
    let sender_seed = [0x31u8; 32];
    let sender = UelTx::signer_address_from_seed(&sender_seed).unwrap();
    let (_kp, authority, mut producer, mut validator, _dp, _dv) = make_poa_pair(chain_id, sender);

    // Runtime EVM bytecode: PUSH1 0x2A, PUSH1 0x01, SSTORE, STOP
    let runtime_code = vec![0x60, 0x2A, 0x60, 0x01, 0x55, 0x00];
    let salt = [0x77u8; 32];
    let local_seed = hash_fields_bytes(&[
        b"BDLM_CONTRACT_ACCOUNT_V1",
        &sender.0,
        &0u64.to_le_bytes(),
        &salt,
    ]);
    let target20 = local_seed[12..32].to_vec();

    let deploy_tx = signed_uel_tx(
        chain_id,
        &sender_seed,
        0,
        EeId::EVM,
        UelAction::Deploy {
            code: runtime_code,
            salt,
        },
        200_000,
        0xA1,
    );
    let call_tx = signed_uel_tx(
        chain_id,
        &sender_seed,
        1,
        EeId::EVM,
        UelAction::Call {
            target: target20.clone(),
            input: vec![],
        },
        150_000,
        0xA2,
    );

    producer
        .mempool
        .submit_uel_tx(&deploy_tx, 1_700_000_000)
        .unwrap();
    producer
        .mempool
        .submit_uel_tx(&call_tx, 1_700_000_000)
        .unwrap();

    let empty_exec_root = producer.state.execution_state.execution_root();
    let (block, _) = producer
        .produce_block(authority)
        .expect("producer must build block with UEL transactions");

    assert_eq!(block.uel_transactions.len(), 2);
    let exec_root = block
        .uel_execution_root
        .expect("block with UEL envelopes must commit uel_execution_root");
    let receipts_root = block
        .uel_receipts_root
        .expect("block with UEL envelopes must commit uer_receipts_root");
    assert_ne!(exec_root, empty_exec_root);
    assert_eq!(exec_root, producer.state.execution_state.execution_root());

    // UER-1 inclusion proofs verify trustlessly against block.uel_receipts_root.
    let (proof0, committed_batch0) = producer
        .prove_uel_receipt(&deploy_tx.tx_hash)
        .expect("deploy receipt proof must exist");
    assert_eq!(committed_batch0, receipts_root);
    proof0.verify(&receipts_root).unwrap();

    let (proof1, committed_batch1) = producer
        .prove_uel_receipt(&call_tx.tx_hash)
        .expect("call receipt proof must exist");
    assert_eq!(committed_batch1, receipts_root);
    proof1.verify(&receipts_root).unwrap();

    // Validator executes the block independently and reaches the identical roots.
    validator
        .validate_and_add_block(block.clone())
        .expect("validator must accept valid UEL block");
    assert_eq!(
        validator.state.execution_state.execution_root(),
        producer.state.execution_state.execution_root()
    );
    assert_eq!(
        validator.state.calculate_state_root(),
        producer.state.calculate_state_root()
    );
}

#[test]
fn tampered_uel_roots_or_envelope_order_are_rejected_fail_closed() {
    let chain_id = 45262;
    let sender_seed = [0x42u8; 32];
    let sender = UelTx::signer_address_from_seed(&sender_seed).unwrap();
    let (authority_keys, authority, mut producer, mut validator, _dp, _dv) =
        make_poa_pair(chain_id, sender);

    let runtime_code = vec![0x60, 0x11, 0x60, 0x02, 0x55, 0x00];
    let salt = [0x88u8; 32];
    let local_seed = hash_fields_bytes(&[
        b"BDLM_CONTRACT_ACCOUNT_V1",
        &sender.0,
        &0u64.to_le_bytes(),
        &salt,
    ]);
    let target20 = local_seed[12..32].to_vec();

    let tx0 = signed_uel_tx(
        chain_id,
        &sender_seed,
        0,
        EeId::EVM,
        UelAction::Deploy {
            code: runtime_code,
            salt,
        },
        200_000,
        0xB1,
    );
    let tx1 = signed_uel_tx(
        chain_id,
        &sender_seed,
        1,
        EeId::EVM,
        UelAction::Call {
            target: target20,
            input: vec![],
        },
        150_000,
        0xB2,
    );

    producer.mempool.submit_uel_tx(&tx0, 1_700_000_000).unwrap();
    producer.mempool.submit_uel_tx(&tx1, 1_700_000_000).unwrap();
    let (valid_block, _) = producer.produce_block(authority).unwrap();
    assert_eq!(valid_block.uel_transactions.len(), 2);

    let validator_root_before = validator.state.calculate_state_root();

    // 1. Tampered uel_execution_root (re-signed by authority) must be rejected.
    let mut bad_exec = valid_block.clone();
    let mut forged_exec_root = bad_exec.uel_execution_root.unwrap();
    forged_exec_root[0] ^= 0xFF;
    bad_exec.uel_execution_root = Some(forged_exec_root);
    bad_exec.sign(&authority_keys);
    assert!(validator.validate_and_add_block(bad_exec).is_err());
    assert_eq!(
        validator.state.calculate_state_root(),
        validator_root_before
    );

    // 2. Tampered uel_receipts_root (re-signed by authority) must be rejected.
    let mut bad_rcpt = valid_block.clone();
    let mut forged_rcpt_root = bad_rcpt.uel_receipts_root.unwrap();
    forged_rcpt_root[0] ^= 0xFF;
    bad_rcpt.uel_receipts_root = Some(forged_rcpt_root);
    bad_rcpt.sign(&authority_keys);
    assert!(validator.validate_and_add_block(bad_rcpt).is_err());
    assert_eq!(
        validator.state.calculate_state_root(),
        validator_root_before
    );

    // 3. Swapped UEL transaction order without updating tx_root must fail tx_root verification.
    let mut swapped = valid_block.clone();
    swapped.uel_transactions.swap(0, 1);
    swapped.sign(&authority_keys);
    assert!(validator.validate_and_add_block(swapped).is_err());
    assert_eq!(
        validator.state.calculate_state_root(),
        validator_root_before
    );
}

#[test]
fn proto_block_wire_roundtrip_preserves_uel_envelopes_and_roots() {
    let chain_id = 45262;
    let sender_seed = [0x53u8; 32];
    let sender = UelTx::signer_address_from_seed(&sender_seed).unwrap();
    let (_kp, authority, mut producer, _validator, _dp, _dv) = make_poa_pair(chain_id, sender);

    let tx0 = signed_uel_tx(
        chain_id,
        &sender_seed,
        0,
        EeId::EVM,
        UelAction::Deploy {
            code: vec![0x60, 0x05, 0x60, 0x00, 0x55, 0x00],
            salt: [0x19u8; 32],
        },
        200_000,
        0xC1,
    );
    producer.mempool.submit_uel_tx(&tx0, 1_700_000_000).unwrap();
    let (block, _) = producer.produce_block(authority).unwrap();
    assert_eq!(block.uel_transactions.len(), 1);
    assert!(block.uel_execution_root.is_some());
    assert!(block.uel_receipts_root.is_some());

    let proto_block = pb::ProtoBlock::from(&block);
    let roundtripped = Block::try_from(proto_block).unwrap();
    assert_eq!(roundtripped.uel_transactions, block.uel_transactions);
    assert_eq!(roundtripped.uel_execution_root, block.uel_execution_root);
    assert_eq!(roundtripped.uel_receipts_root, block.uel_receipts_root);
    assert_eq!(roundtripped.calculate_tx_root(), block.tx_root);
    assert_eq!(roundtripped.calculate_hash(), block.hash);

    let header = BlockHeader::from_block(&block);
    let proto_header = pb::ProtoBlockHeader::from(&header);
    let roundtripped_header = BlockHeader::try_from(proto_header).unwrap();
    assert_eq!(
        roundtripped_header.uel_execution_root,
        header.uel_execution_root
    );
    assert_eq!(
        roundtripped_header.uel_receipts_root,
        header.uel_receipts_root
    );
    assert_eq!(roundtripped_header.calculate_hash(), block.hash);
}

struct SocketSentinelEe;

impl ExecutionEnvironment for SocketSentinelEe {
    fn id(&self) -> EeId {
        EeId::EVM
    }

    fn validate_deploy(&self, code: &[u8]) -> Result<CodeInfo, EeRefusal> {
        if code.is_empty() {
            return Err(EeRefusal {
                code: RefusalCode::InvalidCode,
                message: "empty".into(),
            });
        }
        Ok(CodeInfo {
            code_hash: Sha256::digest(code).into(),
            abi_tag: "sentinel-evm-socket-v1".into(),
        })
    }

    fn execute(
        &mut self,
        _ctx: &BlockContext,
        call: &EeCall,
        host: &mut dyn HostApi,
    ) -> Result<EeOutcome, EeFault> {
        let ns = Namespace::new("ee/evm/storage").unwrap();
        let _ = host.charge(1_000);
        if call.kind == EeCallKind::Deploy {
            host.write(&ns, b"socket_worker_marker", Some(b"UNIX_SOCKET_LIVE"))
                .unwrap();
        }
        Ok(EeOutcome {
            status: OutcomeStatus::Success,
            output: b"UNIX_SOCKET_LIVE".to_vec(),
            gas_used: 1_000,
        })
    }

    fn query(
        &self,
        _ctx: &BlockContext,
        _q: &EeQuery,
        _host: &dyn HostRead,
    ) -> Result<Vec<u8>, EeRefusal> {
        Ok(b"UNIX_SOCKET_LIVE".to_vec())
    }
}

#[cfg(unix)]
#[test]
fn configure_execution_workers_registers_unix_socket_worker_and_fails_closed_for_validator() {
    let chain_id = 45262;
    let sender_seed = [0x64u8; 32];
    let sender = UelTx::signer_address_from_seed(&sender_seed).unwrap();
    let (_kp, authority, mut producer, mut validator, _dp, _dv) = make_poa_pair(chain_id, sender);

    // 1. Missing required worker socket must refuse validator startup fail-closed.
    let missing_sock = std::env::temp_dir().join("nonexistent-budlum-ee-evm-999999.sock");
    let _ = std::fs::remove_file(&missing_sock);
    let err = validator.configure_execution_workers(
        &[WorkerSocketSpec {
            ee: EeId::EVM,
            socket_path: missing_sock,
            binary_path: None,
            required: true,
        }],
        true,
    );
    assert!(
        err.is_err(),
        "validator must fail closed when a required external EE worker socket is missing"
    );

    // 2. Live Unix-domain-socket worker registered via configure_execution_workers executes block txs.
    let seq = SOCK_SEQ.fetch_add(1, Ordering::SeqCst);
    let sock_path = std::env::temp_dir().join(format!(
        "budlum-live-worker-{}-{seq}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&sock_path);
    let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(4).flatten() {
            let mut ee = SocketSentinelEe;
            let _ = budlum_uel_abi::transport::serve_connection(stream, &mut ee);
        }
    });

    producer
        .configure_execution_workers(
            &[WorkerSocketSpec {
                ee: EeId::EVM,
                socket_path: sock_path.clone(),
                binary_path: None,
                required: true,
            }],
            true,
        )
        .expect("live Unix-socket worker must configure cleanly");

    let deploy_tx = signed_uel_tx(
        chain_id,
        &sender_seed,
        0,
        EeId::EVM,
        UelAction::Deploy {
            code: vec![0x01],
            salt: [0x55; 32],
        },
        50_000,
        0xD1,
    );
    producer
        .mempool
        .submit_uel_tx(&deploy_tx, 1_700_000_000)
        .unwrap();
    let (block, _) = producer.produce_block(authority).unwrap();
    assert!(block.uel_execution_root.is_some());

    let marker = producer
        .state
        .execution_state
        .read("ee/evm/storage", b"socket_worker_marker")
        .unwrap();
    let _ = std::fs::remove_file(&sock_path);
    assert_eq!(
        marker.as_deref(),
        Some(b"UNIX_SOCKET_LIVE".as_slice()),
        "block execution must route through the registered Unix-socket worker"
    );
}
