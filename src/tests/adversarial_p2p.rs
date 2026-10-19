//! P2P Adversarial and Topology Simulation.
//! Tests the network layer resistance against common blockchain attacks.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use std::sync::Arc;

#[tokio::test]
async fn test_sybil_role_rejection() {
    // Scenario: a node that holds no validator role submits a block to a PoS
    // chain that has an active validator set. The block is well formed, so the
    // only reason left to refuse it is the missing producer.
    use crate::consensus::pos::{PoSConfig, PoSEngine};

    let consensus = Arc::new(PoSEngine::new(PoSConfig::default(), None));
    let mut bc = Blockchain::new(consensus, None, 45262, None);
    let validator = Address::from([0x55; 32]);
    bc.state.add_validator(validator, 10_000);

    let attacker = Address::from([0x66; 32]);
    assert!(!bc.state.validators.contains_key(&attacker));

    let mut block = crate::core::block::Block::new(1, bc.chain[0].hash.clone(), vec![]);
    block.slot = 1;
    block.state_root = "11".repeat(32);
    block.hash = block.calculate_hash();

    let err = bc
        .validate_and_add_block(block)
        .expect_err("a block without a staked producer must be rejected");
    assert!(
        err.contains("Block has no producer"),
        "unexpected rejection reason: {err}"
    );
}

#[tokio::test]
async fn test_p2p_message_size_gate() {
    // Scenario: Attacker sends an extremely large transaction to cause OOM.
    use crate::core::transaction::Transaction;
    use crate::network::protocol::NetworkMessage;

    let large_data = vec![0u8; 20 * 1024 * 1024]; // 20 MB
    let tx = Transaction::new(Address::zero(), Address::zero(), 0, large_data);

    // Validate_tx_size check
    assert!(NetworkMessage::validate_tx_size(&tx).is_err());
}

#[tokio::test]
async fn test_flood_protection_logic() {
    // This is more of a logic check for the peer manager.
    use crate::network::peer_manager::PeerManager;
    let mut pm = PeerManager::new();
    let peer_id = libp2p::PeerId::random();

    // Report multiple bad behaviors
    for _ in 0..100 {
        pm.report_invalid_block(&peer_id);
    }

    assert!(pm.is_banned(&peer_id));
}

#[tokio::test]
async fn test_p2p_topology_latency_drift_simulation() {
    // Industry Standard Simulation.
    // Tests if the chain handles blocks with slightly future/past timestamps
    // Which simulate network propagation delays (latency drift).
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    // 1. Block from the "Future" (+5 seconds propagation drift)
    // A canonically valid template comes from a shadow chain's production
    // Path: apply_block_effects (epoch/timestamps) and the bridge/message/
    // Settlement/global-header overlays make the committed state_root
    // Non-trivial to replicate by hand. Both chains are freshly constructed
    // (deterministic genesis, no txs), so their states and header summaries
    // Are identical.
    let mut shadow = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
    let Some((mut future_block, _)) = shadow.produce_block(crate::core::address::Address::zero())
    else {
        panic!("shadow block production failed");
    };
    future_block.timestamp = now + 5000;
    future_block.hash = future_block.calculate_hash();

    // Usually accepted if within drift window (e.g. 15s in Bitcoin/Ethereum)
    let future_ts = future_block.timestamp;
    shadow
        .validate_and_add_block(future_block.clone())
        .expect("shadow follows the accepted block");
    let future_res = bc.validate_and_add_block(future_block);
    assert!(
        future_res.is_ok(),
        "future-drift block must be accepted: {:?}",
        future_res.err()
    );

    // 2. Block with a clock-regression timestamp (older than the current
    // Tip - replay / skewed producer clock). NOTE: the chain's genesis
    // Timestamp is a deterministic constant (GENESIS_TIMESTAMP == 0), so
    // "older than genesis" is not representable; regressing against the tip
    // Exercises the same monotonicity guard.
    let Some((mut past_block, _)) = shadow.produce_block(crate::core::address::Address::zero())
    else {
        panic!("shadow block production failed");
    };
    past_block.timestamp = future_ts - 1000;
    past_block.hash = past_block.calculate_hash();

    // MUST be rejected
    let past_res = bc.validate_and_add_block(past_block);
    let err = past_res.expect_err("clock-regressed block must be rejected");
    assert!(err.contains("not monotonic"), "unexpected rejection: {err}");
}
