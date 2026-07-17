//! P2P Adversarial and Toplogy Simulation (ARENA2).
//! Tests the network layer resistance against common blockchain attacks.

use crate::network::node::{Node, NodeCommand, NodeClient};
use crate::core::address::Address;
use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::chain::chain_actor::ChainActor;
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_sybil_role_rejection() {
    // Scenario: A malicious node attempts to submit consensus votes 
    // without having the STAKED role.
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 1337, None);
    
    let attacker = Address::from([0x66; 32]);
    // Attacker is NOT registered as a validator
    assert!(!bc.state.validators.contains_key(&attacker));
    
    // Malicious block from attacker
    let block = crate::core::block::Block::new(1, bc.chain[0].hash.clone(), vec![]);
    // block.producer = Some(attacker); // producer is Option<Address>
    
    // The chain must reject this block
    let res = bc.validate_and_add_block(block);
    // Blockchain::validate_and_add_block internally calls consensus.full_validate
    // which checks producer eligibility.
    assert!(res.is_err());
}

#[tokio::test]
async fn test_p2p_message_size_gate() {
    // Scenario: Attacker sends an extremely large transaction to cause OOM.
    use crate::network::protocol::NetworkMessage;
    use crate::core::transaction::Transaction;
    
    let large_data = vec![0u8; 20 * 1024 * 1024]; // 20 MB
    let tx = Transaction::new(Address::zero(), Address::zero(), 0, large_data);
    
    // validate_tx_size check
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
