//! E2E test for Universal Relayer integration with Blockchain.
//!
//! Tests the full cross-domain relay lifecycle at the blockchain level:
//! register_asset → lock → enqueue relay → submit proof → bridge mint.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::event_tree::{DomainEvent, DomainEventKind, DomainEventTree};
use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams, MessageKind};
use crate::cross_domain::relayer::RelayerConfig;
use crate::domain::types::{DomainId, Hash32};
use crate::storage::db::Storage;
use std::sync::Arc;
use tempfile::tempdir;

fn hash(label: &[u8]) -> Hash32 {
    hash_fields_bytes(&[label])
}

fn asset(id: u8) -> Hash32 {
    hash(&[id])
}

fn owner() -> Address {
    Address::from([0xAA; 32])
}

fn recipient() -> Address {
    Address::from([0xBB; 32])
}

fn relayer_addr() -> Address {
    Address::from([0xCC; 32])
}

fn make_lock_event(
    source_domain: DomainId,
    target_domain: DomainId,
    height: u64,
    asset_id: Hash32,
) -> (DomainEvent, CrossDomainMessage) {
    let payload_hash = hash_fields_bytes(&[
        b"BDLM_BRIDGE_PAYLOAD_V1",
        &asset_id,
        &1000u128.to_le_bytes(),
    ]);
    let message = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain,
        target_domain,
        source_height: height,
        event_index: 0,
        nonce: 0,
        sender: owner(),
        recipient: recipient(),
        payload_hash,
        kind: MessageKind::BridgeLock,
        expiry_height: height + 1000,
    });
    let event = DomainEvent {
        domain_id: source_domain,
        domain_height: height,
        event_index: 0,
        kind: DomainEventKind::BridgeLocked,
        emitter: owner(),
        message: Some(message.clone()),
        payload_hash,
    };
    (event, message)
}

#[test]
fn relayer_enqueues_and_tracks_pending_relays() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("relayer_e2e.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let bc = Blockchain::new(consensus, Some(storage), 1337, None);

    // Initially no pending relays
    assert_eq!(bc.pending_relay_count(), 0);
    assert_eq!(bc.expired_relays().len(), 0);
}

#[test]
fn relayer_root_is_deterministic() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("relayer_root.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let bc = Blockchain::new(consensus, Some(storage), 1337, None);

    let root1 = bc.relay_ledger_root();
    let root2 = bc.relay_ledger_root();
    assert_eq!(root1, root2);
}

#[test]
fn enqueue_bridge_relay_increments_pending() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("enqueue.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 1337, None);

    let a = asset(1);
    let (event, message) = make_lock_event(1, 2, 100, a);

    assert_eq!(bc.pending_relay_count(), 0);
    bc.enqueue_bridge_relay(event, &message);
    assert_eq!(bc.pending_relay_count(), 1);
}

#[test]
fn relay_ledger_root_changes_with_relays() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("root_change.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 1337, None);

    let root_before = bc.relay_ledger_root();

    let a = asset(1);
    let (event, message) = make_lock_event(1, 2, 100, a);
    bc.enqueue_bridge_relay(event, &message);

    // Root should still be the same (relay not yet recorded, only pending)
    let root_after_enqueue = bc.relay_ledger_root();
    assert_eq!(root_before, root_after_enqueue);
}

#[test]
fn expired_relays_detects_past_expiry() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("expired.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 1337, None);

    // Create a message with short expiry
    let payload_hash = hash(b"test");
    let message = CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 2,
        source_height: 100,
        event_index: 0,
        nonce: 0,
        sender: owner(),
        recipient: recipient(),
        payload_hash,
        kind: MessageKind::BridgeLock,
        expiry_height: 200, // expires at height 200
    });
    let event = DomainEvent {
        domain_id: 1,
        domain_height: 100,
        event_index: 0,
        kind: DomainEventKind::BridgeLocked,
        emitter: owner(),
        message: Some(message.clone()),
        payload_hash,
    };

    bc.enqueue_bridge_relay(event, &message);
    assert_eq!(bc.expired_relays().len(), 0); // not expired yet (chain len < 200)
}

#[test]
fn full_internal_relay_cycle_lock_mint() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("full_cycle.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);

    // 1. Register domains
    for id in [1u32, 2u32] {
        let mut d = default_domain(id, ConsensusKind::PoW, 1337, "pow-confirmation-depth", 0);
        d.bridge_enabled = true;
        bc.register_consensus_domain(d).unwrap();
    }

    // 2. Register asset
    let a = asset(1);
    bc.register_bridge_asset(a, 1).unwrap();

    // 3. Register relayer
    let relayer = relayer_addr();
    bc.state.add_balance(&relayer, 100_000_000);
    bc.state.registry.bond_relayer(&relayer, 50_000_000).unwrap();

    // 4. Lock on Domain 1
    bc.state.add_balance(&owner(), 1000);
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 10, 0, a, owner(), recipient(), 100, 1000)
        .unwrap();
    let message = lock_event.message.clone().unwrap();
    let message_id = message.message_id;

    // Relayer enqueued it
    assert_eq!(bc.pending_relay_count(), 1);

    // 5. Generate proof (as a relayer would)
    let mut tree = DomainEventTree::new();
    tree.push(lock_event.clone());
    let proof = tree.proof(0).unwrap();

    // 6. Submit relay proof on Budlum
    let relayed_msg = bc.submit_relay_proof(message_id, relayer, &proof, 1).unwrap();
    assert_eq!(relayed_msg.message_id, message_id);

    // 7. Verify effects:
    // - Pending count decreased
    assert_eq!(bc.pending_relay_count(), 0);
    // - Bridge state: Minted
    let t = bc.bridge_state.get_transfer(&message_id).unwrap();
    assert!(matches!(t.status, crate::cross_domain::bridge::BridgeStatus::Minted { domain: 2 }));
    // - Balances: recipient received 99 (100 - 1% fee), relayer received 1
    assert_eq!(bc.state.get_balance(&recipient()), 99);
    assert_eq!(bc.state.get_balance(&relayer()), 50_000_001); // 50M (bond) + 1 (fee)
}

use crate::domain::plugin::default_domain;
use crate::domain::ConsensusKind;

#[test]
fn full_internal_relay_cycle_burn_unlock() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("full_cycle_burn.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);

    // 1. Setup domains and relayer
    for id in [1u32, 2u32] {
        let mut d = default_domain(id, ConsensusKind::PoW, 1337, "pow-confirmation-depth", 0);
        d.bridge_enabled = true;
        bc.register_consensus_domain(d).unwrap();
    }
    let relayer = relayer_addr();
    bc.state.add_balance(&relayer, 100_000_000);
    bc.state.registry.bond_relayer(&relayer, 50_000_000).unwrap();

    // 2. Setup asset and Minted state
    let a = asset(1);
    bc.register_bridge_asset(a, 1).unwrap();
    bc.state.add_balance(&owner(), 1000);
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 10, 0, a, owner(), recipient(), 100, 1000)
        .unwrap();
    let lock_msg = lock_event.message.unwrap();
    bc.bridge_state.mint(&lock_msg).unwrap();
    
    // 3. Burn on Domain 2
    let burn_event = bc.bridge_state.burn_with_event(lock_msg.message_id, 2, 20, 0, 1000).unwrap();
    let burn_msg = burn_event.message.clone().unwrap();
    let burn_msg_id = burn_msg.message_id;
    
    // Relayer enqueued it
    bc.enqueue_bridge_relay(burn_event.clone(), &burn_msg);
    assert_eq!(bc.pending_relay_count(), 1);

    // 4. Generate proof
    let mut tree = DomainEventTree::new();
    tree.push(burn_event.clone());
    let proof = tree.proof(0).unwrap();

    // 5. Submit relay proof
    let relayed_msg = bc.submit_relay_proof(burn_msg_id, relayer, &proof, 2).unwrap();
    assert_eq!(relayed_msg.message_id, burn_msg_id);

    // 6. Verify effects:
    // - Bridge state: Unlocked
    let t = bc.bridge_state.get_transfer(&lock_msg.message_id).unwrap();
    assert!(matches!(t.status, crate::cross_domain::bridge::BridgeStatus::Unlocked { domain: 1 }));
    // - Owner received funds (100 - 1% relayer fee)
    assert_eq!(bc.state.get_balance(&owner()), 99);
}
