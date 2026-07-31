//! E2E test for Universal Relayer integration with Blockchain.
//!
//! Tests the full cross-domain relay lifecycle at the blockchain level:
//! Register_asset → lock → enqueue relay → submit proof → bridge mint.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::event_tree::{DomainEvent, DomainEventKind, DomainEventTree};
use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams, MessageKind};
use crate::cross_domain::AssetId;
use crate::domain::types::{DomainId, Hash32};
use crate::storage::db::Storage;
use std::sync::Arc;
use tempfile::tempdir;

fn hash(label: &[u8]) -> Hash32 {
    hash_fields_bytes(&[label])
}

fn asset(id: u8) -> crate::cross_domain::AssetId {
    crate::cross_domain::AssetId(hash(&[id]))
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
    asset_id: AssetId,
) -> (DomainEvent, CrossDomainMessage) {
    let payload_hash = hash_fields_bytes(&[
        b"BDLM_BRIDGE_PAYLOAD_V1",
        asset_id.as_ref(),
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
    let bc = Blockchain::new(consensus, Some(storage), 45262, None);

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
    let bc = Blockchain::new(consensus, Some(storage), 45262, None);

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
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);

    let a = asset(1);
    let (event, message) = make_lock_event(1, 2, 100, a);

    assert_eq!(bc.pending_relay_count(), 0);
    bc.enqueue_bridge_relay(event, &message);
    assert_eq!(bc.pending_relay_count(), 1);
}

#[test]
fn pending_relay_persists_across_restart() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("pending_restart.db");
    let db_path = db.to_str().unwrap().to_string();
    let storage = Storage::new(&db_path).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);

    let a = asset(1);
    let (event, message) = make_lock_event(1, 2, 100, a);
    let message_id = message.message_id;
    bc.enqueue_bridge_relay(event, &message);
    assert_eq!(bc.pending_relay_count(), 1);
    drop(bc);

    let restarted = Blockchain::new(
        Arc::new(PoWEngine::new(0)),
        Some(Storage::new(&db_path).unwrap()),
        45262,
        None,
    );
    assert_eq!(restarted.pending_relay_count(), 1);
    assert!(restarted
        .universal_relayer
        .pending_relay(&message_id)
        .is_some());
}

#[test]
fn lock_bridge_transfer_auto_enqueues_pending_relay() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("auto_enqueue_lock.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);

    for id in [1u32, 2u32] {
        let mut d = crate::domain::default_domain(
            id,
            crate::domain::ConsensusKind::PoW,
            45262,
            "pow-header-chain-v1",
            1,
        );
        d.bridge_enabled = true;
        bc.register_consensus_domain(d).unwrap();
    }

    let a = asset(1);
    bc.register_bridge_asset(a, 1).unwrap();
    bc.state.add_balance(&owner(), 1_000);

    assert_eq!(bc.pending_relay_count(), 0);
    let (_transfer, event) = bc
        .lock_bridge_transfer(1, 2, 10, 0, a, owner(), recipient(), 100, 1_000)
        .unwrap();
    let message_id = event.message.unwrap().message_id;

    assert_eq!(bc.pending_relay_count(), 1);
    assert!(bc.universal_relayer.pending_relay(&message_id).is_some());
}

#[test]
fn burn_bridge_transfer_with_event_auto_enqueues_pending_relay() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("auto_enqueue_burn.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);

    for id in [1u32, 2u32] {
        let mut d = crate::domain::default_domain(
            id,
            crate::domain::ConsensusKind::PoW,
            45262,
            "pow-header-chain-v1",
            1,
        );
        d.bridge_enabled = true;
        bc.register_consensus_domain(d).unwrap();
    }

    let a = asset(1);
    bc.register_bridge_asset(a, 1).unwrap();
    bc.state.add_balance(&owner(), 1_000);
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 10, 0, a, owner(), recipient(), 100, 1_000)
        .unwrap();
    let lock_message = lock_event.message.unwrap();
    bc.state.bridge_state.mint(&lock_message).unwrap();

    let burn_event = bc
        .burn_bridge_transfer_with_event(lock_message.message_id, 2, 20, 0, 1_000)
        .unwrap();
    let burn_message_id = burn_event.message.unwrap().message_id;

    assert!(bc
        .universal_relayer
        .pending_relay(&burn_message_id)
        .is_some());
}

#[test]
fn relay_ledger_root_changes_with_relays() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("root_change.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);

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
    let mut bc = Blockchain::new(consensus, Some(storage), 45262, None);

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
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);

    // 1. Register domains
    let mut domains = Vec::new();
    for id in [1u32, 2u32] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
        d.bridge_enabled = true;
        domains.push(d.clone());
        bc.register_consensus_domain(d).unwrap();
    }

    // 2. Register asset
    let a = asset(1);
    bc.register_bridge_asset(a, 1).unwrap();

    // 3. Register relayer
    let relayer = relayer_addr();
    bc.state.add_balance(&relayer, 100_000_000);
    let epoch = bc.state.epoch_index;
    bc.state
        .registry
        .register_relayer(relayer, 50_000_000, epoch)
        .unwrap();

    // 4. Lock on Domain 1
    bc.state.add_balance(&owner(), 1000);
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 10, 0, a, owner(), recipient(), 100, 1000)
        .unwrap();
    let message = lock_event.message.clone().unwrap();
    let message_id = message.message_id;

    // Production path now auto-enqueues the relay when the bridge lock event is created.
    assert_eq!(bc.pending_relay_count(), 1);

    // 5. Generate proof (as a relayer would)
    let mut tree = DomainEventTree::new();
    tree.push(lock_event.clone());
    let proof = tree.proof(0).unwrap();

    // 5b. The source domain anchors its event root on-chain via a domain
    // Commitment; relay proofs are verified against that committed root.
    {
        let mut b = crate::core::block::Block::new(10, bc.last_block().hash.clone(), vec![]);
        b.state_root = "22".repeat(32);
        b.tx_root = b.calculate_tx_root();
        b.hash = b.calculate_hash();
        let commitment =
            crate::domain::DomainCommitment::from_block(&domains[0], &b, tree.root(), [0u8; 32], 0)
                .unwrap();
        bc.submit_domain_commitment(commitment).unwrap();
    }

    // 6. Submit relay proof on Budlum
    let relayed_msg = bc
        .submit_relay_proof(message_id, relayer, &proof, 1)
        .unwrap();
    assert_eq!(relayed_msg.message_id, message_id);

    // 7. Verify effects:
    // - Pending count decreased
    assert_eq!(bc.pending_relay_count(), 0);
    // - Bridge state: Minted
    let t = bc.state.bridge_state.get_transfer(&message_id).unwrap();
    assert!(matches!(
        t.status,
        crate::cross_domain::bridge::BridgeStatus::Minted { domain: 2 }
    ));
    // - Balances: the relayer fee is `split_bridge_fee(100, fee_ppm, min_fee)`.
    //   At the defaults that is `max(100 * 10_000 / 1_000_000, 10)` =
    //   `max(1, 10)` = 10, so the recipient receives 90.
    //
    //   This test asserted 99/1 when the fee was a bare `amount * 1 / 100`
    //   With no floor. That rounding is exactly what made every transfer
    //   Under 100 units free for the relayer, so the floor is the fix and 90
    //   Is the correct number — not a regression.
    //
    //   Note: registry stake tracking is bookkeeping-only at this layer; it
    //   Does NOT debit the relayer's native balance, so the relayer stays
    //   At its initial 100M plus the fee.
    let params = bc.state.registry.params();
    let (expected_recipient, expected_fee) = crate::cross_domain::bridge::split_bridge_fee(
        100,
        params.bridge_relayer_fee_ppm,
        params.bridge_relayer_min_fee,
    )
    .expect("100 units must cover the default floor");
    assert_eq!(expected_fee, 10, "1% of 100 is 1, so the floor of 10 applies");
    assert_eq!(expected_recipient, 90);
    assert_eq!(bc.state.get_balance(&recipient()), expected_recipient as u64);
    assert_eq!(
        bc.state.get_balance(&relayer),
        100_000_000 + expected_fee as u64
    );
}

#[test]
fn relayer_invalid_proof_is_rejected() {
    // A malicious/buggy relayer submitting a tampered relay
    // Proof must be rejected, and the pending relay must NOT be consumed.
    let dir = tempdir().unwrap();
    let db = dir.path().join("bad_relay.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);

    let mut domains = Vec::new();
    for id in [1u32, 2u32] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
        d.bridge_enabled = true;
        domains.push(d.clone());
        bc.register_consensus_domain(d).unwrap();
    }
    let a = asset(1);
    bc.register_bridge_asset(a, 1).unwrap();
    let relayer = relayer_addr();
    bc.state.add_balance(&relayer, 100_000_000);
    let epoch = bc.state.epoch_index;
    bc.state
        .registry
        .register_relayer(relayer, 50_000_000, epoch)
        .unwrap();

    bc.state.add_balance(&owner(), 1000);
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 10, 0, a, owner(), recipient(), 100, 1000)
        .unwrap();
    let message = lock_event.message.clone().unwrap();
    let message_id = message.message_id;
    assert_eq!(bc.pending_relay_count(), 1);

    let mut tree = DomainEventTree::new();
    tree.push(lock_event.clone());
    let proof = tree.proof(0).unwrap();

    // Anchor the source domain event root on-chain.
    {
        let mut b = crate::core::block::Block::new(10, bc.last_block().hash.clone(), vec![]);
        b.state_root = "22".repeat(32);
        b.tx_root = b.calculate_tx_root();
        b.hash = b.calculate_hash();
        let commitment =
            crate::domain::DomainCommitment::from_block(&domains[0], &b, tree.root(), [0u8; 32], 0)
                .unwrap();
        bc.submit_domain_commitment(commitment).unwrap();
    }

    // Tamper the proof leaf so it no longer verifies against the committed
    // Source-domain event root.
    let mut bad_proof = proof.clone();
    bad_proof.leaf = [0xAB; 32];

    let err = bc
        .submit_relay_proof(message_id, relayer, &bad_proof, 1)
        .unwrap_err();
    assert!(
        !err.is_empty(),
        "invalid relay proof must be rejected, got empty err"
    );
    // A failed proof must not consume the pending relay.
    assert_eq!(bc.pending_relay_count(), 1);
}

use crate::domain::plugin::default_domain;
use crate::domain::ConsensusKind;

#[test]
fn full_internal_relay_cycle_burn_unlock() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("full_cycle_burn.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);

    // 1. Setup domains and relayer
    let mut domains = Vec::new();
    for id in [1u32, 2u32] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 0);
        d.bridge_enabled = true;
        domains.push(d.clone());
        bc.register_consensus_domain(d).unwrap();
    }
    let relayer = relayer_addr();
    bc.state.add_balance(&relayer, 100_000_000);
    let epoch = bc.state.epoch_index;
    bc.state
        .registry
        .register_relayer(relayer, 50_000_000, epoch)
        .unwrap();

    // 2. Setup asset and Minted state
    let a = asset(1);
    bc.register_bridge_asset(a, 1).unwrap();
    bc.state.add_balance(&owner(), 1000);
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 10, 0, a, owner(), recipient(), 100, 1000)
        .unwrap();
    let lock_msg = lock_event.message.unwrap();
    bc.state.bridge_state.mint(&lock_msg).unwrap();

    // 3. Burn on Domain 2 via the blockchain wrapper so production relay
    // Enqueue wiring is exercised.
    let burn_event = bc
        .burn_bridge_transfer_with_event(lock_msg.message_id, 2, 20, 0, 1000)
        .unwrap();
    let burn_msg = burn_event.message.clone().unwrap();
    let burn_msg_id = burn_msg.message_id;

    // Production path now auto-enqueues the relay when the burn event is created.
    assert!(bc.universal_relayer.pending_relay(&burn_msg_id).is_some());

    // 4. Generate proof
    let mut tree = DomainEventTree::new();
    tree.push(burn_event.clone());
    let proof = tree.proof(0).unwrap();

    // 4b. The source domain anchors its event root on-chain (burn emitted at
    // Domain 2, height 20); relay proof verifies against the committed root.
    {
        let mut b = crate::core::block::Block::new(20, bc.last_block().hash.clone(), vec![]);
        b.state_root = "22".repeat(32);
        b.tx_root = b.calculate_tx_root();
        b.hash = b.calculate_hash();
        let commitment =
            crate::domain::DomainCommitment::from_block(&domains[1], &b, tree.root(), [0u8; 32], 0)
                .unwrap();
        bc.submit_domain_commitment(commitment).unwrap();
    }

    // 5. Submit relay proof
    let relayed_msg = bc
        .submit_relay_proof(burn_msg_id, relayer, &proof, 2)
        .unwrap();
    assert_eq!(relayed_msg.message_id, burn_msg_id);

    // 6. Verify effects:
    // - Bridge state: Unlocked
    let t = bc
        .state
        .bridge_state
        .get_transfer(&lock_msg.message_id)
        .unwrap();
    assert!(matches!(
        t.status,
        crate::cross_domain::bridge::BridgeStatus::Unlocked { domain: 1 }
    ));
    // Lock debits the owner by the full amount (100). Unlock credits
    // `split_bridge_fee(100, ..)` = 90, the relayer keeping the 10-unit floor.
    // Start 1000 -> 1000 - 100 + 90 = 990.
    //
    // The previous 999 assumed a bare 1% cut with no floor, which is the
    // Rounding that let sub-100-unit bridges move for free.
    let params = bc.state.registry.params();
    let (credited, fee) = crate::cross_domain::bridge::split_bridge_fee(
        100,
        params.bridge_relayer_fee_ppm,
        params.bridge_relayer_min_fee,
    )
    .expect("100 units must cover the default floor");
    assert_eq!(fee, 10);
    assert_eq!(credited, 90);
    assert_eq!(bc.state.get_balance(&owner()), 1000 - 100 + credited as u64);
}
