//! Bridge negative suite (2026-07-18).
//!
//! Every case asserts an ALREADY-DEFINED rejection path of
//! `Blockchain::submit_relay_proof`; no protocol behavior is changed by
//! This file. The anchor of trust is the chain-committed domain event
//! Root (`DomainCommitment`), so a relayer must not be able to mint from
//! Forged proofs, replay consumed relays, or skip commitments.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use crate::core::hash::hash_fields_bytes;
use crate::cross_domain::event_tree::{DomainEvent, DomainEventKind, DomainEventTree};
use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams, MessageKind};
use crate::domain::plugin::default_domain;
use crate::domain::types::{DomainId, Hash32};
use crate::domain::{ConsensusDomain, ConsensusKind};
use crate::storage::db::Storage;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};

fn hash(label: &[u8]) -> Hash32 {
    hash_fields_bytes(&[label])
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

/// One honest bridge setup: two domains, one asset, one registered relayer,
/// One locked transfer, one honest event tree + proof. Mirrors the proven
/// `relayer_e2e` fixture so the negatives differ from the passing positive
/// Path by exactly one mutation each.
struct Fixture {
    /// Keeps the temp DB alive for the Blockchain's lifetime (dropping it
    /// Early pulls the storage directory from under the open handle).
    _dir: TempDir,
    bc: Blockchain,
    domains: Vec<ConsensusDomain>,
    /// (message_id, relayer, honest proof, source_domain)
    message_id: crate::cross_domain::MessageId,
    relayer: Address,
    tree: DomainEventTree,
}

fn make_lock_message(
    source_domain: DomainId,
    target_domain: DomainId,
    height: u64,
) -> CrossDomainMessage {
    let payload_hash = hash_fields_bytes(&[b"BDLM_NEG_LOCK", &height.to_le_bytes()]);
    CrossDomainMessage::new(CrossDomainMessageParams {
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
    })
}

fn honest_fixture(register_relayer: bool) -> Fixture {
    let dir = tempdir().unwrap();
    let storage = Storage::new(dir.path().join("neg.db").to_str().unwrap()).unwrap();
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);

    let mut domains = Vec::new();
    for id in [1u32, 2u32] {
        let mut d = default_domain(id, ConsensusKind::PoW, 45262, "pow-header-chain-v1", 1);
        d.bridge_enabled = true;
        domains.push(d.clone());
        bc.register_consensus_domain(d).unwrap();
    }

    let asset_id = crate::cross_domain::AssetId(hash(b"NEG_ASSET"));
    bc.register_bridge_asset(asset_id, 1).unwrap();

    let relayer = relayer_addr();
    if register_relayer {
        bc.state.add_balance(&relayer, 100_000_000);
        let epoch = bc.state.epoch_index;
        bc.state
            .registry
            .register_relayer(relayer, 50_000_000, epoch)
            .unwrap();
    }

    bc.state.add_balance(&owner(), 1000);
    let (_transfer, lock_event) = bc
        .lock_bridge_transfer(1, 2, 10, 0, asset_id, owner(), recipient(), 100, 1000)
        .unwrap();
    let message = lock_event.message.clone().unwrap();
    let message_id = message.message_id;

    // Off-chain relayer scan enqueues the pending relay.
    bc.enqueue_bridge_relay(lock_event.clone(), &message);
    assert_eq!(bc.pending_relay_count(), 1);

    let mut tree = DomainEventTree::new();
    tree.push(lock_event);
    Fixture {
        _dir: dir,
        bc,
        domains,
        message_id,
        relayer,
        tree,
    }
}

/// Anchor the honest tree root on-chain via a domain commitment (same
/// Recipe as the positive E2E path).
fn anchor_commitment(f: &mut Fixture, domain_idx: usize, height: u64) {
    let mut b = crate::core::block::Block::new(height, f.bc.last_block().hash.clone(), vec![]);
    b.state_root = "22".repeat(32);
    b.tx_root = b.calculate_tx_root();
    b.hash = b.calculate_hash();
    let commitment = crate::domain::DomainCommitment::from_block(
        &f.domains[domain_idx],
        &b,
        f.tree.root(),
        [0u8; 32],
        0,
    )
    .unwrap();
    f.bc.submit_domain_commitment(commitment).unwrap();
}

/// [N1] A proof built from an *attacker-controlled* event tree must not
/// Mint: verification runs against the chain-committed honest event root.
#[test]
fn forged_proof_against_committed_root_rejected() {
    let mut f = honest_fixture(true);
    anchor_commitment(&mut f, 0, 10);

    // Forged tree: different event content (different message id), same index.
    let fake_msg = make_lock_message(1, 2, 10);
    let forged_event = DomainEvent {
        domain_id: 1,
        domain_height: 10,
        event_index: 0,
        kind: DomainEventKind::BridgeLocked,
        emitter: relayer_addr(), // attacker emits
        message: Some(fake_msg),
        payload_hash: hash(b"FORGED"),
    };
    let mut forged_tree = DomainEventTree::new();
    forged_tree.push(forged_event);
    let forged_proof = forged_tree.proof(0).unwrap();

    let res =
        f.bc.submit_relay_proof(f.message_id, f.relayer, &forged_proof, 1);
    assert!(res.is_err(), "forged proof must never mint");
    // Bridge state must still show the transfer un-minted (pending path only).
    let t = f.bc.state.bridge_state.get_transfer(&f.message_id).unwrap();
    assert!(!matches!(
        t.status,
        crate::cross_domain::bridge::BridgeStatus::Minted { .. }
    ));
}

/// [N2] A consumed relay cannot be replayed: the second identical
/// Submission is rejected (pending relay is gone / already recorded).
#[test]
fn replay_same_relay_proof_rejected() {
    let mut f = honest_fixture(true);
    anchor_commitment(&mut f, 0, 10);
    let proof = f.tree.proof(0).unwrap();

    f.bc.submit_relay_proof(f.message_id, f.relayer, &proof, 1)
        .unwrap(); // positive path still holds

    let replay = f.bc.submit_relay_proof(f.message_id, f.relayer, &proof, 1);
    assert!(replay.is_err(), "replayed relay proof must be rejected");
}

/// [N3] No committed anchor at all → the relayer cannot self-attest a root.
#[test]
fn relay_proof_without_committed_anchor_rejected() {
    let mut f = honest_fixture(true);
    let proof = f.tree.proof(0).unwrap();
    let res = f.bc.submit_relay_proof(f.message_id, f.relayer, &proof, 1);
    assert!(
        res.is_err(),
        "proof without a chain-committed event root must be rejected"
    );
}

/// [N4] Anchor committed for the *wrong* domain does not authenticate a
/// Relay claiming source domain 1.
#[test]
fn relay_proof_with_wrong_domain_anchor_rejected() {
    let mut f = honest_fixture(true);
    anchor_commitment(&mut f, 1, 10); // commitment lands on domain 2, not source domain 1
    let proof = f.tree.proof(0).unwrap();
    let res = f.bc.submit_relay_proof(f.message_id, f.relayer, &proof, 1);
    assert!(
        res.is_err(),
        "cross-domain anchor substitution must be rejected"
    );
}

/// [N5] An unstaked / inactive relayer cannot relay even with a valid proof.
#[test]
fn inactive_relayer_proof_rejected() {
    let mut f = honest_fixture(false); // relayer NOT registered
    anchor_commitment(&mut f, 0, 10);
    let proof = f.tree.proof(0).unwrap();
    let res = f.bc.submit_relay_proof(f.message_id, f.relayer, &proof, 1);
    assert!(res.is_err(), "inactive relayer must be rejected");
}

/// [N6] Relaying a message that was never enqueued/observed is rejected
/// Before any proof step.
#[test]
fn unknown_message_proof_rejected() {
    let mut f = honest_fixture(true);
    anchor_commitment(&mut f, 0, 10);
    let proof = f.tree.proof(0).unwrap();
    let ghost_id = hash(b"GHOST_MESSAGE");
    let res = f.bc.submit_relay_proof(ghost_id, f.relayer, &proof, 1);
    assert!(res.is_err(), "unknown message relay must be rejected");
}
