//! What a reorganised proof-of-work domain does to value that already
//! settled.
//!
//! A proof-of-work domain commits a block and bridge locks under that block
//! start to be minted on Budlum. Then a second verified commitment arrives
//! for the same height with another block: the external chain reorganised
//! deeper than the depth the domain registered. Budlum does not pick a
//! winner. The commitment that settled first stays in the book, the second
//! one is evidence, and the domain is frozen in the block that carries it.
//!
//! These tests walk that sequence end to end through the bridge doors and
//! pin what it means for value:
//!
//! - the freeze happens in the same block, and the domain's certificate row
//!   turns `Refuted`;
//! - a lock that was minted before the freeze stays minted, and nothing is
//!   clawed back;
//! - a lock proven under the very same committed block is not minted after
//!   the freeze, and stays a lock;
//! - the other domain keeps committing, and value that was minted before the
//!   freeze still leaves through it.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::cross_domain::bridge_tx::{
    burn_with_event, execute_bridge_tx, lock, unlock_from_verified_event, BridgeTx,
    BridgeTxContext, BurnRequest, LockRequest, ProvenBridgeEvent,
};
use crate::cross_domain::event_tree::DomainEventTree;
use crate::cross_domain::external::spec::SecurityBacking;
use crate::cross_domain::{AssetId, DomainCeilingPolicy, DomainEvent, MerkleProof};
use crate::domain::plugin::default_domain;
use crate::domain::{
    ConsensusKind, DomainCommitment, DomainStatus, Hash32, POW_HEADER_CHAIN_ADAPTER,
};
use crate::settlement::domains::{accept_commitment, CommitmentOutcome};
use crate::settlement::finality_gate::{enforce_domain_not_refuted, ValueGate};
use crate::settlement::universal_finality::FinalityVerdict;
use std::collections::BTreeMap;
use std::sync::Arc;

const CHAIN_ID: u64 = 45_261;
/// The proof-of-work domain that reorganises.
const SOURCE: u32 = 1;
/// The domain value is bridged toward. It stays healthy throughout.
const TARGET: u32 = 2;
/// The source height the two locks sit under.
const LOCK_HEIGHT: u64 = 20;
/// The block the source domain committed at `LOCK_HEIGHT`.
const SETTLED_BLOCK: Hash32 = [0xA1; 32];
/// The block the reorganised chain carries at `LOCK_HEIGHT`.
const RIVAL_BLOCK: Hash32 = [0xB1; 32];
const LOCKED: u64 = 1_000;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn tip_of(domain: u32) -> Hash32 {
    [0xE0 | u8::try_from(domain).unwrap_or(0x0F); 32]
}

fn commitment(
    domain_id: u32,
    domain_height: u64,
    block_hash: Hash32,
    parent: Hash32,
    event_root: Hash32,
) -> DomainCommitment {
    DomainCommitment {
        domain_id,
        domain_height,
        domain_block_hash: block_hash,
        parent_domain_block_hash: parent,
        state_root: [0xB1; 32],
        tx_root: [0xC1; 32],
        event_root,
        finality_proof_hash: [0xD1; 32],
        consensus_kind: ConsensusKind::PoW,
        validator_set_hash: [0u8; 32],
        timestamp_ms: 1_000,
        sequence: 1,
        producer: None,
        state_updates: BTreeMap::new(),
    }
}

/// Two bridge locks under one settled source block, each with its inclusion
/// proof, and the accounts that move them.
struct Settled {
    bc: Blockchain,
    relayer: Address,
    owner: Address,
    recipient: Address,
    first: (DomainEvent, MerkleProof),
    second: (DomainEvent, MerkleProof),
}

impl Settled {
    fn mint(&mut self, lock: &(DomainEvent, MerkleProof), height: u64) -> Result<(), String> {
        execute_bridge_tx(
            &mut self.bc.state,
            &BridgeTxContext {
                sender: self.relayer,
                fee: 0,
                height,
            },
            &BridgeTx::Mint(Box::new(ProvenBridgeEvent {
                domain: SOURCE,
                height: LOCK_HEIGHT,
                sequence: 1,
                expected_block_hash: SETTLED_BLOCK,
                event: lock.0.clone(),
                proof: lock.1.clone(),
            })),
        )
        .map_err(|e| e.to_string())
    }

    /// The reorganised chain's block for `LOCK_HEIGHT`, accepted the way a
    /// commitment is once its finality proof has verified.
    fn rival_commitment_arrives(&mut self) -> CommitmentOutcome {
        accept_commitment(
            &mut self.bc.state,
            commitment(SOURCE, LOCK_HEIGHT, RIVAL_BLOCK, [0u8; 32], [0xEE; 32]),
        )
        .expect("a verified rival commitment is evidence, not an error")
    }

    fn status_of(&self, domain: u32) -> DomainStatus {
        self.bc
            .state
            .settlement
            .domains
            .get(domain)
            .expect("the domain is registered")
            .status
    }

    fn verdict_of(&self, domain: u32, checkpoint: u64) -> FinalityVerdict {
        self.bc
            .state
            .settlement
            .universal_finality_certificate(checkpoint)
            .expect("a certificate is derived")
            .prove_domain(domain)
            .expect("the domain has a row")
            .entry
            .verdict
    }

    fn balance(&self, who: &Address) -> u64 {
        self.bc.state.get_balance(who)
    }
}

/// Moves the test balances out of the richest genesis account, so the supply
/// stays what genesis made it, and bonds the relayer.
fn fund(bc: &mut Blockchain, relayer: Address, owner: Address, recipient: Address) {
    let min_relayer = bc.state.registry.params().min_stake;
    let seeded = min_relayer.saturating_mul(2) + 10 * LOCKED + 100;
    let rich_genesis = *bc
        .state
        .get_all_balances()
        .iter()
        .max_by_key(|(_, balance)| **balance)
        .expect("genesis funds an account")
        .0;
    bc.state.get_or_create(&rich_genesis).balance -= seeded;
    bc.state
        .add_balance(&relayer, min_relayer.saturating_mul(2));
    bc.state
        .bond_relayer(&relayer, min_relayer)
        .expect("the relayer bonds");
    bc.state.add_balance(&owner, 10 * LOCKED);
    bc.state.add_balance(&recipient, 100);
}

/// [`settled_at_depth`] with the single confirmation the bridge tests use.
fn settled() -> Settled {
    settled_at_depth(1)
}

/// Two proof-of-work domains registered at `confirmations`, with a committed
/// tip each, a bonded relayer, and two locks from `owner` toward `TARGET`
/// that the source domain committed in one block at `LOCK_HEIGHT`.
fn settled_at_depth(confirmations: u64) -> Settled {
    let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), None, CHAIN_ID, None);
    let operator = addr(0x41);
    for (id, op) in [(SOURCE, operator), (TARGET, addr(0x42))] {
        let mut domain = default_domain(
            id,
            ConsensusKind::PoW,
            CHAIN_ID,
            POW_HEADER_CHAIN_ADAPTER,
            confirmations,
        );
        domain.operator = Some(op);
        domain.last_committed_height = 50;
        domain.last_committed_hash = tip_of(id);
        bc.state
            .settlement
            .domains
            .register(domain)
            .expect("the domain registers");
        bc.state
            .settlement
            .commitments
            .insert(commitment(id, 50, tip_of(id), [0u8; 32], [0xE5; 32]))
            .expect("the committed tip is recorded");
    }

    let relayer = addr(0x43);
    let owner = addr(0x44);
    let recipient = addr(0x45);
    fund(&mut bc, relayer, owner, recipient);

    let mut events = Vec::new();
    for (index, local) in [[0x77u8; 32], [0x78u8; 32]].iter().enumerate() {
        let asset = AssetId::for_domain(SOURCE, local);
        execute_bridge_tx(
            &mut bc.state,
            &BridgeTxContext {
                sender: operator,
                fee: 0,
                height: 10,
            },
            &BridgeTx::RegisterAsset {
                asset_id: asset,
                domain: SOURCE,
            },
        )
        .expect("the operator registers the asset");
        let (_transfer, event) = lock(
            &mut bc.state,
            owner,
            &LockRequest {
                source_domain: SOURCE,
                target_domain: TARGET,
                source_height: LOCK_HEIGHT,
                event_index: u32::try_from(index).unwrap_or(u32::MAX),
                asset_id: asset,
                recipient,
                amount: LOCKED,
                expiry_height: 500,
            },
            10,
            10,
        )
        .expect("the owner locks on the source domain");
        events.push(event);
    }

    let mut tree = DomainEventTree::new();
    for event in &events {
        tree.push(event.clone());
    }
    bc.state
        .settlement
        .commitments
        .insert(commitment(
            SOURCE,
            LOCK_HEIGHT,
            SETTLED_BLOCK,
            [0u8; 32],
            tree.root(),
        ))
        .expect("the source block is committed");
    let second_proof = tree.proof(1).expect("the second lock is in the tree");
    let first_proof = tree.proof(0).expect("the first lock is in the tree");
    let second = events.pop().expect("two locks were made");
    let first = events.pop().expect("two locks were made");
    Settled {
        bc,
        relayer,
        owner,
        recipient,
        first: (first, first_proof),
        second: (second, second_proof),
    }
}

/// The rival commitment is not an error and does not replace the settled
/// one. It freezes the domain in the block that carries it, the certificate
/// row turns `Refuted`, and the other domain is not touched: it stays
/// active and takes its next commitment.
#[test]
fn a_rival_commitment_at_a_settled_height_freezes_the_domain_in_that_block() {
    let mut world = settled();
    assert_eq!(world.status_of(SOURCE), DomainStatus::Active);
    assert_eq!(world.verdict_of(SOURCE, 25), FinalityVerdict::Established);

    let outcome = world.rival_commitment_arrives();
    assert!(
        matches!(outcome, CommitmentOutcome::Frozen(_)),
        "{outcome:?}"
    );
    assert_eq!(world.status_of(SOURCE), DomainStatus::Frozen);
    assert_eq!(
        world.verdict_of(SOURCE, 25),
        FinalityVerdict::Refuted { code: 1 }
    );
    let settled_block = world
        .bc
        .state
        .settlement
        .commitments
        .find_by_height(SOURCE, LOCK_HEIGHT)
        .expect("the settled commitment stays in the book")
        .domain_block_hash;
    assert_eq!(
        settled_block, SETTLED_BLOCK,
        "the first block is not replaced"
    );

    assert_eq!(world.status_of(TARGET), DomainStatus::Active);
    assert_eq!(world.verdict_of(TARGET, 25), FinalityVerdict::Established);
    let next = accept_commitment(
        &mut world.bc.state,
        commitment(TARGET, 51, [0xF2; 32], tip_of(TARGET), [0xE6; 32]),
    )
    .expect("the other domain takes its next commitment");
    assert_eq!(next, CommitmentOutcome::Advanced);
}

/// Value follows the freeze to the block. The lock minted before the rival
/// arrived stays minted. The lock proven under the very same settled block
/// is not minted afterwards: it stays a lock, and its owner keeps the claim
/// the lock's own expiry gives.
#[test]
fn value_minted_before_the_freeze_stays_and_nothing_under_that_block_is_minted_after_it() {
    let mut world = settled();
    let recipient = world.recipient;
    let first = world.first.clone();
    let second = world.second.clone();

    world.mint(&first, 25).expect("the first lock is minted");
    let minted = world.balance(&recipient);
    assert!(minted > 100, "the recipient was credited");
    let still_locked = world.bc.state.bridge_state.locked_amount_total();
    assert_eq!(still_locked, u128::from(LOCKED), "one lock is still open");

    world.rival_commitment_arrives();

    let err = world
        .mint(&second, 26)
        .expect_err("a frozen domain mints nothing");
    assert!(
        err.contains("is refuted in the finality certificate"),
        "{err}"
    );
    assert_eq!(world.balance(&recipient), minted, "nothing is clawed back");
    assert_eq!(
        world.bc.state.bridge_state.locked_amount_total(),
        still_locked,
        "the second lock is still a lock"
    );
    for gate in [ValueGate::BridgeMint, ValueGate::BridgeUnlock] {
        assert!(enforce_domain_not_refuted(&world.bc.state.settlement, 26, gate, SOURCE).is_err());
    }

    let owner = world.owner;
    let before_expiry = world.balance(&owner);
    let released = world.bc.apply_bridge_sweep(500);
    assert_eq!(released.len(), 1, "only the unminted lock is released");
    assert_eq!(
        world.balance(&owner),
        before_expiry + LOCKED,
        "the unminted lock returns to its owner at its own expiry"
    );
}

/// The freeze closes the reorganised domain, not the way out. Value minted
/// before the freeze is burned on the healthy domain and unlocked to its
/// owner after the freeze, and every atom is accounted for.
#[test]
fn value_minted_before_the_freeze_still_leaves_through_the_healthy_domain() {
    let mut world = settled();
    let (owner, recipient, relayer) = (world.owner, world.recipient, world.relayer);
    let first = world.first.clone();
    let total = world.balance(&owner) + world.balance(&recipient) + world.balance(&relayer);
    let owner_after_locks = world.balance(&owner);

    world.mint(&first, 25).expect("the first lock is minted");
    world.rival_commitment_arrives();
    assert_eq!(world.status_of(SOURCE), DomainStatus::Frozen);

    let message_id = first
        .0
        .message
        .as_ref()
        .expect("a lock event carries its message")
        .message_id;
    let burn = burn_with_event(
        &mut world.bc.state,
        &BurnRequest {
            message_id,
            domain: TARGET,
            domain_height: 30,
            event_index: 0,
            expiry_height: 600,
            recipient_eth: [0xEE; 20],
        },
        10,
        30,
    )
    .expect("the recipient burns on the healthy domain");
    let mut tree = DomainEventTree::new();
    tree.push(burn.clone());
    world
        .bc
        .state
        .settlement
        .commitments
        .insert(commitment(TARGET, 30, [0xA2; 32], [0u8; 32], tree.root()))
        .expect("the healthy domain commits the burn");
    unlock_from_verified_event(
        &mut world.bc.state,
        &ProvenBridgeEvent {
            domain: TARGET,
            height: 30,
            sequence: 1,
            expected_block_hash: [0xA2; 32],
            event: burn,
            proof: tree.proof(0).expect("the burn is in the tree"),
        },
        35,
    )
    .expect("the unlock is proven under the healthy domain");

    assert!(
        world.balance(&owner) > owner_after_locks,
        "the owner has the bridged units back"
    );
    assert_eq!(
        world.balance(&owner) + world.balance(&recipient) + world.balance(&relayer),
        total + LOCKED,
        "the first lock came back whole, fee included"
    );
    assert_eq!(
        world.bc.state.bridge_state.locked_amount_total(),
        u128::from(LOCKED),
        "the second lock is still a lock"
    );
}

/// The value rule for proof-of-work reaches the mint door through the
/// economic guard. A guarded domain that registered fewer confirmations than
/// the value-safe depth has a zero ceiling and mints nothing, whatever work
/// its policy names. The same domain at the value-safe depth mints.
#[test]
fn a_guarded_proof_of_work_domain_below_the_value_safe_depth_mints_nothing() {
    let guard_source = |world: &mut Settled| {
        world
            .bc
            .state
            .bridge_state
            .economic_guard
            .configure_domain(
                SOURCE,
                DomainCeilingPolicy {
                    backing: SecurityBacking::Work {
                        difficulty_bits: 80,
                    },
                    work_window_cap_atoms: 1_000_000,
                    min_work_difficulty_bits: 64,
                    ..DomainCeilingPolicy::default()
                },
                None,
            )
            .expect("the policy is valid");
    };

    let mut shallow = settled_at_depth(1);
    guard_source(&mut shallow);
    let (first, recipient) = (shallow.first.clone(), shallow.recipient);
    let err = shallow
        .mint(&first, 25)
        .expect_err("one confirmation is below the value-safe depth");
    assert!(err.contains("ceiling=0"), "{err}");
    assert_eq!(shallow.balance(&recipient), 100);

    let mut deep = settled_at_depth(6);
    guard_source(&mut deep);
    let (first, recipient) = (deep.first.clone(), deep.recipient);
    deep.mint(&first, 25)
        .expect("six confirmations carry value");
    assert!(deep.balance(&recipient) > 100, "the recipient was credited");
}
