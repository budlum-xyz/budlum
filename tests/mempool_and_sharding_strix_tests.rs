//! Regression and security tests for mempool authorization caching, duty-lane
//! replacement and size bounds, multi-lane nonce ordering, and cross-shard
//! transfer guards (`src/mempool/`, `src/sharding/mod.rs`).

use budlum_core::core::account::AccountState;
use budlum_core::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use budlum_core::core::Address;
use budlum_core::crypto::primitives::KeyPair;
use budlum_core::mempool::duty_lane::DutyRefusal;
use budlum_core::mempool::lanes::{LaneEntry, LaneKind, LaneReplayRule, MultiLaneMempool};
use budlum_core::mempool::pool::{Mempool, MempoolConfig, MempoolError};
use budlum_core::sharding::{apply_cross_shard_transfer, MAX_SHARDS};
use budlum_core::storage::bud3::tx::StorageTxV3;

fn signed_transfer(kp: &KeyPair, to: Address, amount: u64, fee: u64, nonce: u64) -> Transaction {
    let from = Address::from(kp.public_key_bytes());
    let mut tx = Transaction::new_with_chain_id(
        from,
        to,
        amount,
        fee,
        nonce,
        Vec::new(),
        DEFAULT_CHAIN_ID,
        TransactionType::Transfer,
    );
    tx.sign(kp);
    tx
}

fn signed_duty_ack(kp: &KeyPair, nonce: u64, fee: u64, object: [u8; 32]) -> Transaction {
    let from = Address::from(kp.public_key_bytes());
    let mut tx = Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        fee,
        nonce,
        Vec::new(),
        DEFAULT_CHAIN_ID,
        TransactionType::StorageV3(Box::new(StorageTxV3::CustodyAck { object })),
    );
    tx.sign(kp);
    tx
}

/// VULN 1 (`mempool/pool.rs` authority_cache): `auth_claim` lies outside
/// `signing_hash()` and is explicitly refused by `Transaction::verify_in`.
/// A cached authorization digest for an honest transaction must NEVER let a
/// mutated copy carrying `auth_claim = Some(...)` bypass `verify_in`.
#[test]
fn authority_cache_does_not_bypass_auth_claim_rejection() {
    let kp = KeyPair::from_seed(&[0x11; 32]).expect("keypair");
    let to = Address::from([0x22; 32]);
    let tx = signed_transfer(&kp, to, 100, 1_000, 0);
    let tx_hash = tx.hash.clone();

    let mut pool = Mempool::new(MempoolConfig::default());
    pool.admit_at(tx.clone(), 1_000_000)
        .expect("honest tx admitted and cached");
    pool.remove_transaction(&tx_hash);

    let mut claimed = tx;
    claimed.auth_claim = Some([0xAA; 32]);
    assert!(
        !claimed.verify(),
        "Transaction::verify must refuse standalone claimed tx"
    );

    let res = pool.admit_at(claimed, 1_000_001);
    assert!(
        matches!(res, Err(MempoolError::InvalidTransaction(_))),
        "claimed tx must be rejected even after identical honest tx populated authority_cache, got {res:?}"
    );
}

/// VULN 2 (`mempool/pool.rs` RBF / duty lane): A registered validator must NOT
/// be able to replace a pending paying non-duty transaction at the same nonce
/// with a zero-fee duty transaction without paying the RBF fee bump.
#[test]
fn zero_fee_duty_batch_cannot_replace_paying_non_duty_tx_without_rbf_bump() {
    let kp = KeyPair::from_seed(&[0x33; 32]).expect("validator keypair");
    let validator = Address::from(kp.public_key_bytes());
    let to = Address::from([0x44; 32]);

    let mut pool = Mempool::new(MempoolConfig::default());
    pool.sync_duty_validators([validator]);

    let paying = signed_transfer(&kp, to, 500, 10_000, 0);
    let paying_hash = paying.hash.clone();
    pool.admit_at(paying, 600_000)
        .expect("paying transfer admitted");

    // Attempt free cancellation at same nonce 0 with fee=0 CustodyAck.
    let zero_fee_duty = signed_duty_ack(&kp, 0, 0, [0x55; 32]);
    let res = pool.admit_at(zero_fee_duty, 600_001);
    assert_eq!(
        res,
        Err(MempoolError::RbfFeeTooLow),
        "zero-fee duty tx must not evict a high-fee non-duty tx at the same nonce"
    );
    assert!(
        pool.get(&paying_hash).is_some(),
        "paying tx must remain in pool after refused zero-fee duty replacement"
    );
}

/// VULN 3 (`mempool/pool.rs` duty lane): A duty batch larger than both the
/// per-block duty share AND the total duty-lane cap must be refused immediately
/// with `BatchExceedsBlockShare` (not fall through into eviction / `LaneBytesFull`).
#[test]
fn oversized_duty_batch_exceeding_both_share_and_cap_returns_batch_exceeds_block_share() {
    let kp = KeyPair::from_seed(&[0x66; 32]).expect("validator keypair");
    let validator = Address::from(kp.public_key_bytes());

    // Configure a tight duty block share (`duty_block_bytes = 64`) so any real
    // signed duty batch exceeds BOTH `share` (64) and `duty_lane_cap` (4*64 = 256).
    let cfg = MempoolConfig {
        duty_block_bytes: 64,
        ..MempoolConfig::default()
    };
    let mut pool = Mempool::new(cfg);
    pool.sync_duty_validators([validator]);

    let oversized = signed_duty_ack(&kp, 0, 0, [0x77; 32]);
    let res = pool.admit_at(oversized, 600_000);
    assert!(
        matches!(
            res,
            Err(MempoolError::DutyLaneRefused(
                DutyRefusal::BatchExceedsBlockShare { .. }
            ))
        ),
        "batch larger than per-block share must fail immediately with BatchExceedsBlockShare, got {res:?}"
    );
}

/// VULN 4 (`mempool/lanes.rs`): `MultiLaneMempool::select_for_block` must never
/// select a sender's higher nonce ahead of (or without) their lower pending
/// nonce when the higher nonce carries a larger priority tip.
#[test]
fn multi_lane_selection_preserves_per_sender_nonce_order_under_inverted_tips() {
    let mut lanes = MultiLaneMempool::new(16, 65_536);
    let sender = [0x99; 32];

    let nonce_0 = LaneEntry {
        tx_hash: [0x01; 32],
        lane: LaneKind::Local,
        replay: LaneReplayRule::AccountNonce { sender, nonce: 0 },
        gas_limit_bgu: 21_000,
        max_fee_per_bgu_atto: 100,
        max_priority_fee_per_bgu_atto: 10,
        raw_bytes: vec![0xA0; 32],
    };
    let nonce_1 = LaneEntry {
        tx_hash: [0x02; 32],
        lane: LaneKind::Local,
        replay: LaneReplayRule::AccountNonce { sender, nonce: 1 },
        gas_limit_bgu: 21_000,
        max_fee_per_bgu_atto: 500,
        max_priority_fee_per_bgu_atto: 400,
        raw_bytes: vec![0xA1; 32],
    };
    lanes.admit(nonce_0.clone(), 1_000).expect("admit nonce 0");
    lanes.admit(nonce_1.clone(), 1_000).expect("admit nonce 1");

    // When both fit in the block, nonce 0 MUST precede nonce 1.
    let both = lanes.select_for_block(50, 100_000);
    assert_eq!(both.len(), 2);
    assert_eq!(
        both[0].tx_hash, nonce_0.tx_hash,
        "nonce 0 must be ordered before nonce 1 even when nonce 1 has a higher tip"
    );
    assert_eq!(both[1].tx_hash, nonce_1.tx_hash);

    // When only one transaction fits in the block, nonce 0 (NOT nonce 1) must be picked.
    let single = lanes.select_for_block(50, 21_000);
    assert_eq!(single.len(), 1);
    assert_eq!(
        single[0].tx_hash, nonce_0.tx_hash,
        "cannot pick nonce 1 without nonce 0 under tight BGU budget"
    );
}

/// VULN 5 (`sharding/mod.rs`): `apply_cross_shard_transfer` must fail closed
/// on a zero-address sender (`Address::zero()`) and on out-of-range shard
/// counts (`num_shards < 2` or `num_shards > MAX_SHARDS`) without mutating state.
#[test]
fn cross_shard_transfer_rejects_zero_sender_and_invalid_num_shards() {
    let mut state = AccountState::new();
    let zero = Address::zero();
    let alice = Address::from([0x02; 32]);
    let bob = Address::from([0x03; 32]);
    state.get_or_create(&zero).balance = 1_000;
    state.get_or_create(&alice).balance = 1_000;

    // Zero-address sender must be rejected fail-closed.
    let from_zero = Transaction::new_with_chain_id(
        zero,
        bob,
        100,
        10,
        0,
        Vec::new(),
        DEFAULT_CHAIN_ID,
        TransactionType::Transfer,
    );
    assert!(
        apply_cross_shard_transfer(&mut state, &from_zero, 4).is_err(),
        "zero-address sender must be refused by apply_cross_shard_transfer"
    );
    assert_eq!(state.get_balance(&zero), 1_000);
    assert_eq!(state.get_balance(&bob), 0);

    // Out-of-range `num_shards > MAX_SHARDS` must be refused instead of silently
    // clamping to `MAX_SHARDS`.
    let valid_tx = Transaction::new_with_chain_id(
        alice,
        bob,
        100,
        10,
        0,
        Vec::new(),
        DEFAULT_CHAIN_ID,
        TransactionType::Transfer,
    );
    assert!(
        apply_cross_shard_transfer(&mut state, &valid_tx, MAX_SHARDS + 1).is_err(),
        "num_shards > MAX_SHARDS must fail closed instead of silently clamping"
    );
    assert_eq!(state.get_balance(&alice), 1_000);
    assert_eq!(state.get_balance(&bob), 0);
}

/// Positive regression: a validator replacing an existing pending duty batch
/// with a fresh duty batch at the same nonce MUST remain fee-free.
#[test]
fn duty_batch_can_still_replace_existing_duty_batch_at_same_nonce_without_fee() {
    let kp = KeyPair::from_seed(&[0x88; 32]).expect("validator keypair");
    let validator = Address::from(kp.public_key_bytes());

    let mut pool = Mempool::new(MempoolConfig::default());
    pool.sync_duty_validators([validator]);

    let first = signed_duty_ack(&kp, 0, 0, [0x11; 32]);
    let first_hash = first.hash.clone();
    pool.admit_at(first, 600_000)
        .expect("initial duty batch admitted");

    let replacement = signed_duty_ack(&kp, 0, 0, [0x22; 32]);
    let replacement_hash = replacement.hash.clone();
    pool.admit_at(replacement, 600_001)
        .expect("duty batch replacing duty batch at same nonce must succeed fee-free");
    assert!(pool.get(&first_hash).is_none());
    assert!(pool.get(&replacement_hash).is_some());
}

/// Unaffordable `nonce = 0` must block a higher-tip `nonce = 1` from the same
/// sender, while independent senders in the same or other lanes still advance.
#[test]
fn unaffordable_lower_nonce_blocks_higher_nonce_without_starving_other_senders() {
    let mut lanes = MultiLaneMempool::new(16, 65_536);
    let stuck_sender = [0xAA; 32];
    let honest_sender = [0xBB; 32];

    // stuck_sender nonce 0 is unaffordable at base_fee = 100.
    lanes
        .admit(
            LaneEntry {
                tx_hash: [0x10; 32],
                lane: LaneKind::Ethereum,
                replay: LaneReplayRule::AccountNonce {
                    sender: stuck_sender,
                    nonce: 0,
                },
                gas_limit_bgu: 21_000,
                max_fee_per_bgu_atto: 50,
                max_priority_fee_per_bgu_atto: 10,
                raw_bytes: vec![0x01; 32],
            },
            1_000,
        )
        .expect("admit stuck nonce 0");
    // stuck_sender nonce 1 pays a huge tip, yet cannot execute ahead of nonce 0.
    lanes
        .admit(
            LaneEntry {
                tx_hash: [0x11; 32],
                lane: LaneKind::Ethereum,
                replay: LaneReplayRule::AccountNonce {
                    sender: stuck_sender,
                    nonce: 1,
                },
                gas_limit_bgu: 21_000,
                max_fee_per_bgu_atto: 1_000,
                max_priority_fee_per_bgu_atto: 900,
                raw_bytes: vec![0x02; 32],
            },
            1_000,
        )
        .expect("admit stuck nonce 1");
    // honest_sender in Cosmos lane must still be selected cleanly.
    lanes
        .admit(
            LaneEntry {
                tx_hash: [0x20; 32],
                lane: LaneKind::Cosmos,
                replay: LaneReplayRule::CosmosSequence {
                    sender: honest_sender,
                    account_number: 7,
                    sequence: 0,
                },
                gas_limit_bgu: 21_000,
                max_fee_per_bgu_atto: 200,
                max_priority_fee_per_bgu_atto: 50,
                raw_bytes: vec![0x03; 32],
            },
            1_000,
        )
        .expect("admit cosmos seq 0");

    let picked = lanes.select_for_block(100, 100_000);
    assert_eq!(picked.len(), 1);
    assert_eq!(
        picked[0].tx_hash, [0x20; 32],
        "stuck nonce 0 must block nonce 1 while honest sender still gets included"
    );
}
