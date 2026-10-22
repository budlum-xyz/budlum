//! End-to-end state-machine sharding (Whitepaper v1.3).
//!
//! The commitment path: a sharded chain produces blocks that carry
//! `shards_root`, a validator replaying the block recomputes the commitment
//! from state and rejects any block that commits to something else, and a
//! cross-shard transfer moves value between two shards in one atomic state
//! transition whose effect is visible in both shard roots.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::sharding::{self, ShardingConfig};
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn sharded_chain() -> Blockchain {
    Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None).with_sharding(ShardingConfig {
        enabled: true,
        num_shards: 4,
        activation_height: 0,
    })
}

fn plain_chain() -> Blockchain {
    Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None)
}

#[test]
fn produced_block_carries_the_shards_commitment() {
    let mut bc = sharded_chain();
    // Fund accounts across two different shards (address first byte mod 4).
    bc.state.add_balance(&addr(0x01), 1_000); // shard 1
    bc.state.add_balance(&addr(0x02), 2_000); // shard 2
    bc.state.add_balance(&addr(0x03), 3_000); // shard 3

    let (block, _) = bc.produce_block(addr(0x11)).expect("block produced");
    let expected = sharding::shards_commitment(&bc.state, 4);
    assert_eq!(block.shards_root, Some(expected));
    assert!(
        block.shards_root.is_some(),
        "sharded block must carry shards_root"
    );
}

#[test]
fn plain_chain_produces_blocks_without_a_shards_commitment() {
    let mut bc = plain_chain();
    bc.state.add_balance(&addr(0x01), 1_000);
    let (block, _) = bc.produce_block(addr(0x11)).expect("block produced");
    assert_eq!(
        block.shards_root, None,
        "unsharded chain must not carry shards_root"
    );
}

#[test]
fn validator_accepts_an_honest_shards_commitment() {
    let mut producer = sharded_chain();
    producer.state.add_balance(&addr(0x01), 1_000);
    producer.state.add_balance(&addr(0x02), 2_000);
    let (block, _) = producer.produce_block(addr(0x11)).expect("block produced");

    let mut verifier = sharded_chain();
    verifier.state.add_balance(&addr(0x01), 1_000);
    verifier.state.add_balance(&addr(0x02), 2_000);
    verifier
        .validate_and_add_block(block)
        .expect("honest shards commitment accepted");
}

#[test]
fn validator_rejects_a_wrong_shards_commitment() {
    let mut producer = sharded_chain();
    producer.state.add_balance(&addr(0x01), 1_000);
    let (mut block, _) = producer.produce_block(addr(0x11)).expect("block produced");
    block.shards_root = Some([0xAA; 32]);
    block.hash = block.calculate_hash();

    let mut verifier = sharded_chain();
    verifier.state.add_balance(&addr(0x01), 1_000);
    let err = verifier
        .validate_and_add_block(block)
        .expect_err("a wrong shards commitment must be rejected");
    assert!(
        err.contains("Shards commitment mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn validator_rejects_a_missing_commitment_after_activation() {
    let mut producer = sharded_chain();
    producer.state.add_balance(&addr(0x01), 1_000);
    let (mut block, _) = producer.produce_block(addr(0x11)).expect("block produced");
    block.shards_root = None;
    block.hash = block.calculate_hash();

    let mut verifier = sharded_chain();
    verifier.state.add_balance(&addr(0x01), 1_000);
    let err = verifier
        .validate_and_add_block(block)
        .expect_err("a missing commitment must be rejected after activation");
    assert!(
        err.contains("missing the shards commitment"),
        "unexpected error: {err}"
    );
}

#[test]
fn cross_shard_transfer_is_visible_in_both_shard_roots() {
    let mut bc = sharded_chain();
    bc.state.add_balance(&addr(0x01), 1_000); // shard 1
    bc.state.add_balance(&addr(0x02), 0); // shard 2

    let before_from = bc.state.get_balance(&addr(0x01));
    let before_to = bc.state.get_balance(&addr(0x02));
    let before_shard1 = sharding::shard_state_root(&bc.state, sharding::ShardId(1), 4);
    let before_shard2 = sharding::shard_state_root(&bc.state, sharding::ShardId(2), 4);

    let tx = Transaction::new_with_chain_id(
        addr(0x01),
        addr(0x02),
        300,
        5,
        0,
        Vec::new(),
        45262,
        TransactionType::Transfer,
    );
    assert!(sharding::is_cross_shard(&tx, 4));
    sharding::apply_cross_shard_transfer(&mut bc.state, &tx, 4)
        .expect("atomic cross-shard transfer applies");

    let after_shard1 = sharding::shard_state_root(&bc.state, sharding::ShardId(1), 4);
    let after_shard2 = sharding::shard_state_root(&bc.state, sharding::ShardId(2), 4);
    assert_ne!(before_shard1, after_shard1, "source shard root must change");
    assert_ne!(
        before_shard2, after_shard2,
        "destination shard root must change"
    );

    // Genesis funds accounts, so assert on the delta, not the absolute value.
    assert_eq!(
        bc.state.get_balance(&addr(0x01)),
        before_from - 305,
        "source must lose amount + fee"
    );
    assert_eq!(
        bc.state.get_balance(&addr(0x02)),
        before_to + 300,
        "destination must gain the amount"
    );
}
