//! Consensus regression tests for block `shards_root` binding and binary
//! protobuf `BlockBudget` enforcement across tip validation and candidate
//! reorg validation.

use budlum_core::chain::blockchain::Blockchain;
use budlum_core::consensus::budget::{BODY_BUDGET_BYTES, MAX_TX_BYTES, WITNESS_BUDGET_BYTES};
use budlum_core::consensus::pow::PoWEngine;
use budlum_core::consensus::ConsensusEngine;
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use budlum_core::core::transaction::{Transaction, TransactionType};
use budlum_core::sharding::ShardingConfig;
use std::sync::Arc;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
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
fn inactive_sharding_rejects_spurious_shards_root_on_tip_ingest() {
    let mut producer = plain_chain();
    producer.state.add_balance(&addr(0x01), 1_000);
    let (mut block, _) = producer.produce_block(addr(0x11)).expect("block produced");
    assert_eq!(block.shards_root, None);

    // Attach an unverified shards_root while sharding is inactive and re-seal
    // the block hash so only the shards_root rule can stop it.
    block.shards_root = Some([0xDE; 32]);
    block.hash = block.calculate_hash();

    let mut verifier = plain_chain();
    verifier.state.add_balance(&addr(0x01), 1_000);
    let err = verifier
        .validate_and_add_block(block)
        .expect_err("inactive sharding must reject a non-empty shards_root");
    assert!(
        err.to_ascii_lowercase().contains("shards"),
        "expected shards_root rejection, got: {err}"
    );
}

#[test]
fn candidate_reorg_rejects_wrong_shards_root_when_sharding_active() {
    let mut local = sharded_chain();
    let _ = local.produce_block(addr(0x11)).expect("local block 1");

    let mut fork = sharded_chain();
    let _ = fork.produce_block(addr(0x22)).expect("fork block 1");
    let _ = fork.produce_block(addr(0x22)).expect("fork block 2");

    let mut bad_chain = fork.chain.clone();
    let tip = bad_chain.last_mut().expect("fork tip");
    tip.shards_root = Some([0xAA; 32]);
    tip.hash = tip.calculate_hash();

    let err = local
        .try_reorg(bad_chain)
        .expect_err("candidate chain with forged shards_root must be rejected");
    assert!(
        err.to_ascii_lowercase().contains("shards"),
        "expected shards_root rejection on candidate chain, got: {err}"
    );
}

#[test]
fn candidate_reorg_rejects_missing_shards_root_when_sharding_active() {
    let mut local = sharded_chain();
    let _ = local.produce_block(addr(0x11)).expect("local block 1");

    let mut fork = sharded_chain();
    let _ = fork.produce_block(addr(0x22)).expect("fork block 1");
    let _ = fork.produce_block(addr(0x22)).expect("fork block 2");

    let mut bad_chain = fork.chain.clone();
    let tip = bad_chain.last_mut().expect("fork tip");
    tip.shards_root = None;
    tip.hash = tip.calculate_hash();

    let err = local
        .try_reorg(bad_chain)
        .expect_err("candidate chain missing active shards_root must be rejected");
    assert!(
        err.to_ascii_lowercase().contains("shards"),
        "expected missing shards_root rejection on candidate chain, got: {err}"
    );
}

#[test]
fn candidate_reorg_rejects_spurious_shards_root_when_sharding_inactive() {
    let mut local = plain_chain();
    let _ = local.produce_block(addr(0x11)).expect("local block 1");

    let mut fork = plain_chain();
    let _ = fork.produce_block(addr(0x22)).expect("fork block 1");
    let _ = fork.produce_block(addr(0x22)).expect("fork block 2");

    let mut bad_chain = fork.chain.clone();
    let tip = bad_chain.last_mut().expect("fork tip");
    tip.shards_root = Some([0xBE; 32]);
    tip.hash = tip.calculate_hash();

    let err = local
        .try_reorg(bad_chain)
        .expect_err("candidate chain with spurious inactive shards_root must be rejected");
    assert!(
        err.to_ascii_lowercase().contains("shards"),
        "expected spurious shards_root rejection on candidate chain, got: {err}"
    );
}

#[test]
fn consensus_block_size_rejects_single_tx_over_binary_tx_budget() {
    let engine = PoWEngine::new(0);
    // Construct one transaction whose binary payload exceeds MAX_TX_BYTES
    // (160 KiB) while keeping total serialized JSON well below MAX_BLOCK_SIZE
    // (1,000,000 bytes). Without binary BlockBudget wiring this slips past the
    // JSON-only block cap.
    let oversized_data = vec![0x42u8; MAX_TX_BYTES + 128];
    let tx = Transaction::new_with_chain_id(
        addr(0x01),
        addr(0x02),
        10,
        5,
        0,
        oversized_data,
        45262,
        TransactionType::Transfer,
    );
    let block = Block::new(1, "0".repeat(64), vec![tx]);
    // Confirm the JSON size alone would NOT have tripped MAX_BLOCK_SIZE.
    let json_len = serde_json::to_vec(&block).expect("json encodes").len();
    assert!(
        json_len < budlum_core::consensus::MAX_BLOCK_SIZE,
        "test setup expects JSON size ({json_len}) below MAX_BLOCK_SIZE so only BlockBudget rejects it"
    );

    let err = engine
        .validate_block_size(&block)
        .expect_err("transaction exceeding MAX_TX_BYTES must be rejected by binary block budget");
    assert!(
        err.0.to_ascii_lowercase().contains("budget")
            || err.0.to_ascii_lowercase().contains("tx")
            || err.0.to_ascii_lowercase().contains("163840"),
        "unexpected error: {}",
        err.0
    );
}

#[test]
fn consensus_block_size_enforces_binary_witness_and_body_budgets() {
    let engine = PoWEngine::new(0);

    // Oversized witness section: pack binary witness bytes across the block
    // producer signature field above WITNESS_BUDGET_BYTES (2,000,000 bytes).
    let mut witness_heavy = Block::new(1, "0".repeat(64), Vec::new());
    witness_heavy.signature = Some(vec![0x77u8; WITNESS_BUDGET_BYTES + 1]);
    let witness_err = engine
        .validate_block_size(&witness_heavy)
        .expect_err("block exceeding binary witness budget must be rejected");
    assert!(
        witness_err.0.to_ascii_lowercase().contains("budget")
            || witness_err.0.to_ascii_lowercase().contains("witness"),
        "expected binary witness budget error, got: {}",
        witness_err.0
    );

    // Oversized body section via many valid-sized transactions whose combined
    // binary body crosses BODY_BUDGET_BYTES (1,000,000 bytes).
    let per_tx_bytes = 120_000usize;
    let count = (BODY_BUDGET_BYTES / per_tx_bytes) + 2;
    let txs: Vec<Transaction> = (0..count)
        .map(|i| {
            Transaction::new_with_chain_id(
                addr(0x01),
                addr(0x02),
                1,
                5,
                i as u64,
                vec![0x11u8; per_tx_bytes],
                45262,
                TransactionType::Transfer,
            )
        })
        .collect();
    let body_heavy = Block::new(1, "0".repeat(64), txs);
    let body_err = engine
        .validate_block_size(&body_heavy)
        .expect_err("block exceeding binary body budget must be rejected");
    assert!(
        body_err.0.to_ascii_lowercase().contains("budget")
            || body_err.0.to_ascii_lowercase().contains("body"),
        "expected binary body budget error, got: {}",
        body_err.0
    );
}

#[test]
fn candidate_reorg_accepts_valid_sharded_fork_with_matching_shards_root() {
    let mut local = sharded_chain();
    let _ = local.produce_block(addr(0x11)).expect("local block 1");

    let mut fork = sharded_chain();
    let _ = fork.produce_block(addr(0x22)).expect("fork block 1");
    let (tip, _) = fork.produce_block(addr(0x22)).expect("fork block 2");
    assert!(tip.shards_root.is_some());

    let reorged = local
        .try_reorg(fork.chain.clone())
        .expect("valid longer sharded fork must be accepted");
    assert!(reorged, "longer valid sharded fork should replace tip");
    assert_eq!(local.chain.last().map(|b| &b.hash), Some(&tip.hash));
}

#[test]
fn binary_block_budget_splits_body_and_witness_accounting_deterministically() {
    use budlum_core::consensus::budget::{validate_block_budget, BudgetError, Section};

    // 1.5 MiB PQ witness fits inside WITNESS_BUDGET_BYTES (2,000,000) while
    // leaving BODY_BUDGET_BYTES (1,000,000) virtually untouched.
    let mut pq_witness_block = Block::new(1, "0".repeat(64), Vec::new());
    pq_witness_block.signature = Some(vec![0x33u8; 1_500_000]);
    let used = validate_block_budget(&pq_witness_block)
        .expect("1.5 MiB witness fits inside 2 MiB binary witness budget");
    assert!(used.used(Section::Witness) >= 1_500_000);
    assert!(used.used(Section::Body) < 10_000);

    // Witness above WITNESS_BUDGET_BYTES fails with OverBudget(Witness).
    let mut over_witness = Block::new(1, "0".repeat(64), Vec::new());
    over_witness.signature = Some(vec![0x44u8; WITNESS_BUDGET_BYTES + 1]);
    assert_eq!(
        validate_block_budget(&over_witness).unwrap_err(),
        BudgetError::OverBudget(Section::Witness)
    );

    // Body above BODY_BUDGET_BYTES via valid-sized transactions fails with
    // OverBudget(Body).
    let per_tx = 120_000usize;
    let count = (BODY_BUDGET_BYTES / per_tx) + 2;
    let txs: Vec<Transaction> = (0..count)
        .map(|i| {
            Transaction::new_with_chain_id(
                addr(0x01),
                addr(0x02),
                1,
                5,
                i as u64,
                vec![0x22u8; per_tx],
                45262,
                TransactionType::Transfer,
            )
        })
        .collect();
    let over_body = Block::new(1, "0".repeat(64), txs);
    assert_eq!(
        validate_block_budget(&over_body).unwrap_err(),
        BudgetError::OverBudget(Section::Body)
    );
}
