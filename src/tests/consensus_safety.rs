//! Consensus safety invariant tests: verify that the consensus constants are
//! bounded and internally consistent.

use crate::consensus::{
    MAX_BLOCK_SIZE, MAX_FUTURE_BLOCK_TIME_MS, MAX_LEADER_ROUNDS, MAX_PAST_BLOCK_TIME_MS,
    MAX_REORG_DEPTH, MAX_SLASHING_EVIDENCE_BYTES, MAX_TRANSACTIONS_PER_BLOCK,
    MIN_BLOCK_INTERVAL_MS, ROUND_TIMEOUT_MS,
};

#[test]
fn block_size_is_bounded() {
    assert!(
        MAX_BLOCK_SIZE >= 100_000,
        "block size too small for useful txs"
    );
    assert!(MAX_BLOCK_SIZE <= 10_000_000, "block size exceeds 10MB");
}

#[test]
fn max_transactions_per_block_is_bounded() {
    assert!(MAX_TRANSACTIONS_PER_BLOCK >= 100);
    assert!(MAX_TRANSACTIONS_PER_BLOCK <= 50_000);
}

#[test]
fn reorg_depth_is_bounded() {
    assert!(MAX_REORG_DEPTH >= 10, "reorg depth too shallow");
    assert!(MAX_REORG_DEPTH <= 1_000, "reorg depth dangerously deep");
}

#[test]
fn future_block_time_is_fifteen_seconds() {
    assert_eq!(MAX_FUTURE_BLOCK_TIME_MS, 15_000);
}

#[test]
fn past_block_time_is_two_hours() {
    assert_eq!(MAX_PAST_BLOCK_TIME_MS, 2 * 60 * 60 * 1000);
}

#[test]
fn min_block_interval_is_one_second() {
    assert_eq!(MIN_BLOCK_INTERVAL_MS, 1_000);
}

#[test]
fn round_timeout_is_three_seconds() {
    assert_eq!(ROUND_TIMEOUT_MS, 3_000);
}

#[test]
fn max_leader_rounds_is_sixteen() {
    assert_eq!(MAX_LEADER_ROUNDS, 16);
}

#[test]
fn slashing_evidence_is_bounded() {
    assert!(MAX_SLASHING_EVIDENCE_BYTES >= 1_024);
    assert!(MAX_SLASHING_EVIDENCE_BYTES <= 1_000_000);
}

#[test]
fn block_interval_less_than_round_timeout() {
    assert!(
        MIN_BLOCK_INTERVAL_MS < ROUND_TIMEOUT_MS,
        "block interval must be less than round timeout"
    );
}

#[test]
fn round_timeout_less_than_future_block_time() {
    assert!(
        ROUND_TIMEOUT_MS < MAX_FUTURE_BLOCK_TIME_MS,
        "round timeout must be less than future block time tolerance"
    );
}
