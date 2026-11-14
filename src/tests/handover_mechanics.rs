//! Instant Duty Handover (Section 7.6) and Disaster Recovery (Section 7.7) tests.

use crate::validators::handover::{
    FINALITY_STALL_BLOCKS, FINALITY_STALL_CHECKPOINTS, FULL_DURABILITY_UNSEEN_HOURS,
    MOBILE_DURABILITY_UNSEEN_HOURS, PRESENCE_FALLBACK_MAX_BLOCKS, PROPOSER_ROUND_TIMEOUT_MS,
    RECOVERY_COMMITTEE_WAIT_EPOCHS, SEAT_MAX_HANDOVER_DIVISOR,
    SEAT_MISSED_CHECKPOINTS_FOR_HANDOVER, TESTNET_CHECKPOINT_INTERVAL_BLOCKS,
};

/// Proposer round timeout matches the consensus round timeout.
#[test]
fn proposer_timeout_matches_consensus() {
    assert_eq!(PROPOSER_ROUND_TIMEOUT_MS, 3_000);
}

/// Seat handover threshold is 2 missed checkpoints.
#[test]
fn seat_handover_threshold_is_two() {
    assert_eq!(SEAT_MISSED_CHECKPOINTS_FOR_HANDOVER, 2);
}

/// Seat max handover divisor is 10 (at most 10% of seats per checkpoint).
#[test]
fn seat_max_handover_is_ten_percent() {
    assert_eq!(SEAT_MAX_HANDOVER_DIVISOR, 10);
}

/// Testnet checkpoint interval is 5 blocks.
#[test]
fn testnet_checkpoint_interval_is_five() {
    assert_eq!(TESTNET_CHECKPOINT_INTERVAL_BLOCKS, 5);
}

/// Full validator unseen window is 24 hours.
#[test]
fn full_unseen_window_is_24h() {
    assert_eq!(FULL_DURABILITY_UNSEEN_HOURS, 24);
}

/// Mobile validator unseen window is 7 days (168 hours).
#[test]
fn mobile_unseen_window_is_7d() {
    assert_eq!(MOBILE_DURABILITY_UNSEEN_HOURS, 168);
}

/// Presence fallback is 1 block maximum delay.
#[test]
fn presence_fallback_is_one_block() {
    assert_eq!(PRESENCE_FALLBACK_MAX_BLOCKS, 1);
}

/// Finality stall threshold is 8 checkpoint intervals.
#[test]
fn finality_stall_is_eight_checkpoints() {
    assert_eq!(FINALITY_STALL_CHECKPOINTS, 8);
}

/// Finality stall blocks is checkpoint_interval * stall_checkpoints.
#[test]
fn finality_stall_blocks_is_consistent() {
    assert_eq!(
        FINALITY_STALL_BLOCKS,
        FINALITY_STALL_CHECKPOINTS * TESTNET_CHECKPOINT_INTERVAL_BLOCKS
    );
    assert_eq!(FINALITY_STALL_BLOCKS, 40);
}

/// Recovery committee wait is 1 epoch.
#[test]
fn recovery_wait_is_one_epoch() {
    assert_eq!(RECOVERY_COMMITTEE_WAIT_EPOCHS, 1);
}

/// Handover math: for a 21-seat committee, at most 3 can hand over per checkpoint.
#[test]
fn handover_cap_for_21_seats() {
    let seats = 21usize;
    let max_handover = seats.div_ceil(SEAT_MAX_HANDOVER_DIVISOR);
    assert_eq!(max_handover, 3);
}

/// Handover math: for a 7-seat committee, at most 1 can hand over per checkpoint.
#[test]
fn handover_cap_for_7_seats() {
    let seats = 7usize;
    let max_handover = seats.div_ceil(SEAT_MAX_HANDOVER_DIVISOR);
    assert_eq!(max_handover, 1);
}

/// Handover math: for a 100-seat committee, at most 10 can hand over per checkpoint.
#[test]
fn handover_cap_for_100_seats() {
    let seats = 100usize;
    let max_handover = seats.div_ceil(SEAT_MAX_HANDOVER_DIVISOR);
    assert_eq!(max_handover, 10);
}
