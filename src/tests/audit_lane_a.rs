//! Preliminary WP-01 regression coverage for the existing leader-round clock.
//! This does not establish four-node finality or close the finding by itself.

use crate::consensus::{
    affordable_leader_round, MAX_LEADER_ROUNDS, MIN_BLOCK_INTERVAL_MS, ROUND_TIMEOUT_MS,
};

#[test]
fn audit_lane_a_leader_rounds_advance_only_after_each_timeout() {
    let parent = 1_000_000u128;
    let start = parent + MIN_BLOCK_INTERVAL_MS;

    assert_eq!(affordable_leader_round(parent, parent - 1), 0);
    assert_eq!(affordable_leader_round(parent, start), 0);
    for round in 1..=MAX_LEADER_ROUNDS {
        let boundary = start + u128::from(round) * ROUND_TIMEOUT_MS;
        assert_eq!(affordable_leader_round(parent, boundary - 1), round - 1);
        assert_eq!(affordable_leader_round(parent, boundary), round);
    }
    assert_eq!(
        affordable_leader_round(parent, u128::MAX),
        MAX_LEADER_ROUNDS
    );
}
