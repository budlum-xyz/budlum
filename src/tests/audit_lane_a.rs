//! Lane A regression coverage for leader-round timing and retired state updates.
//! These tests do not establish four-node finality or close findings by themselves.

use crate::consensus::{
    affordable_leader_round, MAX_LEADER_ROUNDS, MIN_BLOCK_INTERVAL_MS, ROUND_TIMEOUT_MS,
};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::execution::executor::Executor;

fn address(byte: u8) -> Address {
    let mut bytes = [0; 32];
    bytes[0] = byte;
    Address::from(bytes)
}

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

#[test]
fn audit_lane_a_blg_019_retired_state_update_preserves_accounts() {
    // Exercise the executor's structured refusal on both testnet and devnet,
    // including duplicate victim entries and an attempted sender nonce write.
    for chain_id in [45261, 45262] {
        let sender = address(0xad);
        let victim = address(0xb0);
        let mut state = AccountState::new();
        state.add_balance(&sender, 1_000_000);
        state.add_balance(&victim, 500);
        let transaction = Transaction::new_with_chain_id(
            sender,
            Address::zero(),
            0,
            1,
            state.get_nonce(&sender),
            Vec::new(),
            chain_id,
            TransactionType::StateUpdate {
                domain_id: 1,
                domain_height: 1,
                state_updates: vec![(victim, 123), (victim, u64::MAX - 1001), (sender, 42)],
            },
        );

        let error = Executor::apply_transaction_checked(&mut state, &transaction)
            .expect_err("the retired state update must be refused");
        assert_eq!(error.code(), "state_update_retired");
        assert_eq!(state.get_nonce(&victim), 0);
        assert_eq!(state.get_nonce(&sender), 0);
        assert_eq!(state.get_balance(&victim), 500);
        assert_eq!(state.get_balance(&sender), 1_000_000);
    }
}
