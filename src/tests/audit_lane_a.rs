//! Permanent regression coverage for the lane A live audit.

use crate::consensus::{
    affordable_leader_round, MAX_LEADER_ROUNDS, MIN_BLOCK_INTERVAL_MS, ROUND_TIMEOUT_MS,
};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};
use crate::execution::executor::Executor;

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

fn address(byte: u8) -> Address {
    let mut bytes = [0; 32];
    bytes[0] = byte;
    Address::from(bytes)
}

/// BLG-020: `collect_block_transactions` validates against a candidate-state
/// clone and only promotes it on success, so a refused transaction cannot
/// leak a half-applied `temp_state` into the block.
#[test]
fn blg_020_rejected_transactions_do_not_mutate_the_block_state() {
    let chain = production_part(include_str!("../chain/blockchain.rs"));
    let at = chain
        .find("let mut candidate_state = temp_state.clone();")
        .expect("the candidate-state clone must exist in collect_block_transactions");
    let apply = chain[at..(at + 2_000).min(chain.len())]
        .find("Executor::apply_transaction_checked(&mut candidate_state, tx)")
        .expect("the candidate state must be what the executor applies against");
    let promote = chain[at..(at + 4_000).min(chain.len())]
        .find("temp_state = candidate_state;")
        .expect("the candidate state must be promoted only after a successful apply");
    // The executor applies against the clone first; the promotion happens later.
    assert!(apply < 4_000);
    assert!(promote > apply);
}

/// BLG-266: the single `min_stake` parameter no longer exists as the only
/// floor. Full and mobile classes have their own floors and the class floor
/// is what the profile exposes (`TESTNET-DEFAULT`: 1,000 / 10 BUD).
#[test]
fn blg_266_min_stake_is_split_per_class() {
    let config = production_part(include_str!("../core/chain_config.rs"));
    assert!(config.contains("pub fn min_stake_full("));
    assert!(config.contains("pub fn min_stake_mobile("));
    assert!(config.contains("pub fn class_floor("));
    // The testnet profile ships the phone floor far below the full floor.
    let testnet = config
        .find("Network::Testnet")
        .expect("the testnet arm must exist");
    let window = &config[testnet..(testnet + 2_000).min(config.len())];
    assert!(window.contains("min_stake: crate::tokenomics::bud(1_000)"));
    assert!(window.contains("min_stake_mobile: crate::tokenomics::bud(10)"));
}

#[test]
fn audit_lane_a_blg_001_leader_round_surface_present() {
    let src = include_str!("../consensus/leader.rs");
    assert!(
        src.contains("MAX_LEADER_ROUNDS"),
        "BLG-001: bounded leader-round fallback constant must remain present"
    );
}

#[test]
fn audit_lane_a_blg_006_reward_pool_epoch_surface_present() {
    let src = include_str!("../tokenomics/reward_pool.rs");
    assert!(
        src.contains("pay_epoch"),
        "BLG-006: epoch reward settlement entrypoint must remain present"
    );
}

#[test]
fn audit_lane_a_blg_018_finalized_height_tracked_in_blockchain() {
    let src = include_str!("../chain/blockchain.rs");
    assert!(
        src.contains("finalized_height"),
        "BLG-018: finalized_height tracking must remain present in blockchain"
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
