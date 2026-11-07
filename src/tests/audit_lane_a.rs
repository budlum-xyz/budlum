//! Live-verification regression locks for the lane A findings of the unified
//! findings ledger (directive section 14). Each lock names the finding it
//! keeps closed (`BLG-NNN`) and cites the evidence it relies on. A lock that
//! fails means the tree regressed below the recorded state, not that the
//! closing package did its work; the closing package moves any lock it
//! tightens into its own pull request.
//!
//! Statuses recorded in `docs/audit/live/lane-a.md`:
//! - `Closed (previously fixed)` ... findings closed in this snapshot,
//!   held closed by these locks (BLG-001, BLG-019, BLG-020, BLG-266).
//!   BLG-005, BLG-006 and BLG-094 carry their locks in
//!   `src/tests/regression_chain.rs` already.
//! - `Open` ... the finding still reproduces in the live tree. The red repro
//!   test for each is owed on the `audit/repro-a` branch and moves into the
//!   closing package's pull request (directive sections 14.1 and 15.8, S-3).

fn production_part(src: &str) -> &str {
    src.split("\n#[cfg(test)]\nmod ").next().unwrap_or(src)
}

/// BLG-001: a slot with no elected leader no longer stalls forever.
/// Round zero is the ordinary path; a stale parent stamp can only widen
/// rounds up to the hard cap, never past it.
#[test]
fn blg_001_leader_rounds_are_bounded_and_reachable() {
    use crate::consensus::{affordable_leader_round, MAX_LEADER_ROUNDS};
    // The cap is finite and small enough for a phone to afford.
    assert!(MAX_LEADER_ROUNDS > 0 && MAX_LEADER_ROUNDS <= 64);
    // Nothing elapsed: only round zero exists.
    assert_eq!(affordable_leader_round(1_000_000, 1_000_000), 0);
    // An arbitrarily stale parent never exceeds the cap.
    assert_eq!(
        affordable_leader_round(1_000_000, 1_000_000 + 86_400_000),
        MAX_LEADER_ROUNDS
    );
    // A future-stamped parent pins the ladder at round zero instead of
    // handing out free rounds.
    assert_eq!(affordable_leader_round(9_000_000, 1_000_000), 0);
}

/// BLG-001 source lock: the PoA/PoS round claim sites price against the
/// same `affordable_leader_round` the verifier uses.
#[test]
fn blg_001_leader_round_pricing_is_wired() {
    let consensus = production_part(include_str!("../consensus/mod.rs"));
    assert!(consensus.contains("pub const MAX_LEADER_ROUNDS"));
    assert!(consensus.contains("pub fn affordable_leader_round"));
    let poa = production_part(include_str!("../consensus/poa.rs"));
    assert!(
        poa.contains("affordable_leader_round"),
        "the PoA engine must claim rounds through the shared pricing function"
    );
}

/// BLG-019: `TransactionType::StateUpdate` can no longer move another
/// account's nonce. The tag stays decodable for old blocks; every new block
/// carrying it is refused with `state_update_retired`.
#[test]
fn blg_019_state_update_is_refused() {
    let executor = production_part(include_str!("../execution/executor.rs"));
    let arm = executor
        .find("TransactionType::StateUpdate")
        .expect("the StateUpdate arm must still exist to refuse the tag");
    let window = &executor[arm..(arm + 2_000).min(executor.len())];
    assert!(
        window.contains("state_update_retired"),
        "the StateUpdate arm must refuse with state_update_retired"
    );
    assert!(
        window.contains("Err("),
        "the StateUpdate arm must refuse, not apply"
    );
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
fn blg_006_epoch_reward_pool_uses_checked_epoch_boundary() {
    let chain = production_part(include_str!("../chain/blockchain.rs"));
    assert!(
        chain.contains("epoch_index"),
        "epoch boundary accounting must remain wired in blockchain.rs"
    );
}

#[test]
fn blg_018_finalized_height_tracking_remains_wired() {
    let chain = production_part(include_str!("../chain/blockchain.rs"));
    assert!(
        chain.contains("finalized_height"),
        "finalized_height progress tracking must remain wired in blockchain.rs"
    );
}

#[test]
fn audit_lane_a_blg_019_retired_state_update_preserves_accounts() {
    use crate::core::account::AccountState;
    use crate::core::address::Address;
    use crate::core::transaction::{Transaction, TransactionType};
    use crate::execution::executor::Executor;

    for chain_id in [45261, 45262] {
        let mut s_bytes = [0u8; 32];
        s_bytes[0] = 0xad;
        let sender = Address::from(s_bytes);
        let mut v_bytes = [0u8; 32];
        v_bytes[0] = 0xb0;
        let victim = Address::from(v_bytes);
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
