//! State transition, vesting, staking, governance, sharding, and V2 snapshot
//! hardening regression locks (functional regression names).

use crate::chain::snapshot::{PruningManager, StateSnapshotV2, StateSnapshotV2Params};
use crate::core::account::{AccountState, Validator};
use crate::core::address::Address;
use crate::core::governance::ProposalType;
use crate::core::transaction::{Transaction, TransactionType};
use crate::execution::executor::Executor;
use crate::registry::evidence::{SlashingProof, SlashingReport};
use crate::registry::role::roles;
use crate::sharding::apply_cross_shard_transfer;
use crate::tokenomics::VestingSchedule;

const TEST_CHAIN_ID: u64 = 45262;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn snapshot_params(height: u64) -> StateSnapshotV2Params {
    StateSnapshotV2Params {
        height,
        block_hash: "01".repeat(32),
        genesis_hash: "02".repeat(32),
        chain_id: TEST_CHAIN_ID,
        finalized_height: height,
        finalized_hash: "01".repeat(32),
        finality_certificates: Vec::new(),
    }
}

/// `bond_independent_role` (`bond_relayer` / `bond_prover` /
/// `bond_storage_operator`) must check `spendable_balance` rather than raw
/// `get_balance` so vesting-locked `$BUD` cannot be laundered through a role
/// bond and withdrawn liquid.
#[test]
fn role_bond_enforces_vesting_lock() {
    let mut state = AccountState::new();
    let team = addr(0x21);
    let min_bond = state.registry.params.min_relayer_stake;
    let total_locked = min_bond.saturating_mul(4);

    state.add_balance(&team, total_locked);
    state.team_vesting = Some((
        team,
        VestingSchedule {
            total: total_locked,
            start_epoch: 0,
            cliff_epochs: 50,
            duration_epochs: 200,
        },
    ));

    assert_eq!(state.spendable_balance(&team), 0);
    assert!(
        state.bond_relayer(&team, min_bond).is_err(),
        "vesting-locked balance must not fund a relayer bond"
    );
    assert!(
        state.bond_prover(&team, state.registry.params.min_prover_stake).is_err(),
        "vesting-locked balance must not fund a prover bond"
    );
    assert!(
        state
            .bond_storage_operator(&team, state.registry.params.min_storage_stake)
            .is_err(),
        "vesting-locked balance must not fund a storage operator bond"
    );
    assert!(!state.registry.is_active(&team, roles::RELAYER));
    assert_eq!(state.get_balance(&team), total_locked);
}

/// `StateSnapshotV2::from_bytes` must verify the snapshot digest on
/// current-schema blobs (not only legacy migrations), and `save_snapshot_v2`
/// must commit atomically without leaving a temporary file behind.
#[test]
fn v2_snapshot_from_bytes_verifies_digest_and_saves_atomically() {
    let mut state = AccountState::new();
    state.add_balance(&addr(0x28), 50_000);

    let mut snap = StateSnapshotV2::from_state(&state, snapshot_params(12));
    let valid_bytes = snap.to_bytes();
    assert!(
        StateSnapshotV2::from_bytes(&valid_bytes).is_ok(),
        "untampered current-schema V2 snapshot must parse"
    );

    // Tamper with balances while leaving `snapshot_hash` untouched.
    snap.balances.insert(addr(0x99), 999_999);
    let tampered_bytes = serde_json::to_vec(&snap).expect("tampered JSON serializes");
    let err = StateSnapshotV2::from_bytes(&tampered_bytes)
        .expect_err("tampered current-schema V2 snapshot must fail digest check");
    assert!(
        err.contains("does not match its own digest"),
        "unexpected error for tampered V2 snapshot: {err}"
    );

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let dir_str = tmp_dir.path().to_string_lossy().into_owned();
    let manager = PruningManager::new(100, 10, dir_str);
    let clean = StateSnapshotV2::from_state(&state, snapshot_params(20));
    manager
        .save_snapshot_v2(&clean)
        .expect("atomic V2 snapshot write must succeed");
    assert!(tmp_dir.path().join("snapshot_20.json").exists());
    assert!(!tmp_dir.path().join(".snapshot_20.json.tmp").exists());
}

/// `apply_cross_shard_transfer` must reject `amount + fee` `u64`
/// overflow, enforce `spendable_balance` vesting locks, reject zero recipients,
/// and mark both touched accounts in `dirty_accounts`.
#[test]
fn cross_shard_transfer_enforces_vesting_and_checked_cost() {
    let num_shards = 4;
    let sender = Address::from([0u8; 32]);
    let mut raw_to = [0u8; 32];
    if let Some(last) = raw_to.last_mut() {
        *last = 1;
    }
    let receiver = Address::from(raw_to);

    let mut locked_state = AccountState::new();
    locked_state.add_balance(&sender, 10_000);
    locked_state.team_vesting = Some((
        sender,
        VestingSchedule {
            total: 10_000,
            start_epoch: 0,
            cliff_epochs: 10,
            duration_epochs: 100,
        },
    ));
    let vested_tx = Transaction::new_with_fee(sender, receiver, 500, 10, 0, Vec::new());
    let err = apply_cross_shard_transfer(&mut locked_state, &vested_tx, num_shards)
        .expect_err("vesting-locked cross-shard transfer must be refused");
    assert!(err.contains("spendable balance"), "unexpected error: {err}");
    assert_eq!(locked_state.get_balance(&sender), 10_000);
    assert_eq!(locked_state.get_balance(&receiver), 0);

    let mut max_state = AccountState::new();
    max_state.add_balance(&sender, u64::MAX);
    let overflow_tx = Transaction::new_with_fee(sender, receiver, u64::MAX, 10, 0, Vec::new());
    let overflow_err = apply_cross_shard_transfer(&mut max_state, &overflow_tx, num_shards)
        .expect_err("amount + fee overflow must be refused");
    assert!(
        overflow_err.contains("overflow"),
        "unexpected overflow error: {overflow_err}"
    );
    assert_eq!(max_state.get_balance(&sender), u64::MAX);

    let mut clean_state = AccountState::new();
    clean_state.add_balance(&sender, 5_000);
    clean_state.dirty_accounts.clear();
    let ok_tx = Transaction::new_with_fee(sender, receiver, 1_000, 25, 0, Vec::new());
    apply_cross_shard_transfer(&mut clean_state, &ok_tx, num_shards)
        .expect("valid cross-shard transfer must apply");
    assert!(clean_state.dirty_accounts.contains(&sender));
    assert!(clean_state.dirty_accounts.contains(&receiver));
}

/// `Unstake` only debits `tx.fee` from liquid balance (its `tx.amount`
/// comes out of staked balance), and fee-only arms in `Executor` must still
/// enforce `spendable_balance` when the liquid balance is vesting-locked.
#[test]
fn unstake_checks_fee_not_staked_amount_and_enforces_vesting() {
    let validator = addr(0x41);
    let mut state = AccountState::new();
    let staked = 50_000_000u64;
    let liquid_fee_budget = 500u64;
    state.add_balance(&validator, liquid_fee_budget);
    state.add_validator(Validator::new(validator, staked));

    // Pre-sign validation: `validate_transaction_with_context` must NOT reject
    // `Unstake` for insufficient balance when `spendable_balance >= fee` even
    // though `spendable_balance < staked + fee` (it stops later at signature).
    let unstake_tx = Transaction::new_with_chain_id(
        validator,
        Address::zero(),
        staked,
        100,
        0,
        Vec::new(),
        TEST_CHAIN_ID,
        TransactionType::Unstake,
    );
    let pre_sig_err = state
        .validate_transaction_with_context(&unstake_tx, 0, u64::MAX)
        .expect_err("unsigned tx stops at signature, not balance");
    assert!(
        pre_sig_err.contains("Invalid signature"),
        "Unstake with liquid >= fee was wrongly rejected before signature check: {pre_sig_err}"
    );

    // Executor must apply `Unstake` when spendable balance covers `tx.fee`.
    Executor::apply_transaction_checked(&mut state, &unstake_tx)
        .expect("Unstake with spendable >= fee must succeed");
    assert_eq!(state.get_balance(&validator), liquid_fee_budget - 100);

    // Conversely, if the remaining liquid balance is vesting-locked, even a
    // fee-only `Unstake` must be refused by `Executor` with `vesting_locked`.
    let locked_val = addr(0x42);
    let mut vested_state = AccountState::new();
    vested_state.add_balance(&locked_val, 1_000);
    vested_state.add_validator(Validator::new(locked_val, staked));
    vested_state.team_vesting = Some((
        locked_val,
        VestingSchedule {
            total: 1_000,
            start_epoch: 0,
            cliff_epochs: 10,
            duration_epochs: 100,
        },
    ));
    let locked_unstake = Transaction::new_with_chain_id(
        locked_val,
        Address::zero(),
        1_000,
        100,
        0,
        Vec::new(),
        TEST_CHAIN_ID,
        TransactionType::Unstake,
    );
    let err = Executor::apply_transaction_checked(&mut vested_state, &locked_unstake)
        .expect_err("vesting-locked fee must be rejected");
    assert_eq!(err.code(), "vesting_locked");
    assert_eq!(vested_state.get_balance(&locked_val), 1_000);
}

/// Jailed/slashed validators cannot create governance proposals, and
/// voting on a non-existent proposal fails closed without debiting fee or
/// advancing sender nonce.
#[test]
fn slashed_proposer_and_missing_proposal_vote_refuse_without_debit() {
    let jailed = addr(0x51);
    let mut state = AccountState::new();
    state.add_balance(&jailed, 10_000);
    let mut v = Validator::new(jailed, 50_000);
    v.jailed = true;
    v.jail_until = 100;
    state.add_validator(v);

    let mut create_payload = 10u64.to_le_bytes().to_vec();
    create_payload.extend_from_slice(
        &serde_json::to_vec(&ProposalType::ChangeBaseFee(250)).expect("proposal json"),
    );
    let create_tx = Transaction::new_with_chain_id(
        jailed,
        Address::zero(),
        0,
        100,
        0,
        create_payload,
        TEST_CHAIN_ID,
        TransactionType::Vote,
    );
    let err = Executor::apply_transaction_checked(&mut state, &create_tx)
        .expect_err("jailed validator must not create governance proposal");
    assert_eq!(err.code(), "governance_proposer_not_validator");
    assert_eq!(state.get_balance(&jailed), 10_000);
    assert_eq!(state.get_nonce(&jailed), 0);

    let active = addr(0x52);
    state.add_balance(&active, 10_000);
    state.add_validator(Validator::new(active, 50_000));
    let mut missing_vote = vec![1u8];
    missing_vote.extend_from_slice(&9999u64.to_le_bytes());
    let vote_tx = Transaction::new_with_chain_id(
        active,
        Address::zero(),
        0,
        50,
        0,
        missing_vote,
        TEST_CHAIN_ID,
        TransactionType::Vote,
    );
    let vote_err = Executor::apply_transaction_checked(&mut state, &vote_tx)
        .expect_err("vote for missing proposal must fail closed");
    assert_eq!(vote_err.code(), "governance_proposal_not_found");
    assert_eq!(state.get_balance(&active), 10_000);
    assert_eq!(state.get_nonce(&active), 0);
}

/// Executing `ProposalType::SlashValidator` must mirror the slash
/// into `PermissionlessRegistry` so validator standing and burned supply remain
/// consistent with `state.validators`.
#[test]
fn governance_slash_syncs_permissionless_registry() {
    let offender = addr(0x61);
    let proposer = addr(0x62);
    let mut state = AccountState::new();
    let stake = 20_000u64;
    state.add_validator(Validator::new(offender, stake));
    state
        .registry
        .register_validator(offender, stake, 0)
        .expect("register validator in permissionless registry");

    // Record a verified minor liveness slashing report so `evidence_hash`
    // matches `registry.slashing_history` while validator stake stays positive
    // before the governance 100% slash executes.
    let liveness_report = SlashingReport::new_verified(
        offender,
        roles::VALIDATOR,
        SlashingProof::Liveness {
            window_start_epoch: 0,
            window_end_epoch: 100,
            missed: 50,
            expected: 100,
        },
        Some(proposer),
    );
    let liv_hash = liveness_report.evidence_hash;
    state
        .registry
        .slash_from_report(&liveness_report)
        .expect("liveness report actionable")
        .expect("liveness report produces outcome");
    assert!(
        state.registry.is_active(&offender, roles::VALIDATOR),
        "validator still active after minor liveness slash"
    );

    let prop_id = state
        .governance
        .create_proposal(
            proposer,
            ProposalType::SlashValidator {
                address: offender,
                evidence_hash: liv_hash,
            },
            0,
            10,
        )
        .expect("create slash proposal");
    let prop = state
        .governance
        .find_proposal(prop_id)
        .cloned()
        .expect("proposal exists");
    state.execute_proposal(&prop);

    assert_eq!(state.get_validator(&offender).map(|v| v.stake), Some(0));
    assert!(
        !state.registry.is_active(&offender, roles::VALIDATOR),
        "governance SlashValidator must also deactivate validator in PermissionlessRegistry"
    );
}

/// `checked_total_cost` and `Executor::apply_transaction_checked`
/// refuse `amount + fee > u64::MAX`, and `Stake` refuses `validator.stake`
/// overflow BEFORE debiting sender balance or advancing sender nonce.
#[test]
fn total_cost_overflow_and_stake_overflow_refuse_without_partial_write() {
    let sender = addr(0x71);
    let recipient = addr(0x72);
    let overflow_tx = Transaction::new_with_chain_id(
        sender,
        recipient,
        u64::MAX,
        50,
        0,
        Vec::new(),
        TEST_CHAIN_ID,
        TransactionType::Transfer,
    );
    assert_eq!(overflow_tx.checked_total_cost(), None);

    let mut state = AccountState::new();
    state.add_balance(&sender, u64::MAX);
    let err = Executor::apply_transaction_checked(&mut state, &overflow_tx)
        .expect_err("Executor must refuse overflowing amount + fee");
    assert_eq!(err.code(), "amount_fee_overflow");
    assert_eq!(state.get_balance(&sender), u64::MAX);
    assert_eq!(state.get_nonce(&sender), 0);

    // Stake overflow check must happen BEFORE sender balance/nonce mutation.
    let staker = addr(0x73);
    let mut stake_state = AccountState::new();
    stake_state.add_balance(&staker, 1_000);
    stake_state.add_validator(Validator::new(staker, u64::MAX - 10));
    let stake_tx = Transaction::new_with_chain_id(
        staker,
        Address::zero(),
        500,
        10,
        0,
        Vec::new(),
        TEST_CHAIN_ID,
        TransactionType::Stake,
    );
    let stake_err = Executor::apply_transaction_checked(&mut stake_state, &stake_tx)
        .expect_err("overflowing validator stake must fail closed");
    assert_eq!(stake_err.code(), "stake_overflow");
    assert_eq!(
        stake_state.get_balance(&staker),
        1_000,
        "sender balance must remain untouched when validator stake overflows"
    );
    assert_eq!(
        stake_state.get_nonce(&staker),
        0,
        "sender nonce must remain untouched when validator stake overflows"
    );
}
