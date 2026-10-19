//! Locks that assert the effect, not only that a call returned.
//!
//! P49-F06: the slashing matrix checked `is_ok()` for liveness and spam
//! reports and discarded the result of the unverified case, so a slash that
//! never cut stake and a report that was silently skipped looked the same as a
//! correct run. These tests read the registration before and after.
//!
//! P49-F04: sixty macro-generated tests in `security_auditor.rs` call
//! `validate_transaction` with an unsigned transaction on an empty state and
//! assert `is_err()`, which fails at the first check whatever the nonce is.
//! The overflow rule had no test that pins the reason, so it could be removed
//! while every one of them stayed green.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::chain_config::FIXED_POINT_SCALE;
use crate::core::transaction::Transaction;
use crate::registry::evidence::{SlashingProof, SlashingReport};
use crate::registry::params::RegistryParams;
use crate::registry::permissionless::{PermissionlessRegistry, SlashingCondition};
use crate::registry::roles;

const STAKE: u64 = 10_000;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn registry_with(validators: &[u8]) -> PermissionlessRegistry {
    let mut reg = PermissionlessRegistry::with_params(RegistryParams::default());
    for b in validators {
        reg.register(addr(*b), roles::VALIDATOR, STAKE, 0)
            .expect("register must succeed");
    }
    reg
}

fn double_sign(offender: Address) -> SlashingReport {
    SlashingReport::consensus_double_sign(
        offender,
        SlashingProof::DoubleSign {
            height: 100,
            block_hash_1: "hash_aaa".to_string(),
            block_hash_2: "hash_bbb".to_string(),
            signature_1: vec![0xAA; 64],
            signature_2: vec![0xBB; 64],
        },
        Some(addr(0x01)),
    )
}

fn liveness(offender: Address) -> SlashingReport {
    SlashingReport::new_verified(
        offender,
        roles::VALIDATOR,
        SlashingProof::Liveness {
            window_start_epoch: 0,
            window_end_epoch: 100,
            missed: 50,
            expected: 100,
        },
        Some(addr(0x01)),
    )
}

fn expected_penalty(reg: &PermissionlessRegistry, condition: SlashingCondition) -> u64 {
    let ratio = u128::from(reg.params().slash_ratio(condition));
    u64::try_from(u128::from(STAKE) * ratio / u128::from(FIXED_POINT_SCALE))
        .expect("the penalty fits u64")
}

#[test]
fn a_double_sign_cuts_the_configured_ratio_and_leaves_the_rest() {
    let mut reg = registry_with(&[0x42]);
    let val = addr(0x42);
    let want = expected_penalty(&reg, SlashingCondition::DoubleSign);
    assert!(want > 0, "the double-sign ratio must cut something");

    let outcome = reg
        .slash_from_report(&double_sign(val))
        .expect("the report is actionable")
        .expect("a registered offender produces an outcome");
    assert_eq!(outcome.condition, SlashingCondition::DoubleSign);
    assert_eq!(outcome.penalty, want);
    assert_eq!(outcome.penalty + outcome.remaining_stake, STAKE);

    let after = reg.get(&val, roles::VALIDATOR).expect("still registered");
    assert_eq!(after.stake, outcome.remaining_stake);
    assert!(!reg.is_active(&val, roles::VALIDATOR));
    let history = reg.slashing_history_for(&val);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].penalty, want);
    assert_eq!(history[0].remaining_stake, outcome.remaining_stake);
}

#[test]
fn a_liveness_fault_is_cut_by_its_own_ratio_and_a_repeat_changes_nothing() {
    let mut reg = registry_with(&[0x44]);
    let val = addr(0x44);
    let want = expected_penalty(&reg, SlashingCondition::LivenessFault);

    let outcome = reg
        .slash_from_report(&liveness(val))
        .expect("the report is actionable")
        .expect("a registered offender produces an outcome");
    assert_eq!(outcome.condition, SlashingCondition::LivenessFault);
    assert_eq!(outcome.penalty, want);
    assert_eq!(outcome.penalty + outcome.remaining_stake, STAKE);
    assert_eq!(reg.slashing_history().len(), 1);
    let stake_after_first = reg.get(&val, roles::VALIDATOR).expect("registered").stake;
    assert_eq!(stake_after_first, outcome.remaining_stake);

    // The same report again is answered with a no-op: no second cut.
    let again = reg
        .slash_from_report(&liveness(val))
        .expect("the repeat is still actionable");
    assert!(
        again.is_none(),
        "a repeated liveness report must be a no-op"
    );
    assert_eq!(
        reg.get(&val, roles::VALIDATOR).expect("registered").stake,
        stake_after_first
    );
    assert_eq!(reg.slashing_history().len(), 1);
}

#[test]
fn an_unverified_report_moves_no_stake_while_the_verified_twin_does() {
    let mut reg = registry_with(&[0x60]);
    let val = addr(0x60);
    assert!(reg.is_active(&val, roles::VALIDATOR));

    let unverified = SlashingReport::new(
        val,
        roles::VALIDATOR,
        SlashingProof::DoubleSign {
            height: 100,
            block_hash_1: "aaa".to_string(),
            block_hash_2: "bbb".to_string(),
            signature_1: vec![0xAA; 64],
            signature_2: vec![0xBB; 64],
        },
        Some(addr(0x01)),
    );
    assert!(
        reg.slash_from_report(&unverified).is_err(),
        "an unverified report must be refused, not skipped"
    );
    assert_eq!(
        reg.get(&val, roles::VALIDATOR).expect("registered").stake,
        STAKE
    );
    assert!(reg.is_active(&val, roles::VALIDATOR));
    assert!(reg.slashing_history().is_empty());

    // Positive control: the same offender is slashed by a consensus-verified
    // report, so the refusal above is about provenance and not a broken
    // fixture.
    let outcome = reg
        .slash_from_report(&double_sign(val))
        .expect("actionable")
        .expect("outcome");
    assert!(outcome.penalty > 0);
}

#[test]
fn slashing_one_validator_leaves_its_neighbour_untouched() {
    let mut reg = registry_with(&[0x70, 0x71]);
    let _ = reg
        .slash_from_report(&double_sign(addr(0x70)))
        .expect("actionable")
        .expect("outcome");
    let neighbour = reg
        .get(&addr(0x71), roles::VALIDATOR)
        .expect("neighbour registered");
    assert_eq!(neighbour.stake, STAKE);
    assert!(reg.is_active(&addr(0x71), roles::VALIDATOR));
    assert!(reg.slashing_history_for(&addr(0x71)).is_empty());
}

/// A transfer whose amount plus fee does not fit a `u64` is refused for that
/// reason, before the balance and the signature are looked at. The sender
/// holds `u64::MAX`, the one balance the saturating total cost would admit.
#[test]
fn amount_plus_fee_overflow_is_refused_for_the_overflow() {
    let state = AccountState::new();
    let from = addr(0x07);
    let to = addr(0x08);
    for (amount, fee) in [(1u64, u64::MAX), (u64::MAX, u64::MAX)] {
        let tx = Transaction::new_with_fee(from, to, amount, fee, 0, vec![]);
        let err = state
            .validate_transaction_with_context(&tx, 0, u64::MAX)
            .expect_err("amount + fee overflows");
        assert!(
            err.contains("overflows u64"),
            "refused for the wrong reason: {err}"
        );
    }
}

/// The control for the lock above: with a total that fits, the same call gets
/// past the overflow rule and stops later, so the overflow message is not what
/// every rejection says.
#[test]
fn a_total_that_fits_gets_past_the_overflow_rule() {
    let state = AccountState::new();
    let tx = Transaction::new_with_fee(addr(0x07), addr(0x08), 1, u64::MAX / 2, 0, vec![]);
    let err = state
        .validate_transaction_with_context(&tx, 0, u64::MAX)
        .expect_err("an unsigned transaction is refused somewhere");
    assert!(
        !err.contains("overflows u64"),
        "a fitting total was refused as an overflow: {err}"
    );
    assert!(
        err.contains("Invalid signature"),
        "unexpected reason: {err}"
    );
}

/// The nonce is judged before anything expensive, whatever the amount is.
#[test]
fn a_wrong_nonce_is_refused_as_a_nonce() {
    let state = AccountState::new();
    let mut tx = Transaction::new_with_fee(addr(0x07), addr(0x08), 1, 1_000, 5, vec![]);
    tx.nonce = 5;
    let err = state
        .validate_transaction_with_context(&tx, 0, u64::MAX)
        .expect_err("nonce mismatch");
    assert!(err.contains("Invalid nonce"), "unexpected reason: {err}");
}
