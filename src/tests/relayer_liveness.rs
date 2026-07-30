//! Tests for this turn's features:
//!  1. CrossDomainMessage -> relayer registration gating
//!  2. Slashing-report anti-spam fee (with refund on actionable reports)
//!  3. Liveness fault detection -> slash via the existing report flow
//!
//! Unit-level behaviour of the liveness tracker itself lives in
//! `registry::liveness::tests`; here we exercise the wiring through
//! `Blockchain` / `AccountState`.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::account::AccountState;
use crate::core::address::Address;

use crate::core::chain_config::FIXED_POINT_SCALE;
use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};
use crate::cross_domain::MessageKind;
use crate::registry::evidence::{ProofProvenance, SlashingProof, SlashingReport};
use crate::registry::role::roles;
use std::collections::HashSet;
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn fresh_chain() -> Blockchain {
    let consensus = Arc::new(PoWEngine::new(0));
    Blockchain::new(consensus, None, 45262, None)
}

fn relayed_message(sender: Address, nonce: u64) -> CrossDomainMessage {
    CrossDomainMessage::new(CrossDomainMessageParams {
        source_domain: 1,
        target_domain: 2,
        source_height: 10,
        event_index: 0,
        nonce,
        sender,
        recipient: addr(0xEE),
        payload_hash: [9u8; 32],
        kind: MessageKind::BridgeLock,
        expiry_height: 100,
    })
}

// --- 1. Relayer gating ------------------------------------------------------

#[test]
fn unregistered_account_cannot_submit_cross_domain_message() {
    let mut bc = fresh_chain();
    let stranger = addr(0x01);
    let err = bc
        .submit_relayed_cross_domain_message(relayed_message(stranger, 1))
        .unwrap_err();
    assert!(err.contains("not an active relayer"));
    // No message stored.
    assert_eq!(bc.state.message_registry.len(), 0);
}

#[test]
fn active_relayer_can_submit_cross_domain_message() {
    let mut bc = fresh_chain();
    let relayer = addr(0x02);
    bc.state.add_balance(&relayer, 5_000);
    bc.state.bond_relayer(&relayer, 2_000).unwrap();
    assert!(bc.state.registry.is_active_relayer(&relayer));

    bc.submit_relayed_cross_domain_message(relayed_message(relayer, 1))
        .unwrap();
    assert_eq!(bc.state.message_registry.len(), 1);
}

#[test]
fn slashed_relayer_cannot_submit_cross_domain_message() {
    let mut bc = fresh_chain();
    let relayer = addr(0x03);
    bc.state.add_balance(&relayer, 5_000);
    bc.state.bond_relayer(&relayer, 2_000).unwrap();
    // Slash the relayer role fully.
    bc.state
        .registry
        .slash(
            relayer,
            roles::RELAYER,
            crate::registry::SlashingCondition::MaliciousBehaviour,
            FIXED_POINT_SCALE,
        )
        .unwrap();
    assert!(!bc.state.registry.is_active_relayer(&relayer));

    let err = bc
        .submit_relayed_cross_domain_message(relayed_message(relayer, 1))
        .unwrap_err();
    assert!(err.contains("not an active relayer"));
}

#[test]
fn unbonding_relayer_can_still_submit() {
    // Decision: unbonding is an exit process, not a punishment; the stake is
    // Still locked and slashable, so the relayer may keep relaying.
    let mut bc = fresh_chain();
    let relayer = addr(0x04);
    bc.state.add_balance(&relayer, 5_000);
    bc.state.bond_relayer(&relayer, 2_000).unwrap();
    bc.state
        .registry
        .begin_unbonding(relayer, roles::RELAYER, 0)
        .unwrap();
    assert!(bc.state.registry.is_active_relayer(&relayer));
    bc.submit_relayed_cross_domain_message(relayed_message(relayer, 1))
        .unwrap();
    assert_eq!(bc.state.message_registry.len(), 1);
}

#[test]
fn system_bridge_path_bypasses_relayer_gate() {
    // The internal primitive (used by bridge lock/burn events) must NOT require
    // Relayer registration — those messages come from authorized on-chain logic.
    let mut bc = fresh_chain();
    bc.submit_cross_domain_message(relayed_message(addr(0x05), 1))
        .unwrap();
    assert_eq!(bc.state.message_registry.len(), 1);
}

// --- 2. Anti-spam fee -------------------------------------------------------

fn double_sign_report(offender: Address, reporter: Option<Address>) -> SlashingReport {
    SlashingReport::consensus_double_sign(
        offender,
        7,
        "aa".into(),
        "bb".into(),
        vec![1],
        vec![2],
        reporter,
    )
}

#[test]
fn actionable_report_refunds_fee() {
    let mut bc = fresh_chain();
    let offender = addr(0x11);
    let reporter = addr(0x12);
    bc.state.add_balance(&offender, 1_000_000);
    bc.state.bond_relayer(&offender, 10_000).unwrap(); // registered so slashable
                                                       // Register offender as validator too (double-sign is a validator offence).
    bc.state.add_validator(offender, 10_000);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&reporter, fee);

    let before = bc.state.get_balance(&reporter);
    let outcome = bc
        .submit_registry_slashing_report(double_sign_report(offender, Some(reporter)))
        .unwrap();
    assert!(outcome.is_some(), "validator should have been slashed");
    // Fee refunded because the report was actionable.
    assert_eq!(bc.state.get_balance(&reporter), before);
}

#[test]
fn unverified_report_burns_fee_and_does_not_slash() {
    let mut bc = fresh_chain();
    let offender = addr(0x13);
    let reporter = addr(0x14);
    bc.state.add_validator(offender, 10_000);
    bc.state.sync_validator_registration(&offender);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&reporter, fee);

    let report = SlashingReport::new(
        offender,
        roles::VALIDATOR,
        SlashingProof::DoubleSign {
            height: 7,
            block_hash_1: "aa".into(),
            block_hash_2: "bb".into(),
            signature_1: vec![1],
            signature_2: vec![2],
        },
        ProofProvenance::Unverified,
        Some(reporter),
    );
    // Rejected (not actionable).
    assert!(bc.submit_registry_slashing_report(report).is_err());
    // Fee burned.
    assert_eq!(bc.state.get_balance(&reporter), 0);
    // Offender untouched.
    assert!(bc.state.registry.is_active(&offender, roles::VALIDATOR));
}

#[test]
fn report_fee_insufficient_balance_rejected_without_state_change() {
    let mut bc = fresh_chain();
    let offender = addr(0x15);
    let reporter = addr(0x16); // no balance
    bc.state.add_validator(offender, 10_000);
    bc.state.sync_validator_registration(&offender);

    let err = bc
        .submit_registry_slashing_report(double_sign_report(offender, Some(reporter)))
        .unwrap_err();
    assert!(err.contains("insufficient balance"));
    // Offender not slashed.
    assert!(bc.state.registry.is_active(&offender, roles::VALIDATOR));
}

#[test]
fn consensus_internal_report_pays_no_fee() {
    // Reporter: None -> no fee charged (used by consensus-generated reports).
    let mut bc = fresh_chain();
    let offender = addr(0x17);
    bc.state.add_validator(offender, 10_000);
    bc.state.sync_validator_registration(&offender);
    let outcome = bc
        .submit_registry_slashing_report(double_sign_report(offender, None))
        .unwrap();
    assert!(outcome.is_some());
}

#[test]
fn report_against_unregistered_still_refunds_fee() {
    // Ok(None): verified but offender unregistered -> treated as actionable,
    // So the honest reporter is refunded (regression of previous-turn noop test).
    let mut bc = fresh_chain();
    let reporter = addr(0x18);
    let fee = bc.state.registry.params().slashing_report_fee;
    bc.state.add_balance(&reporter, fee);
    let before = bc.state.get_balance(&reporter);
    let outcome = bc
        .submit_registry_slashing_report(double_sign_report(addr(0x19), Some(reporter)))
        .unwrap();
    assert_eq!(outcome, None);
    assert_eq!(bc.state.get_balance(&reporter), before);
}

// --- 3. Liveness ------------------------------------------------------------

fn state_with_validator(v: Address, stake: u64) -> AccountState {
    let mut state = AccountState::new();
    state.add_validator(v, stake);
    state.sync_validator_registration(&v);
    state
}

#[test]
fn consecutive_liveness_failures_trigger_slash() {
    // Use an isolated AccountState with exactly one validator so the count is
    // Deterministic (fresh_chain seeds a genesis validator).
    let v = addr(0x21);
    let mut state = state_with_validator(v, 10_000);
    let k = state.registry.params().liveness_max_missed_epochs;

    let none: HashSet<Address> = HashSet::new();
    // Miss k-1 epochs: no report yet.
    for e in 1..k {
        assert!(state.record_liveness_epoch(e, &none).is_empty());
    }
    assert!(state.registry.is_active(&v, roles::VALIDATOR));
    // K-th consecutive miss produces exactly one report for this validator.
    let reports = state.record_liveness_epoch(k, &none);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].offender, v);
}

#[test]
fn liveness_slash_applied_through_blockchain_flow() {
    // End-to-end: reports generated at the chain level are routed through the
    // Existing report->slash flow and the target validator ends up slashed.
    let mut bc = fresh_chain();
    let v = addr(0x2A);
    bc.state.add_validator(v, 10_000);
    bc.state.sync_validator_registration(&v);
    let k = bc.state.registry.params().liveness_max_missed_epochs;

    // Everyone participates except `v` (so the genesis validator is unaffected).
    let mut present: HashSet<Address> = bc.state.validators.keys().copied().collect();
    present.remove(&v);

    for e in 1..k {
        assert_eq!(bc.record_liveness_epoch(e, &present), 0);
    }
    assert_eq!(bc.record_liveness_epoch(k, &present), 1);
    assert!(!bc.state.registry.is_active(&v, roles::VALIDATOR));
}

#[test]
fn liveness_counter_resets_on_participation() {
    let mut state = state_with_validator(addr(0x22), 10_000);
    let v = addr(0x22);
    let k = state.registry.params().liveness_max_missed_epochs;
    let none: HashSet<Address> = HashSet::new();
    let mut present: HashSet<Address> = HashSet::new();
    present.insert(v);

    for e in 1..k {
        state.record_liveness_epoch(e, &none);
    }
    assert_eq!(state.liveness.missed_count(&v), k - 1);
    // Participation resets the streak.
    state.record_liveness_epoch(k, &present);
    assert_eq!(state.liveness.missed_count(&v), 0);
}

#[test]
fn liveness_slash_uses_configured_rate() {
    let mut bc = fresh_chain();
    let v = addr(0x23);
    let stake = 10_000u64;
    bc.state.add_validator(v, stake);
    bc.state.sync_validator_registration(&v);
    let k = bc.state.registry.params().liveness_max_missed_epochs;
    let rate = bc.state.registry.params().liveness_slash_ratio_fixed;
    let expected_penalty = (stake as u128 * rate as u128 / FIXED_POINT_SCALE as u128) as u64;

    let none: HashSet<Address> = HashSet::new();
    for e in 1..=k {
        bc.record_liveness_epoch(e, &none);
    }
    let member = bc.state.registry.get(&v, roles::VALIDATOR).unwrap();
    assert_eq!(member.stake, stake - expected_penalty);
}

#[test]
fn liveness_does_not_affect_double_sign_flow() {
    // Regression: the double-sign path still slashes at its own (50%) rate,
    // Unaffected by liveness wiring.
    let mut bc = fresh_chain();
    let offender = addr(0x24);
    let stake = 10_000u64;
    bc.state.add_validator(offender, stake);
    bc.state.sync_validator_registration(&offender);
    let outcome = bc
        .submit_registry_slashing_report(double_sign_report(offender, None))
        .unwrap()
        .unwrap();
    assert_eq!(outcome.penalty, stake / 2);
}
