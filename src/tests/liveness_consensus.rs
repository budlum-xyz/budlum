//! Non-slashing liveness suspension wired into the real epoch flow.
//!
//! These tests drive real block production through `Blockchain::produce_block`
//! (which commits blocks and, at epoch boundaries, runs
//! `apply_epoch_close_liveness`) - NOT the isolated
//! `state.record_liveness_epoch` call.
//!
//! Crossing the miss threshold suspends new duty but NEVER slashes. Tests
//! assert the counter movement, suspension and unchanged stake.

use crate::chain::blockchain::{Blockchain, EPOCH_LENGTH};
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use crate::registry::params::RegistryParams;
use crate::registry::role::roles;
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn chain_with_validators(producer: Address, absentee: Address) -> Blockchain {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);
    // Two validators: `producer` will produce every block; `absentee` never does.
    bc.state.add_validator(producer, 10_000);
    bc.state.add_validator(absentee, 10_000);
    bc
}

/// Produce `n` blocks, all authored by `producer`.
fn produce_n(bc: &mut Blockchain, producer: Address, n: u64) {
    for _ in 0..n {
        let _ = bc
            .produce_block(producer)
            .expect("block production must succeed");
    }
}

// --- End-to-end: miss counter increments via real epoch close ---------------

#[test]
fn absentee_miss_counter_increments_through_real_block_flow() {
    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);

    // Before any epoch closes, no misses recorded.
    assert_eq!(bc.state.liveness.missed_count(&absentee), 0);

    // Produce exactly one full epoch (EPOCH_LENGTH blocks) -> epoch 0 closes.
    produce_n(&mut bc, producer, EPOCH_LENGTH);

    // The absentee (never a producer) missed epoch 0; the counter moved via the
    // Real apply/commit flow, not a manual record_liveness_epoch call.
    assert_eq!(bc.state.liveness.missed_count(&absentee), 1);
    // The active producer participated -> no miss streak.
    assert_eq!(bc.state.liveness.missed_count(&producer), 0);
}

#[test]
fn producer_participation_resets_across_epochs() {
    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);

    // Two full epochs.
    produce_n(&mut bc, producer, EPOCH_LENGTH * 2);
    // Absentee missed both epochs (consecutive).
    assert_eq!(bc.state.liveness.missed_count(&absentee), 2);
    // Producer participated in both -> zero.
    assert_eq!(bc.state.liveness.missed_count(&producer), 0);
}

// --- Threshold crossed: suspension, never a slash ------------------------

#[test]
fn threshold_crossing_suspends_without_slashing_when_legacy_flag_is_disabled() {
    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);

    // Lower the liveness threshold to 2 so we can cross it quickly.
    // Explicitly assert the observe-only (disabled) behavior, this is
    // Also the default, but we set it explicitly so the test documents intent
    // And stays correct even if the default ever changes.
    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 2,
        liveness_slashing_enabled: false,
        ..RegistryParams::default()
    });
    // `add_validator` already auto-registered the absentee in the registry
    // (sync), so a slash WOULD have something to cut, proving the
    // No-slash property is meaningful, not vacuous.
    let stake_before = bc
        .state
        .registry
        .get(&absentee, roles::VALIDATOR)
        .unwrap()
        .stake;
    assert!(bc.state.registry.is_active(&absentee, roles::VALIDATOR));

    // Produce 3 full epochs; absentee misses 3 consecutive (>= threshold 2).
    produce_n(&mut bc, producer, EPOCH_LENGTH * 3);

    // The miss counter clearly crossed the threshold...
    assert_eq!(bc.state.liveness.missed_count(&absentee), 2, "a suspended validator leaves the expected set");

    // ...but OBSERVE MODE means NO slash happened:
    let reg = bc.state.registry.get(&absentee, roles::VALIDATOR).unwrap();
    assert_eq!(
        reg.stake, stake_before,
        "stake must be untouched (no slash)"
    );
    assert!(
        bc.state.registry.is_active(&absentee, roles::VALIDATOR),
        "the bonded registry record is not slashed or unbonded"
    );
    // Validator-set stake also unchanged (belt and suspenders).
    assert_eq!(
        bc.state.get_validator(&absentee).map(|v| v.stake),
        Some(10_000)
    );
}

/// Direct proof that `observe_liveness_epoch` returns reports but performs no
/// Slash, even when the offender is registered and over threshold.
#[test]
fn observe_liveness_epoch_returns_reports_without_slashing() {
    use std::collections::HashSet;
    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);
    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 1,
        ..RegistryParams::default()
    });
    // Absentee is already registered as a validator via add_validator (sync).

    // Nobody participates -> absentee misses; threshold 1 suspends.
    let empty: HashSet<Address> = HashSet::new();
    let suspended = bc.observe_liveness_epoch(0, &empty);
    assert!(suspended >= 1, "a suspension should be recorded");

    // But observe mode applied no slash.
    assert_eq!(
        bc.state
            .registry
            .get(&absentee, roles::VALIDATOR)
            .unwrap()
            .stake,
        10_000
    );
    assert!(bc.state.registry.is_active(&absentee, roles::VALIDATOR));
}

// --- PoA isolation (critical) ----------------------------------------------

#[test]
fn poa_domain_member_is_not_touched_by_liveness_flow() {
    use crate::registry::poa_membership::PoaMembershipRegistry;

    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);

    // A PoA domain with an approved member - kept in the SEPARATE membership
    // Registry, never in AccountState.validators.
    let mut poa = PoaMembershipRegistry::new();
    let poa_domain = 7u32;
    let admin = addr(0xAA);
    let poa_member = addr(0xBB);
    poa.add_admin(poa_domain, admin);
    poa.submit_application(poa_domain, poa_member, [9u8; 32])
        .unwrap();
    poa.approve(poa_domain, admin, poa_member).unwrap();
    assert!(poa.is_authorized(poa_domain, &poa_member));

    // Run several real epochs of the liveness flow.
    produce_n(&mut bc, producer, EPOCH_LENGTH * 2);

    // The PoA member must NOT appear in the permissionless liveness/registry
    // Machinery at all.
    assert_eq!(bc.state.liveness.missed_count(&poa_member), 0);
    assert!(bc
        .state
        .registry
        .get(&poa_member, roles::VALIDATOR)
        .is_none());
    assert!(bc.state.get_validator(&poa_member).is_none());
    // And PoA authorization is unaffected by the liveness flow.
    assert!(poa.is_authorized(poa_domain, &poa_member));
    // The "expected" liveness set is the validator set, which never includes the
    // PoA member.
    assert!(bc.state.validators.contains_key(&producer));
    assert!(!bc.state.validators.contains_key(&poa_member));
}

// ---: real liveness slashing activation (default OFF) -----------------

/// V-4 / WP-13: crossing the miss threshold through the real epoch flow
/// SUSPENDS the validator. The stake is never cut for absence (BLG-251):
/// only proven double-sign and proven bad repair slash.
#[test]
fn threshold_crossing_suspends_but_never_slashes_through_real_epoch_flow() {
    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);

    // Low threshold so it triggers within a few epochs. The old
    // `liveness_slashing_enabled` flag no longer exists as a slash switch:
    // absence cannot slash, so the flag is irrelevant here.
    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 2,
        ..RegistryParams::default()
    });
    let stake_before = bc
        .state
        .registry
        .get(&absentee, roles::VALIDATOR)
        .unwrap()
        .stake;
    assert_eq!(stake_before, 10_000);

    // Produce 3 full epochs; absentee misses >= threshold (2).
    produce_n(&mut bc, producer, EPOCH_LENGTH * 3);

    let reg = bc.state.registry.get(&absentee, roles::VALIDATOR).unwrap();
    assert_eq!(
        reg.stake, stake_before,
        "absence must never cut the stake (V-4)"
    );
    // The absentee is suspended: out of the active set, not slashed.
    let suspended = bc
        .state
        .validators
        .get(&absentee)
        .expect("still a validator");
    assert!(
        !suspended.active,
        "a suspended validator is out of the active set"
    );
    assert!(
        !suspended.slashed,
        "absence is a suspension, not a slash"
    );
    assert!(bc.state.liveness.is_suspended(&absentee));
}

/// Absence through the real epoch flow changes no stake at all, whatever
/// the old liveness ratio was configured to (V-4).
#[test]
fn absence_never_reduces_stake_through_real_epoch_flow() {
    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);

    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 1,
        ..RegistryParams::default()
    });
    let stake_before = bc
        .state
        .registry
        .get(&absentee, roles::VALIDATOR)
        .unwrap()
        .stake;

    // One threshold crossing is enough (threshold = 1).
    produce_n(&mut bc, producer, EPOCH_LENGTH * 2);

    let reg = bc.state.registry.get(&absentee, roles::VALIDATOR).unwrap();
    assert_eq!(reg.stake, stake_before, "absence must not cut the stake");
    assert!(bc.state.liveness.is_suspended(&absentee));
}

/// A validator that has already been slashed must stop accruing downtime.
///
/// `slash_validator` sets `jailed` / `active = false` and flips the registry
/// entry to `MemberStatus::Slashed`, but the validator stays in
/// `AccountState.validators` - that map is where `jail_until` lives, so it has
/// to. `get_active_validators` filters on `active && !slashed`; the liveness
/// expectation set did not.
///
/// Two of the three call sites took `validators.keys()` unfiltered, so a jailed
/// member was counted absent every epoch for not signing blocks it is barred
/// from signing. Its streak climbs, and the moment it is unjailed the next
/// missed epoch tips it over a threshold it should have re-entered at zero.
///
/// This is Cosmos SDK #1867: a validator dropped from the active set kept its
/// `SigningInfo` and was slashed for the window it was not in the set.
///
/// Canary: drop the `registry.is_active` filter from
/// `Blockchain::record_liveness_epoch` and the streak assertion fails.
#[test]
fn a_slashed_validator_stops_accruing_downtime() {
    use std::collections::HashSet;

    let producer = addr(1);
    let offender = addr(2);
    let mut bc = chain_with_validators(producer, offender);
    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 100, // high, so nothing reports during the test
        ..RegistryParams::default()
    });

    // One epoch of absence while still active: the streak starts.
    let only_producer: HashSet<Address> = std::iter::once(producer).collect();
    bc.record_liveness_epoch(1, &only_producer);
    let after_first = bc.state.liveness.missed_count(&offender);
    assert_eq!(after_first, 1, "an active absentee accrues a miss");

    // Now slash it for something else entirely (a double-sign), which jails it.
    bc.state.slash_validator(
        &offender,
        crate::core::chain_config::FIXED_POINT_SCALE / 2,
        "test",
    );
    assert!(
        !bc.state.registry.is_active(&offender, roles::VALIDATOR),
        "a slashed member must be inactive in the registry"
    );
    assert!(
        bc.state.validators.contains_key(&offender),
        "and must still be in the validator map, which is where jail_until lives"
    );

    // Several more epochs pass. It cannot sign, it is jailed.
    for epoch in 2..=6 {
        bc.record_liveness_epoch(epoch, &only_producer);
    }

    assert_eq!(
        bc.state.liveness.missed_count(&offender),
        after_first,
        "a jailed validator must not accrue downtime for blocks it may not sign"
    );
}

/// All three liveness call sites must agree on who is expected to sign.
///
/// `apply_epoch_close_liveness` filtered on `registry.is_active` from the
/// start; `Blockchain::record_liveness_epoch` and
/// `AccountState::record_liveness_epoch` did not. One filter in three places is
/// how the two views drift, so this pins that they are the same set.
#[test]
fn every_liveness_path_expects_the_same_validators() {
    use std::collections::HashSet;

    let producer = addr(1);
    let offender = addr(2);
    let mut bc = chain_with_validators(producer, offender);
    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 100,
        ..RegistryParams::default()
    });
    bc.state.slash_validator(
        &offender,
        crate::core::chain_config::FIXED_POINT_SCALE / 2,
        "test",
    );

    let only_producer: HashSet<Address> = std::iter::once(producer).collect();

    let before = bc.state.liveness.missed_count(&offender);
    bc.observe_liveness_epoch(10, &only_producer);
    let after_observe = bc.state.liveness.missed_count(&offender);
    bc.record_liveness_epoch(11, &only_producer);
    let after_record = bc.state.liveness.missed_count(&offender);

    assert_eq!(
        (before, after_observe, after_record),
        (before, before, before),
        "both entry points must exclude an inactive member identically"
    );
}

/// A liveness suspension follows the one-epoch resume schedule and never
/// touches the stake (V-4, WP-13).
///
/// The old liveness path slashed on absence; two functions disagreed on the
/// jail shape and the live one could leave a permanent ban for an offence
/// whose evidence is absence. WP-13 removes that path: absence suspends,
/// `ResumeValidator` reactivates one epoch later, and the stake is never cut.
#[test]
fn a_liveness_suspension_is_releasable_and_never_slashes() {
    use std::collections::HashSet;

    let producer = addr(1);
    let offender = addr(2);
    let mut bc = chain_with_validators(producer, offender);
    bc.state.registry.set_params(RegistryParams {
        // One missed epoch is enough to suspend. Zero would disable the
        // tracker entirely: `record_epoch` guards on `threshold > 0`.
        liveness_max_missed_epochs: 1,
        ..RegistryParams::default()
    });

    let stake_before = bc
        .state
        .registry
        .get(&offender, roles::VALIDATOR)
        .unwrap()
        .stake;

    // Record one epoch in which the offender did not participate.
    let participated: HashSet<Address> = std::iter::once(producer).collect();
    bc.record_liveness_epoch(1, &participated);

    assert!(bc.state.liveness.is_suspended(&offender));
    let v = bc
        .state
        .get_validator(&offender)
        .expect("a suspended validator stays in the map");
    assert!(!v.slashed, "absence must never set `slashed` (V-4)");
    assert!(!v.jailed, "absence is a suspension, not a jail term");
    assert_eq!(
        bc.state
            .registry
            .get(&offender, roles::VALIDATOR)
            .unwrap()
            .stake,
        stake_before,
        "absence must never cut the stake"
    );

    // ResumeValidator lifts the suspension one epoch later.
    let epoch = bc.state.epoch_index;
    bc.state.liveness.request_resume(&offender, epoch);
    assert!(bc.state.liveness.activate_due_resumes(epoch).is_empty());
    assert_eq!(
        bc.state.liveness.activate_due_resumes(epoch + 1),
        vec![offender]
    );
    assert!(!bc.state.liveness.is_suspended(&offender));
}
