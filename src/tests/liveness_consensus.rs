//! Task 0.30: liveness wired into the real epoch flow (observe mode).
//!
//! These tests drive real block production through `Blockchain::produce_block`
//! (which commits blocks and, at epoch boundaries, runs
//! `maybe_observe_liveness_on_epoch_close`) — NOT the isolated
//! `state.record_liveness_epoch()` call.
//!
//! Decision 2.3 = OBSERVE MODE: crossing the miss threshold is logged/reported
//! but NEVER slashed. Tests assert both the counter movement AND the absence of
//! any slash (stake/registry unchanged).

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
    let mut bc = Blockchain::new(consensus, None, 1337, None);
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
    // real apply/commit flow, not a manual record_liveness_epoch call.
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

// --- Observe mode: threshold crossed, but NO slash (critical) ----------------

#[test]
fn threshold_crossing_reports_but_does_not_slash_when_disabled() {
    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);

    // Lower the liveness threshold to 2 so we can cross it quickly.
    // Task 0.34: explicitly assert the observe-only (disabled) behavior — this is
    // also the default, but we set it explicitly so the test documents intent
    // and stays correct even if the default ever changes.
    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 2,
        liveness_slashing_enabled: false,
        ..RegistryParams::default()
    });
    // `add_validator` already auto-registered the absentee in the registry
    // (Task 0.02 sync), so a slash WOULD have something to cut — proving the
    // no-slash property is meaningful, not vacuous.
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
    assert!(bc.state.liveness.missed_count(&absentee) >= 2);

    // ...but OBSERVE MODE means NO slash happened:
    let reg = bc.state.registry.get(&absentee, roles::VALIDATOR).unwrap();
    assert_eq!(
        reg.stake, stake_before,
        "stake must be untouched (no slash)"
    );
    assert!(
        bc.state.registry.is_active(&absentee, roles::VALIDATOR),
        "validator must remain active (not jailed/slashed)"
    );
    // Validator-set stake also unchanged (belt and suspenders).
    assert_eq!(
        bc.state.get_validator(&absentee).map(|v| v.stake),
        Some(10_000)
    );
}

/// Direct proof that `observe_liveness_epoch` returns reports but performs no
/// slash, even when the offender is registered and over threshold.
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
    // absentee is already registered as a validator via add_validator (Task 0.02 sync).

    // Nobody participates -> absentee misses; threshold 1 => a report is produced.
    let empty: HashSet<Address> = HashSet::new();
    let reported = bc.observe_liveness_epoch(0, &empty);
    assert!(reported >= 1, "a report should be generated");

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

    // A PoA domain with an approved member — kept in the SEPARATE membership
    // registry, never in AccountState.validators.
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
    // machinery at all.
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

// --- Task 0.34: real liveness slashing activation (default OFF) -----------------

/// With slashing ENABLED, crossing the miss threshold through the real epoch
/// flow actually slashes the validator (stake cut AND jailed via slash()).
#[test]
fn threshold_crossing_slashes_when_enabled_through_real_epoch_flow() {
    use crate::core::chain_config::FIXED_POINT_SCALE;
    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);

    // Enable slashing + low threshold so it triggers within a few epochs.
    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 2,
        liveness_slashing_enabled: true,
        ..RegistryParams::default()
    });
    let stake_before = bc
        .state
        .registry
        .get(&absentee, roles::VALIDATOR)
        .unwrap()
        .stake;
    assert_eq!(stake_before, 10_000);
    assert!(bc.state.registry.is_active(&absentee, roles::VALIDATOR));

    // Produce 3 full epochs; absentee misses >= threshold (2) -> real slash.
    produce_n(&mut bc, producer, EPOCH_LENGTH * 3);

    let reg = bc.state.registry.get(&absentee, roles::VALIDATOR).unwrap();
    // Stake was actually cut by the configured liveness ratio (1%).
    let expected_penalty = ((stake_before as u128 * FIXED_POINT_SCALE as u128 / 100)
        / FIXED_POINT_SCALE as u128) as u64;
    assert_eq!(
        reg.stake,
        stake_before - expected_penalty,
        "stake must be reduced by the configured liveness ratio"
    );
    // And the offender is jailed (slash() sets Slashed on any offence).
    assert!(
        !bc.state.registry.is_active(&absentee, roles::VALIDATOR),
        "slashed validator must no longer be active"
    );
}

/// The amount cut through the real epoch flow equals exactly the configured
/// `liveness_slash_ratio_fixed` (default 1%) — same formula as the Task 0.04 isolated
/// test, but driven by the live epoch-close hook.
#[test]
fn liveness_slash_uses_configured_rate_through_real_epoch_flow() {
    use crate::core::chain_config::FIXED_POINT_SCALE;
    let producer = addr(1);
    let absentee = addr(2);
    let mut bc = chain_with_validators(producer, absentee);

    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 1,
        liveness_slashing_enabled: true,
        ..RegistryParams::default()
    });
    let stake_before = bc
        .state
        .registry
        .get(&absentee, roles::VALIDATOR)
        .unwrap()
        .stake;
    let rate = bc.state.registry.params().liveness_slash_ratio_fixed;
    let expected_penalty =
        ((stake_before as u128 * rate as u128) / FIXED_POINT_SCALE as u128) as u64;

    // One threshold crossing is enough (threshold = 1).
    produce_n(&mut bc, producer, EPOCH_LENGTH * 2);

    let reg = bc.state.registry.get(&absentee, roles::VALIDATOR).unwrap();
    assert_eq!(reg.stake, stake_before - expected_penalty);
    assert!(expected_penalty > 0, "1% of 10_000 must be > 0");
}
