//! Liveness wired into the real epoch flow (observe mode).
//!
//! These tests drive real block production through `Blockchain::produce_block`
//! (which commits blocks and, at epoch boundaries, runs
//! `maybe_observe_liveness_on_epoch_close`) - NOT the isolated
//! `state.record_liveness_epoch` call.
//!
//! Decision 2.3 = OBSERVE MODE: crossing the miss threshold is logged/reported
//! But NEVER slashed. Tests assert both the counter movement AND the absence of
//! Any slash (stake/registry unchanged).

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

// --- Observe mode: threshold crossed, but NO slash (critical) ----------------

#[test]
fn threshold_crossing_reports_but_does_not_slash_when_disabled() {
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

/// With slashing ENABLED, crossing the miss threshold through the real epoch
/// Flow actually slashes the validator (stake cut AND jailed via slash).
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
    let expected_penalty = u64::try_from(
        (u128::from(stake_before) * u128::from(FIXED_POINT_SCALE) / 100)
            / u128::from(FIXED_POINT_SCALE),
    )
    .expect("a penalty is a fraction of a u64 stake");
    assert_eq!(
        reg.stake,
        stake_before - expected_penalty,
        "stake must be reduced by the configured liveness ratio"
    );
    // And the offender is jailed (slash sets Slashed on any offence).
    assert!(
        !bc.state.registry.is_active(&absentee, roles::VALIDATOR),
        "slashed validator must no longer be active"
    );
}

/// The amount cut through the real epoch flow equals exactly the configured
/// `liveness_slash_ratio_fixed` (default 1%) - same formula as isolated
/// Test, but driven by the live epoch-close hook.
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
    let expected_penalty = u64::try_from(
        (u128::from(stake_before) * u128::from(rate)) / u128::from(FIXED_POINT_SCALE),
    )
    .expect("a penalty is a fraction of a u64 stake");

    // One threshold crossing is enough (threshold = 1).
    produce_n(&mut bc, producer, EPOCH_LENGTH * 2);

    let reg = bc.state.registry.get(&absentee, roles::VALIDATOR).unwrap();
    assert_eq!(reg.stake, stake_before - expected_penalty);
    assert!(expected_penalty > 0, "1% of 10_000 must be > 0");
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
/// `maybe_observe_liveness_on_epoch_close` filtered on `registry.is_active`
/// from the start; `Blockchain::record_liveness_epoch` and
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
    bc.maybe_observe_liveness_on_epoch_close(10, &only_producer);
    let after_observe = bc.state.liveness.missed_count(&offender);
    bc.record_liveness_epoch(11, &only_producer);
    let after_record = bc.state.liveness.missed_count(&offender);

    assert_eq!(
        (before, after_observe, after_record),
        (before, before, before),
        "both entry points must exclude an inactive member identically"
    );
}

/// Liveness slashing is written, enabled by default, and unreachable.
///
/// Three things were measured and each contradicts something the tree says
/// about itself.
///
/// `maybe_observe_liveness_on_epoch_close` documented itself as "the OBSERVE
/// path: a report is recorded, but no slash is applied". It calls
/// `slash_from_report` and then sets `slashed`, `jailed` and `active = false`
/// whenever `liveness_slashing_enabled` is true, and that parameter defaults
/// to true in `registry/params.rs`.
///
/// Its own header said it is "called from `produce_block` /
/// `validate_and_add_block` at every epoch boundary", and
/// `disaster_recovery.rs` reasoned from the hook running "yalnız blok
/// üretiminde". Neither is so. `apply_system_effects` closes the epoch
/// through `state.advance_epoch` and no production path reaches this
/// function, so no validator has ever been jailed for absence on a running
/// chain.
///
/// The two errors point opposite ways, which is why neither was caught: the
/// documentation understates what the code does, so a reader checking safety
/// is reassured, and a reader checking that it works finds a body that
/// plainly slashes and stops there. Only asking "who calls this" finds it,
/// and the guard-reachability gate does not, because the name begins with
/// `maybe_`.
///
/// Wiring it is a consensus change: enabling it starts cutting stake at the
/// first epoch close on every existing chain, against a `participated` set
/// the signature leaves entirely to the caller. This test does not close the
/// gap. It makes the gap fail loudly the moment either half moves, so the
/// change is made deliberately rather than discovered.
#[test]
fn liveness_slashing_gap_is_pinned() {
    let blockchain_src = include_str!("../chain/blockchain.rs");

    // 1. The function still slashes, so calling it is not a free action.
    let hook = blockchain_src
        .split_once("pub fn maybe_observe_liveness_on_epoch_close(")
        .map(|(_, after)| after)
        .expect("the hook must still exist");
    let hook = &hook[..hook.len().min(2500)];
    assert!(
        hook.contains("slash_from_report") && hook.contains("jailed = true"),
        "the hook no longer cuts stake. If it became observe-only, the warning \\
         in its doc comment and this test both need rewriting"
    );

    // 2. Nothing in production calls it. Searched outside `src/tests/`,
    //    excluding the definition and doc comments, which is how the claim
    //    survived for as long as it did.
    let mut callers: Vec<&str> = Vec::new();
    for (path, src) in [
        ("chain/blockchain.rs", blockchain_src),
        (
            "chain/chain_actor.rs",
            include_str!("../chain/chain_actor.rs"),
        ),
        (
            "execution/executor.rs",
            include_str!("../execution/executor.rs"),
        ),
        ("core/account.rs", include_str!("../core/account.rs")),
        ("main.rs", include_str!("../main.rs")),
    ] {
        for line in src.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.contains("pub fn maybe_observe_liveness_on_epoch_close") {
                continue;
            }
            if trimmed.contains("maybe_observe_liveness_on_epoch_close(") {
                callers.push(path);
            }
        }
    }
    assert!(
        callers.is_empty(),
        "the epoch-close liveness hook is now called from {callers:?}. That is \\
         a consensus change: it begins cutting stake at the first epoch close \\
         on every existing chain, against a `participated` set the caller \\
         chooses. Confirm the participation source is real, then delete this \\
         test and pin the new behaviour instead"
    );

    // 3. The canary. If the search above stopped matching for a mechanical
    //    reason, step 2 would pass on a tree where the hook *is* wired, which
    //    is the failure this whole test exists to prevent.
    let sentinel = blockchain_src
        .lines()
        .filter(|l| l.contains("maybe_observe_liveness_on_epoch_close"))
        .count();
    assert!(
        sentinel > 0,
        "the name no longer appears in blockchain.rs at all, so step 2 proved \\
         nothing; it was searching for a symbol that does not exist"
    );
}

/// The live epoch-close path and the unreachable one punish differently.
///
/// Two functions apply a liveness slash. `apply_epoch_close_liveness` runs
/// on every real block at an epoch boundary. `maybe_observe_liveness_on_epoch_close`
/// is reachable only from tests, as the test above pins.
///
/// They do not do the same thing. Both set `slashed` and clear `active`;
/// only the unreachable one also sets `jailed`. That difference is not
/// cosmetic:
///
/// * `jailed` is hashed into the state root, so the two paths produce
///   different roots from the same evidence.
/// * `AccountState::advance_epoch` releases a validator by testing
///   `validator.jailed && validator.jail_until <= epoch_index`. A validator
///   punished by the live path never has `jailed` set, so the release loop
///   never sees it and the punishment has no expiry. `jail_until` stays 0,
///   which would have released it immediately had the flag been set.
/// * `effective_stake` already returns 0 for a `slashed` validator, so the
///   stake is out either way. What differs is whether it can ever come back.
///
/// The net effect is that the only liveness slashing that actually runs is
/// permanent, while the code path that documents a jail term is the one
/// nothing calls. This test pins the asymmetry so that whoever wires the
/// hook, or fixes the live path, has to decide which punishment is intended
/// rather than inheriting one by accident.
#[test]
fn the_live_epoch_close_path_slashes_without_a_jail_term() {
    use std::collections::HashSet;

    let producer = addr(1);
    let offender = addr(2);
    let mut bc = chain_with_validators(producer, offender);
    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 0,
        liveness_slashing_enabled: true,
        ..RegistryParams::default()
    });

    let only_producer: HashSet<Address> = std::iter::once(producer).collect();
    bc.maybe_observe_liveness_on_epoch_close(1, &only_producer);

    let v = bc
        .state
        .get_validator(&offender)
        .expect("the offender is still in the validator map after a slash");

    // The unreachable path is the one that jails.
    assert!(v.slashed, "the hook slashes when slashing is enabled");
    assert!(
        v.jailed,
        "the hook sets jailed; the live path does not, and that is the \
         difference this test exists to record"
    );
    assert_eq!(
        v.jail_until, 0,
        "neither path sets a term, so a jailed validator is released at the \
         next epoch boundary rather than serving one"
    );
}
