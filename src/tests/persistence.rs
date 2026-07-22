//! Task 0.16: state-persistence round-trip tests.
//!
//! Verifies that the previously-unpersisted `AccountState` fields (permissionless
//! registry, liveness tracker, and the atomic tokenomics burn block) survive a
//! `StateSnapshotV2` round-trip, and that restoring them does NOT cause a double
//! burn of the timed reserve.

use crate::chain::snapshot::{StateSnapshotV2, StateSnapshotV2Params};
use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::registry::params::RegistryParams;
use crate::registry::role::roles;
use crate::tokenomics::{bud, TokenomicsAddresses, VestingSchedule};

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

fn snapshot_params() -> StateSnapshotV2Params {
    StateSnapshotV2Params {
        height: 10,
        block_hash: "bb".repeat(32),
        genesis_hash: "aa".repeat(32),
        chain_id: 1337,
        finalized_height: 5,
        finalized_hash: "cc".repeat(32),
        finality_certificates: vec![],
    }
}

/// Round-trip a state through V2 bytes and back into an AccountState.
fn round_trip(state: &AccountState) -> AccountState {
    let v2 = StateSnapshotV2::from_state(state, snapshot_params());
    let bytes = v2.to_bytes();
    let restored = StateSnapshotV2::from_bytes(&bytes).expect("V2 must deserialize");
    AccountState::from_snapshot_v2(&restored)
}

// --- Registry round-trip ----------------------------------------------------

#[test]
fn registry_survives_snapshot_round_trip() {
    let mut state = AccountState::new();
    state
        .registry
        .register_validator(addr(1), 5_000, 0)
        .unwrap();
    state.registry.register_relayer(addr(2), 2_000, 0).unwrap();
    // Custom params to prove params also round-trip.
    state.registry.set_params(RegistryParams {
        min_stake: 4242,
        ..RegistryParams::default()
    });

    let restored = round_trip(&state);

    assert!(restored.registry.is_active(&addr(1), roles::VALIDATOR));
    assert!(restored.registry.is_active(&addr(2), roles::RELAYER));
    let reg = restored.registry.get(&addr(1), roles::VALIDATOR).unwrap();
    assert_eq!(reg.stake, 5_000);
    assert_eq!(restored.registry.params().min_stake, 4242);
    // Not-registered account stays absent.
    assert!(!restored.registry.is_active(&addr(9), roles::VALIDATOR));
}

// --- Task 0.40: equivocation/slashing history round-trip -----------------------

#[test]
fn slashing_history_survives_snapshot_round_trip() {
    use crate::registry::evidence::{SlashingProof, SlashingReport};

    let mut state = AccountState::new();
    let offender = addr(7);
    // Register the offender so the report is actionable and actually slashes.
    state
        .registry
        .register_validator(offender, 10_000, 0)
        .unwrap();

    // Route a canonical double-sign report through the single slash path; this
    // both slashes AND records the report into the persistent history.
    let report = SlashingReport::consensus_double_sign(
        offender,
        10,
        "HASH_A".into(),
        "HASH_B".into(),
        vec![1u8; 48],
        vec![2u8; 48],
        None,
    );
    let outcome = state
        .registry
        .slash_from_report(&report)
        .expect("actionable")
        .expect("offender registered -> slashed");
    assert!(outcome.penalty > 0);
    assert_eq!(state.registry.slashing_history().len(), 1);

    let restored = round_trip(&state);

    // History survives the round-trip byte-for-byte.
    let hist = restored.registry.slashing_history();
    assert_eq!(hist.len(), 1, "slashing history must survive restore");
    assert_eq!(hist[0].report.offender, offender);
    assert!(matches!(
        hist[0].report.proof,
        SlashingProof::DoubleSign { .. }
    ));
    assert_eq!(hist[0].penalty, outcome.penalty);
    assert_eq!(hist[0].remaining_stake, outcome.remaining_stake);
    // Per-offender query also works after restore.
    assert_eq!(restored.registry.slashing_history_for(&offender).len(), 1);
    assert_eq!(restored.registry.slashing_history_for(&addr(99)).len(), 0);
}

#[test]
fn invalid_vote_counters_survive_snapshot_round_trip() {
    let mut state = AccountState::new();
    let v = addr(8);
    let params = RegistryParams::default();
    // Two invalid votes this epoch (below the default threshold of 20).
    assert!(state
        .invalid_votes
        .record_invalid_vote(3, v, &params)
        .is_none());
    assert!(state
        .invalid_votes
        .record_invalid_vote(3, v, &params)
        .is_none());
    assert_eq!(state.invalid_votes.invalid_count(&v), 2);
    assert_eq!(state.invalid_votes.current_epoch(), 3);

    let restored = round_trip(&state);

    assert_eq!(restored.invalid_votes.invalid_count(&v), 2);
    assert_eq!(restored.invalid_votes.current_epoch(), 3);
}

// --- Liveness round-trip ----------------------------------------------------

#[test]
fn liveness_counters_survive_snapshot_round_trip() {
    let mut state = AccountState::new();
    let v = addr(3);
    let params = RegistryParams::default();
    // Two consecutive misses -> counter == 2.
    let none: std::collections::HashSet<Address> = std::collections::HashSet::new();
    state
        .liveness
        .record_epoch(1, &[v], |a| none.contains(a), &params);
    state
        .liveness
        .record_epoch(2, &[v], |a| none.contains(a), &params);
    assert_eq!(state.liveness.missed_count(&v), 2);

    let restored = round_trip(&state);
    assert_eq!(restored.liveness.missed_count(&v), 2);
}

// --- Tokenomics burn block round-trip (atomic) ------------------------------

#[test]
fn tokenomics_burn_block_survives_round_trip_atomically() {
    let addrs = TokenomicsAddresses::reserved();
    let mut state = AccountState::new();
    state.add_balance(&addrs.burn_reserve, bud(40_000_000));
    state.burn_reserve_address = Some(addrs.burn_reserve);
    state.team_vesting = Some((
        addrs.team,
        VestingSchedule {
            total: bud(20_000_000),
            start_epoch: 0,
            cliff_epochs: 1000,
            duration_epochs: 4000,
        },
    ));
    // Simulate 2 years already burned.
    state.timed_burn.years_burned = 2;
    state.timed_burn.total_burned = bud(8_000_000);

    let restored = round_trip(&state);

    // All three restored together and correctly.
    assert_eq!(restored.burn_reserve_address, Some(addrs.burn_reserve));
    assert_eq!(restored.team_vesting.unwrap().0, addrs.team);
    assert_eq!(restored.timed_burn.years_burned, 2);
    assert_eq!(restored.timed_burn.total_burned, bud(8_000_000));
}

// --- Double-burn prevention (CRITICAL) --------------------------------------

#[test]
fn no_double_burn_after_restore() {
    let addrs = TokenomicsAddresses::reserved();
    let mut state = AccountState::new();
    // Reserve already reduced by 2 years of burns (40M - 8M = 32M).
    state.add_balance(&addrs.burn_reserve, bud(32_000_000));
    state.burn_reserve_address = Some(addrs.burn_reserve);
    state.timed_burn.years_burned = 2;
    state.timed_burn.total_burned = bud(8_000_000);
    // Epoch is at the start of year 2 (2 years already accounted for).
    state.epoch_index = 2 * state.tokenomics.epochs_per_year;

    let reserve_before = state.get_balance(&addrs.burn_reserve);
    let burned_before = state.timed_burn.total_burned;

    // Restart: snapshot + restore.
    let mut restored = round_trip(&state);
    restored.epoch_index = state.epoch_index;

    // Immediately after restore, an epoch advance at the SAME year must NOT
    // re-burn the already-burned 2 years.
    restored.advance_epoch(0);
    // advance_epoch increments epoch_index by 1 (still within year 2), so due
    // years is still 2 -> nothing new burns.
    assert_eq!(restored.get_balance(&addrs.burn_reserve), reserve_before);
    assert_eq!(restored.timed_burn.total_burned, burned_before);
    assert_eq!(restored.timed_burn.years_burned, 2);

    // Now cross into year 3: exactly ONE new annual burn, never the prior two.
    restored.epoch_index = 3 * restored.tokenomics.epochs_per_year - 1;
    restored.advance_epoch(0); // -> epoch_index becomes 3*epy, due=3
    let per_year = restored.tokenomics.annual_burn_amount();
    assert_eq!(restored.timed_burn.years_burned, 3);
    assert_eq!(
        restored.timed_burn.total_burned,
        burned_before + per_year,
        "exactly one new year burned, no double-burn of the restored years"
    );
    assert_eq!(
        restored.get_balance(&addrs.burn_reserve),
        reserve_before - per_year
    );
}

// --- Backward compatibility (schema 2 snapshot without new fields) ----------

#[test]
fn schema_2_snapshot_without_new_fields_still_deserializes() {
    // A minimal schema-2 JSON (no registry/liveness/tokenomics/tokenomics_burn).
    // serde(default) must fill the new fields with empty/None.
    let json = r#"{
        "schema_version": 2,
        "height": 1,
        "block_hash": "x",
        "genesis_hash": "g",
        "chain_id": 1337,
        "created_at": 0,
        "balances": {},
        "nonces": {},
        "finalized_height": 0,
        "finalized_hash": "f",
        "validators": {},
        "unbonding_queue": [],
        "finality_certificates": [],
        "epoch_index": 0,
        "last_epoch_time": 0,
        "base_fee": 1,
        "block_reward": 50,
        "bridge_root": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "message_root": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "settlement_root": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "global_header_summary": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "snapshot_hash": "h"
    }"#;
    let v2 = StateSnapshotV2::from_bytes(json.as_bytes())
        .expect("old schema-2 snapshot must still deserialize");
    // from_bytes upgrades schema-2 to current (4) via C6 legacy-import
    assert_eq!(v2.schema_version, 4);
    // New fields default to empty/None (means: feature not active at snapshot time).
    assert!(v2.registry.clone().unwrap_or_default().is_empty());
    assert!(v2.tokenomics_burn.is_none());

    // And it restores into a usable AccountState (no tokenomics wiring).
    let state = AccountState::from_snapshot_v2(&v2);
    assert_eq!(state.burn_reserve_address, None);
    assert!(state.team_vesting.is_none());
}

// --- Task 0.32: silent-error pattern hardening ---------------------------------

/// The persistence serialize path is now fallible (`try_to_bytes`) rather than
/// silently returning empty bytes. For a real snapshot carrying a POPULATED
/// registry (the exact data class that silently produced empty bytes before the
/// Task 0.16 fix), `try_to_bytes` must return `Ok` and round-trip losslessly.
#[test]
fn try_to_bytes_ok_and_roundtrips_with_populated_registry() {
    let mut state = AccountState::new();
    state
        .registry
        .register_validator(addr(1), 5_000, 0)
        .unwrap();
    state.registry.register_relayer(addr(2), 3_000, 0).unwrap();

    let v2 = StateSnapshotV2::from_state(&state, snapshot_params());
    // Fallible path succeeds and is non-empty (would have been silently empty
    // pre-Task 0.16 due to the tuple-key map; try_to_bytes surfaces any failure).
    let bytes = v2
        .try_to_bytes()
        .expect("try_to_bytes must succeed for valid snapshot");
    assert!(!bytes.is_empty());
    assert_eq!(bytes, v2.to_bytes());

    let restored = StateSnapshotV2::from_bytes(&bytes).unwrap();
    let acct = AccountState::from_snapshot_v2(&restored);
    assert!(acct.registry.is_active(&addr(1), roles::VALIDATOR));
    assert!(acct.registry.is_active(&addr(2), roles::RELAYER));
}

/// Documents the failure class the old `unwrap_or_default()` swallowed: serde_json
/// genuinely fails on a non-string map key. Before Task 0.32 such a failure became
/// silent empty bytes; the hardened paths now either surface it (`try_to_bytes`
/// -> Err / Result), fail-fast (`.expect` on hash paths), or log + degrade
/// visibly (network). This test proves the underlying `to_vec` really can Err,
/// so the hardening is meaningful and not hypothetical.
#[test]
fn serde_json_failure_is_a_real_class_now_surfaced_not_swallowed() {
    use std::collections::HashMap;
    let mut bad: HashMap<[u8; 4], u32> = HashMap::new();
    bad.insert([1, 2, 3, 4], 7);
    let result = serde_json::to_vec(&bad);
    assert!(
        result.is_err(),
        "serde_json must reject a non-string map key (the swallowed failure class)"
    );
    // Old pattern hid this: `.unwrap_or_default()` -> empty Vec, no signal.
    let swallowed = serde_json::to_vec(&bad).unwrap_or_default();
    assert!(
        swallowed.is_empty(),
        "demonstrates the old silent-empty behavior"
    );
    // New persistence path surfaces the same class as an Err instead.
}
