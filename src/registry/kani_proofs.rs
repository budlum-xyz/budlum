//! Kani proof harnesses for bond arithmetic.
//!
//! `SECURITY.md` listed model checking as open work: the previous
//! `scripts/check-kani.sh` printed a stub and pointed at a file that was not in
//! the tree, so it was removed rather than left implying coverage. This module
//! is the replacement, and it is wired into CI by `scripts/check-kani.sh`.
//!
//! Bond arithmetic is the right first target for the reason SECURITY.md gives:
//! it is bounded, self-contained, and it decides how much stake a validator
//! loses. The properties below are the ones a reviewer would otherwise have to
//! argue by hand over `u64`/`u128` casts and a fixed-point divide.
//!
//! These are proofs, not tests. `kani::any()` is every value of the type, so a
//! passing harness rules out the whole input space rather than the handful of
//! points a unit test happens to pick. Proptest already covers the same
//! functions with sampled inputs; the two are complementary and both are kept.
//!
//! The module compiles only under `cfg(kani)`, so an ordinary `cargo build`,
//! `cargo test` or `cargo clippy` never sees it.

use crate::core::chain_config::FIXED_POINT_SCALE;

/// The penalty computation exactly as `slash_role_only` performs it.
///
/// Kept as a private mirror rather than calling the method because the method
/// needs a populated `PermissionlessRegistry` with a `BTreeMap` of
/// registrations, which model checking would have to unroll. The arithmetic is
/// what is being verified, and `bond_arithmetic_mirrors_the_registry` in the
/// ordinary test suite fails if this expression and the registry's ever
/// diverge — so the mirror cannot rot silently.
fn penalty_for(stake: u64, slash_ratio_fixed: u64) -> u64 {
    ((stake as u128 * slash_ratio_fixed as u128) / FIXED_POINT_SCALE as u128) as u64
}

/// A slash can never take more stake than the member has.
///
/// The multiply is done in `u128` and cast back to `u64`. That cast is the
/// interesting step: if the intermediate could exceed `u64::MAX` the result
/// would wrap, and a wrapped penalty subtracted with `saturating_sub` would
/// silently leave the bond untouched — a validator would keep its whole stake
/// after a proven double-sign.
///
/// `validate()` bounds every governance-settable ratio to `FIXED_POINT_SCALE`,
/// so that is the precondition assumed here.
#[kani::proof]
fn penalty_never_exceeds_stake() {
    let stake: u64 = kani::any();
    let ratio: u64 = kani::any();
    kani::assume(ratio <= FIXED_POINT_SCALE);

    let penalty = penalty_for(stake, ratio);

    assert!(
        penalty <= stake,
        "a slash must never exceed the bond it is taken from"
    );
}

/// The remaining stake after a slash is exactly `stake - penalty`.
///
/// `slash_role_only` writes `reg.stake = reg.stake.saturating_sub(penalty)`.
/// `saturating_sub` hides underflow, which is the right runtime behaviour and
/// the wrong thing to rely on: if a penalty could exceed the stake, the
/// saturation would quietly turn a 150% slash into a 100% one and the
/// accounting would disagree with the event that reported it. This proves the
/// saturation is never reached, so the subtraction is exact.
#[kani::proof]
fn remaining_stake_is_exact() {
    let stake: u64 = kani::any();
    let ratio: u64 = kani::any();
    kani::assume(ratio <= FIXED_POINT_SCALE);

    let penalty = penalty_for(stake, ratio);
    let remaining = stake.saturating_sub(penalty);

    assert!(
        remaining == stake - penalty,
        "saturating_sub must not be masking an underflow"
    );
    assert!(
        remaining.checked_add(penalty) == Some(stake),
        "stake must be conserved: remaining + penalty == original"
    );
}

/// A 100% ratio takes the entire bond, and a 0% ratio takes nothing.
///
/// The two endpoints are what the parameters actually use:
/// `malicious_slash_ratio_fixed` defaults to `FIXED_POINT_SCALE` ("proven
/// malice burns the whole bond") and a disabled condition means no penalty. A
/// rounding error at either endpoint would either leave dust in a bond that
/// should be gone, or take stake when nothing was owed.
#[kani::proof]
fn ratio_endpoints_are_exact() {
    let stake: u64 = kani::any();

    assert!(
        penalty_for(stake, FIXED_POINT_SCALE) == stake,
        "a 100% ratio must burn the whole bond, with no rounding dust left"
    );
    assert!(
        penalty_for(stake, 0) == 0,
        "a 0% ratio must not touch the bond"
    );
}

/// Slashing harder never costs the offender less.
///
/// Monotonicity is the property governance relies on when it raises a ratio:
/// the fixed-point divide truncates, and a non-monotonic truncation would mean
/// a higher configured penalty could produce a smaller actual one for some
/// stake — an incentive inversion that no unit test would be likely to sample.
#[kani::proof]
fn penalty_is_monotonic_in_the_ratio() {
    let stake: u64 = kani::any();
    let lower: u64 = kani::any();
    let higher: u64 = kani::any();
    kani::assume(higher <= FIXED_POINT_SCALE);
    kani::assume(lower <= higher);

    assert!(
        penalty_for(stake, lower) <= penalty_for(stake, higher),
        "raising the slash ratio must never reduce the penalty"
    );
}

/// An out-of-range ratio would break the bound — which is why `validate()`
/// rejects one.
///
/// This harness carries the assumption the others make. If `validate()` ever
/// stopped bounding the ratio, `penalty_never_exceeds_stake` would still pass
/// (its precondition is assumed, not enforced) while production became
/// unsound. Here the precondition is dropped deliberately and the harness
/// asserts the failure is real, so the bound is recorded as load-bearing
/// rather than incidental.
#[kani::proof]
fn an_unbounded_ratio_would_overshoot_the_bond() {
    let stake: u64 = kani::any();
    let ratio: u64 = kani::any();
    kani::assume(stake > 0);
    kani::assume(ratio > FIXED_POINT_SCALE);

    // Not an assertion about production: production cannot reach this state,
    // because `RegistryParams::validate` refuses such a ratio and every
    // `set_params` caller runs it first. It states what that check is buying.
    assert!(
        penalty_for(stake, ratio) > stake || stake as u128 * ratio as u128 > u128::from(u64::MAX),
        "a ratio above FIXED_POINT_SCALE must overshoot the bond or overflow \
         the u64 result — either way `validate()` is what prevents it"
    );
}
