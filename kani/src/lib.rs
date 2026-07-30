//! Bond arithmetic under model checking.
//!
//! `SECURITY.md` listed Kani as open work and named the targets: signature
//! verification, bond arithmetic and Merkle paths. Bond arithmetic is the one
//! that is bounded, self-contained and decides how much stake a validator
//! loses, so it is first.
//!
//! # Why this lives outside `budlum-core`
//!
//! Kani ships a pinned nightly. Version 0.67.0 — the newest published release
//! — bundles rustc 1.93.0-nightly, and `budlum-core` declares
//! `rust-version = "1.94.0"`, so cargo refuses the build before a harness
//! runs. The upstream toolchain bump is merged but unreleased. Lowering the
//! crate's MSRV to suit a verification tool would weaken a promise made to
//! operators in order to make a check pass, so the harnesses live in a
//! standalone package instead.
//!
//! # Why a mirror is sound here
//!
//! [`penalty_for`] is the expression from
//! `PermissionlessRegistry::slash_role_only`, character for character. It is
//! not called through the registry because that needs a populated `BTreeMap`
//! of registrations, which a bit-precise model checker would have to unroll —
//! the arithmetic is what is under proof, not the map.
//!
//! A copy can rot. Two things stop it: `budlum-core`'s
//! `bond_arithmetic_matches_the_kani_mirror` recomputes both and fails on any
//! divergence, and `scripts/check-kani.sh` fails if the number of harnesses
//! Kani ran drops below the number declared here.

/// Fixed-point denominator, mirroring `core::chain_config::FIXED_POINT_SCALE`.
pub const FIXED_POINT_SCALE: u64 = 1_000_000;

/// The penalty computation exactly as `slash_role_only` performs it.
///
/// ```text
/// let penalty =
///     ((reg.stake as u128 * slash_ratio_fixed as u128) / FIXED_POINT_SCALE as u128) as u64;
/// ```
#[must_use]
pub fn penalty_for(stake: u64, slash_ratio_fixed: u64) -> u64 {
    ((stake as u128 * slash_ratio_fixed as u128) / FIXED_POINT_SCALE as u128) as u64
}

#[cfg(kani)]
mod proofs {
    use super::{penalty_for, FIXED_POINT_SCALE};

    /// A slash can never take more stake than the member has.
    ///
    /// The multiply happens in `u128` and the result is cast back to `u64`.
    /// That cast is the interesting step: a wrapped penalty subtracted with
    /// `saturating_sub` would leave the bond untouched, so a validator would
    /// keep its whole stake after a proven double-sign.
    ///
    /// `RegistryParams::validate` bounds every governance-settable ratio to
    /// `FIXED_POINT_SCALE`, which is the precondition assumed here.
    #[kani::proof]
    fn penalty_never_exceeds_stake() {
        let stake: u64 = kani::any();
        let ratio: u64 = kani::any();
        kani::assume(ratio <= FIXED_POINT_SCALE);

        assert!(
            penalty_for(stake, ratio) <= stake,
            "a slash must never exceed the bond it is taken from"
        );
    }

    /// Stake is conserved: `remaining + penalty == stake`, exactly.
    ///
    /// `slash_role_only` writes `reg.stake = reg.stake.saturating_sub(penalty)`.
    /// Saturation is the right runtime behaviour and the wrong thing to rely
    /// on: if a penalty could exceed the stake, it would quietly turn a 150%
    /// slash into a 100% one and the accounting would disagree with the
    /// `SlashOutcome` that reported it. This proves saturation is unreachable.
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

    /// The two endpoints are exact.
    ///
    /// `malicious_slash_ratio_fixed` defaults to `FIXED_POINT_SCALE` — "proven
    /// malice burns the whole bond" — and a zero ratio must take nothing.
    /// Rounding at either end would leave dust in a bond that should be gone,
    /// or take stake when none was owed.
    #[kani::proof]
    fn ratio_endpoints_are_exact() {
        let stake: u64 = kani::any();

        assert!(
            penalty_for(stake, FIXED_POINT_SCALE) == stake,
            "a 100% ratio must burn the whole bond, leaving no rounding dust"
        );
        assert!(
            penalty_for(stake, 0) == 0,
            "a 0% ratio must not touch the bond"
        );
    }

    /// Slashing harder never costs the offender less.
    ///
    /// Governance relies on this when it raises a ratio. The fixed-point
    /// divide truncates, and a non-monotonic truncation would mean a higher
    /// configured penalty producing a smaller actual one for some stake — an
    /// incentive inversion no sampled test would be likely to find.
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

    /// Without the bound, the guarantee breaks — which is what `validate()` buys.
    ///
    /// The four harnesses above *assume* `ratio <= FIXED_POINT_SCALE`. If
    /// `RegistryParams::validate` ever stopped enforcing it, they would all
    /// still pass while production became unsound, because an assumption is
    /// not a check. Here the precondition is dropped on purpose and the
    /// failure is asserted, so the bound is recorded as load-bearing.
    ///
    /// This is not a claim about a reachable state: every `set_params` caller
    /// runs `validate()` first.
    #[kani::proof]
    fn an_unbounded_ratio_would_overshoot_the_bond() {
        let stake: u64 = kani::any();
        let ratio: u64 = kani::any();
        kani::assume(stake > 0);
        kani::assume(ratio > FIXED_POINT_SCALE);

        assert!(
            penalty_for(stake, ratio) > stake
                || u128::from(stake) * u128::from(ratio) > u128::from(u64::MAX),
            "a ratio above FIXED_POINT_SCALE must overshoot the bond or \
             overflow the u64 result — `validate()` is what prevents both"
        );
    }
}
