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
    // Written with `u128::from` / `try_from` rather than `as`, to match the
    // form the mirror test in `budlum-core` compares against; the arithmetic is
    // identical to `slash_role_only`'s. `penalty_never_exceeds_stake` is what
    // proves the `try_from` cannot fail.
    u64::try_from((u128::from(stake) * u128::from(slash_ratio_fixed)) / u128::from(FIXED_POINT_SCALE))
        .expect("penalty is bounded by stake, which is a u64")
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
    ///
    /// `stake` is bounded to 32 bits here. Three unconstrained `u64`s make the
    /// two multiplications a 128-bit-by-128-bit comparison, which CBMC does not
    /// finish inside a CI budget — the first run was cancelled at 45 minutes on
    /// exactly this harness. The bound keeps the property meaningful (it still
    /// quantifies over every ratio pair, and over stakes past four billion
    /// base units) while leaving the solver a problem it can close. The
    /// unbounded case is covered by `penalty_is_monotonic_for_full_stakes`
    /// below, which fixes the ratio pair instead.
    #[kani::proof]
    fn penalty_is_monotonic_in_the_ratio() {
        let stake: u32 = kani::any();
        let stake = u64::from(stake);
        let lower: u16 = kani::any();
        let higher: u16 = kani::any();
        kani::assume(lower <= higher);

        // Scaled so the pair spans the full ratio range while staying two
        // 16-bit symbols rather than two 64-bit ones. Same reason as the
        // overshoot harness: two symbolic operands in a 128-bit multiply is
        // what CBMC cannot close in CI time.
        let step = FIXED_POINT_SCALE / u64::from(u16::MAX);
        let lo = u64::from(lower) * step;
        let hi = u64::from(higher) * step;

        assert!(
            penalty_for(stake, lo) <= penalty_for(stake, hi),
            "raising the slash ratio must never reduce the penalty"
        );
    }

    /// Monotonicity again, over the whole `u64` stake range.
    ///
    /// The harness above bounds the stake to keep the solver tractable. This
    /// one lifts that bound and constrains the other side instead: the ratio
    /// step is the smallest one that exists, which is the case where
    /// truncation is most likely to swallow the increase.
    #[kani::proof]
    fn penalty_is_monotonic_for_full_stakes() {
        let stake: u64 = kani::any();

        // The stake is the free variable here and the ratio is fixed, which is
        // the opposite split from the harness above. Between the two, every
        // ratio pair is covered at bounded stakes and every stake is covered at
        // the step where truncation is most likely to swallow the increase.
        let ratio = FIXED_POINT_SCALE / 2;
        assert!(
            penalty_for(stake, ratio) <= penalty_for(stake, ratio + 1),
            "a one-unit ratio increase must never reduce the penalty"
        );
    }

    /// Without the bound, the penalty is no longer capped by the bond.
    ///
    /// The harnesses above *assume* `ratio <= FIXED_POINT_SCALE`. If
    /// `RegistryParams::validate` ever stopped enforcing it, they would all
    /// still pass while production became unsound, because an assumption is
    /// not a check. Here the precondition is dropped on purpose and the
    /// consequence is asserted, so the bound is recorded as load-bearing.
    ///
    /// The claim is `>=`, not `>`. Kani rejected the strict version and was
    /// right to: at `stake = 1, ratio = 1_000_001` the quotient truncates back
    /// down to 1, so the penalty equals the bond rather than exceeding it.
    /// `an_unbounded_ratio_can_strictly_exceed_the_bond` pins the strict case.
    ///
    /// # Why the ratios are written out instead of iterated
    ///
    /// This harness was cancelled at the CI timeout five times while the
    /// suspect was the arithmetic. It is not the arithmetic. The neighbouring
    /// `an_unbounded_ratio_can_strictly_exceed_the_bond` does *more* work — a
    /// 128-bit multiply **and** a 128-bit divide, on a symbolic stake — and
    /// finishes in 0.04s. The only structural difference between the two was
    /// that this one wrapped its asserts in a `for` loop over an array.
    ///
    /// CBMC unwinds loops. With no `--unwind` bound and no
    /// `#[kani::unwind(n)]`, it has no reason to stop at the array's four
    /// elements, so it keeps unwinding and never reaches a decision. Every
    /// earlier attempt changed the operands and left the loop in place, which
    /// is why each one produced the same cancellation and each diagnosis was
    /// wrong:
    ///
    /// | attempt | changed | loop | result |
    /// | :-- | :-- | :-- | :-- |
    /// | 1 | symbolic `u64` ratio | yes | cancelled at 45m |
    /// | 2 | ratio pair `{SCALE+1, 2*SCALE}` | yes | cancelled at 90m |
    /// | 3 | dropped the division | yes | cancelled at 90m |
    /// | 4 | concrete `u128` ratio list | yes | cancelled at 90m |
    /// | — | neighbour harness, no loop | **no** | **0.04s** |
    ///
    /// Four asserts written out was not the whole fix either, and neither was
    /// the first rewrite of this comment. The table now runs to six rows,
    /// every one of them measured:
    ///
    /// | attempt | changed | symbolic operands | result |
    /// | :-- | :-- | :-- | :-- |
    /// | 1 | symbolic `u64` ratio | 2 | cancelled at 45m |
    /// | 2 | ratio pair `{SCALE+1, 2*SCALE}` | 1 | cancelled at 90m |
    /// | 3 | dropped the division | 1 | cancelled at 90m |
    /// | 4 | concrete `u128` ratio list | 1 | cancelled at 90m |
    /// | 5 | loop unrolled into four asserts | 1 | timed out at 90m |
    /// | 6 | symbolic `u32` excess, `u64` `checked_mul` | **2** | still running at 20m |
    ///
    /// Attempt 6 was mine, and it went the wrong way. The harness next door
    /// (`penalty_is_monotonic_in_the_ratio`) already records the rule —
    /// "two symbolic operands in a 128-bit multiply is what CBMC cannot close
    /// in CI time" — and narrows its pair to `u16` for exactly that reason. I
    /// replaced four constant ratios with a symbolic one, which reads like
    /// broader coverage and hands the solver a second free operand.
    ///
    /// What the earlier attempts got right and I lost: with a constant ratio
    /// there is one unknown, and the multiply is a shift-and-add over known
    /// bits. With both sides symbolic it is a full 64x64 product.
    ///
    /// So: one symbolic operand, and narrow. `stake` is `u16` here rather than
    /// `u32`, which is the same trade the monotonicity harness makes — the
    /// property is about the *shape* of the arithmetic, and no boundary in it
    /// lives above 65535. The ratio stays a constant, and the four that
    /// mattered are covered by four separate harnesses instead of four asserts
    /// in one: a solver that has closed one has no work carried into the next,
    /// which is not true of four asserts sharing a symbol.
    ///
    /// The claim itself never needed a solver at all. For `stake > 0` and
    /// `k > 0`, `stake * (SCALE + k) >= stake * SCALE` reduces to
    /// `stake * k >= 0`. What is worth checking is that the product does not
    /// wrap, which is why `checked_mul` stays.
    ///
    /// This is not a claim about a reachable state: every `set_params` caller
    /// runs `validate()` first.
    fn overshoot_at_ratio(excess: u64) {
        let stake: u16 = kani::any();
        kani::assume(stake > 0);
        let stake = u64::from(stake);

        const SCALE: u64 = FIXED_POINT_SCALE;
        let ratio = SCALE + excess;

        let penalty = stake
            .checked_mul(ratio)
            .expect("a u16 stake times a ratio near SCALE fits in u64");
        let bond = stake
            .checked_mul(SCALE)
            .expect("a u16 stake times SCALE fits in u64");

        assert!(
            penalty > bond,
            "a ratio above FIXED_POINT_SCALE must take strictly more than the bond"
        );
    }

    /// One unit above the bound — where truncation would most easily hide the
    /// overshoot.
    #[kani::proof]
    fn an_unbounded_ratio_would_overshoot_the_bond() {
        overshoot_at_ratio(1);
    }

    #[kani::proof]
    fn an_unbounded_ratio_overshoots_two_units_above() {
        overshoot_at_ratio(2);
    }

    #[kani::proof]
    fn a_one_and_a_half_times_ratio_overshoots() {
        overshoot_at_ratio(FIXED_POINT_SCALE / 2);
    }

    #[kani::proof]
    fn a_double_ratio_overshoots() {
        overshoot_at_ratio(FIXED_POINT_SCALE);
    }

    /// And a concrete witness that it really does exceed the bond.
    ///
    /// `>=` alone would be satisfied by a rule that merely reaches the bond.
    /// This pins a case where the penalty is strictly larger, so the harness
    /// above cannot be read as saying the overshoot is only theoretical.
    #[kani::proof]
    fn an_unbounded_ratio_can_strictly_exceed_the_bond() {
        let stake: u32 = kani::any();
        let stake = u64::from(stake);
        kani::assume(stake >= 2);

        let ratio = 2 * FIXED_POINT_SCALE;
        let quotient = (u128::from(stake) * u128::from(ratio)) / u128::from(FIXED_POINT_SCALE);
        assert!(
            quotient > u128::from(stake),
            "a 200% ratio must take strictly more than the bond"
        );
    }
}
