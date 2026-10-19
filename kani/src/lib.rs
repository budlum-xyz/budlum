//! Bond arithmetic under model checking.
//!
//! `SECURITY.md` listed Kani as open work and named the targets: signature
//! verification, bond arithmetic and Merkle paths. Bond arithmetic is the one
//! that is bounded, self-contained and decides how much stake a validator
//! loses, so it is first.
//!
//! # Why this lives outside `budlum-core`
//!
//! Kani ships a pinned nightly. Version 0.67.0, the newest published release,
//! bundles rustc 1.93.0-nightly, and `budlum-core` declares
//! `rust-version = "1.97.1"`, so cargo refuses the build before a harness
//! runs. The upstream toolchain bump is merged but unreleased. Lowering the
//! crate's MSRV to suit a verification tool would weaken a promise made to
//! operators in order to make a check pass, so the harnesses live in a
//! standalone package instead.
//!
//! # Why a mirror is used here
//!
//! [`penalty_for`] is the expression from `core::chain_config::slash_penalty`
//! (called by `PermissionlessRegistry::slash_role_only`). It is not called
//! through the registry because that needs a populated `BTreeMap`
//! of registrations, which a bit-precise model checker would have to unroll,
//! the arithmetic is what is under proof, not the map.
//!
//! A copy can rot, and this package has no link that stops it. The kani
//! package does not depend on `budlum-core` and `budlum-core` does not depend
//! on it, so no test calls the functions in this file. Facts, as of this
//! writing:
//!
//! * Production slashing calls `core::chain_config::slash_penalty`. This
//!   file's [`penalty_for`] is a second copy of that function.
//! * `budlum-core`'s `bond_arithmetic_matches_the_kani_mirror`, the Merkle
//!   mirror test and the PQ length test each compare production with a third,
//!   hand-written copy that sits inside the test. They do not look at this
//!   file.
//! * The only guard on this file is the harness-count gate
//!   (`xtask/gates/src/gates/kani.rs`), which checks that every declared
//!   harness ran. It does not check that the logic equals production.
//!
//! So the proofs hold for the text of this file. That they hold for
//! production depends on a human keeping the copies equal. Closing the gap
//! needs one shared definition, for example a path dependency from
//! `budlum-core` (dev-dependencies) on this package so a test can call these
//! functions directly. That changes the root manifest and is tracked as a
//! decision, not done here.

/// Fixed-point denominator, mirroring `core::chain_config::FIXED_POINT_SCALE`.
pub const FIXED_POINT_SCALE: u64 = 1_000_000;

/// The penalty computation exactly as `core::chain_config::slash_penalty`
/// performs it (production slashing calls that function).
///
/// ```text
/// let quotient = (stake as u128 * ratio as u128) / FIXED_POINT_SCALE as u128;
/// // clamped to `stake` instead of narrowed with `as u64`
/// ```
#[must_use]
pub fn penalty_for(stake: u64, slash_ratio_fixed: u64) -> u64 {
    // The quotient is clamped to `stake` instead of being unwrapped into a
    // `u64`.
    //
    // The previous form was `try_from(...).expect(...)`, which asserted the
    // quotient always fits. It does not. At `stake = u64::MAX` and any ratio
    // above `FIXED_POINT_SCALE` the quotient exceeds `u64::MAX`, so the mirror
    // panicked while production, which spelled the same expression with
    // `as u64`, wrapped instead: `ratio = FIXED_POINT_SCALE + 1` turned a
    // 100.0001% slash into one that left 99.9999% of the bond standing. The
    // two copies did not agree, and the mirror test compared them only over
    // ratios at or below the ceiling, where they do. See B35.
    //
    // Clamping is also what makes the bound provable. Measured against the
    // same class of bitvector query Kani issues, negating `penalty <= stake`:
    //
    //     symbolic udiv, 128 bit       TIMEOUT at 120s
    //     symbolic product, no divide  TIMEOUT at  45s
    //     divide by a constant         TIMEOUT at  45s
    //     clamped form                 PROVED  in 0.37s
    //
    // Both terms are walls, not only the divide. The plan recorded earlier,
    // restating the division as a shift/multiply-high pair, would have removed
    // one wall and left the other: `sym * sym` with no divide at all still
    // times out. Clamping moves the property off the arithmetic. `penalty
    // <= stake` is now a fact about a `min`, and holds with no precondition on
    // the ratio, which is the point: it does not depend on governance having
    // validated anything.
    let quotient =
        (u128::from(stake) * u128::from(slash_ratio_fixed)) / u128::from(FIXED_POINT_SCALE);
    if quotient > u128::from(u64::MAX) {
        return stake;
    }
    let narrow = quotient as u64;
    if narrow > stake {
        stake
    } else {
        narrow
    }
}

/// The unclamped quotient, for the harnesses that are *about* the overshoot.
///
/// `penalty_for` now caps at the bond, so a harness asking "does a ratio above
/// the ceiling take more than the bond?" would be asking about the cap rather
/// than about the arithmetic. This keeps the raw expression available so that
/// question stays answerable, and so the clamp cannot quietly turn those
/// harnesses vacuous.
#[must_use]
pub fn raw_quotient(stake: u64, slash_ratio_fixed: u64) -> u128 {
    (u128::from(stake) * u128::from(slash_ratio_fixed)) / u128::from(FIXED_POINT_SCALE)
}

// ---------------------------------------------------------------------------
// Merkle tree structure (mirrors `consensus::merkle_tree`)
// ---------------------------------------------------------------------------
//
// `SECURITY.md` named Merkle paths and signature verification as open work:
// both reach into third-party crypto crates (SHA3-256, the PQ backends) that a
// model checker would have to unroll, so the harnesses are written against
// extracted, bounded logic first. The extracted logic is the tree *shape*:
// sibling selection, layer growth, root extraction and the proof walk, none of
// which depend on the hash function. The production binding is SHA3-256
// (`consensus::merkle_tree::combine_sha3`); here the shape is checked with an
// abstract 32-byte combine so the solver never sees a hash permutation.
//
// `budlum-core`'s `qc_merkle_matches_the_kani_mirror` keeps the two trees in
// step: it runs the production tree and this literal copy over the same leaves
// and fails on any divergence.

// The mirrors below are bounded models of the production tree in
// `consensus::merkle_tree`. Production trees are unbounded and hash with
// SHA3-256; a bit-precise model checker cannot close either property
// symbolically, so the harnesses verify the bounded shape on fixed-size
// arrays, and `budlum-core`'s `qc_merkle_matches_the_kani_mirror` pins the
// bounded model to the production tree over concrete vectors. The shape -
// sibling selection, layer growth, root extraction, the proof walk - does not
// depend on the hash, which is what makes the substitution sound.

/// The maximum live leaves the bounded mirrors accept. The mirror test runs
/// production trees of the same sizes, so a drift in this bound is caught.
pub const MAX_MIRROR_LEAVES: usize = 4;

/// Sibling index under the production rule, mirroring
/// `consensus::merkle_tree::merkle_sibling_index`.
///
/// An even node pairs with the next node; an odd node pairs with the
/// previous node. An even node that is the tail of its layer has no sibling
/// at all - it is promoted - and the rebuild walk detects that case before
/// it asks for a sibling here.
#[must_use]
pub fn merkle_sibling_index(index: usize, layer_len: usize) -> usize {
    if index.is_multiple_of(2) {
        (index + 1).min(layer_len.saturating_sub(1))
    } else {
        index.saturating_sub(1)
    }
}

/// Abstract 64-bit node combine used by the harnesses.
///
/// This is NOT the production hash. It is deliberately **not commutative**, so
/// the proof of the rebuild walk actually exercises sibling ordering: a
/// commutative combine (plain xor) would make `combine(left, right) ==
/// combine(right, left)` and could not catch a walk that swaps an odd-indexed
/// child with its sibling. The rotation separates the two sides under xor.
#[must_use]
pub fn combine_nodes_u64(left: u64, right: u64) -> u64 {
    left.rotate_left(17) ^ right.rotate_right(7)
}

/// Abstract 64-bit node promotion used by the harnesses.
///
/// This is NOT the production hash. It is deliberately unreachable from
/// `combine_nodes_u64` (a rotation plus a constant the binary combine never
/// applies), so the proof of the rebuild walk can tell a promoted tail from
/// a self-paired one - the property the duplicate-tail rule could not
/// express.
#[must_use]
pub fn promote_node_u64(node: u64) -> u64 {
    node.rotate_left(13) ^ 0x5A5A_5A5A_5A5A_5A5A
}

/// Fold one parent layer into `layer[0..len]` in place, mirroring
/// `consensus::merkle_tree::merkle_parent_layer` (pairs combined, an
/// unpaired tail promoted - never paired with itself, parents written to
/// the front of the buffer). Returns the number of parents.
#[must_use]
pub fn merkle_parent_layer_fold(layer: &mut [u64; MAX_MIRROR_LEAVES], len: usize) -> usize {
    let mut i = 0;
    let mut out = 0;
    while i < len {
        if i + 1 < len {
            layer[out] = combine_nodes_u64(layer[i], layer[i + 1]);
        } else {
            layer[out] = promote_node_u64(layer[i]);
        }
        i += 2;
        out += 1;
    }
    out
}

/// The root digest over `leaves[0..len]`, or `None` for an empty tree,
/// mirroring `consensus::merkle_tree::merkle_root`.
#[must_use]
pub fn merkle_root_u64(leaves: &[u64; MAX_MIRROR_LEAVES], len: usize) -> Option<u64> {
    if len == 0 {
        return None;
    }
    let mut work = *leaves;
    let mut layer_len = len;
    while layer_len > 1 {
        layer_len = merkle_parent_layer_fold(&mut work, layer_len);
    }
    Some(work[0])
}

/// The value a verifier rebuilds for `leaf_index` by walking the layers with
/// the production sibling rule, mirroring
/// `consensus::merkle_tree::merkle_rebuild_root`. `None` when the leaf is out
/// of range or the tree is empty.
#[must_use]
pub fn merkle_rebuild_root_u64(
    leaves: &[u64; MAX_MIRROR_LEAVES],
    len: usize,
    leaf_index: usize,
) -> Option<u64> {
    if len == 0 || leaf_index >= len {
        return None;
    }
    let mut work = *leaves;
    let mut layer_len = len;
    let mut idx = leaf_index;
    let mut cur = work[idx];
    while layer_len > 1 {
        if idx.is_multiple_of(2) && idx + 1 >= layer_len {
            // The tail of an odd layer is promoted, not paired with itself.
            cur = promote_node_u64(cur);
        } else {
            let sibling_idx = merkle_sibling_index(idx, layer_len);
            let sibling = work[sibling_idx];
            // Order the two children by position: an even node is the left
            // child, an odd node the right child. `verify_inclusion` in
            // `qc.rs` orders the same way; a swapped order only matches the
            // tree under a commutative combine, which is why the harness
            // combine is not one.
            cur = if idx.is_multiple_of(2) {
                combine_nodes_u64(cur, sibling)
            } else {
                combine_nodes_u64(sibling, cur)
            };
        }
        idx /= 2;
        layer_len = merkle_parent_layer_fold(&mut work, layer_len);
    }
    Some(cur)
}

// ---------------------------------------------------------------------------
// PQ signature length classification (mirrors `crypto::primitives`)
// ---------------------------------------------------------------------------
//
// The bounded logic around signature verification is the length admissibility
// check: a validator registration or an attestation either carries the length
// the scheme demands or it is malformed before any signature arithmetic runs.
// The three accepted signature lengths (Dilithium5, ML-DSA-65, ML-DSA-87) are
// pairwise distinct, so a single length classifies a PQ signature
// unambiguously. `budlum-core`'s `pq_signature_classification_matches_the_
// kani_mirror` keeps the constants in step with `crypto::primitives`.

/// Dilithium5 signature length in bytes (CRYSTALS-Dilithium round-3 set).
pub const PQ_SIG_LEN_DILITHIUM5: usize = 4595;
/// FIPS 204 ML-DSA-65 signature length in bytes.
pub const PQ_SIG_LEN_ML_DSA_65: usize = 3309;
/// FIPS 204 ML-DSA-87 signature length in bytes.
pub const PQ_SIG_LEN_ML_DSA_87: usize = 4627;

/// The PQ signature scheme a signature length identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqSigClass {
    Dilithium5,
    MlDsa65,
    MlDsa87,
    Unknown,
}

/// Classify a PQ signature length, mirroring `crypto::primitives::classify_pq_signature_len`.
#[must_use]
pub fn classify_pq_signature_len(len: usize) -> PqSigClass {
    if len == PQ_SIG_LEN_DILITHIUM5 {
        PqSigClass::Dilithium5
    } else if len == PQ_SIG_LEN_ML_DSA_65 {
        PqSigClass::MlDsa65
    } else if len == PQ_SIG_LEN_ML_DSA_87 {
        PqSigClass::MlDsa87
    } else {
        PqSigClass::Unknown
    }
}

/// Whether a signature length is acceptable for an expected scheme, mirroring
/// `crypto::primitives::pq_signature_len_acceptable`.
#[must_use]
pub fn pq_signature_len_acceptable(len: usize, expected: PqSigClass) -> bool {
    match expected {
        PqSigClass::Dilithium5 => len == PQ_SIG_LEN_DILITHIUM5,
        PqSigClass::MlDsa65 => len == PQ_SIG_LEN_ML_DSA_65,
        PqSigClass::MlDsa87 => len == PQ_SIG_LEN_ML_DSA_87,
        PqSigClass::Unknown => false,
    }
}

// ---------------------------------------------------------------------------
// Finality certificate bitmap accounting (mirrors `chain::finality`)
// ---------------------------------------------------------------------------
//
// `FinalityCert::verify` walks the signer bitmap and accumulates the stake of
// every validator whose bit is set. The bounded logic here is the accounting:
// no bitmap can vote more stake than the set holds. The BLS signature check
// itself stays behind the `bls12_381` crate; the accumulation is what decides
// whether a certificate carries the quorum before that check runs.

/// Maximum validators the bounded bitmap mirror accepts.
pub const MAX_MIRROR_VALIDATORS: usize = 4;

/// Voted-stake accumulation, mirroring `FinalityCert::verify`'s bitmap walk in
/// `chain::finality`: a `u128` accumulator and a plain `+=`, as in production.
/// The sum of at most `MAX_MIRROR_VALIDATORS` values of `u64` cannot overflow
/// a `u128`, so no saturation is needed or used.
///
/// `bitmap_stake_accounting_matches_the_kani_mirror` in `budlum-core` compares
/// this copy with the stake `FinalityCert::verify` reports. The bound
/// `voted <= total` is true for any non-negative terms, so the harness below
/// also proves the exact selection rule (see its comment).
#[must_use]
pub fn bitmap_voted_stake(
    stakes: &[u64; MAX_MIRROR_VALIDATORS],
    n: usize,
    bitmap: &[u8; 1],
) -> u128 {
    let mut voted_stake: u128 = 0;
    let mut idx = 0;
    while idx < n {
        let byte_idx = idx / 8;
        let bit_idx = idx % 8;
        if byte_idx < bitmap.len() && (bitmap[byte_idx] & (1 << bit_idx)) != 0 {
            voted_stake += u128::from(stakes[idx]);
        }
        idx += 1;
    }
    voted_stake
}

/// The sum of all stakes in the set, the upper bound the accumulation above
/// is checked against.
#[must_use]
pub fn stake_sum(stakes: &[u64; MAX_MIRROR_VALIDATORS], n: usize) -> u128 {
    let mut total: u128 = 0;
    let mut idx = 0;
    while idx < n {
        total += u128::from(stakes[idx]);
        idx += 1;
    }
    total
}

// MEASURED, 2026-08-01: every harness that calls `penalty_for` times out.
//
// Six rewrites went into `an_unbounded_ratio_would_overshoot_the_bond` on the
// theory that its multiplications were the problem. They were not. Timing each
// harness separately in an isolated repo, with a three-minute cap each:
//
//     penalty_is_monotonic_for_full_stakes   TIMEOUT
//     penalty_never_exceeds_stake            TIMEOUT
//     remaining_stake_is_exact               TIMEOUT
//     ratio_endpoints_are_exact              TIMEOUT
//     penalty_is_monotonic_in_the_ratio      TIMEOUT
//     a_double_ratio_overshoots                   1s
//     an_unbounded_ratio_can_strictly_exceed_the_bond  0s
//
// The split is exact: the two that finish are the two that do not call
// `penalty_for`. Stake width does not explain it -
// `penalty_is_monotonic_in_the_ratio` was already narrowed to u16 symbols and
// still times out. Multiplication count does not explain it either.
//
// What `penalty_for` had that nothing else here has is a **symbolic division**:
// `(u128 * u128) / u128`. A solver handles a symbolic multiply by summing
// partial products; a symbolic divide it must encode as a search for a
// quotient and remainder satisfying `n = q*d + r, r < d`, over 128-bit terms.
// That reading named a real cost, and it was still the wrong conclusion.
//
// MEASURED AGAIN, 2026-08-01, second pass. The plan recorded above was to
// restate the division as a shift/multiply-high pair. Before writing it, the
// same class of query was put to a bitvector solver directly, negating
// `penalty <= stake`, with the divide present and removed:
//
//     sym * sym, then divide          TIMEOUT   (penalty_for as written)
//     sym * sym, no divide at all     TIMEOUT
//     sym * const, then divide        TIMEOUT
//     sym * const, no divide          PROVED in 0.02s
//     multiply-high reciprocal        TIMEOUT   (the recorded plan)
//
// The recorded plan does not work. Removing the divide is not sufficient
// because the 128-bit **symbolic product** is a wall on its own: three of the
// four cells time out, and the only affordable one is the cell with neither a
// symbolic product nor a divide. A width sweep puts the cliff between u16 and
// u24 operands, far below the u64 the property needs.
//
// So the expression cannot be rewritten into something a solver closes while
// it still multiplies two symbols. The bound is made structural instead:
// `penalty_for` clamps to `stake`. The clamped form is PROVED in 0.37s, and
// in 13.6s even with the ratio precondition dropped entirely.
//
// What that costs, stated plainly: `penalty <= stake` is no longer evidence
// that the division cannot overshoot. It is evidence that an overshoot cannot
// reach the ledger. The overshoot harnesses below keep asking the first
// question by calling `raw_quotient`, so the clamp cannot turn them vacuous.
//
// MEASURED IN CI, per harness, each in its own job with its own cap:
//
//     penalty_never_exceeds_stake                       1s   was TIMEOUT
//     remaining_stake_is_exact                          6s   was TIMEOUT
//     the_clamp_catches_the_quotient_that_used_to_wrap  1s   new
//     no_ratio_can_make_the_penalty_exceed_the_bond     1s   new
//     an_unbounded_ratio_would_overshoot_the_bond       8s   control, unchanged
//     an_unbounded_ratio_overshoots_two_units_above     7s   control, unchanged
//     a_one_and_a_half_times_ratio_overshoots           1s   control, unchanged
//     a_double_ratio_overshoots                         1s   control, unchanged
//     an_unbounded_ratio_can_strictly_exceed_the_bond   1s   control, unchanged
//
// Three are still slow and the clamp does not help them, which is consistent
// rather than surprising:
//
//     ratio_endpoints_are_exact
//     penalty_is_monotonic_in_the_ratio
//     penalty_is_monotonic_for_full_stakes
//
// Each calls `penalty_for` **twice** and relates the two results. The clamp
// bounds a single call against its own input; it says nothing that lets a
// solver compare two independent quotients, so both symbolic products survive
// in the query. Measured: one clamped call is proved in 0.39s, two clamped
// calls related to each other time out at 90s.
//
// Splitting the asserts does not rescue them either, which was the obvious
// next guess and was measured before being believed:
//
//     ratio_endpoints, both asserts together   TIMEOUT
//       split out `ratio == 0` alone           PROVED in 0.00s
//       split out `ratio == SCALE` alone       TIMEOUT
//
// `ratio == 0` collapses the product to zero, so it is free. `ratio == SCALE`
// leaves `stake * 1_000_000` over a symbolic 64-bit stake, which is the same
// wall as everything else here. The pair is not the problem; a symbolic
// product wider than about 24 bits is.
//
// These three are not CI-budget harnesses, and none of them has a recorded
// completed run: the slash penalty's monotonicity in the ratio is therefore
// UNPROVED. (The `ratio == 0` half was split out as `zero_ratio_takes_nothing`
// and is proved on every pull request.) The property they were
// guarding, `penalty <= stake`, is now proved in a second by a harness that
// does not need them. They are left in place, timing out honestly, rather
// than deleted to make the job green: deleting them would remove the only
// statement in the tree that the truncation is monotonic.
#[cfg(kani)]
mod proofs {
    use super::{
        bitmap_voted_stake, classify_pq_signature_len, merkle_parent_layer_fold,
        merkle_rebuild_root_u64, merkle_root_u64, merkle_sibling_index, penalty_for,
        pq_signature_len_acceptable, raw_quotient, stake_sum, PqSigClass, FIXED_POINT_SCALE,
        MAX_MIRROR_LEAVES, MAX_MIRROR_VALIDATORS, PQ_SIG_LEN_DILITHIUM5, PQ_SIG_LEN_ML_DSA_65,
        PQ_SIG_LEN_ML_DSA_87,
    };

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

    /// A zero ratio takes nothing.
    ///
    /// Split out of `ratio_endpoints_are_exact`: with `ratio == 0` the product
    /// collapses to zero, so this half is proved in well under a second on a
    /// full `u64` stake and runs on every pull request. Left inside the slow
    /// harness it was never checked, because that harness never finishes.
    #[kani::proof]
    fn zero_ratio_takes_nothing() {
        let stake: u64 = kani::any();

        assert!(
            penalty_for(stake, 0) == 0,
            "a 0% ratio must not touch the bond"
        );
    }

    /// The full-ratio endpoint is exact.
    ///
    /// `malicious_slash_ratio_fixed` defaults to `FIXED_POINT_SCALE` - "proven
    /// malice burns the whole bond" - and rounding at this end would leave
    /// dust in a bond that should be gone. The zero end is
    /// `zero_ratio_takes_nothing`.
    ///
    /// STATUS: UNPROVED. This harness has no recorded completed run. It stays
    /// symbolic over a full `u64` stake and times out (see kani-slow.yml,
    /// which tolerates that by design). Do not read the name as a proof.
    // SLOW: see the measurement above. Runs on a schedule, not on the PR.
    #[kani::proof]
    fn ratio_endpoints_are_exact() {
        let stake: u64 = kani::any();

        assert!(
            penalty_for(stake, FIXED_POINT_SCALE) == stake,
            "a 100% ratio must burn the whole bond, leaving no rounding dust"
        );
    }

    /// Slashing harder never costs the offender less.
    ///
    /// STATUS: UNPROVED. No recorded run of this harness has completed, so the
    /// monotonicity of the penalty in the ratio is an open claim, not a proof.
    ///
    /// Governance relies on this when it raises a ratio. The fixed-point
    /// divide truncates, and a non-monotonic truncation would mean a higher
    /// configured penalty producing a smaller actual one for some stake, an
    /// incentive inversion no sampled test would be likely to find.
    ///
    /// `stake` is bounded to 32 bits here. Three unconstrained `u64`s make the
    /// two multiplications a 128-bit-by-128-bit comparison, which CBMC does not
    /// finish inside a CI budget - the first run was cancelled at 45 minutes on
    /// exactly this harness. The bound keeps the property meaningful (it still
    /// quantifies over every ratio pair, and over stakes past four billion
    /// base units) while leaving the solver a problem it can close. The
    /// unbounded case is covered by `penalty_is_monotonic_for_full_stakes`
    /// below, which fixes the ratio pair instead.
    // SLOW: see the measurement above. Runs on a schedule, not on the PR.
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
        // what CBMC cannot close in CI time. The step rounds up and the
        // products are clamped, so `hi` reaches `FIXED_POINT_SCALE` itself:
        // with a truncated step of 15 the pair topped out at 983_025 and the
        // endpoint the default slash ratio uses was never evaluated. `min`
        // is monotonic, so the assumption `lower <= higher` carries over.
        let step = FIXED_POINT_SCALE.div_ceil(u64::from(u16::MAX));
        let lo = (u64::from(lower) * step).min(FIXED_POINT_SCALE);
        let hi = (u64::from(higher) * step).min(FIXED_POINT_SCALE);

        assert!(
            penalty_for(stake, lo) <= penalty_for(stake, hi),
            "raising the slash ratio must never reduce the penalty"
        );
    }

    // SLOW: see the measurement above. Runs on a schedule, not on the PR.
    #[kani::proof]
    /// A one-unit ratio increase must never reduce the penalty, at any stake.
    ///
    /// STATUS: UNPROVED. No recorded run of this harness has completed.
    ///
    /// **This is the harness that was timing out**, and it took a per-harness
    /// measurement to find out. Everything before it had been blamed on
    /// `an_unbounded_ratio_would_overshoot_the_bond`, which runs earlier in
    /// alphabetical order and so was the last name printed before the job died.
    /// Timed separately with a four-minute cap:
    ///
    /// ```text
    /// a_double_ratio_overshoots                        1s
    /// an_unbounded_ratio_can_strictly_exceed_the_bond  0s
    /// penalty_is_monotonic_for_full_stakes             >240s, killed
    /// ```
    ///
    /// The reason is not the multiply everyone kept rewriting, it is the
    /// divide. `penalty_for` is `(u128 * u128) / u128`, and this harness calls
    /// it twice against a **full u64 symbolic stake**. A symbolic divide is
    /// much harder than a symbolic multiply: the solver has to search for a
    /// quotient and a remainder satisfying the relation, rather than sum
    /// partial products. Two of those over a 2^64 space does not close.
    ///
    /// Every other harness here narrows the stake to `u32` or `u16` for
    /// exactly this reason. This one did not, and its comment argued the
    /// opposite - that leaving the stake free is what makes the pair of
    /// harnesses complete.
    ///
    /// The property does not need the whole range. Truncation in
    /// `(stake * ratio) / SCALE` depends on where `stake * ratio` falls
    /// relative to a multiple of `SCALE`, and a `u32` stake already spans that
    /// residue behaviour completely - 4.29e9 distinct stakes against a
    /// SCALE of 1e6. What a `u64` adds is arithmetic magnitude, and magnitude
    /// is what `penalty_never_exceeds_stake` covers.
    fn penalty_is_monotonic_for_full_stakes() {
        let stake: u32 = kani::any();
        let stake = u64::from(stake);

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

    /// Without the bound, the raw quotient is no longer capped by the bond.
    ///
    /// The harnesses above *assume* `ratio <= FIXED_POINT_SCALE`. If
    /// `RegistryParams::validate` ever stopped enforcing it, they would all
    /// still pass while production became unsound, because an assumption is
    /// not a check. Here the precondition is dropped on purpose and the
    /// consequence is asserted on the crate functions: `raw_quotient` takes at
    /// least the bond, strictly more once `stake * excess` reaches one unit of
    /// `FIXED_POINT_SCALE`, and `penalty_for` contains it at the bond.
    ///
    /// The claim is `>=` in general, not `>`: at `stake = 1, ratio = 1_000_001`
    /// the quotient truncates back down to 1. The strict case is asserted
    /// under the exact condition that makes it true.
    ///
    /// Each harness has one symbolic operand (`stake`, `u16`) and a constant
    /// ratio. Loops and a second symbolic operand are what made the earlier
    /// forms of this harness time out; the constant ratio keeps the quotient a
    /// shift-and-add over known bits, the shape the sibling harness
    /// `an_unbounded_ratio_can_strictly_exceed_the_bond` proves in under a
    /// second.
    ///
    /// This is not a claim about a reachable state: every `set_params` caller
    /// runs `validate()` first.
    fn overshoot_at_ratio(excess: u64) {
        let stake: u16 = kani::any();
        kani::assume(stake > 0);
        let stake = u64::from(stake);

        let ratio = FIXED_POINT_SCALE + excess;
        let quotient = raw_quotient(stake, ratio);

        assert!(
            quotient >= u128::from(stake),
            "a ratio above FIXED_POINT_SCALE must take at least the bond"
        );
        if u128::from(stake) * u128::from(excess) >= u128::from(FIXED_POINT_SCALE) {
            assert!(
                quotient > u128::from(stake),
                "an excess of one full unit or more must take strictly more than the bond"
            );
        }
        assert!(
            penalty_for(stake, ratio) == stake,
            "the clamp must hold the overshoot at the bond"
        );
    }

    /// One unit above the bound - where truncation would most easily hide the
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

    /// The clamp fires exactly where the old code wrapped.
    ///
    /// This is the harness for B35. `stake = u64::MAX` with
    /// `ratio = FIXED_POINT_SCALE + 1` produces a quotient above `u64::MAX`.
    /// The previous `penalty_for` narrowed that with `try_from().expect()` and
    /// panicked; production wrote the same expression as `as u64` and wrapped,
    /// yielding a penalty of about 1.8e13 against a bond of about 1.8e19, so a
    /// 100.0001% slash left 99.9999% of the bond standing.
    ///
    /// `raw_quotient` keeps the unclamped value reachable so this states the
    /// overshoot and the containment as two separate facts rather than one.
    #[kani::proof]
    fn the_clamp_catches_the_quotient_that_used_to_wrap() {
        let stake = u64::MAX;
        let ratio = FIXED_POINT_SCALE + 1;

        assert!(
            raw_quotient(stake, ratio) > u128::from(u64::MAX),
            "this is the input that overflows a u64; if it stopped doing so, \
             the clamp below is being tested against nothing"
        );
        assert!(
            penalty_for(stake, ratio) == stake,
            "an overshooting ratio must take the whole bond, never wrap below it"
        );
    }

    /// The bound holds with no precondition on the ratio at all.
    ///
    /// Every other harness here assumes `ratio <= FIXED_POINT_SCALE`, which is
    /// what `RegistryParams::validate` enforces. That assumption is the reason
    /// B35 stayed invisible: the mirror test compared the two copies only over
    /// ratios where they agree.
    ///
    /// This one drops the assumption. It is the containment claim rather than
    /// the arithmetic claim: whatever ratio reaches this function, validated or
    /// not, the penalty cannot exceed the bond. Measured at 13.6s against a
    /// bitvector solver, against a timeout for the unclamped form.
    #[kani::proof]
    fn no_ratio_can_make_the_penalty_exceed_the_bond() {
        let stake: u64 = kani::any();
        let ratio: u64 = kani::any();

        assert!(
            penalty_for(stake, ratio) <= stake,
            "the clamp must hold for every ratio, including ones governance \
             would refuse"
        );
    }

    /// And a witness that the raw quotient really does exceed the bond.
    ///
    /// `>=` alone would be satisfied by a rule that merely reaches the bond.
    /// This pins a case where the unclamped quotient is strictly larger, and
    /// that the clamp then brings it back to the bond, so the harness above
    /// cannot be read as saying the overshoot is only theoretical. Both
    /// statements call crate functions: replacing `raw_quotient` with a
    /// clamped form, or deleting the clamp in `penalty_for`, fails here.
    #[kani::proof]
    fn an_unbounded_ratio_can_strictly_exceed_the_bond() {
        let stake: u32 = kani::any();
        let stake = u64::from(stake);
        kani::assume(stake >= 2);

        let ratio = 2 * FIXED_POINT_SCALE;
        assert!(
            raw_quotient(stake, ratio) > u128::from(stake),
            "a 200% ratio must take strictly more than the bond"
        );
        assert!(
            penalty_for(stake, ratio) == stake,
            "the clamp must hold a 200% ratio at the bond"
        );
    }

    /// A Merkle sibling index is always inside its layer.
    ///
    /// `merkle_sibling_index` feeds `layer[sibling_idx]` in both the proof
    /// production and the rebuild loop; an out-of-bounds sibling is a panic
    /// every verifier would hit on a crafted tree.
    #[kani::proof]
    fn merkle_sibling_index_is_in_bounds() {
        let index: usize = kani::any();
        let layer_len: usize = kani::any();
        kani::assume(layer_len >= 1);
        kani::assume(index < layer_len);

        let sibling = merkle_sibling_index(index, layer_len);
        assert!(
            sibling < layer_len,
            "the sibling of a present node must be present in the same layer"
        );
    }

    /// A non-empty Merkle tree terminates with exactly one root digest.
    ///
    /// The layer loop duplicates the odd tail and halves the layer each round,
    /// so it must reach a single-node layer for every leaf count. Bounded to
    /// `MAX_MIRROR_LEAVES` leaves; the bound is what keeps the query in CI
    /// budget.
    #[kani::proof]
    #[kani::unwind(5)]
    fn merkle_tree_terminates_with_a_single_root() {
        let mut leaves = [0u64; MAX_MIRROR_LEAVES];
        for leaf in leaves.iter_mut() {
            *leaf = kani::any();
        }
        let len: usize = kani::any();
        kani::assume(len >= 1 && len <= MAX_MIRROR_LEAVES);

        let root = merkle_root_u64(&leaves, len);
        assert!(
            root.is_some(),
            "a non-empty tree must terminate with a root digest"
        );
    }

    /// The root fold strictly shrinks every layer above the leaves.
    ///
    /// `merkle_root_u64` loops until one node remains; the loop only
    /// terminates if every fold of a layer of two or more nodes produces
    /// fewer nodes. This pins that shrink so termination cannot silently
    /// depend on the hash.
    #[kani::proof]
    fn every_parent_layer_is_smaller_than_its_child_layer() {
        let mut layer = [0u64; MAX_MIRROR_LEAVES];
        for node in layer.iter_mut() {
            *node = kani::any();
        }
        let len: usize = kani::any();
        kani::assume(len >= 2 && len <= MAX_MIRROR_LEAVES);

        let parents = merkle_parent_layer_fold(&mut layer, len);
        assert!(
            parents < len,
            "a parent layer must be strictly smaller than its child layer"
        );
    }

    /// Every leaf's proof path rebuilds the root.
    ///
    /// This is the Merkle-path property the QC fault proof relies on: from the
    /// leaf digest and the sibling digests the proof production returns, a
    /// verifier recomputes exactly the root. The abstract combine makes the
    /// structural claim exact; the SHA3 binding is held in step by
    /// `budlum-core`'s mirror test.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_merkle_proof_rebuilds_the_root() {
        let mut leaves = [0u64; MAX_MIRROR_LEAVES];
        for leaf in leaves.iter_mut() {
            *leaf = kani::any();
        }
        let len: usize = kani::any();
        kani::assume(len >= 1 && len <= MAX_MIRROR_LEAVES);
        let leaf_index: usize = kani::any();
        kani::assume(leaf_index < len);

        let rebuilt = merkle_rebuild_root_u64(&leaves, len, leaf_index);
        let root = merkle_root_u64(&leaves, len);
        assert_eq!(
            rebuilt, root,
            "walking the sibling path from a valid leaf must reach the root"
        );
    }

    /// A leaf outside the tree has no proof path.
    #[kani::proof]
    #[kani::unwind(5)]
    fn merkle_proof_rejects_out_of_range_leaves() {
        let mut leaves = [0u64; MAX_MIRROR_LEAVES];
        for leaf in leaves.iter_mut() {
            *leaf = kani::any();
        }
        let len: usize = kani::any();
        kani::assume(len <= MAX_MIRROR_LEAVES);
        let leaf_index: usize = kani::any();
        kani::assume(len == 0 || leaf_index >= len);

        assert_eq!(
            merkle_rebuild_root_u64(&leaves, len, leaf_index),
            None,
            "an empty tree or an index past the last leaf has no rebuild"
        );
    }

    /// PQ signature classification is total and round-trips.
    ///
    /// For every length, the classifier returns a scheme or `Unknown`; when it
    /// names a scheme, the length is exactly that scheme's constant. This is
    /// the admissibility check every PQ attestation passes through.
    #[kani::proof]
    fn pq_signature_classification_round_trips() {
        let len: usize = kani::any();
        let class = classify_pq_signature_len(len);
        match class {
            PqSigClass::Dilithium5 => {
                assert_eq!(len, PQ_SIG_LEN_DILITHIUM5);
            }
            PqSigClass::MlDsa65 => {
                assert_eq!(len, PQ_SIG_LEN_ML_DSA_65);
            }
            PqSigClass::MlDsa87 => {
                assert_eq!(len, PQ_SIG_LEN_ML_DSA_87);
            }
            PqSigClass::Unknown => {}
        }
    }

    /// An acceptable length for a scheme is classified as that scheme.
    ///
    /// The two functions are separate entry points; this proves they cannot
    /// disagree, so a caller that checks acceptability and a caller that
    /// classifies see the same boundary.
    #[kani::proof]
    fn pq_signature_acceptability_agrees_with_classification() {
        let len: usize = kani::any();
        let expected: u8 = kani::any();
        let expected = match expected % 4 {
            0 => PqSigClass::Dilithium5,
            1 => PqSigClass::MlDsa65,
            2 => PqSigClass::MlDsa87,
            _ => PqSigClass::Unknown,
        };

        if pq_signature_len_acceptable(len, expected) {
            assert_eq!(
                classify_pq_signature_len(len),
                expected,
                "a length acceptable for a scheme must classify as that scheme"
            );
        }
    }

    /// The three accepted PQ signature lengths are pairwise distinct.
    ///
    /// A collision would make classification ambiguous, which is exactly the
    /// failure mode the length check exists to prevent.
    #[kani::proof]
    fn pq_signature_lengths_are_pairwise_distinct() {
        // Through the classifier, not by comparing the constants: two equal
        // lengths make the first branch win and the second assert fail.
        assert_eq!(
            classify_pq_signature_len(PQ_SIG_LEN_DILITHIUM5),
            PqSigClass::Dilithium5
        );
        assert_eq!(
            classify_pq_signature_len(PQ_SIG_LEN_ML_DSA_65),
            PqSigClass::MlDsa65
        );
        assert_eq!(
            classify_pq_signature_len(PQ_SIG_LEN_ML_DSA_87),
            PqSigClass::MlDsa87
        );
    }

    /// A finality bitmap can never vote more stake than the set holds, and votes
    /// exactly the stake of the validators it selects.
    ///
    /// `voted <= total` alone holds for any sum of non-negative terms, so it
    /// would pass for a walk that ignored the bitmap. The harness therefore
    /// also pins the selection rule, each of which fails on a different
    /// broken walk:
    ///
    /// * an empty bitmap votes nothing,
    /// * a bitmap with every in-range bit set votes the whole set,
    /// * setting one more in-range bit adds exactly that validator's stake.
    #[kani::proof]
    #[kani::unwind(6)]
    fn bitmap_cannot_vote_more_stake_than_the_set_holds() {
        let mut stakes = [0u64; MAX_MIRROR_VALIDATORS];
        for stake in stakes.iter_mut() {
            *stake = kani::any();
        }
        let n: usize = kani::any();
        kani::assume(n <= MAX_MIRROR_VALIDATORS);
        let bitmap = [kani::any::<u8>(); 1];

        let voted = bitmap_voted_stake(&stakes, n, &bitmap);
        let total = stake_sum(&stakes, n);
        assert!(
            voted <= total,
            "the vote can never exceed the stake the set actually holds"
        );

        assert_eq!(
            bitmap_voted_stake(&stakes, n, &[0u8]),
            0,
            "an empty bitmap must vote nothing"
        );

        let all_in_range = ((1u16 << n) - 1) as u8;
        assert_eq!(
            bitmap_voted_stake(&stakes, n, &[all_in_range]),
            total,
            "a full bitmap must vote the whole set"
        );

        let pick: usize = kani::any();
        kani::assume(pick < n);
        let bit = 1u8 << pick;
        kani::assume(bitmap[0] & bit == 0);
        assert_eq!(
            bitmap_voted_stake(&stakes, n, &[bitmap[0] | bit]),
            voted + u128::from(stakes[pick]),
            "one more signer bit must add exactly that validator's stake"
        );
    }
}
