//! AI inference layer effort tiers - how hard an operator is asked to work on a request.
//!
//! An AI inference layer operator answers with the machine it actually owns. A small CPU can
//! serve a shallow, fast answer; a large GPU rig can serve a deep one. The tier
//! is the requester's declared depth, expressed as a multiplier over the
//! baseline `1.0x`:
//!
//! | Tier | Meaning |
//! |---|---|
//! | `0.5x` | fastest, shallowest - cheap and rough, useful for previews |
//! | `1.0x` | baseline - the reference amount of work |
//! | `1.1x` … `9.9x` | progressively deeper |
//! | `10.0x` | deepest - needs dedicated hardware |
//!
//! Two rules make the tier meaningful rather than decorative. Exactly one of
//! them is enforced by the tree today, and the split is stated here rather
//! than left for a reader to discover:
//!
//! 1. **The tier is part of the request identity. Enforced.**
//!    `AiInferenceRequest::effort` is hashed into `calculate_id` under
//!    `BDLM_AI_REQUEST_ID_V2`, `request_id` is inside the transaction signing
//!    preimage, and `AiRegistry::submit_request` refuses a request whose id
//!    does not derive from the fields it carries. So an operator cannot accept
//!    a `5.0x` request, answer it with `0.5x` work, and claim the higher fee:
//!    the tier is inside what the requester signed, and rewriting it in flight
//!    invalidates the id.
//!
//! 2. **Declared capability gates eligibility. Enforced.**
//!    [`tier_is_servable`] expresses the rule: an operator advertises the
//!    highest tier its hardware can serve, and a request above every declared
//!    ceiling must fail closed rather than be silently downgraded to a cheaper
//!    answer.
//!
//!    The declaration lives in `AiRegistry::verifier_effort_ceilings`
//!    (`declare_effort_ceiling`), and an operator that never declares defaults
//!    to `DEFAULT_OPERATOR_CEILING` - baseline `1.0x` - so a machine that has
//!    said nothing is never treated as eligible for a deeper request.
//!    `AiRegistry::submit_request` calls `unservable_reason(request.effort)`,
//!    which applies [`tier_is_servable`] over the *authorized* operators'
//!    ceilings and refuses a request above every one of them.
//!
//!    Two bounds keep the gate sound rather than decorative. Only an operator
//!    that is authorized (staked past the threshold, and whitelisted when
//!    whitelist mode is on) may declare, so a zero-stake address cannot pollute
//!    the ceiling set. And when there is no authorized operator at all the
//!    request is *not* refused: operators may join after a request arrives, so
//!    that case is a liveness problem, not an admission one, and what rule 2
//!    guards is only the case where operators exist and none of them can reach
//!    the requested depth.
//!
//! Deliberately *not* decided here: the fee multiplier. AI inference layer costs are paid to
//! validators the same way consensus rewards are, and the current repository
//! ratios stand. This module exposes `EffortTier::as_ratio()` so a future fee
//! schedule can scale against it without this type having to know the price.

use serde::Serialize;

/// Fixed-point scale for effort tiers: the value is stored as tenths.
///
/// `1.0x` is stored as `10`, `0.5x` as `5`, `10.0x` as `100`. Integer storage
/// keeps the value consensus-safe - no float ever reaches a hash or a
/// comparison.
pub const TIER_SCALE: u16 = 10;

/// Shallowest permitted tier (`0.5x`).
pub const TIER_MIN_TENTHS: u16 = 5;

/// Baseline tier (`1.0x`).
pub const TIER_BASELINE_TENTHS: u16 = 10;

/// Deepest permitted tier (`10.0x`).
pub const TIER_MAX_TENTHS: u16 = 100;

/// How hard an operator is asked to work, in tenths of the baseline.
///
/// Construct through [`EffortTier::from_tenths`] so the range is always
/// enforced; the inner value is public for serialization only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EffortTier(u16);

impl EffortTier {
    /// The `0.5x` floor - fast and rough.
    pub const FASTEST: EffortTier = EffortTier(TIER_MIN_TENTHS);
    /// The `1.0x` reference point.
    pub const BASELINE: EffortTier = EffortTier(TIER_BASELINE_TENTHS);
    /// The `10.0x` ceiling - dedicated hardware only.
    pub const DEEPEST: EffortTier = EffortTier(TIER_MAX_TENTHS);

    /// Build a tier from tenths of the baseline (`5` = 0.5x, `10` = 1.0x,
    /// `100` = 10.0x).
    ///
    /// Values outside `0.5x..=10.0x` are rejected rather than clamped: a
    /// request asking for `20x` is a mistake the caller should see, not a
    /// request that quietly becomes `10x`.
    pub fn from_tenths(tenths: u16) -> Result<Self, String> {
        if tenths < TIER_MIN_TENTHS {
            return Err(format!(
                "effort tier {}.{}x is below the {}.{}x floor",
                tenths / TIER_SCALE,
                tenths % TIER_SCALE,
                TIER_MIN_TENTHS / TIER_SCALE,
                TIER_MIN_TENTHS % TIER_SCALE
            ));
        }
        if tenths > TIER_MAX_TENTHS {
            return Err(format!(
                "effort tier {}.{}x exceeds the {}.{}x ceiling",
                tenths / TIER_SCALE,
                tenths % TIER_SCALE,
                TIER_MAX_TENTHS / TIER_SCALE,
                TIER_MAX_TENTHS % TIER_SCALE
            ));
        }
        Ok(EffortTier(tenths))
    }

    /// The raw tenths value, for hashing and storage.
    #[must_use]
    pub const fn tenths(&self) -> u16 {
        self.0
    }

    /// Canonical bytes for inclusion in a request hash.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; 2] {
        self.0.to_le_bytes()
    }

    /// The multiplier as a ratio of `(numerator, denominator)`.
    ///
    /// Returned as a fraction rather than a float so fee schedules and gas
    /// accounting stay exact. `2.5x` yields `(25, 10)`.
    #[must_use]
    pub const fn as_ratio(&self) -> (u32, u32) {
        (self.0 as u32, TIER_SCALE as u32)
    }

    /// Whether an operator advertising `ceiling` can serve this tier.
    #[must_use]
    pub const fn servable_by(&self, ceiling: EffortTier) -> bool {
        self.0 <= ceiling.0
    }
}

impl<'de> serde::Deserialize<'de> for EffortTier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // A JSON-RPC caller can submit any u16, so the derived Deserialize
        // would admit out-of-range tiers (0, 4, 65535) that from_tenths
        // rejects; those values then flow into request_id and the signature
        // unchecked. Deserialize through from_tenths so the 0.5x..=10.0x
        // invariant holds on every entry path (security review, MEDIUM,
        // CWE-20).
        let tenths = u16::deserialize(deserializer)?;
        Self::from_tenths(tenths).map_err(serde::de::Error::custom)
    }
}

impl Default for EffortTier {
    /// `1.0x` - a request that does not say otherwise gets baseline work.
    fn default() -> Self {
        EffortTier::BASELINE
    }
}

impl std::fmt::Display for EffortTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}x", self.0 / TIER_SCALE, self.0 % TIER_SCALE)
    }
}

/// Whether any registered operator can serve `tier`.
///
/// `ceilings` is what each eligible operator advertises. An empty iterator, or
/// one where every ceiling is below the request, means the request is
/// unservable - the caller must fail closed instead of downgrading.
pub fn tier_is_servable<I: IntoIterator<Item = EffortTier>>(tier: EffortTier, ceilings: I) -> bool {
    ceilings.into_iter().any(|c| tier.servable_by(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_is_one_x_and_is_the_default() {
        assert_eq!(EffortTier::default(), EffortTier::BASELINE);
        assert_eq!(EffortTier::BASELINE.to_string(), "1.0x");
        assert_eq!(EffortTier::BASELINE.as_ratio(), (10, 10));
    }

    #[test]
    fn the_documented_ladder_is_constructible() {
        // 0.5x, then every tenth from 1.0x to 10.0x.
        assert_eq!(EffortTier::from_tenths(5).unwrap().to_string(), "0.5x");
        for tenths in TIER_BASELINE_TENTHS..=TIER_MAX_TENTHS {
            let tier = EffortTier::from_tenths(tenths)
                .unwrap_or_else(|e| panic!("tier {tenths} tenths must be valid: {e}"));
            assert_eq!(tier.tenths(), tenths);
        }
        assert_eq!(EffortTier::from_tenths(11).unwrap().to_string(), "1.1x");
        assert_eq!(EffortTier::from_tenths(12).unwrap().to_string(), "1.2x");
        assert_eq!(EffortTier::DEEPEST.to_string(), "10.0x");
    }

    #[test]
    fn out_of_range_tiers_are_rejected_not_clamped() {
        assert!(EffortTier::from_tenths(0).is_err(), "0x must be rejected");
        assert!(
            EffortTier::from_tenths(4).is_err(),
            "0.4x is below the floor"
        );
        assert!(
            EffortTier::from_tenths(101).is_err(),
            "10.1x is above the ceiling"
        );
        assert!(
            EffortTier::from_tenths(u16::MAX).is_err(),
            "a huge tier must not wrap or clamp"
        );
    }

    #[test]
    fn ratio_is_exact_and_avoids_floats() {
        assert_eq!(EffortTier::from_tenths(25).unwrap().as_ratio(), (25, 10));
        assert_eq!(EffortTier::FASTEST.as_ratio(), (5, 10));
        assert_eq!(EffortTier::DEEPEST.as_ratio(), (100, 10));
    }

    #[test]
    fn an_operator_serves_only_up_to_its_ceiling() {
        let modest = EffortTier::from_tenths(20).unwrap(); // 2.0x rig
        assert!(EffortTier::BASELINE.servable_by(modest));
        assert!(EffortTier::from_tenths(20).unwrap().servable_by(modest));
        assert!(!EffortTier::from_tenths(21).unwrap().servable_by(modest));
        assert!(!EffortTier::DEEPEST.servable_by(modest));
    }

    /// The rule the operator asked for: without hardware for 10.0x, no
    /// verifier can run AI inference layer at that depth.
    #[test]
    fn ten_x_is_unservable_when_no_operator_has_the_hardware() {
        let fleet = vec![
            EffortTier::from_tenths(10).unwrap(),
            EffortTier::from_tenths(35).unwrap(),
            EffortTier::from_tenths(99).unwrap(), // 9.9x - still not enough
        ];
        assert!(
            !tier_is_servable(EffortTier::DEEPEST, fleet.clone()),
            "9.9x hardware must not be allowed to answer a 10.0x request"
        );
        assert!(tier_is_servable(
            EffortTier::from_tenths(99).unwrap(),
            fleet
        ));
    }

    #[test]
    fn an_empty_fleet_serves_nothing() {
        assert!(!tier_is_servable(EffortTier::BASELINE, Vec::new()));
        assert!(!tier_is_servable(EffortTier::FASTEST, Vec::new()));
    }

    #[test]
    fn tiers_order_by_depth() {
        assert!(EffortTier::FASTEST < EffortTier::BASELINE);
        assert!(EffortTier::BASELINE < EffortTier::DEEPEST);
        let mut ladder = vec![
            EffortTier::DEEPEST,
            EffortTier::FASTEST,
            EffortTier::BASELINE,
        ];
        ladder.sort();
        assert_eq!(
            ladder,
            vec![
                EffortTier::FASTEST,
                EffortTier::BASELINE,
                EffortTier::DEEPEST
            ]
        );
    }

    #[test]
    fn canonical_bytes_distinguish_adjacent_tiers() {
        // 1.1x and 1.2x must not hash the same - the tier is part of request
        // identity, so adjacent rungs have to be distinguishable.
        let a = EffortTier::from_tenths(11).unwrap();
        let b = EffortTier::from_tenths(12).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
