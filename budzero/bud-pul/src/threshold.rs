//! The Pul-Full threshold rule.
//!
//! The default retention of a normal node is Pul-Lite pruning. A Pul-Full aggregate is produced
//! only when it is worth it: its full size must stay below half of the witness bytes it would let
//! the archive drop. No claim depends on the rule, and the rule never turns a missing proof into
//! an accepted witness: it only decides whether the proof market is asked for an aggregate.

/// The rule's ratio as a fraction: `pul_full_bytes * DENOMINATOR < witness_bytes * NUMERATOR`
/// is `pul_full_bytes < 0.5 x witness_bytes`.
const NUMERATOR: u128 = 1;
const DENOMINATOR: u128 = 2;

/// The outcome of the rule for one batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// exposed for: the proof/VM crate's test-and-tooling surface — production readers land with the prover wiring wave.
pub enum PulDecision {
    /// Produce a Pul-Full aggregate for the batch.
    ProduceFull,
    /// Keep Pul-Lite pruning: the aggregate is too large for what it saves.
    KeepLite,
}

/// Applies `pul_full_bytes < 0.5 x witness_bytes`, in integers.
///
/// An empty witness set, or an aggregate of zero bytes (which no prover produces), keeps Pul-Lite: there is
/// nothing to save, or the figure cannot be trusted.
#[must_use]
pub fn decide(pul_full_bytes: u64, witness_bytes: u64) -> PulDecision {
    if pul_full_bytes == 0 || witness_bytes == 0 {
        return PulDecision::KeepLite;
    }
    if u128::from(pul_full_bytes) * DENOMINATOR < u128::from(witness_bytes) * NUMERATOR {
        PulDecision::ProduceFull
    } else {
        PulDecision::KeepLite
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_half_produces_the_aggregate() {
        assert_eq!(decide(49, 100), PulDecision::ProduceFull);
    }

    #[test]
    fn exactly_half_and_above_keep_lite() {
        assert_eq!(decide(50, 100), PulDecision::KeepLite);
        assert_eq!(decide(80, 100), PulDecision::KeepLite);
    }

    #[test]
    fn empty_inputs_keep_lite() {
        assert_eq!(decide(0, 100), PulDecision::KeepLite);
        assert_eq!(decide(10, 0), PulDecision::KeepLite);
    }

    #[test]
    fn no_overflow_at_the_top_of_the_range() {
        assert_eq!(decide(u64::MAX / 2, u64::MAX), PulDecision::ProduceFull);
        assert_eq!(decide(u64::MAX, u64::MAX), PulDecision::KeepLite);
    }
}
