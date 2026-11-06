//! B.U.D. 2.0 - AUTOMATIC ZSTD LEVEL, AND SKIP WHEN IT DOES NOT COMPRESS
//! (F133/F179).
//!
//! Remaining work: a smart zstd level. Try the fast level, and if the gain is
//! small (5 percent or less) or the time budget is spent, SKIP the compression
//! and save the CPU - the ZFS smart pattern.
//!
//! Honesty: the decision rests on a REAL measurement, never on a guess.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const AUTOZ_MAGIC: [u8; 8] = *b"\xB5AZST\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZstdDecision {
    Level(u8), // the chosen level
    Skip,      // it does not compress, so store it raw
}

/// The decision, taken from the result of the compression attempt.
///
/// `fast_ratio` is the ratio of the fast level (original over compressed), and
/// `time_budget_ms` says how much time is left. `skip_threshold` is the ratio
/// below which the answer is SKIP (the default is 1.05, a 5 percent gain).
pub fn decide(
    fast_ratio: f64,
    slow_ratio: f64,
    time_budget_ms_left: u64,
    skip_threshold: f64,
) -> ZstdDecision {
    if fast_ratio <= skip_threshold.max(1.0) {
        return ZstdDecision::Skip; // it does not compress
    }
    if time_budget_ms_left < 200 {
        // Time is short, so the fast level is enough (F190: a low level is
        // enough).
        return ZstdDecision::Level(3);
    }
    // Does the slow level give any extra gain?
    let gain = slow_ratio / fast_ratio.max(1e-9);
    if gain >= 1.10 {
        ZstdDecision::Level(19)
    } else if gain >= 1.03 {
        ZstdDecision::Level(9)
    } else {
        ZstdDecision::Level(3)
    }
}

pub fn autoz_digest(fast: f64, slow: f64, budget: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(AUTOZ_MAGIC);
    h.update(fast.to_le_bytes());
    h.update(slow.to_le_bytes());
    h.update(budget.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sikismazsa_gec() {
        assert!(matches!(
            decide(1.01, 1.02, 10_000, 1.05),
            ZstdDecision::Skip
        ));
    }

    #[test]
    fn tight_time_picks_a_fast_level() {
        assert!(matches!(decide(1.5, 3.0, 50, 1.05), ZstdDecision::Level(3)));
    }

    #[test]
    fn a_large_gain_picks_a_slow_level() {
        assert!(matches!(
            decide(1.5, 2.2, 10_000, 1.05),
            ZstdDecision::Level(19)
        ));
    }

    #[test]
    fn digest_deterministik() {
        assert_eq!(autoz_digest(1.5, 2.2, 100), autoz_digest(1.5, 2.2, 100));
    }
}
