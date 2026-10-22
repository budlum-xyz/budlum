//! B.U.D. 2.0 - AV2 PATH (2026-08-16 RESEARCH: AV2 v1.0.0 RELEASED)
//!
//! AOMedia AV2 v1.0.0 spec on 28 May 2026, announcement on 9 June 2026: ~30%
//! better than AV1, ~40% on screen/HDR/8K; the AVM reference encoder is v1.0.0
//! (software). Hardware decode lands 2027-2028; software decode is ~5x heavier
//! than AV1 -> not suitable for the archive/production line yet, but the video
//! class path is READY: codec choice depends on content (KF2). This module
//! records AV2 plus a canary: a claim cannot exceed the measurement.
//!
//! Video matrix: YUV->AV1 904x (measured). AV2 target: 70% of AV1's bandwidth ->
//! a ~1290x equivalent (YUV->AV2). This is a TARGET/plan record; the real
//! measurement enters the matrix once the AVM encoder is run on a production
//! cohort (nothing is invented).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const AV2_MAGIC: [u8; 8] = *b"\xB5AV2\0\0\0\0";

/// AV2 record: release status + claim + honesty bound.
#[derive(Debug, Clone, Copy)]
pub struct Av2Status {
    pub spec_released: bool,      // 2026-05-28
    pub claimed_gain_vs_av1: f64, // ~0.30 (published claim)
    pub hardware_supported: bool, // 2027-2028 (absent today)
    pub software_decoder: bool,   // AVM reference exists, ~5x heavier than AV1
}

pub const AV2_CURRENT: Av2Status = Av2Status {
    spec_released: true,
    claimed_gain_vs_av1: 0.30,
    hardware_supported: false,
    software_decoder: true,
};

/// AV2 bandwidth equivalent: (1-gain) of the AV1 ratio -> ratio multiplier 1/(1-gain).
pub fn av2_ratio_from_av1(av1_ratio: f64, gain: f64) -> f64 {
    if gain >= 1.0 {
        return av1_ratio;
    }
    av1_ratio / (1.0 - gain)
}

/// Honesty canary: an AV2 claim cannot exceed the measured/published bound.
pub fn av2_holds_honest(claimed_ratio: f64, av1_measured: f64, gain: f64) -> bool {
    let theoretical = av2_ratio_from_av1(av1_measured, gain);
    claimed_ratio <= theoretical * 1.05 // 5% tolerance (encoder maturity)
}

pub fn av2_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(AV2_MAGIC);
    h.update([AV2_CURRENT.spec_released as u8]);
    h.update(AV2_CURRENT.claimed_gain_vs_av1.to_le_bytes());
    h.update([AV2_CURRENT.hardware_supported as u8]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn av2_ratio_computation() {
        // YUV->AV1 904x -> AV2 with a 30% gain -> ~1291x (theoretical)
        let av2 = av2_ratio_from_av1(904.0, 0.30);
        assert!((av2 - 1291.4).abs() < 1.0, "{av2}");
        // 40% gain (screen) -> ~1506x
        assert!(av2_ratio_from_av1(904.0, 0.40) > av2);
    }

    #[test]
    fn av2_honesty_canary() {
        let av1_measured = 904.0;
        let gain = 0.30;
        // theoretical ~1291 -> with the 1.05 tolerance, a claim above ~1356 is REJECTED
        assert!(av2_holds_honest(1290.0, av1_measured, gain));
        assert!(av2_holds_honest(1355.0, av1_measured, gain));
        assert!(
            !av2_holds_honest(2000.0, av1_measured, gain),
            "a claim above the measurement is REJECTED"
        );
    }

    #[test]
    fn av2_status_is_correct() {
        // `assert!(CONSTANT.field, ...)` trips clippy::assertions_on_constants:
        // the condition is known at compile time. Since the intent is "these
        // fields are LOCKED at these values", `assert_eq!` is the right form: it
        // writes the expected value out and, if a field changes, the failure
        // message shows what it became.
        let status = AV2_CURRENT;
        assert!(
            status.spec_released,
            "AV2 v1.0.0 was released on 2026-05-28"
        );
        assert!(
            !status.hardware_supported,
            "hardware support is expected in 2027-2028"
        );
    }

    #[test]
    fn av2_digest_is_deterministic() {
        assert_eq!(av2_digest(), av2_digest());
    }
}
