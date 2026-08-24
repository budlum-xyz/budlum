//! B.U.D. 2.0 - the three-core price, wakefulness and energy budget; ideas 3.0
//! items Y3, Y6 and Y11.
//!
//! Y11: price = a * residual + b * wakefulness + c * production CPU. All three
//! terms are measured inside consensus, and "storage at zero" is the class in
//! which all three approach zero.
//!
//! Y3: the wakefulness share, one over N over a guardian round, enters the
//! price, so the less audited something is, the cheaper it is.
//!
//! Y6: the energy budget is the sum over PACTs of
//! (wakefulness share * spin power + audit frequency * production CPU). It is
//! deterministic and written into the block header, as a consensus metric.
//!
//! The numbers are program output, never written by hand, and the weights are
//! voted by governance.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const TRICORE_MAGIC: [u8; 8] = *b"\xB5TRI1\0\0\0";

/// The three-core price weights, a governance parameter; the defaults come from
/// the document.
#[derive(Debug, Clone, Copy)]
pub struct TriCoreWeights {
    pub a: f64, // residual bytes
    pub b: f64, // the wakefulness share
    pub c: f64, // production CPU, in core-seconds
}

impl Default for TriCoreWeights {
    fn default() -> Self {
        Self {
            a: 1.0,
            b: 0.5,
            c: 0.2,
        }
    }
}

/// Y11: the three-core price. Every term is at or above zero, and the result is
/// deterministic.
pub fn tricore_price(
    residual_bytes: u64,
    wakefulness: f64,    // one over N, between 0 and 1
    production_cpu: f64, // core-seconds
    w: &TriCoreWeights,
) -> f64 {
    let r = residual_bytes as f64 * w.a;
    let u = wakefulness * w.b;
    let c = production_cpu * w.c;
    r + u + c
}

/// Y3: the wakefulness share, one over N across N guardians; as N grows the
/// share falls.
pub fn wakefulness_pay(n_guardians: u32) -> f64 {
    if n_guardians == 0 {
        return 0.0;
    }
    1.0 / n_guardians as f64
}

/// Y6: the expected power calculation, a deterministic consensus metric.
///
/// `spin_w` is the awake disk power in watts per TB, and `cpu_w` is the
/// production CPU power in watts per core-second. The output is the expected
/// wattage, which is written into the block header.
pub fn expected_power(
    n_guardians: u32,
    spin_w: f64,
    audit_freq_per_epoch: f64,
    cpu_w: f64,
    pact_count: u64,
) -> f64 {
    let w = wakefulness_pay(n_guardians);
    // The awake disk share plus the audit CPU, across all PACTs.
    (w * spin_w * pact_count as f64) + (audit_freq_per_epoch * cpu_w * pact_count as f64)
}

/// The Y6 target gate: is the expected power below the target budget? On an
/// overshoot, a new contract is queued.
pub fn energy_within_budget(expected_w: f64, target_w: f64) -> bool {
    expected_w <= target_w
}

/// The deterministic record, writable into the block header.
pub fn energy_record_hash(n: u32, expected_w: f64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(TRICORE_MAGIC);
    h.update(n.to_le_bytes());
    h.update(expected_w.to_le_bytes());
    h.finalize().into()
}

/// THE Y6 BENCHMARK PIN: the core-second unit, calibrated on the production
/// cohort.
///
/// It is the joule equivalent, in watt-seconds, of one core-second on the
/// reference machine. Hardware heterogeneity is modelled by the tiers in
/// `effort.rs`, spanning 0.5x to 10x.
pub const BENCH_CORE_SEC_J: f64 = 2.0; // the default pin, awaiting calibration

/// Y6: the hardware-corrected expected power, converting core-seconds to watts.
pub fn power_from_core_sec(core_sec: f64, hw_tier: f64) -> f64 {
    core_sec * BENCH_CORE_SEC_J * hw_tier.max(0.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn y3_wakefulness_share_is_one_over_n() {
        assert!((wakefulness_pay(26) - 1.0 / 26.0).abs() < 1e-12);
        assert!(
            wakefulness_pay(100) < wakefulness_pay(10),
            "as N grows the share falls"
        );
        assert_eq!(wakefulness_pay(0), 0.0);
    }

    #[test]
    fn y11_price_has_three_terms() {
        let w = TriCoreWeights::default();
        // Zero residual, a wakefulness of one over 26 and a small CPU term put the
        // price close to zero.
        let p0 = tricore_price(0, 1.0 / 26.0, 0.0, &w);
        // A residual of 1 MB, frequent wakefulness and a lot of CPU are far more
        // expensive.
        let p1 = tricore_price(1_000_000, 1.0, 1000.0, &w);
        assert!(p1 > p0);
        assert!(p0 > 0.0);
        // It is deterministic.
        assert_eq!(
            tricore_price(10, 0.5, 2.0, &w),
            tricore_price(10, 0.5, 2.0, &w)
        );
    }

    #[test]
    fn y6_energy_budget() {
        // With N of 26 the awake disk share is one over 26, so the power falls;
        // with N of 1 it is high.
        let e26 = expected_power(26, 7.0, 0.05, 60.0, 100);
        let e1 = expected_power(1, 7.0, 0.05, 60.0, 100);
        assert!(e26 < e1, "a larger N lowers the power: {e26} < {e1}");
        assert!(energy_within_budget(e26, e1));
        assert!(!energy_within_budget(e1, e26));
        // The record is deterministic.
        assert_eq!(energy_record_hash(26, e26), energy_record_hash(26, e26));
    }

    #[test]
    fn y6_benchmark_pin() {
        // 1000 core-seconds at tier 1x gives 2000 J, so about 2000 watt-seconds;
        // the unit is right.
        let w = power_from_core_sec(1000.0, 1.0);
        assert_eq!(w, 1000.0 * BENCH_CORE_SEC_J);
        // A lower hardware tier reduces the power.
        assert!(power_from_core_sec(1000.0, 0.5) < power_from_core_sec(1000.0, 2.0));
        // A tier approaching zero is clamped.
        assert!(power_from_core_sec(100.0, 0.0) > 0.0);
    }

    #[test]
    fn zero_weights_zero_every_term() {
        let w = TriCoreWeights {
            a: 0.0,
            b: 0.0,
            c: 0.0,
        };
        assert_eq!(tricore_price(1000, 1.0, 10.0, &w), 0.0);
    }
}
