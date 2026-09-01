//! Runtime hardware-economics measurements - the operator-facing dashboard
//! side of multitiering-based residency.
//!
//! [`residency`](crate::residency) answers *where weights live*; this module
//! answers *what running them costs on this machine*. The two are the two halves
//! of the promise from the "hardware you own" rule: residency keeps a big model
//! running on a small device, and these measurements show what that buys and how
//! much it costs.
//!
//! Everything here is a pure, deterministic function of a plan and a sample,
//! so nothing on this side depends on a live engine: an operator can produce
//! an honest dashboard from a plan and a short measurement run. Tokens-per-
//! second and time-to-first-token are supplied as an
//! [`IntervalSample`]; the bytes are derived from the plan.
//!
//! # What is measured
//!
//! * **Tier bytes** - [`TierBytes`], the live footprint per storage tier.
//! * **Throughput & latency** - [`IntervalSample::tokens_per_second`] and
//!   [`IntervalSample::time_to_first_token_ms`].
//! * **Cost** - [`HardwareCostModel::cost_per_million_tokens_dollars`], which is
//!   the number that falls when residency moves routed weights onto owned disk:
//!   only the fast-memory bytes are rented, the rest are already yours.

use crate::residency::{ResidencyPlan, Tier};

/// The live byte footprint of a served model, broken out by tier.
///
/// This is what the dashboard shows as "how much of my rented fast memory is
/// actually used", and therefore how much of the served model had to be rented
/// at all. Bytes on [`Tier::Disk`] are already on hardware the operator owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierBytes {
    pub accelerator: u64,
    pub system: u64,
    pub disk: u64,
}

impl TierBytes {
    /// Measure the tier usage of a residency plan.
    #[must_use]
    pub fn from_plan(plan: &ResidencyPlan) -> Self {
        Self {
            accelerator: plan.bytes_in(Tier::Accelerator),
            system: plan.bytes_in(Tier::System),
            disk: plan.bytes_in(Tier::Disk),
        }
    }

    /// The complete footprint across all tiers.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.accelerator
            .saturating_add(self.system)
            .saturating_add(self.disk)
    }

    /// Bytes that had to be rented (accelerator + host) rather than read from
    /// owned disk.
    #[must_use]
    pub const fn rented_fast_memory_bytes(self) -> u64 {
        self.accelerator.saturating_add(self.system)
    }

    /// The fraction of the model that lives in rented fast memory, in the
    /// range `0.0..=1.0`. This is the direct measure of how much multitiering
    /// multitiering bought: a plan that keeps the dense part in fast memory and
    /// pushes routed experts to owned disk reports a small number, and a plan
    /// that rents everything reports 1.0.
    ///
    /// Returns `None` for a zero-byte model, which is not a measurement.
    #[must_use]
    pub fn fast_memory_ratio(self) -> Option<f64> {
        let total = self.total();
        if total == 0 {
            return None;
        }
        let rented = self.rented_fast_memory_bytes();
        Some((rented as f64) / (total as f64))
    }
}

/// A short measurement run: the tokens produced and the wall time it took.
///
/// `elapsed_ms` can legitimately be zero only on a machine that produces no
/// tokens in the measured window, which the accessors treat as "not measured"
/// rather than as an infinite rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntervalSample {
    /// Tokens completed in the window.
    pub tokens: u64,
    /// Wall-clock time of the window.
    pub elapsed_ms: u64,
    /// Time from request arrival to the first token, the dashboard latency.
    pub first_token_ms: u64,
}

impl IntervalSample {
    /// The sustained throughput, as tokens per second.
    ///
    /// Returns `None` when the window produced no usable timing (zero elapsed),
    /// so the dashboard can show "pending" instead of a misleading infinity.
    #[must_use]
    pub fn tokens_per_second(&self) -> Option<f64> {
        if self.elapsed_ms == 0 {
            return None;
        }
        Some((self.tokens as f64) / (self.elapsed_ms as f64) * 1000.0)
    }

    /// The measured time-to-first-token in milliseconds.
    #[must_use]
    pub const fn time_to_first_token_ms(&self) -> u64 {
        self.first_token_ms
    }

    /// A sample is only believable as a measurement if it produced content.
    /// A sampling run that emitted nothing is reported as not measured.
    #[must_use]
    pub const fn produced(&self) -> bool {
        self.tokens > 0
    }
}

/// Per-GB-hour rental rates for the fast tiers, in dollars.
///
/// Rates are what an operator actually pays, and the whole point of
/// multitiering is that same operator also owns a disk that costs nothing to
/// keep weights resident on. `system` is the fallback for a machine whose
/// routed weights overflow the accelerator.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HardwareCostModel {
    /// US dollars per accelerator gigabyte-hour.
    pub dollar_per_accelerator_gb_hour: f64,
    /// US dollars per host-memory gigabyte-hour.
    pub dollar_per_system_gb_hour: f64,
}

impl HardwareCostModel {
    /// Service pricing: cost to serve one million tokens, in dollars, given
    /// the live footprint and the measured throughput.
    ///
    /// Only the rented fast memory is priced. Weights that the residency plan
    /// placed on disk are the operator's own, so they contribute no hourly
    /// cost (this is the amount multitiering multitiering saves: a model that
    /// fits entirely in rented accelerator memory costs more per token than the
    /// same model with routed experts staged from owned disk).
    ///
    /// Returns `None` when throughput is not yet measurable (zero tokens), so
    /// cost is never reported before there is a rate to divide by.
    #[must_use]
    pub fn cost_per_million_tokens_dollars(
        &self,
        tier: &TierBytes,
        tokens_per_second: f64,
    ) -> Option<f64> {
        if tokens_per_second <= 0.0 {
            return None;
        }
        let accel_gb = tier.accelerator as f64 / 1_000_000_000.0;
        let system_gb = tier.system as f64 / 1_000_000_000.0;
        let cost_per_hour =
            accel_gb * self.dollar_per_accelerator_gb_hour + system_gb * self.dollar_per_system_gb_hour;
        let tokens_per_hour = tokens_per_second * 3600.0;
        if tokens_per_hour <= 0.0 {
            return None;
        }
        Some(cost_per_hour / tokens_per_hour * 1_000_000.0)
    }
}

#[cfg(test)]
mod metric_tests {
    use super::*;
    use crate::residency::{Demand, DeviceBudget, SemanticProfile, WeightShard};

    fn id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn profile() -> SemanticProfile {
        SemanticProfile {
            weight_bits: 16,
            context_tokens: 4096,
            experts_per_token: 2,
        }
    }

    /// Accelerator 1500, system 1500: the dense part (1000) plus 2000 of
    /// routed experts all fit in fast memory, nothing on disk.
    fn rent_everything() -> (TierBytes, ResidencyPlan) {
        let budget = DeviceBudget {
            accelerator_bytes: 1500,
            system_bytes: 1500,
        };
        let mut shards = vec![WeightShard {
            content_id: id(0),
            bytes: 1000,
            demand: Demand::EveryToken,
        }];
        for n in 1..=4 {
            shards.push(WeightShard {
                content_id: id(n),
                bytes: 500,
                demand: Demand::WhenRouted,
            });
        }
        let plan = ResidencyPlan::plan(&shards, budget, profile()).unwrap();
        (TierBytes::from_plan(&plan), plan)
    }

    /// A small device whose routed experts land on owned disk.
    fn multitier() -> (TierBytes, ResidencyPlan) {
        let budget = DeviceBudget {
            accelerator_bytes: 0,
            system_bytes: 1200,
        };
        let mut shards = vec![WeightShard {
            content_id: id(0),
            bytes: 1000,
            demand: Demand::EveryToken,
        }];
        for n in 1..=4 {
            shards.push(WeightShard {
                content_id: id(n),
                bytes: 500,
                demand: Demand::WhenRouted,
            });
        }
        let plan = ResidencyPlan::plan(&shards, budget, profile()).unwrap();
        (TierBytes::from_plan(&plan), plan)
    }

    fn rates() -> HardwareCostModel {
        HardwareCostModel {
            dollar_per_accelerator_gb_hour: 12.0,
            dollar_per_system_gb_hour: 3.0,
        }
    }

    #[test]
    fn tier_bytes_reflect_the_plan() {
        let (tb, plan) = rent_everything();
        assert_eq!(tb.accelerator, plan.bytes_in(Tier::Accelerator));
        assert_eq!(tb.system, plan.bytes_in(Tier::System));
        assert_eq!(tb.disk, plan.bytes_in(Tier::Disk));
    }

    #[test]
    fn throughput_and_latency_come_from_the_sample() {
        let s = IntervalSample {
            tokens: 400,
            elapsed_ms: 2000,
            first_token_ms: 180,
        };
        assert_eq!(s.tokens_per_second(), Some(200.0));
        assert_eq!(s.time_to_first_token_ms(), 180);
        assert!(s.produced());
    }

    #[test]
    fn a_zero_elapsed_sample_reports_not_measured_not_infinity() {
        let s = IntervalSample {
            tokens: 0,
            elapsed_ms: 0,
            first_token_ms: 0,
        };
        assert_eq!(s.tokens_per_second(), None);
        assert!(!s.produced());
    }

    #[test]
    fn multitiering_cuts_the_cost_per_million_tokens() {
        let (rent_all, _) = rent_everything();
        let (tiered, _) = multitier();

        // Both served at the same throughput; only the memory residency differs.
        let tps = 100.0;
        let costly = rates()
            .cost_per_million_tokens_dollars(&rent_all, tps)
            .unwrap();
        let cheap = rates()
            .cost_per_million_tokens_dollars(&tiered, tps)
            .unwrap();

        // The multitiered plan rents only host memory for a few GB and keeps
        // routed experts on owned disk, so it is materially cheaper than
        // renting the whole footprint in fast memory.
        assert!(
            cheap < costly,
            "multitiering must lower cost: rent-all {costly} vs tiered {cheap}"
        );
        assert!(cheap >= 0.0);
    }

    #[test]
    fn the_fast_memory_ratio_measures_how_much_was_rented() {
        let (rent_all, _) = rent_everything();
        let (tiered, _) = multitier();
        assert_eq!(rent_all.fast_memory_ratio(), Some(1.0));
        assert!(tiered.fast_memory_ratio().unwrap() < 1.0);
        assert!(tiered.fast_memory_ratio().unwrap() > 0.0);
    }

    #[test]
    fn cost_is_not_reported_before_there_is_throughput() {
        let (tb, _) = rent_everything();
        assert_eq!(rates().cost_per_million_tokens_dollars(&tb, 0.0), None);
    }

    #[test]
    fn a_zero_byte_model_has_no_ratio() {
        let tb = TierBytes {
            accelerator: 0,
            system: 0,
            disk: 0,
        };
        assert_eq!(tb.fast_memory_ratio(), None);
        assert_eq!(tb.total(), 0);
    }
}
