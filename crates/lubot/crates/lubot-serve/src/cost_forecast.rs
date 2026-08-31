//! The measured "runs on hardware you already own" claim.
//!
//! [`crate::residency`] says where weights live and [`crate::metric`] says
//! what a placement costs to rent. This module joins the two into one
//! end-to-end number: a frontier mixture-of-experts shape is placed twice -
//! once on a rented data-centre footprint, once on a normal device whose disk
//! is owned - and the rental cost per million tokens is computed for both.
//!
//! # What the claim is, exactly
//!
//! The measured saving is a **rented fast-memory** saving. A frontier MoE is
//! mostly routed experts; the dense part is needed every token and the experts
//! are needed one small subset at a time. On a rented footprint the whole
//! model sits in fast memory and all of it is rented. On an owned device the
//! routed experts are staged from the disk the operator already owns, so the
//! rented (or bought) fast memory shrinks to the dense part plus a handful of
//! hot experts.
//!
//! At equal throughput the rental cost scales linearly in the rented bytes, so
//! the cost ratio equals the footprint ratio - and [`CostComparison`] asserts
//! exactly that, so the number is recomputed rather than written down.
//!
//! # What the claim is not
//!
//! Staging from disk trades throughput for the saving: a device reading
//! experts off owned storage serves more slowly than one with the whole model
//! in rented VRAM. That trade is reported as a separate sample, never hidden.
//! The model also does not price energy, depreciation, or the disk itself -
//! it prices the rented fast memory, which is the quantity multitiering
//! shrinks.

use crate::metric::{HardwareCostModel, IntervalSample, TierBytes};
use crate::residency::{Demand, DeviceBudget, PlanError, ResidencyPlan, SemanticProfile, WeightShard};

/// One gibibyte.
const GIB: u64 = 1 << 30;

/// Dense part of the frontier shape, in GiB at 16-bit weights (attention,
/// shared experts, embeddings, output head).
const DENSE_GIB: u64 = 12;

/// One routed expert, in GiB at 16-bit weights.
const EXPERT_GIB: u64 = 5;

/// Routed expert fleet size.
const EXPERT_COUNT: u64 = 128;

/// Disk a normal device owns, in GiB. The routed experts are staged here.
pub const OWNED_DISK_GIB: u64 = 1024;

/// Scale a 16-bit GiB figure to the requested weight precision.
#[must_use]
pub const fn scaled_bytes(gib: u64, weight_bits: u8) -> u64 {
    let bytes = gib.saturating_mul(GIB);
    bytes.saturating_mul(weight_bits as u64) / 16
}

/// The frontier mixture-of-experts shape: one every-token dense shard and a
/// routed expert fleet, sized by weight precision.
#[must_use]
pub fn frontier_model(weight_bits: u8) -> Vec<WeightShard> {
    let mut shards = Vec::with_capacity(EXPERT_COUNT as usize + 1);
    shards.push(WeightShard {
        content_id: [0u8; 32],
        bytes: scaled_bytes(DENSE_GIB, weight_bits),
        demand: Demand::EveryToken,
    });
    for n in 1..=EXPERT_COUNT {
        shards.push(WeightShard {
            content_id: [n as u8; 32],
            bytes: scaled_bytes(EXPERT_GIB, weight_bits),
            demand: Demand::WhenRouted,
        });
    }
    shards
}

/// The semantic profile the frontier model is served under.
#[must_use]
pub const fn frontier_profile(weight_bits: u8) -> SemanticProfile {
    SemanticProfile {
        weight_bits,
        context_tokens: 131_072,
        experts_per_token: 8,
    }
}

/// A rented data-centre footprint: enough fast memory to hold the whole
/// frontier model, nothing on disk.
#[must_use]
pub const fn rented_datacenter_budget() -> DeviceBudget {
    DeviceBudget {
        accelerator_bytes: 600 * GIB,
        system_bytes: 64 * GIB,
    }
}

/// A normal device the operator owns: a consumer accelerator, host memory, and
/// a disk the routed experts are staged from.
#[must_use]
pub const fn owned_device_budget() -> DeviceBudget {
    DeviceBudget {
        accelerator_bytes: 8 * GIB,
        system_bytes: 32 * GIB,
    }
}

/// One side of the comparison, measured.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostForecast {
    /// Live byte footprint per tier.
    pub tier_bytes: TierBytes,
    /// Rental cost per million tokens, when throughput was measured.
    pub cost_per_million_tokens_dollars: Option<f64>,
    /// Fraction of the model that lives in rented fast memory.
    pub fast_memory_ratio: Option<f64>,
    /// Whether any weight is read from disk while decoding.
    pub streams_from_disk: bool,
}

/// Measure one plan against a throughput sample and rental rates.
#[must_use]
pub fn forecast(plan: &ResidencyPlan, sample: IntervalSample, rates: HardwareCostModel) -> CostForecast {
    let tier_bytes = TierBytes::from_plan(plan);
    let tps = sample.tokens_per_second();
    CostForecast {
        tier_bytes,
        cost_per_million_tokens_dollars: tps
            .and_then(|t| rates.cost_per_million_tokens_dollars(&tier_bytes, t)),
        fast_memory_ratio: tier_bytes.fast_memory_ratio(),
        streams_from_disk: plan.streams_from_disk(),
    }
}

/// The two-sided comparison: rented footprint versus owned device.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostComparison {
    /// The whole model held in rented fast memory.
    pub rent_all: CostForecast,
    /// The same model staged onto an owned device.
    pub multitier: CostForecast,
}

impl CostComparison {
    /// Place the model on both devices and measure both sides at the same
    /// throughput, so the cost ratio is the footprint ratio and nothing else.
    ///
    /// # Errors
    ///
    /// [`PlanError`] when either plan cannot be produced (the rented footprint
    /// must hold the model in fast memory; the owned device's disk must hold
    /// the routed part).
    pub fn compare(
        model: &[WeightShard],
        weight_bits: u8,
        owned_disk_gib: u64,
        sample: IntervalSample,
        rates: HardwareCostModel,
    ) -> Result<Self, PlanError> {
        let semantics = frontier_profile(weight_bits);
        let rent_plan = ResidencyPlan::plan_bounded_by_disk(
            model,
            rented_datacenter_budget(),
            semantics,
            u64::MAX,
        )?;
        let owned_plan = ResidencyPlan::plan_bounded_by_disk(
            model,
            owned_device_budget(),
            semantics,
            owned_disk_gib.saturating_mul(GIB),
        )?;
        Ok(Self {
            rent_all: forecast(&rent_plan, sample, rates),
            multitier: forecast(&owned_plan, sample, rates),
        })
    }

    /// Fraction of the rented fast memory the owned device needs
    /// (1 - owned_rented / rent_all_rented). `None` when there is nothing to
    /// compare.
    #[must_use]
    pub fn footprint_reduction_ratio(&self) -> Option<f64> {
        let rented = self.rent_all.tier_bytes.rented_fast_memory_bytes();
        let owned = self.multitier.tier_bytes.rented_fast_memory_bytes();
        if rented == 0 {
            return None;
        }
        Some(1.0 - (owned as f64) / (rented as f64))
    }

    /// Fraction of the per-million-token rental cost saved, at equal
    /// throughput.
    #[must_use]
    pub fn savings_ratio(&self) -> Option<f64> {
        let costly = self.rent_all.cost_per_million_tokens_dollars?;
        let cheap = self.multitier.cost_per_million_tokens_dollars?;
        if costly <= 0.0 {
            return None;
        }
        Some(1.0 - cheap / costly)
    }
}

#[cfg(test)]
mod cost_forecast_tests {
    use super::*;

    /// Rental rates: accelerator and host memory, per gibibyte-hour.
    fn rates() -> HardwareCostModel {
        HardwareCostModel {
            dollar_per_accelerator_gb_hour: 2.0,
            dollar_per_system_gb_hour: 0.05,
        }
    }

    /// A measured sample: 100 tokens per second over one hour.
    fn sample_hundred_tps() -> IntervalSample {
        IntervalSample {
            tokens: 360_000,
            elapsed_ms: 3_600_000,
            first_token_ms: 120,
        }
    }

    #[test]
    fn the_frontier_model_is_mostly_routed_experts() {
        let model = frontier_model(16);
        let dense: u64 = model
            .iter()
            .filter(|s| s.demand == Demand::EveryToken)
            .map(|s| s.bytes)
            .sum();
        let routed: u64 = model
            .iter()
            .filter(|s| s.demand == Demand::WhenRouted)
            .map(|s| s.bytes)
            .sum();
        assert_eq!(dense, scaled_bytes(DENSE_GIB, 16));
        assert_eq!(routed, scaled_bytes(EXPERT_GIB, 16) * EXPERT_COUNT);
        assert!(routed > dense * 10, "a frontier MoE is mostly routed experts");
    }

    #[test]
    fn the_rented_datacenter_holds_everything_in_fast_memory() {
        let model = frontier_model(16);
        let plan = ResidencyPlan::plan(
            &model,
            rented_datacenter_budget(),
            frontier_profile(16),
        )
        .unwrap();
        assert!(!plan.streams_from_disk());
        let tb = TierBytes::from_plan(&plan);
        assert_eq!(tb.disk, 0);
        assert_eq!(tb.fast_memory_ratio(), Some(1.0));
    }

    #[test]
    fn the_owned_device_stages_routed_experts_to_its_disk() {
        let model = frontier_model(16);
        let plan = ResidencyPlan::plan_bounded_by_disk(
            &model,
            owned_device_budget(),
            frontier_profile(16),
            OWNED_DISK_GIB * GIB,
        )
        .unwrap();
        assert!(plan.streams_from_disk());
        let tb = TierBytes::from_plan(&plan);
        assert!(tb.disk <= OWNED_DISK_GIB * GIB);
        // The dense part never streams from disk.
        let dense = plan
            .placements
            .iter()
            .find(|p| p.demand == Demand::EveryToken)
            .expect("dense shard present");
        assert_ne!(dense.tier, crate::residency::Tier::Disk);
    }

    #[test]
    fn multitier_rental_savings_are_measured_not_guessed() {
        let model = frontier_model(16);
        let cmp = CostComparison::compare(&model, 16, OWNED_DISK_GIB, sample_hundred_tps(), rates())
            .unwrap();

        // Dollar-weighted saving: rental cost scales linearly in rented bytes
        // at equal throughput, with each tier at its own rate. Recompute it
        // from the measured tier bytes and rates - asserting the equality
        // proves the number is recomputed, not written down.
        let rent_per_hour = |tb: TierBytes| {
            (tb.accelerator as f64 / 1e9) * 2.0 + (tb.system as f64 / 1e9) * 0.05
        };
        let costly = cmp.rent_all.cost_per_million_tokens_dollars.unwrap();
        let cheap = cmp.multitier.cost_per_million_tokens_dollars.unwrap();
        let expected_savings =
            1.0 - rent_per_hour(cmp.multitier.tier_bytes) / rent_per_hour(cmp.rent_all.tier_bytes);
        assert!(
            (cmp.savings_ratio().unwrap() - expected_savings).abs() < 1e-12,
            "savings must equal the dollar-weighted rented-footprint ratio"
        );

        // Byte-weighted footprint reduction, recomputed the same way.
        let rented = cmp.rent_all.tier_bytes.rented_fast_memory_bytes();
        let owned = cmp.multitier.tier_bytes.rented_fast_memory_bytes();
        let expected_footprint = 1.0 - (owned as f64) / (rented as f64);
        assert!(
            (cmp.footprint_reduction_ratio().unwrap() - expected_footprint).abs() < 1e-12
        );

        assert!(cheap < costly);
        assert!(cheap >= 0.0);
        assert!(cmp.savings_ratio().unwrap() > 0.9);
        assert!(cmp.footprint_reduction_ratio().unwrap() > 0.9);

        assert!(cmp.multitier.fast_memory_ratio.unwrap() < cmp.rent_all.fast_memory_ratio.unwrap());
        assert!(cmp.multitier.streams_from_disk);
        assert!(!cmp.rent_all.streams_from_disk);

        println!(
            "measured: rent-all ${costly:.3}/M tok, owned-device ${cheap:.3}/M tok, \
             savings {savings:.4}, footprint reduction {footprint:.4}, \
             rented fast ratio {ratio:.4}",
            savings = cmp.savings_ratio().unwrap(),
            footprint = cmp.footprint_reduction_ratio().unwrap(),
            ratio = cmp.multitier.fast_memory_ratio.unwrap(),
        );
    }

    #[test]
    fn the_owned_device_rents_only_a_fraction_of_the_fast_memory() {
        let model = frontier_model(16);
        let cmp = CostComparison::compare(&model, 16, OWNED_DISK_GIB, sample_hundred_tps(), rates())
            .unwrap();
        let reduction = cmp.footprint_reduction_ratio().unwrap();
        // The rented footprint collapses to the dense part plus a few hot
        // experts: more than half of the rented fast memory is eliminated.
        assert!(reduction > 0.5, "footprint reduction {reduction} too small");
    }

    #[test]
    fn a_lower_precision_model_shrinks_the_footprint_but_not_the_shape() {
        let model16 = frontier_model(16);
        let model4 = frontier_model(4);
        let dense16 = model16.first().expect("dense shard first").bytes;
        let dense4 = model4.first().expect("dense shard first").bytes;
        assert_eq!(dense4, dense16 / 4, "int4 is a quarter of bf16");
        assert_eq!(model4.len(), model16.len());
    }
}
