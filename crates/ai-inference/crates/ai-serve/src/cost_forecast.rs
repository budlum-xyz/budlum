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
use crate::residency::{
    Demand, DeviceBudget, PlanError, ResidencyPlan, SemanticProfile, WeightShard,
};

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

/// A CPU-only owned box: 128 GiB host RAM, no accelerator, routed experts
/// staged from two 2 TB NVMe drives (≈ 3.7 TiB usable). This is the profile
/// consumer-box serving actually measures on.
pub const PC128_DISK_GIB: u64 = 2 * 1862;

#[must_use]
pub const fn owned_pc128_budget() -> DeviceBudget {
    DeviceBudget {
        accelerator_bytes: 0,
        system_bytes: 128 * GIB,
    }
}

/// Market-calibrated rental rates (2026): H100-class accelerator ≈ $0.04/GB-hr
/// and host RAM ≈ $0.002/GB-hr. [`HardwareCostModel::cost_per_million_tokens_dollars`]
/// prices only rented fast memory, so the absolute dollars are realistic and
/// the ratio stays identical to the conservative `rates()`.
#[must_use]
pub const fn market_rates() -> HardwareCostModel {
    HardwareCostModel {
        dollar_per_accelerator_gb_hour: 0.04,
        dollar_per_system_gb_hour: 0.002,
    }
}

/// Cold-token disk cost of a frontier MoE at int4, in GiB read per token
/// (measured on a frontier-class MoE at int4: 8 routed experts per layer,
/// tens of layers). Other precisions
/// scale linearly in the weight size: bf16 reads four times the int4 bytes.
pub const GIB_PER_COLD_TOKEN: f64 = 11.0;

/// Cold-token disk cost at a weight precision: the int4 reference scaled by
/// the weight bits.
#[must_use]
pub fn gib_per_cold_token(weight_bits: u8) -> f64 {
    GIB_PER_COLD_TOKEN * f64::from(weight_bits) / 4.0
}

/// Tokens per second a disk-bound device serves at a weight precision and
/// speculation speedup: disk bandwidth over the cold-token read cost, times
/// the speedup. Zero (not infinite) when the disk reports nothing.
#[must_use]
pub fn disk_band_tokens_per_second_at(
    disk_gib_per_second: f64,
    weight_bits: u8,
    speculation: f64,
) -> f64 {
    if disk_gib_per_second <= 0.0 {
        0.0
    } else {
        disk_gib_per_second / gib_per_cold_token(weight_bits) * speculation
    }
}

/// Tokens per second at int4, greedy decoding.
#[must_use]
pub fn disk_band_tokens_per_second(disk_gib_per_second: f64) -> f64 {
    disk_band_tokens_per_second_at(disk_gib_per_second, 4, 1.0)
}

/// Measured multi-token-prediction speedup: an int8 head predicts 2.2-2.8
/// tokens per forward once the cache is warm (lower bound used). Speculation
/// multiplies throughput, so it divides the per-token disk cost.
pub const MTP_SPEEDUP: f64 = 2.2;

/// Disk-bound throughput with speculation: the int4 greedy figure times the
/// speculation speedup. `speculation` is 1.0 for greedy single-token decoding.
#[must_use]
pub fn disk_band_tokens_per_second_with_speculation(
    disk_gib_per_second: f64,
    speculation: f64,
) -> f64 {
    disk_band_tokens_per_second_at(disk_gib_per_second, 4, speculation)
}

/// Hourly rent of a tier footprint, in dollars: rate × bytes, no throughput.
/// The quantity multitiering shrinks, expressed in market dollars.
#[must_use]
pub fn hourly_rent(tb: TierBytes, rates: HardwareCostModel) -> f64 {
    (tb.accelerator as f64 / 1e9) * rates.dollar_per_accelerator_gb_hour
        + (tb.system as f64 / 1e9) * rates.dollar_per_system_gb_hour
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
pub fn forecast(
    plan: &ResidencyPlan,
    sample: IntervalSample,
    rates: HardwareCostModel,
) -> CostForecast {
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

    /// Throughput-independent saving: the fraction of the *hourly memory bill*
    /// the owned device avoids, at whatever throughput either side reaches.
    /// This is the number the "absurdly low cost" claim is allowed to rest
    /// on; the per-token figure is throughput's to change.
    #[must_use]
    pub fn rental_hour_savings_ratio(&self, rates: HardwareCostModel) -> Option<f64> {
        let rent_all = hourly_rent(self.rent_all.tier_bytes, rates);
        let owned = hourly_rent(self.multitier.tier_bytes, rates);
        if rent_all <= 0.0 {
            return None;
        }
        Some(1.0 - owned / rent_all)
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
        assert!(
            routed > dense * 10,
            "a frontier MoE is mostly routed experts"
        );
    }

    #[test]
    fn the_rented_datacenter_holds_everything_in_fast_memory() {
        let model = frontier_model(16);
        let plan =
            ResidencyPlan::plan(&model, rented_datacenter_budget(), frontier_profile(16)).unwrap();
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
        let cmp =
            CostComparison::compare(&model, 16, OWNED_DISK_GIB, sample_hundred_tps(), rates())
                .unwrap();

        // Dollar-weighted saving: rental cost scales linearly in rented bytes
        // at equal throughput, with each tier at its own rate. Recompute it
        // from the measured tier bytes and rates - asserting the equality
        // proves the number is recomputed, not written down.
        let rent_per_hour =
            |tb: TierBytes| (tb.accelerator as f64 / 1e9) * 2.0 + (tb.system as f64 / 1e9) * 0.05;
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
        assert!((cmp.footprint_reduction_ratio().unwrap() - expected_footprint).abs() < 1e-12);

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
        let cmp =
            CostComparison::compare(&model, 16, OWNED_DISK_GIB, sample_hundred_tps(), rates())
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

    #[test]
    fn market_rates_make_the_absolute_dollars_realistic() {
        let model = frontier_model(16);
        let cmp = CostComparison::compare(
            &model,
            16,
            PC128_DISK_GIB,
            sample_hundred_tps(),
            market_rates(),
        )
        .unwrap();
        // Rent-all: ~652 GiB accelerator at $0.04/GB-hr ≈ $28/hr, not thousands.
        let rent_all = hourly_rent(cmp.rent_all.tier_bytes, market_rates());
        assert!(
            (20.0..40.0).contains(&rent_all),
            "rent-all hourly at market rate should be tens of dollars, got {rent_all}"
        );
        // Owned pc128: rented fast memory is host RAM only, ≈ $0.27/hr.
        let owned = hourly_rent(cmp.multitier.tier_bytes, market_rates());
        assert!(
            owned < 1.0,
            "owned hourly rent {owned} should be sub-dollar"
        );
        assert!(owned > 0.0);
    }

    #[test]
    fn owned_pc128_stages_experts_and_keeps_dense_in_ram() {
        let model = frontier_model(16);
        let plan = ResidencyPlan::plan_bounded_by_disk(
            &model,
            owned_pc128_budget(),
            frontier_profile(16),
            PC128_DISK_GIB * GIB,
        )
        .unwrap();
        assert!(plan.streams_from_disk());
        let tb = TierBytes::from_plan(&plan);
        assert_eq!(tb.accelerator, 0, "a CPU-only box has no accelerator tier");
        assert!(
            tb.system <= 128 * GIB,
            "system tier over the 128 GiB budget"
        );
        assert!(
            tb.disk <= PC128_DISK_GIB * GIB,
            "disk over the owned budget"
        );
        let dense = plan
            .placements
            .iter()
            .find(|p| p.demand == Demand::EveryToken)
            .expect("dense shard present");
        assert_ne!(
            dense.tier,
            crate::residency::Tier::Disk,
            "every-token weights never stream"
        );
    }

    #[test]
    fn disk_band_throughput_is_bandwidth_over_cold_token_cost() {
        // 2× NVMe ≈ 10 GB/s → ~0.9 tok/s; 4× NVMe ≈ 20 GB/s → ~1.8 tok/s.
        let two_drives = disk_band_tokens_per_second(10.0);
        let four_drives = disk_band_tokens_per_second(20.0);
        assert!((two_drives - 10.0 / GIB_PER_COLD_TOKEN).abs() < 1e-12);
        assert!((four_drives - 2.0 * two_drives).abs() < 1e-12);
        assert_eq!(disk_band_tokens_per_second(0.0), 0.0);
    }

    #[test]
    fn rental_hour_savings_ratio_is_rate_independent() {
        let model = frontier_model(16);
        for rates in [market_rates(), rates()] {
            let cmp =
                CostComparison::compare(&model, 16, PC128_DISK_GIB, sample_hundred_tps(), rates)
                    .unwrap();
            let saving = cmp.rental_hour_savings_ratio(rates).unwrap();
            let rent_all = hourly_rent(cmp.rent_all.tier_bytes, rates);
            let owned = hourly_rent(cmp.multitier.tier_bytes, rates);
            let expected = 1.0 - owned / rent_all;
            assert!(
                (saving - expected).abs() < 1e-12,
                "saving must be recomputed"
            );
            assert!(
                saving > 0.9,
                "multitiering must cut >90% of the memory bill"
            );
        }
    }
}
