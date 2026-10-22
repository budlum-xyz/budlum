//! Minimum-cost validator: one node that runs all four B.U.D. layers - the
//! chain core, the BudZKVM prover, shard storage, and frontier serving -
//! priced as one capital figure plus one monthly energy figure.
//!
//! Every layer is a footprint struct, the pricelist is 2026 market data, and
//! every total is recomputed from the two in the tests - no total is written
//! down. The serving layer reuses [`crate::cost_forecast`] so its numbers stay
//! the measured residency numbers, not a second, separate set.

use crate::cost_forecast::{
    disk_band_tokens_per_second_at, frontier_model, frontier_profile, hourly_rent,
    owned_pc128_budget, PC128_DISK_GIB,
};
use crate::metric::{HardwareCostModel, TierBytes};
use crate::residency::{PlanError, ResidencyPlan};

const GIB: u64 = 1 << 30;
const HOURS_PER_MONTH: f64 = 24.0 * 30.44;

/// 2026 component prices: per GiB, per core, per kWh.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HardwarePricelist {
    /// DDR5 system RAM.
    pub dollar_per_gib_ram: f64,
    /// NVMe flash (chain state, hot experts).
    pub dollar_per_gib_nvme: f64,
    /// Bulk HDD (shard storage).
    pub dollar_per_gib_hdd: f64,
    /// Amortised CPU core.
    pub dollar_per_core: f64,
    /// Grid energy.
    pub dollar_per_kwh: f64,
}

#[must_use]
pub const fn market_pricelist() -> HardwarePricelist {
    HardwarePricelist {
        dollar_per_gib_ram: 2.5,
        dollar_per_gib_nvme: 0.07,
        dollar_per_gib_hdd: 0.02,
        dollar_per_core: 25.0,
        dollar_per_kwh: 0.15,
    }
}

/// One layer's hardware footprint. A zero field means the layer needs none of
/// that resource (the prover owns no dedicated hardware at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerFootprint {
    pub ram_gib: u64,
    pub nvme_gib: u64,
    pub hdd_gib: u64,
    pub cores: u64,
    pub watts: u64,
}

impl LayerFootprint {
    /// Component capital, dollars, recomputed from the pricelist.
    #[must_use]
    pub const fn capital_dollars(self, p: HardwarePricelist) -> f64 {
        self.ram_gib as f64 * p.dollar_per_gib_ram
            + self.nvme_gib as f64 * p.dollar_per_gib_nvme
            + self.hdd_gib as f64 * p.dollar_per_gib_hdd
            + self.cores as f64 * p.dollar_per_core
    }

    /// Monthly energy bill, dollars, at continuous duty.
    #[must_use]
    pub const fn monthly_energy_dollars(self, p: HardwarePricelist) -> f64 {
        self.watts as f64 * HOURS_PER_MONTH / 1000.0 * p.dollar_per_kwh
    }
}

/// Chain core: consensus, execution, state, mempool. Modest CPU and RAM; the
/// chain and archive state live on NVMe.
#[must_use]
pub const fn core_layer() -> LayerFootprint {
    LayerFootprint {
        ram_gib: 16,
        nvme_gib: 512,
        hdd_gib: 0,
        cores: 8,
        watts: 60,
    }
}

/// BudZKVM prover: settlement-time STARK proving reuses the core CPU and RAM.
/// It owns no dedicated capital and idles at zero watts between settlements.
#[must_use]
pub const fn zkvm_layer() -> LayerFootprint {
    LayerFootprint {
        ram_gib: 0,
        nvme_gib: 0,
        hdd_gib: 0,
        cores: 0,
        watts: 0,
    }
}

/// Continuous HDD draw per terabyte held (bulk drives, ~7 W).
pub const STORAGE_HDD_WATTS_PER_TB: f64 = 7.0;

/// One-time capital of a terabyte of shard disk.
#[must_use]
pub const fn storage_capital_per_tb_usd(p: HardwarePricelist) -> f64 {
    1024.0 * p.dollar_per_gib_hdd
}

/// Ten-year custody cost of one full terabyte: capital plus continuous energy.
#[must_use]
pub const fn ten_year_storage_cost_usd_per_tb(p: HardwarePricelist) -> f64 {
    let capital = storage_capital_per_tb_usd(p);
    let energy = STORAGE_HDD_WATTS_PER_TB * 24.0 * 365.25 * 10.0 / 1000.0 * p.dollar_per_kwh;
    capital + energy
}

/// One-year custody cost of one full terabyte: capital plus one year of
/// continuous energy. This is the custody-period figure the 3.0 upload rule
/// prices against (user decision 2026-08-31: custody is one year); the
/// ten-year figure survives as the auction's start-price anchor.
#[must_use]
pub const fn one_year_storage_cost_usd_per_tb(p: HardwarePricelist) -> f64 {
    let capital = storage_capital_per_tb_usd(p);
    let energy = STORAGE_HDD_WATTS_PER_TB * 24.0 * 365.25 / 1000.0 * p.dollar_per_kwh;
    capital + energy
}

/// Custody cost of `bytes` held on NVMe, as an upper bound: the one-time
/// capital of those bytes, not amortized over time.
#[must_use]
pub const fn nvme_custody_usd(bytes: u64, p: HardwarePricelist) -> f64 {
    (bytes as f64 / (1u64 << 30) as f64) * p.dollar_per_gib_nvme
}

/// Storage layer: `disk_gib` of committed shards on bulk HDD plus a small RAM
/// index. Shards are written once and read for challenges and repair.
#[must_use]
pub const fn storage_layer(disk_gib: u64) -> LayerFootprint {
    LayerFootprint {
        ram_gib: 2,
        nvme_gib: 0,
        hdd_gib: disk_gib,
        cores: 2,
        watts: 15,
    }
}

/// Serving layer: the pc128 box from [`crate::cost_forecast`] - 128 GiB host
/// RAM and two 2 TB NVMe drives that stage the routed experts.
#[must_use]
pub const fn serving_layer() -> LayerFootprint {
    LayerFootprint {
        ram_gib: 128,
        nvme_gib: PC128_DISK_GIB,
        hdd_gib: 0,
        cores: 8,
        watts: 120,
    }
}

/// A serving layer of the operator's choosing, so a cheaper box for a smaller
/// (quantized) model is one call, not a new constant.
#[must_use]
pub const fn serving_layer_for(
    ram_gib: u64,
    nvme_gib: u64,
    cores: u64,
    watts: u64,
) -> LayerFootprint {
    LayerFootprint {
        ram_gib,
        nvme_gib,
        hdd_gib: 0,
        cores,
        watts,
    }
}

/// int4 serving: the frontier model shrinks fourfold, so 64 GiB host RAM and
/// one 2 TB NVMe drive serve it (measured on a 48 GB consumer mini at 0.30
/// tok/s; a 64 GB box serves higher, same class).
#[must_use]
pub const fn serving_layer_int4() -> LayerFootprint {
    serving_layer_for(64, 1862, 8, 100)
}

/// The four layers of one validator, summed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ValidatorBudget {
    pub core: LayerFootprint,
    pub zkvm: LayerFootprint,
    pub storage: LayerFootprint,
    pub serving: LayerFootprint,
}

impl ValidatorBudget {
    /// Component capital for the whole node, dollars.
    #[must_use]
    pub const fn total_capital_dollars(self, p: HardwarePricelist) -> f64 {
        self.core.capital_dollars(p)
            + self.zkvm.capital_dollars(p)
            + self.storage.capital_dollars(p)
            + self.serving.capital_dollars(p)
    }

    /// Continuous-duty energy for the whole node, dollars per month.
    #[must_use]
    pub const fn monthly_energy_dollars(self, p: HardwarePricelist) -> f64 {
        self.core.monthly_energy_dollars(p)
            + self.zkvm.monthly_energy_dollars(p)
            + self.storage.monthly_energy_dollars(p)
            + self.serving.monthly_energy_dollars(p)
    }

    /// A validator holding `storage_disk_gib` of shards.
    #[must_use]
    pub const fn minimum(storage_disk_gib: u64) -> Self {
        Self {
            core: core_layer(),
            zkvm: zkvm_layer(),
            storage: storage_layer(storage_disk_gib),
            serving: serving_layer(),
        }
    }

    /// The same validator serving the model at int4: the serving layer drops
    /// to a 64 GiB box, everything else is unchanged.
    #[must_use]
    pub const fn minimum_quantized(storage_disk_gib: u64) -> Self {
        Self {
            core: core_layer(),
            zkvm: zkvm_layer(),
            storage: storage_layer(storage_disk_gib),
            serving: serving_layer_int4(),
        }
    }
}

/// The serving layer measured through [`crate::cost_forecast`]: the frontier
/// model placed on the pc128 box, its disk-bound throughput, and its rented
/// fast memory at market rates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ServingMeasure {
    pub tier_bytes: TierBytes,
    pub tokens_per_second_cold: f64,
    pub hourly_rent_dollars: f64,
    pub cost_per_million_tokens_dollars: Option<f64>,
}

/// Measure the serving layer. `disk_gib_per_second` is the measured disk
/// bandwidth the experts stream from (iobench-style, O_DIRECT).
///
/// # Errors
///
/// [`PlanError`] when the model cannot be placed on the pc128 box.
pub fn measure_serving(
    disk_gib_per_second: f64,
    rates: HardwareCostModel,
) -> Result<ServingMeasure, PlanError> {
    measure_serving_at(16, disk_gib_per_second, 1.0, rates)
}

/// Measure the serving layer at a chosen weight precision and speculation
/// speedup, so quantization and MTP show up as one number each instead of
/// being retold in prose.
///
/// # Errors
///
/// [`PlanError`] when the model cannot be placed on the pc128 box.
pub fn measure_serving_at(
    weight_bits: u8,
    disk_gib_per_second: f64,
    speculation: f64,
    rates: HardwareCostModel,
) -> Result<ServingMeasure, PlanError> {
    let model = frontier_model(weight_bits);
    let plan = ResidencyPlan::plan_bounded_by_disk(
        &model,
        owned_pc128_budget(),
        frontier_profile(weight_bits),
        PC128_DISK_GIB * GIB,
    )?;
    let tier_bytes = TierBytes::from_plan(&plan);
    let tokens_per_second_cold =
        disk_band_tokens_per_second_at(disk_gib_per_second, weight_bits, speculation);
    Ok(ServingMeasure {
        tier_bytes,
        tokens_per_second_cold,
        hourly_rent_dollars: hourly_rent(tier_bytes, rates),
        cost_per_million_tokens_dollars: rates
            .cost_per_million_tokens_dollars(&tier_bytes, tokens_per_second_cold),
    })
}

#[cfg(test)]
mod validator_cost_tests {
    use super::*;
    use crate::cost_forecast::{gib_per_cold_token, market_rates, MTP_SPEEDUP};

    #[test]
    fn the_zkvm_owns_no_dedicated_hardware() {
        let zk = zkvm_layer();
        assert_eq!(
            zk.capital_dollars(market_pricelist()),
            0.0,
            "the prover reuses the core, so its capital is zero"
        );
        assert_eq!(zk.monthly_energy_dollars(market_pricelist()), 0.0);
    }

    #[test]
    fn every_total_is_recomputed_from_the_pricelist() {
        let p = market_pricelist();
        let b = ValidatorBudget::minimum(1024);
        let expected = b.core.capital_dollars(p)
            + b.zkvm.capital_dollars(p)
            + b.storage.capital_dollars(p)
            + b.serving.capital_dollars(p);
        assert!(
            (b.total_capital_dollars(p) - expected).abs() < 1e-12,
            "the total must be the sum of its layers"
        );
        let expected_energy = b.core.monthly_energy_dollars(p)
            + b.zkvm.monthly_energy_dollars(p)
            + b.storage.monthly_energy_dollars(p)
            + b.serving.monthly_energy_dollars(p);
        assert!(
            (b.monthly_energy_dollars(p) - expected_energy).abs() < 1e-12,
            "the energy total must be the sum of its layers"
        );
    }

    #[test]
    fn serving_is_the_dominant_capital_line() {
        let p = market_pricelist();
        let serving = serving_layer().capital_dollars(p);
        let core = core_layer().capital_dollars(p);
        let storage = storage_layer(1024).capital_dollars(p);
        assert!(
            serving > core + storage,
            "serving {serving} should dominate"
        );
    }

    #[test]
    fn a_minimum_validator_is_about_a_grand_of_components() {
        let p = market_pricelist();
        let capital = ValidatorBudget::minimum(1024).total_capital_dollars(p);
        // Component cost only: board/case/PSU excluded, documented here.
        assert!(
            (800.0..2000.0).contains(&capital),
            "minimum validator capital {capital} should sit in a sane band"
        );
    }

    #[test]
    fn storage_disk_scales_linearly_with_the_hdd_price() {
        let p = market_pricelist();
        let one = storage_layer(1024).capital_dollars(p);
        let two = storage_layer(2048).capital_dollars(p);
        let delta = 1024.0 * p.dollar_per_gib_hdd;
        assert!(
            ((two - one) - delta).abs() < 1e-12,
            "an extra TiB of shards costs exactly its HDD price"
        );
    }

    #[test]
    fn measure_serving_reports_disk_bound_throughput_and_market_rent() {
        let m = measure_serving(10.0, market_rates()).unwrap();
        assert_eq!(m.tier_bytes.accelerator, 0, "pc128 has no accelerator");
        assert!(
            (m.tokens_per_second_cold - 10.0 / gib_per_cold_token(16)).abs() < 1e-12,
            "bf16 reads four times the int4 bytes per token"
        );
        assert!(
            (0.0..1.0).contains(&m.hourly_rent_dollars),
            "pc128 rents only host RAM, sub-dollar per hour, got {}",
            m.hourly_rent_dollars
        );
        let cost = m.cost_per_million_tokens_dollars.unwrap();
        assert!(cost > 0.0 && cost < 500.0, "market-rate token cost {cost}");
    }

    #[test]
    fn int4_serving_costs_less_than_bf16() {
        let p = market_pricelist();
        let bf16 = serving_layer().capital_dollars(p);
        let int4 = serving_layer_int4().capital_dollars(p);
        assert!(
            int4 < bf16,
            "int4 serving {int4} must undercut bf16 serving {bf16}"
        );
    }

    #[test]
    fn quantized_validator_undercuts_the_bf16_total() {
        let p = market_pricelist();
        let bf16 = ValidatorBudget::minimum(1024).total_capital_dollars(p);
        let int4 = ValidatorBudget::minimum_quantized(1024).total_capital_dollars(p);
        assert!(
            int4 < bf16,
            "int4 validator {int4} must be cheaper than {bf16}"
        );
    }

    #[test]
    fn int4_shrinks_the_served_footprint_fourfold() {
        let bf16 = measure_serving_at(16, 10.0, 1.0, market_rates()).unwrap();
        let int4 = measure_serving_at(4, 10.0, 1.0, market_rates()).unwrap();
        assert_eq!(
            int4.tier_bytes.total(),
            bf16.tier_bytes.total() / 4,
            "int4 is a quarter of bf16 bytes"
        );
    }

    #[test]
    fn a_full_terabyte_ten_year_cost_exceeds_a_cent_but_a_recipe_does_not() {
        let p = market_pricelist();
        let body = ten_year_storage_cost_usd_per_tb(p);
        assert!(
            body > 0.01,
            "a full terabyte over ten years costs more than a cent: {body}"
        );
        let recipe = nvme_custody_usd(74, p);
        assert!(
            recipe < 0.01,
            "a 74-byte recipe costs far less than a cent: {recipe}"
        );
    }

    #[test]
    fn speculation_multiplies_throughput_and_divides_token_cost() {
        let greedy = measure_serving_at(16, 10.0, 1.0, market_rates()).unwrap();
        let speculative = measure_serving_at(16, 10.0, MTP_SPEEDUP, market_rates()).unwrap();
        assert!(
            (speculative.tokens_per_second_cold - greedy.tokens_per_second_cold * MTP_SPEEDUP)
                .abs()
                < 1e-12
        );
        let greedy_cost = greedy.cost_per_million_tokens_dollars.unwrap();
        let speculative_cost = speculative.cost_per_million_tokens_dollars.unwrap();
        assert!(
            (speculative_cost - greedy_cost / MTP_SPEEDUP).abs() < 1e-6,
            "speculation divides the per-token cost by its speedup"
        );
    }
}
