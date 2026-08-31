//! Minimum-cost validator: one node that runs all four B.U.D. layers — the
//! chain core, the BudZKVM prover, shard storage, and frontier serving —
//! priced as one capital figure plus one monthly energy figure.
//!
//! Every layer is a footprint struct, the pricelist is 2026 market data, and
//! every total is recomputed from the two in the tests — no total is written
//! down. The serving layer reuses [`crate::cost_forecast`] so its numbers stay
//! the measured residency numbers, not a second, separate set.

use crate::cost_forecast::{
    disk_band_tokens_per_second, frontier_model, frontier_profile, hourly_rent, owned_pc128_budget,
    PC128_DISK_GIB,
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

/// Serving layer: the pc128 box from [`crate::cost_forecast`] — 128 GiB host
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
    let model = frontier_model(16);
    let plan = ResidencyPlan::plan_bounded_by_disk(
        &model,
        owned_pc128_budget(),
        frontier_profile(16),
        PC128_DISK_GIB * GIB,
    )?;
    let tier_bytes = TierBytes::from_plan(&plan);
    let tokens_per_second_cold = disk_band_tokens_per_second(disk_gib_per_second);
    Ok(ServingMeasure {
        tier_bytes,
        tokens_per_second_cold,
        hourly_rent_dollars: hourly_rent(tier_bytes, rates),
        cost_per_million_tokens_dollars: rates.cost_per_million_tokens_dollars(
            &tier_bytes,
            tokens_per_second_cold,
        ),
    })
}

#[cfg(test)]
mod validator_cost_tests {
    use super::*;
    use crate::cost_forecast::market_rates;

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
        assert!(serving > core + storage, "serving {serving} should dominate");
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
        assert!((m.tokens_per_second_cold - 10.0 / 11.0).abs() < 1e-12);
        assert!(
            (0.0..1.0).contains(&m.hourly_rent_dollars),
            "pc128 rents only host RAM, sub-dollar per hour, got {}",
            m.hourly_rent_dollars
        );
        let cost = m.cost_per_million_tokens_dollars.unwrap();
        assert!(cost > 0.0 && cost < 500.0, "market-rate token cost {cost}");
    }
}
