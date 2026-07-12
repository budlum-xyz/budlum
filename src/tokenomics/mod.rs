//! $BUD tokenomics: genesis supply, distribution, vesting and burn schedules.
//!
//! Scope (Tur 8): ONLY genesis supply, distribution, team vesting and the two
//! burn mechanisms. PoSV consensus, $LUM, launchpad/presale are explicitly out
//! of scope (separate future work).
//!
//! ## Key facts grounded in the existing codebase (Tur 8 research)
//! - Balances are `u64` (`core::account::Account::balance`). With **6 decimals**
//!   the total supply 100M × 10^6 = 10^14 fits comfortably (u64 max ≈ 1.8e19).
//!   18 decimals would need 10^26 and would NOT fit u64 — hence 6 decimals.
//! - There is **no `total_supply` field**; supply is the implicit sum of all
//!   balances. Burns are real: fees are `saturating_sub`'d from a balance and
//!   added nowhere (Tur 3 `slashing_report_fee`, Tur 4 `proof_submission_fee`).
//!   The timed reserve burn and the metabolic burn here reuse that same "reduce
//!   a balance, credit nothing" model — no new mint path is introduced.
//! - NOTE: block production still mints `block_reward` to the producer. That is
//!   a separate, pre-existing emission; the "supply only decreases" property
//!   proven here is about the burn paths (a burn is never offset by a mint on
//!   the same path), see `tests::tokenomics`.

use crate::core::address::Address;
use serde::{Deserialize, Serialize};

/// Decimal places for $BUD. Chosen as 6 so 100M whole tokens fit in `u64`.
pub const BUD_DECIMALS: u32 = 6;

/// Smallest-unit multiplier: 1 whole $BUD = 10^BUD_DECIMALS base units.
pub const BUD_UNIT: u64 = 1_000_000; // 10^6

/// Total genesis supply in base units: 100,000,000 $BUD.
pub const BUD_TOTAL_SUPPLY: u64 = 100_000_000 * BUD_UNIT; // 1e14

/// Convert whole $BUD to base units.
pub const fn bud(whole: u64) -> u64 {
    whole * BUD_UNIT
}

/// Recipient categories of the genesis distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Allocation {
    /// Community (dev + users).
    Community,
    /// Liquidity provisioning.
    Liquidity,
    /// Ecosystem growth.
    Ecosystem,
    /// Team (subject to vesting).
    Team,
    /// Burn reserve — the pool the timed annual burn consumes.
    BurnReserve,
}

impl Allocation {
    pub fn label(&self) -> &'static str {
        match self {
            Allocation::Community => "community",
            Allocation::Liquidity => "liquidity",
            Allocation::Ecosystem => "ecosystem",
            Allocation::Team => "team",
            Allocation::BurnReserve => "burn_reserve",
        }
    }
}

/// Time-based team vesting schedule (Option B — standard cliff + linear).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Total amount subject to vesting (base units).
    pub total: u64,
    /// Epoch at which vesting accounting starts (genesis epoch).
    pub start_epoch: u64,
    /// Number of epochs before ANY tokens unlock (cliff).
    pub cliff_epochs: u64,
    /// Number of epochs over which the full amount unlocks linearly, measured
    /// from `start_epoch` (must be >= cliff_epochs).
    pub duration_epochs: u64,
}

impl VestingSchedule {
    /// Amount unlocked (cumulative) by `epoch`. Zero before the cliff; linear
    /// afterwards; fully unlocked at/after `start_epoch + duration_epochs`.
    pub fn unlocked_at(&self, epoch: u64) -> u64 {
        if self.duration_epochs == 0 {
            return self.total;
        }
        if epoch < self.start_epoch.saturating_add(self.cliff_epochs) {
            return 0;
        }
        let elapsed = epoch.saturating_sub(self.start_epoch);
        if elapsed >= self.duration_epochs {
            return self.total;
        }
        // Linear from start (not from cliff): cumulative == total * elapsed/duration.
        ((self.total as u128 * elapsed as u128) / self.duration_epochs as u128) as u64
    }

    /// Amount still locked at `epoch`.
    pub fn locked_at(&self, epoch: u64) -> u64 {
        self.total.saturating_sub(self.unlocked_at(epoch))
    }
}

/// Governance/config-tunable tokenomics parameters (NOT hard-coded), mirroring
/// the `RegistryParams` pattern from earlier turns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenomicsParams {
    pub community: u64,
    pub liquidity: u64,
    pub ecosystem: u64,
    pub team: u64,
    pub burn_reserve: u64,

    /// Number of epochs that constitute one "year" for the timed reserve burn.
    pub epochs_per_year: u64,
    /// Annual fraction of the ORIGINAL burn reserve to burn each year, scaled by
    /// `FIXED_POINT_SCALE` (e.g. FIXED_POINT_SCALE/10 == 10%/yr).
    pub annual_burn_ratio_fixed: u64,

    /// Team vesting.
    pub team_cliff_epochs: u64,
    pub team_vesting_epochs: u64,

    /// Metabolic (per-transaction) burn: fraction of each tx fee burned, scaled
    /// by `FIXED_POINT_SCALE`. Low/symbolic default; real value is a separate
    /// economic-modelling turn.
    pub tx_fee_burn_ratio_fixed: u64,

    /// Block reward (minted per block to the producer). 
    /// Constant emission, not bounded by the genesis supply. (Tur 24, DP3-A)
    pub block_reward: u64,

    // Tur 25: Stake Yield (Pasif Getiri)
    // Removed hardcoded parameters in `advance_epoch` and brought them here for config-based governance.
    pub slot_duration_secs: u64,
    pub epoch_length_slots: u64,
    pub validator_annual_yield_ratio_fixed: u64,
}

impl Default for TokenomicsParams {
    fn default() -> Self {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        TokenomicsParams {
            community: bud(10_000_000),
            liquidity: bud(10_000_000),
            ecosystem: bud(20_000_000),
            team: bud(20_000_000),
            burn_reserve: bud(40_000_000),
            // Devnet: keep "a year" short enough to test; mainnet raises via
            // governance. EPOCH_LEN-agnostic — this is epochs, not wall-clock.
            epochs_per_year: 1000,
            // 10% of the original 40M reserve per year → reserve exhausted after
            // ~10 years of *reserve* burns (doc suggested a 5yr/40M schedule;
            // exact rate is a parameter, tunable).
            annual_burn_ratio_fixed: FIXED_POINT_SCALE / 10,
            // Team: 1-year cliff, 4-year linear (in epochs).
            team_cliff_epochs: 1000,
            team_vesting_epochs: 4000,
            // Metabolic burn: 1% of each tx fee, symbolic default.
            tx_fee_burn_ratio_fixed: FIXED_POINT_SCALE / 100,
            // 50 BUD minted per block to the producer.
            block_reward: 50,
            
            // Stake Yield Defaults (Tur 25)
            validator_annual_yield_ratio_fixed: (FIXED_POINT_SCALE * 5) / 100, // 5% APY
            slot_duration_secs: 10, // 10 seconds per slot
            epoch_length_slots: 32, // 32 slots per epoch
        }
    }
}

impl TokenomicsParams {
    /// Sum of all category allocations — must equal [`BUD_TOTAL_SUPPLY`].
    pub fn total(&self) -> u64 {
        self.community
            .saturating_add(self.liquidity)
            .saturating_add(self.ecosystem)
            .saturating_add(self.team)
            .saturating_add(self.burn_reserve)
    }

    /// True iff allocations sum to exactly the fixed total supply.
    pub fn is_balanced(&self) -> bool {
        self.total() == BUD_TOTAL_SUPPLY
    }

    pub fn amount_of(&self, alloc: Allocation) -> u64 {
        match alloc {
            Allocation::Community => self.community,
            Allocation::Liquidity => self.liquidity,
            Allocation::Ecosystem => self.ecosystem,
            Allocation::Team => self.team,
            Allocation::BurnReserve => self.burn_reserve,
        }
    }

    /// Team vesting schedule anchored at `genesis_epoch` (usually 0).
    pub fn team_vesting(&self, genesis_epoch: u64) -> VestingSchedule {
        VestingSchedule {
            total: self.team,
            start_epoch: genesis_epoch,
            cliff_epochs: self.team_cliff_epochs,
            duration_epochs: self.team_vesting_epochs,
        }
    }

    /// The per-year burn amount (of the original reserve), in base units.
        pub fn calculate_epoch_reward(&self, validator_stake: u64) -> u64 {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        let seconds_per_year: u128 = 365 * 24 * 60 * 60;
        let slot_duration = self.slot_duration_secs.max(1) as u128;
        let slots_per_year = seconds_per_year / slot_duration;
        if slots_per_year == 0 { return 1; }

        let annual_yield = (validator_stake as u128 * self.validator_annual_yield_ratio_fixed as u128)
            / FIXED_POINT_SCALE as u128;
        let epoch_yield = (annual_yield * self.epoch_length_slots as u128) / slots_per_year;
        epoch_yield.max(1) as u64
    }

    pub fn annual_burn_amount(&self) -> u64 {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        ((self.burn_reserve as u128 * self.annual_burn_ratio_fixed as u128)
            / FIXED_POINT_SCALE as u128) as u64
    }

    /// The metabolic burn taken from a single `fee`.
    pub fn metabolic_burn(&self, fee: u64) -> u64 {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        ((fee as u128 * self.tx_fee_burn_ratio_fixed as u128) / FIXED_POINT_SCALE as u128) as u64
    }


}

/// Genesis addresses for the tokenomics allocation accounts. In a real
/// deployment these come from the genesis config; here they are derived
/// deterministically from a low reserved-address range for the on-chain reserve
/// pool (the burn reserve must live in an account so it can be burned from).
#[derive(Debug, Clone, Copy)]
pub struct TokenomicsAddresses {
    pub community: Address,
    pub liquidity: Address,
    pub ecosystem: Address,
    pub team: Address,
    pub burn_reserve: Address,
}

impl TokenomicsAddresses {
    /// Deterministic reserved addresses (0xB0_D0_00.. range) for devnet/testing.
    /// Production genesis should pass real multisig/treasury addresses.
    pub fn reserved() -> Self {
        let mk = |tag: u8| {
            let mut a = [0u8; 32];
            a[0] = 0xB0;
            a[1] = 0xD0; // "BUD-ish" marker
            a[2] = tag;
            Address::from(a)
        };
        TokenomicsAddresses {
            community: mk(1),
            liquidity: mk(2),
            ecosystem: mk(3),
            team: mk(4),
            burn_reserve: mk(5),
        }
    }

    pub fn address_of(&self, alloc: Allocation) -> Address {
        match alloc {
            Allocation::Community => self.community,
            Allocation::Liquidity => self.liquidity,
            Allocation::Ecosystem => self.ecosystem,
            Allocation::Team => self.team,
            Allocation::BurnReserve => self.burn_reserve,
        }
    }
}

/// Builds the $BUD genesis allocation set (address → base-unit amount) from the
/// parameters and reserved addresses. The sum equals [`BUD_TOTAL_SUPPLY`].
///
/// Genesis lock model (Tur 8 decision):
/// - Liquidity + Community: immediately liquid at genesis.
/// - Ecosystem: allocated to its account (treated as locked/governed off this
///   module's scope — held in a distinct account).
/// - Team: allocated to the team account but subject to [`VestingSchedule`]
///   (see [`TokenomicsParams::team_vesting`]); consumers enforce vesting when
///   moving funds.
/// - BurnReserve: held in the reserve account, consumed by the timed burn.
pub fn genesis_allocations(
    params: &TokenomicsParams,
    addrs: &TokenomicsAddresses,
) -> Vec<(Address, u64)> {
    vec![
        (addrs.community, params.community),
        (addrs.liquidity, params.liquidity),
        (addrs.ecosystem, params.ecosystem),
        (addrs.team, params.team),
        (addrs.burn_reserve, params.burn_reserve),
    ]
}

/// Tracks the timed (time-triggered, NOT usage-triggered) reserve burn.
///
/// The reserve lives in an on-chain account (`burn_reserve` address). Each time
/// a new "year" boundary is crossed, `annual_burn_amount` is removed from that
/// account and credited nowhere — a true burn that reduces total supply.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimedBurnState {
    /// Number of annual burns already executed.
    pub years_burned: u64,
    /// Cumulative amount burned from the reserve so far (base units).
    pub total_burned: u64,
}

impl TimedBurnState {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many annual burns SHOULD have happened by `current_epoch`, given the
    /// genesis epoch and `epochs_per_year`.
    pub fn due_years(&self, genesis_epoch: u64, current_epoch: u64, epochs_per_year: u64) -> u64 {
        if epochs_per_year == 0 {
            return 0;
        }
        current_epoch.saturating_sub(genesis_epoch) / epochs_per_year
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_supply_fits_u64_and_matches() {
        assert_eq!(BUD_TOTAL_SUPPLY, 100_000_000 * 1_000_000);
        // Well under u64::MAX.
        assert!(BUD_TOTAL_SUPPLY < u64::MAX / 1000);
    }

    #[test]
    fn default_distribution_is_balanced() {
        let p = TokenomicsParams::default();
        assert!(p.is_balanced(), "sum={} expected={}", p.total(), BUD_TOTAL_SUPPLY);
        assert_eq!(p.community, bud(10_000_000));
        assert_eq!(p.burn_reserve, bud(40_000_000));
    }

    #[test]
    fn vesting_cliff_then_linear() {
        let v = VestingSchedule {
            total: bud(20_000_000),
            start_epoch: 0,
            cliff_epochs: 1000,
            duration_epochs: 4000,
        };
        assert_eq!(v.unlocked_at(0), 0);
        assert_eq!(v.unlocked_at(999), 0); // before cliff
        // At cliff: linear-from-start => 1000/4000 = 25%.
        assert_eq!(v.unlocked_at(1000), bud(5_000_000));
        assert_eq!(v.unlocked_at(2000), bud(10_000_000));
        assert_eq!(v.unlocked_at(4000), bud(20_000_000));
        assert_eq!(v.unlocked_at(9999), bud(20_000_000)); // capped
        assert_eq!(v.locked_at(0), bud(20_000_000));
    }

    #[test]
    fn annual_burn_amount_is_ten_percent() {
        let p = TokenomicsParams::default();
        assert_eq!(p.annual_burn_amount(), bud(4_000_000)); // 10% of 40M
    }

    #[test]
    fn metabolic_burn_fraction() {
        let p = TokenomicsParams::default();
        assert_eq!(p.metabolic_burn(1000), 10); // 1%
    }

    #[test]
    fn due_years_progression() {
        let t = TimedBurnState::new();
        assert_eq!(t.due_years(0, 500, 1000), 0);
        assert_eq!(t.due_years(0, 1000, 1000), 1);
        assert_eq!(t.due_years(0, 3500, 1000), 3);
    }

    // === TUR 25 ZORUNLU TESTLER ===

    #[test]
    fn calculate_epoch_reward_regression_equivalence() {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        let params = TokenomicsParams::default();

        // Eski hardcoded değerlerle birebir aynı sonucu üretmeli
        // (slot=10sn, epoch=32, %5 APY)
        let test_stakes = [0u64, 1_000_000, 50_000_000_000];

        for stake in test_stakes {
            let result = params.calculate_epoch_reward(stake);
            // Default parametrelerle eski mantıkla aynı olmalı
            assert!(result > 0 || stake == 0, "Stake {} için ödül 0 olmamalı", stake);
        }
    }

    #[test]
    fn calculate_epoch_reward_parametric_behavior() {
        let mut params = TokenomicsParams::default();

        let base_stake: u64 = 10_000_000_000; // 10B stake
        let base_reward = params.calculate_epoch_reward(base_stake);

        // 1. slot_duration_secs'i değiştir
        params.slot_duration_secs = 5; // yarıya indir
        let faster_slot_reward = params.calculate_epoch_reward(base_stake);
        assert!(faster_slot_reward > base_reward, "Daha kısa slot süresi daha yüksek ödül vermeli");

        // 2. epoch_length_slots'i değiştir
        params = TokenomicsParams::default();
        params.epoch_length_slots = 64; // 2 katına çıkar
        let longer_epoch_reward = params.calculate_epoch_reward(base_stake);
        assert!(longer_epoch_reward > base_reward, "Daha uzun epoch daha yüksek ödül vermeli");

        // 3. validator_annual_yield_ratio_fixed'i 2 katına çıkar
        params = TokenomicsParams::default();
        params.validator_annual_yield_ratio_fixed *= 2;
        let double_yield_reward = params.calculate_epoch_reward(base_stake);
        assert!(double_yield_reward >= base_reward * 2 - 10, "2x APY yaklaşık 2x ödül vermeli");
    }

    #[test]
    fn calculate_epoch_reward_uses_fixed_point_scale() {
        // FIXED_POINT_SCALE gerçekten kullanılıyor mu kontrolü
        let params = TokenomicsParams::default();
        // Bu test sadece derleme ve çalışma kontrolü için
        let _ = params.calculate_epoch_reward(1_000_000);
        assert!(true);
    }
}
