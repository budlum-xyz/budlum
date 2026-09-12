//! $BUD tokenomics: genesis supply, distribution, vesting and burn schedules.
//!
//! Scope: ONLY genesis supply, distribution, team vesting and the two
//! Burn mechanisms. PoSV consensus, $LUM, launchpad/presale are explicitly out
//! Of scope (separate future work).
//!
//! ## Key facts grounded in the existing codebase (research)
//! - Balances are `u64` (`core::account::Account::balance`). With **6 decimals**
//!   The total supply 100M × 10^6 = 10^14 fits comfortably (u64 max ≈ 1.8e19).
//!   18 decimals would need 10^26 and would NOT fit u64 - hence 6 decimals.
//! - There is **no `total_supply` field**; supply is the implicit sum of all
//!   Balances. Burns are real: fees are `saturating_sub`'d from a balance and
//!   Added nowhere (`slashing_report_fee`, `proof_submission_fee`).
//!   The timed reserve burn and the metabolic burn here reuse that same "reduce
//!   A balance, credit nothing" model - no new mint path is introduced.
//! - Validator income is fee-only: block and epoch emissions are disabled.
//!   The producer receives `tx.fee - metabolic_burn` exactly once per included
//!   Transaction. The legacy `block_reward` field is wire/snapshot compatibility
//!   Metadata and cannot mint supply.

pub mod reward_pool;

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
    /// Burn reserve - the pool the timed annual burn consumes.
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

/// Time-based team vesting schedule (Option B - standard cliff + linear).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Total amount subject to vesting (base units).
    pub total: u64,
    /// Epoch at which vesting accounting starts (genesis epoch).
    pub start_epoch: u64,
    /// Number of epochs before ANY tokens unlock (cliff).
    pub cliff_epochs: u64,
    /// Number of epochs over which the full amount unlocks linearly, measured
    /// From `start_epoch` (must be >= cliff_epochs).
    pub duration_epochs: u64,
}

impl VestingSchedule {
    /// Amount unlocked (cumulative) by `epoch`. Zero before the cliff; linear
    /// Afterwards; fully unlocked at/after `start_epoch + duration_epochs`.
    ///
    /// The cliff is checked first. A schedule with `duration_epochs: 0` and a
    /// nonzero cliff unlocks everything at the cliff, not at genesis: the
    /// zero-duration shortcut is for the no-schedule case, and it used to
    /// bypass the cliff.
    pub fn unlocked_at(&self, epoch: u64) -> u64 {
        if epoch < self.start_epoch.saturating_add(self.cliff_epochs) {
            return 0;
        }
        if self.duration_epochs == 0 {
            return self.total;
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
/// The `RegistryParams` pattern from earlier turns.
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
    /// By `FIXED_POINT_SCALE`. Low/symbolic default; real value is a separate
    /// Economic-modelling turn.
    pub tx_fee_burn_ratio_fixed: u64,

    /// Legacy snapshot/genesis field. Runtime emission is disabled; validators
    /// Earn only flat transaction fees minus metabolic burn.
    pub block_reward: u64,

    // Stake Yield (Pasif Getiri)
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
            // Governance. EPOCH_LEN-agnostic - this is epochs, not wall-clock.
            epochs_per_year: 1000,
            // 10% of the original 40M reserve per year → reserve exhausted after
            // ~10 years of *reserve* burns (doc suggested a 5yr/40M schedule;
            // Exact rate is a parameter, tunable).
            annual_burn_ratio_fixed: FIXED_POINT_SCALE / 10,
            // Team: 1-year cliff, 4-year linear (in epochs).
            team_cliff_epochs: 1000,
            team_vesting_epochs: 4000,
            // Metabolic burn: 1% of each tx fee, symbolic default.
            tx_fee_burn_ratio_fixed: FIXED_POINT_SCALE / 100,
            // Legacy wire value; Executor never mints it.
            block_reward: 50,

            // Stake Yield Defaults
            validator_annual_yield_ratio_fixed: (FIXED_POINT_SCALE * 5) / 100, // 5% APY
            slot_duration_secs: 10, // 10 seconds per slot
            epoch_length_slots: 32, // 32 slots per epoch
        }
    }
}

impl TokenomicsParams {
    /// Wall-clock seconds represented by one canonical tokenomics epoch.
    pub fn seconds_per_epoch(&self) -> u64 {
        self.slot_duration_secs
            .max(1)
            .saturating_mul(self.epoch_length_slots.max(1))
    }

    /// Wall-clock seconds represented by one annual reserve-burn period.
    pub fn seconds_per_year(&self) -> u64 {
        self.epochs_per_year
            .max(1)
            .saturating_mul(self.seconds_per_epoch())
    }

    /// Convert a wall-clock timestamp to the tokenomics epoch index used by
    /// Existing vesting schedules. This keeps the storage format stable while
    /// Ensuring production unlocks advance with time, not with arbitrary epoch
    /// Counter jumps.
    pub fn epoch_at_timestamp(&self, timestamp_secs: u64) -> u64 {
        timestamp_secs / self.seconds_per_epoch()
    }

    /// Sum of all category allocations - must equal [`BUD_TOTAL_SUPPLY`].
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

    /// The per-epoch validator reward for `validator_stake`, in base units:
    /// the annual yield on the stake, spread over the epochs in a year.
    ///
    /// There is no per-epoch floor. A stake so small that its yield rounds to
    /// zero earns zero; a floor of one base unit per epoch paid every account
    /// holding a single unit more than its share of the annual budget, and
    /// with enough such accounts the sum exceeded the yield the parameters
    /// promise.
    pub fn calculate_epoch_reward(&self, validator_stake: u64) -> u64 {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        if validator_stake == 0 {
            return 0;
        }
        // Per-epoch reward formula.
        //
        // The annual yield is spread across the CONFIGURED number of epochs
        // per year:
        //
        //   Epoch_yield = (stake * APY) / epochs_per_year
        //
        // `epochs_per_year` is part of the genesis parameters and must match
        // the chain's actual epoch cadence (mainnet: 6 s slots, 100 slots
        // per epoch -> 600 s epochs -> 52 560 epochs per calendar year).
        // The previous formula derived the share from
        // `slot_duration_secs * SEC_PER_YEAR / 10` instead and never read
        // `epochs_per_year`; with the mainnet parameters it paid only about
        // 27.8 percent of the promised annual yield, and the conservation
        // held for no configuration except a 10 s slot. The pin
        // `mainnet_parameters_pay_the_configured_annual_yield` locks the
        // aggregate payout to the promised yield.
        //
        // Slot and epoch geometry still determine how many epochs a year
        // has; operators express that through `epochs_per_year` rather than
        // through this function re-deriving it. Devnet keeps its own
        // deterministic (faster) payout cadence through its own
        // `epochs_per_year` value.
        let annual_yield = (validator_stake as u128
            * self.validator_annual_yield_ratio_fixed as u128)
            / FIXED_POINT_SCALE as u128;
        let epochs_per_year = u128::from(self.epochs_per_year.max(1));
        let epoch_yield = annual_yield / epochs_per_year;
        u64::try_from(epoch_yield).unwrap_or(u64::MAX)
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
/// Deployment these come from the genesis config; here they are derived
/// Deterministically from a low reserved-address range for the on-chain reserve
/// Pool (the burn reserve must live in an account so it can be burned from).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenomicsAddresses {
    pub community: Address,
    pub liquidity: Address,
    pub ecosystem: Address,
    pub team: Address,
    pub burn_reserve: Address,
}

impl TokenomicsAddresses {
    /// Deterministic reserved addresses (0xB0_D0_00.. range) for devnet/testing.
    /// Production genesis must pass ceremony-controlled destinations. This
    /// Address bundle does not by itself encode or prove a multisig policy.
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
/// Parameters and reserved addresses. The sum equals [`BUD_TOTAL_SUPPLY`].
///
/// Genesis lock model (decision):
/// - Liquidity + Community: immediately liquid at genesis.
/// - Ecosystem: allocated to its account (treated as locked/governed off this
///   Module's scope - held in a distinct account).
/// - Team: allocated to the team account but subject to [`VestingSchedule`]
///   (see [`TokenomicsParams::team_vesting`]); consumers enforce vesting when
///   Moving funds.
/// - BurnReserve: held in the reserve account, consumed by the timed burn.
///
/// # Errors
///
/// Refuses a configuration whose allocations do not sum to
/// [`BUD_TOTAL_SUPPLY`]: seeding it would mint a supply other than the one
/// every other tokenomics rule assumes.
pub fn genesis_allocations(
    params: &TokenomicsParams,
    addrs: &TokenomicsAddresses,
) -> Result<Vec<(Address, u64)>, String> {
    if !params.is_balanced() {
        return Err(format!(
            "tokenomics allocations sum to {} base units, not the fixed supply of {}",
            params.total(),
            BUD_TOTAL_SUPPLY
        ));
    }
    Ok(vec![
        (addrs.community, params.community),
        (addrs.liquidity, params.liquidity),
        (addrs.ecosystem, params.ecosystem),
        (addrs.team, params.team),
        (addrs.burn_reserve, params.burn_reserve),
    ])
}

/// Tracks the timed (time-triggered, NOT usage-triggered) reserve burn.
///
/// The reserve lives in an on-chain account (`burn_reserve` address). Each time
/// A new "year" boundary is crossed, `annual_burn_amount` is removed from that
/// Account and credited nowhere - a true burn that reduces total supply.
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
    /// Genesis epoch and `epochs_per_year`. Kept for deterministic legacy/devnet
    /// Tests; production callers should prefer [`Self::due_years_by_time`].
    pub fn due_years(&self, genesis_epoch: u64, current_epoch: u64, epochs_per_year: u64) -> u64 {
        if epochs_per_year == 0 {
            return 0;
        }
        current_epoch.saturating_sub(genesis_epoch) / epochs_per_year
    }

    /// How many annual burns SHOULD have happened by wall-clock time.
    pub fn due_years_by_time(
        &self,
        genesis_timestamp_secs: u64,
        current_timestamp_secs: u64,
        seconds_per_year: u64,
    ) -> u64 {
        if seconds_per_year == 0 {
            return 0;
        }
        current_timestamp_secs.saturating_sub(genesis_timestamp_secs) / seconds_per_year
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_supply_fits_u64_and_matches() {
        assert_eq!(BUD_TOTAL_SUPPLY, 100_000_000 * 1_000_000);
        // Compile-time invariant: total supply well under u64::MAX so that
        // Balance arithmetic never overflows in any of the burn / mint
        // Paths (saturating_* still works if it does, but the constant
        // Is small enough to skip that worry entirely).
        const { assert!(BUD_TOTAL_SUPPLY < u64::MAX / 1000) };
    }

    #[test]
    fn default_distribution_is_balanced() {
        let p = TokenomicsParams::default();
        assert!(
            p.is_balanced(),
            "sum={} expected={}",
            p.total(),
            BUD_TOTAL_SUPPLY
        );
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
    fn epoch_linear_vesting_unlocks_between_year_boundaries() {
        let v = VestingSchedule {
            total: bud(20_000_000),
            start_epoch: 0,
            cliff_epochs: 1000,
            duration_epochs: 4000,
        };

        assert_eq!(v.unlocked_at(1500), bud(7_500_000));
        assert_eq!(v.locked_at(1500), bud(12_500_000));
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

    #[test]
    fn wall_clock_years_use_seconds_not_epoch_counter() {
        let params = TokenomicsParams::default();
        let t = TimedBurnState::new();
        let year = params.seconds_per_year();
        assert_eq!(t.due_years_by_time(0, year - 1, year), 0);
        assert_eq!(t.due_years_by_time(0, year, year), 1);
        assert_eq!(t.due_years_by_time(0, 3 * year + 1, year), 3);
        assert_eq!(params.epoch_at_timestamp(params.seconds_per_epoch() * 7), 7);
    }

    // === MANDATORY TESTS ===

    /// The default parameters (5 percent a year over the configured
    /// `epochs_per_year` = 1000) give exactly these rewards. Pinned as
    /// values rather than as "not zero": the old assertion was satisfied by
    /// the floor this function no longer has.
    #[test]
    fn calculate_epoch_reward_regression_equivalence() {
        let params = TokenomicsParams::default();
        // annual yield = stake / 20; epoch share = annual yield / 1000.
        assert_eq!(params.calculate_epoch_reward(0), 0);
        assert_eq!(
            params.calculate_epoch_reward(1_000_000),
            50,
            "1 BUD: 50 000 / 1000"
        );
        assert_eq!(
            params.calculate_epoch_reward(bud(1_000)),
            50_000,
            "1 000 BUD: 50 000 000 / 1000"
        );
        assert_eq!(params.calculate_epoch_reward(50_000_000_000), 2_500_000);
        assert_eq!(
            params.calculate_epoch_reward(bud(100_000_000)),
            5_000_000_000
        );
    }

    /// The mainnet configuration (6 s slots, 100 slots per epoch, 52 560
    /// epochs per year, 5 percent APY) must pay the configured annual yield
    /// over a year of epochs - not more, and not the 27.8 percent the old
    /// slot-derived formula paid.
    #[test]
    fn mainnet_parameters_pay_the_configured_annual_yield() {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        let params = TokenomicsParams {
            epochs_per_year: 52_560,
            slot_duration_secs: 6,
            epoch_length_slots: 100,
            ..TokenomicsParams::default()
        };
        let stake = bud(1_000_000);
        let annual_yield = (u128::from(stake)
            * u128::from(params.validator_annual_yield_ratio_fixed))
            / u128::from(FIXED_POINT_SCALE);
        let reward = params.calculate_epoch_reward(stake);
        assert!(reward > 0, "a 1M BUD stake earns a visible epoch reward");
        let paid = u128::from(reward) * u128::from(params.epochs_per_year);
        // Rounding floors each epoch share, so the aggregate stays at or
        // below the promise and misses it by less than one unit per epoch.
        assert!(
            paid <= annual_yield,
            "a year of epochs ({paid}) pays more than the annual yield ({annual_yield})"
        );
        assert!(
            annual_yield - paid < u128::from(params.epochs_per_year),
            "a year of epochs ({paid}) loses more than rounding against the \
             annual yield ({annual_yield})"
        );
    }

    /// No stake earns nothing, and a stake whose yield rounds to zero earns
    /// zero as well. The old floor of one base unit per epoch paid every
    /// one-unit account more than its share of the annual budget.
    #[test]
    fn a_dust_stake_earns_nothing() {
        let params = TokenomicsParams::default();
        assert_eq!(params.calculate_epoch_reward(0), 0);
        assert_eq!(
            params.calculate_epoch_reward(1),
            0,
            "one base unit at 5 percent a year is far below one unit per epoch"
        );
        // A year of epochs on any stake stays within the promised yield.
        let stake = 1_000_000u64;
        let annual_yield = (u128::from(stake)
            * u128::from(params.validator_annual_yield_ratio_fixed))
            / u128::from(crate::core::chain_config::FIXED_POINT_SCALE);
        let epochs_per_year = u128::from(params.epochs_per_year);
        let paid = u128::from(params.calculate_epoch_reward(stake)) * epochs_per_year;
        assert!(
            paid <= annual_yield,
            "a year of epoch rewards ({paid}) exceeds the annual yield ({annual_yield})"
        );
    }

    /// A zero-duration schedule still waits for its cliff.
    #[test]
    fn a_zero_duration_schedule_honours_the_cliff() {
        let v = VestingSchedule {
            total: bud(1_000),
            start_epoch: 10,
            cliff_epochs: 5,
            duration_epochs: 0,
        };
        assert_eq!(v.unlocked_at(0), 0);
        assert_eq!(v.unlocked_at(14), 0, "one epoch before the cliff");
        assert_eq!(v.unlocked_at(15), bud(1_000), "everything at the cliff");
    }

    /// An unbalanced configuration is refused before it seeds anything.
    #[test]
    fn genesis_allocations_refuse_an_unbalanced_configuration() {
        let mut params = TokenomicsParams::default();
        params.community += 1;
        let addrs = TokenomicsAddresses::reserved();
        let err = genesis_allocations(&params, &addrs).unwrap_err();
        assert!(err.contains("not the fixed supply"), "{err}");
        assert_eq!(
            genesis_allocations(&TokenomicsParams::default(), &addrs)
                .unwrap()
                .len(),
            5
        );
    }

    #[test]
    fn calculate_epoch_reward_parametric_behavior() {
        let mut params = TokenomicsParams::default();

        let base_stake: u64 = 10_000_000_000; // 10B stake
        let base_reward = params.calculate_epoch_reward(base_stake);

        // 1. Double epochs_per_year: twice as many epochs share the same
        //    annual budget, so each one claims half.
        params.epochs_per_year *= 2;
        let denser_cadence_reward = params.calculate_epoch_reward(base_stake);
        assert!(
            denser_cadence_reward <= base_reward / 2 + 1
                && denser_cadence_reward >= base_reward / 2 - 1,
            "twice the epochs per year has to give half the per-epoch reward \
             ({denser_cadence_reward} vs {})",
            base_reward / 2
        );

        // 2. Slot and epoch geometry alone do not change the per-epoch
        //    share: the cadence is carried by `epochs_per_year`, which the
        //    genesis parameters must keep consistent with the geometry.
        params = TokenomicsParams::default();
        params.slot_duration_secs = 5;
        params.epoch_length_slots = 64;
        let geometry_changed_reward = params.calculate_epoch_reward(base_stake);
        assert_eq!(
            geometry_changed_reward, base_reward,
            "slot/epoch geometry without a matching epochs_per_year change \
             must not move the per-epoch reward"
        );

        // 3. Double validator_annual_yield_ratio_fixed.
        params = TokenomicsParams::default();
        params.validator_annual_yield_ratio_fixed *= 2;
        let double_yield_reward = params.calculate_epoch_reward(base_stake);
        assert!(
            double_yield_reward >= base_reward * 2 - 2
                && double_yield_reward <= base_reward * 2 + 2,
            "2x APY has to give 2x the reward up to rounding"
        );
    }

    /// The yield ratio is read through `FIXED_POINT_SCALE`: a ratio of one
    /// whole scale is 100 percent a year, and the reward grows linearly in
    /// the stake with no floor and no overflow up to the full supply.
    #[test]
    fn calculate_epoch_reward_uses_fixed_point_scale() {
        use crate::core::chain_config::FIXED_POINT_SCALE;
        let mut params = TokenomicsParams {
            validator_annual_yield_ratio_fixed: FIXED_POINT_SCALE,
            ..TokenomicsParams::default()
        };
        // The formula, written out: the annual yield on the stake divided
        // by the configured number of epochs per year, rounded down once.
        let expected = |params: &TokenomicsParams, stake: u64| -> u64 {
            let annual = u128::from(stake) * u128::from(params.validator_annual_yield_ratio_fixed)
                / u128::from(FIXED_POINT_SCALE);
            u64::try_from(annual / u128::from(params.epochs_per_year.max(1))).unwrap_or(u64::MAX)
        };
        let stake = bud(1_000);
        let full = params.calculate_epoch_reward(stake);
        assert_eq!(full, expected(&params, stake));
        assert_eq!(
            full, 1_000_000,
            "100 percent a year on 1000 BUD over 1000 epochs"
        );
        params.validator_annual_yield_ratio_fixed /= 2;
        let half = params.calculate_epoch_reward(stake);
        assert_eq!(half, expected(&params, stake));
        assert!(
            full / 2 <= half && half <= full.div_ceil(2),
            "half the ratio, half the reward: {half} vs {full}"
        );
        let tenfold = params.calculate_epoch_reward(stake * 10);
        assert_eq!(tenfold, expected(&params, stake * 10));
        assert!(
            half * 10 <= tenfold && tenfold < half * 10 + 10,
            "linear in stake up to rounding: {tenfold} vs {half}"
        );
        let cap = params.calculate_epoch_reward(BUD_TOTAL_SUPPLY);
        assert!(cap > 0 && cap < BUD_TOTAL_SUPPLY / 1000, "{cap}");
    }

    #[test]
    fn test_tokenomics_edge_cases_and_precision() {
        let params = TokenomicsParams::default();
        // Check 6-decimal scaling precision helpers
        assert_eq!(bud(1), 1_000_000);
        assert_eq!(params.total(), BUD_TOTAL_SUPPLY);

        // Vesting edge cases
        let v = VestingSchedule {
            total: bud(1_000_000),
            start_epoch: 10,
            cliff_epochs: 50,
            duration_epochs: 200,
        };
        // Before start
        assert_eq!(v.unlocked_at(5), 0);
        // During cliff (start + cliff = 60)
        assert_eq!(v.unlocked_at(59), 0);
        // At the cliff (start+cliff=60): the linear-from-start design (see the
        // unlocked_at doc) unlocks the accrued share, total*50/200.
        // (fix 2026-07-17: the earlier "0" expectation was a wrong model
        // assumption; mod.rs:82-96 is the lock on the documented behaviour.)
        assert_eq!(v.unlocked_at(60), bud(1_000_000) / 4);
        // Mid duration
        assert!(v.unlocked_at(160) > 0);
        // After full duration (10 + 200 = 210)
        assert_eq!(v.unlocked_at(300), bud(1_000_000));
        assert_eq!(v.locked_at(300), 0);
    }

    #[test]
    fn no_emission_invariant_fixed_supply_and_pool() {
        use crate::core::address::Address;
        use crate::tokenomics::reward_pool::{
            reward_for_epoch, total_epoch_payout, RewardPoolSchedule,
            DEFAULT_VALIDATION_REWARD_POOL,
        };

        // ADR-001: a fixed 100M supply, NO emission. The genesis distribution
        // consumes exactly BUD_TOTAL_SUPPLY; rewards are paid from a
        // PRE-ALLOCATED pool and no new supply is created.
        let p = TokenomicsParams::default();
        assert!(
            p.is_balanced(),
            "genesis must allocate exactly the fixed supply"
        );
        assert_eq!(p.total(), BUD_TOTAL_SUPPLY);

        // Genesis validation reward pool must sit in the ADR-001 8-12% band.
        let pool_pct = DEFAULT_VALIDATION_REWARD_POOL as u128 * 100 / BUD_TOTAL_SUPPLY as u128;
        assert!(
            (8..=12).contains(&pool_pct),
            "validation reward pool {pool_pct}% outside ADR-001 8-12% band"
        );

        // Reward distribution draws from the pre-allocated pool and never mints
        // Beyond it (no-emission invariant at the payout level).
        let schedule = RewardPoolSchedule::default();
        let remaining = bud(10_000_000);
        let payouts = reward_for_epoch(
            schedule,
            0,
            remaining,
            &[
                (Address::from([1u8; 32]), 1_000_000),
                (Address::from([2u8; 32]), 3_000_000),
            ],
        );
        assert!(
            total_epoch_payout(&payouts) <= remaining,
            "epoch payout must not mint beyond the pre-allocated pool"
        );
        assert!(
            schedule.validate().is_ok(),
            "default pools must stay within the fixed supply"
        );
    }
}
