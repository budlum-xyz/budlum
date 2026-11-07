//! The validation reward pool.
//!
//! Rewards are paid from a pre-allocated pool, not by minting new BUD. The
//! genesis moves the pool out of the ecosystem share into a keyless account
//! ([`reward_pool_account`]); the block transition of every epoch boundary
//! pays the closing epoch's budget from that account to the active
//! validators by stake ([`pay_epoch`]). Block emission stays disabled, so
//! supply is conserved: see the economy invariant
//! `epoch_transition_does_not_mint_validator_yield`. A chain pays only when
//! its profile enables a pool (`Network::reward_pool`).
//!
//! # The three shares (directive section 11.4, )
//!
//! One epoch budget is split into three shares: 40 percent consensus, 50
//! percent storage and 10 percent repair and relay ([`EpochSplit`]). The
//! stake weighted payout of [`pay_epoch`] is the consensus share. The
//! storage share ([`storage_share`]) and the repair and relay share stay in
//! the pool account until the payers that read them exist, so the pool never
//! pays ahead of the work it pays for. Nothing is minted and nothing leaves
//! the pool without a payer.

use crate::core::address::Address;
use crate::tokenomics::{bud, BUD_TOTAL_SUPPLY};
use serde::{Deserialize, Serialize};

/// Default decision: 10% of the fixed 100M supply.
pub const DEFAULT_VALIDATION_REWARD_POOL: u64 = bud(10_000_000);
/// Default treasury side-pool (2%) tracked separately from validator rewards.
pub const DEFAULT_TREASURY_POOL: u64 = bud(2_000_000);
pub const DEFAULT_VALIDATION_POOL_EPOCHS: u64 = 100_000;

/// Parts per million in one whole.
const PPM: u64 = 1_000_000;
/// The consensus share of an epoch budget: 40 percent (TESTNET-DEFAULT).
pub const CONSENSUS_SHARE_PPM: u64 = 400_000;
/// The storage share of an epoch budget: 50 percent (TESTNET-DEFAULT).
pub const STORAGE_SHARE_PPM: u64 = 500_000;
/// The repair and relay share of an epoch budget: 10 percent
/// (TESTNET-DEFAULT).
pub const REPAIR_RELAY_SHARE_PPM: u64 = 100_000;

// The three shares are one whole. A split that does not add up to the budget
// would mint or burn the difference, so it does not compile.
const _: () = assert!(CONSENSUS_SHARE_PPM + STORAGE_SHARE_PPM + REPAIR_RELAY_SHARE_PPM == PPM);

/// One epoch budget split into its three shares.
///
/// The storage share and the repair and relay share are rounded down. The
/// consensus share is what is left, so the three always add up to the budget
/// exactly and the rounding remainder goes to the stake weighted payout, as
/// it did before the split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSplit {
    /// Paid to the active validators by stake at the epoch boundary.
    pub consensus: u64,
    /// Held for the storage reward payer.
    pub storage: u64,
    /// Held for the repair and relay payer.
    pub repair_relay: u64,
}

/// `ppm` parts per million of `amount`, rounded down. The result is never
/// larger than `amount` because `ppm` is at most one whole.
fn ppm_of(amount: u64, ppm: u64) -> u64 {
    u64::try_from(u128::from(amount) * u128::from(ppm) / u128::from(PPM)).unwrap_or(amount)
}

impl EpochSplit {
    /// Split `budget` into the three shares.
    #[must_use]
    pub fn of(budget: u64) -> Self {
        let storage = ppm_of(budget, STORAGE_SHARE_PPM);
        let repair_relay = ppm_of(budget, REPAIR_RELAY_SHARE_PPM);
        // The two rounded shares are at most 60 percent of the budget, so the
        // subtraction cannot go below zero.
        let consensus = budget.saturating_sub(storage.saturating_add(repair_relay));
        Self {
            consensus,
            storage,
            repair_relay,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardPoolSchedule {
    pub validation_reward_pool: u64,
    pub validation_pool_epochs: u64,
    pub treasury_pool: u64,
    pub reward_pool_start_epoch: u64,
}

impl Default for RewardPoolSchedule {
    fn default() -> Self {
        Self {
            validation_reward_pool: DEFAULT_VALIDATION_REWARD_POOL,
            validation_pool_epochs: DEFAULT_VALIDATION_POOL_EPOCHS,
            treasury_pool: DEFAULT_TREASURY_POOL,
            reward_pool_start_epoch: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RewardPoolError {
    EmptyEpochSchedule,
    PoolExceedsFixedSupply,
}

impl RewardPoolSchedule {
    pub fn validate(&self) -> Result<(), RewardPoolError> {
        if self.validation_pool_epochs == 0 {
            return Err(RewardPoolError::EmptyEpochSchedule);
        }
        if self
            .validation_reward_pool
            .saturating_add(self.treasury_pool)
            > BUD_TOTAL_SUPPLY
        {
            return Err(RewardPoolError::PoolExceedsFixedSupply);
        }
        Ok(())
    }

    pub fn per_epoch_budget(&self, epoch: u64, remaining_pool: u64) -> u64 {
        if epoch < self.reward_pool_start_epoch || self.validation_pool_epochs == 0 {
            return 0;
        }
        let base = self.validation_reward_pool / self.validation_pool_epochs;
        base.min(remaining_pool)
    }

    /// The epoch budget of `per_epoch_budget`, split into its three shares.
    #[must_use]
    pub fn split_epoch_budget(&self, epoch: u64, remaining_pool: u64) -> EpochSplit {
        EpochSplit::of(self.per_epoch_budget(epoch, remaining_pool))
    }
}

/// The storage share of the epoch budget: what the storage reward payer
/// () reads for `epoch`.
///
/// WIRING: read by the storage reward payer of . Until that payer
/// lands, the share stays in the pool account and no other path moves it.
#[must_use]
pub fn storage_share(schedule: &RewardPoolSchedule, epoch: u64, remaining_pool: u64) -> u64 {
    schedule.split_epoch_budget(epoch, remaining_pool).storage
}

/// Deterministically split the consensus share of one epoch budget across
/// active validator stakes. The first address in sorted order receives the
/// rounding remainder. The storage share and the repair and relay share are
/// not paid here (see [`EpochSplit`]).
pub fn reward_for_epoch(
    schedule: RewardPoolSchedule,
    epoch: u64,
    remaining_pool: u64,
    active_validator_stakes: &[(Address, u64)],
) -> Vec<(Address, u64)> {
    let budget = schedule.split_epoch_budget(epoch, remaining_pool).consensus;
    if budget == 0 || active_validator_stakes.is_empty() {
        return Vec::new();
    }

    let mut validators: Vec<(Address, u64)> = active_validator_stakes
        .iter()
        .copied()
        .filter(|(_, stake)| *stake > 0)
        .collect();
    validators.sort_by_key(|(addr, _)| *addr);
    // One address, one share. A repeated row used to be
    // paid twice; duplicates are merged into one stake before the split.
    validators.dedup_by(|a, b| {
        if a.0 == b.0 {
            b.1 = b.1.saturating_add(a.1);
            true
        } else {
            false
        }
    });

    let total_stake: u128 = validators.iter().map(|(_, stake)| u128::from(*stake)).sum();
    if total_stake == 0 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(validators.len());
    let mut paid = 0u64;
    for (addr, stake) in validators {
        let share = (u128::from(budget) * u128::from(stake) / total_stake) as u64;
        paid = paid.saturating_add(share);
        out.push((addr, share));
    }

    let remainder = budget.saturating_sub(paid);
    if remainder > 0 {
        if let Some((_, first_share)) = out.first_mut() {
            *first_share = first_share.saturating_add(remainder);
        }
    }
    out
}

pub fn total_epoch_payout(payouts: &[(Address, u64)]) -> u64 {
    payouts
        .iter()
        .fold(0u64, |acc, (_, amount)| acc.saturating_add(*amount))
}

/// The keyless account the validation reward pool lives in. Its address is
/// a domain-separated hash, not a public key anyone holds, so only
/// [`pay_epoch`] moves its balance.
#[must_use]
pub fn reward_pool_account() -> Address {
    Address::from(crate::core::hash::hash_fields_bytes(&[
        b"BDLM_REWARD_POOL_ACCOUNT_V1",
    ]))
}

/// Pay `closed_epoch` from the pool account to the validators that are
/// active, not jailed and not slashed, by stake. Returns what was paid.
///
/// The amount is the consensus share of the schedule's per-epoch budget,
/// capped by the pool's balance, so the pool never pays what it does not
/// hold and nothing is minted. The storage share and the repair and relay
/// share stay in the pool account. A jailed validator is paid nothing for
/// the epoch.
pub fn pay_epoch(
    state: &mut crate::core::account::AccountState,
    schedule: &RewardPoolSchedule,
    closed_epoch: u64,
) -> u64 {
    if schedule.validate().is_err() {
        return 0;
    }
    let pool = reward_pool_account();
    let eligible: Vec<(Address, u64)> = state
        .validators
        .iter()
        .filter(|(address, v)| {
            v.active
                && !v.jailed
                && !v.slashed
                && state
                    .registry
                    .is_active(address, crate::registry::role::roles::VALIDATOR)
        })
        .map(|(address, v)| (*address, v.stake))
        .collect();
    let payouts = reward_for_epoch(*schedule, closed_epoch, state.get_balance(&pool), &eligible);
    let mut paid = 0u64;
    for (address, amount) in payouts {
        if amount == 0 {
            continue;
        }
        let delegated = state.registry.delegated_stake(&address);
        // The rate in force for the epoch being paid: a reprice during that
        // epoch prices the next one, not the rewards that already accrued.
        let commission_ppm = state
            .registry
            .validator_commission_ppm_at(&address, closed_epoch);
        let delegated_reward = if delegated == 0 {
            0
        } else {
            (u128::from(amount) * u128::from(delegated)
                / u128::from(
                    state
                        .validators
                        .get(&address)
                        .map_or(amount, |v| v.stake)
                        .max(1),
                )) as u64
        };
        let commission =
            (u128::from(delegated_reward) * u128::from(commission_ppm) / 1_000_000u128) as u64;
        let validator_reward = amount
            .saturating_sub(delegated_reward)
            .saturating_add(commission);

        // The validator's self share and commission are paid first. A failed
        // overflow leaves the whole validator split unpaid rather than paying
        // delegators for a reward whose owner cannot receive its share.
        if state.try_add_balance(&address, validator_reward).is_err() {
            continue;
        }
        paid = paid.saturating_add(validator_reward);

        let delegator_budget = delegated_reward.saturating_sub(commission);
        if delegator_budget > 0 && delegated > 0 {
            // `delegations_for` returns one validator's contiguous slice of
            // the sorted delegation table, so this never walks another
            // validator's positions and the list is already in delegator
            // order - the order the split is defined in.
            let positions = state.registry.delegations_for(&address);
            let mut shares = Vec::with_capacity(positions.len());
            let mut distributed = 0u64;
            for (index, position) in positions.iter().enumerate() {
                let share = if index + 1 == positions.len() {
                    delegator_budget.saturating_sub(distributed)
                } else {
                    (u128::from(delegator_budget) * u128::from(position.amount)
                        / u128::from(delegated)) as u64
                };
                if share == 0 {
                    continue;
                }
                distributed = distributed.saturating_add(share);
                shares.push((position.delegator, share));
            }
            // The delegator shares are credited as claimable debts rather than
            // pushed into the balances: `ClaimRewards` is how they reach an
            // account, so a delegator cannot be paid twice and the payout is an
            // explicit, signed transaction. One merge for the whole validator,
            // not one table insert per position.
            if let Ok(credited) = state.registry.credit_claimable_rewards(address, &shares) {
                paid = paid.saturating_add(credited);
            }
        }
    }
    if paid > 0 {
        let account = state.get_or_create(&pool);
        account.balance = account.balance.saturating_sub(paid);
        state.mark_dirty(&pool);
    }
    paid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    #[test]
    fn reward_pool_default_schedule_valid() {
        let schedule = RewardPoolSchedule::default();
        assert!(schedule.validate().is_ok());
        assert_eq!(schedule.validation_reward_pool, bud(10_000_000));
        assert_eq!(schedule.treasury_pool, bud(2_000_000));
    }

    #[test]
    fn reward_pool_rejects_zero_epochs() {
        let schedule = RewardPoolSchedule {
            validation_pool_epochs: 0,
            ..Default::default()
        };
        assert_eq!(
            schedule.validate(),
            Err(RewardPoolError::EmptyEpochSchedule)
        );
    }

    #[test]
    fn reward_pool_rejects_pool_over_fixed_supply() {
        let schedule = RewardPoolSchedule {
            validation_reward_pool: BUD_TOTAL_SUPPLY,
            treasury_pool: 1,
            ..Default::default()
        };
        assert_eq!(
            schedule.validate(),
            Err(RewardPoolError::PoolExceedsFixedSupply)
        );
    }

    #[test]
    fn reward_pool_conserves_budget() {
        let schedule = RewardPoolSchedule {
            validation_reward_pool: 100,
            validation_pool_epochs: 10,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        // The epoch budget is 10; the consensus share of it is 4. The 70 / 30
        // split rounds to 2 and 1, and the remainder of 1 goes to the first
        // address.
        let payouts = reward_for_epoch(schedule, 0, 100, &[(addr(2), 30), (addr(1), 70)]);
        assert_eq!(total_epoch_payout(&payouts), 4);
        assert_eq!(payouts, vec![(addr(1), 3), (addr(2), 1)]);
    }

    #[test]
    fn reward_pool_rounding_remainder_deterministic() {
        let schedule = RewardPoolSchedule {
            validation_reward_pool: 10,
            validation_pool_epochs: 10,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        let payouts =
            reward_for_epoch(schedule, 0, 10, &[(addr(9), 1), (addr(1), 1), (addr(2), 1)]);
        assert_eq!(total_epoch_payout(&payouts), 1);
        assert_eq!(payouts[0], (addr(1), 1));
        assert_eq!(payouts[1], (addr(2), 0));
        assert_eq!(payouts[2], (addr(9), 0));
    }

    #[test]
    fn reward_pool_halts_before_start_or_empty() {
        let schedule = RewardPoolSchedule {
            reward_pool_start_epoch: 10,
            ..Default::default()
        };
        assert!(reward_for_epoch(schedule, 9, 100, &[(addr(1), 1)]).is_empty());
        assert!(reward_for_epoch(schedule, 10, 0, &[(addr(1), 1)]).is_empty());
    }

    #[test]
    fn reward_pool_ignores_zero_stake() {
        let schedule = RewardPoolSchedule {
            validation_reward_pool: 10,
            validation_pool_epochs: 10,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        let payouts = reward_for_epoch(schedule, 0, 10, &[(addr(1), 0), (addr(2), 5)]);
        assert_eq!(payouts, vec![(addr(2), 1)]);
    }

    fn funded_state(validators: &[(u8, u64, bool)]) -> crate::core::account::AccountState {
        let mut state = crate::core::account::AccountState::new();
        state.add_balance(&reward_pool_account(), bud(1_000));
        for (byte, stake, jailed) in validators {
            state.add_validator(addr(*byte), *stake);
            let v = state.get_validator_mut(&addr(*byte)).expect("added");
            v.active = true;
            v.jailed = *jailed;
        }
        state
    }

    #[test]
    fn an_epoch_moves_its_budget_from_the_pool_to_the_validators_by_stake() {
        let schedule = RewardPoolSchedule {
            validation_reward_pool: bud(100),
            validation_pool_epochs: 10,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        // Above the registry's `min_stake`, because a validator that is too
        // small to register is not an active member and earns nothing - the
        // payout reads the registry, not the validator table.
        let mut state = funded_state(&[(1, 3_000, false), (2, 1_000, false), (3, 1_000, true)]);
        let before = state.get_balance(&reward_pool_account())
            + state.get_balance(&addr(1))
            + state.get_balance(&addr(2))
            + state.get_balance(&addr(3));
        let paid = pay_epoch(&mut state, &schedule, 0);
        // The epoch budget is 10 BUD; the consensus share of it is 4 BUD.
        assert_eq!(paid, bud(4));
        // 3:1 by stake; the jailed validator is paid nothing.
        assert_eq!(state.get_balance(&addr(1)), bud(4) * 3 / 4);
        assert_eq!(state.get_balance(&addr(2)), bud(4) / 4);
        assert_eq!(state.get_balance(&addr(3)), 0);
        let after = state.get_balance(&reward_pool_account())
            + state.get_balance(&addr(1))
            + state.get_balance(&addr(2))
            + state.get_balance(&addr(3));
        assert_eq!(before, after, "the pool pays, nothing is minted");
    }

    #[test]
    fn delegation_rewards_are_split_after_validator_commission() {
        let validator = addr(1);
        let delegator = addr(2);
        let pool = reward_pool_account();
        let mut state = crate::core::account::AccountState::new();
        state.add_validator(validator, 1_000);
        // Set during epoch 0, so it prices epoch 1: the rate is prospective.
        // Set before the delegation exists, because the registry caps a first
        // rate at `max_commission_change_ppm_per_epoch` (1 %) once stake is
        // delegated; the 10 % rate below is what the split is measured
        // against, not what the cap would allow a validator with delegators
        // to take in one epoch.
        state.set_validator_commission(&validator, 100_000).unwrap();
        state.add_balance(&delegator, 100);
        state
            .delegate_to_validator(&delegator, &validator, 100)
            .unwrap();
        state.epoch_index = 1;
        state.add_balance(&pool, 1_100);
        let schedule = RewardPoolSchedule {
            validation_reward_pool: 1_100,
            validation_pool_epochs: 1,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        // The epoch budget is 1,100; the consensus share of it is 440, and the
        // other 660 stay in the pool.
        assert_eq!(pay_epoch(&mut state, &schedule, 1), 440);
        // The delegated share is 40; 10% is commission, so the validator
        // receives its 400 self share plus 4. The delegator's 36 is a
        // claimable debt until the delegator signs a claim.
        assert_eq!(state.get_balance(&validator), 404);
        assert_eq!(state.get_balance(&delegator), 0);
        assert_eq!(state.registry.claimable_reward(delegator, validator), 36);
        assert_eq!(
            state
                .claim_delegator_rewards(&delegator, &validator)
                .unwrap(),
            36
        );
        assert_eq!(state.get_balance(&delegator), 36);
        assert_eq!(state.get_balance(&pool), 660);
    }

    /// A reprice is prospective: a commission set in the block that closes an
    /// epoch does not tax the delegated share of rewards that already accrued.
    #[test]
    fn a_commission_set_in_the_closing_epoch_does_not_price_that_epoch() {
        let validator = addr(1);
        let delegator = addr(2);
        let pool = reward_pool_account();
        let mut state = crate::core::account::AccountState::new();
        state.add_validator(validator, 1_000);
        // The epoch being closed is 0; the new rate starts at epoch 1. As
        // above, the rate is set while nothing is delegated: the per-epoch
        // change cap bounds a first rate only for a validator that already
        // holds delegations, and what this test measures is the epoch the
        // rate starts pricing.
        state.set_validator_commission(&validator, 100_000).unwrap();
        state.add_balance(&delegator, 100);
        state
            .delegate_to_validator(&delegator, &validator, 100)
            .unwrap();
        assert_eq!(state.registry.validator_commission_ppm_at(&validator, 0), 0);
        assert_eq!(
            state.registry.validator_commission_ppm_at(&validator, 1),
            100_000
        );
        state.add_balance(&pool, 1_100);
        let schedule = RewardPoolSchedule {
            validation_reward_pool: 1_100,
            validation_pool_epochs: 1,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        // The consensus share of the 1,100 budget is 440.
        assert_eq!(pay_epoch(&mut state, &schedule, 0), 440);
        // No commission was in force for epoch 0, so the whole delegated
        // share of 40 is the delegator's claim and the validator keeps 400.
        assert_eq!(state.get_balance(&validator), 400);
        assert_eq!(state.registry.claimable_reward(delegator, validator), 40);
    }

    #[test]
    fn an_empty_pool_pays_nothing() {
        let schedule = RewardPoolSchedule::default();
        let mut state = funded_state(&[(1, 300, false)]);
        let pool = reward_pool_account();
        let balance = state.get_balance(&pool);
        let account = state.get_or_create(&pool);
        account.balance = 0;
        assert_eq!(pay_epoch(&mut state, &schedule, 0), 0);
        assert_eq!(state.get_balance(&addr(1)), 0);
        assert!(balance > 0);
    }

    /// : the epoch budget is split 40 percent consensus, 50 percent
    /// storage and 10 percent repair and relay (directive section 11.4), and
    /// the stake weighted payout of `pay_epoch` is the consensus share only.
    /// The other two shares stay in the pool account until their payers
    /// read them, so the pool is never paid out ahead of its work.
    #[test]
    fn pay_epoch_pays_only_the_consensus_share_of_the_budget() {
        let schedule = RewardPoolSchedule {
            validation_reward_pool: bud(100),
            validation_pool_epochs: 10,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        let mut state = funded_state(&[(1, 3_000, false), (2, 1_000, false)]);
        let pool_before = state.get_balance(&reward_pool_account());
        // The epoch budget is 10 BUD; the consensus share of it is 4 BUD.
        let paid = pay_epoch(&mut state, &schedule, 0);
        assert_eq!(paid, bud(4), "only the consensus share is paid out");
        assert_eq!(
            state.get_balance(&reward_pool_account()),
            pool_before - bud(4),
            "the storage and the repair and relay shares stay in the pool"
        );
    }

    /// The split of a budget is 40 / 50 / 10 (directive section 11.4).
    #[test]
    fn pool_split_is_40_50_10() {
        let split = EpochSplit::of(bud(100));
        assert_eq!(split.consensus, bud(40));
        assert_eq!(split.storage, bud(50));
        assert_eq!(split.repair_relay, bud(10));
        assert_eq!(CONSENSUS_SHARE_PPM, 400_000);
        assert_eq!(STORAGE_SHARE_PPM, 500_000);
        assert_eq!(REPAIR_RELAY_SHARE_PPM, 100_000);
    }

    /// The three shares always add up to the budget: the split neither mints
    /// nor burns a rounding remainder, and the remainder is paid by stake.
    #[test]
    fn pool_split_adds_up_to_the_budget() {
        let mut budgets: Vec<u64> = (0..2_000).collect();
        budgets.extend([
            bud(1),
            bud(100) + 7,
            DEFAULT_VALIDATION_REWARD_POOL,
            u64::MAX - 1,
            u64::MAX,
        ]);
        for budget in budgets {
            let split = EpochSplit::of(budget);
            let sum = u128::from(split.consensus)
                + u128::from(split.storage)
                + u128::from(split.repair_relay);
            assert_eq!(sum, u128::from(budget), "budget {budget}");
        }
        // 7 units: storage 3, repair and relay 0, consensus keeps the rest.
        assert_eq!(
            EpochSplit::of(7),
            EpochSplit {
                consensus: 4,
                storage: 3,
                repair_relay: 0,
            }
        );
    }

    /// The interface  reads: the storage share of the epoch budget, the
    /// same value `split_epoch_budget` holds back.
    #[test]
    fn storage_share_is_half_of_the_epoch_budget() {
        let schedule = RewardPoolSchedule {
            validation_reward_pool: bud(100),
            validation_pool_epochs: 10,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        assert_eq!(storage_share(&schedule, 0, bud(100)), bud(5));
        assert_eq!(
            storage_share(&schedule, 0, bud(100)),
            schedule.split_epoch_budget(0, bud(100)).storage
        );
        // Before the start epoch, and with an empty pool, nothing is held.
        let late = RewardPoolSchedule {
            reward_pool_start_epoch: 10,
            ..schedule
        };
        assert_eq!(storage_share(&late, 9, bud(100)), 0);
        assert_eq!(storage_share(&schedule, 0, 0), 0);
    }
}
