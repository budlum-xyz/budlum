//! Phase 11.8 — genesis validation reward pool primitives.
//!
//! Rewards are paid from a pre-allocated pool, not by minting new BUD. This
//! module keeps the schedule pure/deterministic so economy invariant tests can
//! reason about supply conservation before the full executor wiring lands.

use crate::core::address::Address;
use crate::tokenomics::{bud, BUD_TOTAL_SUPPLY};
use serde::{Deserialize, Serialize};

/// Default Phase 11.6 decision: 10% of the fixed 100M supply.
pub const DEFAULT_VALIDATION_REWARD_POOL: u64 = bud(10_000_000);
/// Default treasury side-pool (2%) tracked separately from validator rewards.
pub const DEFAULT_TREASURY_POOL: u64 = bud(2_000_000);
pub const DEFAULT_VALIDATION_POOL_EPOCHS: u64 = 100_000;

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
}

/// Deterministically split `remaining_pool` for one epoch across active validator
/// stakes. The first address in sorted order receives the rounding remainder.
pub fn reward_for_epoch(
    schedule: RewardPoolSchedule,
    epoch: u64,
    remaining_pool: u64,
    active_validator_stakes: &[(Address, u64)],
) -> Vec<(Address, u64)> {
    let budget = schedule.per_epoch_budget(epoch, remaining_pool);
    if budget == 0 || active_validator_stakes.is_empty() {
        return Vec::new();
    }

    let mut validators: Vec<(Address, u64)> = active_validator_stakes
        .iter()
        .copied()
        .filter(|(_, stake)| *stake > 0)
        .collect();
    validators.sort_by_key(|(addr, _)| *addr);

    let total_stake: u128 = validators.iter().map(|(_, stake)| *stake as u128).sum();
    if total_stake == 0 {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(validators.len());
    let mut paid = 0u64;
    for (addr, stake) in validators {
        let share = ((budget as u128) * (stake as u128) / total_stake) as u64;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    #[test]
    fn default_schedule_is_valid_and_preallocated() {
        let schedule = RewardPoolSchedule::default();
        assert!(schedule.validate().is_ok());
        assert_eq!(schedule.validation_reward_pool, bud(10_000_000));
        assert_eq!(schedule.treasury_pool, bud(2_000_000));
    }

    #[test]
    fn schedule_rejects_zero_epochs() {
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
    fn schedule_rejects_pool_over_fixed_supply() {
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
    fn rewards_are_stake_proportional_and_conserve_budget() {
        let schedule = RewardPoolSchedule {
            validation_reward_pool: 100,
            validation_pool_epochs: 10,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        let payouts = reward_for_epoch(schedule, 0, 100, &[(addr(2), 30), (addr(1), 70)]);
        assert_eq!(total_epoch_payout(&payouts), 10);
        assert_eq!(payouts, vec![(addr(1), 7), (addr(2), 3)]);
    }

    #[test]
    fn rounding_remainder_goes_to_lowest_address() {
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
    fn no_rewards_before_start_or_after_pool_empty() {
        let schedule = RewardPoolSchedule {
            reward_pool_start_epoch: 10,
            ..Default::default()
        };
        assert!(reward_for_epoch(schedule, 9, 100, &[(addr(1), 1)]).is_empty());
        assert!(reward_for_epoch(schedule, 10, 0, &[(addr(1), 1)]).is_empty());
    }

    #[test]
    fn zero_stake_validators_are_ignored() {
        let schedule = RewardPoolSchedule {
            validation_reward_pool: 10,
            validation_pool_epochs: 10,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        let payouts = reward_for_epoch(schedule, 0, 10, &[(addr(1), 0), (addr(2), 5)]);
        assert_eq!(payouts, vec![(addr(2), 1)]);
    }
}
