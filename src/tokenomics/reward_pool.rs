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

use crate::core::address::Address;
use crate::tokenomics::{bud, BUD_TOTAL_SUPPLY};
use serde::{Deserialize, Serialize};

/// Default decision: 10% of the fixed 100M supply.
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
/// Stakes. The first address in sorted order receives the rounding remainder.
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
    // BLG-0079 (P03-F22): one address, one share. A repeated row used to be
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
/// The budget is the schedule's per-epoch share, capped by the pool's
/// balance, so the pool never pays what it does not hold and nothing is
/// minted. A jailed validator is paid nothing for the epoch.
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
        let commission_ppm = state.registry.validator_commission_ppm(&address);
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
            let mut positions = state.registry.delegations_for(&address);
            positions.sort_by_key(|position| position.delegator);
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
                // The delegator share is credited as a claimable debt rather
                // than pushed into the balance: `ClaimRewards` is how it
                // reaches the account, so a delegator cannot be paid twice and
                // the payout is an explicit, signed transaction.
                if state
                    .registry
                    .credit_claimable_reward(position.delegator, address, share)
                    .is_ok()
                {
                    distributed = distributed.saturating_add(share);
                    paid = paid.saturating_add(share);
                }
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
        let payouts = reward_for_epoch(schedule, 0, 100, &[(addr(2), 30), (addr(1), 70)]);
        assert_eq!(total_epoch_payout(&payouts), 10);
        assert_eq!(payouts, vec![(addr(1), 7), (addr(2), 3)]);
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
        let mut state = funded_state(&[(1, 300, false), (2, 100, false), (3, 100, true)]);
        let before = state.get_balance(&reward_pool_account())
            + state.get_balance(&addr(1))
            + state.get_balance(&addr(2))
            + state.get_balance(&addr(3));
        let paid = pay_epoch(&mut state, &schedule, 0);
        assert_eq!(paid, bud(10));
        // 3:1 by stake; the jailed validator is paid nothing.
        assert_eq!(state.get_balance(&addr(1)), bud(10) * 3 / 4);
        assert_eq!(state.get_balance(&addr(2)), bud(10) / 4);
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
        state.add_balance(&delegator, 100);
        state
            .delegate_to_validator(&delegator, &validator, 100)
            .unwrap();
        state.set_validator_commission(&validator, 100_000).unwrap();
        state.add_balance(&pool, 1_100);
        let schedule = RewardPoolSchedule {
            validation_reward_pool: 1_100,
            validation_pool_epochs: 1,
            treasury_pool: 0,
            reward_pool_start_epoch: 0,
        };
        assert_eq!(pay_epoch(&mut state, &schedule, 0), 1_100);
        // The delegated share is 100; 10% is commission, so the validator
        // receives its 1,000 self share plus 10. The delegator's 90 is a
        // claimable debt until the delegator signs a claim.
        assert_eq!(state.get_balance(&validator), 1_010);
        assert_eq!(state.get_balance(&delegator), 0);
        assert_eq!(state.registry.claimable_reward(delegator, validator), 90);
        assert_eq!(
            state
                .claim_delegator_rewards(&delegator, &validator)
                .unwrap(),
            90
        );
        assert_eq!(state.get_balance(&delegator), 90);
        assert_eq!(state.get_balance(&pool), 0);
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
}
