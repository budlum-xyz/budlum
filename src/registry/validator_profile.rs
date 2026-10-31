//! Validator profiles for the operator market.
//!
//! A profile states facts the chain holds and nothing else: bonded stake and
//! how much of it is delegated, the commission and when it last changed, the
//! jail and slash record, and the checkpoints the liveness tracker counted as
//! missed. There is no score, no ranking and no yield figure: a delegator
//! reads what happened, not a promise of what will.
//!
//! The declared region and hardware tier have no transaction door yet, so a
//! profile reports them as undeclared rather than inventing a value.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::registry::role::roles;

fn hex0x(address: &Address) -> String {
    format!("0x{}", address.to_hex())
}

/// The profile of `address`, or `None` when it is not a validator.
#[must_use]
pub fn validator_profile(state: &AccountState, address: &Address) -> Option<serde_json::Value> {
    let validator = state.validators.get(address)?;
    let registry = &state.registry;
    let delegated = registry.delegated_stake(address);
    let delegators = registry.delegations_for(address).len();
    let pending_exit = registry
        .delegation_unbonding_for(address)
        .iter()
        .fold(0u64, |total, entry| total.saturating_add(entry.amount));
    // The live rate, read through the registry accessor: one place states
    // what a validator charges today, and the profile is the caller that
    // shows it to a delegator.
    let commission_ppm = registry.validator_commission_ppm(address);
    let commission = registry.validator_commission(address);
    let slashes: Vec<serde_json::Value> = registry
        .slashing_history_for(address)
        .into_iter()
        .map(|record| {
            serde_json::json!({
                "condition": format!("{:?}", record.report.condition()),
                "penalty": record.penalty,
                "remainingStake": record.remaining_stake,
            })
        })
        .collect();
    Some(serde_json::json!({
        "address": hex0x(address),
        "stake": validator.stake,
        "selfStake": validator.stake.saturating_sub(delegated),
        "delegatedStake": delegated,
        "delegators": delegators,
        "pendingDelegationExit": pending_exit,
        "commissionPpm": commission_ppm,
        "commissionLastChangeEpoch": commission.map(|c| c.last_change_epoch),
        // The first epoch the live rate prices, so a delegator can see a
        // change before it taxes their rewards.
        "commissionEffectiveEpoch": registry.validator_commission_effective_epoch(address),
        "active": validator.active,
        "eligible": validator.is_eligible(state.epoch_index),
        "registeredValidatorRole": registry.is_active(address, roles::VALIDATOR),
        "consensusKeysRegistered": !validator.bls_public_key.is_empty(),
        "jailed": validator.jailed,
        "jailUntilEpoch": validator.jail_until,
        "slashed": validator.slashed,
        "slashCount": slashes.len(),
        "slashes": slashes,
        "missedCheckpoints": state.liveness.missed_count(address),
        "lastProposedBlock": validator.last_proposed_block,
        "declaredRegion": serde_json::Value::Null,
        "declaredHardwareTier": serde_json::Value::Null,
    }))
}

/// Every validator's profile, in address order.
#[must_use]
pub fn validator_profiles(state: &AccountState) -> Vec<serde_json::Value> {
    state
        .validators
        .keys()
        .filter_map(|address| validator_profile(state, address))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_states_bond_delegation_and_commission_facts() {
        let validator = Address::from([0x61; 32]);
        let delegator = Address::from([0x62; 32]);
        let mut state = AccountState::new();
        state.add_validator(validator, 10_000);
        // The rate is set before the delegation exists, because the registry
        // caps a first rate at `max_commission_change_ppm_per_epoch` once
        // stake is delegated (a validator holding delegators cannot jump from
        // 0 to a high rate in one epoch and take the jump out of their next
        // payout). The profile states the rate that is in force either way;
        // what is being pinned here is that it reports 5 %, not which epoch
        // the registry would have allowed it in.
        state.set_validator_commission(&validator, 50_000).unwrap();
        state.add_balance(&delegator, 500);
        state
            .delegate_to_validator(&delegator, &validator, 500)
            .unwrap();

        let profile = validator_profile(&state, &validator).unwrap();
        assert_eq!(profile["stake"], 10_500);
        assert_eq!(profile["selfStake"], 10_000);
        assert_eq!(profile["delegatedStake"], 500);
        assert_eq!(profile["delegators"], 1);
        assert_eq!(profile["commissionPpm"], 50_000);
        assert_eq!(profile["slashCount"], 0);
        assert!(profile["declaredRegion"].is_null());
        assert!(profile.get("score").is_none() && profile.get("apy").is_none());

        assert!(validator_profile(&state, &delegator).is_none());
        assert_eq!(validator_profiles(&state).len(), 1);
    }
}
