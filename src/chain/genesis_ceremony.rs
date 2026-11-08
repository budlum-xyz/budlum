//! The genesis ceremony.
//!
//! Each operator generates its validator keys on its own machine
//! (`bud validator init`) and publishes an [`OperatorRecord`]: the validator
//! address and the public consensus-key registration (VRF key, BLS key with
//! its proof of possession bound to the chain and the address, PQ key). The
//! coordinator assembles the genesis from the network template, the records
//! and the destination accounts, checks it with
//! `GenesisConfig::validate_consensus_ceremony`, and publishes the file and
//! its hash. Nothing secret passes through the ceremony, and every input is
//! public, so any operator can repeat the assembly and compare the hash.

use crate::chain::genesis::GenesisConfig;
use crate::core::address::Address;
use crate::core::chain_config::Network;
use crate::core::transaction::ConsensusKeyRegistration;
use crate::tokenomics::TokenomicsAddresses;
use serde::{Deserialize, Serialize};

/// One operator's public contribution to the ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRecord {
    /// The validator's account address (its signing key).
    pub validator: Address,
    /// The public consensus keys and the proof of possession.
    pub registration: ConsensusKeyRegistration,
    /// A display name. Not part of the genesis.
    #[serde(default)]
    pub moniker: String,
}

/// Everything the coordinator supplies besides the operator records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyInputs {
    /// The operator records, in any order.
    pub operators: Vec<OperatorRecord>,
    /// The five distribution destinations. On the testnet the faucet account
    /// is the `community` destination.
    pub tokenomics_addresses: TokenomicsAddresses,
    /// The genesis timestamp in milliseconds; the template's when absent.
    pub timestamp_ms: Option<u128>,
    /// Extra genesis balances, on top of the template's. With a tokenomics
    /// distribution the fixed supply leaves no room for any, and the
    /// ceremony check refuses them; the devnet rehearsal funds a validator
    /// that joins later this way.
    pub allocations: Vec<(Address, u64)>,
}

/// A published testnet/mainnet ceremony needs eight full validators.
/// The chain-level floor in `genesis.rs` stays 3f+1 = four; the devnet
/// rehearsal keeps that smaller form.
const MIN_CEREMONY_VALIDATORS: usize = 8;

/// The single `u128` supply audit of a ceremony genesis. Every source is
/// named exactly once: the five distribution
/// categories, extra allocations, validator stakes and the pre-funded
/// validation pool. With a tokenomics distribution the stakes and the pool
/// are drawn from the ecosystem category, so they are reported as deductions
/// from that category, never added to the total a second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyAudit {
    pub categories: u128,
    pub extra_allocations: u128,
    pub validator_stake: u128,
    pub validation_pool: u128,
    pub total: u128,
    pub fixed_supply: u128,
}

/// Audit the genesis the ceremony is about to publish.
///
/// # Errors
///
/// Names the total when it exceeds the fixed supply, the ecosystem category
/// when the stakes and pool do not fit inside it, or an unknown chain id.
pub fn supply_audit(genesis: &GenesisConfig) -> Result<SupplyAudit, String> {
    let network = Network::from_chain_id(genesis.chain_id)
        .ok_or_else(|| format!("unknown chain id {}", genesis.chain_id))?;
    let params = genesis.bud_tokenomics.as_ref();
    let categories = u128::from(params.map_or(0, |p| p.total()));
    let extra_allocations: u128 = genesis
        .allocations
        .iter()
        .map(|(_, amount)| u128::from(*amount))
        .sum();
    // Fold rather than cast a `usize` count into `u128`: the sum stays
    // independent of the host word size.
    let validator_stake = genesis
        .validators
        .iter()
        .fold(0u128, |sum, _| sum.saturating_add(u128::from(network.min_stake())));
    let validation_pool = u128::from(
        network
            .reward_pool()
            .map_or(0, |schedule| schedule.validation_reward_pool),
    );
    let total = match params {
        Some(p) => {
            let ecosystem = u128::from(p.ecosystem);
            if validator_stake.saturating_add(validation_pool) > ecosystem {
                return Err(format!(
                    "genesis stakes {validator_stake} and pool {validation_pool} exceed the ecosystem category {ecosystem}"
                ));
            }
            categories.saturating_add(extra_allocations)
        }
        None => categories
            .saturating_add(extra_allocations)
            .saturating_add(validator_stake),
    };
    let fixed_supply = u128::from(crate::tokenomics::BUD_TOTAL_SUPPLY);
    if total > fixed_supply {
        return Err(format!(
            "genesis supply audit totals {total} atoms, above the fixed supply {fixed_supply}"
        ));
    }
    Ok(SupplyAudit {
        categories,
        extra_allocations,
        validator_stake,
        validation_pool,
        total,
        fixed_supply,
    })
}

/// Assemble and check the genesis of `network` from the ceremony inputs.
///
/// The validators are sorted by address, so the result, and its hash, do
/// not depend on the order the records were collected in. The tool also
/// produces the single `u128` supply audit report.
///
/// # Errors
///
/// A duplicate validator, fewer than eight full validators on a published
/// network, a supply audit that does not hold the fixed supply, or any
/// refusal of `validate_consensus_ceremony`: a record whose keys or proof of
/// possession do not verify for this chain and address, or a distribution
/// that does not hold the fixed supply.
pub fn assemble(network: Network, inputs: CeremonyInputs) -> Result<GenesisConfig, String> {
    let mut operators = inputs.operators;
    operators.sort_by_key(|record| record.validator);
    if operators
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a.validator == b.validator))
    {
        return Err("two operator records name the same validator".into());
    }
    if matches!(network, Network::Mainnet | Network::Testnet)
        && operators.len() < MIN_CEREMONY_VALIDATORS
    {
        return Err(format!(
            "{network} ceremony requires at least eight full validators, got {}",
            operators.len()
        ));
    }
    let mut genesis = GenesisConfig::for_network(network);
    genesis.validators = operators.iter().map(|record| record.validator).collect();
    genesis.validator_consensus_keys = operators
        .into_iter()
        .map(|record| crate::chain::genesis::GenesisConsensusKeys {
            validator: record.validator,
            registration: record.registration,
        })
        .collect();
    genesis.tokenomics_addresses = Some(inputs.tokenomics_addresses);
    genesis.allocations.extend(inputs.allocations);
    if let Some(timestamp) = inputs.timestamp_ms {
        genesis.timestamp = timestamp;
    }
    supply_audit(&genesis)?;
    genesis.validate_consensus_ceremony(network)?;
    Ok(genesis)
}

/// The hash of the genesis block `genesis` builds: what every operator
/// compares before starting its node.
#[must_use]
pub fn genesis_hash(genesis: &GenesisConfig) -> String {
    genesis.build_genesis_block().hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::primitives::ValidatorKeys;

    const TESTNET: u64 = 45261;

    fn record(keys: &ValidatorKeys) -> OperatorRecord {
        OperatorRecord {
            validator: keys.address(),
            registration: keys
                .consensus_key_registration(TESTNET)
                .expect("a full key set registers"),
            moniker: String::new(),
        }
    }

    fn destinations() -> TokenomicsAddresses {
        TokenomicsAddresses {
            community: Address::from([0x51; 32]),
            liquidity: Address::from([0x52; 32]),
            ecosystem: Address::from([0x53; 32]),
            team: Address::from([0x54; 32]),
            burn_reserve: Address::from([0x55; 32]),
        }
    }

    fn inputs(operators: Vec<OperatorRecord>) -> CeremonyInputs {
        CeremonyInputs {
            operators,
            tokenomics_addresses: destinations(),
            timestamp_ms: Some(1_800_000_000_000),
            allocations: Vec::new(),
        }
    }

    fn operators(n: usize) -> Vec<OperatorRecord> {
        (0..n)
            .map(|_| record(&ValidatorKeys::generate().expect("keys generate")))
            .collect()
    }

    #[test]
    fn eight_operators_assemble_a_testnet_genesis_with_active_validators() {
        let records = operators(8);
        let genesis = assemble(Network::Testnet, inputs(records.clone())).expect("assembles");
        let state = genesis.build_state();
        let stake = Network::Testnet.min_stake();
        for record in &records {
            let entry = state
                .validators
                .get(&record.validator)
                .expect("a genesis validator");
            assert!(entry.active, "complete keys make the validator active");
            assert_eq!(entry.stake, stake);
        }
        // The stake and the reward pool come out of the ecosystem share: the
        // genesis holds the fixed supply and no more.
        let ecosystem = genesis
            .bud_tokenomics
            .expect("testnet tokenomics")
            .ecosystem;
        let pool = Network::Testnet
            .reward_pool()
            .expect("the testnet pays from a pool")
            .validation_reward_pool;
        assert_eq!(
            state.get_balance(&destinations().ecosystem),
            ecosystem - 8 * stake - pool
        );
        assert_eq!(
            state.get_balance(&crate::tokenomics::reward_pool::reward_pool_account()),
            pool
        );
    }

    #[test]
    fn the_hash_does_not_depend_on_the_order_of_the_records() {
        let records = operators(8);
        let mut reversed = records.clone();
        reversed.reverse();
        let a = assemble(Network::Testnet, inputs(records)).expect("assembles");
        let b = assemble(Network::Testnet, inputs(reversed)).expect("assembles");
        assert_eq!(genesis_hash(&a), genesis_hash(&b));
    }

    #[test]
    fn the_published_network_ceremony_floor_is_eight() {
        let err = assemble(Network::Testnet, inputs(operators(7))).unwrap_err();
        assert!(err.contains("at least eight"), "{err}");
    }

    #[test]
    fn a_record_for_another_chain_is_refused() {
        // Seven good records plus one wrong-chain record: the ceremony floor
        // is met, so the refusal still comes from the proof of possession.
        let mut records = operators(7);
        let keys = ValidatorKeys::generate().expect("keys generate");
        records.push(OperatorRecord {
            validator: keys.address(),
            // The proof of possession is bound to the devnet chain id.
            registration: keys.consensus_key_registration(45262).expect("registers"),
            moniker: String::new(),
        });
        assert!(assemble(Network::Testnet, inputs(records)).is_err());
    }

    /// The ceremony floor is eight even though the chain-level 3f+1 floor is four.
    #[test]
    fn ceremony_refuses_fewer_than_eight_full_validators() {
        let err = assemble(Network::Testnet, inputs(operators(7))).unwrap_err();
        assert!(err.contains("at least eight"), "{err}");
        let genesis = assemble(Network::Testnet, inputs(operators(8))).expect("assembles");
        assert_eq!(genesis.validators.len(), 8);
    }

    /// One `u128` audit names every source and refuses excess allocation.
    #[test]
    fn genesis_supply_audit_counts_every_source() {
        let genesis = assemble(Network::Testnet, inputs(operators(8))).expect("assembles");
        let audit = supply_audit(&genesis).expect("audits");
        let fixed = u128::from(crate::tokenomics::BUD_TOTAL_SUPPLY);
        assert_eq!(audit.fixed_supply, fixed);
        assert_eq!(audit.categories, fixed);
        assert_eq!(audit.total, fixed);
        assert_eq!(audit.extra_allocations, 0);
        assert_eq!(
            audit.validator_stake,
            u128::from(Network::Testnet.min_stake()) * 8
        );
        assert!(audit.validation_pool > 0);
        // Stakes and the pool are drawn from the ecosystem category; they
        // are not minted on top of the distribution.
        let ecosystem = u128::from(
            genesis
                .bud_tokenomics
                .as_ref()
                .expect("testnet tokenomics")
                .ecosystem,
        );
        assert!(audit.validator_stake + audit.validation_pool < ecosystem);
        // An extra allocation is counted in the same `u128` total and
        // refused instead of silently minting past the fixed supply.
        let mut inflated = genesis.clone();
        inflated.allocations.push((Address::from([0x77; 32]), 1));
        let err = supply_audit(&inflated).unwrap_err();
        assert!(err.contains("fixed supply"), "{err}");
    }

    #[test]
    fn a_duplicate_validator_is_refused() {
        let mut records = operators(8);
        records.push(records[0].clone());
        let err = assemble(Network::Testnet, inputs(records)).unwrap_err();
        assert!(err.contains("same validator"), "{err}");
    }

    #[test]
    fn an_allocation_beyond_the_fixed_supply_is_refused() {
        let mut ceremony = inputs(operators(8));
        ceremony.allocations = vec![(Address::from([0x77; 32]), 1)];
        assert!(assemble(Network::Testnet, ceremony).is_err());
    }
}
