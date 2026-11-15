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

/// Assemble and check the genesis of `network` from the ceremony inputs.
///
/// The validators are sorted by address, so the result, and its hash, do
/// not depend on the order the records were collected in.
///
/// # Errors
///
/// A duplicate validator, or any refusal of
/// `validate_consensus_ceremony`: fewer than four validators, a record whose
/// keys or proof of possession do not verify for this chain and address, or
/// a distribution that does not hold the fixed supply.
pub fn assemble(network: Network, inputs: CeremonyInputs) -> Result<GenesisConfig, String> {
    let mut operators = inputs.operators;
    operators.sort_by_key(|record| record.validator);
    if operators
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a.validator == b.validator))
    {
        return Err("two operator records name the same validator".into());
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
    fn four_operators_assemble_a_testnet_genesis_with_active_validators() {
        let records = operators(4);
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
            ecosystem - 4 * stake - pool
        );
        assert_eq!(
            state.get_balance(&crate::tokenomics::reward_pool::reward_pool_account()),
            pool
        );
    }

    #[test]
    fn the_hash_does_not_depend_on_the_order_of_the_records() {
        let records = operators(4);
        let mut reversed = records.clone();
        reversed.reverse();
        let a = assemble(Network::Testnet, inputs(records)).expect("assembles");
        let b = assemble(Network::Testnet, inputs(reversed)).expect("assembles");
        assert_eq!(genesis_hash(&a), genesis_hash(&b));
    }

    #[test]
    fn fewer_than_four_operators_are_refused() {
        let err = assemble(Network::Testnet, inputs(operators(3))).unwrap_err();
        assert!(err.contains("at least four"), "{err}");
    }

    #[test]
    fn a_record_for_another_chain_is_refused() {
        let mut records = operators(3);
        let keys = ValidatorKeys::generate().expect("keys generate");
        records.push(OperatorRecord {
            validator: keys.address(),
            // The proof of possession is bound to the devnet chain id.
            registration: keys.consensus_key_registration(45262).expect("registers"),
            moniker: String::new(),
        });
        assert!(assemble(Network::Testnet, inputs(records)).is_err());
    }

    #[test]
    fn a_duplicate_validator_is_refused() {
        let mut records = operators(4);
        records.push(records[0].clone());
        let err = assemble(Network::Testnet, inputs(records)).unwrap_err();
        assert!(err.contains("same validator"), "{err}");
    }

    #[test]
    fn an_allocation_beyond_the_fixed_supply_is_refused() {
        let mut ceremony = inputs(operators(4));
        ceremony.allocations = vec![(Address::from([0x77; 32]), 1)];
        assert!(assemble(Network::Testnet, ceremony).is_err());
    }
}
