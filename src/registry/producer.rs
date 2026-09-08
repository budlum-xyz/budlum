//! E4: Open Producer Registration & Incentive Mechanism.
//!
//! Enables permissionless registration of data and block producers via bond staking,
//! stake-weighted scheduling, and performance reward tracking.

use crate::core::address::Address;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

const MIN_PRODUCER_BOND: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProducerEntry {
    pub producer: Address,
    pub bond: u64,
    pub registered_at_epoch: u64,
    pub blocks_produced: u64,
    pub manifests_served: u64,
    pub active: bool,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct ProducerRegistry {
    pub producers: BTreeMap<Address, ProducerEntry>,
    pub total_producer_bond: u64,
}

impl ProducerRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            producers: BTreeMap::new(),
            total_producer_bond: 0,
        }
    }

    /// # Errors
    ///
    /// A string finding when the bond is below [`MIN_PRODUCER_BOND`] or the
    /// producer is already registered.
    pub fn register(
        &mut self,
        producer: Address,
        bond: u64,
        epoch: u64,
        endpoint: String,
    ) -> Result<(), String> {
        if bond < MIN_PRODUCER_BOND {
            return Err(format!("Insufficient bond: {bond} < {MIN_PRODUCER_BOND}"));
        }
        if self.producers.contains_key(&producer) {
            return Err("Producer already registered".to_string());
        }
        self.producers.insert(
            producer,
            ProducerEntry {
                producer,
                bond,
                registered_at_epoch: epoch,
                blocks_produced: 0,
                manifests_served: 0,
                active: true,
                endpoint,
            },
        );
        self.total_producer_bond = self.total_producer_bond.saturating_add(bond);
        Ok(())
    }

    fn record_production(&mut self, producer: &Address) -> bool {
        if let Some(entry) = self.producers.get_mut(producer) {
            if entry.active {
                entry.blocks_produced = entry.blocks_produced.saturating_add(1);
                return true;
            }
        }
        false
    }

    #[must_use]
    fn select_producer(&self, seed: &Hash32) -> Option<Address> {
        let active_producers: Vec<&ProducerEntry> =
            self.producers.values().filter(|p| p.active).collect();
        if active_producers.is_empty() || self.total_producer_bond == 0 {
            return None;
        }
        let mut seed_num = 0u64;
        for &b in seed.iter().take(8) {
            seed_num = (seed_num << 8) | u64::from(b);
        }
        }
        let target = seed_num % self.total_producer_bond;
        let mut acc = 0u64;
        for p in active_producers {
            acc = acc.saturating_add(p.bond);
            if acc > target {
                return Some(p.producer);
            }
        }
        self.producers.keys().next().copied()
    }

    #[must_use]
    fn root_hash(&self) -> Hash32 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_PRODUCER_REGISTRY_V1");
        for (addr, p) in &self.producers {
            hasher.update(addr.0);
            hasher.update(p.bond.to_le_bytes());
            hasher.update(p.blocks_produced.to_le_bytes());
            hasher.update([u8::from(p.active)]);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_registration_and_selection() {
        let mut reg = ProducerRegistry::new();
        let alice = Address::from([0x01u8; 32]);
        let bob = Address::from([0x02u8; 32]);

        assert!(reg
            .register(alice, 5000, 1, "https://alice.node".into())
            .is_err());
        assert!(reg
            .register(alice, 10000, 1, "https://alice.node".into())
            .is_ok());
        assert!(reg
            .register(bob, 20000, 1, "https://bob.node".into())
            .is_ok());

        assert_eq!(reg.total_producer_bond, 30000);
        let selected = reg.select_producer(&[0x12; 32]);
        assert!(selected.is_some());
    }
}
