use crate::bns::types::{BnsError, NameRecord};
use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BnsRegistry {
    /// name -> record
    pub names: BTreeMap<String, NameRecord>,
    pub base_cost: u64, // Cost per epoch
}

impl BnsRegistry {
    pub fn new() -> Self {
        Self {
            names: BTreeMap::new(),
            base_cost: 100,
        }
    }

    pub fn register(
        &mut self,
        name: String,
        owner: Address,
        current_epoch: u64,
        duration: u64,
    ) -> Result<(), BnsError> {
        if name.len() < 3 || name.len() > 32 {
            return Err(BnsError::InvalidName);
        }
        if self.names.contains_key(&name) {
            let record = self.names.get(&name).unwrap();
            if record.expires_at > current_epoch {
                return Err(BnsError::NameTaken);
            }
        }

        let record = NameRecord {
            name: name.clone(),
            owner,
            expires_at: current_epoch + duration,
            resolver: None,
        };
        self.names.insert(name, record);
        Ok(())
    }

    pub fn resolve(&self, name: &str, current_epoch: u64) -> Option<Address> {
        self.names.get(name).and_then(|record| {
            if record.expires_at > current_epoch {
                Some(record.owner)
            } else {
                None
            }
        })
    }
}
