use crate::bns::types::{BnsError, BnsResolved, NameRecord};
use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BnsRegistry {
    pub names: BTreeMap<String, NameRecord>,
    pub base_cost: u64,
}

impl BnsRegistry {
    /// F14 (Phase 10.5): isim expire olduktan sonra eski owner'ın yenileme
    /// penceresi (epoch sayısı). Bu süre içinde 3. taraf register edemez
    /// (squatting/front-running koruması). ~30 günlük epoch (~100 epoch/gün).
    pub const GRACE_PERIOD: u64 = 3000;

    pub fn new() -> Self {
        Self {
            names: BTreeMap::new(),
            base_cost: 100,
        }
    }

    pub fn calculate_cost(&self, name: &str, duration: u64) -> u64 {
        let length = name.len();
        let multiplier = match length {
            1..=3 => 100,
            4..=6 => 10,
            _ => 1,
        };
        let base = self.base_cost * multiplier * duration;
        if multiplier >= 10 || duration >= 100 {
            base * 2
        } else {
            base
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
        if let Some(record) = self.names.get(&name) {
            if record.expires_at > current_epoch {
                return Err(BnsError::NameTaken);
            }
            // F14 (Phase 10.5): grace-period — expire olmuş isim, eski owner'a
            // yenileme penceresi tanır. `current_epoch < expires_at + GRACE_PERIOD`
            // içinde yalnızca eski owner register/renew yapabilir; böylece
            // front-running squatting (3. tarafın expired ismi kapması) engellenir.
            let grace_until = record.expires_at.saturating_add(Self::GRACE_PERIOD);
            if current_epoch < grace_until && record.owner != owner {
                return Err(BnsError::NameTaken);
            }
        }
        let record = NameRecord::new(name.clone(), owner, current_epoch + duration);
        self.names.insert(name, record);
        Ok(())
    }

    /// Renew an existing name registration. Only the current owner may renew
    /// and only while the record is still live (not expired). The new expiry
    /// extends from the current expiry — never from `current_epoch` — so
    /// renewing early never shortens the registration.
    pub fn renew(
        &mut self,
        name: &str,
        caller: &Address,
        current_epoch: u64,
        duration: u64,
    ) -> Result<(), BnsError> {
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        if &record.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if record.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        record.expires_at = record
            .expires_at
            .checked_add(duration)
            .ok_or(BnsError::InvalidName)?;
        Ok(())
    }

    /// Transfer ownership of a live (non-expired) name to a new owner. Only
    /// the current owner may transfer. Resolver/content bindings and existing
    /// subdomain mappings are preserved; after the transfer the previous
    /// owner loses all control over the record.
    pub fn transfer(
        &mut self,
        name: &str,
        caller: &Address,
        new_owner: Address,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        if &record.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if record.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        record.owner = new_owner;
        Ok(())
    }

    pub fn register_subdomain(
        &mut self,
        parent_name: &str,
        sub_label: String,
        owner: Address,
        caller: &Address,
    ) -> Result<(), BnsError> {
        let parent = self
            .names
            .get_mut(parent_name)
            .ok_or(BnsError::InvalidName)?;
        if &parent.owner != caller {
            return Err(BnsError::NotOwner);
        }
        parent.subdomains.insert(sub_label, owner);
        Ok(())
    }

    pub fn resolve_subdomain(
        &self,
        parent_name: &str,
        sub_label: &str,
        current_epoch: u64,
    ) -> Option<Address> {
        let parent = self.names.get(parent_name)?;
        if parent.expires_at > current_epoch {
            parent.subdomains.get(sub_label).cloned()
        } else {
            None
        }
    }

    pub fn set_content(
        &mut self,
        name: &str,
        owner: &Address,
        cid: ContentId,
    ) -> Result<(), BnsError> {
        let record = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        if &record.owner != owner {
            return Err(BnsError::NotOwner);
        }
        record.content_id = Some(cid);
        Ok(())
    }

    pub fn resolve_content(&self, name: &str, current_epoch: u64) -> Option<ContentId> {
        self.names.get(name).and_then(|record| {
            if record.expires_at > current_epoch {
                record.content_id
            } else {
                None
            }
        })
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

    pub fn resolve_full(&self, name: &str, current_epoch: u64) -> Option<BnsResolved> {
        self.names
            .get(name)
            .map(|record| {
                let expired = record.expires_at <= current_epoch;
                BnsResolved {
                    name: record.name.clone(),
                    owner: record.owner,
                    address: if expired { None } else { record.address },
                    storage_root: if expired { None } else { record.storage_root },
                    storage_domain_id: if expired {
                        None
                    } else {
                        record.storage_domain_id
                    },
                    content_id: if expired { None } else { record.content_id },
                    is_expired: expired,
                }
            })
            .filter(|r| !r.is_expired)
    }

    pub fn set_storage(
        &mut self,
        name: &str,
        caller: Address,
        storage_root: [u8; 32],
        storage_domain_id: u32,
        current_epoch: u64,
    ) -> Result<(), BnsError> {
        let rec = self.names.get_mut(name).ok_or(BnsError::InvalidName)?;
        if rec.owner != caller {
            return Err(BnsError::NotOwner);
        }
        if rec.expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        rec.storage_root = Some(storage_root);
        rec.storage_domain_id = Some(storage_domain_id);
        rec.storage_root_height = Some(current_epoch);
        Ok(())
    }
}
