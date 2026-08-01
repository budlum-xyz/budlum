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
    /// F14: isim expire olduktan sonra eski owner'ın yenileme
    /// Penceresi (epoch sayısı). Bu süre içinde 3. taraf register edemez
    /// (squatting/front-running koruması). ~30 günlük epoch (~100 epoch/gün).
    pub const GRACE_PERIOD: u64 = 3000;

    /// Maximum number of BNS names in the registry.
    /// At 100K names with subdomains, this bounds state growth to ~50MB.
    pub const MAX_NAMES: usize = 100_000;

    /// Maximum subdomains per name.
    pub const MAX_SUBDOMAINS_PER_NAME: usize = 1_000;

    pub fn new() -> Self {
        Self {
            names: BTreeMap::new(),
            base_cost: 100,
        }
    }

    pub fn calculate_cost(&self, name: &str, duration: u64) -> u64 {
        // Use char count instead of byte length for Unicode support
        let char_count = name.chars().count();
        let multiplier: u64 = match char_count {
            1..=3 => 100,
            4..=6 => 10,
            _ => 1,
        };
        // Use saturating_mul to prevent overflow
        let base = self
            .base_cost
            .saturating_mul(multiplier)
            .saturating_mul(duration);
        if multiplier >= 10 || duration >= 100 {
            base.saturating_mul(2)
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
        // Use char count instead of byte length for Unicode support
        let char_count = name.chars().count();
        if !(3..=32).contains(&char_count) {
            return Err(BnsError::InvalidName);
        }
        // Duration must be > 0. Zero-duration registration
        // Would expire immediately (current_epoch + 0), creating a useless
        // Record that wastes state space and could be used for name squatting.
        if duration == 0 {
            return Err(BnsError::InvalidName);
        }
        if let Some(record) = self.names.get(&name) {
            if record.expires_at > current_epoch {
                return Err(BnsError::NameTaken);
            }
            // F14: grace-period - expire olmuş isim, eski owner'a
            // Yenileme penceresi tanır. `current_epoch < expires_at + GRACE_PERIOD`
            // Içinde yalnızca eski owner register/renew yapabilir; böylece
            // Front-running squatting (3. tarafın expired ismi kapması) engellenir.
            let grace_until = record.expires_at.saturating_add(Self::GRACE_PERIOD);
            if current_epoch < grace_until && record.owner != owner {
                return Err(BnsError::NameTaken);
            }
        }
        // Cap total name count - fail-closed.
        // Reuse slots from expired names first; only reject if truly at capacity.
        if self.names.len() >= Self::MAX_NAMES {
            // Try to evict the oldest expired name to make room
            let expired_key = self
                .names
                .iter()
                .find(|(_, r)| r.expires_at.saturating_add(Self::GRACE_PERIOD) < current_epoch)
                .map(|(k, _)| k.clone());
            if let Some(key) = expired_key {
                self.names.remove(&key);
            } else {
                return Err(BnsError::NameTaken); // at capacity, no evictable names
            }
        }
        let record = NameRecord::new(name.clone(), owner, current_epoch + duration);
        self.names.insert(name, record);
        Ok(())
    }

    /// Renew an existing name registration. Only the current owner may renew
    /// And only while the record is still live (not expired). The new expiry
    /// Extends from the current expiry - never from `current_epoch` - so
    /// Renewing early never shortens the registration.
    ///
    /// # No transaction reaches this
    ///
    /// `TransactionType` carries `BnsRegister`, `BnsSetContent`,
    /// `BnsRegisterSubdomain` and `BnsSetStorage`. There is no `BnsRenew` and
    /// No `BnsTransfer`, so this method and [`Self::transfer`] are called only
    /// From tests. On a live chain an owner cannot renew, and cannot hand a
    /// Name over.
    ///
    /// It is survivable rather than fatal, because `register` accepts the
    /// Previous owner inside `GRACE_PERIOD` - see the front-running note there.
    /// But re-registering is not the same operation:
    ///
    /// ```text
    /// renew:    expires_at += duration        (extends from the old expiry)
    /// register: expires_at  = now + duration  (restarts from today)
    /// ```
    ///
    /// So the only available path throws away whatever time was left. An owner
    /// Who renews a year early loses that year, and one who waits until the
    /// Last epoch to avoid the loss is one missed block from the grace period
    /// And a squatter. The safe move and the cheap move point in opposite
    /// Directions, which is exactly the shape `renew` exists to remove.
    ///
    /// Wiring it needs a transaction type, an executor arm that charges
    /// `calculate_cost`, and a signature check, small, but consensus surface,
    /// So it is recorded here rather than smuggled into a hardening pass.
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
    /// The current owner may transfer. Resolver/content bindings and existing
    /// Subdomain mappings are preserved; after the transfer the previous
    /// Owner loses all control over the record.
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
        // Cap subdomains per name - fail-closed.
        if parent.subdomains.len() >= Self::MAX_SUBDOMAINS_PER_NAME {
            return Err(BnsError::InvalidName);
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

    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.base_cost == 100
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_BNS_REGISTRY_V1");
        hasher.update(self.base_cost.to_le_bytes());
        for (name, record) in &self.names {
            hasher.update(name.as_bytes());
            hasher.update(record.owner.0);
            hasher.update(record.expires_at.to_le_bytes());
            match record.resolver {
                Some(resolver) => {
                    hasher.update([1u8]);
                    hasher.update(resolver.0);
                }
                None => hasher.update([0u8]),
            }
            match record.address {
                Some(address) => {
                    hasher.update([1u8]);
                    hasher.update(address.0);
                }
                None => hasher.update([0u8]),
            }
            match record.consensus_domain_id {
                Some(domain_id) => {
                    hasher.update([1u8]);
                    hasher.update(domain_id.to_le_bytes());
                }
                None => hasher.update([0u8]),
            }
            match record.storage_root {
                Some(storage_root) => {
                    hasher.update([1u8]);
                    hasher.update(storage_root);
                }
                None => hasher.update([0u8]),
            }
            match record.storage_domain_id {
                Some(domain_id) => {
                    hasher.update([1u8]);
                    hasher.update(domain_id.to_le_bytes());
                }
                None => hasher.update([0u8]),
            }
            match record.storage_root_height {
                Some(height) => {
                    hasher.update([1u8]);
                    hasher.update(height.to_le_bytes());
                }
                None => hasher.update([0u8]),
            }
            match record.content_id {
                Some(content_id) => {
                    hasher.update([1u8]);
                    hasher.update(content_id.0);
                }
                None => hasher.update([0u8]),
            }
            for (sub_label, sub_owner) in &record.subdomains {
                hasher.update(sub_label.as_bytes());
                hasher.update(sub_owner.0);
            }
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_changes_when_record_mutates() {
        let mut reg = BnsRegistry::new();
        let owner = Address::from([1u8; 32]);
        reg.register("alice.bud".into(), owner, 1, 10).unwrap();
        let root_before = reg.root();
        reg.set_content("alice.bud", &owner, ContentId([0x55; 32]))
            .unwrap();
        assert_ne!(root_before, reg.root());
    }
}
