use crate::core::address::Address;
use crate::storage::bud3::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// B.U.D. Name Service (BNS) - decentralized naming for the Budlum network.
/// Full_impl per Q10 (storage_root + full resolve) + lifecycle integration.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameRecord {
    pub name: String,
    pub owner: Address,
    pub expires_at: u64,
    pub resolver: Option<Address>,

    // Full_impl - storage/address binding
    pub address: Option<Address>,
    pub consensus_domain_id: Option<u32>,
    pub storage_root: Option<[u8; 32]>,
    pub storage_domain_id: Option<u32>,
    pub storage_root_height: Option<u64>,

    pub content_id: Option<ContentId>,
    pub subdomains: std::collections::BTreeMap<String, Address>,
}

impl NameRecord {
    /// Convenience: validated constructor enforcing the BNS character-set and
    /// 3..=32 length rule, a non-zero owner, and a live expiry past
    /// `current_epoch`; wired through `BnsRegistry::register`.
    pub fn try_new(
        name: String,
        owner: Address,
        current_epoch: u64,
        expires_at: u64,
    ) -> Result<Self, BnsError> {
        let char_count = name.chars().count();
        if !(3..=32).contains(&char_count)
            || !crate::bns::registry::BnsRegistry::is_valid_name(&name)
            || owner == Address::zero()
        {
            return Err(BnsError::InvalidName);
        }
        if expires_at <= current_epoch {
            return Err(BnsError::Expired);
        }
        Ok(Self::new(name, owner, expires_at))
    }

    pub fn new(name: String, owner: Address, expires_at: u64) -> Self {
        Self {
            name,
            owner,
            expires_at,
            resolver: None,
            address: Some(owner),
            consensus_domain_id: None,
            storage_root: None,
            storage_domain_id: None,
            storage_root_height: None,
            content_id: None,
            subdomains: std::collections::BTreeMap::new(),
        }
    }

    pub fn with_storage(
        mut self,
        storage_root: [u8; 32],
        storage_domain_id: u32,
        height: u64,
    ) -> Self {
        self.storage_root = Some(storage_root);
        self.storage_domain_id = Some(storage_domain_id);
        self.storage_root_height = Some(height);
        self
    }

    pub fn with_address(mut self, address: Address, domain_id: Option<u32>) -> Self {
        self.address = Some(address);
        self.consensus_domain_id = domain_id;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnsResolved {
    pub name: String,
    pub owner: Address,
    pub address: Option<Address>,
    pub storage_root: Option<[u8; 32]>,
    pub storage_domain_id: Option<u32>,
    pub content_id: Option<ContentId>,
    pub is_expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BnsError {
    InvalidName,
    NameTaken,
    NotOwner,
    Expired,
}

impl fmt::Display for BnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BnsError::InvalidName => write!(f, "Name too short or long"),
            BnsError::NameTaken => write!(f, "Name already taken"),
            BnsError::NotOwner => write!(f, "Not the owner"),
            BnsError::Expired => write!(f, "Name expired"),
        }
    }
}

impl std::error::Error for BnsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blg_169_name_record_try_new_rejects_invalid_name_owner_or_expiry() {
        let alice = Address::from([1u8; 32]);
        let valid = NameRecord::try_new(String::from("ayaz.bud"), alice, 5, 10);
        assert!(valid.is_ok());
        assert_eq!(
            NameRecord::try_new(String::from("ab"), alice, 5, 10),
            Err(BnsError::InvalidName)
        );
        assert_eq!(
            NameRecord::try_new(String::from("UPPER.bud"), alice, 5, 10),
            Err(BnsError::InvalidName)
        );
        assert_eq!(
            NameRecord::try_new(String::from("ayaz.bud"), Address::zero(), 5, 10),
            Err(BnsError::InvalidName)
        );
        assert_eq!(
            NameRecord::try_new(String::from("ayaz.bud"), alice, 10, 10),
            Err(BnsError::Expired)
        );
    }
}
