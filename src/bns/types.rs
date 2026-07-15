use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// B.U.D. Name Service (BNS) — decentralized naming for the Budlum network.
/// Phase 6: full_impl per Q10 (storage_root + full resolve) + lifecycle integration.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameRecord {
    pub name: String,
    pub owner: Address,
    pub expires_at: u64,
    pub resolver: Option<Address>,

    // Phase 6 full_impl (Q10) — storage/address binding
    pub address: Option<Address>,
    pub consensus_domain_id: Option<u32>,
    pub storage_root: Option<[u8; 32]>,
    pub storage_domain_id: Option<u32>,
    pub storage_root_height: Option<u64>,

    pub content_id: Option<ContentId>,
    pub subdomains: std::collections::BTreeMap<String, Address>,
}

impl NameRecord {
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

    pub fn with_storage(mut self, storage_root: [u8; 32], storage_domain_id: u32, height: u64) -> Self {
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
