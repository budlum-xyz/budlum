use crate::core::address::Address;
use serde::{Deserialize, Serialize};

/// B.U.D. Name Service (BNS) — decentralized naming for the Budlum network.
/// Phase 6 started early by user decision.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameRecord {
    pub name: String,              // e.g., "ayaz.bud"
    pub owner: Address,            // The account that owns the name
    pub expires_at: u64,           // Epoch when the name expires
    pub resolver: Option<Address>, // Optional smart contract for complex resolution
}

#[derive(Debug, thiserror::Error)]
pub enum BnsError {
    #[error("Name too short or long")]
    InvalidName,
    #[error("Name already taken")]
    NameTaken,
    #[error("Not the owner")]
    NotOwner,
    #[error("Name expired")]
    Expired,
}
