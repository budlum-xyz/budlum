use crate::core::address::Address;
use serde::{Deserialize, Serialize};

/// Listing kind for a `.bud` domain offer on the marketplace.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OfferKind {
    /// First sale of an unregistered or post-grace expired `.bud` name by an
    /// authorized primary seller (`BNS_PRIMARY_SELLERS`).
    Primary,
    /// Secondary resale of a currently live `.bud` name by its owner.
    Resale,
}

/// Marketplace listing for a `.bud` domain name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameOffer {
    pub id: u64,
    pub seller: Address,
    pub name: String,
    pub price_atoms: u64,
    pub duration: u64,
    pub kind: OfferKind,
    pub expires_at_epoch: u64,
    pub active: bool,
}

/// Signed transaction payload for `TransactionType::BnsCreateOffer`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateNameOffer {
    pub name: String,
    pub price_atoms: u64,
    pub duration: u64,
    pub kind: OfferKind,
    pub expires_at_epoch: u64,
}
