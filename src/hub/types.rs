use crate::core::address::Address;
use serde::{Deserialize, Serialize};

/// Budlum Hub — Unified Ecosystem Interface for dApp Registration.
/// Every blockchain application can register here to be visible to Budlum users.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppCategory {
    SocialFi,
    DeFi,
    Storage,
    Gaming,
    Infrastructure,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRecord {
    pub id: u64,
    pub name: String,       // e.g. "Budlum Social"
    pub developer: Address, // Owner of the app record
    pub category: AppCategory,
    pub website_url: String, // Can point to a .bud BNS name
    pub manifest_id: Option<crate::storage::content_id::ContentId>, // B.U.D. link for the app frontend
    pub registered_at_epoch: u64,
    /// Developer self-attestation only (ownership proof). NOT third-party audit.
    pub developer_attested: bool,
    /// DAO / governance-vetted flag (Task 9+). Distinct from developer_attested.
    pub verified: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum HubError {
    #[error("App not found")]
    NotFound,
    #[error("Not the developer")]
    NotDeveloper,
    #[error("Invalid metadata")]
    InvalidData,
    #[error("Not authorized for governance verification")]
    NotAuthorized,
}
