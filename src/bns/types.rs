use crate::core::address::Address;
use crate::storage::content_id::ContentId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// B.U.D. Name Service (BNS) - decentralized naming for the Budlum network.
/// Full_impl per Q10 (`storage_root` + full resolve) + lifecycle integration.

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
    #[serde(default)]
    pub bud3_content: Option<crate::storage::bud3::content_ref::ContentRef>,
    pub subdomains: std::collections::BTreeMap<String, Address>,
    #[serde(default)]
    pub records: std::collections::BTreeMap<String, String>,
}

impl NameRecord {
    /// Convenience: validated constructor enforcing a single 3..=32 character
    /// label plus `.bud` suffix, a non-zero owner, and a live expiry past
    /// `current_epoch`; wired through `BnsRegistry::register`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn try_new(
        name: String,
        owner: Address,
        current_epoch: u64,
        expires_at: u64,
    ) -> Result<Self, BnsError> {
        if !crate::bns::registry::BnsRegistry::is_valid_name(&name) || owner == Address::zero() {
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
            bud3_content: None,
            subdomains: std::collections::BTreeMap::new(),
            records: std::collections::BTreeMap::new(),
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

/// Lifecycle state of a registered `.bud` name at a given epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameStatus {
    /// Live (`current_epoch < expires_at`): resolves and accepts owner mutations.
    #[default]
    Active,
    /// Grace (`expires_at <= current_epoch <= expires_at + GRACE_PERIOD`):
    /// resolution and mutations fail closed, third parties cannot register, and
    /// only the owner may rescue via `renew`.
    Grace,
    /// Expired past grace (`current_epoch > expires_at + GRACE_PERIOD`):
    /// eligible for eviction and primary marketplace registration.
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnsResolved {
    pub name: String,
    pub owner: Address,
    pub address: Option<Address>,
    pub storage_root: Option<[u8; 32]>,
    pub storage_domain_id: Option<u32>,
    pub content_id: Option<ContentId>,
    #[serde(default)]
    pub bud3_content: Option<crate::storage::bud3::content_ref::ContentRef>,
    #[serde(default)]
    pub subdomains: std::collections::BTreeMap<String, Address>,
    #[serde(default)]
    pub records: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub status: NameStatus,
    #[serde(default)]
    pub expires_at: u64,
    #[serde(default)]
    pub grace_expires_at: u64,
    pub is_expired: bool,
}

/// Authenticated Merkle branch for a single leaf in `BnsRegistry`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnsMerkleBranch {
    pub name: String,
    pub owner: Address,
    pub address: Option<Address>,
    pub expires_at: u64,
    pub content_id: Option<ContentId>,
    pub storage_root: Option<[u8; 32]>,
    pub extras_digest: [u8; 32],
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<bool>,
    /// Position of this leaf in the ordered name list the branch was built
    /// from, and the size of that list.
    ///
    /// Absence proofs need both. Without them a verifier can only compare the
    /// disclosed names lexicographically, and every branch in the tree sorts
    /// next to *some* target, so an honest inclusion branch of one name can be
    /// relabelled to prove any other name absent. With the index and the count
    /// the verifier can require the two boundary branches to be adjacent
    /// positions, which is what "no name sorts between them" actually means.
    ///
    /// Absent means "position unknown": such a branch still verifies for
    /// inclusion, and is refused for non-inclusion.
    #[serde(default)]
    pub leaf_index: Option<u64>,
    #[serde(default)]
    pub tree_size: Option<u64>,
    /// The pre-image of `extras_digest`, when the prover ships it.
    ///
    /// `extras_digest` is a commitment, not a disclosure: on its own the leaf
    /// binds `address`, the records, the subdomains and the B.U.D. 3.0
    /// reference, but a verifier that only sees the 32 opaque bytes cannot tell
    /// what they commit to. The branch already discloses `address` next to the
    /// digest, so before this field those disclosed values were whatever the
    /// answering node chose, and an identity profile that trusted them could
    /// show a Verified badge over a swapped forwarding address.
    ///
    /// A verifier that receives this recomputes `extras_digest` from it and
    /// refuses the branch on any mismatch, so every disclosed field is bound to
    /// the header root. Absent means "the prover did not disclose the extras":
    /// the branch still proves the fields that sit outside the digest, and a
    /// caller that needs `address` or the records must not use it.
    #[serde(default)]
    pub extras: Option<BnsBranchExtras>,
}

/// The verified pre-image of [`BnsMerkleBranch::extras_digest`].
///
/// Field order and encoding mirror the registry's own extras commitment, so a
/// verifier can recompute the digest without trusting the prover for anything
/// but the values themselves - and those values either fold to the digest the
/// header root commits to, or they do not.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnsBranchExtras {
    pub resolver: Option<Address>,
    pub address: Option<Address>,
    pub consensus_domain_id: Option<u32>,
    pub storage_domain_id: Option<u32>,
    pub storage_root_height: Option<u64>,
    pub bud3_content: Option<crate::storage::bud3::content_ref::ContentRef>,
    pub subdomains: std::collections::BTreeMap<String, Address>,
    pub records: std::collections::BTreeMap<String, String>,
}

/// Compact per-name inclusion or lexicographic non-existence proof against `BnsRegistry::root()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnsStateProof {
    pub name: String,
    pub included: bool,
    pub bns_root: [u8; 32],
    pub meta_digest: [u8; 32],
    pub names_count: u64,
    pub epoch: u64,
    pub entry: Option<BnsMerkleBranch>,
    pub predecessor: Option<BnsMerkleBranch>,
    pub successor: Option<BnsMerkleBranch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BnsError {
    InvalidName,
    ReservedName,
    InvalidDuration,
    InvalidRecord,
    OwnerNameLimitExceeded,
    NameTaken,
    NotOwner,
    Expired,
}

impl fmt::Display for BnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BnsError::InvalidName => write!(f, "Name too short or long"),
            BnsError::ReservedName => write!(f, "Name label is reserved"),
            BnsError::InvalidDuration => write!(f, "Registration duration out of bounds"),
            BnsError::InvalidRecord => write!(f, "Invalid BNS record key, value, or count"),
            BnsError::OwnerNameLimitExceeded => write!(f, "Owner name limit exceeded"),
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
    fn name_record_try_new_rejects_invalid_name_owner_or_expiry() {
        let alice = Address::from([1u8; 32]);
        let valid = NameRecord::try_new(String::from("ayaz.bud"), alice, 5, 10);
        assert!(valid.is_ok());
        assert!(NameRecord::try_new(format!("{}.bud", "a".repeat(32)), alice, 5, 10).is_ok());
        assert_eq!(
            NameRecord::try_new(String::from("bids"), alice, 5, 10),
            Err(BnsError::InvalidName)
        );
        assert_eq!(
            NameRecord::try_new(String::from("ab.bud"), alice, 5, 10),
            Err(BnsError::InvalidName)
        );
        assert_eq!(
            NameRecord::try_new(format!("{}.bud", "a".repeat(33)), alice, 5, 10),
            Err(BnsError::InvalidName)
        );
        assert_eq!(
            NameRecord::try_new(String::from("sub.ayaz.bud"), alice, 5, 10),
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
