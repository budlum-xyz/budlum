use crate::core::address::Address;
use crate::storage::bud3::content_ref::ContentRef;
use serde::{Deserialize, Serialize};
use std::fmt;

// B.U.D. Name Service (BNS) - decentralized naming for the Budlum network.
// Full_impl per Q10 (`storage_root` + full resolve) + lifecycle integration.

/// The JSON form of a content reference. Every RPC answer and every proof
/// uses this one shape: `{kind, digest, len, object_commitment, nft_id}`.
#[must_use]
pub fn content_ref_to_json(content: &ContentRef) -> serde_json::Value {
    use crate::storage::bud3::content_id::ContentIdKind;
    serde_json::json!({
        "kind": match content.content_id.kind {
            ContentIdKind::Public => "public",
            ContentIdKind::Sealed => "sealed",
        },
        "digest": format!("0x{}", hex::encode(content.content_id.digest)),
        "len": content.content_id.len,
        "object_commitment": format!("0x{}", hex::encode(content.object_commitment)),
        "nft_id": content.nft_id.map(|n| format!("0x{}", hex::encode(n))),
    })
}

/// Read the JSON form of a content reference back.
///
/// # Errors
///
/// Returns the name of the field that is missing or malformed. A malformed
/// field is never read as absent: the reference feeds a proof digest.
pub fn content_ref_from_json(value: &serde_json::Value) -> Result<ContentRef, String> {
    use crate::storage::bud3::content_id::{ContentId, ContentIdKind};
    fn hex32(value: Option<&serde_json::Value>, field: &str) -> Result<[u8; 32], String> {
        let text = value
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("content {field} is missing or not a string"))?;
        let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
            .map_err(|_| format!("content {field} is not hex"))?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| format!("content {field} is not 32 bytes"))
    }
    let kind = match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("public") => ContentIdKind::Public,
        Some("sealed") => ContentIdKind::Sealed,
        _ => return Err("content kind is missing or invalid".into()),
    };
    let content_id = ContentId {
        kind,
        digest: hex32(value.get("digest"), "digest")?,
        len: value
            .get("len")
            .and_then(serde_json::Value::as_u64)
            .ok_or("content len is missing or invalid")?,
    };
    let object_commitment = hex32(value.get("object_commitment"), "object_commitment")?;
    let nft_id = match value.get("nft_id") {
        Some(v) if !v.is_null() => Some(hex32(Some(v), "nft_id")?),
        _ => None,
    };
    ContentRef::new(content_id, object_commitment, nft_id)
        .map_err(|e| format!("invalid content reference: {e:?}"))
}

/// One subdomain of a `.bud` name.
///
/// The parent owner creates and removes it. The subdomain owner sets what it
/// serves. `address` is where a payment to `<label>.<name>.bud` goes; it
/// starts as the owner.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubdomainRecord {
    pub owner: Address,
    pub address: Option<Address>,
    pub content: Option<ContentRef>,
}

impl SubdomainRecord {
    /// A fresh subdomain: it pays its owner and serves nothing yet.
    #[must_use]
    pub const fn owned_by(owner: Address) -> Self {
        Self {
            owner,
            address: Some(owner),
            content: None,
        }
    }

    /// The JSON form every RPC answer and every proof carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "owner": format!("0x{}", hex::encode(self.owner.0)),
            "address": self.address.map(|a| format!("0x{}", hex::encode(a.0))),
            "content": self.content.as_ref().map(content_ref_to_json),
        })
    }

    /// Read the JSON form back. A field that is not 32 bytes of hex is an
    /// error, never a silent `None`: the record feeds a proof digest.
    ///
    /// # Errors
    ///
    /// Returns the name of the field that is missing or malformed.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        fn hex32(value: &serde_json::Value, field: &str) -> Result<[u8; 32], String> {
            let text = value
                .as_str()
                .ok_or_else(|| format!("subdomain {field} is not a string"))?;
            let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
                .map_err(|_| format!("subdomain {field} is not hex"))?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| format!("subdomain {field} is not 32 bytes"))
        }
        fn optional(value: &serde_json::Value, field: &str) -> Result<Option<[u8; 32]>, String> {
            match value.get(field) {
                Some(v) if !v.is_null() => hex32(v, field).map(Some),
                _ => Ok(None),
            }
        }
        let owner = value
            .get("owner")
            .ok_or_else(|| "subdomain owner is missing".to_string())
            .and_then(|v| hex32(v, "owner"))?;
        Ok(Self {
            owner: Address::from(owner),
            address: optional(value, "address")?.map(Address::from),
            content: match value.get("content") {
                Some(v) if !v.is_null() => Some(content_ref_from_json(v)?),
                _ => None,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameRecord {
    pub name: String,
    pub owner: Address,
    pub expires_at: u64,

    // Full_impl - storage/address binding
    pub address: Option<Address>,
    pub consensus_domain_id: Option<u32>,
    pub storage_root: Option<[u8; 32]>,
    pub storage_domain_id: Option<u32>,
    pub storage_root_height: Option<u64>,

    /// What the name serves: one B.U.D. 3.0 content reference, or nothing.
    pub content: Option<ContentRef>,
    pub subdomains: std::collections::BTreeMap<String, SubdomainRecord>,
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

    #[must_use]
    pub fn new(name: String, owner: Address, expires_at: u64) -> Self {
        Self {
            name,
            owner,
            expires_at,
            address: Some(owner),
            consensus_domain_id: None,
            storage_root: None,
            storage_domain_id: None,
            storage_root_height: None,
            content: None,
            subdomains: std::collections::BTreeMap::new(),
            records: std::collections::BTreeMap::new(),
        }
    }

    #[must_use]
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

    #[must_use]
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
    pub content: Option<ContentRef>,
    #[serde(default)]
    pub subdomains: std::collections::BTreeMap<String, SubdomainRecord>,
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
    /// The content the name serves. The leaf commits to it through the
    /// binding digest over `(name, owner, content)`, so a verifier that
    /// folds this branch to the header root has checked this field.
    pub content: Option<ContentRef>,
    pub storage_root: Option<[u8; 32]>,
    pub extras_digest: [u8; 32],
    /// The record digest: the value the name's slot holds in the tree.
    pub leaf: [u8; 32],
    /// Sibling digests from the name's leaf node up to the names root.
    pub siblings: Vec<[u8; 32]>,
    /// The pre-image of `extras_digest`, when the prover ships it.
    ///
    /// `extras_digest` is a commitment, not a disclosure: on its own the leaf
    /// binds `address`, the records and the subdomains, but a verifier that only sees the 32 opaque bytes cannot tell
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
    pub address: Option<Address>,
    pub consensus_domain_id: Option<u32>,
    pub storage_domain_id: Option<u32>,
    pub storage_root_height: Option<u64>,
    pub subdomains: std::collections::BTreeMap<String, SubdomainRecord>,
    pub records: std::collections::BTreeMap<String, String>,
}

/// Another name's leaf standing where the queried name would be.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnsOccupiedSlot {
    /// The tree key of the name that holds the slot.
    pub key: [u8; 32],
    /// The record digest of that name.
    pub value: [u8; 32],
}

/// Why a name is not in the registry: its path ends in an empty slot, or in
/// the leaf of a different name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnsAbsenceProof {
    /// Sibling digests from the end of the path up to the names root.
    pub siblings: Vec<[u8; 32]>,
    /// `None` when the path ends in an empty slot.
    pub occupant: Option<BnsOccupiedSlot>,
}

/// The wire form of a [`BnsAbsenceProof`].
#[must_use]
pub fn absence_to_json(absence: &BnsAbsenceProof) -> serde_json::Value {
    serde_json::json!({
        "siblings": absence
            .siblings
            .iter()
            .map(|s| format!("0x{}", hex::encode(s)))
            .collect::<Vec<_>>(),
        "occupant": absence.occupant.as_ref().map(|slot| serde_json::json!({
            "key": format!("0x{}", hex::encode(slot.key)),
            "value": format!("0x{}", hex::encode(slot.value)),
        })),
    })
}

/// Read the wire form written by [`absence_to_json`].
///
/// # Errors
///
/// Names the field that is missing or is not 32 bytes of hex.
pub fn absence_from_json(value: &serde_json::Value) -> Result<BnsAbsenceProof, String> {
    fn hex32(value: Option<&serde_json::Value>, field: &str) -> Result<[u8; 32], String> {
        let text = value
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("missing {field}"))?;
        let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text))
            .map_err(|_| format!("{field} is not hex"))?;
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("{field} is not 32 bytes"))
    }
    let siblings = value
        .get("siblings")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing absence.siblings")?
        .iter()
        .map(|s| hex32(Some(s), "absence.siblings[]"))
        .collect::<Result<Vec<_>, _>>()?;
    let occupant = match value.get("occupant") {
        Some(slot) if !slot.is_null() => Some(BnsOccupiedSlot {
            key: hex32(slot.get("key"), "absence.occupant.key")?,
            value: hex32(slot.get("value"), "absence.occupant.value")?,
        }),
        _ => None,
    };
    Ok(BnsAbsenceProof { siblings, occupant })
}

/// Per-name inclusion or absence proof against `BnsRegistry::root()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BnsStateProof {
    pub name: String,
    pub included: bool,
    pub bns_root: [u8; 32],
    pub meta_digest: [u8; 32],
    pub names_count: u64,
    pub epoch: u64,
    pub entry: Option<BnsMerkleBranch>,
    /// Present exactly when `included` is false.
    #[serde(default)]
    pub absence: Option<BnsAbsenceProof>,
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
            Self::InvalidName => write!(f, "Name too short or long"),
            Self::ReservedName => write!(f, "Name label is reserved"),
            Self::InvalidDuration => write!(f, "Registration duration out of bounds"),
            Self::InvalidRecord => write!(f, "Invalid BNS record key, value, or count"),
            Self::OwnerNameLimitExceeded => write!(f, "Owner name limit exceeded"),
            Self::NameTaken => write!(f, "Name already taken"),
            Self::NotOwner => write!(f, "Not the owner"),
            Self::Expired => write!(f, "Name expired"),
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
