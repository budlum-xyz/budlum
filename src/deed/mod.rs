//! DeEd domain primitives.
//!
//! DeEd is an application domain on Budlum, not a new chain or settlement
//! layer. This module contains only the canonical manifest and permissionless
//! role vocabulary; consensus, RPC, rewards, and bridge wiring remain separate
//! follow-up changes.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::registry::role::RoleId;
use crate::storage::ContentId;
use serde::{Deserialize, Serialize};

/// Permissionless DeEd participant roles.
///
/// These IDs extend the open registry without changing the registry's policy:
/// registration still requires only the configured stake floor.
pub mod roles {
    use super::RoleId;

    pub const INDUSTRY_SPONSOR: RoleId = RoleId(10);
    pub const RESEARCH_CONTRIBUTOR: RoleId = RoleId(11);
}

/// DeEd artifact categories. The artifact bytes remain in B.U.D.; this enum
/// is the domain-level meaning committed by the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Dataset,
    Research,
    IntellectualProperty,
    Educational,
}

impl ArtifactKind {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Dataset => b"dataset",
            Self::Research => b"research",
            Self::IntellectualProperty => b"intellectual_property",
            Self::Educational => b"educational",
        }
    }
}

/// Visibility policy for student, educator, and peer sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    EducatorOnly,
    PeerOnly,
}

impl Visibility {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Public => b"public",
            Self::EducatorOnly => b"educator_only",
            Self::PeerOnly => b"peer_only",
        }
    }
}

/// Canonical DeEd manifest. Content is addressed by B.U.D.; this record binds
/// its meaning, owner, visibility, and metadata into a deterministic identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub contributor: Address,
    pub content_id: ContentId,
    pub artifact_kind: ArtifactKind,
    pub visibility: Visibility,
    pub metadata_hash: [u8; 32],
    pub created_at: u64,
}

impl Manifest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.contributor == Address::zero() {
            return Err("DeEd contributor cannot be the zero address");
        }
        if self.content_id.0 == [0u8; 32] {
            return Err("DeEd content_id cannot be zero");
        }
        if self.metadata_hash == [0u8; 32] {
            return Err("DeEd metadata_hash cannot be zero");
        }
        if self.created_at == 0 {
            return Err("DeEd created_at cannot be zero");
        }
        Ok(())
    }

    pub fn id(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_DEED_MANIFEST_V1",
            self.contributor.as_bytes(),
            &self.content_id.0,
            self.artifact_kind.as_bytes(),
            self.visibility.as_bytes(),
            &self.metadata_hash,
            &self.created_at.to_le_bytes(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            contributor: Address::from([7u8; 32]),
            content_id: ContentId([8u8; 32]),
            artifact_kind: ArtifactKind::Research,
            visibility: Visibility::EducatorOnly,
            metadata_hash: [9u8; 32],
            created_at: 42,
        }
    }

    #[test]
    fn valid_manifest_is_deterministic() {
        let value = manifest();
        assert!(value.validate().is_ok());
        assert_eq!(value.id(), value.id());
    }

    #[test]
    fn manifest_id_binds_every_security_relevant_field() {
        let base = manifest();
        let mut variants = Vec::new();

        let mut value = base.clone();
        value.contributor = Address::from([1u8; 32]);
        variants.push(value);
        let mut value = base.clone();
        value.content_id = ContentId([2u8; 32]);
        variants.push(value);
        let mut value = base.clone();
        value.artifact_kind = ArtifactKind::Dataset;
        variants.push(value);
        let mut value = base.clone();
        value.visibility = Visibility::Public;
        variants.push(value);
        let mut value = base.clone();
        value.metadata_hash = [3u8; 32];
        variants.push(value);
        let mut value = base;
        value.created_at = 43;
        variants.push(value);

        for variant in variants {
            assert_ne!(variant.id(), manifest().id());
        }
    }

    #[test]
    fn manifest_serde_round_trip_is_stable() {
        let value = manifest();
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: Manifest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert!(String::from_utf8(encoded).unwrap().contains("educator_only"));
    }

    #[test]
    fn manifest_rejects_zero_identity_content_and_metadata() {
        let mut value = manifest();
        value.contributor = Address::zero();
        assert_eq!(value.validate(), Err("DeEd contributor cannot be the zero address"));
        value = manifest();
        value.content_id = ContentId([0u8; 32]);
        assert_eq!(value.validate(), Err("DeEd content_id cannot be zero"));
        value = manifest();
        value.metadata_hash = [0u8; 32];
        assert_eq!(value.validate(), Err("DeEd metadata_hash cannot be zero"));
        value = manifest();
        value.created_at = 0;
        assert_eq!(value.validate(), Err("DeEd created_at cannot be zero"));
    }

    #[test]
    fn permissionless_roles_are_distinct() {
        assert_ne!(roles::INDUSTRY_SPONSOR, roles::RESEARCH_CONTRIBUTOR);
        assert_eq!(roles::INDUSTRY_SPONSOR.value(), 10);
        assert_eq!(roles::RESEARCH_CONTRIBUTOR.value(), 11);
    }
}
