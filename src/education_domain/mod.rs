//! B.U.D. 3.0 Education Domain (Section 5.6).
//!
//! Educational and research artifacts carry a B.U.D. 3.0 [`ContentId`] and
//! register on-chain exclusively through [`StorageTxV3::RegisterObject`].
//!
//! exposed for: Education Domain registration handlers and SDK callers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::registry::role::RoleId;
use crate::storage::bud3::content_id::ContentId;
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::pipeline::ObjectRecord;
use crate::storage::bud3::placement::Share;
use crate::storage::bud3::registry::{Bud3Registry, ObjectKey, RegistryError};
use crate::storage::bud3::tx::{apply as apply_bud3_tx, Applied, StorageTxV3};

/// Domain tag committing an Education Domain artifact record.
pub const DOMAIN_EDUCATION_ARTIFACT: &[u8] = b"BDLM_BUD3_EDUCATION_ARTIFACT_V1";
/// Industry sponsor permissionless role id.
pub const ROLE_INDUSTRY_SPONSOR: RoleId = RoleId(10);
/// Research contributor permissionless role id.
pub const ROLE_RESEARCH_CONTRIBUTOR: RoleId = RoleId(11);

/// Categories of Education Domain artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EducationArtifactKind {
    Dataset,
    Research,
    IntellectualProperty,
    Educational,
}

/// Sharing visibility policy for an Education Domain artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EducationVisibility {
    Public,
    EducatorOnly,
    PeerOnly,
}

/// Errors returned by B.U.D. 3.0 Education Domain registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EducationDomainError {
    InvalidArtifact(&'static str),
    ContentIdMismatch,
    InvalidContentRef(ContentRefError),
    Storage(RegistryError),
}

/// Canonical B.U.D. 3.0 Education Domain artifact record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EducationArtifact {
    pub contributor: Address,
    pub content_ref: ContentRef,
    pub object_commitment: ObjectKey,
    pub artifact_kind: EducationArtifactKind,
    pub visibility: EducationVisibility,
    pub metadata_hash: [u8; 32],
    pub created_at: u64,
}

impl EducationArtifact {
    /// Validate non-zero identity and metadata fields.
    ///
    /// exposed for: `EducationDomainRegistry::register_artifact`.
    pub fn validate(&self) -> Result<(), EducationDomainError> {
        if self.contributor == Address::zero() {
            return Err(EducationDomainError::InvalidArtifact(
                "contributor cannot be zero",
            ));
        }
        if self.content_ref.content_id.digest == [0u8; 32] {
            return Err(EducationDomainError::InvalidArtifact(
                "content_id cannot be zero",
            ));
        }
        if self.metadata_hash == [0u8; 32] {
            return Err(EducationDomainError::InvalidArtifact(
                "metadata_hash cannot be zero",
            ));
        }
        if self.created_at == 0 {
            return Err(EducationDomainError::InvalidArtifact(
                "created_at cannot be zero",
            ));
        }
        Ok(())
    }

    /// Deterministic 32-byte artifact id bound to `ContentId` and `object_commitment`.
    ///
    /// exposed for: Education Domain indexing and attestation checks.
    #[must_use]
    pub fn artifact_id(&self) -> [u8; 32] {
        let kind_tag: u8 = match self.artifact_kind {
            EducationArtifactKind::Dataset => 1,
            EducationArtifactKind::Research => 2,
            EducationArtifactKind::IntellectualProperty => 3,
            EducationArtifactKind::Educational => 4,
        };
        let vis_tag: u8 = match self.visibility {
            EducationVisibility::Public => 1,
            EducationVisibility::EducatorOnly => 2,
            EducationVisibility::PeerOnly => 3,
        };
        hash_fields_bytes(&[
            DOMAIN_EDUCATION_ARTIFACT,
            self.contributor.as_bytes(),
            &self.content_ref.content_id.digest,
            &self.content_ref.content_id.len.to_le_bytes(),
            &self.object_commitment,
            &[kind_tag, vis_tag],
            &self.metadata_hash,
            &self.created_at.to_le_bytes(),
        ])
    }
}

/// Parameters describing an Education Domain artifact registration.
#[derive(Debug, Clone)]
pub struct ArtifactRegistrationSpec {
    pub contributor: Address,
    pub content_id: ContentId,
    pub artifact_kind: EducationArtifactKind,
    pub visibility: EducationVisibility,
    pub metadata_hash: [u8; 32],
    pub created_at: u64,
}

/// Education Domain registry storing artifacts backed by `StorageTxV3::RegisterObject`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EducationDomainRegistry {
    artifacts: BTreeMap<[u8; 32], EducationArtifact>,
}

impl EducationDomainRegistry {
    /// Create an empty Education Domain registry.
    ///
    /// exposed for: Education Domain state initialization.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the canonical [`StorageTxV3::RegisterObject`] payload for an artifact.
    ///
    /// exposed for: Education Domain transaction construction.
    #[must_use]
    pub fn build_register_tx(
        record: ObjectRecord,
        shares: Vec<(u64, Share)>,
        lifetime_epochs: u64,
    ) -> StorageTxV3 {
        StorageTxV3::RegisterObject {
            record,
            shares,
            lifetime_epochs,
        }
    }

    /// Register an artifact's B.U.D. 3.0 object via [`StorageTxV3::RegisterObject`].
    ///
    /// exposed for: Education Domain registration handlers.
    pub fn register_artifact(
        &mut self,
        bud3: &mut Bud3Registry,
        spec: ArtifactRegistrationSpec,
        record: ObjectRecord,
        shares: Vec<(u64, Share)>,
        lifetime_epochs: u64,
        current_epoch: u64,
    ) -> Result<([u8; 32], Applied), EducationDomainError> {
        let _ = (ROLE_INDUSTRY_SPONSOR, ROLE_RESEARCH_CONTRIBUTOR);
        if record.content_id != spec.content_id {
            return Err(EducationDomainError::ContentIdMismatch);
        }
        let commitment = record.commitment;
        let content_ref = ContentRef::new(spec.content_id, commitment, None)
            .map_err(EducationDomainError::InvalidContentRef)?;
        let artifact = EducationArtifact {
            contributor: spec.contributor,
            content_ref,
            object_commitment: commitment,
            artifact_kind: spec.artifact_kind,
            visibility: spec.visibility,
            metadata_hash: spec.metadata_hash,
            created_at: spec.created_at,
        };
        artifact.validate()?;

        let tx = Self::build_register_tx(record, shares, lifetime_epochs);
        let applied = apply_bud3_tx(bud3, spec.contributor.0, tx, current_epoch)
            .map_err(EducationDomainError::Storage)?;

        let id = artifact.artifact_id();
        self.artifacts.insert(id, artifact);
        Ok((id, applied))
    }

    /// Look up a registered Education Domain artifact by id.
    ///
    /// exposed for: Education Domain queries.
    #[must_use]
    pub fn artifact(&self, id: &[u8; 32]) -> Option<&EducationArtifact> {
        self.artifacts.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::limits::{Bud3Limits, Profile};
    use crate::storage::bud3::pipeline::prepare_public_upload;
    use crate::storage::bud3::placement::Class;
    use crate::storage::bud3::registry::Registered;

    const P: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    #[test]
    fn education_domain_registers_object() {
        let scholar = Address([0x33; 32]);
        let mut bud3 = Bud3Registry::default();
        let mut domain = EducationDomainRegistry::new();

        let paper = b"open-access post-quantum cryptography lecture notes".repeat(6);
        let up = prepare_public_upload(&paper, &P, &Bud3Limits::default(), 8).expect("upload");
        let cid = up.record.content_id;
        let obj_key = up.record.commitment;

        let (artifact_id, applied) = domain
            .register_artifact(
                &mut bud3,
                ArtifactRegistrationSpec {
                    contributor: scholar,
                    content_id: cid,
                    artifact_kind: EducationArtifactKind::Educational,
                    visibility: EducationVisibility::Public,
                    metadata_hash: [0xAB; 32],
                    created_at: 1_700_000_000,
                },
                up.record,
                vec![(
                    0,
                    Share {
                        validator: [5u8; 32],
                        class: Class::Full,
                        first_esi: 0,
                        symbols: 8,
                    },
                )],
                20,
                1,
            )
            .expect("register_artifact");

        assert_eq!(applied, Applied::Registered(Registered::New(obj_key)));
        assert!(bud3.object(&obj_key).is_some());
        let stored = domain.artifact(&artifact_id).expect("artifact");
        assert_eq!(stored.content_ref.content_id, cid);
        assert_eq!(stored.object_commitment, obj_key);
    }
}
