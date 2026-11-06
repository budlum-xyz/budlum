//! B.U.D. 3.0 Education Domain artifact registration (`StorageTxV3::RegisterObject`,
//! Section 5.6, WP-23, BLG-261).
//! exposed for Education Domain transaction builders and research/dataset registries.
//!
//! Every educational or research artifact is addressed by its B.U.D. 3.0
//! [`ContentId`] and registered on-chain through [`StorageTxV3::RegisterObject`]
//! rather than any retired 2.0 manifest transaction.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{ArtifactKind, Visibility as DomainVisibility};
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::storage::bud3::content_id::ContentId;
use crate::storage::bud3::content_ref::{ContentRef, ContentRefError};
use crate::storage::bud3::pipeline::ObjectRecord;
use crate::storage::bud3::placement::Share;
use crate::storage::bud3::registry::{Bud3Registry, ObjectKey, RegistryError};
use crate::storage::bud3::tx::{apply as apply_bud3_tx, Applied, StorageTxV3};

/// Domain tag committing an Education Domain artifact record.
pub const DOMAIN_EDUCATION_ARTIFACT: &[u8] = b"BDLM_BUD3_EDUCATION_ARTIFACT_V1";

/// Errors returned by B.U.D. 3.0 Education Domain registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EducationDomainError {
    /// Zero contributor, zero `ContentId`, zero metadata hash, or zero timestamp.
    InvalidArtifact(&'static str),
    /// Supplied `ObjectRecord.content_id` does not match the artifact `ContentId`.
    ContentIdMismatch,
    /// Invalid `ContentRef`.
    InvalidContentRef(ContentRefError),
    /// `StorageTxV3::RegisterObject` execution failed in [`Bud3Registry`].
    Storage(RegistryError),
}

impl std::fmt::Display for EducationDomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArtifact(msg) => write!(f, "invalid education artifact: {msg}"),
            Self::ContentIdMismatch => {
                f.write_str("education artifact ContentId does not match B.U.D. 3.0 ObjectRecord")
            }
            Self::InvalidContentRef(e) => write!(f, "invalid ContentRef: {e:?}"),
            Self::Storage(e) => write!(f, "bud3 register_object error: {e:?}"),
        }
    }
}

impl std::error::Error for EducationDomainError {}

/// Canonical B.U.D. 3.0 Education Domain artifact record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EducationArtifact {
    pub contributor: Address,
    pub content_ref: ContentRef,
    pub object_commitment: ObjectKey,
    pub artifact_kind: ArtifactKind,
    pub visibility: DomainVisibility,
    pub metadata_hash: [u8; 32],
    pub created_at: u64,
}

impl EducationArtifact {
    /// Validate non-zero identity and metadata fields.
    ///
    /// # Errors
    ///
    /// Returns [`EducationDomainError::InvalidArtifact`] if any required field is zero.
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
    /// exposed for Education Domain indexing and attestation verification.
    #[must_use]
    pub fn artifact_id(&self) -> [u8; 32] {
        let kind_tag: u8 = match self.artifact_kind {
            ArtifactKind::Dataset => 1,
            ArtifactKind::Research => 2,
            ArtifactKind::IntellectualProperty => 3,
            ArtifactKind::Educational => 4,
        };
        let vis_tag: u8 = match self.visibility {
            DomainVisibility::Public => 1,
            DomainVisibility::EducatorOnly => 2,
            DomainVisibility::PeerOnly => 3,
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
    pub artifact_kind: ArtifactKind,
    pub visibility: DomainVisibility,
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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the canonical [`StorageTxV3::RegisterObject`] payload for an artifact.
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

    /// Register an artifact's B.U.D. 3.0 object via [`StorageTxV3::RegisterObject`]
    /// and record the [`EducationArtifact`] (`BLG-261`).
    /// exposed for Education Domain registration handlers and SDK callers.
    ///
    /// # Errors
    ///
    /// Returns [`EducationDomainError`] if validation or `RegisterObject` fails.
    pub fn register_artifact(
        &mut self,
        bud3: &mut Bud3Registry,
        spec: ArtifactRegistrationSpec,
        record: ObjectRecord,
        shares: Vec<(u64, Share)>,
        lifetime_epochs: u64,
        current_epoch: u64,
    ) -> Result<([u8; 32], Applied), EducationDomainError> {
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
        let up = prepare_public_upload(&paper, &P, &Bud3Limits::default(), 8).unwrap();
        let cid = up.record.content_id;
        let obj_key = up.record.commitment;

        let (artifact_id, applied) = domain
            .register_artifact(
                &mut bud3,
                ArtifactRegistrationSpec {
                    contributor: scholar,
                    content_id: cid,
                    artifact_kind: ArtifactKind::Educational,
                    visibility: DomainVisibility::Public,
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
            .unwrap();

        assert_eq!(applied, Applied::Registered(Registered::New(obj_key)));
        assert!(bud3.object(&obj_key).is_some());
        let stored = domain.artifact(&artifact_id).unwrap();
        assert_eq!(stored.content_ref.content_id, cid);
        assert_eq!(stored.object_commitment, obj_key);
    }
}
