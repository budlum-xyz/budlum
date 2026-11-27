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
use crate::storage::bud3::registry::{Bud3Registry, ObjectKey, Registered, RegistryError};
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

/// Publish the artifact only when the store actually took it.
///
/// [`register_artifact`](EducationDomainRegistry::register_artifact) inserted
/// its record unconditionally, so an apply that deduplicated (or one that
/// replaced an existing object) still left a domain entry behind: the domain
/// listed a contribution the storage layer had not stored as new. The record
/// is admitted only when the store reports a new object under the same key.
///
/// # Errors
///
/// [`EducationDomainError::ArtifactNotStored`] when the apply did not report a
/// new object, or reported one under a different key than the artifact names.
fn admit_registered(
    artifact: &EducationArtifact,
    applied: &Applied,
) -> Result<(), EducationDomainError> {
    match applied {
        Applied::Registered(Registered::New(key)) if key == &artifact.object_commitment => Ok(()),
        _ => Err(EducationDomainError::ArtifactNotStored),
    }
}

/// Errors returned by B.U.D. 3.0 Education Domain registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EducationDomainError {
    InvalidArtifact(&'static str),
    ContentIdMismatch,
    InvalidContentRef(ContentRefError),
    Storage(RegistryError),
    /// The store did not take the artifact as a new object under its key.
    ArtifactNotStored,
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
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
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
        // A commitment the object key does not match is another object's
        // artifact: `artifact_id` folds both, and the domain would then serve a
        // record whose own two halves disagree.
        if self.content_ref.object_commitment != self.object_commitment {
            return Err(EducationDomainError::InvalidArtifact(
                "object_commitment disagrees with content_ref commitment",
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
    #[serde(with = "crate::core::map_keys")]
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
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
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
        // The store decides whether the artifact exists; the domain only
        // records what the store took.
        admit_registered(&artifact, &applied)?;

        let id = artifact.artifact_id();
        // One artifact id is one artifact. A second registration under the same
        // id used to overwrite the first, so the domain's answer to "who
        // contributed this" became whoever registered last.
        if let Some(existing) = self.artifacts.get(&id) {
            if existing != &artifact {
                return Err(EducationDomainError::InvalidArtifact(
                    "an artifact with this id is already registered",
                ));
            }
        }
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
                vec![
                    (
                        0,
                        Share {
                            validator: [5u8; 32],
                            class: Class::Full,
                            first_esi: 0,
                            symbols: 4,
                        },
                    ),
                    (
                        0,
                        Share {
                            validator: [6u8; 32],
                            class: Class::Full,
                            first_esi: 4,
                            symbols: 4,
                        },
                    ),
                ],
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

    fn budget_spec(contributor: Address, cid: ContentId) -> ArtifactRegistrationSpec {
        ArtifactRegistrationSpec {
            contributor,
            content_id: cid,
            artifact_kind: EducationArtifactKind::Research,
            visibility: EducationVisibility::Public,
            metadata_hash: [0xCD; 32],
            created_at: 1_700_000_001,
        }
    }

    /// The domain may only list what the store took as a new object. The record
    /// used to be inserted unconditionally, so a deduplicated apply still left a
    /// contribution behind that the storage layer had not stored as new.
    #[test]
    fn an_artifact_is_recorded_only_when_the_store_took_it_as_new() {
        let scholar = Address([0x41; 32]);
        let mut bud3 = Bud3Registry::default();
        let mut domain = EducationDomainRegistry::new();
        let payload = b"lecture notes on lattice assumptions".repeat(5);
        let up = prepare_public_upload(&payload, &P, &Bud3Limits::default(), 8).unwrap();
        let cid = up.record.content_id;
        let obj = up.record.commitment;
        assert_ne!(obj, [0u8; 32], "the upload carries a commitment");

        let shares = vec![
            (
                0,
                Share {
                    validator: [5u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 4,
                },
            ),
            (
                0,
                Share {
                    validator: [6u8; 32],
                    class: Class::Full,
                    first_esi: 4,
                    symbols: 4,
                },
            ),
        ];

        let (id, applied) = domain
            .register_artifact(
                &mut bud3,
                budget_spec(scholar, cid),
                up.record.clone(),
                shares.clone(),
                20,
                1,
            )
            .expect("first registration");
        assert!(matches!(applied, Applied::Registered(Registered::New(_))));
        assert!(domain.artifact(&id).is_some());

        // The gate itself: only a `New` under the artifact's own key admits.
        let artifact = domain.artifact(&id).expect("artifact").clone();
        let other_key: ObjectKey = [0x99; 32];
        for refused in [
            Applied::Registered(Registered::Deduplicated(obj)),
            Applied::Registered(Registered::New(other_key)),
            Applied::Acked(1),
            Applied::Repaired,
        ] {
            assert_eq!(
                admit_registered(&artifact, &refused),
                Err(EducationDomainError::ArtifactNotStored),
                "an apply that did not store a new object under this key was admitted"
            );
        }
        assert_eq!(
            admit_registered(&artifact, &Applied::Registered(Registered::New(obj))),
            Ok(())
        );
    }

    /// The refusal has to reach the caller, not just live in a helper.
    ///
    /// A sealed object is the reachable dedupe: the store answers `Deduplicated`
    /// for a second registration of the same sealed content, and the domain must
    /// then keep no entry. The first block also records a hard limit found while
    /// writing this test: a *public* re-registration of unconfirmed custody is
    /// refused by the store itself (`BadRecord("awaiting custody confirmation")`),
    /// so the public path can never reach the seeded-contribution case.
    #[test]
    fn a_deduplicated_sealed_registration_leaves_no_domain_entry() {
        use crate::storage::bud3::content_id::{ContentIdKind, ContentKey};
        use crate::storage::bud3::pipeline::prepare_sealed_upload;
        let scholar = Address([0x43; 32]);
        let mut bud3 = Bud3Registry::default();
        let mut domain = EducationDomainRegistry::new();
        let payload = b"sealed dataset of post-quantum signature timings".repeat(5);
        let key = ContentKey([0x7Au8; 32]);
        let up = prepare_sealed_upload(&payload, &key, [3u8; 24], &P, &Bud3Limits::default(), 8)
            .expect("sealed upload");
        let up2 = prepare_sealed_upload(&payload, &key, [3u8; 24], &P, &Bud3Limits::default(), 8)
            .expect("sealed upload again");
        let cid = up.record.content_id;
        assert_eq!(cid.kind, ContentIdKind::Sealed);
        let shares = vec![
            (
                0,
                Share {
                    validator: [5u8; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 4,
                },
            ),
            (
                0,
                Share {
                    validator: [6u8; 32],
                    class: Class::Full,
                    first_esi: 4,
                    symbols: 4,
                },
            ),
        ];
        let (id, applied) = domain
            .register_artifact(
                &mut bud3,
                budget_spec(scholar, cid),
                up.record,
                shares.clone(),
                20,
                1,
            )
            .expect("first sealed registration");
        assert_eq!(
            applied,
            Applied::Registered(Registered::New(up2.record.commitment))
        );
        assert!(domain.artifact(&id).is_some());

        let repeat = domain.register_artifact(
            &mut bud3,
            budget_spec(scholar, cid),
            up2.record,
            shares,
            20,
            2,
        );
        assert!(
            repeat.is_err(),
            "a repeat sealed registration was accepted as a contribution: {repeat:?}"
        );
        assert_eq!(
            domain.artifacts.len(),
            1,
            "the refused registration wrote a second entry"
        );
    }

    #[test]
    fn rejected_scoped_registration_does_not_mutate_storage() {
        use crate::storage::bud3::content_id::ContentKey;
        use crate::storage::bud3::pipeline::prepare_sealed_upload;
        let key = ContentKey([0x7a; 32]);
        let payload = b"sealed dataset of post-quantum signature timings".repeat(5);
        let first = prepare_sealed_upload(&payload, &key, [3u8; 24], &P, &Bud3Limits::default(), 8)
            .unwrap();
        let second =
            prepare_sealed_upload(&payload, &key, [3u8; 24], &P, &Bud3Limits::default(), 8)
                .unwrap();
        let shares = vec![
            (
                0,
                Share {
                    validator: [5; 32],
                    class: Class::Full,
                    first_esi: 0,
                    symbols: 4,
                },
            ),
            (
                0,
                Share {
                    validator: [6; 32],
                    class: Class::Full,
                    first_esi: 4,
                    symbols: 4,
                },
            ),
        ];
        let mut store = Bud3Registry::default();
        let mut domain = EducationDomainRegistry::new();
        let cid = first.record.content_id;
        domain
            .register_artifact(
                &mut store,
                budget_spec(Address([0x43; 32]), cid),
                first.record,
                shares.clone(),
                20,
                1,
            )
            .unwrap();
        let before = store.clone();
        let result = domain.register_artifact(
            &mut store,
            budget_spec(Address([0x44; 32]), cid),
            second.record,
            shares,
            20,
            2,
        );
        assert_eq!(result, Err(EducationDomainError::ArtifactNotStored));
        assert_eq!(
            store, before,
            "a rejected scoped registration mutated the store"
        );
    }

    /// An artifact whose commitment and content reference disagree is refused:
    /// `artifact_id` folds both, so the domain would serve a record whose own
    /// two halves name different objects.
    #[test]
    fn an_artifact_commitment_that_disagrees_with_its_reference_is_refused() {
        use crate::storage::bud3::content_id::ContentIdKind;
        let record = match ContentRef::new(
            ContentId {
                kind: ContentIdKind::Public,
                digest: [0x11; 32],
                len: 32,
            },
            [0x22; 32],
            None,
        ) {
            Ok(record) => record,
            Err(err) => panic!("content ref builds: {err:?}"),
        };
        let mismatch = EducationArtifact {
            contributor: Address([0x42; 32]),
            content_ref: record,
            object_commitment: [0x23; 32],
            artifact_kind: EducationArtifactKind::Dataset,
            visibility: EducationVisibility::PeerOnly,
            metadata_hash: [0xEE; 32],
            created_at: 7,
        };
        assert_eq!(
            mismatch.validate(),
            Err(EducationDomainError::InvalidArtifact(
                "object_commitment disagrees with content_ref commitment"
            ))
        );

        let agreed = EducationArtifact {
            object_commitment: [0x22; 32],
            ..mismatch.clone()
        };
        assert_eq!(agreed.validate(), Ok(()));
        assert_ne!(agreed.artifact_id(), [0u8; 32]);

        // The two halves are inside the id, so swapping only the commitment
        // changes it.
        let swapped = EducationArtifact {
            object_commitment: [0x24; 32],
            ..agreed.clone()
        };
        assert_ne!(swapped.artifact_id(), agreed.artifact_id());
    }
}
