//! Reference dependencies, cryptographic shredding (`SocialDelete`), and DAO
//! public content deletion (Section 6.8.2 & Section 6.8.3).
//! exposed for `Bud3Registry`, `StorageTxV3::SocialDelete`, and governance takedown.
//!
//! * Same-owner base dependencies (delta codec 11 / crop derivation codec 10):
//!   a dependent object may only reference a base object owned by the same
//!   account, and increases the base object's live dependency count so the base
//!   object cannot be deleted until dependent objects are detached/rehydrated.
//! * Cryptographic erasure (`SocialDelete` / sealed NFT burn): atomically shreds
//!   every listed unlinkable `GrantRow` (verified via one-time ML-DSA-65
//!   signatures) so the network stops serving those key packages immediately,
//!   removes the NFT reference, and writes a permanent tombstone once zero
//!   references remain.
//! * DAO public takedown: removes a public content digest, all referencing NFTs,
//!   and all placed shares, recording a permanent tombstone.

use super::registry::{Address, ObjectKey};
use crate::core::hash::hash_fields_bytes;
use std::collections::BTreeSet;

/// Domain tag for deterministic [`DeletionSet`] commitment roots.
const DELETION_SET_TAG: &[u8] = b"BDLM_BUD3_DELETION_SET_V1";

/// Cryptographic erasure tombstone set (`deletion_set`) tracking revoked
/// consent/view grants and permanently deleted sealed objects.
///
/// Any `ConsentProof` or `ComputeWithoutSeeingPermit` whose grant tag or
/// object commitment appears in the `DeletionSet` is refused even before key
/// unwrapping or STARK proof verification.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeletionSet {
    revoked_grants: BTreeSet<[u8; 32]>,
    deleted_objects: BTreeSet<[u8; 32]>,
}

impl DeletionSet {
    /// WIRING: exposed to consent and compute verifiers that build revocation
    /// snapshots. Record an unlinkable grant tag as cryptographically erased.
    pub fn tombstone_grant(&mut self, grant_tag: [u8; 32]) {
        self.revoked_grants.insert(grant_tag);
    }

    /// Record a sealed or consented object commitment as deleted.
    pub fn tombstone_object(&mut self, object: ObjectKey) {
        self.deleted_objects.insert(object);
    }

    /// True if `grant_tag` has been tombstoned.
    #[must_use]
    pub fn contains_grant(&self, grant_tag: &[u8; 32]) -> bool {
        self.revoked_grants.contains(grant_tag)
    }

    /// True if `object` has been tombstoned.
    #[must_use]
    pub fn contains_object(&self, object: &ObjectKey) -> bool {
        self.deleted_objects.contains(object)
    }

    /// True if either `grant_tag` or `object` is present in the deletion set.
    #[must_use]
    pub fn is_revoked(&self, grant_tag: &[u8; 32], object: &ObjectKey) -> bool {
        self.contains_grant(grant_tag) || self.contains_object(object)
    }

    /// Number of tombstoned grant tags plus tombstoned objects.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revoked_grants
            .len()
            .saturating_add(self.deleted_objects.len())
    }

    /// Whether no revocations or deletions are recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revoked_grants.is_empty() && self.deleted_objects.is_empty()
    }

    /// WIRING: exposed to transaction builders and indexers that commit the
    /// canonical domain-separated root of the sorted tombstone sets.
    #[must_use]
    pub fn deletion_root(&self) -> [u8; 32] {
        let mut acc = hash_fields_bytes(&[DELETION_SET_TAG, b"INIT"]);
        for tag in &self.revoked_grants {
            acc = hash_fields_bytes(&[DELETION_SET_TAG, b"GRANT", &acc, tag]);
        }
        for obj in &self.deleted_objects {
            acc = hash_fields_bytes(&[DELETION_SET_TAG, b"OBJECT", &acc, obj]);
        }
        acc
    }
}

/// Authorization pair `(grant_tag, one_time_signature)` submitted when burning
/// or socially deleting a sealed NFT so its active grant capsules are shredded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantShredAuth {
    /// Unlinkable grant tag `H(BDLM_BUD3_GRANT_V1 || nft_id || grant_nonce)`.
    pub grant_tag: [u8; 32],
    /// ML-DSA-65 signature over `grant_revoke_digest(grant_tag)` under `one_time_pk`.
    pub one_time_signature: Vec<u8>,
}

/// Summary of an executed `SocialDelete` or DAO takedown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShredOutcome {
    /// Object whose NFT reference or public content was targeted.
    pub object: ObjectKey,
    /// Number of unlinkable view-grant key packages permanently shredded.
    pub grants_shredded: usize,
    /// True when the object reached zero references and was tombstoned.
    pub object_deleted: bool,
}

/// Check the Section 6.8.2.3 same-owner rule before registering or transferring
/// a dependent delta/derived object.
#[must_use]
pub fn check_same_owner_dependency(dependent_owner: &Address, base_owner: &Address) -> bool {
    dependent_owner == base_owner
}

/// Convenience: marker helper documenting that NFT transfer of a dependent object
/// requires standalone rehydration first when `from_owner != to_owner`.
#[must_use]
pub fn requires_rehydration_before_transfer(
    has_base_dependency: bool,
    from_owner: &Address,
    to_owner: &Address,
) -> bool {
    has_base_dependency && from_owner != to_owner
}

#[cfg(test)]
mod deletion_set_tests {
    use super::*;

    #[test]
    fn deletion_set_tombstones_grants_and_objects_deterministically() {
        let mut set = DeletionSet::default();
        assert!(set.is_empty());
        let empty_root = set.deletion_root();

        let g1 = [0x11u8; 32];
        let o1 = [0x22u8; 32];
        let g2 = [0x33u8; 32];
        assert!(!set.is_revoked(&g1, &o1));

        set.tombstone_grant(g1);
        assert!(set.is_revoked(&g1, &o1));
        assert!(set.contains_grant(&g1));
        assert!(!set.contains_object(&o1));
        let grant_root = set.deletion_root();
        assert_ne!(grant_root, empty_root);

        set.tombstone_object(o1);
        assert!(set.is_revoked(&g2, &o1));
        assert_eq!(set.len(), 2);
        assert_ne!(set.deletion_root(), grant_root);
    }
}
