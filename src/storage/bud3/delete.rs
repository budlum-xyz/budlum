//! Reference dependencies, cryptographic shredding (`SocialDelete`), and DAO
//! public content deletion (Section 6.8.2 & Section 6.8.3).
//!
//! * Same-owner base dependencies (delta codec 11 / crop derivation codec 10):
//!   a dependent object may only reference a base object owned by the same
//!   account, and increases the base object's live dependency count so the base
//!   object cannot be deleted until dependent objects are detached/rehydrated.
//! * Cryptographic erasure (`SocialDelete` / sealed NFT burn): atomically shreds
//!   every listed unlinkable [`GrantRow`] (verified via one-time ML-DSA-65
//!   signatures) so the network stops serving those key packages immediately,
//!   removes the NFT reference, and writes a permanent tombstone once zero
//!   references remain.
//! * DAO public takedown: removes a public content digest, all referencing NFTs,
//!   and all placed shares, recording a permanent tombstone.

use super::registry::{Address, NftId, ObjectKey};

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

