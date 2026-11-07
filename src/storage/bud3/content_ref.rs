//! Permanent B.U.D. 3.0 content reference (`ContentRef`, WP-23 & Section 5.7).
//!
//! exposed for: BNS, SocialFi, Data Market, Education Domain, and App Registry.

use super::content_id::ContentId;
use super::registry::{NftId, ObjectKey};
use serde::{Deserialize, Serialize};

/// Permanent on-chain reference to a B.U.D. 3.0 object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentRef {
    /// Immutable content identifier (SHA-256 public or keyed HMAC-SHA-256 sealed).
    pub content_id: ContentId,
    /// Current BOF-1 object commitment carrying `content_id`.
    pub object_commitment: ObjectKey,
    /// Optional bound NFT reference controlling access grants and lifecycle.
    pub nft_id: Option<NftId>,
}

/// Errors validating a [`ContentRef`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRefError {
    /// `object_commitment` is all-zero.
    ZeroObjectCommitment,
    /// `content_id.digest` is all-zero.
    ZeroContentDigest,
}

impl ContentRef {
    /// Construct and validate a [`ContentRef`].
    ///
    /// exposed for: B.U.D. 3.0 dependent modules (`WP-23`).
    pub fn new(
        content_id: ContentId,
        object_commitment: ObjectKey,
        nft_id: Option<NftId>,
    ) -> Result<Self, ContentRefError> {
        if object_commitment == [0u8; 32] {
            return Err(ContentRefError::ZeroObjectCommitment);
        }
        if content_id.digest == [0u8; 32] {
            return Err(ContentRefError::ZeroContentDigest);
        }
        Ok(Self {
            content_id,
            object_commitment,
            nft_id,
        })
    }

    /// Update the underlying object commitment on `ReplaceObject` while preserving
    /// `content_id` and `nft_id`.
    ///
    /// exposed for: B.U.D. 3.0 `ReplaceObject` flows (`WP-24`).
    pub fn with_replaced_commitment(
        self,
        new_commitment: ObjectKey,
    ) -> Result<Self, ContentRefError> {
        if new_commitment == [0u8; 32] {
            return Err(ContentRefError::ZeroObjectCommitment);
        }
        Ok(Self {
            object_commitment: new_commitment,
            ..self
        })
    }
}


/// Positive content-ownership lookup table held on `AccountState` (`WP-07`).
/// Convenience: exposed for Pollen data-asset ownership checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContentOwnershipBook {
    owners: std::collections::BTreeMap<[u8; 32], crate::core::address::Address>,
}

impl ContentOwnershipBook {
    /// Convenience: look up the recorded owner of a 32-byte content digest.
    #[must_use]
    pub fn owner_of(&self, cid: &ContentId) -> Option<crate::core::address::Address> {
        self.owners.get(cid.as_bytes()).copied()
    }

    /// Record positive ownership in tests.
    #[cfg(test)]
    pub fn record_test_owner(&mut self, cid: ContentId, owner: crate::core::address::Address) {
        self.owners.insert(*cid.as_bytes(), owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_ref_validates_and_updates_commitment_atomically() {
        let cid = ContentId::public(b"permanent bud3 content reference");
        assert_eq!(
            ContentRef::new(cid, [0u8; 32], None),
            Err(ContentRefError::ZeroObjectCommitment)
        );
        let r = ContentRef::new(cid, [0x11; 32], Some([0x22; 32])).expect("ref");
        let replaced = r.with_replaced_commitment([0x33; 32]).expect("replace");
        assert_eq!(replaced.content_id, cid);
        assert_eq!(replaced.nft_id, Some([0x22; 32]));
        assert_eq!(replaced.object_commitment, [0x33; 32]);
    }
}
