//! Content reference and refusal bridge for B.U.D. 3.0.
//!
//! `ContentRef` is the narrow 32-byte content handle held by NFTs, AI
//! inference inputs/outputs, Pollen data assets, and Budlum Go domain records.
//! Direct node-local content registration refuses with [`StorageError::Bud3NotReady`]
//! until the in-block B.U.D. 3.0 object flow lands.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::address::Address;
use crate::storage::bud3::content_id::ContentId;

/// Minimal content reference held by higher-level protocol modules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentRef {
    /// Content identifier (32-byte digest + optional byte length).
    pub content_id: ContentId,
    /// Declared byte length of the original content.
    pub total_size: u64,
    /// Declared MIME content type.
    pub content_type: String,
    /// Owner address that declared the content.
    pub owner: Address,
}

/// Errors returned by the B.U.D. 3.0 content bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Content registration is closed until the in-block B.U.D. 3.0 object flow lands.
    Bud3NotReady,
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bud3NotReady => write!(
                f,
                "B.U.D. 3.0 content registration is not open on this build; submit a signed storage transaction once the object flow lands"
            ),
        }
    }
}

impl std::error::Error for StorageError {}

/// Content registration door; refuses until the in-block B.U.D. 3.0 object flow lands.
///
/// # Errors
///
/// Always returns [`StorageError::Bud3NotReady`] at this milestone.
pub fn register_content(
    _bytes: &[u8],
    _content_type: &str,
    _owner: Address,
) -> Result<ContentRef, StorageError> {
    Err(StorageError::Bud3NotReady)
}

/// Positive content-ownership lookup table held on `AccountState` until the full
/// B.U.D. 3.0 object registry lands.
///
/// In production this table starts empty and has no unauthenticated write door,
/// so `PollenRegisterDataAsset` fails closed unless positive ownership exists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentOwnershipBook {
    owners: BTreeMap<[u8; 32], Address>,
}

impl ContentOwnershipBook {
    /// Look up the recorded owner of a 32-byte content digest.
    #[must_use]
    pub fn owner_of(&self, cid: &ContentId) -> Option<Address> {
        self.owners.get(cid.as_bytes()).copied()
    }

    /// Record positive ownership in unit/integration tests that exercise
    /// downstream consumers (such as Pollen data-asset binding) before the
    /// full B.U.D. 3.0 object registry lands.
    #[cfg(test)]
    pub fn record_test_owner(&mut self, cid: ContentId, owner: Address) {
        self.owners.insert(*cid.as_bytes(), owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_registration_refused_until_bud3_ready() {
        let owner = Address::from([0x11; 32]);
        assert_eq!(
            register_content(b"hello bud3", "text/plain", owner),
            Err(StorageError::Bud3NotReady)
        );
    }

    #[test]
    fn ownership_book_is_empty_by_default() {
        let book = ContentOwnershipBook::default();
        let cid = ContentId::public(b"unregistered");
        assert_eq!(book.owner_of(&cid), None);
    }
}
