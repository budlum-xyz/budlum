//! Temporary content reference (IP-07, section 5.7).
//!
//! `ContentRef` is the only type dependent modules may use until B.U.D. 3.0
//! is complete. It carries the content id that will later be backed by a
//! full B.U.D. 3.0 object. Content registration itself is rejected with
//! `StorageError::Bud3NotReady` until IP-21.

use crate::storage::content_id::ContentId;

/// Temporary reference to content, used by BNS, SocialFi, Data Market, Education
/// and the content gateway until `src/storage/bud3` is the full storage system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ContentRef {
    pub content_id: ContentId,
}

impl ContentRef {
    pub fn new(content_id: ContentId) -> Self {
        Self { content_id }
    }
}
