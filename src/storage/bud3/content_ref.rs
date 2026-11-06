//! The temporary content reference that keeps dependent modules compiling
//! while the legacy storage system is removed.
//!
//! Between the legacy removal and the `StorageTx` v3 door, dependent modules
//! carry only [`ContentRef`]. Every content-registration request is refused
//! with `StorageError::Bud3NotReady` until the v3 door is wired. When the v3
//! door lands this type stays as the permanent reference.

use super::content_id::ContentId;
use serde::{Deserialize, Serialize};

/// A reference to content: the B.U.D. 3.0 content id, nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentRef {
    /// The content identifier.
    pub content_id: ContentId,
}

impl ContentRef {
    /// Wrap a content id.
    #[must_use]
    pub fn new(content_id: ContentId) -> Self {
        Self { content_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_ref_carries_only_the_content_id() {
        let id = ContentId {
            kind: super::super::content_id::ContentIdKind::Public,
            digest: [7u8; 32],
            len: 42,
        };
        let r = ContentRef::new(id);
        assert_eq!(r.content_id, id);
    }
}
