//! Narrow B.U.D. 3.0 content registration handle for application domains (`WP-07`, `WP-21`).
//! Convenience: re-exported at `crate::storage::{register_content, ContentRef, StorageError}`.

use serde::{Deserialize, Serialize};

use crate::core::address::Address;
use crate::storage::bud3::bof1::Object;
use crate::storage::bud3::content_id::ContentId;
use crate::storage::bud3::limits::{Bud3Limits, LimitError};

/// Application-domain content handle binding a B.U.D. 3.0 [`ContentId`] (`WP-07`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentRef {
    /// B.U.D. 3.0 content identifier (`SHA-256` + byte length).
    pub content_id: ContentId,
    /// Declared byte length of the content.
    pub total_size: u64,
    /// Declared MIME content type.
    pub content_type: String,
    /// Owner address that registered the content.
    pub owner: Address,
}

/// Errors returned when validating content for B.U.D. 3.0 registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Content exceeds genesis `Bud3Limits` (`LimitError`).
    LimitExceeded(LimitError),
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LimitExceeded(err) => write!(f, "B.U.D. 3.0 content limit exceeded: {err:?}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Validate and package public content into a B.U.D. 3.0 [`ContentRef`] (`WP-21` item 7).
/// Convenience: exposed for AI inference, SocialFi, and BNS callers.
///
/// # Errors
///
/// Returns [`StorageError::LimitExceeded`] if `bytes` violates [`Bud3Limits::GENESIS`].
pub fn register_content(
    bytes: &[u8],
    content_type: &str,
    owner: Address,
) -> Result<ContentRef, StorageError> {
    Bud3Limits::GENESIS
        .check_content_len(bytes.len() as u64)
        .map_err(StorageError::LimitExceeded)?;
    let _bof1 = Object::raw_public(bytes);
    let content_id = ContentId::public(bytes);
    Ok(ContentRef {
        content_id,
        total_size: content_id.len,
        content_type: content_type.to_owned(),
        owner,
    })
}
