//! Temporary content reference (Section 5.7 of THE BUDLUM DIREKTIF).
//!
//! Between WP-07 (legacy storage removal) and WP-21 (upload/view/`StorageTx`
//! v3 landing), dependent modules (BNS, SocialFi, Data Market, education
//! domain, content gateway, wallet/CLI) need one stable handle to a piece of
//! content without importing the retired B.U.D. 2.0 manifest machinery.
//! `ContentRef` is that handle: a newtype around [`ContentId`].
//!
//! Any transaction path that needs to register or resolve content against
//! the on-chain registry returns [`Bud3NotReady`](ContentRefError::Bud3NotReady)
//! until WP-21 lands. The refusal is pinned by a test
//! (`content_registration_refused_until_bud3_ready`) so the gate cannot be
//! silently lifted. Once WP-21 merges this type stays as the permanent
//! content handle used across the tree.

use crate::storage::bud3::content_id::ContentId;

/// A stable handle to a piece of content.
///
/// All dependent modules (BNS, SocialFi, Data Market, education domain,
/// content gateway, wallet, CLI) import this type rather than referencing
/// the retired legacy content-registry types. The inner id is the only
/// datum exposed until the upload/view pipeline lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentRef {
    /// The content identifier (public SHA-256+len or sealed keyed HMAC+len).
    pub content_id: ContentId,
}

impl ContentRef {
    /// Build a reference from an already-known content id.
    #[must_use]
    pub const fn new(content_id: ContentId) -> Self {
        Self { content_id }
    }
}

/// Failures reported through the temporary content reference surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRefError {
    /// B.U.D. 3.0 registration/retrieval is not yet wired. Any transaction
    /// that needs to register or resolve content refuses with this error
    /// until WP-21 lands. The refusal is tested
    /// (`content_registration_refused_until_bud3_ready`); removing the
    /// variant or its production call site is a defect until WP-21 merges.
    Bud3NotReady,
}

impl core::fmt::Display for ContentRefError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bud3NotReady => f.write_str(
                "B.U.D. 3.0 content registration is not yet wired (WP-21); \
                 refusing this path rather than routing through legacy storage",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_registration_refused_until_bud3_ready() {
        // The temporary refusal exists and names the door (WP-21). When the
        // full pipeline lands this test is replaced by a happy-path test;
        // until then the error is the contract.
        let err = ContentRefError::Bud3NotReady;
        let msg = err.to_string();
        assert!(msg.contains("WP-21"), "error must name the landing package: {msg}");
        assert!(
            msg.contains("not yet wired") || msg.contains("refusing"),
            "error must describe the refusal: {msg}"
        );
    }
}
