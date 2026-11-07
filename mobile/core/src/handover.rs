//! Client-side share handover (section 7.6).
//!
//! If a share owner does not answer in two seconds, the client asks the
//! next owner. No human step, no governance vote.

use crate::error::CoreError;
use std::time::Duration;

/// How long the client waits for one share owner.
pub const SHARE_OWNER_TIMEOUT: Duration = Duration::from_secs(2);

/// A holder the client can ask for a symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    /// Validator address.
    pub address: [u8; 32],
}

/// A source the host uses to fetch a symbol from one holder.
pub trait ShareSource {
    /// Fetch the symbol from `holder`, or `None` when the holder is silent
    /// for `timeout`.
    fn fetch(&self, holder: &Holder, timeout: Duration) -> Option<Vec<u8>>;
}

/// Ask each holder in order. The first that answers within
/// [`SHARE_OWNER_TIMEOUT`] wins.
///
/// # Errors
///
/// [`CoreError`] when every holder is silent.
pub fn fetch_from_holders<S: ShareSource>(
    holders: &[Holder],
    source: &S,
) -> Result<Vec<u8>, CoreError> {
    for holder in holders {
        if let Some(bytes) = source.fetch(holder, SHARE_OWNER_TIMEOUT) {
            return Ok(bytes);
        }
    }
    Err(CoreError::new(
        "mobile_share_owners_silent",
        "no share owner answered within two seconds",
    ))
}
