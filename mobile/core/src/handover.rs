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

/// Ask each holder in order. The first non-empty answer within
/// [`SHARE_OWNER_TIMEOUT`] wins.
///
/// Callers that know the expected symbol leaf and byte length must prefer
/// [`fetch_verified_from_holders`] so a corrupted or truncated answer from an
/// earlier holder triggers deterministic failover instead of poisoning custody.
///
/// # Errors
///
/// [`CoreError`] when every holder is silent or returns empty bytes.
pub fn fetch_from_holders<S: ShareSource>(
    holders: &[Holder],
    source: &S,
) -> Result<Vec<u8>, CoreError> {
    for holder in holders {
        if let Some(bytes) = source.fetch(holder, SHARE_OWNER_TIMEOUT) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }
    }
    Err(CoreError::new(
        "mobile_share_owners_silent",
        "no share owner answered within two seconds",
    ))
}

/// Ask each holder in order and return the first response matching both
/// `expected_len` and `expected_leaf` under [`crate::custody::symbol_leaf`].
///
/// Checking `expected_len` alongside `expected_leaf` prevents a malicious
/// holder from truncating trailing zero bytes inside the final 64-byte Merkle
/// sub-block while still reproducing the same sub-block leaf hash.
///
/// # Errors
///
/// [`CoreError`] when `expected_len` is zero or above
/// [`crate::store::MAX_SYMBOL_BYTES`], when every holder is silent, or when
/// responding holders only serve mismatched bytes.
pub fn fetch_verified_from_holders<S: ShareSource>(
    holders: &[Holder],
    expected_leaf: &[u8; 32],
    expected_len: usize,
    source: &S,
) -> Result<Vec<u8>, CoreError> {
    if expected_len == 0 || expected_len > crate::store::MAX_SYMBOL_BYTES {
        return Err(CoreError::new(
            "mobile_expected_symbol_len",
            "expected symbol length must be between 1 and MAX_SYMBOL_BYTES",
        ));
    }
    let mut saw_invalid = false;
    for holder in holders {
        if let Some(bytes) = source.fetch(holder, SHARE_OWNER_TIMEOUT) {
            if bytes.len() == expected_len && crate::custody::symbol_leaf(&bytes) == *expected_leaf
            {
                return Ok(bytes);
            }
            saw_invalid = true;
        }
    }
    if saw_invalid {
        Err(CoreError::new(
            "mobile_share_owners_unverified",
            "no responding share owner supplied bytes matching the committed symbol leaf and length",
        ))
    } else {
        Err(CoreError::new(
            "mobile_share_owners_silent",
            "no share owner answered within two seconds",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::symbol_leaf;
    use std::collections::BTreeMap;

    struct ScriptedSource {
        answers: BTreeMap<[u8; 32], Vec<u8>>,
    }

    impl ShareSource for ScriptedSource {
        fn fetch(&self, holder: &Holder, _timeout: Duration) -> Option<Vec<u8>> {
            self.answers.get(&holder.address).cloned()
        }
    }

    #[test]
    fn verified_handover_skips_corrupted_and_zero_truncated_peers_until_honest_holder() {
        // Honest 64-byte symbol ends with trailing zeros so a 16-byte prefix
        // shares the exact same 64-byte zero-padded sub-block leaf hash.
        let mut honest = vec![0u8; 64];
        honest[..16].copy_from_slice(b"budlum-custody!!");
        let truncated = honest[..16].to_vec();
        assert_eq!(
            symbol_leaf(&honest),
            symbol_leaf(&truncated),
            "sub-block zero padding shares leaf hash; length check must separate them"
        );
        let expected_leaf = symbol_leaf(&honest);

        let h_silent = Holder { address: [1; 32] };
        let h_corrupt = Holder { address: [2; 32] };
        let h_truncated = Holder { address: [3; 32] };
        let h_honest = Holder { address: [4; 32] };

        let mut answers = BTreeMap::new();
        answers.insert(h_corrupt.address, vec![0xFF; 64]);
        answers.insert(h_truncated.address, truncated);
        answers.insert(h_honest.address, honest.clone());
        let source = ScriptedSource { answers };

        let got = fetch_verified_from_holders(
            &[
                h_silent.clone(),
                h_corrupt.clone(),
                h_truncated.clone(),
                h_honest,
            ],
            &expected_leaf,
            honest.len(),
            &source,
        )
        .expect("verified handover must skip silent, corrupt, and zero-truncated holders");
        assert_eq!(got, honest);

        // If only Byzantine holders answer, the refusal distinguishes corruption from silence.
        assert_eq!(
            fetch_verified_from_holders(
                &[h_silent.clone(), h_corrupt, h_truncated],
                &expected_leaf,
                honest.len(),
                &source,
            )
            .err()
            .map(|e| e.code),
            Some("mobile_share_owners_unverified")
        );

        // Pure silence keeps its original code.
        assert_eq!(
            fetch_verified_from_holders(&[h_silent], &expected_leaf, honest.len(), &source)
                .err()
                .map(|e| e.code),
            Some("mobile_share_owners_silent")
        );
    }
}
