//! Content verification - a real SHA-256.
//!
//! The first step of the production path: the skeleton no longer returns a
//! fail-closed "not implemented" error; the content hash is verified with a
//! real SHA-256. If verification fails the answer is `HashMismatch`, and no
//! data flows.

use ai_core::model::Hash32;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

use crate::source::DataError;

/// Verifies content against an expected hex SHA-256.
///
/// # Errors
///
/// - `HashMismatch` if the hex cannot be decoded (empty or malformed).
/// - `HashMismatch` if the digest does not match.
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> Result<(), DataError> {
    let expected: Vec<u8> = hex_bytes(expected_hex).ok_or_else(|| DataError::HashMismatch {
        detail: format!(
            "the expected hex could not be decoded: {}",
            shown(expected_hex)
        ),
    })?;
    if expected.len() != 32 {
        return Err(DataError::HashMismatch {
            detail: format!(
                "a SHA-256 is 32 bytes; {} has a different length",
                shown(expected_hex)
            ),
        });
    }
    let actual = Sha256::digest(data);
    if actual.as_slice() == expected.as_slice() {
        Ok(())
    } else {
        Err(DataError::HashMismatch {
            detail: format!(
                "expected: {}, actual: {}",
                shown(expected_hex),
                hex_of(actual.as_slice())
            ),
        })
    }
}

/// Derives a content_id from content - SHA-256, the production form.
#[must_use]
pub fn content_id_of(data: &[u8]) -> Hash32 {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// One hex digit. Only `0-9a-fA-F`: no sign and no non-ASCII character.
fn hex_nibble(b: u8) -> Option<u8> {
    u8::try_from(char::from(b).to_digit(16)?).ok()
}

/// Decodes hex over bytes, so a multi-byte character cannot split a pair and
/// a `+` sign is not accepted as a digit.
fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_nibble(*pair.first()?)?;
            let lo = hex_nibble(*pair.get(1)?)?;
            Some((hi << 4) | lo)
        })
        .collect()
}

/// A bounded copy of untrusted text for an error message.
fn shown(s: &str) -> String {
    const MAX_CHARS: usize = 80;
    let mut out: String = s.chars().take(MAX_CHARS).collect();
    if s.chars().nth(MAX_CHARS).is_some() {
        out.push_str("...");
    }
    out
}

fn hex_of(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_hash_passes() {
        let hex = hex_of(&content_id_of(b"ai_inference"));
        assert_eq!(verify_sha256(b"ai_inference", &hex), Ok(()));
    }

    #[test]
    fn tampered_data_is_rejected() {
        let hex = hex_of(&content_id_of(b"ai_inference"));
        assert!(matches!(
            verify_sha256(b"lobot", &hex),
            Err(DataError::HashMismatch { .. })
        ));
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert!(matches!(
            verify_sha256(b"x", "zz"),
            Err(DataError::HashMismatch { .. })
        ));
        assert!(matches!(
            verify_sha256(b"x", "abcd"),
            Err(DataError::HashMismatch { .. })
        ));
    }

    #[test]
    fn content_id_is_deterministic_and_32_bytes() {
        assert_eq!(
            content_id_of(b"ai_inference"),
            content_id_of(b"ai_inference")
        );
        assert_eq!(content_id_of(b"ai_inference").len(), 32);
    }

    /// A multi-byte character that straddles a pair boundary must not panic.
    #[test]
    fn non_ascii_hex_is_rejected_without_panic() {
        for bad in ["a\u{e9}b", "\u{e9}\u{e9}", "ab\u{e9}", "\u{1F600}\u{1F600}"] {
            assert!(matches!(
                verify_sha256(b"x", bad),
                Err(DataError::HashMismatch { .. })
            ));
        }
    }

    /// `+` and `-` signs are not hex digits: no alias of a digest decodes.
    #[test]
    fn signed_hex_is_rejected() {
        let hex = hex_of(&content_id_of(b"ai_inference"));
        let aliased = format!("+{}", &hex[1..]);
        assert_ne!(aliased, hex);
        assert!(matches!(
            verify_sha256(b"ai_inference", &aliased),
            Err(DataError::HashMismatch { .. })
        ));
        assert_eq!(hex_bytes("+a"), None);
        assert_eq!(hex_bytes("0aFf"), Some(vec![0x0a, 0xff]));
    }

    /// The error text does not echo an unbounded input.
    #[test]
    fn long_input_is_cut_in_the_error() {
        let long = "z".repeat(10_000);
        let Err(DataError::HashMismatch { detail }) = verify_sha256(b"x", &long) else {
            panic!("expected HashMismatch");
        };
        assert!(detail.len() < 200);
    }
}
