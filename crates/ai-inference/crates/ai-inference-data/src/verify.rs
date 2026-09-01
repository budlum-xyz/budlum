//! Content verification - a real SHA-256.
//!
//! The first step of the production path: the skeleton no longer returns a
//! fail-closed "not implemented" error; the content hash is verified with a
//! real SHA-256. If verification fails the answer is `HashMismatch`, and no
//! data flows.

use ai_inference_core::model::Hash32;
use sha2::{Digest, Sha256};

use crate::source::DataError;

/// Verifies content against an expected hex SHA-256.
///
/// # Errors
///
/// - `HashMismatch` if the hex cannot be decoded (empty or malformed).
/// - `HashMismatch` if the digest does not match.
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> Result<(), DataError> {
    let expected: Vec<u8> = hex_bytes(expected_hex).ok_or_else(|| DataError::HashMismatch {
        detail: format!("the expected hex could not be decoded: {expected_hex}"),
    })?;
    if expected.len() != 32 {
        return Err(DataError::HashMismatch {
            detail: format!("a SHA-256 is 32 bytes; {expected_hex} has a different length"),
        });
    }
    let actual = Sha256::digest(data);
    if actual.as_slice() == expected.as_slice() {
        Ok(())
    } else {
        Err(DataError::HashMismatch {
            detail: format!(
                "expected: {expected_hex}, actual: {}",
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

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
}
