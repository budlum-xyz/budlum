//! A0 — 2.0 → 3.0 transform contract (plan §CH A0).
//!
//! A thin, single entry so the Three pipe does not reach into scattered 2.0
//! helpers. Real 2.0 codecs stay where they are; this only normalises their
//! output into something A1 can pack.
//!
//! # Rules (K-QR-SIKISTIR / format class)
//!
//! - `codec_flags` records what the 2.0 side already did.
//! - Entropy-coded inputs should set [`CodecFlags::ENTROPY_CODED`] so A1's
//!   zlib-if-shrinks still runs harmlessly but callers can skip a wasted try.
//! - This module does **not** invent a second zlib path; A1 owns pack-time
//!   compression.

use crate::core::hash::calculate_hash_bytes;

/// Flags describing how the bytes were produced before A1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct CodecFlags(pub u32);

impl CodecFlags {
    /// No special marking.
    pub const NONE: Self = Self(0);
    /// Input was already entropy-coded (jpeg/mp4/zip/cipher) — zlib unlikely.
    pub const ENTROPY_CODED: Self = Self(1 << 0);
    /// 2.0 side already applied a shrink-only zlib (or equivalent).
    pub const PRE_SHRUNK: Self = Self(1 << 1);
    /// Bytes are ciphertext (caller will typically seal via G1 before A1).
    pub const CIPHERTEXT: Self = Self(1 << 2);

    /// Bit test.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Union.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Normalised 2.0 output ready for the Three pipe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransformedPayload {
    /// Transformed content bytes (not yet A1-packed).
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`.
    pub content_sha256: [u8; 32],
    /// What the 2.0 side claims about these bytes.
    pub codec_flags: CodecFlags,
}

impl TransformedPayload {
    /// Build from raw transformed bytes.
    ///
    /// # Errors
    ///
    /// Empty bytes refused.
    pub fn from_bytes(bytes: Vec<u8>, codec_flags: CodecFlags) -> Result<Self, TransformError> {
        if bytes.is_empty() {
            return Err(TransformError::Empty);
        }
        let content_sha256 = calculate_hash_bytes(&bytes);
        Ok(Self {
            bytes,
            content_sha256,
            codec_flags,
        })
    }

    /// Verify the pinned hash still matches the body.
    #[must_use]
    pub fn verify_hash(&self) -> bool {
        calculate_hash_bytes(&self.bytes) == self.content_sha256
    }
}

/// A0 errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformError {
    /// Empty transform refused.
    Empty,
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "transformed payload refuses empty bytes"),
        }
    }
}

impl std::error::Error for TransformError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_hash() {
        let t = TransformedPayload::from_bytes(b"abc".to_vec(), CodecFlags::NONE).unwrap();
        assert!(t.verify_hash());
        assert_eq!(t.content_sha256, calculate_hash_bytes(b"abc"));
    }

    #[test]
    fn empty_refused() {
        assert_eq!(
            TransformedPayload::from_bytes(vec![], CodecFlags::NONE).unwrap_err(),
            TransformError::Empty
        );
    }
}
