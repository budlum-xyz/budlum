//! B.U.D. 3.0 content addressing, the browser side.
//!
//! Mirrors `src/storage/bud3/content_id.rs` in `budlum-core`:
//! - Public content identity is `Sha256::digest(bytes)`.
//! - Sealed content identity uses `BDLM_BUD3_CID_SEALED_V1` with length-prefixed fields.
//! Convenience: retained public API surface after legacy storage retirement (`WP-07`).

use sha2::{Digest, Sha256};

/// Domain tag shared with `src/storage/bud3/content_id.rs`.
pub const SEALED_ID_TAG: &[u8] = b"BDLM_BUD3_CID_SEALED_V1";

/// Length-prefixed field hash, mirroring `budlum-core`'s length-prefixed framing.
#[must_use]
pub fn hash_fields_bytes(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// The canonical 32-byte content identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Compute the public SHA-256 `ContentId` of `bytes`.
    #[must_use]
    pub fn public(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Alias for `ContentId::public` used across explorer fetch/verify paths.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self::public(bytes)
    }

    /// Compute the sealed commitment under `SEALED_ID_TAG`.
    #[must_use]
    pub fn sealed(id_key: &[u8; 32], plaintext: &[u8]) -> Self {
        Self(hash_fields_bytes(&[SEALED_ID_TAG, id_key, plaintext]))
    }

    /// Borrow the raw 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reads from a 64-character hex string.
    ///
    /// # Errors
    ///
    /// If the length is not 64, or the input is not hex.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| String::from("a ContentId has to be 32 bytes"))?;
        Ok(ContentId(arr))
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Identity comparison for fetched public content bytes.
#[must_use]
pub fn bytes_match(expected: ContentId, bytes: &[u8]) -> bool {
    ContentId::of(bytes) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_is_deterministic() {
        assert_eq!(ContentId::of(b"hello world"), ContentId::of(b"hello world"));
    }

    #[test]
    fn different_bytes_different_id() {
        assert_ne!(ContentId::of(b"a"), ContentId::of(b"b"));
    }

    #[test]
    fn empty_bytes_match_sha256_vector() {
        assert_eq!(
            ContentId::public(b"").to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sealed_id_is_length_prefixed() {
        let key = [0x42u8; 32];
        assert_ne!(ContentId::sealed(&key, b"ab"), ContentId::sealed(&key, b"a"));
    }

    #[test]
    fn hex_roundtrip() {
        let id = ContentId::of(b"x");
        assert_eq!(ContentId::from_hex(&id.to_string()).unwrap(), id);
        assert_eq!(ContentId::from_hex(&format!("0x{id}")).unwrap(), id);
        assert!(ContentId::from_hex("00").is_err());
    }
}
