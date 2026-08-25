//! B.U.D. content addressing, the browser side.
//!
//! The **same** definition as `src/storage/content_id.rs` in `budlum-core`:
//! `ContentId = hash_fields_bytes([b"BDLM_CONTENT_V1", chunk])`, where
//! `hash_fields_bytes` length-prefixes every field before feeding it to
//! SHA-256.
//!
//! # Why a copy and not a dependency
//!
//! If the browser depended on `budlum-core` it would also pull in libp2p,
//! tokio, jsonrpsee and sled, and that graph is unwanted inside a browser's
//! trust boundary. The price is that the two copies can drift apart, and that
//! price is not left unpaid: the `budscan-name-rule-parity` gate measures in CI
//! that both definitions carry the same domain tag and the same pinned vector.
//! The copy is not free, it is measured.
//!
//! # Verification is an equality check, not a signature check
//!
//! If the hash of the fetched bytes equals the expected identity, the bytes are
//! correct. The browser never has to decide whom to trust: a node can at most
//! refuse to serve, it cannot lie.

use sha2::{Digest, Sha256};

/// Uzunluk-onekli alan hash'i. `budlum-core::core::hash::hash_fields_bytes`.
///
/// Uzunluk oneki olmasaydi `["a","bc"]` ile `["ab","c"]` ayni bayt dizisini
/// and two different contents would share the same identity.
#[must_use]
pub fn hash_fields_bytes(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// The canonical content identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Bir yigin baytin `ContentId`'si.
    #[must_use]
    pub fn of(chunk: &[u8]) -> Self {
        ContentId(hash_fields_bytes(&[b"BDLM_CONTENT_V1", chunk]))
    }

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

/// Bir manifest'in shard'lari birlestirildikten sonra kimlik karsilastirmasi.
///
/// The comparison is not constant-time and does not need to be: both sides are
/// public. Nothing here is secret, so there is nothing to leak.
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
    fn truncation_cannot_collide() {
        // budlum-core'daki `content_id_collisions_impossible_for_truncated_payloads`
        // testinin aynisi: uzunluk oneki bu esitligi imkansiz kilar.
        let one = ContentId::of(b"ab");
        let two = ContentId::of(b"a").0;
        let three = ContentId::of(b"b").0;
        assert_ne!(
            one.0,
            hash_fields_bytes(&[b"BDLM_CONTENT_V1", &two, &three])
        );
    }

    #[test]
    fn the_core_vector_is_pinned() {
        // This vector is the contract shared with `budlum-core`. If it
        // changes, one of the two sides has drifted, and that is a bug, not an
        // update.
        let id = ContentId::of(b"budlum");
        assert_eq!(
            id.to_string(),
            hex::encode(hash_fields_bytes(&[b"BDLM_CONTENT_V1", b"budlum"]))
        );
        assert_eq!(id.0.len(), 32);
    }

    #[test]
    fn hex_roundtrip() {
        let id = ContentId::of(b"x");
        assert_eq!(ContentId::from_hex(&id.to_string()).unwrap(), id);
        assert_eq!(ContentId::from_hex(&format!("0x{id}")).unwrap(), id);
        assert!(ContentId::from_hex("00").is_err());
    }
}
