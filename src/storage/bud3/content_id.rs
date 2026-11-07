//! The B.U.D. 3.0 content identifier.
//!
//! * Public content: `SHA-256(content)` and the content length. The digest is
//!   the plain SHA-256 of the bytes, so any standard tool reproduces it.
//! * Sealed content: `HMAC-SHA-256(mac_key, content)` and the content length,
//!   where `mac_key = HMAC-SHA-256(content_key, BDLM_BUD3_CID_SEALED_V1)`.
//!   Without the content key nobody can test a guess of the plaintext against
//!   the id, and the id never equals the public id of the same bytes.
//!
//! A content id never changes. The object that carries the content may change
//! (a better codec, a new dictionary); the content id does not.
//! Convenience: public B.U.D. 3.0 storage library surface consumed by CLI, gateway, and verification harnesses.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The tag that derives the sealed-id MAC key from the content key.
pub const SEALED_ID_TAG: &[u8] = b"BDLM_BUD3_CID_SEALED_V1";

/// Which rule produced a [`ContentId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ContentIdKind {
    /// Plain SHA-256 of public bytes.
    Public,
    /// Keyed HMAC-SHA-256 of sealed bytes.
    Sealed,
}

/// The content identifier: digest, length and the rule that made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentId {
    /// The rule.
    pub kind: ContentIdKind,
    /// SHA-256 (public) or HMAC-SHA-256 (sealed) of the content.
    pub digest: [u8; 32],
    /// Content length in bytes.
    pub len: u64,
}

/// A 32-byte content key. It never leaves the owner's devices in the clear.
#[derive(Clone, PartialEq, Eq)]
pub struct ContentKey(pub [u8; 32]);

impl core::fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ContentKey(<redacted>)")
    }
}

impl ContentId {
    /// The id of public content held in memory.
    #[must_use]
    pub fn public(content: &[u8]) -> Self {
        let mut h = PublicHasher::new();
        h.update(content);
        h.finish()
    }

    /// The id of sealed content held in memory.
    #[must_use]
    pub fn sealed(key: &ContentKey, content: &[u8]) -> Self {
        let mut h = SealedHasher::new(key);
        h.update(content);
        h.finish()
    }

    /// Whether `content` is the content this public id names. A sealed id
    /// never matches here: it needs the key.
    #[must_use]
    pub fn matches_public(&self, content: &[u8]) -> bool {
        self.kind == ContentIdKind::Public && Self::public(content) == *self
    }

    /// Whether `content` is the content this sealed id names under `key`.
    #[must_use]
    pub fn matches_sealed(&self, key: &ContentKey, content: &[u8]) -> bool {
        self.kind == ContentIdKind::Sealed && Self::sealed(key, content) == *self
    }
}

/// Incremental public id, for content that does not fit in memory.
#[derive(Clone, Default)]
pub struct PublicHasher {
    hasher: Sha256,
    len: u64,
}

impl PublicHasher {
    /// A fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb the next bytes of the content.
    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.len = self.len.saturating_add(bytes.len() as u64);
    }

    /// The id of everything absorbed.
    #[must_use]
    pub fn finish(self) -> ContentId {
        ContentId {
            kind: ContentIdKind::Public,
            digest: self.hasher.finalize().into(),
            len: self.len,
        }
    }
}

/// HMAC-SHA-256 (RFC 2104) over a 32-byte key. The key is shorter than the
/// 64-byte block, so it is zero-padded and never hashed first.
#[derive(Clone)]
struct HmacSha256 {
    inner: Sha256,
    outer_key: [u8; 64],
}

impl HmacSha256 {
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    fn new(key: &[u8; 32]) -> Self {
        let mut ikey = [Self::IPAD; 64];
        let mut okey = [Self::OPAD; 64];
        for ((i, o), k) in ikey.iter_mut().zip(okey.iter_mut()).zip(key.iter()) {
            *i ^= *k;
            *o ^= *k;
        }
        let mut inner = Sha256::new();
        inner.update(ikey);
        Self {
            inner,
            outer_key: okey,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    fn finish(self) -> [u8; 32] {
        let inner: [u8; 32] = self.inner.finalize().into();
        let mut outer = Sha256::new();
        outer.update(self.outer_key);
        outer.update(inner);
        outer.finalize().into()
    }
}

/// The MAC key of the sealed id: `HMAC-SHA-256(content_key, SEALED_ID_TAG)`.
fn sealed_mac_key(key: &ContentKey) -> [u8; 32] {
    let mut mac = HmacSha256::new(&key.0);
    mac.update(SEALED_ID_TAG);
    mac.finish()
}

/// Incremental sealed id.
#[derive(Clone)]
pub struct SealedHasher {
    mac: HmacSha256,
    len: u64,
}

impl SealedHasher {
    /// A fresh hasher under `key`.
    #[must_use]
    pub fn new(key: &ContentKey) -> Self {
        Self {
            mac: HmacSha256::new(&sealed_mac_key(key)),
            len: 0,
        }
    }

    /// Absorb the next bytes of the content.
    pub fn update(&mut self, bytes: &[u8]) {
        self.mac.update(bytes);
        self.len = self.len.saturating_add(bytes.len() as u64);
    }

    /// The id of everything absorbed.
    #[must_use]
    pub fn finish(self) -> ContentId {
        ContentId {
            kind: ContentIdKind::Sealed,
            digest: self.mac.finish(),
            len: self.len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        v.try_into().unwrap()
    }

    #[test]
    fn content_id_public_is_sha256_and_len() {
        // FIPS 180-2 test vector for "abc".
        let id = ContentId::public(b"abc");
        assert_eq!(id.kind, ContentIdKind::Public);
        assert_eq!(id.len, 3);
        assert_eq!(
            id.digest,
            hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        let empty = ContentId::public(b"");
        assert_eq!(empty.len, 0);
        assert_eq!(
            empty.digest,
            hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn content_id_sealed_is_keyed() {
        let k1 = ContentKey([1u8; 32]);
        let k2 = ContentKey([2u8; 32]);
        let a = ContentId::sealed(&k1, b"secret");
        let b = ContentId::sealed(&k2, b"secret");
        assert_eq!(a.kind, ContentIdKind::Sealed);
        assert_eq!(a.len, 6);
        assert_ne!(a.digest, b.digest, "a different key gives a different id");
        assert_ne!(
            a.digest,
            ContentId::public(b"secret").digest,
            "the sealed id never equals the public id"
        );
        assert!(a.matches_sealed(&k1, b"secret"));
        assert!(!a.matches_sealed(&k2, b"secret"));
        assert!(!a.matches_public(b"secret"));
    }

    #[test]
    fn incremental_hashers_equal_one_shot() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let mut p = PublicHasher::new();
        let key = ContentKey([7u8; 32]);
        let mut s = SealedHasher::new(&key);
        for chunk in data.chunks(333) {
            p.update(chunk);
            s.update(chunk);
        }
        assert_eq!(p.finish(), ContentId::public(&data));
        assert_eq!(s.finish(), ContentId::sealed(&key, &data));
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2_shape() {
        // RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There". The key
        // here is 32 bytes, so pad the RFC key with zeros: HMAC zero-pads a
        // short key, so the result is the RFC value.
        let mut key = [0u8; 32];
        key[..20].copy_from_slice(&[0x0b; 20]);
        let mut mac = HmacSha256::new(&key);
        mac.update(b"Hi There");
        assert_eq!(
            mac.finish(),
            hex32("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn content_key_debug_is_redacted() {
        let k = ContentKey([0xAB; 32]);
        assert_eq!(format!("{k:?}"), "ContentKey(<redacted>)");
    }
}
