//! B.U.D. 2.0 Invention - Direction 4: the Social Bridge Record (2026-08-16).
//!
//! An AT Proto / ActivityPub post turns into a B.U.D. archive (S.94/S.96,
//!):
//! A record holds the source platform URL, the content hash (ContentId), the
//! owner DID and a timestamp. Even if the source is deleted, the B.U.D. copy
//! stays authoritative (content provenance). Lossless: if the source has not
//! changed the content_id matches; if it has, the record is REFUSED (source
//! drift).

#![forbid(unsafe_code)]

use crate::bud_format_container::content_id;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocialPlatform {
    AtProto,
    ActivityPub,
    Other(&'static str),
}

/// The AB 2426 (California 2025) ownership split: if "buy" means REAL
/// ownership it cannot be revoked and is portable; if it is a "licence" it can
/// be revoked and an explicit disclosure is mandatory. A B.U.D. record is
/// Owned, which is REAL ownership, unlike platform licences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipKind {
    Owned,    // real ownership: immutable, non-revocable, portable (B.U.D.)
    Licensed, // a licence: revocable, needs an explicit disclosure (AB 2426)
}

#[derive(Debug, Clone)]
pub struct SocialBridgeRecord {
    pub platform: SocialPlatform,
    pub source_uri: String,
    pub owner_did: String,
    pub content: Vec<u8>,
    pub content_id: [u8; 32],
    pub ts_unix: u64,
    /// The ownership kind - Owned (real B.U.D. ownership) or Licensed.
    pub ownership: OwnershipKind,
}

impl SocialBridgeRecord {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_SOCIAL_V1";

    pub fn new(
        platform: SocialPlatform,
        source_uri: &str,
        owner_did: &str,
        content: Vec<u8>,
        ts_unix: u64,
    ) -> Self {
        Self::new_with_ownership(
            platform,
            source_uri,
            owner_did,
            content,
            ts_unix,
            OwnershipKind::Owned,
        )
    }

    /// B.U.D. records carry REAL ownership by default (Owned); a licence
    /// bridge is marked explicitly with Licensed (the AB 2426 disclosure
    /// obligation).
    pub fn new_with_ownership(
        platform: SocialPlatform,
        source_uri: &str,
        owner_did: &str,
        content: Vec<u8>,
        ts_unix: u64,
        ownership: OwnershipKind,
    ) -> Self {
        let cid = content_id(&content);
        SocialBridgeRecord {
            platform,
            source_uri: source_uri.to_string(),
            owner_did: owner_did.to_string(),
            content,
            content_id: cid,
            ts_unix,
            ownership,
        }
    }

    /// The evidence: Owned records are non-revocable and portable (Data
    /// Act/).
    pub fn is_revocable(&self) -> bool {
        matches!(self.ownership, OwnershipKind::Licensed)
    }
    pub fn is_transferable(&self) -> bool {
        true // a B.U.D. record is machine-readable and an open format , so it is portable
    }

    /// The record identity: source URI + owner + content hash + OWNERSHIP +
    /// time (domain-tagged).
    /// ownership (Owned/Licensed) is part of the identity. If the
    /// label changes the identity changes, so ownership manipulation is caught
    /// on the chain (the guarantee).
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        match &self.platform {
            SocialPlatform::AtProto => h.update([0u8]),
            SocialPlatform::ActivityPub => h.update([1u8]),
            SocialPlatform::Other(label) => {
                h.update([2u8]);
                h.update((label.len() as u64).to_le_bytes());
                h.update(label.as_bytes());
            }
        }
        h.update((self.source_uri.len() as u64).to_le_bytes());
        h.update(self.source_uri.as_bytes());
        h.update((self.owner_did.len() as u64).to_le_bytes());
        h.update(self.owner_did.as_bytes());
        // The identity binds the content itself, not the stored field, so a
        // record with a wrong content_id cannot carry a valid-looking hash.
        h.update(content_id(&self.content));
        h.update([match self.ownership {
            OwnershipKind::Owned => 0u8,
            OwnershipKind::Licensed => 1u8,
        }]);
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }

    /// Content integrity: the stored content has to match the hash taken at
    /// record time.
    pub fn verify_content(&self) -> bool {
        self.content_id == content_id(&self.content)
    }

    /// Source drift: if the content on the platform differs, REJECT (the source changed).
    /// An empty fetch proves nothing (a blocked fetch looks the same as a
    /// deleted post), so it is not a match unless the record is empty too.
    pub fn verify_source(&self, platform_content: &[u8]) -> bool {
        self.content_id == content_id(platform_content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_verifies_content() {
        let rec = SocialBridgeRecord::new(
            SocialPlatform::AtProto,
            "at://did:plc:abc/app.bsky.feed.post/xyz",
            "did:plc:abc",
            b"social content".to_vec(),
            1_700_000_000,
        );
        assert!(rec.verify_content());
        assert_ne!(rec.record_hash(), [0u8; 32]);
    }

    #[test]
    fn ownership_k74() {
        // AB 2426: Owned is non-revocable and portable; Licensed is revocable.
        let owned = SocialBridgeRecord::new(
            SocialPlatform::AtProto,
            "https://bsky.app/profile/u/post/1",
            "did:plc:abc",
            b"content".to_vec(),
            1,
        );
        assert_eq!(owned.ownership, OwnershipKind::Owned);
        assert!(
            !owned.is_revocable(),
            "an Owned record cannot be revoked (real ownership)"
        );
        assert!(owned.is_transferable());
        let licensed = SocialBridgeRecord::new_with_ownership(
            SocialPlatform::ActivityPub,
            "https://fediverse.example/@u/1",
            "u@fediverse.example",
            b"content".to_vec(),
            1,
            OwnershipKind::Licensed,
        );
        assert!(
            licensed.is_revocable(),
            "a licence can be revoked (the AB 2426 disclosure)"
        );
        // Does record_hash cover the ownership kind?: yes - a malicious
        // Owned-to-Licensed conversion changes the record identity, so the
        // corruption is caught.
        assert_ne!(owned.record_hash(), licensed.record_hash());
    }

    #[test]
    fn tampered_content_rejected() {
        let mut rec = SocialBridgeRecord::new(
            SocialPlatform::ActivityPub,
            "https://fediverse.example/@user/123",
            "user@fediverse.example",
            b"original".to_vec(),
            100,
        );
        assert!(rec.verify_content());
        rec.content = b"changed".to_vec();
        assert!(!rec.verify_content(), "changed content is REFUSED");
    }

    #[test]
    fn source_mismatch_and_empty_fetch_rejected() {
        let rec = SocialBridgeRecord::new(
            SocialPlatform::Other("x"),
            "https://x.com/u/1",
            "did:web:x",
            b"post".to_vec(),
            200,
        );
        // an empty fetch is not a match: it cannot show the source is unchanged
        assert!(!rec.verify_source(b""));
        // source content differs -> drift REFUSED
        assert!(!rec.verify_source(b"different"));
        // source identical -> OK
        assert!(rec.verify_source(b"post"));
    }

    #[test]
    fn record_hash_binds_the_content_and_the_platform() {
        let mut a =
            SocialBridgeRecord::new(SocialPlatform::AtProto, "uri", "did", b"x".to_vec(), 1);
        let before = a.record_hash();
        a.content_id = [9u8; 32];
        assert_eq!(
            a.record_hash(),
            before,
            "a stray content_id does not move it"
        );
        a.content = b"y".to_vec();
        assert_ne!(a.record_hash(), before, "the content does");
        let b =
            SocialBridgeRecord::new(SocialPlatform::ActivityPub, "uri", "did", b"x".to_vec(), 1);
        assert_ne!(b.record_hash(), before, "so does the platform");
    }

    #[test]
    fn record_hash_deterministic() {
        let a = SocialBridgeRecord::new(SocialPlatform::AtProto, "uri", "did", b"x".to_vec(), 1);
        let b = SocialBridgeRecord::new(SocialPlatform::AtProto, "uri", "did", b"x".to_vec(), 1);
        assert_eq!(a.record_hash(), b.record_hash());
        assert_ne!(
            a.record_hash(),
            SocialBridgeRecord::new(SocialPlatform::AtProto, "uri2", "did", b"x".to_vec(), 1)
                .record_hash()
        );
    }
}

#[test]
fn ownership_is_bound_to_identity() {
    // if the ownership label changes the identity changes, so the
    // manipulation is caught.
    let mut a = SocialBridgeRecord {
        source_uri: "x.com/post/1".to_string(),
        owner_did: "did:bud:alice".to_string(),
        content_id: [7u8; 32],
        ts_unix: 100,
        ownership: OwnershipKind::Owned,
        platform: SocialPlatform::AtProto,
        content: b"content".to_vec(),
    };
    let h_owned = a.record_hash();
    a.ownership = OwnershipKind::Licensed;
    let h_licensed = a.record_hash();
    assert_ne!(
        h_owned, h_licensed,
        "a change of ownership must change the identity"
    );
    // deterministic under the same ownership
    let b = SocialBridgeRecord {
        source_uri: "x.com/post/1".to_string(),
        owner_did: "did:bud:alice".to_string(),
        content_id: [7u8; 32],
        ts_unix: 100,
        ownership: OwnershipKind::Owned,
        platform: SocialPlatform::AtProto,
        content: b"content".to_vec(),
    };
    assert_eq!(h_owned, b.record_hash());
}
