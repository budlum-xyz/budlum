//! B.U.D. 2.0 Icat - Yon 4: Sosyal Kopru Kaydi (2026-08-16)
//!
//! AT Proto / ActivityPub gonderisi -> B.U.D. arsivi (S.94/S.96, K27/K33):
//! kayit, kaynak platform URL'si + icerik hash'i (ContentId) + sahip DID + zaman
//! damgasi tutar. Kaynak silinse bile B.U.D. kopyasi yetkili kalir (icerik kokeni).
//! Kayipsiz: kaynak degismedi ise content_id eslesir; degisti ise RED (kaynak sapmasi).

#![forbid(unsafe_code)]

use crate::bud_format_container::content_id;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocialPlatform {
    AtProto,
    ActivityPub,
    Other(&'static str),
}

/// AB 2426 (California 2025) sahiplik ayrımı (K74): "buy" GERÇEK mülkiyet ise
/// revoke edilemez + taşınabilir; "lisans" ise revoke edilebilir ve açık bildirim
/// zorunludur. B.U.D. kaydı Owned → platform lisanslarının aksine GERÇEK sahiplik.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipKind {
    Owned,    // gerçek sahiplik: immutable, revoke edilemez, taşınabilir (B.U.D.)
    Licensed, // lisans: revoke edilebilir, açık bildirim gerekir (AB 2426)
}

#[derive(Debug, Clone)]
pub struct SocialBridgeRecord {
    pub platform: SocialPlatform,
    pub source_uri: String,
    pub owner_did: String,
    pub content: Vec<u8>,
    pub content_id: [u8; 32],
    pub ts_unix: u64,
    /// K74: sahiplik türü - Owned (B.U.D. gerçek sahiplik) veya Licensed (lisans).
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
        Self::new_with_ownership(platform, source_uri, owner_did, content, ts_unix, OwnershipKind::Owned)
    }

    /// K74: B.U.D. kayıtları varsayılan GERÇEK sahiplik taşır (Owned); lisans köprüsü
    /// açıkça Licensed ile işaretlenir (AB 2426 bildirim zorunluluğu).
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

    /// K74 kanıtı: Owned kayıtlar revoke edilemez + taşınabilir (Data Act/K27).
    pub fn is_revocable(&self) -> bool {
        matches!(self.ownership, OwnershipKind::Licensed)
    }
    pub fn is_transferable(&self) -> bool {
        true // B.U.D. kaydı makine-okur + açık format (K72) → taşınabilir
    }

    /// Kayit kimligi: kaynak URI + sahip + icerik hash + SAHIPLIK + zaman (domain-etiketli).
    /// STRIX fix: ownership (Owned/Licensed) kimlige dahil - etiket degisirse kimlik degisir,
    /// boylece zincirde sahiplik manipulasyonu yakalanir (K74 güvencesi).
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((self.source_uri.len() as u64).to_le_bytes());
        h.update(self.source_uri.as_bytes());
        h.update((self.owner_did.len() as u64).to_le_bytes());
        h.update(self.owner_did.as_bytes());
        h.update(self.content_id);
        h.update([match self.ownership {
            OwnershipKind::Owned => 0u8,
            OwnershipKind::Licensed => 1u8,
        }]);
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }

    /// Icerik butunlugu: saklanan icerik kayit anindaki hash ile eslesmeli.
    pub fn verify_content(&self) -> bool {
        self.content_id == content_id(&self.content)
    }

    /// Kaynak sapmasi: platformdaki mevcut icerik farkliysa RED (kaynak degisti).
    pub fn verify_source(&self, platform_content: &[u8]) -> bool {
        platform_content.is_empty() || self.content_id == content_id(platform_content)
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
            b"sosyal icerik".to_vec(),
            1_700_000_000,
        );
        assert!(rec.verify_content());
        assert_ne!(rec.record_hash(), [0u8; 32]);
    }

    #[test]
    fn ownership_k74() {
        // AB 2426: Owned → revoke edilemez + taşınabilir; Licensed → revoke edilebilir
        let owned = SocialBridgeRecord::new(
            SocialPlatform::AtProto,
            "https://bsky.app/profile/u/post/1",
            "did:plc:abc",
            b"icerik".to_vec(),
            1,
        );
        assert_eq!(owned.ownership, OwnershipKind::Owned);
        assert!(!owned.is_revocable(), "Owned kayıt revoke edilemez (gerçek sahiplik)");
        assert!(owned.is_transferable());
        let licensed = SocialBridgeRecord::new_with_ownership(
            SocialPlatform::ActivityPub,
            "https://fediverse.example/@u/1",
            "u@fediverse.example",
            b"icerik".to_vec(),
            1,
            OwnershipKind::Licensed,
        );
        assert!(licensed.is_revocable(), "Lisans revoke edilebilir (AB 2426 bildirimi)");
        // record_hash sahiplik türünü kapsar mı? K74: evet - kötü niyetli Owned→Licensed
        // dönüşümü kayıt kimliğini değiştirir (kayıt bozulması yakalanır)
        assert_ne!(owned.record_hash(), licensed.record_hash());
    }

    #[test]
    fn tampered_content_rejected() {
        let mut rec = SocialBridgeRecord::new(
            SocialPlatform::ActivityPub,
            "https://fediverse.example/@user/123",
            "user@fediverse.example",
            b"orijinal".to_vec(),
            100,
        );
        assert!(rec.verify_content());
        rec.content = b"degistirildi".to_vec();
        assert!(!rec.verify_content(), "icerik degisince RED");
    }

    #[test]
    fn source_mismatch_rejected_but_empty_ok() {
        let rec = SocialBridgeRecord::new(
            SocialPlatform::Other("x"),
            "https://x.com/u/1",
            "did:web:x",
            b"paylasim".to_vec(),
            200,
        );
        // kaynak silindi (bos) -> yetkili kalir
        assert!(rec.verify_source(b""));
        // kaynak icerigi farkli -> sapma RED
        assert!(!rec.verify_source(b"farkli"));
        // kaynak ayni -> OK
        assert!(rec.verify_source(b"paylasim"));
    }

    #[test]
    fn record_hash_deterministic() {
        let a = SocialBridgeRecord::new(SocialPlatform::AtProto, "uri", "did", b"x".to_vec(), 1);
        let b = SocialBridgeRecord::new(SocialPlatform::AtProto, "uri", "did", b"x".to_vec(), 1);
        assert_eq!(a.record_hash(), b.record_hash());
        assert_ne!(a.record_hash(), SocialBridgeRecord::new(SocialPlatform::AtProto, "uri2", "did", b"x".to_vec(), 1).record_hash());
    }
}

    #[test]
    fn strix_ownership_kimlige_bagli() {
        // STRIX fix: sahiplik etiketi degisirse kimlik degisir (manipulasyon yakalanir).
        let mut a = SocialBridgeRecord {
            source_uri: "x.com/post/1".to_string(),
            owner_did: "did:bud:alice".to_string(),
            content_id: [7u8; 32],
            ts_unix: 100,
            ownership: OwnershipKind::Owned,
            platform: SocialPlatform::AtProto,
            content: b"icerik".to_vec(),
        };
        let h_owned = a.record_hash();
        a.ownership = OwnershipKind::Licensed;
        let h_licensed = a.record_hash();
        assert_ne!(h_owned, h_licensed, "sahiplik degisimi kimligi degistirmeli");
        // ayni sahiplikte deterministik
        let b = SocialBridgeRecord { source_uri: "x.com/post/1".to_string(), owner_did: "did:bud:alice".to_string(), content_id: [7u8; 32], ts_unix: 100, ownership: OwnershipKind::Owned, platform: SocialPlatform::AtProto, content: b"icerik".to_vec() };
        assert_eq!(h_owned, b.record_hash());
    }

