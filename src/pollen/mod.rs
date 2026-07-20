//! B.U.D. Marketplace — AccessGrant v2 (APPROVED RFC) §3.1 temel tipleri (P0).
//!
//! Kapsam (P0-deseni, tek atomik iş): `AssetId`, `Signature64`, `GrantId`.
//! P1 (primitifler) bu tipler main'de yeşil olduktan sonra başlar.
//!
//! Sabitler:
//! - **R2:** `Signature` tipi kod tabanında yoktu; burada bounded
//!   `Signature64` olarak tanımlanır. `Default` = sıfır-sentinel
//!   (geçersiz-imza); sentinel ile hiçbir doğrulama geçemez (§5 kuralı).
//! - **R3:** serde_json object-key yalnız string olabilir; ham `[u8; N]`
//!   anahtar serialize patlar (`permissionless.rs:176` tuzağı). `AssetId`
//!   Address deseniyle string-serialize (`core/address.rs:64-73`).
//! - **B1 (ARENA1 review kararı; revize — kullanıcı scope_v1):** bu `AssetId`
//!   başlangıçta `crate::bud::marketplace` yolundaydı; kategorizasyon C2 ile
//!   `crate::pollen` altına taşındı. `cross_domain::AssetId`
//!   (= `Hash32` alias) dokunulmaz.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// JSON-safe map anahtarı: hex-string serde wrapper, Address deseni.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetId(pub [u8; 32]);

impl AssetId {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 32 {
            return Err(format!(
                "Invalid asset id length: expected 32, got {}",
                bytes.len()
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(AssetId(id))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn zero() -> Self {
        AssetId([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for AssetId {
    fn default() -> Self {
        Self::zero()
    }
}

impl FromStr for AssetId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AssetId({})", self.to_hex())
    }
}

impl Serialize for AssetId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for AssetId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        AssetId::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl From<[u8; 32]> for AssetId {
    fn from(bytes: [u8; 32]) -> Self {
        AssetId(bytes)
    }
}

/// Ed25519 imzası — bounded, sentinel-default (R2 çözümü).
///
/// `Default` sıfır-imzadır (geçersiz-sentinel): boş bırakılmış imza alanı
/// geçerli imza gibi davranamaz; §5 kuralı sentinel'i her zaman reddeder.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature64(pub [u8; 64]);

impl Signature64 {
    /// Geçersiz-imza sentinel'i (`Default` ile aynı değer).
    pub const SENTINEL: Self = Signature64([0u8; 64]);

    pub fn is_sentinel(&self) -> bool {
        self.0 == [0u8; 64]
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        if bytes.len() != 64 {
            return Err(format!(
                "Invalid signature length: expected 64, got {}",
                bytes.len()
            ));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes);
        Ok(Signature64(sig))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Default for Signature64 {
    fn default() -> Self {
        Self::SENTINEL
    }
}

impl FromStr for Signature64 {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl fmt::Display for Signature64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Signature64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature64({})", self.to_hex())
    }
}

impl Serialize for Signature64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature64::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl From<[u8; 64]> for Signature64 {
    fn from(bytes: [u8; 64]) -> Self {
        Signature64(bytes)
    }
}

/// Grant kimliği = hash(grant payload) üzerinden deterministik anahtar (§3.2).
/// Alias bırakılmıştır: formatı `AssetId` ile aynıdır (doc-lock testi kilitler).
pub type GrantId = AssetId;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn asset_id_hex_roundtrip() {
        let id = AssetId::from([7u8; 32]);
        let hex = id.to_hex();
        assert_eq!(AssetId::from_hex(&hex).unwrap(), id);
        assert_eq!(AssetId::from_hex(&format!("0x{hex}")).unwrap(), id);
    }

    #[test]
    fn asset_id_rejects_bad_length() {
        assert!(AssetId::from_hex(&"ab".repeat(31)).is_err());
        assert!(AssetId::from_hex(&"ab".repeat(33)).is_err());
        assert!(AssetId::from_hex("not-hex").is_err());
    }

    /// R3 kilidi: `BTreeMap<AssetId, _>` serde_json object-key olarak roundtrip
    /// yapmalı ve anahtarlar string olmalı (ham [u8; 32] anahtar YASAK).
    #[test]
    fn asset_id_is_json_map_key_safe() {
        let mut map = BTreeMap::new();
        map.insert(AssetId::from([1u8; 32]), 10u64);
        map.insert(AssetId::from([2u8; 32]), 20u64);
        let json = serde_json::to_string(&map).unwrap();
        assert!(json.starts_with("{\""), "key string olmali: {json}");
        let back: BTreeMap<AssetId, u64> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, map);
    }

    #[test]
    fn asset_id_orders_deterministically() {
        let a = AssetId::from([1u8; 32]);
        let b = AssetId::from([2u8; 32]);
        let mut map = BTreeMap::new();
        map.insert(b, ());
        map.insert(a, ());
        assert_eq!(map.keys().next().unwrap(), &a);
    }

    #[test]
    fn signature64_hex_roundtrip() {
        let sig = Signature64::from([9u8; 64]);
        assert_eq!(Signature64::from_hex(&sig.to_hex()).unwrap(), sig);
        assert!(Signature64::from_hex(&"ab".repeat(63)).is_err());
        assert!(Signature64::from_hex(&"ab".repeat(65)).is_err());
    }

    /// R2 kilidi: `Default` sentinel'dir ve sıfırdan farklı her imza sentinel değildir.
    #[test]
    fn signature64_default_is_sentinel() {
        assert_eq!(Signature64::default(), Signature64::SENTINEL);
        assert!(Signature64::default().is_sentinel());
        assert!(!Signature64::from([1u8; 64]).is_sentinel());
    }

    #[test]
    fn signature64_json_roundtrip() {
        let sig = Signature64::from([3u8; 64]);
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.starts_with('"'));
        assert_eq!(serde_json::from_str::<Signature64>(&json).unwrap(), sig);
    }

    /// Doc-lock: `GrantId` alias'ı `AssetId` ile aynı serileşir (§3.2).
    #[test]
    fn grant_id_alias_matches_asset_id_format() {
        let grant: GrantId = AssetId::from([5u8; 32]);
        let asset = AssetId::from([5u8; 32]);
        assert_eq!(
            serde_json::to_string(&grant).unwrap(),
            serde_json::to_string(&asset).unwrap()
        );
    }
}

// ---------------------------------------------------------------------------
// C3 (Phase 10 kategorizasyonu, kullanıcı: mkt_migrate): Phase 5 AI DataOffer
// ekonomisi `src/marketplace`'ten buraya taşındı. Fiziksel taşıma bu adımda;
// model birleştirmesi (DataOffer (u64 id, seller, cid, price, active) ↔
// v2 DataAsset/MarketplaceListing (AssetId + SaleAuthorization)) P1/P2
// kapsamında tasarlanır — bu modül v2 ile ÇAKIŞAN İKİ modeli barındırmaz,
// geçiş köprüsüdür (bkz. RFC_ACCESSGRANT_V2 §3.2/).
// ---------------------------------------------------------------------------

/// Pollen Data Rights / AccessGrant v2 primitives.
pub mod data_rights;
pub use data_rights::{
    AccessGrant, AccessGrantStatus, AiDataInputRef, DataAsset, DataAssetStatus, EncryptionPolicy,
    SaleAuthorization, SaleAuthorizationId, POLLEN_AI_INPUT_REF_PREFIX,
};

/// Phase 5 §5.5 AI Data Marketplace (satıcı-teklifi ekonomisi) — geçiş modülü.
pub mod offers;
pub use offers::{DataOffer, MarketplaceRegistry};
