//! P12-12: Fixture üreteçleri — test ve geliştirme için deterministik veri üretimi.
//!
//! Bu modül, geliştiricilerin test ve entegrasyon çalışmaları için
//! deterministik fixture verileri üretmesini sağlar. Üç tip fixture
//! desteklenir:
//!
//! - **Proof Fixture:** Settlement proof doğrulama testleri için
//! - **Pollen Fixture:** Pollen data asset ve access grant fixture'ları
//! - **Relayer Intent Fixture:** Relayer intent simülasyonu için
//!
//! Tüm fixture üreteçleri seed tabanlıdır — aynı seed ile aynı fixture seti
//! elde edilir. Bu, test tekrarlanabilirliği için kritiktir.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::pollen::{AssetId, GrantId};
use crate::domain::Hash32;
use serde::{Deserialize, Serialize};

/// Ortak fixture üreteç trait'i.
pub trait FixtureGenerator {
    /// Fixture çıktı türü.
    type Output;
    /// Fixture set üretir.
    fn generate(&self) -> Vec<Self::Output>;
    /// Tek bir fixture üretir.
    fn generate_one(&self, index: usize) -> Self::Output;
}

// ---------------------------------------------------------------------------
// Proof Fixture
// ---------------------------------------------------------------------------

/// Settlement proof fixture yapısı.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofFixture {
    /// Domain ID.
    pub domain_id: u32,
    /// Domain yüksekliği.
    pub domain_height: u64,
    /// Event indeksi.
    pub event_index: u32,
    /// Event kök hash.
    pub event_root: Hash32,
    /// Merkle proof siblings.
    pub proof_siblings: Vec<Hash32>,
    /// Leaf hash.
    pub leaf_hash: Hash32,
    /// Fixture etiketi.
    pub label: String,
}

/// Proof fixture üreteci.
#[derive(Debug, Clone)]
pub struct ProofFixtureGenerator {
    /// Deterministik seed.
    pub seed: u64,
    /// Üretilecek fixture sayısı.
    pub count: usize,
    /// Başlangıç domain ID'si.
    pub start_domain_id: u32,
}

impl ProofFixtureGenerator {
    pub fn new(seed: u64, count: usize) -> Self {
        Self {
            seed,
            count,
            start_domain_id: 0,
        }
    }

    /// Seed + indeksten deterministik hash üretir.
    fn seeded_hash(&self, tag: &str, index: usize) -> Hash32 {
        hash_fields_bytes(&[
            self.seed.to_le_bytes().as_slice(),
            index.to_le_bytes().as_slice(),
            tag.as_bytes(),
        ])
    }
}

impl FixtureGenerator for ProofFixtureGenerator {
    type Output = ProofFixture;

    fn generate(&self) -> Vec<Self::Output> {
        (0..self.count).map(|i| self.generate_one(i)).collect()
    }

    fn generate_one(&self, index: usize) -> Self::Output {
        let domain_id = self.start_domain_id + (index as u32 % 4);
        let domain_height = (index as u64) * 100 + 10;
        let event_index = (index as u32) % 8;

        let leaf_hash = self.seeded_hash("leaf", index);
        let event_root = self.seeded_hash("root", index);

        // 4 sibling (merkle depth = 64, ama fixture için 4 yeterli)
        let proof_siblings: Vec<Hash32> = (0..4)
            .map(|s| self.seeded_hash(&format!("sib-{}", s), index))
            .collect();

        ProofFixture {
            domain_id,
            domain_height,
            event_index,
            event_root,
            proof_siblings,
            leaf_hash,
            label: format!("proof-fixture-{}", index),
        }
    }
}

// ---------------------------------------------------------------------------
// Pollen Fixture
// ---------------------------------------------------------------------------

/// Pollen data asset fixture yapısı.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollenAssetFixture {
    /// Asset ID.
    pub asset_id: AssetId,
    /// Sahip adresi.
    pub owner: Address,
    /// Asset metadata CID.
    pub metadata_cid: String,
    /// Fiyat (u64 BUD birimi).
    pub price: u64,
    /// Aktif mi?
    pub active: bool,
    /// Fixture etiketi.
    pub label: String,
}

/// Pollen access grant fixture yapısı.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollenGrantFixture {
    /// Grant ID.
    pub grant_id: GrantId,
    /// Asset ID.
    pub asset_id: AssetId,
    /// İzin veren (asset sahibi).
    pub grantor: Address,
    /// İzin alan (AI ajanı vs.).
    pub grantee: Address,
    /// Erişim türü.
    pub access_type: String,
    /// Süre (epoch sayısı).
    pub duration_epochs: u64,
    /// Fixture etiketi.
    pub label: String,
}

/// Pollen fixture üreteci.
#[derive(Debug, Clone)]
pub struct PollenFixtureGenerator {
    /// Deterministik seed.
    pub seed: u64,
    /// Üretilecek asset sayısı.
    pub asset_count: usize,
    /// Üretilecek grant sayısı.
    pub grant_count: usize,
}

impl PollenFixtureGenerator {
    pub fn new(seed: u64, asset_count: usize, grant_count: usize) -> Self {
        Self {
            seed,
            asset_count,
            grant_count,
        }
    }

    fn seeded_address(&self, tag: &str, index: usize) -> Address {
        let hash = hash_fields_bytes(&[
            self.seed.to_le_bytes().as_slice(),
            index.to_le_bytes().as_slice(),
            tag.as_bytes(),
        ]);
        Address::from(hash)
    }

    fn seeded_asset_id(&self, tag: &str, index: usize) -> AssetId {
        let hash = hash_fields_bytes(&[
            self.seed.to_le_bytes().as_slice(),
            index.to_le_bytes().as_slice(),
            tag.as_bytes(),
        ]);
        AssetId::from(hash)
    }
}

impl FixtureGenerator for PollenAssetFixture {
    type Output = PollenAssetFixture;
    fn generate(&self) -> Vec<Self::Output> { vec![self.clone()] }
    fn generate_one(&self, _index: usize) -> Self::Output { self.clone() }
}

impl FixtureGenerator for PollenGrantFixture {
    type Output = PollenGrantFixture;
    fn generate(&self) -> Vec<Self::Output> { vec![self.clone()] }
    fn generate_one(&self, _index: usize) -> Self::Output { self.clone() }
}

impl PollenFixtureGenerator {
    /// Asset fixture seti üretir.
    pub fn generate_assets(&self) -> Vec<PollenAssetFixture> {
        (0..self.asset_count)
            .map(|i| {
                let asset_id = self.seeded_asset_id("asset", i);
                let owner = self.seeded_address("owner", i);
                PollenAssetFixture {
                    asset_id,
                    owner,
                    metadata_cid: format!("bafkrei_seed{}_asset{}", self.seed, i),
                    price: 100 * (i as u64 + 1),
                    active: i % 3 != 2, // 2/3 aktif
                    label: format!("pollen-asset-{}", i),
                }
            })
            .collect()
    }

    /// Grant fixture seti üretir (önce asset'ler üretilmelidir).
    pub fn generate_grants(&self, assets: &[PollenAssetFixture]) -> Vec<PollenGrantFixture> {
        (0..self.grant_count)
            .map(|i| {
                let asset = &assets[i % assets.len()];
                let grant_id = self.seeded_asset_id("grant", i);
                let grantee = self.seeded_address("grantee", i);
                PollenGrantFixture {
                    grant_id,
                    asset_id: asset.asset_id,
                    grantor: asset.owner,
                    grantee,
                    access_type: if i % 2 == 0 { "read" } else { "compute" }.to_string(),
                    duration_epochs: 10 + (i as u64) * 5,
                    label: format!("pollen-grant-{}", i),
                }
            })
            .collect()
    }

    /// Asset + grant fixture setini birlikte üretir.
    pub fn generate_all(&self) -> (Vec<PollenAssetFixture>, Vec<PollenGrantFixture>) {
        let assets = self.generate_assets();
        let grants = self.generate_grants(&assets);
        (assets, grants)
    }
}

// ---------------------------------------------------------------------------
// Relayer Intent Fixture
// ---------------------------------------------------------------------------

/// Relayer intent fixture yapısı.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerIntentFixture {
    /// Kaynak domain ID.
    pub source_domain: u32,
    /// Hedef domain ID.
    pub target_domain: u32,
    /// Gönderen adres.
    pub sender: Address,
    /// Alıcı adres.
    pub recipient: Address,
    /// Intent türü.
    pub intent_type: String,
    /// Payload hash.
    pub payload_hash: Hash32,
    /// Tutar (BUD birimi).
    pub amount: u64,
    /// Fixture etiketi.
    pub label: String,
}

/// Relayer intent fixture üreteci.
#[derive(Debug, Clone)]
pub struct RelayerIntentFixtureGenerator {
    /// Deterministik seed.
    pub seed: u64,
    /// Üretilecek fixture sayısı.
    pub count: usize,
}

impl RelayerIntentFixtureGenerator {
    pub fn new(seed: u64, count: usize) -> Self {
        Self { seed, count }
    }

    fn seeded_address(&self, tag: &str, index: usize) -> Address {
        let hash = hash_fields_bytes(&[
            self.seed.to_le_bytes().as_slice(),
            index.to_le_bytes().as_slice(),
            tag.as_bytes(),
        ]);
        Address::from(hash)
    }

    fn seeded_hash(&self, tag: &str, index: usize) -> Hash32 {
        hash_fields_bytes(&[
            self.seed.to_le_bytes().as_slice(),
            index.to_le_bytes().as_slice(),
            tag.as_bytes(),
        ])
    }
}

impl FixtureGenerator for RelayerIntentFixtureGenerator {
    type Output = RelayerIntentFixture;

    fn generate(&self) -> Vec<Self::Output> {
        (0..self.count).map(|i| self.generate_one(i)).collect()
    }

    fn generate_one(&self, index: usize) -> Self::Output {
        let source_domain = (index as u32) % 4;
        let target_domain = ((index as u32) + 1) % 4;

        RelayerIntentFixture {
            source_domain,
            target_domain,
            sender: self.seeded_address("sender", index),
            recipient: self.seeded_address("recipient", index),
            intent_type: match index % 3 {
                0 => "bridge_lock".to_string(),
                1 => "bridge_mint".to_string(),
                _ => "message".to_string(),
            },
            payload_hash: self.seeded_hash("payload", index),
            amount: 1000 * (index as u64 + 1),
            label: format!("relayer-intent-{}", index),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_fixture_deterministic() {
        let gen = ProofFixtureGenerator::new(42, 5);
        let set1 = gen.generate();
        let set2 = gen.generate();
        assert_eq!(set1.len(), 5);
        assert_eq!(set1[0].domain_id, set2[0].domain_id);
        assert_eq!(set1[0].event_root, set2[0].event_root);
    }

    #[test]
    fn proof_fixture_different_seeds_differ() {
        let gen1 = ProofFixtureGenerator::new(42, 1);
        let gen2 = ProofFixtureGenerator::new(99, 1);
        assert_ne!(
            gen1.generate_one(0).event_root,
            gen2.generate_one(0).event_root
        );
    }

    #[test]
    fn pollen_fixture_assets_and_grants() {
        let gen = PollenFixtureGenerator::new(42, 3, 5);
        let (assets, grants) = gen.generate_all();
        assert_eq!(assets.len(), 3);
        assert_eq!(grants.len(), 5);
        // Her grant bir asset'e referans vermeli
        for grant in &grants {
            assert!(assets.iter().any(|a| a.asset_id == grant.asset_id));
        }
    }

    #[test]
    fn pollen_asset_prices_scale() {
        let gen = PollenFixtureGenerator::new(42, 3, 0);
        let assets = gen.generate_assets();
        assert_eq!(assets[0].price, 100);
        assert_eq!(assets[1].price, 200);
        assert_eq!(assets[2].price, 300);
    }

    #[test]
    fn relayer_intent_fixture_cross_domain() {
        let gen = RelayerIntentFixtureGenerator::new(42, 10);
        let fixtures = gen.generate();
        assert_eq!(fixtures.len(), 10);
        // Her intent farklı source/target domain'ler arası
        for fixture in &fixtures {
            assert_ne!(fixture.source_domain, fixture.target_domain);
        }
    }

    #[test]
    fn fixture_serialization_roundtrip() {
        let gen = ProofFixtureGenerator::new(42, 1);
        let fixture = gen.generate_one(0);
        let json = serde_json::to_string(&fixture).unwrap();
        let parsed: ProofFixture = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.domain_id, fixture.domain_id);
        assert_eq!(parsed.leaf_hash, fixture.leaf_hash);
    }
}
