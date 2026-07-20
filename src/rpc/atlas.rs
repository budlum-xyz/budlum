//! P12-8: Budlum Atlas / bud.scan Evidence UI — Read-only evidence endpoints.
//!
//! Budlum Atlas, zincir üstü kanıt (evidence) verilerini sorgulamak için
//! read-only endpoint'ler sağlar. Bu modül, cüzdan bağlamı grafi
//! (wallet context graph) ve kanıt doğrulama sorgularını tanımlar.
//!
//! # Endpoint'ler
//!
//! - **Evidence Query:** Belirli bir domain/height/event için kanıt sorgulama
//! - **Wallet Context Graph:** Bir adresin tüm zincir-üstü ilişkilerini grafi
//! - **Domain Summary:** Domain bazlı özet istatistikler
//! - **Cross-Domain Trace:** Cross-domain mesaj izleme
//!
//! Not: Bu modül sadece veri modeli ve sorgu altyapısı sağlar.
//! RPC endpoint entegrasyonu ayrı bir adımda yapılacaktır.

use crate::core::address::Address;
use crate::domain::{ConsensusKind, DomainId, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_ATLAS_EVIDENCE_RECORDS: usize = 10_000;
pub const MAX_ATLAS_DOMAIN_SUMMARIES: usize = 1_024;
pub const MAX_WALLET_GRAPH_NODES: usize = 2_048;
pub const MAX_WALLET_GRAPH_EDGES: usize = 8_192;

fn nonzero_hash(value: &Hash32) -> bool {
    *value != [0u8; 32]
}

fn validate_label(field: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && !value.contains("..")
        && !value.contains('/')
        && value.bytes().all(|b| !b.is_ascii_control());
    if valid {
        Ok(())
    } else {
        Err(format!("{field} invalid"))
    }
}

/// Kanıt sorgu sonucu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Domain ID.
    pub domain_id: DomainId,
    /// Domain yüksekliği.
    pub domain_height: u64,
    /// Event indeksi.
    pub event_index: u32,
    /// Event türü.
    pub event_kind: String,
    /// Event kök hash.
    pub event_root: Hash32,
    /// Commitment block hash.
    pub block_hash: Hash32,
    /// Doğrulanma zamanı (epoch).
    pub verified_epoch: u64,
    /// Consensus türü.
    pub consensus_kind: ConsensusKind,
}

impl EvidenceRecord {
    pub fn validate(&self) -> Result<(), String> {
        if self.domain_id == 0 {
            return Err("EvidenceRecord domain_id cannot be zero".into());
        }
        if self.domain_height == 0 {
            return Err("EvidenceRecord domain_height cannot be zero".into());
        }
        validate_label("EvidenceRecord event_kind", &self.event_kind)?;
        if !nonzero_hash(&self.event_root) {
            return Err("EvidenceRecord event_root cannot be zero".into());
        }
        if !nonzero_hash(&self.block_hash) {
            return Err("EvidenceRecord block_hash cannot be zero".into());
        }
        Ok(())
    }
}

/// Cüzdan bağlam grafi düğümü.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletContextNode {
    /// Adres.
    pub address: Address,
    /// Düğüm türü.
    pub node_type: WalletNodeType,
    /// İlişki sayısı.
    pub connection_count: u32,
    /// Son aktivite epoch'u.
    pub last_active_epoch: u64,
}

/// Cüzdan bağlam grafi kenarı.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletContextEdge {
    /// Kaynak adres.
    pub from: Address,
    /// Hedef adres.
    pub to: Address,
    /// Kenar türü.
    pub edge_type: WalletEdgeType,
    /// Ağırlık (işlem hacmi, stake miktarı vb.).
    pub weight: u64,
    /// Son etkileşim epoch'u.
    pub last_interaction_epoch: u64,
}

/// Cüzdan düğüm türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletNodeType {
    /// Normal kullanıcı.
    User,
    /// Doğrulayıcı.
    Validator,
    /// Prover.
    Prover,
    /// Relayer.
    Relayer,
    /// AI ajanı.
    AiAgent,
    /// Akıllı sözleşme.
    Contract,
    /// BNS kayıt sahibi.
    BnsOwner,
}

/// Cüzdan kenar türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletEdgeType {
    /// Transfer.
    Transfer,
    /// Staking.
    Stake,
    /// Cross-domain köprü.
    Bridge,
    /// AI ödeme.
    AiPayment,
    /// BNS kayıt.
    BnsRegistration,
    /// Storage anlaşma.
    StorageDeal,
    /// Governance oy.
    GovernanceVote,
    /// Pollen erişim izni.
    PollenGrant,
}

/// Cüzdan bağlam grafi — bir adresin tüm zincir-üstü ilişkileri.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletContextGraph {
    /// Merkez adres.
    pub center: Address,
    /// Bağlantılı düğümler.
    pub nodes: Vec<WalletContextNode>,
    /// Bağlantı kenarları.
    pub edges: Vec<WalletContextEdge>,
    /// Toplam transfer hacmi (u64 BUD).
    pub total_transfer_volume: u64,
    /// Graf derinliği (kaç atlama).
    pub depth: u32,
}

impl WalletContextGraph {
    pub fn validate(&self) -> Result<(), String> {
        if self.center == Address::zero() {
            return Err("WalletContextGraph center cannot be zero".into());
        }
        if self.nodes.len() > MAX_WALLET_GRAPH_NODES {
            return Err("WalletContextGraph node limit exceeded".into());
        }
        if self.edges.len() > MAX_WALLET_GRAPH_EDGES {
            return Err("WalletContextGraph edge limit exceeded".into());
        }
        if self.depth > 8 {
            return Err("WalletContextGraph depth too large".into());
        }
        for node in &self.nodes {
            if node.address == Address::zero() {
                return Err("WalletContextGraph node address cannot be zero".into());
            }
        }
        for edge in &self.edges {
            if edge.from == Address::zero() || edge.to == Address::zero() {
                return Err("WalletContextGraph edge address cannot be zero".into());
            }
            if edge.weight == 0 {
                return Err("WalletContextGraph edge weight cannot be zero".into());
            }
        }
        Ok(())
    }
}

/// Domain özet istatistikleri.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DomainSummary {
    /// Domain ID.
    pub domain_id: DomainId,
    /// Domain adı.
    pub name: String,
    /// Consensus türü.
    pub consensus_kind: ConsensusKind,
    /// Mevcut yükseklik.
    pub current_height: u64,
    /// Toplam transaction sayısı.
    pub total_transactions: u64,
    /// Toplam event sayısı.
    pub total_events: u64,
    /// Aktif doğrulayıcı sayısı.
    pub active_validators: u32,
    /// Son commit epoch'u.
    pub last_commit_epoch: u64,
}

impl DomainSummary {
    pub fn validate(&self) -> Result<(), String> {
        if self.domain_id == 0 {
            return Err("DomainSummary domain_id cannot be zero".into());
        }
        validate_label("DomainSummary name", &self.name)?;
        if self.last_commit_epoch > self.current_height.saturating_add(1_000_000) {
            return Err("DomainSummary last_commit_epoch implausible".into());
        }
        Ok(())
    }
}

/// Cross-domain mesaj iz sonucu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossDomainTrace {
    /// Kaynak domain.
    pub source_domain: DomainId,
    /// Hedef domain.
    pub target_domain: DomainId,
    /// Kaynak yükseklik.
    pub source_height: u64,
    /// Mesaj indeksi.
    pub message_index: u32,
    /// Mesaj durumu.
    pub status: MessageTraceStatus,
    /// Gönderen.
    pub sender: Address,
    /// Alıcı.
    pub recipient: Address,
    /// Payload hash.
    pub payload_hash: Hash32,
}

impl CrossDomainTrace {
    pub fn validate(&self) -> Result<(), String> {
        if self.source_domain == 0 || self.target_domain == 0 {
            return Err("CrossDomainTrace domains cannot be zero".into());
        }
        if self.source_domain == self.target_domain {
            return Err("CrossDomainTrace source/target domains must differ".into());
        }
        if self.source_height == 0 {
            return Err("CrossDomainTrace source_height cannot be zero".into());
        }
        if self.sender == Address::zero() || self.recipient == Address::zero() {
            return Err("CrossDomainTrace addresses cannot be zero".into());
        }
        if !nonzero_hash(&self.payload_hash) {
            return Err("CrossDomainTrace payload_hash cannot be zero".into());
        }
        Ok(())
    }
}

/// Mesaj iz durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageTraceStatus {
    /// Kaynak domain'de yayınlandı.
    Emitted,
    /// Settlement layer'da doğrulandı.
    Verified,
    /// Hedef domain'de alındı.
    Delivered,
    /// Zaman aşımı.
    Expired,
    /// Başarısız.
    Failed,
}

/// Atlas sorgu motoru.
#[derive(Debug, Clone, Default)]
pub struct AtlasQueryEngine {
    /// Kanıt kayıt defteri.
    pub evidence_records: Vec<EvidenceRecord>,
    /// Domain özetleri.
    pub domain_summaries: BTreeMap<DomainId, DomainSummary>,
}

impl AtlasQueryEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_evidence_record(&mut self, record: EvidenceRecord) -> Result<(), String> {
        record.validate()?;
        if self.evidence_records.len() >= MAX_ATLAS_EVIDENCE_RECORDS {
            self.evidence_records.remove(0);
        }
        self.evidence_records.push(record);
        Ok(())
    }

    pub fn upsert_domain_summary(&mut self, summary: DomainSummary) -> Result<(), String> {
        summary.validate()?;
        if !self.domain_summaries.contains_key(&summary.domain_id)
            && self.domain_summaries.len() >= MAX_ATLAS_DOMAIN_SUMMARIES
        {
            let oldest = self
                .domain_summaries
                .keys()
                .next()
                .copied()
                .ok_or_else(|| "Atlas domain summary index empty".to_string())?;
            self.domain_summaries.remove(&oldest);
        }
        self.domain_summaries.insert(summary.domain_id, summary);
        Ok(())
    }

    /// Domain ID'ye göre kanıt kayıtlarını sorgular.
    pub fn query_evidence_by_domain(&self, domain_id: DomainId) -> Vec<&EvidenceRecord> {
        self.evidence_records
            .iter()
            .filter(|r| r.domain_id == domain_id)
            .collect()
    }

    /// Belirli bir yükseklik aralığındaki kanıt kayıtlarını sorgular.
    pub fn query_evidence_by_height_range(
        &self,
        domain_id: DomainId,
        from_height: u64,
        to_height: u64,
    ) -> Vec<&EvidenceRecord> {
        if domain_id == 0 || from_height > to_height {
            return Vec::new();
        }
        self.evidence_records
            .iter()
            .filter(|r| {
                r.domain_id == domain_id
                    && r.domain_height >= from_height
                    && r.domain_height <= to_height
            })
            .collect()
    }

    /// Domain özetini döndürür.
    pub fn get_domain_summary(&self, domain_id: DomainId) -> Option<&DomainSummary> {
        self.domain_summaries.get(&domain_id)
    }

    /// Tüm domain özetlerini döndürür.
    pub fn all_domain_summaries(&self) -> Vec<&DomainSummary> {
        self.domain_summaries.values().collect()
    }

    /// Adrese göre kanıt kayıtlarını sorgular (tüm domain'lerde).
    ///
    /// Not: Şu an basit bir filtre; gerçek impl. için event'lerde adres
    /// indeksi gerekli.
    pub fn query_evidence_for_address(&self, _address: &Address) -> Vec<&EvidenceRecord> {
        // Stub: gerçek impl. için event emitter index gerekli
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(byte: u8) -> Hash32 {
        [byte; 32]
    }

    #[test]
    fn atlas_query_by_domain() {
        let mut engine = AtlasQueryEngine::new();
        engine.evidence_records.push(EvidenceRecord {
            domain_id: 1,
            domain_height: 100,
            event_index: 0,
            event_kind: "BridgeLocked".to_string(),
            event_root: test_hash(1),
            block_hash: test_hash(2),
            verified_epoch: 50,
            consensus_kind: ConsensusKind::PoW,
        });
        engine.evidence_records.push(EvidenceRecord {
            domain_id: 2,
            domain_height: 200,
            event_index: 0,
            event_kind: "BridgeMinted".to_string(),
            event_root: test_hash(3),
            block_hash: test_hash(4),
            verified_epoch: 55,
            consensus_kind: ConsensusKind::PoS,
        });

        let results = engine.query_evidence_by_domain(1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain_height, 100);
    }

    #[test]
    fn atlas_query_by_height_range() {
        let mut engine = AtlasQueryEngine::new();
        for h in [50, 100, 150, 200, 250] {
            engine.evidence_records.push(EvidenceRecord {
                domain_id: 1,
                domain_height: h,
                event_index: 0,
                event_kind: "Test".to_string(),
                event_root: test_hash(h as u8),
                block_hash: test_hash((h + 1) as u8),
                verified_epoch: h / 2,
                consensus_kind: ConsensusKind::PoW,
            });
        }

        let results = engine.query_evidence_by_height_range(1, 100, 200);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn atlas_domain_summary() {
        let mut engine = AtlasQueryEngine::new();
        engine
            .upsert_domain_summary(DomainSummary {
                domain_id: 1,
                name: "pow-main".to_string(),
                consensus_kind: ConsensusKind::PoW,
                current_height: 1000,
                total_transactions: 500,
                total_events: 200,
                active_validators: 10,
                last_commit_epoch: 500,
            })
            .unwrap();

        let summary = engine.get_domain_summary(1).unwrap();
        assert_eq!(summary.current_height, 1000);
        assert_eq!(engine.get_domain_summary(99), None);
    }

    #[test]
    fn wallet_context_graph_serialization() {
        let graph = WalletContextGraph {
            center: Address::from([1u8; 32]),
            nodes: vec![WalletContextNode {
                address: Address::from([2u8; 32]),
                node_type: WalletNodeType::Validator,
                connection_count: 5,
                last_active_epoch: 100,
            }],
            edges: vec![WalletContextEdge {
                from: Address::from([1u8; 32]),
                to: Address::from([2u8; 32]),
                edge_type: WalletEdgeType::Stake,
                weight: 10000,
                last_interaction_epoch: 100,
            }],
            total_transfer_volume: 10000,
            depth: 1,
        };

        let json = serde_json::to_string(&graph).unwrap();
        let parsed: WalletContextGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.nodes.len(), 1);
        assert_eq!(parsed.edges.len(), 1);
    }

    #[test]
    fn cross_domain_trace_serialization() {
        let trace = CrossDomainTrace {
            source_domain: 1,
            target_domain: 2,
            source_height: 100,
            message_index: 5,
            status: MessageTraceStatus::Verified,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash: test_hash(9),
        };

        let json = serde_json::to_string(&trace).unwrap();
        let parsed: CrossDomainTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, MessageTraceStatus::Verified);
    }

    #[test]
    fn atlas_rejects_zero_domain_evidence() {
        let mut engine = AtlasQueryEngine::new();
        let err = engine
            .insert_evidence_record(EvidenceRecord {
                domain_id: 0,
                domain_height: 1,
                event_index: 0,
                event_kind: "Test".to_string(),
                event_root: test_hash(1),
                block_hash: test_hash(2),
                verified_epoch: 1,
                consensus_kind: ConsensusKind::PoW,
            })
            .unwrap_err();
        assert!(err.contains("domain_id"));
    }

    #[test]
    fn atlas_rejects_invalid_wallet_graph() {
        let graph = WalletContextGraph {
            center: Address::zero(),
            nodes: vec![],
            edges: vec![],
            total_transfer_volume: 0,
            depth: 0,
        };
        assert!(graph.validate().unwrap_err().contains("center"));
    }

    #[test]
    fn cross_domain_trace_rejects_zero_payload() {
        let trace = CrossDomainTrace {
            source_domain: 1,
            target_domain: 2,
            source_height: 100,
            message_index: 5,
            status: MessageTraceStatus::Verified,
            sender: Address::from([1u8; 32]),
            recipient: Address::from([2u8; 32]),
            payload_hash: [0u8; 32],
        };
        assert!(trace.validate().unwrap_err().contains("payload_hash"));
    }

    #[test]
    fn atlas_summary_insert_prunes_when_limit_exceeded() {
        let mut engine = AtlasQueryEngine::new();
        for i in 1..=(MAX_ATLAS_DOMAIN_SUMMARIES as u32 + 1) {
            engine
                .upsert_domain_summary(DomainSummary {
                    domain_id: i,
                    name: format!("domain-{i}"),
                    consensus_kind: ConsensusKind::PoS,
                    current_height: 1,
                    total_transactions: 0,
                    total_events: 0,
                    active_validators: 0,
                    last_commit_epoch: 1,
                })
                .unwrap();
        }
        assert_eq!(engine.domain_summaries.len(), MAX_ATLAS_DOMAIN_SUMMARIES);
        assert!(engine.get_domain_summary(1).is_none());
    }
}
