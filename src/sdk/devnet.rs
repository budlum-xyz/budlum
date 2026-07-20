//! P12-12: Lokal 4-domain devnet yönetimi.
//!
//! Budlum Developer OS'un merkezinde, geliştiricinin lokal makinesinde
//! 4 bağımsız consensus domain'ini (PoW, PoS, PoA, Bft) başlatan devnet
//! yönetimi bulunur.
//!
//! # Devnet Mimarisi
//!
//! ```text
//! LocalDevnet
//! ├── Domain 0: PoW (Permissionless) — mining, difficulty adjustment
//! ├── Domain 1: PoS (Permissionless) — staking, epoch rotation
//! ├── Domain 2: PoA (Permissioned)   — KYC validators, sealed blocks
//! └── Domain 3: Bft (Permissionless) — sync committee, BLS quorum
//! ```
//!
//! Her domain kendi chain actor'üne, depolama alanına ve RPC endpoint'ine
//! sahiptir. Settlement layer domain commit'leri birleştirir.

use crate::domain::{ConsensusKind, DomainId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;

/// Lokal devnet'te öntanımlı domain sayısı.
pub const LOCAL_DEVNET_DOMAIN_COUNT: usize = 4;

/// Lokal devnet domain profilleri.
pub const LOCAL_DEVNET_DOMAINS: [DevnetDomainProfile; LOCAL_DEVNET_DOMAIN_COUNT] = [
    DevnetDomainProfile {
        domain_id: 0,
        name: "pow-local",
        consensus: "pow",
        rpc_port: 8640,
        chain_id_offset: 0,
    },
    DevnetDomainProfile {
        domain_id: 1,
        name: "pos-local",
        consensus: "pos",
        rpc_port: 8641,
        chain_id_offset: 1,
    },
    DevnetDomainProfile {
        domain_id: 2,
        name: "poa-local",
        consensus: "poa",
        rpc_port: 8642,
        chain_id_offset: 2,
    },
    DevnetDomainProfile {
        domain_id: 3,
        name: "bft-local",
        consensus: "bft",
        rpc_port: 8643,
        chain_id_offset: 3,
    },
];

/// Tek bir devnet domain'inin yapılandırma profili.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevnetDomainProfile {
    /// Domain ID (settlement layer'da kayıtlı ID).
    pub domain_id: DomainId,
    /// Domain adı (insan-okunur).
    pub name: &'static str,
    /// Consensus türü ("pow", "pos", "poa", "bft").
    pub consensus: &'static str,
    /// RPC dinleme portu.
    pub rpc_port: u16,
    /// Base chain_id üzerine eklenecek offset.
    pub chain_id_offset: u64,
}

impl DevnetDomainProfile {
    /// Consensus türünü `ConsensusKind`'a dönüştürür.
    pub fn consensus_kind(&self) -> ConsensusKind {
        match self.consensus {
            "pow" => ConsensusKind::PoW,
            "pos" => ConsensusKind::PoS,
            "poa" => ConsensusKind::PoA,
            "bft" => ConsensusKind::Bft,
            other => ConsensusKind::Custom(other.to_string()),
        }
    }

    /// RPC dinleme adresini döndürür (localhost:port).
    pub fn rpc_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.rpc_port)
            .parse()
            .expect("valid socket addr")
    }
}

/// Devnet yapılandırması — `budlum.toml` [devnet] bölümü ve ek parametreler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevnetConfig {
    /// Base chain ID (öntanımlı: 1337, devnet standardı).
    #[serde(default = "default_base_chain_id")]
    pub base_chain_id: u64,
    /// Domain yapılandırmaları.
    #[serde(default = "default_domain_configs")]
    pub domains: BTreeMap<DomainId, DomainConfig>,
    /// Data dizini kökü.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// Genesis dosyası yolu.
    #[serde(default = "default_genesis_file")]
    pub genesis_file: String,
    /// Devnet auto-mine interval (ms). 0 = manuel mining.
    #[serde(default)]
    pub auto_mine_interval_ms: u64,
}

fn default_base_chain_id() -> u64 {
    1337
}

fn default_data_dir() -> String {
    "./data/sdk-devnet/".to_string()
}

fn default_genesis_file() -> String {
    "./config/devnet-genesis.json".to_string()
}

fn default_domain_configs() -> BTreeMap<DomainId, DomainConfig> {
    LOCAL_DEVNET_DOMAINS
        .iter()
        .map(|p| {
            (
                p.domain_id,
                DomainConfig {
                    name: p.name.to_string(),
                    consensus: p.consensus.to_string(),
                    rpc_port: p.rpc_port,
                    chain_id: default_base_chain_id() + p.chain_id_offset,
                    enabled: true,
                },
            )
        })
        .collect()
}

impl Default for DevnetConfig {
    fn default() -> Self {
        Self {
            base_chain_id: default_base_chain_id(),
            domains: default_domain_configs(),
            data_dir: default_data_dir(),
            genesis_file: default_genesis_file(),
            auto_mine_interval_ms: 0,
        }
    }
}

/// Tek bir domain'in detaylı yapılandırması.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    /// Domain adı.
    pub name: String,
    /// Consensus türü.
    pub consensus: String,
    /// RPC portu.
    pub rpc_port: u16,
    /// Bu domain'in chain ID'si.
    pub chain_id: u64,
    /// Domain aktif mi?
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Çalışan bir lokal devnet örneği.
///
/// Devnet başlatıldığında her domain için ayrı bir veri dizini ve
/// RPC endpoint oluşturulur. Bu yapı, çalışan devnet'in durumunu
/// takip etmek için kullanılır.
#[derive(Debug, Clone)]
pub struct LocalDevnet {
    /// Devnet yapılandırması.
    pub config: DevnetConfig,
    /// Aktif domain'lerin durumları.
    pub domain_statuses: BTreeMap<DomainId, DomainStatus>,
}

/// Bir domain'in çalışma durumu.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DomainRunStatus {
    /// Başlatılmadı.
    Stopped,
    /// Başlatılıyor.
    Starting,
    /// Çalışıyor.
    Running,
    /// Hata ile durdu.
    Failed(String),
}

/// Domain durum bilgisi.
#[derive(Debug, Clone)]
pub struct DomainStatus {
    /// Domain yapılandırması.
    pub config: DomainConfig,
    /// Çalışma durumu.
    pub status: DomainRunStatus,
    /// Mevcut blok yüksekliği (çalışıyorsa).
    pub height: u64,
}

impl LocalDevnet {
    /// Yeni bir devnet örneği oluşturur (henüz başlatmaz).
    pub fn new(config: DevnetConfig) -> Self {
        let domain_statuses = config
            .domains
            .iter()
            .map(|(&id, dc)| {
                (
                    id,
                    DomainStatus {
                        config: dc.clone(),
                        status: DomainRunStatus::Stopped,
                        height: 0,
                    },
                )
            })
            .collect();

        Self {
            config,
            domain_statuses,
        }
    }

    /// Varsayılan 4-domain devnet oluştur.
    pub fn default_devnet() -> Self {
        Self::new(DevnetConfig::default())
    }

    /// Belirli bir domain'i başlatır.
    pub fn start_domain(&mut self, domain_id: DomainId) -> Result<(), String> {
        let status = self
            .domain_statuses
            .get_mut(&domain_id)
            .ok_or_else(|| format!("Unknown domain ID: {}", domain_id))?;

        if !status.config.enabled {
            return Err(format!(
                "Domain {} ({}) is disabled",
                domain_id, status.config.name
            ));
        }

        if status.status == DomainRunStatus::Running {
            return Ok(()); // Zaten çalışıyor
        }

        // Veri dizinini oluştur
        let domain_data_dir = format!(
            "{}domain-{}/",
            self.config.data_dir, domain_id
        );
        std::fs::create_dir_all(&domain_data_dir)
            .map_err(|e| format!("Failed to create data dir for domain {}: {}", domain_id, e))?;

        status.status = DomainRunStatus::Running;
        status.height = 0;

        tracing::info!(
            "SDK Devnet: Domain {} ({}) started — RPC at 127.0.0.1:{}",
            domain_id,
            status.config.name,
            status.config.rpc_port
        );

        Ok(())
    }

    /// Tüm aktif domain'leri başlatır.
    pub fn start_all(&mut self) -> Result<(), Vec<(DomainId, String)>> {
        let domain_ids: Vec<DomainId> = self.domain_statuses.keys().copied().collect();
        let mut errors = Vec::new();

        for id in domain_ids {
            if let Err(e) = self.start_domain(id) {
                errors.push((id, e));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Bir domain'i durdurur.
    pub fn stop_domain(&mut self, domain_id: DomainId) -> Result<(), String> {
        let status = self
            .domain_statuses
            .get_mut(&domain_id)
            .ok_or_else(|| format!("Unknown domain ID: {}", domain_id))?;

        status.status = DomainRunStatus::Stopped;
        tracing::info!(
            "SDK Devnet: Domain {} ({}) stopped",
            domain_id,
            status.config.name
        );
        Ok(())
    }

    /// Tüm domain'leri durdurur.
    pub fn stop_all(&mut self) {
        let domain_ids: Vec<DomainId> = self.domain_statuses.keys().copied().collect();
        for id in domain_ids {
            let _ = self.stop_domain(id);
        }
    }

    /// Çalışan domain'lerin RPC endpoint'lerini listeler.
    pub fn rpc_endpoints(&self) -> BTreeMap<DomainId, String> {
        self.domain_statuses
            .iter()
            .filter(|(_, s)| s.status == DomainRunStatus::Running)
            .map(|(&id, s)| (id, format!("http://127.0.0.1:{}", s.config.rpc_port)))
            .collect()
    }

    /// Devnet durumunu JSON olarak serileştirir.
    pub fn status_json(&self) -> String {
        #[derive(Serialize)]
        struct DevnetStatusReport<'a> {
            domains: BTreeMap<DomainId, DomainStatusReport<'a>>,
            rpc_endpoints: BTreeMap<DomainId, String>,
        }

        #[derive(Serialize)]
        struct DomainStatusReport<'a> {
            name: &'a str,
            consensus: &'a str,
            status: String,
            height: u64,
        }

        let domains = self
            .domain_statuses
            .iter()
            .map(|(&id, s)| {
                let status_str = match &s.status {
                    DomainRunStatus::Stopped => "stopped".to_string(),
                    DomainRunStatus::Starting => "starting".to_string(),
                    DomainRunStatus::Running => "running".to_string(),
                    DomainRunStatus::Failed(e) => format!("failed: {}", e),
                };
                (
                    id,
                    DomainStatusReport {
                        name: &s.config.name,
                        consensus: &s.config.consensus,
                        status: status_str,
                        height: s.height,
                    },
                )
            })
            .collect();

        let report = DevnetStatusReport {
            domains,
            rpc_endpoints: self.rpc_endpoints(),
        };

        serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_devnet_has_four_domains() {
        let config = DevnetConfig::default();
        assert_eq!(config.domains.len(), 4);
        assert!(config.domains.contains_key(&0));
        assert!(config.domains.contains_key(&1));
        assert!(config.domains.contains_key(&2));
        assert!(config.domains.contains_key(&3));
    }

    #[test]
    fn default_domain_chain_ids_are_sequential() {
        let config = DevnetConfig::default();
        assert_eq!(config.domains[&0].chain_id, 1337);
        assert_eq!(config.domains[&1].chain_id, 1338);
        assert_eq!(config.domains[&2].chain_id, 1339);
        assert_eq!(config.domains[&3].chain_id, 1340);
    }

    #[test]
    fn devnet_start_stop_lifecycle() {
        let mut devnet = LocalDevnet::default_devnet();
        assert!(devnet.start_all().is_ok());

        for status in devnet.domain_statuses.values() {
            assert_eq!(status.status, DomainRunStatus::Running);
        }

        let endpoints = devnet.rpc_endpoints();
        assert_eq!(endpoints.len(), 4);

        devnet.stop_all();
        for status in devnet.domain_statuses.values() {
            assert_eq!(status.status, DomainRunStatus::Stopped);
        }
    }

    #[test]
    fn domain_profile_consensus_kind_mapping() {
        assert_eq!(LOCAL_DEVNET_DOMAINS[0].consensus_kind(), ConsensusKind::PoW);
        assert_eq!(LOCAL_DEVNET_DOMAINS[1].consensus_kind(), ConsensusKind::PoS);
        assert_eq!(LOCAL_DEVNET_DOMAINS[2].consensus_kind(), ConsensusKind::PoA);
        assert_eq!(LOCAL_DEVNET_DOMAINS[3].consensus_kind(), ConsensusKind::Bft);
    }

    #[test]
    fn devnet_status_json_is_valid() {
        let mut devnet = LocalDevnet::default_devnet();
        devnet.start_all().unwrap();
        let json = devnet.status_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("domains").is_some());
        assert!(parsed.get("rpc_endpoints").is_some());
    }

    #[test]
    fn devnet_config_roundtrip_toml() {
        let config = DevnetConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: DevnetConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.base_chain_id, 1337);
        assert_eq!(parsed.domains.len(), 4);
    }
}
