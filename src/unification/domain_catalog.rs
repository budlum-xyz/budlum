//! Universal Chain-as-Domain Catalog (`D-1`, `D-2`, `D-3`, `D-4`).
//!
//! Every blockchain network, consensus family, virtual machine, storage
//! network, and compute network registers in Budlum as a sovereign domain
//! without mutating its native consensus or execution semantics.
//!
//! WIRING: read through `bud_getUniversalDomains` in `src/rpc/server.rs` and
//! referenced across `src/unification/` (`output_composer`, `payment_router`,
//! `storage_fabric`).

use crate::domain::storage_params::StorageDomainParams;
use crate::domain::types::{ConsensusKind, DomainId, Hash32};
use crate::object_layer::family::HomeVmFamily;
use crate::unification::{hash_domain_fields, unification_merkle_root, validate_safe_label};
use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum number of registered universal domains held in one catalog snapshot.
pub const MAX_UNIVERSAL_DOMAINS: usize = 512;

/// Maximum capabilities declared by a single domain record.
pub const MAX_DOMAIN_CAPABILITIES: usize = 16;

/// Capabilities a registered domain offers to Budlum's unification fabric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainCapability {
    /// Domain participates in universal multi-token atomic payments.
    UniversalPayment,
    /// Domain supports POS / card-network instant settlement rails.
    PosAndCardRail,
    /// Domain assets can serve as cross-domain lending collateral or debt.
    CrossDomainLiquidation,
    /// Domain execution outputs can be composed in `OutputComposer`.
    OutputComposition,
    /// Domain hosts or verifies decentralized Web3 storage objects.
    DecentralizedStorage,
    /// Domain supports `HomeVmFamily` object-layer asset custody.
    ObjectLayerCustody,
    /// Domain provides zero-knowledge or verifiable AI compute proofs.
    VerifiableCompute,
}

/// Descriptor for one blockchain, execution environment, or storage network
/// registered as a Budlum domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalDomainRecord {
    /// Canonical Budlum settlement domain identifier.
    pub domain_id: DomainId,
    /// Human-readable ecosystem name (for example `Ethereum` or `Bitcoin`).
    pub name: String,
    /// CAIP-2 chain reference (for example `eip155:1`, `bip122:000000000019d6689c085ae165831e93`).
    pub caip2_reference: String,
    /// Native consensus family, preserved unchanged by Budlum.
    pub consensus_kind: ConsensusKind,
    /// Native execution machine byte (`EeId.0`) when the domain executes programs.
    pub execution_env_id: Option<u8>,
    /// Native object-layer VM family when the domain settles via UOL charters.
    pub object_layer_family: Option<HomeVmFamily>,
    /// Native gas / settlement ticker symbol (for example `BTC`, `ETH`, `SOL`, `BUD`).
    pub native_symbol: String,
    /// Native decimal precision (`0..=18`).
    pub native_decimals: u8,
    /// Whether external rules remain strictly sovereign (always `true` per `D-1`).
    pub preserves_inner_rules: bool,
    /// Set of unification capabilities enabled for this domain.
    pub capabilities: BTreeSet<DomainCapability>,
}

impl UniversalDomainRecord {
    /// Returns the typed `EeId` when this domain binds an execution machine.
    #[must_use]
    pub const fn execution_env(&self) -> Option<EeId> {
        match self.execution_env_id {
            Some(id) => Some(EeId(id)),
            None => None,
        }
    }

    /// Deterministic SHA3-256 commitment for this domain record.
    #[must_use]
    pub fn commitment_hash(&self) -> Hash32 {
        let id_bytes = self.domain_id.to_le_bytes();
        let consensus_bytes = self.consensus_kind.as_bytes();
        let ee_bytes = [
            u8::from(self.execution_env_id.is_some()),
            self.execution_env_id.unwrap_or(0),
        ];
        let uol_byte = [match self.object_layer_family {
            None => 0u8,
            Some(HomeVmFamily::Evm) => 1u8,
            Some(HomeVmFamily::CosmWasm) => 2u8,
            Some(HomeVmFamily::Svm) => 3u8,
            Some(HomeVmFamily::Move) => 4u8,
        }];
        let meta = [self.native_decimals, u8::from(self.preserves_inner_rules)];
        let mut cap_bytes = Vec::with_capacity(self.capabilities.len());
        for cap in &self.capabilities {
            cap_bytes.push(match cap {
                DomainCapability::UniversalPayment => 1,
                DomainCapability::PosAndCardRail => 2,
                DomainCapability::CrossDomainLiquidation => 3,
                DomainCapability::OutputComposition => 4,
                DomainCapability::DecentralizedStorage => 5,
                DomainCapability::ObjectLayerCustody => 6,
                DomainCapability::VerifiableCompute => 7,
            });
        }
        hash_domain_fields(
            b"BDLM_UNIVERSAL_DOMAIN_V1",
            &[
                &id_bytes,
                self.name.as_bytes(),
                self.caip2_reference.as_bytes(),
                &consensus_bytes,
                &ee_bytes,
                &uol_byte,
                self.native_symbol.as_bytes(),
                &meta,
                &cap_bytes,
            ],
        )
    }
}

/// Errors produced when validating or mutating a [`UniversalDomainCatalog`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    #[error("invalid domain record: {0}")]
    InvalidRecord(String),
    #[error("domain id {0} is already registered")]
    DuplicateDomainId(DomainId),
    #[error("CAIP-2 reference {0} is already registered")]
    DuplicateCaip2(String),
    #[error("universal domain catalog reached its {MAX_UNIVERSAL_DOMAINS}-domain ceiling")]
    CatalogFull,
    #[error("domain must preserve inner protocol rules (preserves_inner_rules=true)")]
    InnerRulesViolation,
}

/// Permissionless, deterministic registry of every blockchain, virtual machine,
/// and storage network unified under Budlum.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalDomainCatalog {
    domains: BTreeMap<DomainId, UniversalDomainRecord>,
    by_caip2: BTreeMap<String, DomainId>,
}

impl UniversalDomainCatalog {
    /// Creates an empty universal domain catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds the canonical catalog covering every major blockchain consensus
    /// model, execution machine, and decentralized storage network (`D-2`, `D-4`).
    #[must_use]
    pub fn with_canonical_ecosystems() -> Self {
        let mut catalog = Self::new();
        let all_exec_pay = [
            DomainCapability::UniversalPayment,
            DomainCapability::PosAndCardRail,
            DomainCapability::CrossDomainLiquidation,
            DomainCapability::OutputComposition,
        ];
        let presets = [
            PresetSpec {
                domain_id: 1,
                name: "Budlum Core",
                caip2: "budlum:45261",
                consensus: ConsensusKind::PoS,
                ee: Some(EeId::BUDZERO.0),
                uol: None,
                symbol: "BUD",
                decimals: 18,
                caps: &[
                    DomainCapability::UniversalPayment,
                    DomainCapability::PosAndCardRail,
                    DomainCapability::CrossDomainLiquidation,
                    DomainCapability::OutputComposition,
                    DomainCapability::DecentralizedStorage,
                    DomainCapability::VerifiableCompute,
                ],
            },
            PresetSpec {
                domain_id: 2,
                name: "Bitcoin",
                caip2: "bip122:000000000019d6689c085ae165831e93",
                consensus: ConsensusKind::PoW,
                ee: Some(EeId::UTXO.0),
                uol: None,
                symbol: "BTC",
                decimals: 8,
                caps: &all_exec_pay,
            },
            PresetSpec {
                domain_id: 3,
                name: "Ethereum",
                caip2: "eip155:1",
                consensus: ConsensusKind::PoS,
                ee: Some(EeId::EVM.0),
                uol: Some(HomeVmFamily::Evm),
                symbol: "ETH",
                decimals: 18,
                caps: &[
                    DomainCapability::UniversalPayment,
                    DomainCapability::PosAndCardRail,
                    DomainCapability::CrossDomainLiquidation,
                    DomainCapability::OutputComposition,
                    DomainCapability::ObjectLayerCustody,
                ],
            },
            PresetSpec {
                domain_id: 4,
                name: "Solana",
                caip2: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                consensus: ConsensusKind::PoS,
                ee: Some(EeId::SVM.0),
                uol: Some(HomeVmFamily::Svm),
                symbol: "SOL",
                decimals: 9,
                caps: &[
                    DomainCapability::UniversalPayment,
                    DomainCapability::PosAndCardRail,
                    DomainCapability::CrossDomainLiquidation,
                    DomainCapability::OutputComposition,
                    DomainCapability::ObjectLayerCustody,
                ],
            },
            PresetSpec {
                domain_id: 5,
                name: "Cosmos Hub / CosmWasm",
                caip2: "cosmos:cosmoshub-4",
                consensus: ConsensusKind::Bft,
                ee: Some(EeId::WASM.0),
                uol: Some(HomeVmFamily::CosmWasm),
                symbol: "ATOM",
                decimals: 6,
                caps: &[
                    DomainCapability::UniversalPayment,
                    DomainCapability::PosAndCardRail,
                    DomainCapability::CrossDomainLiquidation,
                    DomainCapability::OutputComposition,
                    DomainCapability::ObjectLayerCustody,
                ],
            },
            PresetSpec {
                domain_id: 6,
                name: "Aptos",
                caip2: "aptos:mainnet",
                consensus: ConsensusKind::Bft,
                ee: Some(EeId::MOVE.0),
                uol: Some(HomeVmFamily::Move),
                symbol: "APT",
                decimals: 8,
                caps: &[
                    DomainCapability::UniversalPayment,
                    DomainCapability::PosAndCardRail,
                    DomainCapability::CrossDomainLiquidation,
                    DomainCapability::OutputComposition,
                    DomainCapability::ObjectLayerCustody,
                ],
            },
            PresetSpec {
                domain_id: 7,
                name: "Sui",
                caip2: "sui:mainnet",
                consensus: ConsensusKind::Bft,
                ee: Some(EeId::MOVE_SUI.0),
                uol: Some(HomeVmFamily::Move),
                symbol: "SUI",
                decimals: 9,
                caps: &all_exec_pay,
            },
            PresetSpec {
                domain_id: 8,
                name: "Starknet",
                caip2: "starknet:SN_MAIN",
                consensus: ConsensusKind::Zk,
                ee: Some(EeId::CAIRO.0),
                uol: None,
                symbol: "STRK",
                decimals: 18,
                caps: &[
                    DomainCapability::UniversalPayment,
                    DomainCapability::CrossDomainLiquidation,
                    DomainCapability::OutputComposition,
                    DomainCapability::VerifiableCompute,
                ],
            },
            PresetSpec {
                domain_id: 9,
                name: "NEAR Protocol",
                caip2: "near:mainnet",
                consensus: ConsensusKind::PoS,
                ee: Some(EeId::NEAR_WASM.0),
                uol: None,
                symbol: "NEAR",
                decimals: 18,
                caps: &all_exec_pay,
            },
            PresetSpec {
                domain_id: 10,
                name: "Polkadot / PolkaVM",
                caip2: "polkadot:91b171bb158e2d3848fa23a9f1c25182",
                consensus: ConsensusKind::PoS,
                ee: Some(EeId::POLKAVM.0),
                uol: None,
                symbol: "DOT",
                decimals: 10,
                caps: &all_exec_pay,
            },
            PresetSpec {
                domain_id: 11,
                name: "TON",
                caip2: "ton:mainnet",
                consensus: ConsensusKind::Bft,
                ee: Some(EeId::TVM.0),
                uol: None,
                symbol: "TON",
                decimals: 9,
                caps: &all_exec_pay,
            },
            PresetSpec {
                domain_id: 12,
                name: "Cardano",
                caip2: "cardano:mainnet",
                consensus: ConsensusKind::PoS,
                ee: Some(EeId::PLUTUS.0),
                uol: None,
                symbol: "ADA",
                decimals: 6,
                caps: &all_exec_pay,
            },
            PresetSpec {
                domain_id: 13,
                name: "RISC-V Sovereign Rollup",
                caip2: "riscv:budlum-rv32",
                consensus: ConsensusKind::Zk,
                ee: Some(EeId::RV32.0),
                uol: None,
                symbol: "RV32",
                decimals: 18,
                caps: &[
                    DomainCapability::OutputComposition,
                    DomainCapability::VerifiableCompute,
                ],
            },
            PresetSpec {
                domain_id: 14,
                name: "B.U.D. 3.0 Storage",
                caip2: "bud-storage:v3",
                consensus: ConsensusKind::StorageAttestation(StorageDomainParams::default()),
                ee: None,
                uol: None,
                symbol: "BUD",
                decimals: 18,
                caps: &[
                    DomainCapability::DecentralizedStorage,
                    DomainCapability::UniversalPayment,
                ],
            },
            PresetSpec {
                domain_id: 15,
                name: "IPFS Content Network",
                caip2: "storage:ipfs",
                consensus: ConsensusKind::Custom(String::from("content-addressed-dht")),
                ee: None,
                uol: None,
                symbol: "IPFS",
                decimals: 0,
                caps: &[DomainCapability::DecentralizedStorage],
            },
            PresetSpec {
                domain_id: 16,
                name: "Arweave Permaweb",
                caip2: "storage:arweave",
                consensus: ConsensusKind::PoW,
                ee: None,
                uol: None,
                symbol: "AR",
                decimals: 12,
                caps: &[
                    DomainCapability::DecentralizedStorage,
                    DomainCapability::UniversalPayment,
                ],
            },
            PresetSpec {
                domain_id: 17,
                name: "Filecoin Storage",
                caip2: "fil:mainnet",
                consensus: ConsensusKind::Custom(String::from("proof-of-spacetime")),
                ee: Some(EeId::EVM.0),
                uol: None,
                symbol: "FIL",
                decimals: 18,
                caps: &[
                    DomainCapability::DecentralizedStorage,
                    DomainCapability::UniversalPayment,
                    DomainCapability::OutputComposition,
                ],
            },
            PresetSpec {
                domain_id: 18,
                name: "Walrus Blob Network",
                caip2: "storage:walrus",
                consensus: ConsensusKind::Bft,
                ee: Some(EeId::MOVE_SUI.0),
                uol: None,
                symbol: "WAL",
                decimals: 9,
                caps: &[
                    DomainCapability::DecentralizedStorage,
                    DomainCapability::UniversalPayment,
                ],
            },
            PresetSpec {
                domain_id: 19,
                name: "Budlum AI Inference",
                caip2: "bud-ai:paradigma",
                consensus: ConsensusKind::AiInference,
                ee: Some(EeId::BUDZERO.0),
                uol: None,
                symbol: "BUD",
                decimals: 18,
                caps: &[
                    DomainCapability::VerifiableCompute,
                    DomainCapability::OutputComposition,
                ],
            },
        ];
        for spec in presets {
            let _ = catalog.register_domain(spec.into_record());
        }
        catalog
    }

    /// Registers a new blockchain, virtual machine, or storage network domain.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] if the catalog is full, inner-rule preservation
    /// is disabled, any identifier is malformed, or the domain id / CAIP-2
    /// reference collides with an existing entry.
    pub fn register_domain(&mut self, record: UniversalDomainRecord) -> Result<(), CatalogError> {
        if self.domains.len() >= MAX_UNIVERSAL_DOMAINS {
            return Err(CatalogError::CatalogFull);
        }
        if record.domain_id == 0 {
            return Err(CatalogError::InvalidRecord(String::from(
                "domain_id must be non-zero",
            )));
        }
        if !record.preserves_inner_rules {
            return Err(CatalogError::InnerRulesViolation);
        }
        validate_safe_label("name", &record.name, 64).map_err(CatalogError::InvalidRecord)?;
        validate_safe_label("caip2_reference", &record.caip2_reference, 96)
            .map_err(CatalogError::InvalidRecord)?;
        if !record.caip2_reference.contains(':') {
            return Err(CatalogError::InvalidRecord(String::from(
                "caip2_reference must contain a namespace separator ':'",
            )));
        }
        validate_safe_label("native_symbol", &record.native_symbol, 16)
            .map_err(CatalogError::InvalidRecord)?;
        if record.native_decimals > 18 {
            return Err(CatalogError::InvalidRecord(String::from(
                "native_decimals cannot exceed 18",
            )));
        }
        if record.capabilities.is_empty() || record.capabilities.len() > MAX_DOMAIN_CAPABILITIES {
            return Err(CatalogError::InvalidRecord(format!(
                "capabilities count must be within 1..={MAX_DOMAIN_CAPABILITIES}"
            )));
        }
        if self.domains.contains_key(&record.domain_id) {
            return Err(CatalogError::DuplicateDomainId(record.domain_id));
        }
        if self.by_caip2.contains_key(&record.caip2_reference) {
            return Err(CatalogError::DuplicateCaip2(record.caip2_reference));
        }
        self.by_caip2
            .insert(record.caip2_reference.clone(), record.domain_id);
        self.domains.insert(record.domain_id, record);
        Ok(())
    }

    /// Looks up a domain by its numeric `DomainId`.
    #[must_use]
    pub fn get(&self, domain_id: DomainId) -> Option<&UniversalDomainRecord> {
        self.domains.get(&domain_id)
    }

    /// Looks up a domain by its CAIP-2 reference.
    ///
    /// Convenience: exposed for CAIP-2 ecosystem lookup callers.
    #[must_use]
    pub fn get_by_caip2(&self, caip2: &str) -> Option<&UniversalDomainRecord> {
        let id = self.by_caip2.get(caip2)?;
        self.domains.get(id)
    }

    /// Lists all registered domains in deterministic `DomainId` order.
    #[must_use]
    pub fn list(&self) -> Vec<&UniversalDomainRecord> {
        self.domains.values().collect()
    }

    /// Lists all registered domains that advertise `capability`.
    ///
    /// Convenience: exposed for capability-filtered domain queries.
    #[must_use]
    pub fn with_capability(&self, capability: DomainCapability) -> Vec<&UniversalDomainRecord> {
        self.domains
            .values()
            .filter(|rec| rec.capabilities.contains(&capability))
            .collect()
    }

    /// Number of domains registered in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Returns `true` when no domains are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Deterministic Merkle root committing to every registered domain record.
    #[must_use]
    pub fn catalog_root(&self) -> Hash32 {
        let leaves: Vec<Hash32> = self
            .domains
            .values()
            .map(UniversalDomainRecord::commitment_hash)
            .collect();
        unification_merkle_root(b"BDLM_UNIVERSAL_CATALOG_V1", &leaves)
    }
}

struct PresetSpec<'a> {
    domain_id: DomainId,
    name: &'a str,
    caip2: &'a str,
    consensus: ConsensusKind,
    ee: Option<u8>,
    uol: Option<HomeVmFamily>,
    symbol: &'a str,
    decimals: u8,
    caps: &'a [DomainCapability],
}

impl PresetSpec<'_> {
    fn into_record(self) -> UniversalDomainRecord {
        UniversalDomainRecord {
            domain_id: self.domain_id,
            name: String::from(self.name),
            caip2_reference: String::from(self.caip2),
            consensus_kind: self.consensus,
            execution_env_id: self.ee,
            object_layer_family: self.uol,
            native_symbol: String::from(self.symbol),
            native_decimals: self.decimals,
            preserves_inner_rules: true,
            capabilities: self.caps.iter().copied().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_catalog_covers_all_thirteen_execution_environments_and_storage() {
        let catalog = UniversalDomainCatalog::with_canonical_ecosystems();
        assert_eq!(catalog.len(), 19);
        assert!(catalog.get_by_caip2("eip155:1").is_some());
        assert!(catalog.get_by_caip2("bud-storage:v3").is_some());
        assert!(catalog.get_by_caip2("storage:ipfs").is_some());
        assert!(catalog.get_by_caip2("storage:arweave").is_some());
        assert!(
            catalog
                .with_capability(DomainCapability::DecentralizedStorage)
                .len()
                >= 5
        );
        // Every registered execution environment from EeId must appear in the catalog.
        let present_ees: BTreeSet<u8> = catalog
            .list()
            .into_iter()
            .filter_map(|d| d.execution_env_id)
            .collect();
        for ee in [
            EeId::EVM,
            EeId::WASM,
            EeId::SVM,
            EeId::MOVE,
            EeId::BUDZERO,
            EeId::MOVE_SUI,
            EeId::CAIRO,
            EeId::NEAR_WASM,
            EeId::POLKAVM,
            EeId::TVM,
            EeId::UTXO,
            EeId::PLUTUS,
            EeId::RV32,
        ] {
            assert!(
                present_ees.contains(&ee.0),
                "missing EeId 0x{:02x} in canonical catalog",
                ee.0
            );
        }
        assert_ne!(catalog.catalog_root(), [0u8; 32]);
    }

    #[test]
    fn permissionless_registration_accepts_future_network_and_rejects_rule_override() {
        let mut catalog = UniversalDomainCatalog::with_canonical_ecosystems();
        let before_root = catalog.catalog_root();
        let mut future_chain = UniversalDomainRecord {
            domain_id: 42,
            name: String::from("FutureDAG"),
            caip2_reference: String::from("futuredag:mainnet"),
            consensus_kind: ConsensusKind::Custom(String::from("dag-bft")),
            execution_env_id: Some(EeId::WASM.0),
            object_layer_family: None,
            native_symbol: String::from("FDAG"),
            native_decimals: 18,
            preserves_inner_rules: false,
            capabilities: [DomainCapability::UniversalPayment].into_iter().collect(),
        };
        assert_eq!(
            catalog.register_domain(future_chain.clone()),
            Err(CatalogError::InnerRulesViolation)
        );
        future_chain.preserves_inner_rules = true;
        catalog.register_domain(future_chain.clone()).unwrap();
        assert_ne!(catalog.catalog_root(), before_root);
        assert_eq!(
            catalog.register_domain(future_chain),
            Err(CatalogError::DuplicateDomainId(42))
        );
    }
}
