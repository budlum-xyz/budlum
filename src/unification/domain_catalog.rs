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
use crate::unification::{
    build_merkle_proof, hash_domain_fields, unification_merkle_root, validate_safe_label,
    verify_merkle_proof,
};
use budlum_uel_abi::EeId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum number of registered universal domains held in one catalog snapshot.
pub const MAX_UNIVERSAL_DOMAINS: usize = crate::domain::registry::MAX_REGISTERED_DOMAINS;
const _: () = assert!(MAX_UNIVERSAL_DOMAINS == crate::domain::registry::MAX_REGISTERED_DOMAINS);

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

    /// Projects live chain state (local `ConsensusDomainRegistry`, external
    /// `IntakeState`, active `ObjectLayerRegistry` charters, and `BridgeState`
    /// assets) into a read-only unified domain catalog view.
    ///
    /// Unregistered ecosystem templates from [`Self::with_canonical_ecosystems`]
    /// are never included, and every [`DomainCapability`] is derived directly
    /// from live on-chain records rather than self-declared metadata.
    #[must_use]
    pub fn from_chain_state(state: &crate::core::account::AccountState) -> Self {
        use crate::cross_domain::external::profile::DomainState;
        use crate::object_layer::charter::CharterStatus;

        let mut catalog = Self::new();

        // 1. Registered local consensus domains.
        for domain in state.settlement.domains.domains() {
            let active_charter = state
                .settlement
                .object_layer
                .charters
                .get(&domain.id)
                .filter(|c| c.status == CharterStatus::Active);

            let caip2_reference = state
                .settlement
                .domains
                .caip2_for_domain(domain.id)
                .or_else(|| {
                    active_charter
                        .map(|c| c.chain_reference.trim())
                        .filter(|r| !r.is_empty())
                })
                .map_or_else(
                    || format!("budlum-domain:{}:{}", domain.domain_chain_id, domain.id),
                    ToOwned::to_owned,
                );

            let mut capabilities = BTreeSet::new();
            let has_bridge_backing =
                domain.bridge_enabled || state.bridge_state.has_asset_for_domain(domain.id);
            if has_bridge_backing {
                capabilities.insert(DomainCapability::UniversalPayment);
                capabilities.insert(DomainCapability::CrossDomainLiquidation);
            }
            if domain.bridge_enabled && domain.is_active() {
                capabilities.insert(DomainCapability::PosAndCardRail);
            }
            if active_charter.is_some() {
                capabilities.insert(DomainCapability::ObjectLayerCustody);
            }
            let adapter_lower = domain.finality_adapter.to_ascii_lowercase();
            if domain.kind == ConsensusKind::Pospace
                || adapter_lower.contains("storage")
                || adapter_lower.contains("arweave")
                || adapter_lower.contains("filecoin")
            {
                capabilities.insert(DomainCapability::DecentralizedStorage);
            }
            if domain.kind == ConsensusKind::Zk || !domain.zk_program_allowlist.is_empty() {
                capabilities.insert(DomainCapability::VerifiableCompute);
            }
            if domain.is_active() {
                capabilities.insert(DomainCapability::OutputComposition);
            }

            let record = UniversalDomainRecord {
                domain_id: domain.id,
                name: format!("Domain-{}", domain.id),
                caip2_reference,
                consensus_kind: domain.kind.clone(),
                execution_env_id: None,
                object_layer_family: active_charter.map(|c| c.vm_family),
                native_symbol: if domain.id == 0 {
                    "BUD".to_string()
                } else {
                    format!("DOM{}", domain.id)
                },
                native_decimals: 8,
                preserves_inner_rules: true,
                capabilities,
            };
            let _ = catalog.register_domain(record);
        }

        // 2. Registered external intake domains (live on-chain external adapters).
        for (key, entry) in &state.settlement.external_intake.entries {
            let intake_network = entry.golden.network.as_str();
            if state
                .settlement
                .domains
                .domain_id_by_caip2(intake_network)
                .is_some()
                || catalog.by_caip2.contains_key(intake_network)
            {
                continue;
            }
            let mut candidate =
                u32::from_le_bytes([key.0[0], key.0[1], key.0[2], key.0[3]]) | 0x8000_0000;
            while catalog.domains.contains_key(&candidate) {
                candidate = candidate.wrapping_add(1) | 0x8000_0000;
            }
            let is_serving = state
                .settlement
                .external_intake
                .registry
                .domain(key)
                .is_some_and(|reg| {
                    matches!(
                        reg.record.state,
                        DomainState::Active | DomainState::Admitted
                    )
                });
            let adapter_name = entry.golden.adapter;
            let network = entry.golden.network.as_str();
            let caip2_reference = format!(
                "external:{}:{}",
                hex::encode(adapter_name.0.get(..6).unwrap_or(&adapter_name.0)),
                network
            );
            let mut capabilities = BTreeSet::new();
            if state.bridge_state.has_asset_for_domain(candidate) {
                capabilities.insert(DomainCapability::UniversalPayment);
                capabilities.insert(DomainCapability::CrossDomainLiquidation);
            }
            if is_serving {
                capabilities.insert(DomainCapability::OutputComposition);
            }
            let record = UniversalDomainRecord {
                domain_id: candidate,
                name: format!("External-{network}"),
                caip2_reference,
                consensus_kind: ConsensusKind::Bft,
                execution_env_id: None,
                object_layer_family: None,
                native_symbol: "EXT".to_string(),
                native_decimals: 8,
                preserves_inner_rules: true,
                capabilities,
            };
            let _ = catalog.register_domain(record);
        }

        catalog
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

    /// Builds a single Merkle inclusion proof attesting that `domain_id` (with
    /// its canonical CAIP-2 identity, consensus family, and derived
    /// capabilities) is committed under [`Self::catalog_root`].
    #[must_use]
    pub fn prove_domain_inclusion(
        &self,
        domain_id: DomainId,
    ) -> Option<UniversalDomainInclusionProof> {
        let mut leaves = Vec::with_capacity(self.domains.len());
        let mut target = None;
        for (idx, (&id, record)) in self.domains.iter().enumerate() {
            leaves.push(record.commitment_hash());
            if id == domain_id {
                target = Some((idx, record.clone()));
            }
        }
        let (leaf_index, record) = target?;
        let siblings = build_merkle_proof(b"BDLM_UNIVERSAL_CATALOG_V1", &leaves, leaf_index)?;
        Some(UniversalDomainInclusionProof {
            record,
            leaf_index,
            leaf_count: leaves.len(),
            siblings,
        })
    }
}

/// Self-contained Merkle inclusion proof against [`UniversalDomainCatalog::catalog_root`].
///
/// Allows a light client to verify with a single proof that a domain is
/// registered together with its CAIP-2 reference, consensus family, and
/// state-derived capability set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalDomainInclusionProof {
    /// Registered domain record committed at `leaf_index`.
    pub record: UniversalDomainRecord,
    /// Zero-based position of `record` in the canonical sorted catalog.
    pub leaf_index: usize,
    /// Total number of registered domains in the committed catalog.
    pub leaf_count: usize,
    /// Merkle sibling hashes from leaf to root.
    pub siblings: Vec<Hash32>,
}

impl UniversalDomainInclusionProof {
    /// Verifies this inclusion proof against `catalog_root`.
    #[must_use]
    pub fn verify(&self, catalog_root: &Hash32) -> bool {
        verify_merkle_proof(
            b"BDLM_UNIVERSAL_CATALOG_V1",
            catalog_root,
            self.leaf_index,
            self.leaf_count,
            &self.record.commitment_hash(),
            &self.siblings,
        )
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

    #[test]
    fn from_chain_state_exposes_only_registered_domains_and_derives_capabilities() {
        use crate::core::account::AccountState;
        use crate::cross_domain::bridge::AssetId;
        use crate::domain::types::{ConsensusDomain, DomainStatus, RootScheme};
        use crate::object_layer::charter::{CharterStatus, DataPolicy, DomainCharter};

        // Empty state produces an empty live catalog (never leaks unregistered templates).
        let mut state = AccountState::new();
        let empty = UniversalDomainCatalog::from_chain_state(&state);
        assert_eq!(empty.len(), 0);

        // Register a local BFT domain with bridge disabled and no charter.
        let domain = ConsensusDomain {
            id: 77,
            kind: ConsensusKind::Bft,
            status: DomainStatus::Active,
            domain_chain_id: 777,
            operator: Some(crate::core::address::Address::from([0x77; 32])),
            operator_bond: crate::domain::registry::MIN_DOMAIN_OPERATOR_BOND,
            config_hash: [1u8; 32],
            validator_set_hash: [2u8; 32],
            finality_adapter: "bft-quorum-commit".to_string(),
            min_confirmations: 1,
            bridge_enabled: false,
            block_hash_scheme: RootScheme::Sha3_256,
            state_root_scheme: RootScheme::Sha3_256,
            tx_root_scheme: RootScheme::Sha3_256,
            last_committed_height: 0,
            last_committed_hash: [0u8; 32],
            pow_parameters: None,
            zk_program_allowlist: Vec::new(),
            plugin_code_hash: None,
            genesis_state_root: [0u8; 32],
        };
        state
            .settlement
            .domains
            .register(domain)
            .expect("register domain");

        let view1 = UniversalDomainCatalog::from_chain_state(&state);
        assert_eq!(view1.len(), 1);
        let rec1 = view1.get(77).expect("registered domain must appear");
        assert!(rec1
            .capabilities
            .contains(&DomainCapability::OutputComposition));
        assert!(!rec1
            .capabilities
            .contains(&DomainCapability::UniversalPayment));
        assert!(!rec1
            .capabilities
            .contains(&DomainCapability::ObjectLayerCustody));

        // Registering a bridge asset for domain 77 derives UniversalPayment immediately.
        let asset = AssetId::for_domain(77, b"USDC");
        state
            .bridge_state
            .register_asset(asset, 77)
            .expect("register bridge asset");
        let view2 = UniversalDomainCatalog::from_chain_state(&state);
        let rec2 = view2.get(77).expect("domain");
        assert!(rec2
            .capabilities
            .contains(&DomainCapability::UniversalPayment));

        // Adding an active ObjectLayer charter derives ObjectLayerCustody + CAIP-2;
        // retiring the charter removes ObjectLayerCustody immediately.
        state.settlement.object_layer.charters.insert(
            77,
            DomainCharter {
                vm_family: HomeVmFamily::Evm,
                chain_reference: "eip155:777".to_string(),
                address_prefix: String::new(),
                endpoint: vec![0xAA; 20],
                endpoint_code_hash: [0x11; 32],
                verifier: vec![0xBB; 20],
                verifier_code_hash: [0x22; 32],
                upgrade_notice: 100,
                silence_window: 1000,
                data_policy: DataPolicy::Public,
                status: CharterStatus::Active,
                operator: None,
            },
        );
        let view3 = UniversalDomainCatalog::from_chain_state(&state);
        let rec3 = view3.get(77).expect("domain");
        assert!(rec3
            .capabilities
            .contains(&DomainCapability::ObjectLayerCustody));
        assert_eq!(rec3.caip2_reference, "eip155:777");

        state
            .settlement
            .object_layer
            .charters
            .get_mut(&77)
            .expect("charter")
            .status = CharterStatus::Retired;
        let view4 = UniversalDomainCatalog::from_chain_state(&state);
        let rec4 = view4.get(77).expect("domain");
        assert!(!rec4
            .capabilities
            .contains(&DomainCapability::ObjectLayerCustody));
    }
    #[test]
    fn single_merkle_proof_verifies_registered_domain_and_rejects_tampered_record() {
        let catalog = UniversalDomainCatalog::with_canonical_ecosystems();
        let root = catalog.catalog_root();
        let target_id = catalog.list()[0].domain_id;

        let proof = catalog
            .prove_domain_inclusion(target_id)
            .expect("registered domain must produce an inclusion proof");
        assert!(proof.verify(&root));

        // Tampering with consensus family or CAIP-2 reference invalidates proof.
        let mut tampered_caip2 = proof.clone();
        tampered_caip2.record.caip2_reference = "eip155:999999".to_string();
        assert!(!tampered_caip2.verify(&root));

        // Wrong root is rejected.
        let mut bad_root = root;
        bad_root[0] ^= 0xFF;
        assert!(!proof.verify(&bad_root));

        // Unregistered domain yields None.
        assert!(catalog.prove_domain_inclusion(u32::MAX - 7).is_none());
    }
}
