use crate::core::address::Address;
use crate::core::block::Block;
use crate::core::hash::hash_fields_bytes;
use crate::domain::finality_adapter::FinalityProof;
use crate::domain::storage_params::StorageDomainParams;
use serde::{Deserialize, Serialize};

pub type DomainId = u32;
pub type Hash32 = [u8; 32];

pub const POW_HEADER_CHAIN_ADAPTER: &str = "pow-header-chain-v1";

/// Canonical name of the storage-attestation domain finality adapter.
///
/// Set as the `ConsensusDomain::finality_adapter` value when registering a
/// `StorageAttestation` domain. Distinct from the PoW header-chain adapter
/// (`POW_HEADER_CHAIN_ADAPTER`) because storage finality is **not** the same
/// shape as bounded-PoW header finality (Görev 3 will introduce
/// `StorageFinalityAdapter`, vision §3 + §8.3).
pub const STORAGE_ATTESTATION_ADAPTER: &str = "storage-attestation-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsensusKind {
    PoW,
    PoS,
    PoA,
    Bft,
    Zk,
    Custom(String),
    /// B.U.D. Storage ConsensusDomain (Task 0.38, Görev 1, vision §8.1).
    ///
    /// Carries the bounded `StorageDomainParams` so the type system forces
    /// every consumer to handle the storage-specific limits. We use a new
    /// enum variant (not `Custom("StorageProofOfReplication")`) because the
    /// parameter bundle is part of the consensus surface — see Task 0.38 plan
    /// §3.1: "yeni bir hash fonksiyonu icat etme" / "yeni bir köprü protokolü
    /// icat etme" but it IS a new domain kind that needs its own typing.
    StorageAttestation(StorageDomainParams),
    /// P5 ADIM8 — AI Inference Consensus Domain (Paradigma §5).
    ///
    /// AI Inference operates as a first-class consensus domain in the
    /// settlement layer. AI verifiers stake and attest to inference results;
    /// their collective agreement threshold produces `AiInferenceOutcome`s
    /// that are committed to the `GlobalBlockHeader.ai_root`.
    ///
    /// This is NOT a separate blockchain — it's an attestation domain
    /// within Budlum's multi-consensus architecture, analogous to
    /// `StorageAttestation` for B.U.D. but for AI verification.
    AiInference,
}

impl ConsensusKind {
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            ConsensusKind::PoW => b"pow".to_vec(),
            ConsensusKind::PoS => b"pos".to_vec(),
            ConsensusKind::PoA => b"poa".to_vec(),
            ConsensusKind::Bft => b"bft".to_vec(),
            ConsensusKind::Zk => b"zk".to_vec(),
            ConsensusKind::Custom(name) => {
                let mut out = b"custom:".to_vec();
                out.extend_from_slice(name.as_bytes());
                out
            }
            ConsensusKind::StorageAttestation(params) => {
                // Tag + parameters: distinct from any `Custom(...)` string so
                // downstream code that already pattern-matches on `as_bytes()`
                // can recognize storage domains unambiguously.
                let mut out = b"storage_attestation:".to_vec();
                out.extend_from_slice(&crate::domain::storage_params::storage_params_bytes(params));
                out
            }
            ConsensusKind::AiInference => b"ai_inference".to_vec(),
        }
    }

    /// Convenience: is this a B.U.D. storage domain?
    pub fn is_storage(&self) -> bool {
        matches!(self, ConsensusKind::StorageAttestation(_))
    }

    /// Convenience: is this an AI Inference domain?
    pub fn is_ai(&self) -> bool {
        matches!(self, ConsensusKind::AiInference)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DomainStatus {
    Active,
    Frozen,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RootScheme {
    BudlumBlockV2,
    Sha256,
    Sha3_256,
    Custom(String),
}

impl RootScheme {
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            RootScheme::BudlumBlockV2 => b"budlum-block-v2".to_vec(),
            RootScheme::Sha256 => b"sha256".to_vec(),
            RootScheme::Sha3_256 => b"sha3-256".to_vec(),
            RootScheme::Custom(name) => {
                let mut out = b"custom:".to_vec();
                out.extend_from_slice(name.as_bytes());
                out
            }
        }
    }
}

fn default_domain_operator() -> Option<Address> {
    Some(Address::zero())
}

fn default_domain_operator_bond() -> u64 {
    crate::domain::registry::MIN_DOMAIN_OPERATOR_BOND
}

/// Consensus-critical limits for the bounded PoW header-chain verifier.
///
/// These parameters are fixed when a domain is registered. In particular,
/// difficulty is never accepted from a relayer without checking it against
/// this range, and the verifier never accepts an unbounded header vector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoWDomainParameters {
    pub min_difficulty_bits: u32,
    pub max_difficulty_bits: u32,
    pub min_cumulative_work: u128,
    pub max_headers: u32,
}

impl PoWDomainParameters {
    pub fn validate(&self, min_confirmations: u64) -> Result<(), String> {
        if self.min_difficulty_bits == 0 || self.max_difficulty_bits > 120 {
            return Err("PoW difficulty range must be within 1..=120 bits".into());
        }
        if self.min_difficulty_bits > self.max_difficulty_bits {
            return Err("PoW min_difficulty_bits exceeds max_difficulty_bits".into());
        }
        if self.min_cumulative_work == 0 {
            return Err("PoW min_cumulative_work must be non-zero".into());
        }
        if self.max_headers == 0 || self.max_headers > 4096 {
            return Err("PoW max_headers must be within 1..=4096".into());
        }
        if min_confirmations == 0 || min_confirmations > u64::from(self.max_headers) {
            return Err("PoW min_confirmations must be within 1..=max_headers".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusDomain {
    pub id: DomainId,
    pub kind: ConsensusKind,
    pub status: DomainStatus,
    pub domain_chain_id: u64,
    #[serde(default = "default_domain_operator")]
    pub operator: Option<Address>,
    #[serde(default = "default_domain_operator_bond")]
    pub operator_bond: u64,
    pub config_hash: Hash32,
    pub validator_set_hash: Hash32,
    pub finality_adapter: String,
    pub min_confirmations: u64,
    pub bridge_enabled: bool,
    pub block_hash_scheme: RootScheme,
    pub state_root_scheme: RootScheme,
    pub tx_root_scheme: RootScheme,
    pub last_committed_height: u64,
    pub last_committed_hash: Hash32,
    /// Required when `finality_adapter == "pow-header-chain-v1"`.
    /// Appended for bincode field-order stability; legacy records are migrated
    /// by the storage loader and remain bridge-gated.
    #[serde(default)]
    pub pow_parameters: Option<PoWDomainParameters>,
}

impl ConsensusDomain {
    pub fn is_active(&self) -> bool {
        self.status == DomainStatus::Active
    }

    pub fn has_operator_bond(&self, minimum_bond: u64) -> bool {
        self.operator.is_some() && self.operator_bond >= minimum_bond
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainCommitment {
    pub domain_id: DomainId,
    pub domain_height: u64,
    pub domain_block_hash: Hash32,
    pub parent_domain_block_hash: Hash32,
    pub state_root: Hash32,
    pub tx_root: Hash32,
    pub event_root: Hash32,
    pub finality_proof_hash: Hash32,
    pub consensus_kind: ConsensusKind,
    pub validator_set_hash: Hash32,
    pub timestamp_ms: u128,
    pub sequence: u64,
    pub producer: Option<Address>,
    pub state_updates: std::collections::BTreeMap<Address, u64>,
}

impl DomainCommitment {
    pub fn from_block(
        domain: &ConsensusDomain,
        block: &Block,
        event_root: Hash32,
        finality_proof_hash: Hash32,
        sequence: u64,
    ) -> Result<Self, String> {
        Ok(Self {
            domain_id: domain.id,
            domain_height: block.index,
            domain_block_hash: normalize_hash32(
                b"domain_block_hash",
                domain.id,
                &domain.block_hash_scheme,
                block.hash.as_bytes(),
            )?,
            parent_domain_block_hash: normalize_hash32(
                b"parent_domain_block_hash",
                domain.id,
                &domain.block_hash_scheme,
                block.previous_hash.as_bytes(),
            )?,
            state_root: normalize_hash32(
                b"state_root",
                domain.id,
                &domain.state_root_scheme,
                block.state_root.as_bytes(),
            )?,
            tx_root: normalize_hash32(
                b"tx_root",
                domain.id,
                &domain.tx_root_scheme,
                block.tx_root.as_bytes(),
            )?,
            event_root,
            finality_proof_hash,
            consensus_kind: domain.kind.clone(),
            validator_set_hash: domain.validator_set_hash,
            timestamp_ms: block.timestamp,
            sequence,
            producer: block.producer,
            state_updates: std::collections::BTreeMap::new(),
        })
    }

    pub fn leaf_hash(&self) -> Hash32 {
        let kind = self.consensus_kind.as_bytes();
        let producer = self
            .producer
            .map(|address| address.as_bytes().to_vec())
            .unwrap_or_default();

        let mut state_updates_bytes = Vec::new();
        for (addr, nonce) in &self.state_updates {
            state_updates_bytes.extend_from_slice(addr.as_bytes());
            state_updates_bytes.extend_from_slice(&nonce.to_le_bytes());
        }

        hash_fields_bytes(&[
            b"BDLM_DOMAIN_COMMITMENT_V1",
            &self.domain_id.to_le_bytes(),
            &self.domain_height.to_le_bytes(),
            &self.domain_block_hash,
            &self.parent_domain_block_hash,
            &self.state_root,
            &self.tx_root,
            &self.event_root,
            &self.finality_proof_hash,
            &kind,
            &self.validator_set_hash,
            &self.timestamp_ms.to_le_bytes(),
            &self.sequence.to_le_bytes(),
            &producer,
            &state_updates_bytes,
        ])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedDomainCommitment {
    pub commitment: DomainCommitment,
    pub proof: FinalityProof,
}

impl VerifiedDomainCommitment {
    pub fn leaf_hash(&self) -> Hash32 {
        self.commitment.leaf_hash()
    }
}

pub fn normalize_hash32(
    tag: &[u8],
    domain_id: DomainId,
    scheme: &RootScheme,
    raw: &[u8],
) -> Result<Hash32, String> {
    if let Ok(decoded) = hex::decode(raw) {
        if decoded.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&decoded);
            return Ok(out);
        }
    }

    if raw.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        return Ok(out);
    }

    let scheme_bytes = scheme.as_bytes();
    Ok(hash_fields_bytes(&[
        b"BDLM_NORMALIZED_ROOT_V1",
        tag,
        &domain_id.to_le_bytes(),
        &scheme_bytes,
        raw,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_hash32_accepts_hex_and_hashes_non_32_byte_input() {
        let hex_root = "11".repeat(32);
        let normalized =
            normalize_hash32(b"state", 1, &RootScheme::BudlumBlockV2, hex_root.as_bytes()).unwrap();
        assert_eq!(normalized, [0x11u8; 32]);

        let custom = normalize_hash32(
            b"state",
            1,
            &RootScheme::Custom("foreign".into()),
            b"short-root",
        )
        .unwrap();
        assert_ne!(custom, [0u8; 32]);
        assert_ne!(custom, normalized);
    }
}
