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
/// Shape as bounded-PoW header finality (will introduce
/// `StorageFinalityAdapter`, vision §3 + §8.3).
pub const STORAGE_ATTESTATION_ADAPTER: &str = "storage-attestation-v1";

/// Set as the `ConsensusDomain::finality_adapter` value when registering an
/// `AiInference` domain.
///
/// The name was previously only a string literal in the registration gate,
/// with no adapter answering to it, so an `AiInference` domain could be
/// registered and never finalize. It is a constant now so the gate and the
/// adapter cannot drift apart again silently.
pub const AI_INFERENCE_ADAPTER: &str = "ai-inference-threshold";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsensusKind {
    PoW,
    PoS,
    PoA,
    Bft,
    Zk,
    Custom(String),
    /// B.U.D. Storage ConsensusDomain.
    ///
    /// Carries the bounded `StorageDomainParams` so the type system forces
    /// Every consumer to handle the storage-specific limits. We use a new
    /// Enum variant (not `Custom("StorageProofOfReplication")`) because the
    /// Parameter bundle is part of the consensus surface plan
    /// §3.1: "yeni bir hash fonksiyonu icat etme" / "yeni bir köprü protokolü
    /// Icat etme" but it IS a new domain kind that needs its own typing.
    StorageAttestation(StorageDomainParams),
    /// AI Inference Consensus Domain (Paradigma §5).
    ///
    /// AI Inference operates as a first-class consensus domain in the
    /// Settlement layer. AI verifiers stake and attest to inference results;
    /// Their collective agreement threshold produces `AiInferenceOutcome`s
    /// That are committed to the `GlobalBlockHeader.ai_root`.
    ///
    /// This is NOT a separate blockchain - it's an attestation domain
    /// Within Budlum's multi-consensus architecture, analogous to
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
                // Downstream code that already pattern-matches on `as_bytes`
                // Can recognize storage domains unambiguously.
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
/// Difficulty is never accepted from a relayer without checking it against
/// This range, and the verifier never accepts an unbounded header vector.
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
    /// By the storage loader and remain bridge-gated.
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

/// Bind a validator-set digest to the domain that registered it.
///
/// This is deliberately *not* [`normalize_hash32`]. That function exists to
/// carry a foreign chain's own hash through unchanged when it is already 32
/// bytes, so the same block hash lands on the same value in every field that
/// mentions it. A validator-set commitment needs the opposite property.
///
/// Measured before this existed: both production callers passed
/// `ValidatorSetSnapshot::compute_hash(..).as_bytes()`, which is a 64-character
/// hex `String`. `hex::decode` accepted it, produced 32 bytes, and returned
/// from the first branch - so `tag`, `domain_id` and `scheme` were all
/// discarded. Two `PoA` domains sharing an authority set therefore had byte-equal
/// `validator_set_hash` values, and `reject_unregistered_poa_authorities`
/// compares exactly that field. A quorum assembled for one domain satisfied the
/// registered-set check on the other.
///
/// Hashing unconditionally is what makes the domain id load-bearing. The cost
/// is one extra hash per comparison; the alternative is a cross-domain replay
/// on the check that exists to prevent an attacker supplying their own
/// authority set.
#[must_use]
pub fn validator_set_commitment(
    tag: &[u8],
    domain_id: DomainId,
    scheme: &RootScheme,
    digest: &[u8],
) -> Hash32 {
    hash_fields_bytes(&[
        b"BDLM_VALIDATOR_SET_COMMITMENT_V1",
        tag,
        &domain_id.to_le_bytes(),
        &scheme.as_bytes(),
        digest,
    ])
}

/// Normalise a foreign root into 32 bytes.
///
/// A root that is already 32 bytes, or 32 bytes of hex, is passed through
/// unchanged, because the same external block hash has to normalise to the
/// same value wherever it appears; `domain_block_hash` and
/// `parent_domain_block_hash` use different tags, and a chain could never line
/// up if the same hash produced two values.
///
/// That pass-through means `tag`, `domain_id` and `scheme` only take effect
/// for inputs that are *not* 32 bytes. Do not use this to commit to something
/// that must be unique per domain - see [`validator_set_commitment`].
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

#[cfg(test)]
mod validator_set_commitment_locks {
    use super::*;

    /// The digest both production callers actually pass: a 64-character hex
    /// string from `ValidatorSetSnapshot::compute_hash`, not 32 raw bytes.
    fn snapshot_digest() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn two_domains_with_the_same_authorities_get_different_commitments() {
        // The bug this pins: `normalize_hash32` hex-decoded the 64-char digest
        // to 32 bytes and returned before `domain_id` was ever mixed in, so
        // two PoA domains sharing an authority set had byte-equal
        // `validator_set_hash` values. `reject_unregistered_poa_authorities`
        // compares that field, so a quorum gathered on one domain satisfied
        // the registered-set check on the other.
        let digest = snapshot_digest();
        let a = validator_set_commitment(
            b"bootstrap_validator_set_hash",
            1,
            &RootScheme::Sha3_256,
            digest.as_bytes(),
        );
        let b = validator_set_commitment(
            b"bootstrap_validator_set_hash",
            7,
            &RootScheme::Sha3_256,
            digest.as_bytes(),
        );
        assert_ne!(
            a, b,
            "the domain id must be load-bearing in a validator-set commitment"
        );
    }

    #[test]
    fn the_tag_and_scheme_are_load_bearing_too() {
        let digest = snapshot_digest();
        let base =
            validator_set_commitment(b"tag_one", 1, &RootScheme::Sha3_256, digest.as_bytes());
        assert_ne!(
            base,
            validator_set_commitment(b"tag_two", 1, &RootScheme::Sha3_256, digest.as_bytes()),
            "tag must change the commitment"
        );
        assert_ne!(
            base,
            validator_set_commitment(b"tag_one", 1, &RootScheme::BudlumBlockV2, digest.as_bytes()),
            "root scheme must change the commitment"
        );
    }

    #[test]
    fn a_different_authority_set_still_changes_the_commitment() {
        // Domain separation must not come at the cost of the property the
        // commitment existed for.
        let a = validator_set_commitment(
            b"bootstrap_validator_set_hash",
            1,
            &RootScheme::Sha3_256,
            "ab".repeat(32).as_bytes(),
        );
        let b = validator_set_commitment(
            b"bootstrap_validator_set_hash",
            1,
            &RootScheme::Sha3_256,
            "cd".repeat(32).as_bytes(),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn the_same_inputs_are_still_deterministic() {
        let digest = snapshot_digest();
        let a = validator_set_commitment(b"t", 3, &RootScheme::Sha3_256, digest.as_bytes());
        let b = validator_set_commitment(b"t", 3, &RootScheme::Sha3_256, digest.as_bytes());
        assert_eq!(a, b, "consensus requires this to be a pure function");
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn raw_32_byte_input_is_hashed_rather_than_passed_through() {
        // `normalize_hash32` returns 32-byte input unchanged on purpose.
        // `validator_set_commitment` must not, or the domain id would drop out
        // again for any caller that happens to hand it raw bytes.
        let raw = [0x11u8; 32];
        let committed = validator_set_commitment(
            b"bootstrap_validator_set_hash",
            1,
            &RootScheme::Sha3_256,
            &raw,
        );
        assert_ne!(
            committed, raw,
            "a validator-set commitment must never be its own input"
        );
        let other = validator_set_commitment(
            b"bootstrap_validator_set_hash",
            2,
            &RootScheme::Sha3_256,
            &raw,
        );
        assert_ne!(committed, other);
    }

    #[test]
    fn normalize_hash32_keeps_its_pass_through_for_foreign_roots() {
        // The two functions are split precisely because this behaviour has to
        // stay: `domain_block_hash` and `parent_domain_block_hash` use
        // different tags, and a chain could not line up if the same external
        // block hash normalised to two values.
        let block_hash = "a1".repeat(32);
        let as_child = normalize_hash32(
            b"domain_block_hash",
            1,
            &RootScheme::BudlumBlockV2,
            block_hash.as_bytes(),
        )
        .unwrap();
        let as_parent = normalize_hash32(
            b"parent_domain_block_hash",
            9,
            &RootScheme::Sha256,
            block_hash.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            as_child, as_parent,
            "a 32-byte foreign root must survive normalisation unchanged"
        );
    }
}
