//! Arweave `SPoRA` / Recall-Weave permanent storage external finality adapter.
//!
//! Arweave funds permanent storage through an on-chain endowment pool paired
//! with Succinct Proofs of Random Access (`SPoRA`). This adapter verifies external
//! Arweave storage-recall evidence under four fail-closed rules:
//!
//! 1. **Domain-separated Merkle inclusion**: reconstructs the canonical weave
//!    root from the chunk leaf `(chunk_id, chunk_offset, chunk_size,
//!    chunk_data_hash)` and bounded sibling path using distinct `leaf` and
//!    `node` domain separators and path bits derived from the chunk index, and
//!    compares it in constant time against the non-zero `weave_root`.
//! 2. **Overflow-safe contamination ceiling**: enforces
//!    `encumbered_endowment * 10_000 <= 3_000 * gross_endowment` using exact
//!    256-bit unsigned multiplication so large `u128` values never saturate
//!    into a false pass.
//! 3. **Checked endowment solvency**: verifies `free_endowment >= chunk_size *
//!    spora_rate * MIN_SUSTAINANCE_EPOCHS` with checked arithmetic (overflow
//!    fails closed).
//! 4. **Authenticated hybrid operator signature**: verifies both a strict
//!    Ed25519 signature and a FIPS 204 ML-DSA-65 post-quantum signature under
//!    [`crate::crypto::ctx::CROSS_DOMAIN_V1`] over the canonical
//!    domain-separated attestation digest binding the network, height, epoch,
//!    weave root, chunk commitment and endowment parameters.
//!
//! WIRING: unwired - external Arweave `SPoRA` recall adapter awaits `AdapterSpec`
//! variant binding in `external_tx` domain intake.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::core::hash::hash_fields_bytes;
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::pq;
use crate::crypto::primitives::verify_signature;
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

const ADAPTER_NAME: &str = "arweave-spora-recall-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;

const PAYLOAD_MAGIC: &[u8; 8] = b"BDLARA01";
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_CHUNK_ID_LEN: usize = 128;
const ED25519_PK_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
/// 30% contamination ceiling in basis points.
const CONTAMINATION_CAP_BPS: u128 = 3_000;
const BPS_DENOMINATOR: u128 = 10_000;
/// Minimum endowment sustenance in Arweave epochs (~2 weeks each).
const MIN_SUSTAINANCE_EPOCHS: u64 = 26;
const MAX_MERKLE_PROOF_DEPTH: usize = 64;

/// Arweave `SPoRA` storage attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArweaveSpOraEvidence {
    /// Protocol magic (`b"BDLARA01"`).
    pub magic: [u8; 8],
    /// Data chunk identifier (printable ASCII base64url Arweave chunk id).
    pub chunk_id: Vec<u8>,
    /// Canonical 32-byte digest of the stored recall chunk bytes.
    pub chunk_data_hash: [u8; 32],
    /// Arweave block height.
    pub block_height: u64,
    /// Current Arweave epoch.
    pub epoch: u64,
    /// Non-zero weave Merkle root at this height.
    pub weave_root: [u8; 32],
    /// Non-empty Merkle sibling path from chunk leaf to `weave_root`.
    pub merkle_proof: Vec<[u8; 32]>,
    /// Byte offset of the chunk within the weave (multiple of `chunk_size`).
    pub chunk_offset: u64,
    /// Non-zero chunk size in bytes.
    pub chunk_size: u64,
    /// Gross storage endowment balance in winston.
    pub gross_endowment: u128,
    /// Encumbered endowment committed to existing storage obligations.
    pub encumbered_endowment: u128,
    /// Current `SPoRA` storage rate in winston per byte per epoch.
    pub spora_rate: u128,
    /// Classical Ed25519 operator signature over [`Self::signing_digest`].
    pub operator_signature: Vec<u8>,
    /// Classical 32-byte Ed25519 operator public key.
    pub operator_key: Vec<u8>,
    /// Post-quantum FIPS 204 ML-DSA-65 operator signature over [`Self::signing_digest`].
    pub operator_pq_signature: Vec<u8>,
    /// Post-quantum FIPS 204 ML-DSA-65 operator public key.
    pub operator_pq_key: Vec<u8>,
}

/// Compute the canonical domain-separated leaf digest for a weave chunk.
#[must_use]
pub fn compute_weave_leaf(
    chunk_id: &[u8],
    chunk_data_hash: &Hash32,
    chunk_offset: u64,
    chunk_size: u64,
) -> Hash32 {
    let off = chunk_offset.to_le_bytes();
    let sz = chunk_size.to_le_bytes();
    hash_fields_bytes(&[
        b"BDLM_ARWEAVE_SPORA_V1",
        b"leaf",
        chunk_id,
        chunk_data_hash,
        &off,
        &sz,
    ])
}

/// Fold a leaf digest and sibling path using direction bits from `leaf_index`
/// with distinct internal-node domain separation.
#[must_use]
pub fn fold_weave_merkle_path(leaf: Hash32, leaf_index: u64, proof: &[Hash32]) -> Hash32 {
    let mut acc = leaf;
    for (depth, sibling) in proof.iter().enumerate() {
        let level = (depth as u32).to_le_bytes();
        let is_right = depth < 64 && ((leaf_index >> depth) & 1) == 1;
        let (left, right) = if is_right {
            (sibling, &acc)
        } else {
            (&acc, sibling)
        };
        acc = hash_fields_bytes(&[b"BDLM_ARWEAVE_SPORA_V1", b"node", &level, left, right]);
    }
    acc
}

fn wide_mul_u128(x: u128, y: u128) -> (u128, u128) {
    let mask = u128::from(u64::MAX);
    let x0 = x & mask;
    let x1 = x >> 64;
    let y0 = y & mask;
    let y1 = y >> 64;

    let p0 = x0 * y0;
    let p1 = x0 * y1;
    let p2 = x1 * y0;
    let p3 = x1 * y1;

    let mid = (p0 >> 64) + (p1 & mask) + (p2 & mask);
    let hi = p3 + (p1 >> 64) + (p2 >> 64) + (mid >> 64);
    let lo = (p0 & mask) | (mid << 64);
    (hi, lo)
}

impl ArweaveSpOraEvidence {
    /// Canonical domain-separated message signed by the operator's Ed25519 and
    /// ML-DSA-65 keys for `network`.
    #[must_use]
    pub fn signing_digest(&self, network: &str) -> Hash32 {
        let block_height = self.block_height.to_le_bytes();
        let epoch = self.epoch.to_le_bytes();
        let chunk_offset = self.chunk_offset.to_le_bytes();
        let chunk_size = self.chunk_size.to_le_bytes();
        let gross_endowment = self.gross_endowment.to_le_bytes();
        let encumbered_endowment = self.encumbered_endowment.to_le_bytes();
        let spora_rate = self.spora_rate.to_le_bytes();
        let mut fields: Vec<&[u8]> = vec![
            b"BDLM_ARWEAVE_SPORA_V1",
            b"attest",
            network.as_bytes(),
            &self.magic,
            &self.chunk_id,
            &self.chunk_data_hash,
            &block_height,
            &epoch,
            &self.weave_root,
            &chunk_offset,
            &chunk_size,
            &gross_endowment,
            &encumbered_endowment,
            &spora_rate,
            &self.operator_key,
            &self.operator_pq_key,
        ];
        for node in &self.merkle_proof {
            fields.push(node);
        }
        hash_fields_bytes(&fields)
    }

    /// Canonical domain-separated digest of the complete evidence envelope.
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        let signing = self.signing_digest("");
        hash_fields_bytes(&[
            b"BDLM_ARWEAVE_SPORA_V1",
            b"bundle",
            &signing,
            &self.operator_signature,
            &self.operator_pq_signature,
        ])
    }
}

fn validate_evidence_fields(ev: &ArweaveSpOraEvidence) -> Result<(), AdapterError> {
    if &ev.magic != PAYLOAD_MAGIC {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave evidence magic mismatch: expected {PAYLOAD_MAGIC:?}, got {:?}",
                ev.magic
            ),
        });
    }
    if ev.chunk_id.is_empty()
        || ev.chunk_id.len() > MAX_CHUNK_ID_LEN
        || !ev.chunk_id.iter().all(|b| b.is_ascii_graphic())
    {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave chunk_id invalid or length {} outside 1..={MAX_CHUNK_ID_LEN}",
                ev.chunk_id.len()
            ),
        });
    }
    if ev.chunk_data_hash == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "Arweave chunk_data_hash must be non-zero".into(),
        });
    }
    if ev.weave_root == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "Arweave weave_root must be non-zero".into(),
        });
    }
    if ev.chunk_size == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "Arweave chunk_size must be non-zero".into(),
        });
    }
    if !ev.chunk_offset.is_multiple_of(ev.chunk_size) {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave chunk_offset {} not aligned to chunk_size {}",
                ev.chunk_offset, ev.chunk_size
            ),
        });
    }
    if ev.merkle_proof.is_empty() || ev.merkle_proof.len() > MAX_MERKLE_PROOF_DEPTH {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave merkle_proof depth {} outside 1..={MAX_MERKLE_PROOF_DEPTH}",
                ev.merkle_proof.len()
            ),
        });
    }
    Ok(())
}

fn verify_weave_inclusion(ev: &ArweaveSpOraEvidence) -> Result<(), AdapterError> {
    let leaf = compute_weave_leaf(
        &ev.chunk_id,
        &ev.chunk_data_hash,
        ev.chunk_offset,
        ev.chunk_size,
    );
    let leaf_index = ev.chunk_offset / ev.chunk_size;
    if ev.merkle_proof.len() < 64 && (leaf_index >> ev.merkle_proof.len()) != 0 {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave leaf_index {leaf_index} exceeds 2^{} tree capacity",
                ev.merkle_proof.len()
            ),
        });
    }
    let derived = fold_weave_merkle_path(leaf, leaf_index, &ev.merkle_proof);
    if !bool::from(derived.ct_eq(&ev.weave_root)) {
        return Err(AdapterError::ConsensusRule {
            rule: "Arweave Merkle proof does not reconstruct weave_root".into(),
        });
    }
    Ok(())
}

fn validate_contamination(ev: &ArweaveSpOraEvidence) -> Result<u128, AdapterError> {
    if ev.encumbered_endowment > ev.gross_endowment {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave encumbered ({}) exceeds gross ({})",
                ev.encumbered_endowment, ev.gross_endowment
            ),
        });
    }
    if ev.gross_endowment > 0
        && wide_mul_u128(ev.encumbered_endowment, BPS_DENOMINATOR)
            > wide_mul_u128(ev.gross_endowment, CONTAMINATION_CAP_BPS)
    {
        return Err(AdapterError::ConsensusRule {
            rule: format!("Arweave contamination exceeds cap {CONTAMINATION_CAP_BPS} bps"),
        });
    }
    Ok(ev.gross_endowment.saturating_sub(ev.encumbered_endowment))
}

fn validate_endowment_solvency(ev: &ArweaveSpOraEvidence, free: u128) -> Result<(), AdapterError> {
    if ev.spora_rate == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "Arweave SPoRA rate is zero".into(),
        });
    }
    let sustain_cost = u128::from(ev.chunk_size)
        .checked_mul(ev.spora_rate)
        .and_then(|v| v.checked_mul(u128::from(MIN_SUSTAINANCE_EPOCHS)))
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Arweave sustenance cost overflows u128".into(),
        })?;
    if free < sustain_cost {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Arweave endowment insufficient: free={free}, need={sustain_cost} for {MIN_SUSTAINANCE_EPOCHS} epochs"
            ),
        });
    }
    Ok(())
}

fn verify_operator_signatures(
    ev: &ArweaveSpOraEvidence,
    network: &str,
    pinned_keys: Option<(&[u8; ED25519_PK_LEN], &[u8])>,
) -> Result<(), AdapterError> {
    let pk_arr: [u8; ED25519_PK_LEN] =
        ev.operator_key
            .as_slice()
            .try_into()
            .map_err(|_| AdapterError::Crypto {
                what: format!(
                    "Arweave operator Ed25519 key length {} != {ED25519_PK_LEN}",
                    ev.operator_key.len()
                ),
            })?;
    let sig_arr: [u8; ED25519_SIG_LEN] =
        ev.operator_signature
            .as_slice()
            .try_into()
            .map_err(|_| AdapterError::Crypto {
                what: format!(
                    "Arweave operator Ed25519 signature length {} != {ED25519_SIG_LEN}",
                    ev.operator_signature.len()
                ),
            })?;
    if let Some((expected_ed, expected_pq)) = pinned_keys {
        if !bool::from(pk_arr.ct_eq(expected_ed))
            || ev.operator_pq_key.len() != expected_pq.len()
            || !bool::from(ev.operator_pq_key.as_slice().ct_eq(expected_pq))
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Arweave operator key does not match pinned oracle anchor".into(),
            });
        }
    }
    pq::validate_public_key(SchemeId::ML_DSA_65, &ev.operator_pq_key).map_err(|e| {
        AdapterError::Crypto {
            what: format!("Arweave invalid ML-DSA-65 operator key: {e}"),
        }
    })?;

    let msg = ev.signing_digest(network);
    verify_signature(&msg, &sig_arr, &pk_arr).map_err(|e| AdapterError::Crypto {
        what: format!("Arweave operator Ed25519 signature verification failed: {e}"),
    })?;
    pq::verify(
        SchemeId::ML_DSA_65,
        &ev.operator_pq_key,
        &msg,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &ev.operator_pq_signature,
    )
    .map_err(|e| AdapterError::Crypto {
        what: format!("Arweave operator ML-DSA-65 signature verification failed: {e}"),
    })?;
    Ok(())
}

/// Arweave `SPoRA` / Recall-Weave permanent storage adapter.
#[derive(Debug, Clone)]
pub struct ArweaveSpOraAdapter {
    network: String,
    pinned_operator: Option<([u8; ED25519_PK_LEN], Vec<u8>)>,
}

impl ArweaveSpOraAdapter {
    /// Create a new adapter bound to the named Arweave network.
    #[must_use]
    pub fn new(network: impl Into<String>) -> Self {
        Self {
            network: network.into(),
            pinned_operator: None,
        }
    }

    /// Pin the expected hybrid operator keys (Ed25519 + ML-DSA-65) so unpinned
    /// self-signed storage claims fail closed.
    ///
    /// WIRING: consumed by operator-pinned weave intake and adversarial tests.
    #[must_use]
    pub fn with_pinned_operator(
        mut self,
        ed25519_pk: [u8; ED25519_PK_LEN],
        pq_pk: Vec<u8>,
    ) -> Self {
        self.pinned_operator = Some((ed25519_pk, pq_pk));
        self
    }

    /// Verify field bounds, Merkle weave inclusion, contamination ceiling,
    /// checked endowment solvency, and hybrid Ed25519 + ML-DSA-65 operator
    /// signatures, returning non-encumbered endowment in winston.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError`] if any structural, Merkle, solvency, or
    /// cryptographic signature check fails.
    pub fn verify_storage(&self, evidence: &ArweaveSpOraEvidence) -> Result<u128, AdapterError> {
        validate_evidence_fields(evidence)?;
        verify_weave_inclusion(evidence)?;
        let free = validate_contamination(evidence)?;
        validate_endowment_solvency(evidence, free)?;
        let pinned = self
            .pinned_operator
            .as_ref()
            .map(|(ed, pq_pk)| (ed, pq_pk.as_slice()));
        verify_operator_signatures(evidence, &self.network, pinned)?;
        Ok(free)
    }
}

impl ExternalFinalityAdapter for ArweaveSpOraAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            id: AdapterId::from_name(ADAPTER_NAME),
            name: ADAPTER_NAME.to_string(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "arweave-spora-recall".to_string(),
            finality_kind: FinalityKind::EconomicFinality,
            required_depth: 1,
            time_unit: TimeUnit::Height,
            trust_model: TrustModel::HonestMajority { set_size: 50 },
        }
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Arweave evidence_version {} != expected {EVIDENCE_VERSION}",
                    evidence.evidence_version
                ),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Arweave network mismatch: adapter={}, evidence={}",
                    self.network, evidence.network
                ),
            });
        }
        if evidence.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Arweave payload {} exceeds limit {MAX_PAYLOAD_BYTES}",
                    evidence.payload.len()
                ),
            });
        }
        let ev: ArweaveSpOraEvidence =
            serde_json::from_slice(&evidence.payload).map_err(|e| AdapterError::Malformed {
                offset: 0,
                reason: e.to_string(),
            })?;
        let free_endowment = self.verify_storage(&ev)?;

        if policy.min_depth > 1 {
            return Err(AdapterError::InsufficientDepth {
                observed: 1,
                required: policy.min_depth,
            });
        }

        if policy.max_age > 0 {
            if ev.block_height > policy.now {
                return Err(AdapterError::Stale {
                    age: ev.block_height.saturating_sub(policy.now),
                    max_age: policy.max_age,
                });
            }
            let age = policy.now.saturating_sub(ev.block_height);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let state_root = ev.weave_root;
        if policy.require_declared_match {
            if evidence.declared_height != ev.block_height {
                return Err(AdapterError::DeclarationMismatch {
                    field: "declared_height",
                });
            }
            if evidence.declared_root != state_root {
                return Err(AdapterError::DeclarationMismatch {
                    field: "declared_root",
                });
            }
        }

        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }

        let digest = ev.digest();
        let backing = SecurityBacking::SignatureSet {
            scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
            signers: 1,
            required: 1,
            total_weight: free_endowment,
            // External SPoRA operator attestations have no local Budlum
            // confiscation bond or BridgeEconomicGuard arm yet.
            slashable: false,
        };

        Ok(FinalityAttestation {
            adapter: self.descriptor().id,
            domain: DomainKey::from_parts(&self.descriptor().id, &evidence.network),
            height: ev.block_height,
            state_root,
            finalized_at: ev.block_height,
            time_unit: TimeUnit::Height,
            security: backing,
            evidence_digest: digest,
            adapter_version: ADAPTER_VERSION,
            evidence_version: EVIDENCE_VERSION,
            attested_block_hash: Some(state_root),
            attested_event_root: None,
            attested_tx_root: None,
        })
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let attestation = self.verify(evidence, policy)?;
        observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        Ok(attestation)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        vec![
            FaultProbe {
                name: "corrupt-payload-opening".to_string(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xFF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "wrong-evidence-version".to_string(),
                patch: BytePatch::EvidenceVersion {
                    value: EVIDENCE_VERSION + 1,
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "wrong-network".to_string(),
                patch: BytePatch::Network {
                    value: "arweave-wrongnet".to_string(),
                },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "corrupt-declared-root".to_string(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Any,
            },
            FaultProbe {
                name: "corrupt-declared-height".to_string(),
                patch: BytePatch::DeclaredHeight { value: 1 },
                expect: ExpectedRefusal::Any,
            },
        ]
    }
}

#[cfg(test)]
struct TestOperator {
    ed: crate::crypto::primitives::KeyPair,
    pq: crate::crypto::primitives::PqKeyPair,
}

#[cfg(test)]
impl TestOperator {
    fn generate() -> Self {
        Self {
            ed: crate::crypto::primitives::KeyPair::from_seed(&[0x47; 32]).expect("ed25519 seed"),
            pq: crate::crypto::primitives::PqKeyPair::generate(),
        }
    }

    fn sign(&self, network: &str, ev: &mut ArweaveSpOraEvidence) {
        ev.operator_key = self.ed.public_key_bytes().to_vec();
        ev.operator_pq_key = self.pq.public_key_bytes().to_vec();
        let msg = ev.signing_digest(network);
        ev.operator_signature = self.ed.sign(&msg).to_vec();
        ev.operator_pq_signature = self
            .pq
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg)
            .expect("mldsa65 sign");
    }
}

#[cfg(test)]
fn recompute_and_sign(network: &str, op: &TestOperator, ev: &mut ArweaveSpOraEvidence) {
    let leaf = compute_weave_leaf(
        &ev.chunk_id,
        &ev.chunk_data_hash,
        ev.chunk_offset,
        ev.chunk_size,
    );
    let idx = ev
        .chunk_offset
        .checked_div(ev.chunk_size)
        .unwrap_or_default();
    ev.weave_root = fold_weave_merkle_path(leaf, idx, &ev.merkle_proof);
    op.sign(network, ev);
}

#[cfg(test)]
fn sample_evidence_with_operator(network: &str) -> (ArweaveSpOraEvidence, TestOperator) {
    let op = TestOperator::generate();
    let chunk_id = b"arweave-chunk-abc123".to_vec();
    let chunk_data_hash = [0x5A; 32];
    let chunk_size = 256 * 1024;
    let chunk_offset = 262_144; // leaf_index = 1 (right child at depth 0)
    let merkle_proof = vec![[0x01; 32], [0x02; 32], [0x03; 32]];
    let mut ev = ArweaveSpOraEvidence {
        magic: *PAYLOAD_MAGIC,
        chunk_id,
        chunk_data_hash,
        block_height: 1_200_000,
        epoch: 5_000,
        weave_root: [0u8; 32],
        merkle_proof,
        chunk_offset,
        chunk_size,
        gross_endowment: 10_000_000_000_000,
        encumbered_endowment: 1_000_000_000_000,
        spora_rate: 1_000,
        operator_signature: Vec::new(),
        operator_key: Vec::new(),
        operator_pq_signature: Vec::new(),
        operator_pq_key: Vec::new(),
    };
    recompute_and_sign(network, &op, &mut ev);
    (ev, op)
}

#[cfg(test)]
pub(crate) fn encode_arweave_spora_evidence(ev: &ArweaveSpOraEvidence) -> Vec<u8> {
    serde_json::to_vec(ev).expect("arweave evidence serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::facts::CryptoFacts;

    #[test]
    fn valid_merkle_and_hybrid_signed_evidence_verifies() {
        let (ev, op) = sample_evidence_with_operator("arweave-mainnet");
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet")
            .with_pinned_operator(op.ed.public_key_bytes(), op.pq.public_key_bytes().to_vec());
        let free = adapter.verify_storage(&ev).expect("valid evidence passes");
        assert_eq!(free, 9_000_000_000_000);

        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "arweave-mainnet".to_string(),
            payload: encode_arweave_spora_evidence(&ev),
            declared_height: ev.block_height,
            declared_root: ev.weave_root,
            submitter: crate::core::address::Address([0; 32]),
        };
        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&raw, &VerificationPolicy::strict(0), &mut facts)
            .expect("full verify");
        assert_eq!(att.state_root, ev.weave_root);
        assert_eq!(att.height, 1_200_000);
        assert!(facts
            .observed()
            .iter()
            .any(|c| c.scheme == ObservedScheme::Scheme(SchemeId::ED25519)));
        assert!(facts
            .observed()
            .iter()
            .any(|c| c.scheme == ObservedScheme::Scheme(SchemeId::ML_DSA_65)));
    }

    #[test]
    fn tampered_merkle_path_or_chunk_offset_is_refused_even_when_resigned() {
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet");
        let (mut bad_sibling, op) = sample_evidence_with_operator("arweave-mainnet");
        bad_sibling.merkle_proof[1][0] ^= 0x01;
        op.sign("arweave-mainnet", &mut bad_sibling);
        assert!(
            matches!(adapter.verify_storage(&bad_sibling).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("Merkle"))
        );

        let (mut swapped_branch, op2) = sample_evidence_with_operator("arweave-mainnet");
        swapped_branch.chunk_offset = 0; // flips direction bit 0
        op2.sign("arweave-mainnet", &mut swapped_branch);
        assert!(
            matches!(adapter.verify_storage(&swapped_branch).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("Merkle"))
        );
    }

    #[test]
    fn forged_ed25519_pq_or_unpinned_operator_signature_is_refused() {
        let (ev, op) = sample_evidence_with_operator("arweave-mainnet");
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet")
            .with_pinned_operator(op.ed.public_key_bytes(), op.pq.public_key_bytes().to_vec());

        let mut bad_ed = ev.clone();
        bad_ed.operator_signature[4] ^= 0x40;
        assert!(matches!(
            adapter.verify_storage(&bad_ed).unwrap_err(),
            AdapterError::Crypto { .. }
        ));

        let mut bad_pq = ev;
        bad_pq.operator_pq_signature[9] ^= 0x20;
        assert!(matches!(
            adapter.verify_storage(&bad_pq).unwrap_err(),
            AdapterError::Crypto { .. }
        ));

        let (foreign, _) = sample_evidence_with_operator("arweave-mainnet");
        assert!(
            matches!(adapter.verify_storage(&foreign).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("pinned"))
        );
    }

    #[test]
    fn contamination_solvency_overflow_and_declared_mismatches_fail_closed() {
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet");

        let (mut contam, op) = sample_evidence_with_operator("arweave-mainnet");
        contam.encumbered_endowment = 3_000_000_000_001;
        op.sign("arweave-mainnet", &mut contam);
        assert!(
            matches!(adapter.verify_storage(&contam).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("contamination"))
        );

        let (mut insolvent, op) = sample_evidence_with_operator("arweave-mainnet");
        insolvent.gross_endowment = 100;
        insolvent.encumbered_endowment = 0;
        op.sign("arweave-mainnet", &mut insolvent);
        assert!(
            matches!(adapter.verify_storage(&insolvent).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("insufficient"))
        );

        let (mut overflow, op) = sample_evidence_with_operator("arweave-mainnet");
        overflow.spora_rate = u128::MAX;
        overflow.gross_endowment = u128::MAX;
        overflow.encumbered_endowment = 0;
        op.sign("arweave-mainnet", &mut overflow);
        assert!(
            matches!(adapter.verify_storage(&overflow).unwrap_err(), AdapterError::ConsensusRule { rule } if rule.contains("overflow"))
        );

        let (ev, _) = sample_evidence_with_operator("arweave-mainnet");
        let raw_bad_height = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "arweave-mainnet".to_string(),
            payload: encode_arweave_spora_evidence(&ev),
            declared_height: ev.block_height + 1,
            declared_root: ev.weave_root,
            submitter: crate::core::address::Address([0; 32]),
        };
        assert!(matches!(
            adapter.verify(&raw_bad_height, &VerificationPolicy::strict(0)),
            Err(AdapterError::DeclarationMismatch {
                field: "declared_height"
            })
        ));

        let mut stale_policy = VerificationPolicy::strict(ev.block_height + 50);
        stale_policy.max_age = 20;
        let raw_valid = RawConsensusEvidence {
            declared_height: ev.block_height,
            ..raw_bad_height
        };
        assert!(matches!(
            adapter.verify(&raw_valid, &stale_policy),
            Err(AdapterError::Stale {
                age: 50,
                max_age: 20
            })
        ));

        let unbonded_policy = VerificationPolicy::strict(0);
        let att = adapter
            .verify(&raw_valid, &unbonded_policy)
            .expect("valid SPoRA recall evidence verifies when slashability is not required");
        assert!(
            matches!(
                att.security,
                SecurityBacking::SignatureSet {
                    slashable: false,
                    ..
                }
            ),
            "unbonded external SPoRA operator signature without a local Budlum confiscation arm must report slashable=false"
        );
        let mut slash_policy = unbonded_policy;
        slash_policy.require_slashable = true;
        assert!(
            matches!(
                adapter.verify(&raw_valid, &slash_policy),
                Err(AdapterError::UnslashableBacking)
            ),
            "require_slashable=true must fail closed with UnslashableBacking"
        );
    }

    #[test]
    fn future_block_height_is_refused_when_max_age_is_enforced() {
        let (ev, _op) = sample_evidence_with_operator("arweave-mainnet");
        let adapter = ArweaveSpOraAdapter::new("arweave-mainnet");
        let raw = RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: EVIDENCE_VERSION,
            network: "arweave-mainnet".to_string(),
            payload: encode_arweave_spora_evidence(&ev),
            declared_height: ev.block_height,
            declared_root: ev.weave_root,
            submitter: crate::core::address::Address([0; 32]),
        };
        let mut future_policy = VerificationPolicy::strict(ev.block_height.saturating_sub(5));
        future_policy.max_age = 20;
        assert!(
            matches!(
                adapter.verify(&raw, &future_policy),
                Err(AdapterError::Stale {
                    age: 5,
                    max_age: 20
                })
            ),
            "future-dated Arweave block_height must fail closed when policy.max_age > 0"
        );
    }
}
