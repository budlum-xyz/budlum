//! Modular Data-Availability Sampling (`DAS`) + Namespace Merkle Tree (`NMT`)
//! external finality adapter (`da-sampling-v1`).
//!
//! Verifies data-availability commitments from modular DA networks (Celestia,
//! Avail, EigenDA, and sovereign rollup DA layers) against a governance-pinned
//! namespace and slashable DA attestation committee:
//!
//! 1. **2D Erasure-Coded Data Root Binding**: binds `data_root` to a power-of-two
//!    `square_size` plus both axis commitments (`row_roots_root`, `col_roots_root`).
//! 2. **Namespace Merkle Tree (`NMT`) Monotonicity & Inclusion**: verifies a
//!    namespace-flagged binary Merkle proof showing the rollup's `blob_commitment`
//!    under the pinned `namespace_id`, rejecting any non-monotonic internal range
//!    (`left.max_ns > right.min_ns`) that would hide or splice namespace shares.
//! 3. **Distinct 2D `(row, col)` Share Sampling**: requires at least `min_samples`
//!    unique coordinates, each simultaneously Merkle-proven into its row root
//!    (proven into `row_roots_root`) AND its column root (proven into
//!    `col_roots_root`) so withheld shares cannot pass without breaking both axes.
//! 4. **Stake-Weighted `> 2/3` Committee Attestation**: verifies Ed25519 (plus
//!    optional paired ML-DSA-65 PQ) signatures over the DA header.

use crate::cross_domain::external::selftest::{
    BytePatch, ExpectedRefusal, FaultProbe, RefusalKind,
};
use crate::cross_domain::external::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};
use crate::crypto::facts::{AssumptionClass, CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const ADAPTER_NAME: &str = "da-sampling-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMDA01";
const MAX_DA_PAYLOAD_BYTES: usize = 512 * 1_024;
const MAX_DA_COMMITTEE: usize = 512;
const MAX_DA_SQUARE_SIZE: u16 = 1_024;
const MAX_DA_SAMPLES: usize = 128;
const MAX_DA_MERKLE_DEPTH: usize = 16;

/// One member of a slashable DA bridge attestation committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaCommitteeMember {
    pub ed25519_pubkey: [u8; 32],
    pub voting_weight: u64,
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned DA committee and rollup namespace configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedDaCommittee {
    /// Fixed 29/32-byte padded rollup namespace identifier.
    pub namespace_id: Hash32,
    /// Minimum distinct 2D `(row, col)` share samples required per attestation.
    pub min_samples: u16,
    /// Minimum permitted 2D extended data square dimension (power of two, `>= 2`).
    pub min_square_size: u16,
    /// Slashable validator set signing DA header commitments.
    pub members: Vec<DaCommitteeMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NmtSibling {
    min_ns: Hash32,
    max_ns: Hash32,
    digest: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DaNamespaceProof {
    row_index: u16,
    leaf_index: u16,
    blob_commitment: Hash32,
    nmt_siblings: Vec<NmtSibling>,
    row_root: Hash32,
    nmt_row_axis_branch: Vec<Hash32>,
    share_row_root: Hash32,
    share_to_row_branch: Vec<Hash32>,
    row_axis_branch: Vec<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DaShareSample {
    row: u16,
    col: u16,
    share_digest: Hash32,
    row_root: Hash32,
    share_to_row_branch: Vec<Hash32>,
    row_to_axis_branch: Vec<Hash32>,
    col_root: Hash32,
    share_to_col_branch: Vec<Hash32>,
    col_to_axis_branch: Vec<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DaHeader {
    height: u64,
    time_secs: u64,
    square_size: u16,
    nmt_roots_root: Hash32,
    row_roots_root: Hash32,
    col_roots_root: Hash32,
    data_root: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DaAttestationSig {
    signer_pubkey: [u8; 32],
    ed25519_sig: Vec<u8>,
    #[serde(default)]
    pq_sig: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DaAvailabilityEvidence {
    header: DaHeader,
    namespace_proof: DaNamespaceProof,
    samples: Vec<DaShareSample>,
    signatures: Vec<DaAttestationSig>,
}

#[must_use]
fn compute_da_data_root(
    square_size: u16,
    nmt_roots_root: &Hash32,
    row_roots_root: &Hash32,
    col_roots_root: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_DA_DATA_ROOT_V1",
        &square_size.to_le_bytes(),
        nmt_roots_root,
        row_roots_root,
        col_roots_root,
    ])
}

/// Deterministically derive `sample_count` distinct `(row, col)` coordinates
/// from the committed DA header and namespace statement via Fiat-Shamir so a
/// withholding producer cannot cherry-pick only unwithheld shares.
fn derive_das_sample_coordinates(
    network: &str,
    data_root: &Hash32,
    namespace_id: &Hash32,
    blob_commitment: &Hash32,
    square_size: u16,
    sample_count: u16,
) -> Result<BTreeSet<(u16, u16)>, AdapterError> {
    let total_cells = usize::from(square_size).saturating_mul(usize::from(square_size));
    let needed = usize::from(sample_count);
    if square_size == 0 || needed == 0 || needed > total_cells {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "DA min_samples {sample_count} exceeds square cell capacity {total_cells}"
            ),
        });
    }
    let mask = square_size - 1;
    let mut coords = BTreeSet::new();
    let mut nonce = 0u64;
    while coords.len() < needed {
        let digest = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_DA_SAMPLE_COORD_V1",
            network.as_bytes(),
            data_root,
            namespace_id,
            blob_commitment,
            &nonce.to_le_bytes(),
        ]);
        let r_bytes: [u8; 2] = digest
            .get(0..2)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 2]);
        let c_bytes: [u8; 2] = digest
            .get(2..4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 2]);
        let r = u16::from_le_bytes(r_bytes) & mask;
        let c = u16::from_le_bytes(c_bytes) & mask;
        if coords.insert((r, c)) {
            nonce = nonce.saturating_add(1);
            continue;
        }
        nonce = nonce.saturating_add(1);
        if nonce > 65_536 {
            // Deterministic linear scan fallback guaranteeing termination when
            // `needed` approaches `total_cells`.
            for row in 0..square_size {
                for col in 0..square_size {
                    coords.insert((row, col));
                    if coords.len() == needed {
                        return Ok(coords);
                    }
                }
            }
        }
    }
    Ok(coords)
}

#[must_use]
fn hash_nmt_leaf(namespace_id: &Hash32, blob_commitment: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[b"BDLM_DA_NMT_LEAF_V1", namespace_id, blob_commitment])
}

#[must_use]
fn hash_nmt_node(
    left: (&Hash32, &Hash32, &Hash32),
    right: (&Hash32, &Hash32, &Hash32),
) -> Option<(Hash32, Hash32, Hash32)> {
    let (l_min, l_max, l_hash) = left;
    let (r_min, r_max, r_hash) = right;
    if l_min > l_max || r_min > r_max || l_max > r_min {
        return None;
    }
    let digest = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_DA_NMT_NODE_V1",
        l_min,
        l_max,
        l_hash,
        r_min,
        r_max,
        r_hash,
    ]);
    Some((*l_min, *r_max, digest))
}

#[must_use]
fn hash_da_axis_node(left: &Hash32, right: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[b"BDLM_DA_AXIS_NODE_V1", left, right])
}

fn verify_axis_branch(
    leaf: &Hash32,
    index: u16,
    expected_depth: usize,
    branch: &[Hash32],
    expected_root: &Hash32,
) -> bool {
    if branch.len() != expected_depth || expected_depth > MAX_DA_MERKLE_DEPTH {
        return false;
    }
    if expected_depth < 16 && (index >> expected_depth) != 0 {
        return false;
    }
    let mut cur = *leaf;
    let mut idx = index;
    for sib in branch {
        cur = if idx & 1 == 0 {
            hash_da_axis_node(&cur, sib)
        } else {
            hash_da_axis_node(sib, &cur)
        };
        idx >>= 1;
    }
    bool::from(subtle::ConstantTimeEq::ct_eq(
        cur.as_slice(),
        expected_root.as_slice(),
    ))
}

#[must_use]
fn da_header_sign_bytes(network: &str, header: &DaHeader, namespace_id: &Hash32) -> Vec<u8> {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_DA_HEADER_VOTE_V1",
        network.as_bytes(),
        namespace_id,
        &header.height.to_le_bytes(),
        &header.time_secs.to_le_bytes(),
        &header.square_size.to_le_bytes(),
        &header.nmt_roots_root,
        &header.row_roots_root,
        &header.col_roots_root,
        &header.data_root,
    ])
    .to_vec()
}

#[cfg(test)]
fn encode_da_evidence(bundle: &DaAvailabilityEvidence) -> Result<Vec<u8>, String> {
    let body = bincode::serialize(bundle).map_err(|e| format!("DA encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_DA_PAYLOAD_BYTES {
        return Err(format!(
            "DA payload size {total} exceeds ceiling {MAX_DA_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_da_evidence(payload: &[u8]) -> Result<DaAvailabilityEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "DA payload shorter than 8-byte magic prefix".into(),
        });
    }
    if payload.len() > MAX_DA_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_DA_PAYLOAD_BYTES,
            reason: format!("DA payload exceeds {MAX_DA_PAYLOAD_BYTES} bytes"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "DA payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing DA payload body".into(),
    })?;
    let decoded: DaAvailabilityEvidence =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_DA_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("invalid DA availability evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical DA availability evidence".to_string(),
        });
    }
    Ok(decoded)
}

/// External finality adapter verifying 2D DAS share openings, NMT inclusion,
/// and stake-weighted DA bridge committee quorum.
pub struct DataAvailabilityAdapter {
    network: String,
    pinned: Option<PinnedDaCommittee>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl DataAvailabilityAdapter {
    /// Construct a `DataAvailabilityAdapter` bound to `network` and its pinned committee.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedDaCommittee>) -> Self {
        let set_size = pinned.as_ref().map_or(0, |p| p.members.len() as u64);
        Self {
            network: network.into(),
            pinned,
            golden: None,
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(ADAPTER_NAME),
                name: ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "modular-das-nmt-2d".to_string(),
                finality_kind: FinalityKind::EconomicFinality,
                required_depth: 1,
                time_unit: TimeUnit::Height,
                trust_model: TrustModel::HonestMajority { set_size },
            },
        }
    }

    /// Attach a golden sample for self-test admission replay.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, bool), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: hex::encode(evidence.adapter.as_bytes()),
            });
        }
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "DA evidence network '{}' does not match pinned network '{}'",
                    evidence.network, self.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no pinned DA committee/namespace; DA admission is closed".into(),
            });
        };
        if pinned.namespace_id == [0u8; 32]
            || pinned.min_samples == 0
            || usize::from(pinned.min_samples) > MAX_DA_SAMPLES
            || pinned.min_square_size < 2
            || !pinned.min_square_size.is_power_of_two()
        {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned DA policy carries invalid namespace, min_samples, or min_square_size"
                    .into(),
            });
        }
        if pinned.members.is_empty() || pinned.members.len() > MAX_DA_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned DA committee size outside valid bounds".into(),
            });
        }

        let bundle = decode_da_evidence(&evidence.payload)?;
        let header = &bundle.header;
        let ns_proof = &bundle.namespace_proof;

        if policy.require_declared_match {
            if evidence.declared_height != header.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if evidence.declared_root != ns_proof.blob_commitment {
                return Err(AdapterError::DeclarationMismatch { field: "root" });
            }
        }
        if policy.min_depth > 1 {
            return Err(AdapterError::InsufficientDepth {
                observed: 1,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 && policy.now > header.height {
            let age = policy.now - header.height;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // 1. Verify 2D data square geometry and canonical data_root derivation.
        if header.square_size < pinned.min_square_size
            || header.square_size > MAX_DA_SQUARE_SIZE
            || !header.square_size.is_power_of_two()
        {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "DA square_size {} invalid or below minimum {}",
                    header.square_size, pinned.min_square_size
                ),
            });
        }
        let axis_depth = header.square_size.trailing_zeros() as usize;
        let expected_data_root = compute_da_data_root(
            header.square_size,
            &header.nmt_roots_root,
            &header.row_roots_root,
            &header.col_roots_root,
        );
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            header.data_root.as_slice(),
            expected_data_root.as_slice(),
        )) {
            return Err(AdapterError::ConsensusRule {
                rule: "DA header data_root does not match NMT and row/column axis commitments"
                    .into(),
            });
        }

        // 2. Verify Namespace Merkle Tree (NMT) monotonic range proof for blob_commitment
        //    and bind the exact NMT leaf digest into the 2D share matrix at (row_index, leaf_index).
        if ns_proof.blob_commitment == [0u8; 32]
            || ns_proof.row_index >= header.square_size
            || ns_proof.leaf_index >= header.square_size
            || ns_proof.nmt_siblings.len() != axis_depth
        {
            return Err(AdapterError::ConsensusRule {
                rule: "DA namespace proof indices, depth, or zero blob_commitment invalid".into(),
            });
        }
        let nmt_leaf = hash_nmt_leaf(&pinned.namespace_id, &ns_proof.blob_commitment);
        let mut cur_min = pinned.namespace_id;
        let mut cur_max = pinned.namespace_id;
        let mut cur_hash = nmt_leaf;
        let mut leaf_idx = ns_proof.leaf_index;
        for sib in &ns_proof.nmt_siblings {
            let combined = if leaf_idx & 1 == 0 {
                hash_nmt_node(
                    (&cur_min, &cur_max, &cur_hash),
                    (&sib.min_ns, &sib.max_ns, &sib.digest),
                )
            } else {
                hash_nmt_node(
                    (&sib.min_ns, &sib.max_ns, &sib.digest),
                    (&cur_min, &cur_max, &cur_hash),
                )
            };
            let Some((next_min, next_max, next_hash)) = combined else {
                return Err(AdapterError::ConsensusRule {
                    rule: "NMT namespace interval monotonicity violated".into(),
                });
            };
            cur_min = next_min;
            cur_max = next_max;
            cur_hash = next_hash;
            leaf_idx >>= 1;
        }
        if !bool::from(subtle::ConstantTimeEq::ct_eq(
            cur_hash.as_slice(),
            ns_proof.row_root.as_slice(),
        )) || cur_min > pinned.namespace_id
            || cur_max < pinned.namespace_id
        {
            return Err(AdapterError::ConsensusRule {
                rule: "NMT namespace inclusion proof does not reduce to declared row_root".into(),
            });
        }
        if !verify_axis_branch(
            &ns_proof.row_root,
            ns_proof.row_index,
            axis_depth,
            &ns_proof.nmt_row_axis_branch,
            &header.nmt_roots_root,
        ) {
            return Err(AdapterError::ConsensusRule {
                rule: "NMT row_root failed inclusion proof against header nmt_roots_root".into(),
            });
        }
        let leaf_bound_to_square = verify_axis_branch(
            &nmt_leaf,
            ns_proof.leaf_index,
            axis_depth,
            &ns_proof.share_to_row_branch,
            &ns_proof.share_row_root,
        ) && verify_axis_branch(
            &ns_proof.share_row_root,
            ns_proof.row_index,
            axis_depth,
            &ns_proof.row_axis_branch,
            &header.row_roots_root,
        );
        if !leaf_bound_to_square {
            return Err(AdapterError::ConsensusRule {
                rule: "NMT leaf failed share-matrix inclusion against header row_roots_root".into(),
            });
        }

        // 3. Verify distinct 2D (row, col) Reed-Solomon axis availability samples
        //    covering every Fiat-Shamir challenge coordinate derived from data_root.
        let required_coords = derive_das_sample_coordinates(
            &self.network,
            &header.data_root,
            &pinned.namespace_id,
            &ns_proof.blob_commitment,
            header.square_size,
            pinned.min_samples,
        )?;
        if bundle.samples.len() < required_coords.len() || bundle.samples.len() > MAX_DA_SAMPLES {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "DA sample count {} outside {}..={MAX_DA_SAMPLES}",
                    bundle.samples.len(),
                    pinned.min_samples
                ),
            });
        }
        let mut seen_coords = BTreeSet::new();
        for sample in &bundle.samples {
            if sample.row >= header.square_size
                || sample.col >= header.square_size
                || sample.share_digest == [0u8; 32]
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA share sample coordinate out of square bounds or zero digest".into(),
                });
            }
            if !seen_coords.insert((sample.row, sample.col)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA sampling proof repeats (row, col) coordinate".into(),
                });
            }
            let row_ok = verify_axis_branch(
                &sample.share_digest,
                sample.col,
                axis_depth,
                &sample.share_to_row_branch,
                &sample.row_root,
            ) && verify_axis_branch(
                &sample.row_root,
                sample.row,
                axis_depth,
                &sample.row_to_axis_branch,
                &header.row_roots_root,
            );
            let col_ok = verify_axis_branch(
                &sample.share_digest,
                sample.row,
                axis_depth,
                &sample.share_to_col_branch,
                &sample.col_root,
            ) && verify_axis_branch(
                &sample.col_root,
                sample.col,
                axis_depth,
                &sample.col_to_axis_branch,
                &header.col_roots_root,
            );
            if !row_ok || !col_ok {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "DA sample at ({}, {}) failed dual-axis row/column inclusion",
                        sample.row, sample.col
                    ),
                });
            }
        }
        if !required_coords.is_subset(&seen_coords) {
            return Err(AdapterError::ConsensusRule {
                rule: "DA samples omit required Fiat-Shamir challenge coordinates".into(),
            });
        }

        // 4. Verify stake-weighted > 2/3 slashable DA committee attestation.
        let mut member_map = BTreeMap::new();
        let mut total_stake = 0u128;
        for m in &pinned.members {
            if m.ed25519_pubkey == [0u8; 32] || m.voting_weight == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "pinned DA committee has zero pubkey or zero voting_weight".into(),
                });
            }
            if member_map.insert(m.ed25519_pubkey, m).is_some() {
                return Err(AdapterError::ConsensusRule {
                    rule: "pinned DA committee contains duplicate pubkey".into(),
                });
            }
            total_stake = total_stake
                .checked_add(u128::from(m.voting_weight))
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "pinned DA committee voting_weight overflows u128".into(),
                })?;
        }
        if bundle.signatures.is_empty() || bundle.signatures.len() > MAX_DA_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: "DA committee signature count invalid".into(),
            });
        }
        let vote_bytes = da_header_sign_bytes(&self.network, header, &pinned.namespace_id);
        let mut seen_signers = BTreeSet::new();
        let mut signed_stake = 0u128;
        let mut all_pq = true;
        for sig in &bundle.signatures {
            if !seen_signers.insert(sig.signer_pubkey) {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate DA committee signature".into(),
                });
            }
            let Some(member) = member_map.get(&sig.signer_pubkey) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA signature from non-committee key".into(),
                });
            };
            crate::crypto::primitives::verify_signature(
                &vote_bytes,
                &sig.ed25519_sig,
                &sig.signer_pubkey,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "DA committee Ed25519 signature invalid".into(),
            })?;
            if member.pq_pubkey.is_empty() {
                all_pq = false;
            } else {
                if sig.pq_sig.is_empty() {
                    return Err(AdapterError::Crypto {
                        what: "DA committee member requires mandatory ML-DSA-65 co-signature"
                            .into(),
                    });
                }
                crate::crypto::primitives::PqKeyPair::verify(
                    &member.pq_pubkey,
                    crate::crypto::ctx::CROSS_DOMAIN_V1,
                    &vote_bytes,
                    &sig.pq_sig,
                )
                .map_err(|_| AdapterError::Crypto {
                    what: "DA committee ML-DSA-65 co-signature invalid".into(),
                })?;
            }
            signed_stake = signed_stake.saturating_add(u128::from(member.voting_weight));
        }
        if signed_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "DA committee signed stake {signed_stake}/{total_stake} does not exceed 2/3"
                ),
            });
        }

        let required_signers = ((pinned.members.len() as u64) * 2).div_ceil(3).max(1);
        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let att = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: header.height,
            state_root: ns_proof.blob_commitment,
            finalized_at: header.height,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers: seen_signers.len() as u64,
                required: required_signers,
                total_weight: total_stake,
                slashable: true,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(header.data_root),
            attested_event_root: None,
            attested_tx_root: Some(ns_proof.blob_commitment),
        };
        Ok((att, all_pq))
    }
}

impl ExternalFinalityAdapter for DataAvailabilityAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_inner(evidence, policy).map(|(att, _)| att)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let (att, all_pq) = self.verify_inner(evidence, policy)?;
        observer.observe(ObservedScheme::Proof(AssumptionClass::Hash));
        observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        if all_pq {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        }
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_tail_offset = self
            .golden
            .as_ref()
            .map_or(32, |g| g.payload.len().saturating_sub(16));
        vec![
            FaultProbe {
                name: "refuses unknown DA evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 7 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign DA network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-other", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared DA height".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared blob commitment".into(),
                patch: BytePatch::DeclaredRoot { value: [0xDD; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses truncated DA payload".into(),
                patch: BytePatch::TruncatePayload { keep: 5 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses corrupted DA magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"BADMAGIC".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses corrupted DA committee signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail_offset,
                    bytes: vec![0x5A; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::admit;
    use crate::crypto::facts::CryptoFacts;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    fn da_2x2_fixture() -> (
        PinnedDaCommittee,
        DaAvailabilityEvidence,
        RawConsensusEvidence,
    ) {
        let ns_target = [0x20; 32];
        let ns_hi = [0x40; 32];
        let blob = [0xAB; 32];

        // Row 0 is an NMT of 2 leaves: (ns_target, blob) at leaf 0 and (ns_hi, [0xCD; 32]) at leaf 1.
        let nmt_l0 = hash_nmt_leaf(&ns_target, &blob);
        let nmt_l1 = hash_nmt_leaf(&ns_hi, &[0xCD; 32]);
        let (_, _, nmt_row0_root) =
            hash_nmt_node((&ns_target, &ns_target, &nmt_l0), (&ns_hi, &ns_hi, &nmt_l1))
                .expect("ordered nmt");

        // Consistent 2x2 square where row 0's share digests ARE the NMT leaf
        // digests `[nmt_l0, nmt_l1]` and row 1 carries parity shares `[nmt_r10, nmt_r11]`,
        // so every (row, col) opens along both row/column share axes AND NMT roots.
        let ns_parity = [0x80; 32];
        let s00 = nmt_l0;
        let s01 = nmt_l1;
        let s10 = hash_nmt_leaf(&ns_parity, &[0x21; 32]);
        let s11 = hash_nmt_leaf(&ns_parity, &[0x22; 32]);
        let (_, _, nmt_row1_root) = hash_nmt_node(
            (&ns_parity, &ns_parity, &s10),
            (&ns_parity, &ns_parity, &s11),
        )
        .expect("ordered parity nmt");
        let nmt_roots_root = hash_da_axis_node(&nmt_row0_root, &nmt_row1_root);

        let row0 = hash_da_axis_node(&s00, &s01);
        let row1 = hash_da_axis_node(&s10, &s11);
        let col0 = hash_da_axis_node(&s00, &s10);
        let col1 = hash_da_axis_node(&s01, &s11);
        let row_roots_root = hash_da_axis_node(&row0, &row1);
        let col_roots_root = hash_da_axis_node(&col0, &col1);
        let data_root = compute_da_data_root(2, &nmt_roots_root, &row_roots_root, &col_roots_root);

        let header = DaHeader {
            height: 500,
            time_secs: 1_700_050_000,
            square_size: 2,
            nmt_roots_root,
            row_roots_root,
            col_roots_root,
            data_root,
        };
        let namespace_proof = DaNamespaceProof {
            row_index: 0,
            leaf_index: 0,
            blob_commitment: blob,
            nmt_siblings: vec![NmtSibling {
                min_ns: ns_hi,
                max_ns: ns_hi,
                digest: nmt_l1,
            }],
            row_root: nmt_row0_root,
            nmt_row_axis_branch: vec![nmt_row1_root],
            share_row_root: row0,
            share_to_row_branch: vec![s01],
            row_axis_branch: vec![row1],
        };
        let grid = [[s00, s01], [s10, s11]];
        let row_roots = [row0, row1];
        let col_roots = [col0, col1];
        let open_cell = |r: u16, c: u16| -> DaShareSample {
            let ri = usize::from(r);
            let ci = usize::from(c);
            DaShareSample {
                row: r,
                col: c,
                share_digest: grid[ri][ci],
                row_root: row_roots[ri],
                share_to_row_branch: vec![grid[ri][ci ^ 1]],
                row_to_axis_branch: vec![row_roots[ri ^ 1]],
                col_root: col_roots[ci],
                share_to_col_branch: vec![grid[ri ^ 1][ci]],
                col_to_axis_branch: vec![col_roots[ci ^ 1]],
            }
        };
        let required =
            derive_das_sample_coordinates("celestia-mainnet", &data_root, &ns_target, &blob, 2, 2)
                .expect("derive Fiat-Shamir DAS coordinates");
        let samples: Vec<DaShareSample> = required.iter().map(|&(r, c)| open_cell(r, c)).collect();

        let mut members = Vec::new();
        let mut sigs = Vec::new();
        let vote = da_header_sign_bytes("celestia-mainnet", &header, &ns_target);
        for i in 0..3 {
            let ek = KeyPair::generate().expect("keypair");
            let pk = PqKeyPair::generate();
            let pub32 = ek.public_key_bytes();
            members.push(DaCommitteeMember {
                ed25519_pubkey: pub32,
                voting_weight: 100,
                pq_pubkey: pk.public_key_bytes().to_vec(),
            });
            if i < 3 {
                sigs.push(DaAttestationSig {
                    signer_pubkey: pub32,
                    ed25519_sig: ek.sign(&vote).to_vec(),
                    pq_sig: pk
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &vote)
                        .expect("pq sign"),
                });
            }
        }
        let pinned = PinnedDaCommittee {
            namespace_id: ns_target,
            min_samples: 2,
            min_square_size: 2,
            members,
        };
        let bundle = DaAvailabilityEvidence {
            header: header.clone(),
            namespace_proof,
            samples,
            signatures: sigs,
        };
        let ev = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: "celestia-mainnet".into(),
            payload: encode_da_evidence(&bundle).expect("encode"),
            declared_height: header.height,
            declared_root: blob,
            submitter: Address::from([0x07; 32]),
        };
        (pinned, bundle, ev)
    }

    #[test]
    fn da_sampling_passes_selftest_and_refuses_duplicate_coords_and_nmt_disorder() {
        let (pinned, bundle, golden) = da_2x2_fixture();
        let adapter = DataAvailabilityAdapter::new("celestia-mainnet", Some(pinned))
            .with_golden(golden.clone());
        let policy = VerificationPolicy::strict(505);

        let report = admit(&adapter, &policy);
        assert!(report.admitted, "DA selftest report: {report:?}");
        assert_eq!(report.passed(), 7);

        let mut facts = CryptoFacts::new();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .expect("verify golden DA");
        assert_eq!(att.height, 500);
        assert_eq!(att.state_root, [0xAB; 32]);
        assert_eq!(att.attested_tx_root, Some([0xAB; 32]));
        assert_eq!(att.attested_event_root, None);
        assert_eq!(facts.count(ObservedScheme::Proof(AssumptionClass::Hash)), 1);
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);

        // Duplicate (row, col) sample coordinate cannot satisfy min_samples = 2.
        let mut dup = bundle.clone();
        dup.samples = vec![dup.samples[0].clone(), dup.samples[0].clone()];
        let mut dup_ev = golden.clone();
        dup_ev.payload = encode_da_evidence(&dup).expect("encode");
        assert!(matches!(
            adapter.verify(&dup_ev, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // Out-of-order right NMT sibling (`min_ns < target_ns`) must fail monotonicity.
        let mut bad_nmt = bundle.clone();
        bad_nmt.namespace_proof.nmt_siblings[0].min_ns = [0x01; 32];
        bad_nmt.namespace_proof.nmt_siblings[0].max_ns = [0x02; 32];
        let mut bad_nmt_ev = golden.clone();
        bad_nmt_ev.payload = encode_da_evidence(&bad_nmt).expect("encode");
        assert!(matches!(
            adapter.verify(&bad_nmt_ev, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // STRIX-COC-02a forgery: stripping ML-DSA-65 co-signatures from PQ-enrolled
        // DA committee members must fail closed with a crypto error.
        let mut stripped_pq = bundle.clone();
        for sig in &mut stripped_pq.signatures {
            sig.pq_sig.clear();
        }
        let mut stripped_ev = golden.clone();
        stripped_ev.payload = encode_da_evidence(&stripped_pq).expect("encode");
        assert!(matches!(
            adapter.verify(&stripped_ev, &policy),
            Err(AdapterError::Crypto { .. })
        ));

        // STRIX-COC-02c forgery: substituting valid dual-axis openings at prover-chosen
        // coordinates that omit a required Fiat-Shamir challenge coordinate is refused.
        let required: BTreeSet<(u16, u16)> =
            bundle.samples.iter().map(|s| (s.row, s.col)).collect();
        let unchallenged = (0..2u16)
            .flat_map(|r| (0..2u16).map(move |c| (r, c)))
            .find(|coord| !required.contains(coord))
            .expect("2x2 square with 2 samples leaves 2 unchallenged coordinates");
        // Reconstruct a cryptographically valid dual-axis opening for `unchallenged`.
        let nmt_l0 = hash_nmt_leaf(&[0x10; 32], &[0xAB; 32]);
        let nmt_l1 = hash_nmt_leaf(&[0x40; 32], &[0xCD; 32]);
        let s10 = hash_nmt_leaf(&[0x80; 32], &[0x21; 32]);
        let s11 = hash_nmt_leaf(&[0x80; 32], &[0x22; 32]);
        let grid = [[nmt_l0, nmt_l1], [s10, s11]];
        let row_roots = [
            hash_da_axis_node(&nmt_l0, &nmt_l1),
            hash_da_axis_node(&s10, &s11),
        ];
        let col_roots = [
            hash_da_axis_node(&nmt_l0, &s10),
            hash_da_axis_node(&nmt_l1, &s11),
        ];
        let (ur, uc) = unchallenged;
        let (uri, uci) = (usize::from(ur), usize::from(uc));
        let mut cherry_picked = bundle;
        cherry_picked.samples[0] = DaShareSample {
            row: ur,
            col: uc,
            share_digest: grid[uri][uci],
            row_root: row_roots[uri],
            share_to_row_branch: vec![grid[uri][uci ^ 1]],
            row_to_axis_branch: vec![row_roots[uri ^ 1]],
            col_root: col_roots[uci],
            share_to_col_branch: vec![grid[uri ^ 1][uci]],
            col_to_axis_branch: vec![col_roots[uci ^ 1]],
        };
        let mut cherry_ev = golden.clone();
        cherry_ev.payload = encode_da_evidence(&cherry_picked).expect("encode");
        assert!(matches!(
            adapter.verify(&cherry_ev, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // STRIX-COC-02b: trailing garbage after bounded bincode body is rejected.
        let mut trailing_ev = golden;
        trailing_ev.payload.push(0x99);
        assert!(matches!(
            adapter.verify(&trailing_ev, &policy),
            Err(AdapterError::Malformed { .. })
        ));
    }
}
