//! Modular Data-Availability Sampling (`DAS`) + Namespace Merkle Tree (`NMT`)
//! external finality adapter (`da-sampling-v1`).
//!
//! Verifies data-availability commitments from modular DA networks (Celestia,
//! Avail, `EigenDA`, and sovereign rollup DA layers) against a governance-pinned
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
    share_col_root: Hash32,
    share_to_col_branch: Vec<Hash32>,
    col_axis_branch: Vec<Hash32>,
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
/// Committed 2D Reed-Solomon data-availability square header.
///
/// WIRING: Verified by [`DataAvailabilityAdapter`] and [`verify_da_fraud_proof`].
pub struct DaHeader {
    pub height: u64,
    pub time_secs: u64,
    pub square_size: u16,
    pub nmt_roots_root: Hash32,
    pub row_roots_root: Hash32,
    pub col_roots_root: Hash32,
    pub data_root: Hash32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Committee attestation signature (Ed25519 plus optional ML-DSA-65 co-signature)
/// over a committed [`DaHeader`].
///
/// WIRING: Verified by [`DataAvailabilityAdapter`] and [`verify_da_fraud_proof`].
pub struct DaAttestationSig {
    pub signer_pubkey: [u8; 32],
    pub ed25519_sig: Vec<u8>,
    #[serde(default)]
    pub pq_sig: Vec<u8>,
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

fn min_signers_for_quorum<I: IntoIterator<Item = u64>>(weights: I, total_stake: u128) -> u64 {
    let mut sorted: Vec<u64> = weights.into_iter().filter(|&w| w > 0).collect();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let mut acc = 0u128;
    let mut count = 0u64;
    let two_thirds = total_stake.saturating_mul(2);
    for w in sorted {
        acc = acc.saturating_add(u128::from(w));
        count = count.saturating_add(1);
        if acc.saturating_mul(3) > two_thirds {
            return count;
        }
    }
    count.max(1)
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
        validate_pinned_da_policy(pinned)?;
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
        if policy.max_age > 0 {
            if header.height > policy.now {
                return Err(AdapterError::Stale {
                    age: header.height - policy.now,
                    max_age: policy.max_age,
                });
            }
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
        ) && verify_axis_branch(
            &nmt_leaf,
            ns_proof.row_index,
            axis_depth,
            &ns_proof.share_to_col_branch,
            &ns_proof.share_col_root,
        ) && verify_axis_branch(
            &ns_proof.share_col_root,
            ns_proof.leaf_index,
            axis_depth,
            &ns_proof.col_axis_branch,
            &header.col_roots_root,
        );
        if !leaf_bound_to_square {
            return Err(AdapterError::ConsensusRule {
                rule: "NMT leaf failed dual-axis inclusion against header row/col roots".into(),
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

        let required_signers =
            min_signers_for_quorum(pinned.members.iter().map(|m| m.voting_weight), total_stake);
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

    fn has_pinned_trust_anchor(&self) -> bool {
        self.pinned.is_some()
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

/// Maximum raw byte length of a single fixed-size DA share inside a fraud or
/// erasure-reconstruction proof (bounds verification CPU and allocation).
const MAX_DA_SHARE_BYTES: usize = 4_096;

/// Maximum extended square dimension permitted inside synchronous in-block
/// Reed-Solomon fraud verification (keeps `O(k^2)` barycentric setup cheap).
const MAX_FRAUD_PROOF_SQUARE_SIZE: u16 = 128;

/// Primitive polynomial `x^16 + x^12 + x^3 + x + 1` (low 16 bits `0x100B`)
/// defining the canonical binary Galois field `GF(2^16)`.
const GF16_REDUCTION_POLY: u16 = 0x100B;

#[inline]
#[must_use]
const fn gf16_mul(mut a: u16, mut b: u16) -> u16 {
    let mut acc = 0u16;
    let mut i = 0u8;
    while i < 16 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let carry = (a & 0x8000) != 0;
        a <<= 1;
        if carry {
            a ^= GF16_REDUCTION_POLY;
        }
        b >>= 1;
        i += 1;
    }
    acc
}

#[inline]
#[must_use]
const fn gf16_inv(base: u16) -> u16 {
    // By Fermat's identity in GF(2^16)*, base^(2^16 - 2) == base^(-1) for all base != 0.
    let mut exp = 0xFFFEu16;
    let mut acc = 1u16;
    let mut cur = base;
    while exp != 0 {
        if (exp & 1) != 0 {
            acc = gf16_mul(acc, cur);
        }
        cur = gf16_mul(cur, cur);
        exp >>= 1;
    }
    acc
}

#[inline]
#[must_use]
const fn rs_eval_point(index: u16) -> Option<u16> {
    // Distinct non-zero field points x_i = i + 1 for every share index i < 65_535.
    index.checked_add(1)
}

/// Precompute barycentric Lagrange weights `w_t = prod_{r != t} (x_t ^ x_r)^(-1)`
/// for distinct share indices `indices`.
fn barycentric_weights(indices: &[u16]) -> Result<Vec<u16>, AdapterError> {
    let mut points = Vec::with_capacity(indices.len());
    for &idx in indices {
        let pt = rs_eval_point(idx).ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Reed-Solomon share index overflows GF(2^16) domain".into(),
        })?;
        points.push(pt);
    }
    let mut weights = Vec::with_capacity(points.len());
    for (i, &xi) in points.iter().enumerate() {
        let mut prod = 1u16;
        for (j, &xj) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let diff = xi ^ xj;
            if diff == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate Reed-Solomon share index in interpolation set".into(),
                });
            }
            prod = gf16_mul(prod, diff);
        }
        weights.push(gf16_inv(prod));
    }
    Ok(weights)
}

/// Evaluate the unique degree `< k` polynomial interpolating `(indices[t], shares[t])`
/// at target share position `target_index` across all 16-bit symbol lanes.
fn evaluate_rs_share_at(
    indices: &[u16],
    weights: &[u16],
    shares: &[&[u8]],
    share_len: usize,
    target_index: u16,
) -> Result<Vec<u8>, AdapterError> {
    if let Some(pos) = indices.iter().position(|&idx| idx == target_index) {
        return shares
            .get(pos)
            .map(|s| (*s).to_vec())
            .ok_or_else(|| AdapterError::Malformed {
                offset: 0,
                reason: "Reed-Solomon interpolation share index out of bounds".into(),
            });
    }
    let x = rs_eval_point(target_index).ok_or_else(|| AdapterError::ConsensusRule {
        rule: "Reed-Solomon target index overflows GF(2^16) domain".into(),
    })?;
    let mut kernels = Vec::with_capacity(indices.len());
    let mut denom = 0u16;
    for (&idx, &w) in indices.iter().zip(weights.iter()) {
        let xt = rs_eval_point(idx).ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Reed-Solomon source index overflows GF(2^16) domain".into(),
        })?;
        let k_t = gf16_mul(w, gf16_inv(x ^ xt));
        denom ^= k_t;
        kernels.push(k_t);
    }
    if denom == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "degenerate Reed-Solomon barycentric denominator".into(),
        });
    }
    let inv_denom = gf16_inv(denom);
    let mut coeffs = Vec::with_capacity(kernels.len());
    for k_t in kernels {
        coeffs.push(gf16_mul(k_t, inv_denom));
    }
    let mut out = vec![0u8; share_len];
    let mut offset = 0usize;
    while offset < share_len {
        let mut sum = 0u16;
        for (share, &c_t) in shares.iter().zip(coeffs.iter()) {
            let lo = share.get(offset).copied().unwrap_or(0);
            let hi = share.get(offset + 1).copied().unwrap_or(0);
            let sym = u16::from_le_bytes([lo, hi]);
            sum ^= gf16_mul(c_t, sym);
        }
        let bytes = sum.to_le_bytes();
        if let Some(dst) = out.get_mut(offset..offset + 2) {
            dst.copy_from_slice(&bytes);
        }
        offset += 2;
    }
    Ok(out)
}

fn validate_share_slice(share: &[u8]) -> Result<(), AdapterError> {
    if share.is_empty() || share.len() > MAX_DA_SHARE_BYTES || !share.len().is_multiple_of(2) {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "DA share length {} must be non-zero, even, and <= {MAX_DA_SHARE_BYTES}",
                share.len()
            ),
        });
    }
    Ok(())
}

/// Domain-separated SHA-256 digest of a raw fixed-size DA share committed into
/// row and column Merkle axes.
///
/// WIRING: Canonical share digest shared by 2D Reed-Solomon square commitment
/// builders, light-node erasure reconstructors, and [`verify_da_fraud_proof`].
#[must_use]
pub fn compute_da_share_digest(share_bytes: &[u8]) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[b"BDLM_DA_SHARE_LEAF_V1", share_bytes])
}

/// Compute the canonical binary Merkle root over a power-of-two row or column
/// of `2..=MAX_SQUARE_SIZE` share digests (or axis roots).
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] when `leaves.len()` is not a power
/// of two in `2..=MAX_SQUARE_SIZE`.
///
/// WIRING: Pairs with [`open_da_axis_leaf`] and [`verify_da_fraud_proof`] for
/// 2D Reed-Solomon axis commitment and fraud proof construction.
pub fn commit_da_axis(leaves: &[Hash32]) -> Result<Hash32, AdapterError> {
    if leaves.len() < 2
        || leaves.len() > usize::from(MAX_DA_SQUARE_SIZE)
        || !leaves.len().is_power_of_two()
    {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "DA axis length {} must be a power of two in 2..={MAX_DA_SQUARE_SIZE}",
                leaves.len()
            ),
        });
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.as_chunks::<2>().0 {
            next.push(hash_da_axis_node(&pair[0], &pair[1]));
        }
        level = next;
    }
    level
        .first()
        .copied()
        .ok_or_else(|| AdapterError::Malformed {
            offset: 0,
            reason: "empty DA axis reduction".into(),
        })
}

/// Open the binary Merkle sibling branch for `index` in a power-of-two DA axis.
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] when `leaves.len()` is invalid or
/// `index` is out of bounds.
///
/// WIRING: Produces Merkle openings verified by [`DataAvailabilityAdapter`] and
/// [`verify_da_fraud_proof`].
pub fn open_da_axis_leaf(leaves: &[Hash32], index: u16) -> Result<Vec<Hash32>, AdapterError> {
    let _ = commit_da_axis(leaves)?;
    let mut idx = usize::from(index);
    if idx >= leaves.len() {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "DA axis index {index} out of range for len {}",
                leaves.len()
            ),
        });
    }
    let mut level = leaves.to_vec();
    let mut branch = Vec::new();
    while level.len() > 1 {
        let sib = level
            .get(idx ^ 1)
            .copied()
            .ok_or_else(|| AdapterError::Malformed {
                offset: 0,
                reason: "DA axis sibling lookup out of bounds".into(),
            })?;
        branch.push(sib);
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.as_chunks::<2>().0 {
            next.push(hash_da_axis_node(&pair[0], &pair[1]));
        }
        level = next;
        idx >>= 1;
    }
    Ok(branch)
}

/// Systematically extend `k` fixed-size data shares (`k` a power of two) into a
/// `2k`-share rate-1/2 Reed-Solomon codeword over `GF(2^16)`.
///
/// Shares `0..k` equal the input data shares verbatim; shares `k..2k` hold the
/// unique degree `< k` polynomial evaluations guaranteeing full data recovery
/// from any `k` surviving shares.
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] when `k` is not a power of two in
/// `1..=MAX_FRAUD_PROOF_SQUARE_SIZE / 2` or share lengths are invalid/unequal.
///
/// WIRING: Rate-1/2 systematic Reed-Solomon axis encoder paired with
/// [`reconstruct_rs_axis`] and [`verify_da_fraud_proof`].
pub fn encode_rs_extended_axis(data_shares: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, AdapterError> {
    let k = data_shares.len();
    let max_k = usize::from(MAX_FRAUD_PROOF_SQUARE_SIZE / 2);
    if k == 0 || k > max_k || !k.is_power_of_two() {
        return Err(AdapterError::ConsensusRule {
            rule: format!("DA data share count {k} must be a power of two in 1..={max_k}"),
        });
    }
    let first = data_shares
        .first()
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "empty DA data share slice".into(),
        })?;
    validate_share_slice(first)?;
    let share_len = first.len();
    for s in data_shares {
        if s.len() != share_len {
            return Err(AdapterError::ConsensusRule {
                rule: "DA data shares on an axis must have uniform byte length".into(),
            });
        }
    }
    let k_u16 = u16::try_from(k).map_err(|_| AdapterError::ConsensusRule {
        rule: "DA data share count exceeds u16".into(),
    })?;
    let total_u16 = k_u16.saturating_mul(2);
    let indices: Vec<u16> = (0..k_u16).collect();
    let weights = barycentric_weights(&indices)?;
    let refs: Vec<&[u8]> = data_shares.iter().map(Vec::as_slice).collect();
    let mut extended = Vec::with_capacity(usize::from(total_u16));
    extended.extend(data_shares.iter().cloned());
    for target in k_u16..total_u16 {
        extended.push(evaluate_rs_share_at(
            &indices, &weights, &refs, share_len, target,
        )?);
    }
    Ok(extended)
}

/// Reconstruct all `k = square_size / 2` systematic data shares of an RS axis.
///
/// Succeeds from any `>= k` distinct surviving `(index, share)` openings
/// (tolerating up to 50% adversarial share withholding).
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] when `square_size` is invalid, fewer
/// than `k` distinct in-range shares are provided, or share sizes disagree.
///
/// WIRING: Rate-1/2 erasure decoder for DA availability recovery and fraud generation.
pub fn reconstruct_rs_axis(
    square_size: u16,
    available_shares: &[(u16, Vec<u8>)],
) -> Result<Vec<Vec<u8>>, AdapterError> {
    if !(2..=MAX_FRAUD_PROOF_SQUARE_SIZE).contains(&square_size) || !square_size.is_power_of_two() {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "DA square_size {square_size} must be a power of two in 2..={MAX_FRAUD_PROOF_SQUARE_SIZE}"
            ),
        });
    }
    let k = usize::from(square_size / 2);
    let mut by_index: BTreeMap<u16, &[u8]> = BTreeMap::new();
    let mut expected_len: Option<usize> = None;
    for (idx, bytes) in available_shares {
        if *idx >= square_size {
            return Err(AdapterError::ConsensusRule {
                rule: format!("DA share index {idx} out of range for square_size {square_size}"),
            });
        }
        validate_share_slice(bytes)?;
        if let Some(len) = expected_len {
            if bytes.len() != len {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA shares supplied for reconstruction have mismatched lengths".into(),
                });
            }
        } else {
            expected_len = Some(bytes.len());
        }
        if let Some(prev) = by_index.insert(*idx, bytes.as_slice()) {
            if prev != bytes.as_slice() {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("conflicting share payloads supplied for index {idx}"),
                });
            }
        }
    }
    if by_index.len() < k {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "insufficient surviving DA shares {}/{k} for rate-1/2 reconstruction",
                by_index.len()
            ),
        });
    }
    let share_len = expected_len.unwrap_or(0);
    let indices: Vec<u16> = by_index.keys().take(k).copied().collect();
    let refs: Vec<&[u8]> = by_index.values().take(k).copied().collect();
    let weights = barycentric_weights(&indices)?;
    let k_u16 = square_size / 2;
    let mut data = Vec::with_capacity(k);
    for target in 0..k_u16 {
        data.push(evaluate_rs_share_at(
            &indices, &weights, &refs, share_len, target,
        )?);
    }
    // Verify any extra provided shares agree with the reconstructed degree < k codeword.
    for (&idx, &bytes) in by_index.iter().skip(k) {
        let check = evaluate_rs_share_at(&indices, &weights, &refs, share_len, idx)?;
        if check.as_slice() != bytes {
            return Err(AdapterError::ConsensusRule {
                rule: format!("inconsistent Reed-Solomon codeword detected at share index {idx}"),
            });
        }
    }
    Ok(data)
}

/// Axis selector for a 2D Reed-Solomon bad-encoding fraud proof.
///
/// WIRING: Distinguishes row and column openings inside [`DaFraudKind::BadAxisEncoding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaAxis {
    /// Horizontal row axis committed under `DaHeader::row_roots_root`.
    Row,
    /// Vertical column axis committed under `DaHeader::col_roots_root`.
    Col,
}

/// Authenticated raw share opening along a committed row or column Merkle root.
///
/// WIRING: Source-share witness inside [`DaFraudKind::BadAxisEncoding`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaOpenedAxisShare {
    pub share_index: u16,
    pub share_bytes: Vec<u8>,
    pub share_to_axis_branch: Vec<Hash32>,
}

/// Compact, deterministically verifiable fraud evidence against a signed [`DaHeader`].
///
/// WIRING: Variant payload of [`DaFraudProof`] verified by [`verify_da_fraud_proof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaFraudKind {
    /// Al-Bassam et al. single-axis bad-encoding fraud proof: `k = square_size / 2`
    /// Merkle-authenticated shares define a unique degree `< k` Reed-Solomon
    /// polynomial whose canonical evaluation at `bad_index` disagrees with the
    /// committed digest at `bad_index` under the same row or column root.
    BadAxisEncoding {
        axis: DaAxis,
        axis_index: u16,
        axis_root: Hash32,
        axis_to_header_branch: Vec<Hash32>,
        source_openings: Vec<DaOpenedAxisShare>,
        bad_index: u16,
        bad_share_digest: Hash32,
        bad_share_to_axis_branch: Vec<Hash32>,
    },
    /// Dual-axis inconsistency proof: cell `(row, col)` opens to two distinct
    /// share digests under `header.row_roots_root` and `header.col_roots_root`.
    AxisCellMismatch {
        row: u16,
        col: u16,
        row_share_digest: Hash32,
        row_root: Hash32,
        share_to_row_branch: Vec<Hash32>,
        row_to_axis_branch: Vec<Hash32>,
        col_share_digest: Hash32,
        col_root: Hash32,
        share_to_col_branch: Vec<Hash32>,
        col_to_axis_branch: Vec<Hash32>,
    },
    /// Slashable committee equivocation: committee member(s) signed two distinct
    /// canonical `DaHeader` roots at the exact same `(network, namespace_id, height)`.
    HeaderEquivocation {
        conflicting_header: DaHeader,
        conflicting_signatures: Vec<DaAttestationSig>,
    },
}

/// Signed DA fraud proof bundle evaluated by [`verify_da_fraud_proof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaFraudProof {
    pub header: DaHeader,
    pub signatures: Vec<DaAttestationSig>,
    pub kind: DaFraudKind,
}

/// Deterministic slashable attribution emitted when [`verify_da_fraud_proof`] succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaFraudVerdict {
    pub height: u64,
    pub invalid_data_root: Hash32,
    pub slashable_signers: Vec<[u8; 32]>,
    pub slashed_weight: u128,
    pub total_committee_weight: u128,
    pub quorum_safety_breached: bool,
}

fn validate_pinned_da_policy(pinned: &PinnedDaCommittee) -> Result<(), AdapterError> {
    if pinned.namespace_id == [0u8; 32]
        || pinned.min_samples == 0
        || usize::from(pinned.min_samples) > MAX_DA_SAMPLES
        || pinned.min_square_size < 2
        || !pinned.min_square_size.is_power_of_two()
        || pinned.min_square_size > MAX_DA_SQUARE_SIZE
    {
        return Err(AdapterError::ConsensusRule {
            rule: "pinned DA policy carries invalid namespace, min_samples, or min_square_size"
                .into(),
        });
    }
    Ok(())
}

fn verify_da_committee_map(
    pinned: &PinnedDaCommittee,
) -> Result<(BTreeMap<[u8; 32], &DaCommitteeMember>, u128), AdapterError> {
    validate_pinned_da_policy(pinned)?;
    if pinned.members.is_empty() || pinned.members.len() > MAX_DA_COMMITTEE {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "pinned DA committee size {} outside 1..={MAX_DA_COMMITTEE}",
                pinned.members.len()
            ),
        });
    }
    let mut map = BTreeMap::new();
    let mut total = 0u128;
    for m in &pinned.members {
        if m.ed25519_pubkey == [0u8; 32] || m.voting_weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned DA committee contains zero pubkey or zero weight".into(),
            });
        }
        if map.insert(m.ed25519_pubkey, m).is_some() {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned DA committee contains duplicate pubkey".into(),
            });
        }
        total = total
            .checked_add(u128::from(m.voting_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "pinned DA committee stake overflows u128".into(),
            })?;
    }
    Ok((map, total))
}

fn verify_da_header_signatures(
    network: &str,
    header: &DaHeader,
    namespace_id: &Hash32,
    signatures: &[DaAttestationSig],
    members: &BTreeMap<[u8; 32], &DaCommitteeMember>,
) -> Result<BTreeSet<[u8; 32]>, AdapterError> {
    if signatures.is_empty() || signatures.len() > MAX_DA_COMMITTEE {
        return Err(AdapterError::ConsensusRule {
            rule: "DA fraud proof signature list is empty or exceeds committee cap".into(),
        });
    }
    let expected_root = compute_da_data_root(
        header.square_size,
        &header.nmt_roots_root,
        &header.row_roots_root,
        &header.col_roots_root,
    );
    if !bool::from(subtle::ConstantTimeEq::ct_eq(
        expected_root.as_slice(),
        header.data_root.as_slice(),
    )) {
        return Err(AdapterError::ConsensusRule {
            rule: "DA fraud proof header data_root does not match axis commitments".into(),
        });
    }
    let vote = da_header_sign_bytes(network, header, namespace_id);
    let mut signers = BTreeSet::new();
    for sig in signatures {
        if !signers.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate signer in DA fraud proof".into(),
            });
        }
        let Some(member) = members.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: "DA fraud proof cites signature from non-committee key".into(),
            });
        };
        crate::crypto::primitives::verify_signature(&vote, &sig.ed25519_sig, &sig.signer_pubkey)
            .map_err(|_| AdapterError::Crypto {
                what: "DA fraud proof Ed25519 signature invalid".into(),
            })?;
        if !member.pq_pubkey.is_empty() {
            if sig.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: "DA fraud proof omits mandatory ML-DSA-65 co-signature".into(),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &member.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &vote,
                &sig.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "DA fraud proof ML-DSA-65 co-signature invalid".into(),
            })?;
        }
    }
    Ok(signers)
}

/// Verify a compact DA fraud proof and attribute slashable committee weight.
///
/// Covers 2D Reed-Solomon bad-encoding, row/column axis mismatch, and committee
/// header equivocation, returning the sorted set of slashable committee signers.
///
/// Guarantees zero false positives against any honestly extended 2D Reed-Solomon
/// square while catching every single-cell encoding or equivocation fault with
/// `O(k)` share openings.
///
/// # Errors
///
/// Returns [`AdapterError`] if any committee signature (including mandatory
/// ML-DSA-65 co-signatures) or Merkle opening fails, or if the challenged square
/// is in fact validly encoded (no fraud established).
///
/// WIRING: Settlement dispute and committee-slashing entry point complementing
/// [`DataAvailabilityAdapter`] probabilistic DAS intake.
pub fn verify_da_fraud_proof(
    network: &str,
    pinned: &PinnedDaCommittee,
    proof: &DaFraudProof,
) -> Result<DaFraudVerdict, AdapterError> {
    if network.trim().is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "DA fraud proof network identifier must be non-empty".into(),
        });
    }
    let (member_map, total_stake) = verify_da_committee_map(pinned)?;
    let header = &proof.header;
    if header.square_size < pinned.min_square_size
        || header.square_size > MAX_DA_SQUARE_SIZE
        || !header.square_size.is_power_of_two()
    {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "DA fraud proof square_size {} invalid or below minimum {}",
                header.square_size, pinned.min_square_size
            ),
        });
    }
    let primary_signers = verify_da_header_signatures(
        network,
        header,
        &pinned.namespace_id,
        &proof.signatures,
        &member_map,
    )?;
    let axis_depth = header.square_size.trailing_zeros() as usize;

    let offenders: Vec<[u8; 32]> = match &proof.kind {
        DaFraudKind::BadAxisEncoding {
            axis,
            axis_index,
            axis_root,
            axis_to_header_branch,
            source_openings,
            bad_index,
            bad_share_digest,
            bad_share_to_axis_branch,
        } => {
            if header.square_size > MAX_FRAUD_PROOF_SQUARE_SIZE {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "DA bad-encoding fraud square_size {} exceeds {MAX_FRAUD_PROOF_SQUARE_SIZE}",
                        header.square_size
                    ),
                });
            }
            if *axis_index >= header.square_size || *bad_index >= header.square_size {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA bad-encoding fraud axis_index or bad_index out of range".into(),
                });
            }
            let header_axis_root = match axis {
                DaAxis::Row => &header.row_roots_root,
                DaAxis::Col => &header.col_roots_root,
            };
            if !verify_axis_branch(
                axis_root,
                *axis_index,
                axis_depth,
                axis_to_header_branch,
                header_axis_root,
            ) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA bad-encoding axis_root failed inclusion against header".into(),
                });
            }
            let k = usize::from(header.square_size / 2);
            if source_openings.len() != k {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "DA bad-encoding fraud requires exactly {k} source openings, got {}",
                        source_openings.len()
                    ),
                });
            }
            let mut seen = BTreeSet::new();
            let mut indices = Vec::with_capacity(k);
            let mut share_refs = Vec::with_capacity(k);
            let mut share_len: Option<usize> = None;
            for opening in source_openings {
                if opening.share_index >= header.square_size
                    || opening.share_index == *bad_index
                    || !seen.insert(opening.share_index)
                {
                    return Err(AdapterError::ConsensusRule {
                        rule: "DA bad-encoding fraud source share index invalid or duplicated"
                            .into(),
                    });
                }
                validate_share_slice(&opening.share_bytes)?;
                if let Some(len) = share_len {
                    if opening.share_bytes.len() != len {
                        return Err(AdapterError::ConsensusRule {
                            rule: "DA bad-encoding source shares have unequal byte length".into(),
                        });
                    }
                } else {
                    share_len = Some(opening.share_bytes.len());
                }
                let digest = compute_da_share_digest(&opening.share_bytes);
                if !verify_axis_branch(
                    &digest,
                    opening.share_index,
                    axis_depth,
                    &opening.share_to_axis_branch,
                    axis_root,
                ) {
                    return Err(AdapterError::ConsensusRule {
                        rule: "DA bad-encoding source share failed axis Merkle opening".into(),
                    });
                }
                indices.push(opening.share_index);
                share_refs.push(opening.share_bytes.as_slice());
            }
            if !verify_axis_branch(
                bad_share_digest,
                *bad_index,
                axis_depth,
                bad_share_to_axis_branch,
                axis_root,
            ) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA bad-encoding challenged digest failed axis Merkle opening".into(),
                });
            }
            let weights = barycentric_weights(&indices)?;
            let expected_share = evaluate_rs_share_at(
                &indices,
                &weights,
                &share_refs,
                share_len.unwrap_or(0),
                *bad_index,
            )?;
            let expected_digest = compute_da_share_digest(&expected_share);
            if bool::from(subtle::ConstantTimeEq::ct_eq(
                expected_digest.as_slice(),
                bad_share_digest.as_slice(),
            )) {
                return Err(AdapterError::ConsensusRule {
                    rule: "challenged DA share matches canonical Reed-Solomon encoding (no fraud)"
                        .into(),
                });
            }
            primary_signers.into_iter().collect()
        }
        DaFraudKind::AxisCellMismatch {
            row,
            col,
            row_share_digest,
            row_root,
            share_to_row_branch,
            row_to_axis_branch,
            col_share_digest,
            col_root,
            share_to_col_branch,
            col_to_axis_branch,
        } => {
            if *row >= header.square_size || *col >= header.square_size {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA axis-mismatch coordinate exceeds square_size".into(),
                });
            }
            let row_ok = verify_axis_branch(
                row_share_digest,
                *col,
                axis_depth,
                share_to_row_branch,
                row_root,
            ) && verify_axis_branch(
                row_root,
                *row,
                axis_depth,
                row_to_axis_branch,
                &header.row_roots_root,
            );
            let col_ok = verify_axis_branch(
                col_share_digest,
                *row,
                axis_depth,
                share_to_col_branch,
                col_root,
            ) && verify_axis_branch(
                col_root,
                *col,
                axis_depth,
                col_to_axis_branch,
                &header.col_roots_root,
            );
            if !row_ok || !col_ok {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA axis-mismatch fraud proof contains invalid Merkle branch".into(),
                });
            }
            if bool::from(subtle::ConstantTimeEq::ct_eq(
                row_share_digest.as_slice(),
                col_share_digest.as_slice(),
            )) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA row and column commitments agree at challenged cell (no fraud)"
                        .into(),
                });
            }
            primary_signers.into_iter().collect()
        }
        DaFraudKind::HeaderEquivocation {
            conflicting_header,
            conflicting_signatures,
        } => {
            if conflicting_header.height != header.height {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA header equivocation requires identical height".into(),
                });
            }
            if conflicting_header.square_size < pinned.min_square_size
                || conflicting_header.square_size > MAX_DA_SQUARE_SIZE
                || !conflicting_header.square_size.is_power_of_two()
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA conflicting header square_size invalid or below minimum".into(),
                });
            }
            if bool::from(subtle::ConstantTimeEq::ct_eq(
                conflicting_header.data_root.as_slice(),
                header.data_root.as_slice(),
            )) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DA equivocation headers commit to the same data_root (no fraud)".into(),
                });
            }
            let secondary_signers = verify_da_header_signatures(
                network,
                conflicting_header,
                &pinned.namespace_id,
                conflicting_signatures,
                &member_map,
            )?;
            let double_signers: Vec<[u8; 32]> = primary_signers
                .intersection(&secondary_signers)
                .copied()
                .collect();
            if double_signers.is_empty() {
                return Err(AdapterError::ConsensusRule {
                    rule: "no overlapping committee signer across conflicting DA headers".into(),
                });
            }
            double_signers
        }
    };

    let mut slashed_weight = 0u128;
    for pk in &offenders {
        if let Some(m) = member_map.get(pk) {
            slashed_weight = slashed_weight.saturating_add(u128::from(m.voting_weight));
        }
    }
    Ok(DaFraudVerdict {
        height: header.height,
        invalid_data_root: header.data_root,
        slashable_signers: offenders,
        slashed_weight,
        total_committee_weight: total_stake,
        quorum_safety_breached: slashed_weight.saturating_mul(3) >= total_stake,
    })
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
            share_col_root: col0,
            share_to_col_branch: vec![s10],
            col_axis_branch: vec![col1],
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

        // Forgery: stripping ML-DSA-65 co-signatures from PQ-enrolled
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

        // Forgery: substituting valid dual-axis openings at prover-chosen
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

        // trailing garbage after bounded bincode body is rejected.
        let mut trailing_ev = golden;
        trailing_ev.payload.push(0x99);
        assert!(matches!(
            adapter.verify(&trailing_ev, &policy),
            Err(AdapterError::Malformed { .. })
        ));
    }

    #[test]
    fn da_sampling_refuses_unsampled_blob_cell_column_axis_split() {
        let (pinned, mut bundle, mut ev) = da_2x2_fixture();
        let adapter = DataAvailabilityAdapter::new("celestia-mainnet", Some(pinned));
        let policy = VerificationPolicy::strict(505);

        // Corrupt the column commitment branch of the namespace blob cell while
        // keeping its NMT branch and row-axis branch completely intact.
        bundle.namespace_proof.share_to_col_branch[0][0] ^= 0xFF;
        ev.payload = encode_da_evidence(&bundle).expect("encode");
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn reed_solomon_extended_square_recovers_from_half_erasure_and_proves_all_fraud_classes() {
        let network = "celestia-fraud-1";
        let namespace_id = [0x33; 32];
        // Build a 2x2 data matrix extended into a 4x4 2D Reed-Solomon square (k = 2, 2k = 4).
        let r0_data = vec![vec![0x10u8, 0x20, 0x30, 0x40], vec![0x55, 0x66, 0x77, 0x88]];
        let r1_data = vec![vec![0x99u8, 0xAA, 0xBB, 0xCC], vec![0xDE, 0xAD, 0xBE, 0xEF]];
        let r0_ext = encode_rs_extended_axis(&r0_data).expect("encode row 0");
        let r1_ext = encode_rs_extended_axis(&r1_data).expect("encode row 1");
        assert_eq!(r0_ext.len(), 4);
        assert_eq!(&r0_ext[..2], r0_data.as_slice());

        // Extend every column across rows 0..2 -> 0..4 to form a true 2D RS 4x4 square.
        let mut grid: Vec<Vec<Vec<u8>>> = vec![vec![Vec::new(); 4]; 4];
        for col in 0..4 {
            let col_ext =
                encode_rs_extended_axis(&[r0_ext[col].clone(), r1_ext[col].clone()]).expect("col");
            for (row, cell) in col_ext.into_iter().enumerate() {
                grid[row][col] = cell;
            }
        }
        // Tensor-product property: parity rows 2 and 3 are ALSO valid RS codewords!
        for row in &grid {
            // Recover from pure parity shares (indices 2 and 3; 50% data withholding).
            let recovered =
                reconstruct_rs_axis(4, &[(2, row[2].clone()), (3, row[3].clone())]).expect("rec");
            assert_eq!(recovered, row[..2]);
            // Recover from mixed data + parity shares (indices 1 and 3).
            let mixed =
                reconstruct_rs_axis(4, &[(1, row[1].clone()), (3, row[3].clone())]).expect("mix");
            assert_eq!(mixed, row[..2]);
        }

        // Helper to build Merkle commitments and PQ-signed header over a 4x4 digest grid.
        let keys: Vec<(KeyPair, PqKeyPair)> = (0..3)
            .map(|_| (KeyPair::generate().expect("ek"), PqKeyPair::generate()))
            .collect();
        let members: Vec<DaCommitteeMember> = keys
            .iter()
            .map(|(ek, pk)| DaCommitteeMember {
                ed25519_pubkey: ek.public_key_bytes(),
                voting_weight: 100,
                pq_pubkey: pk.public_key_bytes().to_vec(),
            })
            .collect();
        let pinned = PinnedDaCommittee {
            namespace_id,
            min_samples: 4,
            min_square_size: 4,
            members,
        };
        let sign_header = |hdr: &DaHeader, idxs: &[usize]| -> Vec<DaAttestationSig> {
            let vote = da_header_sign_bytes(network, hdr, &namespace_id);
            idxs.iter()
                .map(|&i| DaAttestationSig {
                    signer_pubkey: keys[i].0.public_key_bytes(),
                    ed25519_sig: keys[i].0.sign(&vote).to_vec(),
                    pq_sig: keys[i]
                        .1
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &vote)
                        .expect("pq sign"),
                })
                .collect()
        };

        // 1. Honest square: challenging parity cell (0, 3) MUST fail (zero false positives).
        let honest_digests: Vec<Vec<Hash32>> = grid
            .iter()
            .map(|row| row.iter().map(|s| compute_da_share_digest(s)).collect())
            .collect();
        let honest_row_roots: Vec<Hash32> = honest_digests
            .iter()
            .map(|r| commit_da_axis(r).expect("row root"))
            .collect();
        let honest_col_roots: Vec<Hash32> = (0..4)
            .map(|c| {
                let col: Vec<Hash32> = (0..4).map(|r| honest_digests[r][c]).collect();
                commit_da_axis(&col).expect("col root")
            })
            .collect();
        let honest_rr = commit_da_axis(&honest_row_roots).expect("rr");
        let honest_cr = commit_da_axis(&honest_col_roots).expect("cr");
        let nmt_root = [0x51; 32];
        let honest_hdr = DaHeader {
            height: 777,
            time_secs: 1_750_000_000,
            square_size: 4,
            nmt_roots_root: nmt_root,
            row_roots_root: honest_rr,
            col_roots_root: honest_cr,
            data_root: compute_da_data_root(4, &nmt_root, &honest_rr, &honest_cr),
        };
        let honest_challenge = DaFraudProof {
            header: honest_hdr.clone(),
            signatures: sign_header(&honest_hdr, &[0, 1, 2]),
            kind: DaFraudKind::BadAxisEncoding {
                axis: DaAxis::Row,
                axis_index: 0,
                axis_root: honest_row_roots[0],
                axis_to_header_branch: open_da_axis_leaf(&honest_row_roots, 0).expect("open"),
                source_openings: vec![
                    DaOpenedAxisShare {
                        share_index: 1,
                        share_bytes: grid[0][1].clone(),
                        share_to_axis_branch: open_da_axis_leaf(&honest_digests[0], 1)
                            .expect("open"),
                    },
                    DaOpenedAxisShare {
                        share_index: 2,
                        share_bytes: grid[0][2].clone(),
                        share_to_axis_branch: open_da_axis_leaf(&honest_digests[0], 2)
                            .expect("open"),
                    },
                ],
                bad_index: 3,
                bad_share_digest: honest_digests[0][3],
                bad_share_to_axis_branch: open_da_axis_leaf(&honest_digests[0], 3).expect("open"),
            },
        };
        assert!(matches!(
            verify_da_fraud_proof(network, &pinned, &honest_challenge),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 2. Bad column parity encoding at cell (3, 2): caught and attributed to all signers.
        let mut corrupt_digests = honest_digests.clone();
        let mut bad_cell = grid[3][2].clone();
        bad_cell[0] ^= 0x01;
        corrupt_digests[3][2] = compute_da_share_digest(&bad_cell);
        let bad_row_roots: Vec<Hash32> = corrupt_digests
            .iter()
            .map(|r| commit_da_axis(r).expect("row"))
            .collect();
        let bad_col2: Vec<Hash32> = (0..4).map(|r| corrupt_digests[r][2]).collect();
        let mut bad_col_roots = honest_col_roots.clone();
        bad_col_roots[2] = commit_da_axis(&bad_col2).expect("col2");
        let bad_rr = commit_da_axis(&bad_row_roots).expect("rr");
        let bad_cr = commit_da_axis(&bad_col_roots).expect("cr");
        let bad_hdr = DaHeader {
            row_roots_root: bad_rr,
            col_roots_root: bad_cr,
            data_root: compute_da_data_root(4, &nmt_root, &bad_rr, &bad_cr),
            ..honest_hdr.clone()
        };
        let bad_col_proof = DaFraudProof {
            header: bad_hdr.clone(),
            signatures: sign_header(&bad_hdr, &[0, 2]),
            kind: DaFraudKind::BadAxisEncoding {
                axis: DaAxis::Col,
                axis_index: 2,
                axis_root: bad_col_roots[2],
                axis_to_header_branch: open_da_axis_leaf(&bad_col_roots, 2).expect("open col"),
                source_openings: vec![
                    DaOpenedAxisShare {
                        share_index: 0,
                        share_bytes: grid[0][2].clone(),
                        share_to_axis_branch: open_da_axis_leaf(&bad_col2, 0).expect("open s0"),
                    },
                    DaOpenedAxisShare {
                        share_index: 1,
                        share_bytes: grid[1][2].clone(),
                        share_to_axis_branch: open_da_axis_leaf(&bad_col2, 1).expect("open s1"),
                    },
                ],
                bad_index: 3,
                bad_share_digest: corrupt_digests[3][2],
                bad_share_to_axis_branch: open_da_axis_leaf(&bad_col2, 3).expect("open bad"),
            },
        };
        let verdict = verify_da_fraud_proof(network, &pinned, &bad_col_proof).expect("bad col RS");
        assert_eq!(verdict.height, 777);
        assert_eq!(verdict.slashed_weight, 200);
        assert_eq!(verdict.total_committee_weight, 300);
        assert!(verdict.quorum_safety_breached);
        assert_eq!(verdict.slashable_signers.len(), 2);

        // Stripping mandatory ML-DSA-65 co-signature from fraud proof must fail closed.
        let mut stripped = bad_col_proof;
        stripped.signatures[0].pq_sig.clear();
        assert!(matches!(
            verify_da_fraud_proof(network, &pinned, &stripped),
            Err(AdapterError::Crypto { .. })
        ));

        // 3. Axis cell mismatch: header uses corrupt row_roots_root with honest col_roots_root.
        let split_hdr = DaHeader {
            row_roots_root: bad_rr,
            col_roots_root: honest_cr,
            data_root: compute_da_data_root(4, &nmt_root, &bad_rr, &honest_cr),
            ..honest_hdr.clone()
        };
        let honest_col2: Vec<Hash32> = (0..4).map(|r| honest_digests[r][2]).collect();
        let mismatch_proof = DaFraudProof {
            header: split_hdr.clone(),
            signatures: sign_header(&split_hdr, &[1]),
            kind: DaFraudKind::AxisCellMismatch {
                row: 3,
                col: 2,
                row_share_digest: corrupt_digests[3][2],
                row_root: bad_row_roots[3],
                share_to_row_branch: open_da_axis_leaf(&corrupt_digests[3], 2).expect("open"),
                row_to_axis_branch: open_da_axis_leaf(&bad_row_roots, 3).expect("open"),
                col_share_digest: honest_digests[3][2],
                col_root: honest_col_roots[2],
                share_to_col_branch: open_da_axis_leaf(&honest_col2, 3).expect("open"),
                col_to_axis_branch: open_da_axis_leaf(&honest_col_roots, 2).expect("open"),
            },
        };
        let split_verdict =
            verify_da_fraud_proof(network, &pinned, &mismatch_proof).expect("axis mismatch fraud");
        assert_eq!(
            split_verdict.slashable_signers,
            vec![keys[1].0.public_key_bytes()]
        );
        assert_eq!(split_verdict.slashed_weight, 100);
        assert!(split_verdict.quorum_safety_breached);

        // 4. Header equivocation: only validator 2 double-signed honest_hdr and bad_hdr.
        let eq_primary_sigs = sign_header(&honest_hdr, &[0, 2]);
        let eq_secondary_sigs = sign_header(&bad_hdr, &[1, 2]);
        let equiv_proof = DaFraudProof {
            header: honest_hdr,
            signatures: eq_primary_sigs,
            kind: DaFraudKind::HeaderEquivocation {
                conflicting_header: bad_hdr,
                conflicting_signatures: eq_secondary_sigs,
            },
        };
        let eq_verdict = verify_da_fraud_proof(network, &pinned, &equiv_proof).expect("equivoc");
        assert_eq!(
            eq_verdict.slashable_signers,
            vec![keys[2].0.public_key_bytes()]
        );
        assert_eq!(eq_verdict.slashed_weight, 100);
        assert!(eq_verdict.quorum_safety_breached);
    }

    #[test]
    fn regression_skewed_stake_and_future_height() {
        use crate::domain::finality_proof_model::FinalityProofShape;

        let (mut pinned, mut bundle, mut ev) = da_2x2_fixture();
        // Skewed stake [800, 100, 100, 100] (800/1100 > 2/3) signed by validator 0 alone.
        pinned.members.first_mut().expect("member 0").voting_weight = 800;
        bundle.signatures.truncate(1);
        ev.payload = encode_da_evidence(&bundle).expect("encode skewed");

        let adapter = DataAvailabilityAdapter::new("celestia-mainnet", Some(pinned));
        let policy = VerificationPolicy::strict(505);
        let att = adapter
            .verify(&ev, &policy)
            .expect("single >2/3 DA validator verifies");
        FinalityProofShape::from_external_attestation(&adapter.descriptor(), &att)
            .expect("skewed >2/3 DA quorum must pass FinalityProofShape");

        // Future header.height > policy.now when policy.max_age > 0 must return Stale.
        let mut future_policy = policy;
        future_policy.max_age = 10;
        future_policy.now = bundle.header.height - 1;
        assert!(
            matches!(
                adapter.verify(&ev, &future_policy),
                Err(AdapterError::Stale {
                    age: 1,
                    max_age: 10
                })
            ),
            "future DA header height above policy.now must fail closed with AdapterError::Stale"
        );
    }

    #[test]
    fn da_fraud_proof_refuses_same_data_root_reproposal_and_invalid_pinned_policy() {
        let network = "celestia-mainnet";
        let namespace_id = [0x42; 32];
        let keys: Vec<(KeyPair, PqKeyPair)> = (0..3)
            .map(|_| (KeyPair::generate().expect("ek"), PqKeyPair::generate()))
            .collect();
        let members: Vec<DaCommitteeMember> = keys
            .iter()
            .map(|(ek, pk)| DaCommitteeMember {
                ed25519_pubkey: ek.public_key_bytes(),
                voting_weight: 100,
                pq_pubkey: pk.public_key_bytes().to_vec(),
            })
            .collect();
        let pinned = PinnedDaCommittee {
            namespace_id,
            min_samples: 2,
            min_square_size: 4,
            members,
        };
        let sign_for_ns = |hdr: &DaHeader, ns: &Hash32, idxs: &[usize]| -> Vec<DaAttestationSig> {
            let vote = da_header_sign_bytes(network, hdr, ns);
            idxs.iter()
                .map(|&i| DaAttestationSig {
                    signer_pubkey: keys[i].0.public_key_bytes(),
                    ed25519_sig: keys[i].0.sign(&vote).to_vec(),
                    pq_sig: keys[i]
                        .1
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &vote)
                        .expect("pq sign"),
                })
                .collect()
        };

        let nmt_root = [0x61; 32];
        let rr = [0x62; 32];
        let cr = [0x63; 32];
        let round0_hdr = DaHeader {
            height: 900,
            time_secs: 1_750_000_000,
            square_size: 4,
            nmt_roots_root: nmt_root,
            row_roots_root: rr,
            col_roots_root: cr,
            data_root: compute_da_data_root(4, &nmt_root, &rr, &cr),
        };
        // Honest BFT round-1 timeout re-proposal of the exact same data_root at a newer timestamp
        // commits to the exact same 2D square and MUST NOT slash honest committee signers.
        let round1_hdr = DaHeader {
            time_secs: round0_hdr.time_secs + 6,
            ..round0_hdr.clone()
        };
        let non_conflicting = DaFraudProof {
            header: round0_hdr.clone(),
            signatures: sign_for_ns(&round0_hdr, &namespace_id, &[0, 1, 2]),
            kind: DaFraudKind::HeaderEquivocation {
                conflicting_header: round1_hdr.clone(),
                conflicting_signatures: sign_for_ns(&round1_hdr, &namespace_id, &[0, 1, 2]),
            },
        };
        let reproposal_err = verify_da_fraud_proof(network, &pinned, &non_conflicting)
            .expect_err("honest round re-proposal with identical data_root must not slash");
        assert!(matches!(reproposal_err, AdapterError::ConsensusRule { .. }));

        // Zero namespace_id in PinnedDaCommittee must be refused just like DataAvailabilityAdapter::verify.
        let mut zero_ns_pinned = pinned.clone();
        zero_ns_pinned.namespace_id = [0u8; 32];
        let alt_cr = [0x64; 32];
        let forked_hdr = DaHeader {
            col_roots_root: alt_cr,
            data_root: compute_da_data_root(4, &nmt_root, &rr, &alt_cr),
            ..round0_hdr.clone()
        };
        let zero_ns_proof = DaFraudProof {
            header: round0_hdr.clone(),
            signatures: sign_for_ns(&round0_hdr, &[0u8; 32], &[0, 1]),
            kind: DaFraudKind::HeaderEquivocation {
                conflicting_header: forked_hdr,
                conflicting_signatures: sign_for_ns(
                    &DaHeader {
                        col_roots_root: alt_cr,
                        data_root: compute_da_data_root(4, &nmt_root, &rr, &alt_cr),
                        ..round0_hdr
                    },
                    &[0u8; 32],
                    &[0, 1],
                ),
            },
        };
        let zero_ns_err = verify_da_fraud_proof(network, &zero_ns_pinned, &zero_ns_proof)
            .expect_err("zero namespace_id in pinned DA committee must fail closed");
        assert!(matches!(zero_ns_err, AdapterError::ConsensusRule { .. }));

        // Header square_size below pinned.min_square_size must also fail closed.
        let sub_square_hdr = DaHeader {
            height: 901,
            time_secs: 1_750_000_010,
            square_size: 2,
            nmt_roots_root: nmt_root,
            row_roots_root: rr,
            col_roots_root: cr,
            data_root: compute_da_data_root(2, &nmt_root, &rr, &cr),
        };
        let sub_square_fork = DaHeader {
            col_roots_root: alt_cr,
            data_root: compute_da_data_root(2, &nmt_root, &rr, &alt_cr),
            ..sub_square_hdr.clone()
        };
        let sub_square_proof = DaFraudProof {
            header: sub_square_hdr.clone(),
            signatures: sign_for_ns(&sub_square_hdr, &namespace_id, &[0, 1]),
            kind: DaFraudKind::HeaderEquivocation {
                conflicting_header: sub_square_fork.clone(),
                conflicting_signatures: sign_for_ns(&sub_square_fork, &namespace_id, &[0, 1]),
            },
        };
        let sub_square_err = verify_da_fraud_proof(network, &pinned, &sub_square_proof)
            .expect_err("DA fraud proof square_size below pinned.min_square_size must fail closed");
        assert!(matches!(sub_square_err, AdapterError::ConsensusRule { .. }));
    }
}
