//! Stake-weighted round-DAG BFT (`Narwhal` / `Bullshark` / `Mysticeti`)
//! external finality adapter verifying causal DAG availability certificates
//! and wave-anchor commit quorums.
//!
//! Under Spiegelman et al. (`Bullshark`, CCS 2022) and Danezis et al.
//! (`Narwhal`, `EuroSys` 2022), validators build a round-structured Directed
//! Acyclic Graph whose vertices separate data dissemination from deterministic
//! ordering. An anchor vertex `A` at even wave round `r >= 2` is irrevocably
//! committed once all four properties hold under a governance-pinned epoch
//! committee of total stake `S`:
//!
//! 1. **Self-derived anchor integrity**: `A` is authored by an active committee
//!    member at even round `r >= 2` in the pinned epoch, and its digest equals
//!    the canonical domain-separated hash over `(network, epoch, round, author,
//!    timestamp_secs, state_root, tx_root, event_root, sorted_parent_digests)`.
//! 2. **Causal history quorum (round `r - 1`)**: `A`'s parent references open
//!    to distinct certified round `r - 1` vertices authored by distinct
//!    committee validators whose combined stake strictly exceeds `2/3 * S`.
//! 3. **Anchor availability certificate (round `r`)**: strictly more than
//!    `2/3 * S` committee stake signs `A.digest` (guaranteeing non-equivocation
//!    and data availability of the anchor batch).
//! 4. **Wave commit quorum (round `r + 1`)**: distinct round `r + 1` voter
//!    vertices authored and signed by distinct committee validators with total
//!    stake strictly exceeding `2/3 * S` each include `A.digest` in their
//!    strictly ordered causal parent edge list.
//!
//! Every validator with a registered ML-DSA-65 public key MUST attach a valid
//! ML-DSA-65 co-signature under [`crate::crypto::ctx::CROSS_DOMAIN_V1`];
//! classical-only stripping is refused fail-closed.

use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter name for stake-weighted round-DAG BFT finality.
pub(crate) const ADAPTER_NAME: &str = "bullshark-dag-v1";
/// Adapter implementation version.
const ADAPTER_VERSION: u32 = 1;
/// Wire evidence version accepted by [`BullsharkDagAdapter`].
const EVIDENCE_VERSION: u32 = 1;
/// Two-round wave commit depth (even anchor round `r` + voter round `r + 1`).
const WAVE_COMMIT_DEPTH: u64 = 2;

const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMDG01";
const MAX_DAG_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_DAG_COMMITTEE: usize = 256;
const MAX_VERTEX_PARENTS: usize = 256;

/// One bonded validator in a governance-pinned round-DAG BFT committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagBftValidator {
    /// Classical Ed25519 verifying key (32 bytes).
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero bonded voting weight.
    pub voting_weight: u64,
    /// Optional ML-DSA-65 post-quantum public key; when non-empty, every
    /// certificate and voter vertex signature MUST include a valid ML-DSA-65
    /// co-signature.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned epoch validator set for a stake-weighted DAG-BFT domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedDagCommittee {
    /// Consensus epoch served by this committee.
    pub epoch: u64,
    /// Bonded validators for `epoch`.
    pub members: Vec<DagBftValidator>,
}

/// One validator signature inside an availability certificate or voter vertex.
///
/// WIRING: Verified by [`BullsharkDagAdapter`] and [`verify_dag_equivocation_proof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagBftSig {
    pub signer_pubkey: [u8; 32],
    pub ed25519_sig: Vec<u8>,
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Summary of a round `r - 1` causal parent referenced by the wave anchor.
///
/// WIRING: Causal ancestry witness in [`DagWaveCommitEvidence`] and [`DagEquivocationProof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagCausalParent {
    pub round: u64,
    pub author: [u8; 32],
    pub payload_root: Hash32,
    pub digest: Hash32,
    pub author_ed25519_sig: Vec<u8>,
    #[serde(default)]
    pub author_pq_sig: Vec<u8>,
}

impl DagCausalParent {
    /// Canonical self-derived digest of a round `r - 1` causal parent header.
    #[must_use]
    pub(crate) fn compute_digest(&self, network: &str, epoch: u64) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_DAGBFT_PARENT_V1",
            network.as_bytes(),
            &epoch.to_le_bytes(),
            &self.round.to_le_bytes(),
            &self.author,
            &self.payload_root,
        ])
    }
}

/// Even-round Bullshark wave anchor vertex committing state, tx, and event roots.
///
/// WIRING: Anchor commitment in [`DagWaveCommitEvidence`] and [`DagIndirectWaveCommitProof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagAnchorVertex {
    pub epoch: u64,
    pub round: u64,
    pub author: [u8; 32],
    pub timestamp_secs: u64,
    pub state_root: Hash32,
    pub tx_root: Hash32,
    pub event_root: Hash32,
    /// Strictly ascending canonical parent digests in round `r - 1`.
    pub parent_digests: Vec<Hash32>,
    pub digest: Hash32,
}

impl DagAnchorVertex {
    /// Canonical self-derived anchor vertex digest.
    #[must_use]
    pub(crate) fn compute_digest(&self, network: &str) -> Hash32 {
        let parent_fold = fold_sorted_digests(&self.parent_digests);
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_DAGBFT_VERTEX_V1",
            network.as_bytes(),
            &self.epoch.to_le_bytes(),
            &self.round.to_le_bytes(),
            &self.author,
            &self.timestamp_secs.to_le_bytes(),
            &self.state_root,
            &self.tx_root,
            &self.event_root,
            &parent_fold,
        ])
    }
}

/// Round `r + 1` voter vertex with a direct causal edge to the anchor vertex.
///
/// WIRING: Wave-quorum and causal-relay witness in [`BullsharkDagAdapter`],
/// [`verify_indirect_dag_wave_commit`], and [`verify_dag_equivocation_proof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagVoterVertex {
    pub round: u64,
    pub author: [u8; 32],
    /// Strictly ascending round `r` parent digests (MUST contain `anchor.digest`).
    pub parent_digests: Vec<Hash32>,
    pub digest: Hash32,
    pub ed25519_sig: Vec<u8>,
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

impl DagVoterVertex {
    /// Canonical self-derived voter vertex digest.
    #[must_use]
    pub(crate) fn compute_digest(&self, network: &str, epoch: u64) -> Hash32 {
        let parent_fold = fold_sorted_digests(&self.parent_digests);
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_DAGBFT_VOTE_V1",
            network.as_bytes(),
            &epoch.to_le_bytes(),
            &self.round.to_le_bytes(),
            &self.author,
            &parent_fold,
        ])
    }
}

/// Complete Bullshark round-DAG finality bundle committing `anchor`.
///
/// WIRING: Wire body verified by [`BullsharkDagAdapter`] and [`verify_indirect_dag_wave_commit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagWaveCommitEvidence {
    pub anchor: DagAnchorVertex,
    pub causal_parents: Vec<DagCausalParent>,
    pub anchor_cert_sigs: Vec<DagBftSig>,
    pub voter_vertices: Vec<DagVoterVertex>,
}

fn fold_sorted_digests(digests: &[Hash32]) -> Hash32 {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(1 + digests.len());
    parts.push(b"BDLM_DAGBFT_EDGES_V1");
    for d in digests {
        parts.push(d.as_slice());
    }
    crate::core::hash::hash_fields_bytes(&parts)
}

fn is_strictly_ascending(digests: &[Hash32]) -> bool {
    digests
        .windows(2)
        .all(|pair| match (pair.first(), pair.get(1)) {
            (Some(a), Some(b)) => a < b,
            _ => false,
        })
}

/// Canonical domain-separated message signed by validators certifying `anchor`.
#[must_use]
/// WIRING: canonical DAG anchor-certificate signing bytes verified by `verify_dag_equivocation_proof` and `external_tx` tests.
pub(crate) fn dag_anchor_cert_sign_bytes(
    network: &str,
    epoch: u64,
    round: u64,
    anchor_digest: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_DAGBFT_CERT_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &round.to_le_bytes(),
        anchor_digest,
    ])
}

fn verify_member_sig(
    member: &DagBftValidator,
    msg: &[u8],
    ed_sig: &[u8],
    pq_sig: &[u8],
    what: &str,
) -> Result<bool, AdapterError> {
    crate::crypto::primitives::verify_signature(msg, ed_sig, &member.ed25519_pubkey).map_err(
        |_| AdapterError::Crypto {
            what: format!("invalid Ed25519 signature on {what}"),
        },
    )?;
    if member.pq_pubkey.is_empty() {
        Ok(false)
    } else {
        if pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: format!("missing mandatory ML-DSA-65 co-signature on {what}"),
            });
        }
        crate::crypto::primitives::PqKeyPair::verify(
            &member.pq_pubkey,
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            msg,
            pq_sig,
        )
        .map_err(|_| AdapterError::Crypto {
            what: format!("invalid ML-DSA-65 co-signature on {what}"),
        })?;
        Ok(true)
    }
}

/// Canonical wire payload of a wave-commit bundle: the magic prefix the
/// decoder requires, then the bincode body, under the payload ceiling.
///
/// Convenience: exposed for the fault-proof test in `external_tx`, which
/// registers a Bullshark domain from a golden sample in this exact encoding.
pub(crate) fn encode_dag_evidence(bundle: &DagWaveCommitEvidence) -> Result<Vec<u8>, String> {
    let body = bincode::serialize(bundle).map_err(|e| format!("DAG-BFT encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_DAG_PAYLOAD_BYTES {
        return Err(format!(
            "DAG-BFT payload size {total} exceeds ceiling {MAX_DAG_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_dag_evidence(payload: &[u8]) -> Result<DagWaveCommitEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "DAG-BFT payload shorter than 8-byte magic prefix".into(),
        });
    }
    if payload.len() > MAX_DAG_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_DAG_PAYLOAD_BYTES,
            reason: format!("DAG-BFT payload exceeds {MAX_DAG_PAYLOAD_BYTES} bytes"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "DAG-BFT payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing DAG-BFT payload body".into(),
    })?;
    let decoded =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_DAG_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("invalid DAG-BFT wave evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical DAG-BFT wave evidence".to_string(),
        });
    }
    Ok(decoded)
}

/// External finality adapter for stake-weighted round-DAG BFT (`Bullshark`).
pub struct BullsharkDagAdapter {
    network: String,
    pinned: Option<PinnedDagCommittee>,
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

impl BullsharkDagAdapter {
    /// Construct a `BullsharkDagAdapter` bound to `network` and its pinned committee.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedDagCommittee>) -> Self {
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
                consensus_kind: "bullshark-round-dag-bft".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                required_depth: WAVE_COMMIT_DEPTH,
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
        if evidence.evidence_version != EVIDENCE_VERSION && evidence.evidence_version != 2 {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: "1,2".into(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "DAG-BFT evidence network '{}' does not match pinned network '{}'",
                    evidence.network, self.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no pinned DAG-BFT committee; admission is closed".into(),
            });
        };
        if evidence.evidence_version == 2 {
            let indirect = decode_indirect_dag_evidence(&evidence.payload)?;
            if policy.require_declared_match {
                if evidence.declared_height != indirect.target_anchor.round {
                    return Err(AdapterError::DeclarationMismatch { field: "height" });
                }
                if !bool::from(
                    evidence
                        .declared_root
                        .ct_eq(&indirect.target_anchor.state_root),
                ) {
                    return Err(AdapterError::DeclarationMismatch { field: "root" });
                }
            }
            let att = verify_indirect_dag_wave_commit(&self.network, pinned, &indirect, policy)?;
            let pq = matches!(
                att.security,
                SecurityBacking::SignatureSet {
                    scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                    ..
                }
            );
            return Ok((att, pq));
        }
        if pinned.members.is_empty() || pinned.members.len() > MAX_DAG_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned DAG-BFT committee size outside valid bounds".into(),
            });
        }

        let mut member_map = BTreeMap::new();
        let mut total_stake = 0u128;
        for m in &pinned.members {
            if m.ed25519_pubkey == [0u8; 32] || m.voting_weight == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "pinned DAG-BFT committee has zero pubkey or zero voting weight".into(),
                });
            }
            if member_map.insert(m.ed25519_pubkey, m).is_some() {
                return Err(AdapterError::ConsensusRule {
                    rule: "pinned DAG-BFT committee contains duplicate pubkey".into(),
                });
            }
            total_stake = total_stake
                .checked_add(u128::from(m.voting_weight))
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "pinned DAG-BFT committee voting weight overflows u128".into(),
                })?;
        }

        let bundle = decode_dag_evidence(&evidence.payload)?;
        let anchor = &bundle.anchor;

        if policy.require_declared_match {
            if evidence.declared_height != anchor.round {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&anchor.state_root)) {
                return Err(AdapterError::DeclarationMismatch { field: "root" });
            }
        }
        if policy.min_depth > WAVE_COMMIT_DEPTH {
            return Err(AdapterError::InsufficientDepth {
                observed: WAVE_COMMIT_DEPTH,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 {
            if anchor.round > policy.now {
                return Err(AdapterError::Stale {
                    age: anchor.round - policy.now,
                    max_age: policy.max_age,
                });
            }
            let age = policy.now - anchor.round;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // 1. Verify even wave anchor round >= 2, epoch, committee author, and canonical digest.
        if anchor.epoch != pinned.epoch {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "DAG anchor epoch {} does not match pinned epoch {}",
                    anchor.epoch, pinned.epoch
                ),
            });
        }
        if anchor.round < 2 || anchor.round % 2 != 0 {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Bullshark anchor round {} must be an even wave round >= 2",
                    anchor.round
                ),
            });
        }
        if anchor.state_root == [0u8; 32] || !member_map.contains_key(&anchor.author) {
            return Err(AdapterError::ConsensusRule {
                rule: "DAG anchor carries zero state_root or non-committee leader author".into(),
            });
        }
        // Deterministic Bullshark/Mysticeti wave-leader rule: each even round r in
        // `(network, epoch)` maps to a single stake-weighted leader, preventing two
        // distinct honest round-r vertices from finalizing conflicting roots.
        let expected_leader = elect_dag_wave_leader(&self.network, pinned, anchor.round)?;
        if !bool::from(anchor.author.ct_eq(&expected_leader)) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "DAG anchor author is not the deterministic wave leader for round {}",
                    anchor.round
                ),
            });
        }
        if anchor.parent_digests.is_empty()
            || anchor.parent_digests.len() > MAX_VERTEX_PARENTS
            || !is_strictly_ascending(&anchor.parent_digests)
        {
            return Err(AdapterError::ConsensusRule {
                rule: "DAG anchor parent_digests must be non-empty, bounded, and strictly sorted"
                    .into(),
            });
        }
        let expected_anchor = anchor.compute_digest(&self.network);
        if !bool::from(anchor.digest.ct_eq(&expected_anchor)) {
            return Err(AdapterError::ConsensusRule {
                rule: "DAG anchor digest does not match canonical vertex fields".into(),
            });
        }

        // 2. Verify round `r - 1` causal parents referenced by `anchor` span > 2/3 stake.
        let parent_round = anchor.round - 1;
        if bundle.causal_parents.len() != anchor.parent_digests.len() {
            return Err(AdapterError::ConsensusRule {
                rule: "DAG causal_parents list does not match anchor parent_digests count".into(),
            });
        }
        let mut parent_authors = BTreeSet::new();
        let mut opened_parent_digests = Vec::with_capacity(bundle.causal_parents.len());
        let mut parent_stake = 0u128;
        let mut all_pq = true;

        for parent in &bundle.causal_parents {
            if parent.round != parent_round {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "DAG causal parent round {} is not anchor.round - 1 ({parent_round})",
                        parent.round
                    ),
                });
            }
            if !parent_authors.insert(parent.author) {
                return Err(AdapterError::ConsensusRule {
                    rule: "equivocating or duplicate author in round r - 1 causal parents".into(),
                });
            }
            let Some(member) = member_map.get(&parent.author) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "round r - 1 causal parent authored by non-committee key".into(),
                });
            };
            let expected_p = parent.compute_digest(&self.network, pinned.epoch);
            if !bool::from(parent.digest.ct_eq(&expected_p)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "round r - 1 causal parent digest mismatch".into(),
                });
            }
            let pq_ok = verify_member_sig(
                member,
                &parent.digest,
                &parent.author_ed25519_sig,
                &parent.author_pq_sig,
                "DAG causal parent",
            )?;
            all_pq &= pq_ok;
            opened_parent_digests.push(parent.digest);
            parent_stake = parent_stake.saturating_add(u128::from(member.voting_weight));
        }
        opened_parent_digests.sort_unstable();
        if opened_parent_digests != anchor.parent_digests {
            return Err(AdapterError::ConsensusRule {
                rule: "opened causal parents do not match anchor.parent_digests exactly".into(),
            });
        }
        if parent_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "DAG anchor causal parent stake {parent_stake}/{total_stake} does not exceed 2/3"
                ),
            });
        }

        // 3. Verify round `r` Narwhal availability certificate over `anchor.digest` (> 2/3 stake).
        if bundle.anchor_cert_sigs.is_empty() || bundle.anchor_cert_sigs.len() > MAX_DAG_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: "DAG anchor availability certificate signature count invalid".into(),
            });
        }
        let cert_msg =
            dag_anchor_cert_sign_bytes(&self.network, anchor.epoch, anchor.round, &anchor.digest);
        let mut cert_signers = BTreeSet::new();
        let mut cert_stake = 0u128;
        for sig in &bundle.anchor_cert_sigs {
            if !cert_signers.insert(sig.signer_pubkey) {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate signer in DAG anchor availability certificate".into(),
                });
            }
            let Some(member) = member_map.get(&sig.signer_pubkey) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "non-committee signer in DAG anchor availability certificate".into(),
                });
            };
            let pq_ok = verify_member_sig(
                member,
                &cert_msg,
                &sig.ed25519_sig,
                &sig.pq_sig,
                "DAG anchor availability cert",
            )?;
            all_pq &= pq_ok;
            cert_stake = cert_stake.saturating_add(u128::from(member.voting_weight));
        }
        if cert_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "DAG anchor availability stake {cert_stake}/{total_stake} does not exceed 2/3"
                ),
            });
        }

        // 4. Verify Bullshark round `r + 1` voter vertices linking to `anchor.digest` (> 2/3 stake).
        let voter_round =
            anchor
                .round
                .checked_add(1)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "DAG anchor round overflows u64".into(),
                })?;
        if bundle.voter_vertices.is_empty() || bundle.voter_vertices.len() > MAX_DAG_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: "DAG wave voter vertex count outside valid bounds".into(),
            });
        }
        let mut voter_authors = BTreeSet::new();
        let mut vote_stake = 0u128;
        for voter in &bundle.voter_vertices {
            if voter.round != voter_round {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "DAG voter vertex round {} is not anchor.round + 1 ({voter_round})",
                        voter.round
                    ),
                });
            }
            if !voter_authors.insert(voter.author) {
                return Err(AdapterError::ConsensusRule {
                    rule: "equivocating or duplicate author in round r + 1 voter vertices".into(),
                });
            }
            let Some(member) = member_map.get(&voter.author) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "round r + 1 voter vertex authored by non-committee key".into(),
                });
            };
            if voter.parent_digests.is_empty()
                || voter.parent_digests.len() > MAX_VERTEX_PARENTS
                || !is_strictly_ascending(&voter.parent_digests)
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "round r + 1 voter parent_digests invalid or unsorted".into(),
                });
            }
            if voter.parent_digests.binary_search(&anchor.digest).is_err() {
                return Err(AdapterError::ConsensusRule {
                    rule: "round r + 1 voter vertex lacks causal edge to anchor.digest".into(),
                });
            }
            let expected_v = voter.compute_digest(&self.network, pinned.epoch);
            if !bool::from(voter.digest.ct_eq(&expected_v)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "round r + 1 voter vertex digest mismatch".into(),
                });
            }
            let pq_ok = verify_member_sig(
                member,
                &voter.digest,
                &voter.ed25519_sig,
                &voter.pq_sig,
                "DAG wave voter vertex",
            )?;
            all_pq &= pq_ok;
            vote_stake = vote_stake.saturating_add(u128::from(member.voting_weight));
        }
        if vote_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Bullshark wave voter stake {vote_stake}/{total_stake} does not exceed 2/3"
                ),
            });
        }

        let min_signers = u64::try_from(cert_signers.len())
            .unwrap_or(u64::MAX)
            .min(u64::try_from(voter_authors.len()).unwrap_or(u64::MAX));
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
            height: anchor.round,
            state_root: anchor.state_root,
            finalized_at: anchor.round,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers: min_signers,
                required: required_signers,
                total_weight: total_stake,
                slashable: true,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(anchor.digest),
            attested_event_root: Some(anchor.event_root),
            attested_tx_root: Some(anchor.tx_root),
        };
        Ok((att, all_pq))
    }
}

impl ExternalFinalityAdapter for BullsharkDagAdapter {
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
                name: "refuses unknown DAG-BFT evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 7 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign DAG-BFT network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-other", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared DAG round".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared DAG state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted DAG payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xFF, 0xFF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated DAG anchor epoch".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0x7F],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted DAG voter vertex signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail_offset,
                    bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated DAG payload".into(),
                patch: BytePatch::TruncatePayload { keep: 3 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

type CommitteeIndex<'a> = (BTreeMap<[u8; 32], &'a DagBftValidator>, u128, Hash32);

fn canonical_committee_map(
    pinned: &PinnedDagCommittee,
) -> Result<CommitteeIndex<'_>, AdapterError> {
    if pinned.members.is_empty() || pinned.members.len() > MAX_DAG_COMMITTEE {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "pinned DAG committee size {} outside 1..={MAX_DAG_COMMITTEE}",
                pinned.members.len()
            ),
        });
    }
    let mut map = BTreeMap::new();
    let mut total = 0u128;
    for m in &pinned.members {
        if m.ed25519_pubkey == [0u8; 32] || m.voting_weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned DAG committee has zero pubkey or zero voting_weight".into(),
            });
        }
        if map.insert(m.ed25519_pubkey, m).is_some() {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned DAG committee contains duplicate pubkey".into(),
            });
        }
        total = total
            .checked_add(u128::from(m.voting_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "pinned DAG committee stake overflows u128".into(),
            })?;
    }
    // Canonical committee digest over sorted pubkeys (order-invariant across input Vecs).
    let mut running = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_DAGBFT_COMMITTEE_V1",
        &pinned.epoch.to_le_bytes(),
        &(map.len() as u64).to_le_bytes(),
    ]);
    for (pk, m) in &map {
        let w = m.voting_weight.to_le_bytes();
        running = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_DAGBFT_MEMBER_V1",
            &running,
            pk,
            &w,
            &m.pq_pubkey,
        ]);
    }
    Ok((map, total, running))
}

/// Deterministically elect the unique stake-weighted Bullshark/Mysticeti wave
/// leader for an even wave `round` in `(network, pinned.epoch)`.
///
/// Order-invariant over `pinned.members` and pure-integer (no floats or RNG).
///
/// # Errors
///
/// Returns [`AdapterError::ConsensusRule`] when `network` is empty, `round` is
/// odd or `< 2`, or `pinned` is malformed.
///
/// WIRING: Enforced by [`BullsharkDagAdapter`] and [`verify_indirect_dag_wave_commit`]
/// to guarantee unique anchor finality per wave round.
pub fn elect_dag_wave_leader(
    network: &str,
    pinned: &PinnedDagCommittee,
    round: u64,
) -> Result<[u8; 32], AdapterError> {
    if network.trim().is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "DAG leader schedule requires non-empty network".into(),
        });
    }
    if round < 2 || !round.is_multiple_of(2) {
        return Err(AdapterError::ConsensusRule {
            rule: format!("DAG wave leader round {round} must be an even round >= 2"),
        });
    }
    let (map, total_stake, committee_root) = canonical_committee_map(pinned)?;
    let seed = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_DAGBFT_LEADER_V1",
        network.as_bytes(),
        &pinned.epoch.to_le_bytes(),
        &round.to_le_bytes(),
        &committee_root,
    ]);
    let mut ticket_bytes = [0u8; 16];
    if let Some(prefix) = seed.get(..16) {
        ticket_bytes.copy_from_slice(prefix);
    }
    let ticket = u128::from_le_bytes(ticket_bytes) % total_stake;
    let mut cumulative = 0u128;
    for (pk, member) in &map {
        cumulative = cumulative.saturating_add(u128::from(member.voting_weight));
        if ticket < cumulative {
            return Ok(*pk);
        }
    }
    map.keys()
        .next()
        .copied()
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "empty DAG committee during leader election".into(),
        })
}

/// Indirect Bullshark/Mysticeti two-wave commit proof for an even round `r`.
///
/// Finalizes `target_anchor` whose direct round `r + 1` votes missed quorum
/// via a certified causal path from a directly committed round `r + 2` anchor.
///
/// WIRING: Version-2 wire payload verified by [`BullsharkDagAdapter`] and
/// [`verify_indirect_dag_wave_commit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagIndirectWaveCommitProof {
    /// Target even-round anchor at round `r` being finalized indirectly.
    pub target_anchor: DagAnchorVertex,
    /// Certified round `r - 1` causal parents proving `> 2/3` causal history.
    pub target_causal_parents: Vec<DagCausalParent>,
    /// Availability certificate (`> 2/3` committee stake) over `target_anchor`.
    pub target_cert_sigs: Vec<DagBftSig>,
    /// Certified round `r + 1` relay vertex referencing `target_anchor.digest`
    /// and matching a certified causal parent of `committing_wave.anchor` (`r + 2`).
    pub relay_vertex: DagVoterVertex,
    /// Payload root binding `relay_vertex.digest` into `committing_wave.causal_parents`.
    pub committing_wave: DagWaveCommitEvidence,
    /// Submitter address recorded on the resulting finality attestation.
    pub submitter: crate::core::address::Address,
}

const INDIRECT_DAG_MAGIC: &[u8; 8] = b"BDLMDGI2";

fn decode_indirect_dag_evidence(bytes: &[u8]) -> Result<DagIndirectWaveCommitProof, AdapterError> {
    if bytes.is_empty() || bytes.len() > MAX_DAG_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: format!("indirect DAG-BFT payload len {} out of bounds", bytes.len()),
        });
    }
    if bytes.get(..8) != Some(INDIRECT_DAG_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "missing indirect DAG-BFT evidence magic".into(),
        });
    }
    let body = bytes.get(8..).unwrap_or(&[]);
    let proof: DagIndirectWaveCommitProof =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_DAG_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("indirect DAG-BFT bincode decode failed: {e}"),
            })?;
    if bincode::serialized_size(&proof).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after indirect DAG-BFT evidence".into(),
        });
    }
    Ok(proof)
}

/// Verify an indirect two-wave Bullshark/Mysticeti finality proof.
///
/// Confirms that `committing_wave` directly finalizes canonical leader `A_{r+2}`
/// and carries an authenticated causal path `A_{r+2} -> relay_{r+1} -> A_r`.
///
/// # Errors
///
/// Returns [`AdapterError`] if either wave leader mismatches, any availability
/// or causal quorum is `<= 2/3`, any signature fails, or the causal bridge
/// between `A_{r+2}`, `relay_{r+1}`, and `A_r` is broken.
///
/// WIRING: Asynchronous liveness continuation for [`BullsharkDagAdapter`] domains.
pub fn verify_indirect_dag_wave_commit(
    network: &str,
    pinned: &PinnedDagCommittee,
    proof: &DagIndirectWaveCommitProof,
    policy: &VerificationPolicy,
) -> Result<FinalityAttestation, AdapterError> {
    let target = &proof.target_anchor;
    let commit_round = target
        .round
        .checked_add(2)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "indirect DAG anchor round overflows u64".into(),
        })?;
    if proof.committing_wave.anchor.round != commit_round {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "indirect DAG committing anchor round {} must equal target round + 2 ({commit_round})",
                proof.committing_wave.anchor.round
            ),
        });
    }
    // 1. Verify full direct wave finality of round `r + 2` committing anchor.
    let adapter = BullsharkDagAdapter::new(network, Some(pinned.clone()));
    let direct_raw = RawConsensusEvidence {
        adapter: AdapterId::from_name(ADAPTER_NAME),
        evidence_version: EVIDENCE_VERSION,
        network: network.to_string(),
        payload: encode_dag_evidence(&proof.committing_wave)
            .map_err(|reason| AdapterError::Malformed { offset: 0, reason })?,
        declared_height: proof.committing_wave.anchor.round,
        declared_root: proof.committing_wave.anchor.state_root,
        submitter: proof.submitter,
    };
    let direct_att = adapter.verify(&direct_raw, policy)?;
    if policy.max_age > 0 {
        if target.round > policy.now {
            return Err(AdapterError::Stale {
                age: target.round - policy.now,
                max_age: policy.max_age,
            });
        }
        let target_age = policy.now - target.round;
        if target_age > policy.max_age {
            return Err(AdapterError::Stale {
                age: target_age,
                max_age: policy.max_age,
            });
        }
    }
    let (direct_signers, direct_pq) = match direct_att.security {
        SecurityBacking::SignatureSet {
            signers, scheme, ..
        } => (
            signers,
            scheme == ObservedScheme::Scheme(SchemeId::ML_DSA_65),
        ),
        _ => (0, false),
    };

    // 2. Verify target round-r anchor canonical leader, digest, >2/3 parents, and >2/3 cert.
    let (member_map, total_stake, _) = canonical_committee_map(pinned)?;
    if target.epoch != pinned.epoch || target.state_root == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "indirect target DAG anchor has wrong epoch or zero state_root".into(),
        });
    }
    let expected_leader = elect_dag_wave_leader(network, pinned, target.round)?;
    if !bool::from(target.author.ct_eq(&expected_leader)) {
        return Err(AdapterError::ConsensusRule {
            rule: "indirect target DAG anchor is not the canonical wave leader".into(),
        });
    }
    if target.parent_digests.is_empty()
        || target.parent_digests.len() > MAX_VERTEX_PARENTS
        || !is_strictly_ascending(&target.parent_digests)
    {
        return Err(AdapterError::ConsensusRule {
            rule: "indirect target DAG anchor parent_digests invalid".into(),
        });
    }
    let expected_target = target.compute_digest(network);
    if !bool::from(target.digest.ct_eq(&expected_target)) {
        return Err(AdapterError::ConsensusRule {
            rule: "indirect target DAG anchor digest mismatch".into(),
        });
    }

    let prev_round = target.round - 1;
    let mut parent_authors = BTreeSet::new();
    let mut parent_stake = 0u128;
    let mut all_pq = true;
    for p in &proof.target_causal_parents {
        if p.round != prev_round
            || !parent_authors.insert(p.author)
            || target.parent_digests.binary_search(&p.digest).is_err()
        {
            return Err(AdapterError::ConsensusRule {
                rule: "indirect target DAG causal parent invalid, duplicate, or unreferenced"
                    .into(),
            });
        }
        let Some(m) = member_map.get(&p.author) else {
            return Err(AdapterError::ConsensusRule {
                rule: "indirect target DAG causal parent from unknown validator".into(),
            });
        };
        if !bool::from(p.digest.ct_eq(&p.compute_digest(network, pinned.epoch))) {
            return Err(AdapterError::ConsensusRule {
                rule: "indirect target DAG causal parent digest mismatch".into(),
            });
        }
        all_pq &= verify_member_sig(
            m,
            &p.digest,
            &p.author_ed25519_sig,
            &p.author_pq_sig,
            "indirect DAG causal parent",
        )?;
        parent_stake = parent_stake.saturating_add(u128::from(m.voting_weight));
    }
    if parent_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
        return Err(AdapterError::ConsensusRule {
            rule: "indirect target DAG causal parent stake does not exceed 2/3".into(),
        });
    }

    let cert_msg = dag_anchor_cert_sign_bytes(network, pinned.epoch, target.round, &target.digest);
    let mut cert_signers = BTreeSet::new();
    let mut cert_stake = 0u128;
    for sig in &proof.target_cert_sigs {
        if !cert_signers.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate signer in indirect target DAG certificate".into(),
            });
        }
        let Some(m) = member_map.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: "unknown signer in indirect target DAG certificate".into(),
            });
        };
        all_pq &= verify_member_sig(
            m,
            &cert_msg,
            &sig.ed25519_sig,
            &sig.pq_sig,
            "indirect DAG anchor cert",
        )?;
        cert_stake = cert_stake.saturating_add(u128::from(m.voting_weight));
    }
    if cert_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
        return Err(AdapterError::ConsensusRule {
            rule: "indirect target DAG anchor certificate stake does not exceed 2/3".into(),
        });
    }

    // 3. Verify authenticated round `r + 1` causal relay bridging A_{r+2} -> relay -> A_r.
    let relay = &proof.relay_vertex;
    let relay_round = target.round + 1;
    if relay.round != relay_round
        || relay.parent_digests.is_empty()
        || relay.parent_digests.len() > MAX_VERTEX_PARENTS
        || !is_strictly_ascending(&relay.parent_digests)
        || relay.parent_digests.binary_search(&target.digest).is_err()
    {
        return Err(AdapterError::ConsensusRule {
            rule: "indirect DAG relay vertex fails round, sorting, or edge-to-target check".into(),
        });
    }
    let Some(relay_member) = member_map.get(&relay.author) else {
        return Err(AdapterError::ConsensusRule {
            rule: "indirect DAG relay vertex authored by non-committee validator".into(),
        });
    };
    if !bool::from(
        relay
            .digest
            .ct_eq(&relay.compute_digest(network, pinned.epoch)),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "indirect DAG relay vertex digest mismatch".into(),
        });
    }
    all_pq &= verify_member_sig(
        relay_member,
        &relay.digest,
        &relay.ed25519_sig,
        &relay.pq_sig,
        "indirect DAG relay vertex",
    )?;
    let bridge_included = proof.committing_wave.causal_parents.iter().any(|cp| {
        cp.round == relay_round
            && bool::from(cp.author.ct_eq(&relay.author))
            && bool::from(cp.payload_root.ct_eq(&relay.digest))
            && proof
                .committing_wave
                .anchor
                .parent_digests
                .binary_search(&cp.digest)
                .is_ok()
    });
    if !bridge_included {
        return Err(AdapterError::ConsensusRule {
            rule: "committing round r + 2 anchor does not causally include relay vertex".into(),
        });
    }

    let scheme = if all_pq && direct_pq {
        ObservedScheme::Scheme(SchemeId::ML_DSA_65)
    } else {
        ObservedScheme::Scheme(SchemeId::ED25519)
    };
    let min_signers = direct_signers
        .min(u64::try_from(parent_authors.len()).unwrap_or(u64::MAX))
        .min(u64::try_from(cert_signers.len()).unwrap_or(u64::MAX));
    let required_signers =
        min_signers_for_quorum(pinned.members.iter().map(|m| m.voting_weight), total_stake);
    let evidence_digest = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_DAGBFT_INDIRECT_ATTEST_V1",
        network.as_bytes(),
        &target.digest,
        &relay.digest,
        &proof.committing_wave.anchor.digest,
    ]);
    Ok(FinalityAttestation {
        adapter: adapter.descriptor.id,
        domain: DomainKey::from_parts(&adapter.descriptor.id, network),
        height: target.round,
        state_root: target.state_root,
        finalized_at: proof.committing_wave.anchor.round,
        time_unit: TimeUnit::Height,
        security: SecurityBacking::SignatureSet {
            scheme,
            signers: min_signers,
            required: required_signers,
            total_weight: total_stake,
            slashable: true,
        },
        evidence_digest,
        adapter_version: adapter.descriptor.adapter_version,
        evidence_version: EVIDENCE_VERSION,
        attested_block_hash: Some(target.digest),
        attested_event_root: Some(target.event_root),
        attested_tx_root: Some(target.tx_root),
    })
}

/// Slashable Byzantine equivocation evidence against DAG-BFT committee member(s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DagEquivocationProof {
    /// One or more validators signed availability certificates for two distinct
    /// anchor digests at the exact same `(network, epoch, round)`.
    AnchorCertificate {
        round: u64,
        first_anchor_digest: Hash32,
        first_sigs: Vec<DagBftSig>,
        second_anchor_digest: Hash32,
        second_sigs: Vec<DagBftSig>,
    },
    /// A validator authored and signed two distinct causal-parent vertices in the
    /// exact same `(network, epoch, round)`.
    CausalParent {
        first: DagCausalParent,
        second: DagCausalParent,
    },
    /// A validator authored and signed two distinct wave-voter vertices in the
    /// exact same `(network, epoch, round)`.
    VoterVertex {
        first: DagVoterVertex,
        second: DagVoterVertex,
    },
}

/// Deterministic slash verdict produced by [`verify_dag_equivocation_proof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagSlashVerdict {
    pub epoch: u64,
    pub round: u64,
    pub slashable_validators: Vec<[u8; 32]>,
    pub slashed_weight: u128,
    pub total_committee_weight: u128,
    pub quorum_safety_breached: bool,
}

/// Verify slashable DAG-BFT equivocation (double availability certification or
/// same-round vertex fork) with full Ed25519 + mandatory ML-DSA-65 verification.
///
/// # Errors
///
/// Returns [`AdapterError`] if any signature or digest is invalid, the two
/// signed items do not conflict at the same round, or no committee overlap exists.
///
/// WIRING: Objective slashing verifier for bonded `AdapterSpec::DagCertificate` domains.
pub fn verify_dag_equivocation_proof(
    network: &str,
    pinned: &PinnedDagCommittee,
    proof: &DagEquivocationProof,
) -> Result<DagSlashVerdict, AdapterError> {
    if network.trim().is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "DAG equivocation proof network must be non-empty".into(),
        });
    }
    let (member_map, total_stake, _) = canonical_committee_map(pinned)?;
    let (round, offenders): (u64, Vec<[u8; 32]>) = match proof {
        DagEquivocationProof::AnchorCertificate {
            round,
            first_anchor_digest,
            first_sigs,
            second_anchor_digest,
            second_sigs,
        } => {
            if *round < 2 || !round.is_multiple_of(2) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DAG anchor certificate equivocation requires even round >= 2".into(),
                });
            }
            if bool::from(first_anchor_digest.ct_eq(second_anchor_digest)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DAG anchor certificate digests are identical (no equivocation)".into(),
                });
            }
            let verify_side =
                |digest: &Hash32, sigs: &[DagBftSig]| -> Result<BTreeSet<[u8; 32]>, AdapterError> {
                    if sigs.is_empty() || sigs.len() > MAX_DAG_COMMITTEE {
                        return Err(AdapterError::ConsensusRule {
                            rule: "DAG equivocation signature set empty or over cap".into(),
                        });
                    }
                    let msg = dag_anchor_cert_sign_bytes(network, pinned.epoch, *round, digest);
                    let mut seen = BTreeSet::new();
                    for s in sigs {
                        if !seen.insert(s.signer_pubkey) {
                            return Err(AdapterError::ConsensusRule {
                                rule: "duplicate signer in DAG equivocation proof".into(),
                            });
                        }
                        let Some(m) = member_map.get(&s.signer_pubkey) else {
                            return Err(AdapterError::ConsensusRule {
                                rule: "non-committee signer in DAG equivocation proof".into(),
                            });
                        };
                        let _ = verify_member_sig(
                            m,
                            &msg,
                            &s.ed25519_sig,
                            &s.pq_sig,
                            "DAG cert equivocation",
                        )?;
                    }
                    Ok(seen)
                };
            let a = verify_side(first_anchor_digest, first_sigs)?;
            let b = verify_side(second_anchor_digest, second_sigs)?;
            let overlap: Vec<[u8; 32]> = a.intersection(&b).copied().collect();
            if overlap.is_empty() {
                return Err(AdapterError::ConsensusRule {
                    rule: "no overlapping validator signed both conflicting DAG anchors".into(),
                });
            }
            (*round, overlap)
        }
        DagEquivocationProof::CausalParent { first, second } => {
            if first.round != second.round || !bool::from(first.author.ct_eq(&second.author)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DAG parent equivocation requires identical round and author".into(),
                });
            }
            if !bool::from(
                first
                    .digest
                    .ct_eq(&first.compute_digest(network, pinned.epoch)),
            ) || !bool::from(
                second
                    .digest
                    .ct_eq(&second.compute_digest(network, pinned.epoch)),
            ) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DAG parent equivocation digest mismatch".into(),
                });
            }
            if bool::from(first.digest.ct_eq(&second.digest)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DAG parent vertices are identical (no equivocation)".into(),
                });
            }
            let Some(m) = member_map.get(&first.author) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "DAG parent equivocation cites unknown validator".into(),
                });
            };
            let _ = verify_member_sig(
                m,
                &first.digest,
                &first.author_ed25519_sig,
                &first.author_pq_sig,
                "DAG parent equivocation (first)",
            )?;
            let _ = verify_member_sig(
                m,
                &second.digest,
                &second.author_ed25519_sig,
                &second.author_pq_sig,
                "DAG parent equivocation (second)",
            )?;
            (first.round, vec![first.author])
        }
        DagEquivocationProof::VoterVertex { first, second } => {
            if first.round != second.round || !bool::from(first.author.ct_eq(&second.author)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DAG voter equivocation requires identical round and author".into(),
                });
            }
            for v in [first, second] {
                if v.parent_digests.is_empty()
                    || v.parent_digests.len() > MAX_VERTEX_PARENTS
                    || !is_strictly_ascending(&v.parent_digests)
                    || !bool::from(v.digest.ct_eq(&v.compute_digest(network, pinned.epoch)))
                {
                    return Err(AdapterError::ConsensusRule {
                        rule: "DAG voter equivocation vertex malformed or digest mismatch".into(),
                    });
                }
            }
            if bool::from(first.digest.ct_eq(&second.digest)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "DAG voter vertices are identical (no equivocation)".into(),
                });
            }
            let Some(m) = member_map.get(&first.author) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "DAG voter equivocation cites unknown validator".into(),
                });
            };
            let _ = verify_member_sig(
                m,
                &first.digest,
                &first.ed25519_sig,
                &first.pq_sig,
                "DAG voter equivocation (first)",
            )?;
            let _ = verify_member_sig(
                m,
                &second.digest,
                &second.ed25519_sig,
                &second.pq_sig,
                "DAG voter equivocation (second)",
            )?;
            (first.round, vec![first.author])
        }
    };

    let mut slashed_weight = 0u128;
    for pk in &offenders {
        if let Some(m) = member_map.get(pk) {
            slashed_weight = slashed_weight.saturating_add(u128::from(m.voting_weight));
        }
    }
    Ok(DagSlashVerdict {
        epoch: pinned.epoch,
        round,
        slashable_validators: offenders,
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

    fn dag_wave_fixture() -> (
        PinnedDagCommittee,
        Vec<(KeyPair, PqKeyPair)>,
        DagWaveCommitEvidence,
        RawConsensusEvidence,
    ) {
        let network = "sui-bullshark-1";
        let epoch = 12;
        let anchor_round = 100u64;
        let mut keys = Vec::new();
        let mut members = Vec::new();
        for _ in 0..4 {
            let ek = KeyPair::generate().expect("ed25519");
            let pk = PqKeyPair::generate();
            members.push(DagBftValidator {
                ed25519_pubkey: ek.public_key_bytes(),
                voting_weight: 100,
                pq_pubkey: pk.public_key_bytes().to_vec(),
            });
            keys.push((ek, pk));
        }

        // Build 3 certified round 99 causal parents (300/400 = 75% > 2/3 stake).
        let mut causal_parents = Vec::new();
        for (i, (ek, pk)) in keys.iter().take(3).enumerate() {
            let mut p = DagCausalParent {
                round: anchor_round - 1,
                author: ek.public_key_bytes(),
                payload_root: [(i as u8) + 0x10; 32],
                digest: [0u8; 32],
                author_ed25519_sig: Vec::new(),
                author_pq_sig: Vec::new(),
            };
            p.digest = p.compute_digest(network, epoch);
            p.author_ed25519_sig = ek.sign(&p.digest).to_vec();
            p.author_pq_sig = pk
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &p.digest)
                .expect("pq sign");
            causal_parents.push(p);
        }
        let mut parent_digests: Vec<Hash32> = causal_parents.iter().map(|p| p.digest).collect();
        parent_digests.sort_unstable();

        // Build round 100 even wave anchor vertex authored by the canonical leader.
        let committee = PinnedDagCommittee {
            epoch,
            members: members.clone(),
        };
        let leader =
            elect_dag_wave_leader(network, &committee, anchor_round).expect("elect wave leader");
        let mut anchor = DagAnchorVertex {
            epoch,
            round: anchor_round,
            author: leader,
            timestamp_secs: 1_750_100_000,
            state_root: [0xA1; 32],
            tx_root: [0xA2; 32],
            event_root: [0xA3; 32],
            parent_digests,
            digest: [0u8; 32],
        };
        anchor.digest = anchor.compute_digest(network);

        // Certify anchor availability with 3/4 validators.
        let cert_msg = dag_anchor_cert_sign_bytes(network, epoch, anchor.round, &anchor.digest);
        let anchor_cert_sigs: Vec<DagBftSig> = keys
            .iter()
            .take(3)
            .map(|(ek, pk)| DagBftSig {
                signer_pubkey: ek.public_key_bytes(),
                ed25519_sig: ek.sign(&cert_msg).to_vec(),
                pq_sig: pk
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &cert_msg)
                    .expect("pq sign"),
            })
            .collect();

        // Build 3 round 101 voter vertices each referencing `anchor.digest` plus another edge.
        let mut voter_vertices = Vec::new();
        for (i, (ek, pk)) in keys.iter().skip(1).enumerate() {
            let mut edges = vec![anchor.digest, [(i as u8) + 0x50; 32]];
            edges.sort_unstable();
            edges.dedup();
            let mut v = DagVoterVertex {
                round: anchor_round + 1,
                author: ek.public_key_bytes(),
                parent_digests: edges,
                digest: [0u8; 32],
                ed25519_sig: Vec::new(),
                pq_sig: Vec::new(),
            };
            v.digest = v.compute_digest(network, epoch);
            v.ed25519_sig = ek.sign(&v.digest).to_vec();
            v.pq_sig = pk
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &v.digest)
                .expect("pq sign");
            voter_vertices.push(v);
        }

        let bundle = DagWaveCommitEvidence {
            anchor: anchor.clone(),
            causal_parents,
            anchor_cert_sigs,
            voter_vertices,
        };
        let ev = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: network.to_string(),
            payload: encode_dag_evidence(&bundle).expect("encode"),
            declared_height: anchor.round,
            declared_root: anchor.state_root,
            submitter: Address::from([0x0B; 32]),
        };
        (PinnedDagCommittee { epoch, members }, keys, bundle, ev)
    }

    #[test]
    fn bullshark_dag_passes_selftest_and_refuses_causal_and_pq_forgery() {
        let (pinned, keys, bundle, golden) = dag_wave_fixture();
        let adapter =
            BullsharkDagAdapter::new("sui-bullshark-1", Some(pinned)).with_golden(golden.clone());
        let policy = VerificationPolicy::strict(110);

        let report = admit(&adapter, &policy);
        assert!(report.admitted, "DAG-BFT admission failed: {report:?}");
        assert_eq!(report.passed(), 8);

        let mut facts = CryptoFacts::new();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .expect("valid Bullshark wave commits anchor");
        assert_eq!(att.height, 100);
        assert_eq!(att.state_root, [0xA1; 32]);
        assert_eq!(att.attested_tx_root, Some([0xA2; 32]));
        assert_eq!(att.attested_event_root, Some([0xA3; 32]));
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);

        // 1. Forgery: voter vertex in round r + 1 signed validly but omitting anchor.digest.
        let mut missing_edge = bundle.clone();
        let (ek, pk) = &keys[1];
        let mut unlinked = DagVoterVertex {
            round: 101,
            author: ek.public_key_bytes(),
            parent_digests: vec![[0x77; 32]],
            digest: [0u8; 32],
            ed25519_sig: Vec::new(),
            pq_sig: Vec::new(),
        };
        unlinked.digest = unlinked.compute_digest("sui-bullshark-1", 12);
        unlinked.ed25519_sig = ek.sign(&unlinked.digest).to_vec();
        unlinked.pq_sig = pk
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &unlinked.digest)
            .expect("pq sign");
        missing_edge.voter_vertices[0] = unlinked;
        let mut bad_ev = golden.clone();
        bad_ev.payload = encode_dag_evidence(&missing_edge).expect("encode");
        assert!(matches!(
            adapter.verify(&bad_ev, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 2. Forgery: sub-quorum voter vertices (2 of 4 = 50% <= 2/3 stake).
        let mut sub_votes = bundle.clone();
        sub_votes.voter_vertices.truncate(2);
        let mut sub_ev = golden.clone();
        sub_ev.payload = encode_dag_evidence(&sub_votes).expect("encode");
        assert!(matches!(
            adapter.verify(&sub_ev, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 3. Forgery: stripped ML-DSA-65 co-signature on anchor availability certificate.
        let mut stripped_pq = bundle;
        stripped_pq.anchor_cert_sigs[0].pq_sig.clear();
        let mut stripped_ev = golden;
        stripped_ev.payload = encode_dag_evidence(&stripped_pq).expect("encode");
        assert!(matches!(
            adapter.verify(&stripped_ev, &policy),
            Err(AdapterError::Crypto { .. })
        ));
    }

    #[test]
    fn dag_bft_refuses_competing_non_leader_anchor_and_verifies_indirect_commit_and_slashing() {
        let network = "sui-bullshark-1";
        let (pinned, keys, bundle, golden) = dag_wave_fixture();
        let adapter = BullsharkDagAdapter::new(network, Some(pinned.clone()));
        let policy = VerificationPolicy::strict(110);

        // Leader schedule is strictly order-invariant over committee member permutation.
        let mut reversed = pinned.clone();
        reversed.members.reverse();
        assert_eq!(
            elect_dag_wave_leader(network, &pinned, 100).expect("leader"),
            elect_dag_wave_leader(network, &reversed, 100).expect("leader rev")
        );

        // Construct a SECOND round-100 anchor authored by a non-leader validator
        // committing a conflicting state_root ([0xFE; 32] vs [0xA1; 32]), certified
        // by the same 3/4 honest committee members with zero equivocation.
        let alt_author = keys
            .iter()
            .map(|(ek, _)| ek.public_key_bytes())
            .find(|pk| *pk != bundle.anchor.author)
            .expect("distinct committee author");
        let mut alt_anchor = DagAnchorVertex {
            author: alt_author,
            state_root: [0xFE; 32],
            tx_root: [0xFD; 32],
            event_root: [0xFC; 32],
            digest: [0u8; 32],
            ..bundle.anchor.clone()
        };
        alt_anchor.digest = alt_anchor.compute_digest(network);
        let alt_cert_msg =
            dag_anchor_cert_sign_bytes(network, pinned.epoch, alt_anchor.round, &alt_anchor.digest);
        let alt_cert_sigs: Vec<DagBftSig> = keys
            .iter()
            .take(3)
            .map(|(ek, pk)| DagBftSig {
                signer_pubkey: ek.public_key_bytes(),
                ed25519_sig: ek.sign(&alt_cert_msg).to_vec(),
                pq_sig: pk
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &alt_cert_msg)
                    .expect("pq sign"),
            })
            .collect();
        let mut shared_voters = Vec::new();
        for (ek, pk) in keys.iter().skip(1) {
            let mut edges = vec![bundle.anchor.digest, alt_anchor.digest];
            edges.sort_unstable();
            let mut v = DagVoterVertex {
                round: alt_anchor.round + 1,
                author: ek.public_key_bytes(),
                parent_digests: edges,
                digest: [0u8; 32],
                ed25519_sig: Vec::new(),
                pq_sig: Vec::new(),
            };
            v.digest = v.compute_digest(network, pinned.epoch);
            v.ed25519_sig = ek.sign(&v.digest).to_vec();
            v.pq_sig = pk
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &v.digest)
                .expect("pq sign");
            shared_voters.push(v);
        }
        let mut ev_a = golden.clone();
        ev_a.payload = encode_dag_evidence(&DagWaveCommitEvidence {
            voter_vertices: shared_voters.clone(),
            ..bundle.clone()
        })
        .expect("encode A");
        let mut ev_b = golden;
        ev_b.declared_root = alt_anchor.state_root;
        ev_b.payload = encode_dag_evidence(&DagWaveCommitEvidence {
            anchor: alt_anchor.clone(),
            causal_parents: bundle.causal_parents.clone(),
            anchor_cert_sigs: alt_cert_sigs.clone(),
            voter_vertices: shared_voters,
        })
        .expect("encode B");

        assert!(adapter.verify(&ev_a, &policy).is_ok());
        assert!(matches!(
            adapter.verify(&ev_b, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // Indirect commit: round-100 anchor committed asynchronously via a single
        // round-101 relay vertex causally included by a directly committed round-102 wave.
        let relay = bundle.voter_vertices[0].clone();
        let mut r101_parents = Vec::new();
        for (i, (ek, pk)) in keys.iter().skip(1).enumerate() {
            let payload_root = if i == 0 {
                relay.digest
            } else {
                [u8::try_from(i).unwrap_or(0).saturating_add(0x70); 32]
            };
            let mut cp = DagCausalParent {
                round: 101,
                author: ek.public_key_bytes(),
                payload_root,
                digest: [0u8; 32],
                author_ed25519_sig: Vec::new(),
                author_pq_sig: Vec::new(),
            };
            cp.digest = cp.compute_digest(network, pinned.epoch);
            cp.author_ed25519_sig = ek.sign(&cp.digest).to_vec();
            cp.author_pq_sig = pk
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &cp.digest)
                .expect("pq sign");
            r101_parents.push(cp);
        }
        let mut r102_pdigs: Vec<Hash32> = r101_parents.iter().map(|p| p.digest).collect();
        r102_pdigs.sort_unstable();
        let leader_102 = elect_dag_wave_leader(network, &pinned, 102).expect("leader 102");
        let mut anchor_102 = DagAnchorVertex {
            epoch: pinned.epoch,
            round: 102,
            author: leader_102,
            timestamp_secs: 1_750_100_002,
            state_root: [0xC1; 32],
            tx_root: [0xC2; 32],
            event_root: [0xC3; 32],
            parent_digests: r102_pdigs,
            digest: [0u8; 32],
        };
        anchor_102.digest = anchor_102.compute_digest(network);
        let cert_102_msg =
            dag_anchor_cert_sign_bytes(network, pinned.epoch, 102, &anchor_102.digest);
        let cert_102_sigs: Vec<DagBftSig> = keys
            .iter()
            .take(3)
            .map(|(ek, pk)| DagBftSig {
                signer_pubkey: ek.public_key_bytes(),
                ed25519_sig: ek.sign(&cert_102_msg).to_vec(),
                pq_sig: pk
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &cert_102_msg)
                    .expect("pq sign"),
            })
            .collect();
        let voters_103: Vec<DagVoterVertex> = keys
            .iter()
            .take(3)
            .map(|(ek, pk)| {
                let mut v = DagVoterVertex {
                    round: 103,
                    author: ek.public_key_bytes(),
                    parent_digests: vec![anchor_102.digest],
                    digest: [0u8; 32],
                    ed25519_sig: Vec::new(),
                    pq_sig: Vec::new(),
                };
                v.digest = v.compute_digest(network, pinned.epoch);
                v.ed25519_sig = ek.sign(&v.digest).to_vec();
                v.pq_sig = pk
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &v.digest)
                    .expect("pq sign");
                v
            })
            .collect();
        let indirect = DagIndirectWaveCommitProof {
            target_anchor: bundle.anchor.clone(),
            target_causal_parents: bundle.causal_parents.clone(),
            target_cert_sigs: bundle.anchor_cert_sigs.clone(),
            relay_vertex: relay,
            committing_wave: DagWaveCommitEvidence {
                anchor: anchor_102,
                causal_parents: r101_parents,
                anchor_cert_sigs: cert_102_sigs,
                voter_vertices: voters_103,
            },
            submitter: Address::from([0x0C; 32]),
        };
        let ind_att = verify_indirect_dag_wave_commit(network, &pinned, &indirect, &policy)
            .expect("valid indirect 2-wave DAG commit");
        assert_eq!(ind_att.height, 100);
        assert_eq!(ind_att.finalized_at, 102);
        assert_eq!(ind_att.state_root, [0xA1; 32]);

        // Severing the causal bridge from A_102 to relay_101 must fail closed.
        let mut severed = indirect;
        let (ek1, pk1) = &keys[1];
        severed.committing_wave.causal_parents[0].payload_root = [0xEE; 32];
        let new_d = severed.committing_wave.causal_parents[0].compute_digest(network, pinned.epoch);
        severed.committing_wave.causal_parents[0].digest = new_d;
        severed.committing_wave.causal_parents[0].author_ed25519_sig = ek1.sign(&new_d).to_vec();
        severed.committing_wave.causal_parents[0].author_pq_sig = pk1
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &new_d)
            .expect("pq sign");
        assert!(verify_indirect_dag_wave_commit(network, &pinned, &severed, &policy).is_err());

        // Slashable equivocation 1: 3 validators co-certified conflicting round-100 anchors.
        let cert_eq = verify_dag_equivocation_proof(
            network,
            &pinned,
            &DagEquivocationProof::AnchorCertificate {
                round: 100,
                first_anchor_digest: bundle.anchor.digest,
                first_sigs: bundle.anchor_cert_sigs.clone(),
                second_anchor_digest: alt_anchor.digest,
                second_sigs: alt_cert_sigs,
            },
        )
        .expect("cert equivocation slashed");
        assert_eq!(cert_eq.slashed_weight, 300);
        assert_eq!(cert_eq.total_committee_weight, 400);
        assert!(cert_eq.quorum_safety_breached);

        // Identical digest must never falsely slash an honest validator.
        assert!(verify_dag_equivocation_proof(
            network,
            &pinned,
            &DagEquivocationProof::AnchorCertificate {
                round: 100,
                first_anchor_digest: bundle.anchor.digest,
                first_sigs: bundle.anchor_cert_sigs.clone(),
                second_anchor_digest: bundle.anchor.digest,
                second_sigs: bundle.anchor_cert_sigs,
            },
        )
        .is_err());

        // Slashable equivocation 2: validator 0 authors two conflicting round-99 vertices.
        let (ek0, pk0) = &keys[0];
        let mut fork_parent = bundle.causal_parents[0].clone();
        fork_parent.payload_root = [0xDE; 32];
        fork_parent.digest = fork_parent.compute_digest(network, pinned.epoch);
        fork_parent.author_ed25519_sig = ek0.sign(&fork_parent.digest).to_vec();
        fork_parent.author_pq_sig = pk0
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &fork_parent.digest)
            .expect("pq sign");
        let parent_eq = verify_dag_equivocation_proof(
            network,
            &pinned,
            &DagEquivocationProof::CausalParent {
                first: bundle.causal_parents[0].clone(),
                second: fork_parent,
            },
        )
        .expect("parent equivocation slashed");
        assert_eq!(parent_eq.slashable_validators, vec![ek0.public_key_bytes()]);
        assert_eq!(parent_eq.slashed_weight, 100);
        assert!(!parent_eq.quorum_safety_breached);
    }

    fn sign_skewed_indirect_commit(
        network: &str,
        pinned: &PinnedDagCommittee,
        ek0: &KeyPair,
        pk0: &PqKeyPair,
        bundle: &DagWaveCommitEvidence,
        v0: DagVoterVertex,
    ) -> DagIndirectWaveCommitProof {
        let mut cp_101 = DagCausalParent {
            round: 101,
            author: ek0.public_key_bytes(),
            payload_root: v0.digest,
            digest: [0u8; 32],
            author_ed25519_sig: Vec::new(),
            author_pq_sig: Vec::new(),
        };
        cp_101.digest = cp_101.compute_digest(network, pinned.epoch);
        cp_101.author_ed25519_sig = ek0.sign(&cp_101.digest).to_vec();
        cp_101.author_pq_sig = pk0
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &cp_101.digest)
            .expect("pq sign");
        let leader_102 = elect_dag_wave_leader(network, pinned, 102).expect("leader 102");
        let mut anchor_102 = DagAnchorVertex {
            epoch: pinned.epoch,
            round: 102,
            author: leader_102,
            timestamp_secs: 1_750_100_002,
            state_root: [0xC1; 32],
            tx_root: [0xC2; 32],
            event_root: [0xC3; 32],
            parent_digests: vec![cp_101.digest],
            digest: [0u8; 32],
        };
        anchor_102.digest = anchor_102.compute_digest(network);
        let cert_102_msg =
            dag_anchor_cert_sign_bytes(network, pinned.epoch, 102, &anchor_102.digest);
        let cert_102_sigs = vec![DagBftSig {
            signer_pubkey: ek0.public_key_bytes(),
            ed25519_sig: ek0.sign(&cert_102_msg).to_vec(),
            pq_sig: pk0
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &cert_102_msg)
                .expect("pq sign"),
        }];
        let mut v_103 = DagVoterVertex {
            round: 103,
            author: ek0.public_key_bytes(),
            parent_digests: vec![anchor_102.digest],
            digest: [0u8; 32],
            ed25519_sig: Vec::new(),
            pq_sig: Vec::new(),
        };
        v_103.digest = v_103.compute_digest(network, pinned.epoch);
        v_103.ed25519_sig = ek0.sign(&v_103.digest).to_vec();
        v_103.pq_sig = pk0
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &v_103.digest)
            .expect("pq sign");
        DagIndirectWaveCommitProof {
            target_anchor: bundle.anchor.clone(),
            target_causal_parents: bundle.causal_parents.clone(),
            target_cert_sigs: bundle.anchor_cert_sigs.clone(),
            relay_vertex: v0,
            committing_wave: DagWaveCommitEvidence {
                anchor: anchor_102,
                causal_parents: vec![cp_101],
                anchor_cert_sigs: cert_102_sigs,
                voter_vertices: vec![v_103],
            },
            submitter: Address::from([0x0D; 32]),
        }
    }

    #[test]
    fn regression_skewed_stake_indirect_weakest_link_and_future_round() {
        use crate::domain::finality_proof_model::FinalityProofShape;

        let network = "sui-bullshark-1";
        let (mut pinned, keys, mut bundle, mut ev) = dag_wave_fixture();

        // Find which validator is leader under [800, 100, 100, 100] and build a 1-signer >2/3 wave.
        let (ek0, pk0) = keys.first().expect("key 0");
        pinned.members.first_mut().expect("member 0").voting_weight = 800;
        let leader_100 = elect_dag_wave_leader(network, &pinned, 100).expect("leader 100");
        bundle.causal_parents.truncate(1);
        bundle.anchor.author = leader_100;
        bundle.anchor.parent_digests = vec![bundle.causal_parents.first().expect("cp0").digest];
        bundle.anchor.digest = bundle.anchor.compute_digest(network);
        let cert_msg =
            dag_anchor_cert_sign_bytes(network, pinned.epoch, 100, &bundle.anchor.digest);
        bundle.anchor_cert_sigs = vec![DagBftSig {
            signer_pubkey: ek0.public_key_bytes(),
            ed25519_sig: ek0.sign(&cert_msg).to_vec(),
            pq_sig: pk0
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &cert_msg)
                .expect("pq sign"),
        }];
        let mut v0 = DagVoterVertex {
            round: 101,
            author: ek0.public_key_bytes(),
            parent_digests: vec![bundle.anchor.digest],
            digest: [0u8; 32],
            ed25519_sig: Vec::new(),
            pq_sig: Vec::new(),
        };
        v0.digest = v0.compute_digest(network, pinned.epoch);
        v0.ed25519_sig = ek0.sign(&v0.digest).to_vec();
        v0.pq_sig = pk0
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &v0.digest)
            .expect("pq sign");
        bundle.voter_vertices = vec![v0.clone()];
        ev.payload = encode_dag_evidence(&bundle).expect("encode skewed");

        let adapter = BullsharkDagAdapter::new(network, Some(pinned.clone()));
        let policy = VerificationPolicy::strict(110);
        let att = adapter
            .verify(&ev, &policy)
            .expect("single >2/3 Bullshark validator verifies");
        FinalityProofShape::from_external_attestation(&adapter.descriptor(), &att)
            .expect("skewed >2/3 Bullshark direct quorum must pass FinalityProofShape");

        // Future anchor.round > policy.now when policy.max_age > 0 must return Stale.
        let mut future_policy = policy.clone();
        future_policy.max_age = 10;
        future_policy.now = bundle.anchor.round - 1;
        assert!(
            matches!(
                adapter.verify(&ev, &future_policy),
                Err(AdapterError::Stale {
                    age: 1,
                    max_age: 10
                })
            ),
            "future Bullshark round above policy.now must fail closed with AdapterError::Stale"
        );

        let indirect = sign_skewed_indirect_commit(network, &pinned, ek0, pk0, &bundle, v0);
        let ind_att = verify_indirect_dag_wave_commit(network, &pinned, &indirect, &policy)
            .expect("skewed indirect wave verifies");
        FinalityProofShape::from_external_attestation(&adapter.descriptor(), &ind_att)
            .expect("skewed indirect Bullshark quorum must pass FinalityProofShape");

        // Target round 100 is stale at now=111, max_age=10 (age=11 > 10) even though commit_round=102 has age=9 <= 10.
        let mut border_policy = policy;
        border_policy.max_age = 10;
        border_policy.now = 111;
        assert!(matches!(
            verify_indirect_dag_wave_commit(network, &pinned, &indirect, &border_policy),
            Err(AdapterError::Stale {
                age: 11,
                max_age: 10
            })
        ));
    }
}
