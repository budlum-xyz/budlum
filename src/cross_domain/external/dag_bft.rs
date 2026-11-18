//! Stake-weighted round-DAG BFT (`Narwhal` / `Bullshark` / `Mysticeti`)
//! external finality adapter verifying causal DAG availability certificates
//! and wave-anchor commit quorums.
//!
//! Under Spiegelman et al. (`Bullshark`, CCS 2022) and Danezis et al.
//! (`Narwhal`, EuroSys 2022), validators build a round-structured Directed
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
const ADAPTER_NAME: &str = "bullshark-dag-v1";
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DagBftSig {
    signer_pubkey: [u8; 32],
    ed25519_sig: Vec<u8>,
    #[serde(default)]
    pq_sig: Vec<u8>,
}

/// Summary of a round `r - 1` causal parent referenced by the wave anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DagCausalParent {
    round: u64,
    author: [u8; 32],
    payload_root: Hash32,
    digest: Hash32,
    author_ed25519_sig: Vec<u8>,
    #[serde(default)]
    author_pq_sig: Vec<u8>,
}

impl DagCausalParent {
    /// Canonical self-derived digest of a round `r - 1` causal parent header.
    #[must_use]
    fn compute_digest(&self, network: &str, epoch: u64) -> Hash32 {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DagAnchorVertex {
    epoch: u64,
    round: u64,
    author: [u8; 32],
    timestamp_secs: u64,
    state_root: Hash32,
    tx_root: Hash32,
    event_root: Hash32,
    /// Strictly ascending canonical parent digests in round `r - 1`.
    parent_digests: Vec<Hash32>,
    digest: Hash32,
}

impl DagAnchorVertex {
    /// Canonical self-derived anchor vertex digest.
    #[must_use]
    fn compute_digest(&self, network: &str) -> Hash32 {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DagVoterVertex {
    round: u64,
    author: [u8; 32],
    /// Strictly ascending round `r` parent digests (MUST contain `anchor.digest`).
    parent_digests: Vec<Hash32>,
    digest: Hash32,
    ed25519_sig: Vec<u8>,
    #[serde(default)]
    pq_sig: Vec<u8>,
}

impl DagVoterVertex {
    /// Canonical self-derived voter vertex digest.
    #[must_use]
    fn compute_digest(&self, network: &str, epoch: u64) -> Hash32 {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DagWaveCommitEvidence {
    anchor: DagAnchorVertex,
    causal_parents: Vec<DagCausalParent>,
    anchor_cert_sigs: Vec<DagBftSig>,
    voter_vertices: Vec<DagVoterVertex>,
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
fn dag_anchor_cert_sign_bytes(
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

#[cfg(test)]
fn encode_dag_evidence(bundle: &DagWaveCommitEvidence) -> Result<Vec<u8>, String> {
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
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
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
        if policy.max_age > 0 && policy.now > anchor.round {
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

        let min_signers = (cert_signers.len() as u64).min(voter_authors.len() as u64);
        let required_signers = ((pinned.members.len() as u64) * 2).div_ceil(3).max(1);
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

        // Build round 100 even wave anchor vertex.
        let mut anchor = DagAnchorVertex {
            epoch,
            round: anchor_round,
            author: keys[0].0.public_key_bytes(),
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
}
