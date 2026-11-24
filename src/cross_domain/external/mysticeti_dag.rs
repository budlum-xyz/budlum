//! Uncertified three-round Mysticeti `DAG-BFT` finality adapter and objective
//! same-round equivocation verifier.
//!
//! Unlike certified `DAG` protocols (`Narwhal`/`Bullshark`) that emit explicit
//! per-round quorum certificates, Mysticeti (Spiegelman et al., 2024) commits
//! an anchor leader vertex `A` at round `r` directly in three message delays
//! over raw signed `DAG` vertices:
//!
//! 1. **Anchor (`round = r`):** Validator `author_A` signs `A` committing
//!    [`MysticetiAnchorCommitment`] `(state_root, tx_root, event_root,
//!    block_hash, parent_anchor_digest)` via `payload_digest` and causally
//!    referencing `parent_anchor_digest` in `A.parents`.
//! 2. **Voting (`round = r + 1`):** Distinct committee validators holding
//!    strictly more than `2/3` of total voting weight sign round-`(r + 1)`
//!    vertices that list `A.digest(network)` in `parents`.
//! 3. **Decision (`round = r + 2`):** Distinct committee validators holding
//!    strictly more than `2/3` of total voting weight sign round-`(r + 2)`
//!    vertices whose `parents` each reference a `> 2/3` stake quorum of the
//!    verified round-`(r + 1)` voting vertices (*certified link* to `A`).
//!
//! Every vertex digest binds `BDLM_MYSTICETI_VERTEX_V1` and `network`; every
//! committee member with a pinned FIPS 204 `ML-DSA-65` key must co-sign under
//! `CROSS_DOMAIN_V1`; and [`verify_mysticeti_equivocation`] proves objective
//! same-`(author, epoch, round)` fork equivocation.
//!
//! WIRING: re-exported by `crate::cross_domain::external`, constructible via
//! `AdapterSpec::MysticetiDag` in `intake.rs`, and verified by `selftest::admit`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::crypto::ctx;
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier for uncertified three-round Mysticeti `DAG` finality.
pub const MYSTICETI_DAG_ADAPTER_NAME: &str = "mysticeti-uncertified-dag-v1";

/// Domain-separation tag for signed Mysticeti `DAG` vertices.
pub const MYSTICETI_VERTEX_TAG: &[u8] = b"BDLM_MYSTICETI_VERTEX_V1";

/// Domain-separation tag for [`MysticetiAnchorCommitment`] digests.
pub const MYSTICETI_COMMITMENT_TAG: &[u8] = b"BDLM_MYSTICETI_ANCHOR_V1";

const ADAPTER_VERSION: u32 = 1;
/// Canonical wire version for Mysticeti three-round wave bundles.
pub const MYSTICETI_EVIDENCE_VERSION: u32 = 1;
/// Three-round direct commit wave (`r`, `r + 1`, `r + 2`).
pub const MYSTICETI_WAVE_ROUNDS: u64 = 3;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMMy01";
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_COMMITTEE_MEMBERS: usize = 1024;
const MAX_ROUND_VERTICES: usize = 1024;
const MAX_PARENTS_PER_VERTEX: usize = 1024;
const MAX_SIGNATURE_BYTES: usize = 8192;

/// One validator in a governance-pinned Mysticeti epoch committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MysticetiMember {
    /// Ed25519 verifying key (`32` bytes, `!= 0`).
    pub ed25519_pubkey: [u8; 32],
    /// Stake-derived voting weight (`> 0`).
    pub voting_weight: u64,
    /// Optional FIPS 204 `ML-DSA-65` public key (`1952` bytes when non-empty).
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned Mysticeti committee bound to a single `epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedMysticetiCommittee {
    /// Epoch number (`> 0`).
    pub epoch: u64,
    /// Committee members sorted deterministically by `ed25519_pubkey`.
    pub members: Vec<MysticetiMember>,
}

impl PinnedMysticetiCommittee {
    /// Validate and canonicalise a Mysticeti epoch committee.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::ConsensusRule`] on zero epoch, empty/oversized
    /// committee, zero key or weight, duplicate key, or malformed `ML-DSA-65` key.
    pub fn new(epoch: u64, mut members: Vec<MysticetiMember>) -> Result<Self, AdapterError> {
        if epoch == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti committee epoch must be non-zero".to_string(),
            });
        }
        if members.is_empty() || members.len() > MAX_COMMITTEE_MEMBERS {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti committee size is out of bounds".to_string(),
            });
        }
        members.sort_by_key(|m| m.ed25519_pubkey);
        for pair in members.windows(2) {
            if let [left, right] = pair {
                if left.ed25519_pubkey == right.ed25519_pubkey {
                    return Err(AdapterError::ConsensusRule {
                        rule: "Mysticeti committee lists duplicate validator key".to_string(),
                    });
                }
            }
        }
        for m in &members {
            if m.ed25519_pubkey == [0u8; 32] || m.voting_weight == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "Mysticeti committee member has zero key or zero voting weight"
                        .to_string(),
                });
            }
            if !m.pq_pubkey.is_empty() {
                crate::crypto::primitives::PqKeyPair::validate_public_key(&m.pq_pubkey).map_err(
                    |_| AdapterError::ConsensusRule {
                        rule: "Mysticeti committee member has malformed ML-DSA-65 public key"
                            .to_string(),
                    },
                )?;
            }
        }
        Ok(Self { epoch, members })
    }

    /// Re-validate a deserialized committee.
    ///
    /// # Errors
    ///
    /// Propagates any [`Self::new`] refusal.
    pub fn validate(&self) -> Result<Self, AdapterError> {
        Self::new(self.epoch, self.members.clone())
    }

    /// Sum of voting weights across the committee.
    #[must_use]
    pub fn total_stake(&self) -> u128 {
        self.members
            .iter()
            .map(|m| u128::from(m.voting_weight))
            .fold(0u128, u128::saturating_add)
    }

    /// Minimum stake strictly exceeding two thirds (`floor(2 * total / 3) + 1`).
    #[must_use]
    pub fn quorum_stake(&self) -> u128 {
        (self.total_stake().saturating_mul(2)) / 3 + 1
    }
}

/// Execution roots committed by a Mysticeti anchor leader vertex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MysticetiAnchorCommitment {
    /// Post-execution state root (`!= 0`).
    pub state_root: [u8; 32],
    /// Executed transaction root (`!= 0`).
    pub tx_root: [u8; 32],
    /// Emitted event root (`!= 0`).
    pub event_root: [u8; 32],
    /// Canonical checkpoint/sub-DAG block hash (`!= 0`).
    pub block_hash: [u8; 32],
    /// Digest of the immediately preceding committed anchor (`!= 0`).
    pub parent_anchor_digest: [u8; 32],
}

impl MysticetiAnchorCommitment {
    /// Domain-separated commitment digest carried as `anchor.payload_digest`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        crate::core::hash::hash_fields_bytes(&[
            MYSTICETI_COMMITMENT_TAG,
            &self.state_root,
            &self.tx_root,
            &self.event_root,
            &self.block_hash,
            &self.parent_anchor_digest,
        ])
    }

    fn validate_nonzero(&self) -> Result<(), AdapterError> {
        if self.state_root == [0u8; 32]
            || self.tx_root == [0u8; 32]
            || self.event_root == [0u8; 32]
            || self.block_hash == [0u8; 32]
            || self.parent_anchor_digest == [0u8; 32]
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti anchor commitment has an unset execution or parent root"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Raw signed `DAG` vertex in a Mysticeti wave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MysticetiVertex {
    /// Validator Ed25519 verifying key.
    pub author: [u8; 32],
    /// Epoch number (`> 0`).
    pub epoch: u64,
    /// `DAG` round number (`> 0`).
    pub round: u64,
    /// Payload digest committed by this vertex.
    pub payload_digest: [u8; 32],
    /// Causal parent vertex digests from earlier rounds (`!is_empty()`).
    pub parents: Vec<[u8; 32]>,
    /// Ed25519 signature over [`Self::digest`].
    pub ed25519_sig: Vec<u8>,
    /// Optional `ML-DSA-65` co-signature over [`Self::digest`].
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

impl MysticetiVertex {
    /// Network-bound, length-prefixed canonical digest of this `DAG` vertex.
    #[must_use]
    pub fn digest(&self, network: &str) -> [u8; 32] {
        let epoch_le = self.epoch.to_le_bytes();
        let round_le = self.round.to_le_bytes();
        let parent_count_le = u32::try_from(self.parents.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes();
        let mut parents_concat = Vec::with_capacity(self.parents.len().saturating_mul(32));
        for p in &self.parents {
            parents_concat.extend_from_slice(p);
        }
        crate::core::hash::hash_fields_bytes(&[
            MYSTICETI_VERTEX_TAG,
            network.as_bytes(),
            &self.author,
            &epoch_le,
            &round_le,
            &self.payload_digest,
            &parent_count_le,
            &parents_concat,
        ])
    }
}

/// Objective same-round Mysticeti `DAG` equivocation proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MysticetiEquivocationProof {
    /// First signed vertex at `(author, epoch, round)`.
    pub vertex_a: MysticetiVertex,
    /// Conflicting signed vertex at the same `(author, epoch, round)`.
    pub vertex_b: MysticetiVertex,
}

fn verify_vertex_crypto(
    role: &str,
    network: &str,
    expected_epoch: u64,
    expected_round: u64,
    member: &MysticetiMember,
    vertex: &MysticetiVertex,
) -> Result<([u8; 32], bool), AdapterError> {
    if vertex.epoch != expected_epoch {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Mysticeti {role} vertex epoch {} != pinned epoch {expected_epoch}",
                vertex.epoch
            ),
        });
    }
    if vertex.round != expected_round {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Mysticeti {role} vertex round {} != expected round {expected_round}",
                vertex.round
            ),
        });
    }
    if vertex.parents.is_empty() || vertex.parents.len() > MAX_PARENTS_PER_VERTEX {
        return Err(AdapterError::ConsensusRule {
            rule: format!("Mysticeti {role} vertex parent count out of bounds"),
        });
    }
    let mut unique_parents = BTreeSet::new();
    for p in &vertex.parents {
        if *p == [0u8; 32] || !unique_parents.insert(*p) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Mysticeti {role} vertex carries zero or duplicate parent digest"),
            });
        }
    }
    let digest = vertex.digest(network);
    crate::crypto::primitives::verify_signature(&digest, &vertex.ed25519_sig, &vertex.author)
        .map_err(|_| AdapterError::Crypto {
            what: format!("invalid Ed25519 signature on Mysticeti {role} vertex"),
        })?;
    if member.pq_pubkey.is_empty() {
        Ok((digest, false))
    } else {
        if vertex.pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: format!("missing ML-DSA-65 co-signature on Mysticeti {role} vertex"),
            });
        }
        crate::crypto::primitives::PqKeyPair::verify(
            &member.pq_pubkey,
            ctx::CROSS_DOMAIN_V1,
            &digest,
            &vertex.pq_sig,
        )
        .map_err(|_| AdapterError::Crypto {
            what: format!("invalid ML-DSA-65 co-signature on Mysticeti {role} vertex"),
        })?;
        Ok((digest, true))
    }
}

/// Verify objective Mysticeti same-`(author, epoch, round)` equivocation and
/// return `(offender_pubkey, round, voting_weight)`.
///
/// # Errors
///
/// Returns [`AdapterError`] if the committee is invalid, the authors/rounds
/// differ, the vertices are identical, or either signature fails verification.
pub fn verify_mysticeti_equivocation(
    network: &str,
    committee: &PinnedMysticetiCommittee,
    proof: &MysticetiEquivocationProof,
) -> Result<([u8; 32], u64, u64), AdapterError> {
    let canonical = committee.validate()?;
    let a = &proof.vertex_a;
    let b = &proof.vertex_b;
    if a.author != b.author || a.epoch != canonical.epoch || b.epoch != canonical.epoch {
        return Err(AdapterError::ConsensusRule {
            rule: "Mysticeti equivocation vertices do not match author or pinned epoch".to_string(),
        });
    }
    if a.round == 0 || a.round != b.round {
        return Err(AdapterError::ConsensusRule {
            rule: "Mysticeti equivocation vertices are not from the same non-zero round"
                .to_string(),
        });
    }
    let Some(member) = canonical
        .members
        .iter()
        .find(|m| m.ed25519_pubkey == a.author)
    else {
        return Err(AdapterError::ConsensusRule {
            rule: "Mysticeti equivocation author is outside the pinned committee".to_string(),
        });
    };
    let (digest_a, _) = verify_vertex_crypto(
        "equivocation_a",
        network,
        canonical.epoch,
        a.round,
        member,
        a,
    )?;
    let (digest_b, _) = verify_vertex_crypto(
        "equivocation_b",
        network,
        canonical.epoch,
        b.round,
        member,
        b,
    )?;
    if digest_a == digest_b {
        return Err(AdapterError::ConsensusRule {
            rule: "identical Mysticeti vertex replayed twice is not equivocation".to_string(),
        });
    }
    Ok((a.author, a.round, member.voting_weight))
}

/// Complete three-round Mysticeti direct-commit finality bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MysticetiWaveEvidence {
    /// Execution commitment of the anchor vertex.
    pub commitment: MysticetiAnchorCommitment,
    /// Anchor leader vertex at round `r`.
    pub anchor: MysticetiVertex,
    /// Voting vertices at round `r + 1` referencing `anchor`.
    pub voting_vertices: Vec<MysticetiVertex>,
    /// Decision vertices at round `r + 2` each holding a certified link to `anchor`.
    pub decision_vertices: Vec<MysticetiVertex>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AdapterError> {
        let offset = self.at;
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| AdapterError::Malformed {
                offset,
                reason: "Mysticeti payload length overflow".to_string(),
            })?;
        let s = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| AdapterError::Malformed {
                offset,
                reason: "truncated Mysticeti payload".to_string(),
            })?;
        self.at = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, AdapterError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, AdapterError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    fn bytes32(&mut self) -> Result<[u8; 32], AdapterError> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32)?);
        Ok(b)
    }

    fn sig_blob(&mut self) -> Result<Vec<u8>, AdapterError> {
        let offset = self.at;
        let len = self.u32()? as usize;
        if len > MAX_SIGNATURE_BYTES {
            return Err(AdapterError::Malformed {
                offset,
                reason: "Mysticeti signature exceeds bound".to_string(),
            });
        }
        Ok(self.take(len)?.to_vec())
    }

    fn vertex(&mut self) -> Result<MysticetiVertex, AdapterError> {
        let author = self.bytes32()?;
        let epoch = self.u64()?;
        let round = self.u64()?;
        let payload_digest = self.bytes32()?;
        let parent_count = self.u32()? as usize;
        if parent_count == 0 || parent_count > MAX_PARENTS_PER_VERTEX {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti vertex parent count out of bounds".to_string(),
            });
        }
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count {
            parents.push(self.bytes32()?);
        }
        let ed25519_sig = self.sig_blob()?;
        let pq_sig = self.sig_blob()?;
        Ok(MysticetiVertex {
            author,
            epoch,
            round,
            payload_digest,
            parents,
            ed25519_sig,
            pq_sig,
        })
    }
}

fn push_vertex(out: &mut Vec<u8>, v: &MysticetiVertex) {
    out.extend_from_slice(&v.author);
    out.extend_from_slice(&v.epoch.to_le_bytes());
    out.extend_from_slice(&v.round.to_le_bytes());
    out.extend_from_slice(&v.payload_digest);
    out.extend_from_slice(
        &u32::try_from(v.parents.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for p in &v.parents {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(
        &u32::try_from(v.ed25519_sig.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&v.ed25519_sig);
    out.extend_from_slice(
        &u32::try_from(v.pq_sig.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    out.extend_from_slice(&v.pq_sig);
}

/// Encode [`MysticetiWaveEvidence`] into canonical wire bytes.
#[must_use]
pub fn encode_mysticeti_evidence(ev: &MysticetiWaveEvidence) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&MYSTICETI_EVIDENCE_VERSION.to_le_bytes());
    out.extend_from_slice(&ev.commitment.state_root);
    out.extend_from_slice(&ev.commitment.tx_root);
    out.extend_from_slice(&ev.commitment.event_root);
    out.extend_from_slice(&ev.commitment.block_hash);
    out.extend_from_slice(&ev.commitment.parent_anchor_digest);
    push_vertex(&mut out, &ev.anchor);
    for set in [&ev.voting_vertices, &ev.decision_vertices] {
        out.extend_from_slice(&u32::try_from(set.len()).unwrap_or(u32::MAX).to_le_bytes());
        for v in set {
            push_vertex(&mut out, v);
        }
    }
    out
}

/// Decode canonical wire bytes into [`MysticetiWaveEvidence`].
///
/// # Errors
///
/// Returns [`AdapterError`] on bad magic, unsupported version, oversized sets,
/// trailing bytes, or truncated reads.
pub fn decode_mysticeti_evidence(payload: &[u8]) -> Result<MysticetiWaveEvidence, AdapterError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "Mysticeti payload exceeds 512 KiB".to_string(),
        });
    }
    let mut r = Reader::new(payload);
    if r.take(PAYLOAD_MAGIC.len())? != PAYLOAD_MAGIC {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "bad Mysticeti payload magic".to_string(),
        });
    }
    let version = r.u32()?;
    if version != MYSTICETI_EVIDENCE_VERSION {
        return Err(AdapterError::UnsupportedEvidenceVersion {
            version,
            accepted: MYSTICETI_EVIDENCE_VERSION.to_string(),
        });
    }
    let commitment = MysticetiAnchorCommitment {
        state_root: r.bytes32()?,
        tx_root: r.bytes32()?,
        event_root: r.bytes32()?,
        block_hash: r.bytes32()?,
        parent_anchor_digest: r.bytes32()?,
    };
    let anchor = r.vertex()?;
    let vote_count = r.u32()? as usize;
    if vote_count == 0 || vote_count > MAX_ROUND_VERTICES {
        return Err(AdapterError::ConsensusRule {
            rule: "Mysticeti voting vertex count out of bounds".to_string(),
        });
    }
    let mut voting_vertices = Vec::with_capacity(vote_count);
    for _ in 0..vote_count {
        voting_vertices.push(r.vertex()?);
    }
    let decision_count = r.u32()? as usize;
    if decision_count == 0 || decision_count > MAX_ROUND_VERTICES {
        return Err(AdapterError::ConsensusRule {
            rule: "Mysticeti decision vertex count out of bounds".to_string(),
        });
    }
    let mut decision_vertices = Vec::with_capacity(decision_count);
    for _ in 0..decision_count {
        decision_vertices.push(r.vertex()?);
    }
    if r.at != payload.len() {
        return Err(AdapterError::Malformed {
            offset: r.at,
            reason: "Mysticeti payload carries trailing bytes".to_string(),
        });
    }
    Ok(MysticetiWaveEvidence {
        commitment,
        anchor,
        voting_vertices,
        decision_vertices,
    })
}

/// External finality adapter for uncertified three-round Mysticeti `DAG` waves.
pub struct MysticetiDagAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    committee: Option<PinnedMysticetiCommittee>,
    members: BTreeMap<[u8; 32], MysticetiMember>,
    golden: Option<RawConsensusEvidence>,
}

struct ValidatedMysticetiAnchor<'a> {
    committee: &'a PinnedMysticetiCommittee,
    bundle: MysticetiWaveEvidence,
    anchor_round: u64,
    decision_round: u64,
    anchor_digest: [u8; 32],
    anchor_pq: bool,
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

impl MysticetiDagAdapter {
    /// Build a Mysticeti adapter for `network` over an optional pinned committee.
    #[must_use]
    pub fn new(network: &str, committee: Option<PinnedMysticetiCommittee>) -> Self {
        let validated = committee.and_then(|c| c.validate().ok());
        let set_size = validated
            .as_ref()
            .map_or(0, |c| u64::try_from(c.members.len()).unwrap_or(u64::MAX));
        let id = AdapterId::from_name(MYSTICETI_DAG_ADAPTER_NAME);
        let descriptor = AdapterDescriptor {
            id,
            name: MYSTICETI_DAG_ADAPTER_NAME.to_string(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![MYSTICETI_EVIDENCE_VERSION],
            consensus_kind: "mysticeti-uncertified-dag".to_string(),
            finality_kind: FinalityKind::ProtocolFinality,
            required_depth: MYSTICETI_WAVE_ROUNDS,
            time_unit: TimeUnit::Round,
            trust_model: TrustModel::HonestMajority { set_size },
        };
        let members = validated
            .as_ref()
            .map(|c| {
                c.members
                    .iter()
                    .map(|m| (m.ed25519_pubkey, m.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            descriptor,
            network: network.to_string(),
            committee: validated,
            members,
            golden: None,
        }
    }

    /// Attach a golden sample for `selftest::admit`.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn validate_clock_and_depth(
        anchor_round: u64,
        decision_round: u64,
        policy: &VerificationPolicy,
    ) -> Result<(), AdapterError> {
        if policy.min_depth > MYSTICETI_WAVE_ROUNDS {
            return Err(AdapterError::InsufficientDepth {
                observed: MYSTICETI_WAVE_ROUNDS,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 && decision_round > policy.now {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Mysticeti decision round {decision_round} is ahead of caller clock {}",
                    policy.now
                ),
            });
        }
        if policy.max_age > 0 && policy.now > anchor_round {
            let age = policy.now - anchor_round;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }
        Ok(())
    }

    fn validate_envelope_and_anchor(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<ValidatedMysticetiAnchor<'_>, AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: hex::encode(evidence.adapter.as_bytes()),
            });
        }
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: MYSTICETI_EVIDENCE_VERSION.to_string(),
            });
        }
        if self.network.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti network identifier must not be empty".to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Mysticeti evidence network {:?} != adapter network {:?}",
                    evidence.network, self.network
                ),
            });
        }
        let Some(committee) = self.committee.as_ref() else {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti adapter has no valid governance-pinned committee".to_string(),
            });
        };

        let bundle = decode_mysticeti_evidence(&evidence.payload)?;
        bundle.commitment.validate_nonzero()?;

        let anchor_round = bundle.anchor.round;
        if anchor_round == 0 || anchor_round > u64::MAX - 2 {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti anchor round is zero or overflows wave rounds".to_string(),
            });
        }
        if policy.require_declared_match
            && (evidence.declared_height != anchor_round
                || evidence.declared_root != bundle.commitment.state_root)
        {
            return Err(AdapterError::DeclarationMismatch {
                field: "mysticeti_wave_anchor",
            });
        }
        let decision_round = anchor_round + 2;
        Self::validate_clock_and_depth(anchor_round, decision_round, policy)?;
        if bundle.anchor.payload_digest != bundle.commitment.digest() {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti anchor payload_digest does not match commitment digest"
                    .to_string(),
            });
        }
        if !bundle
            .anchor
            .parents
            .contains(&bundle.commitment.parent_anchor_digest)
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti anchor vertex does not causally reference parent_anchor_digest"
                    .to_string(),
            });
        }
        let Some(anchor_member) = self.members.get(&bundle.anchor.author) else {
            return Err(AdapterError::ConsensusRule {
                rule: "Mysticeti anchor author is outside the pinned committee".to_string(),
            });
        };
        let (anchor_digest, anchor_pq) = verify_vertex_crypto(
            "anchor",
            &self.network,
            committee.epoch,
            anchor_round,
            anchor_member,
            &bundle.anchor,
        )?;
        Ok(ValidatedMysticetiAnchor {
            committee,
            bundle,
            anchor_round,
            decision_round,
            anchor_digest,
            anchor_pq,
        })
    }

    fn verify_voting_and_decision_rounds(
        &self,
        committee: &PinnedMysticetiCommittee,
        bundle: &MysticetiWaveEvidence,
        (anchor_round, decision_round, anchor_digest, anchor_pq): (u64, u64, [u8; 32], bool),
    ) -> Result<(u64, bool), AdapterError> {
        let quorum = committee.quorum_stake();
        let mut vote_authors = BTreeSet::new();
        let mut vote_weight_by_digest: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        let mut total_vote_stake = 0u128;
        let mut all_pq = anchor_pq;

        for vote in &bundle.voting_vertices {
            let Some(member) = self.members.get(&vote.author) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "Mysticeti voting vertex author is outside the pinned committee"
                        .to_string(),
                });
            };
            if !vote_authors.insert(vote.author) {
                return Err(AdapterError::ConsensusRule {
                    rule: "Mysticeti voting round lists the same validator twice".to_string(),
                });
            }
            if vote.parents.first() != Some(&anchor_digest) {
                return Err(AdapterError::ConsensusRule {
                    rule: "Mysticeti voting vertex must endorse the round-r anchor as primary parent (parents[0])"
                        .to_string(),
                });
            }
            let (v_digest, v_pq) = verify_vertex_crypto(
                "voting",
                &self.network,
                committee.epoch,
                anchor_round + 1,
                member,
                vote,
            )?;
            all_pq &= v_pq;
            vote_weight_by_digest.insert(v_digest, member.voting_weight);
            total_vote_stake = total_vote_stake.saturating_add(u128::from(member.voting_weight));
        }
        if total_vote_stake < quorum {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Mysticeti voting round stake {total_vote_stake} < quorum {quorum}"),
            });
        }

        let mut decision_authors = BTreeSet::new();
        let mut total_decision_stake = 0u128;
        for dec in &bundle.decision_vertices {
            let Some(member) = self.members.get(&dec.author) else {
                return Err(AdapterError::ConsensusRule {
                    rule: "Mysticeti decision vertex author is outside the pinned committee"
                        .to_string(),
                });
            };
            if !decision_authors.insert(dec.author) {
                return Err(AdapterError::ConsensusRule {
                    rule: "Mysticeti decision round lists the same validator twice".to_string(),
                });
            }
            let (_, d_pq) = verify_vertex_crypto(
                "decision",
                &self.network,
                committee.epoch,
                decision_round,
                member,
                dec,
            )?;
            all_pq &= d_pq;

            let mut linked_vote_stake = 0u128;
            for parent_hash in &dec.parents {
                if let Some(w) = vote_weight_by_digest.get(parent_hash) {
                    linked_vote_stake = linked_vote_stake.saturating_add(u128::from(*w));
                }
            }
            if linked_vote_stake < quorum {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "Mysticeti decision vertex links to {linked_vote_stake} voting stake, below certified-link quorum {quorum}"
                    ),
                });
            }
            total_decision_stake =
                total_decision_stake.saturating_add(u128::from(member.voting_weight));
        }
        if total_decision_stake < quorum {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "Mysticeti decision round stake {total_decision_stake} < quorum {quorum}"
                ),
            });
        }
        Ok((
            u64::try_from(decision_authors.len()).unwrap_or(u64::MAX),
            all_pq,
        ))
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, bool), AdapterError> {
        if policy.require_slashable {
            return Err(AdapterError::ConsensusRule {
                rule: "external Mysticeti stake is not slashable on Budlum; pair with bonded IntakeState prover".to_string(),
            });
        }
        let ValidatedMysticetiAnchor {
            committee,
            bundle,
            anchor_round,
            decision_round,
            anchor_digest,
            anchor_pq,
        } = self.validate_envelope_and_anchor(evidence, policy)?;
        let (signers, all_pq) = self.verify_voting_and_decision_rounds(
            committee,
            &bundle,
            (anchor_round, decision_round, anchor_digest, anchor_pq),
        )?;
        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let total_stake = committee.total_stake();
        let required = min_signers_for_quorum(
            committee.members.iter().map(|m| m.voting_weight),
            total_stake,
        );
        let att = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: anchor_round,
            state_root: bundle.commitment.state_root,
            finalized_at: decision_round,
            time_unit: TimeUnit::Round,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers,
                required,
                total_weight: total_stake,
                slashable: false,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(bundle.commitment.block_hash),
            attested_event_root: Some(bundle.commitment.event_root),
            attested_tx_root: Some(bundle.commitment.tx_root),
        };
        Ok((att, all_pq))
    }
}

impl ExternalFinalityAdapter for MysticetiDagAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.committee.is_some()
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

    fn attested_parent(&self, evidence: &RawConsensusEvidence) -> Option<[u8; 32]> {
        decode_mysticeti_evidence(&evidence.payload)
            .ok()
            .map(|w| w.commitment.parent_anchor_digest)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        vec![
            FaultProbe {
                name: "refuses unknown Mysticeti evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 9 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign Mysticeti network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared Mysticeti anchor round".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared Mysticeti state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xee; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted Mysticeti payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"BADMAGIC".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses truncated Mysticeti payload".into(),
                patch: BytePatch::TruncatePayload { keep: 20 },
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
    use crate::cross_domain::external::selftest::{admit, ProbeOutcome};
    use crate::crypto::facts::CryptoFacts;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    const NET: &str = "sui-mysticeti-testnet";
    const EPOCH: u64 = 7;
    const ANCHOR_ROUND: u64 = 40;

    struct ValSigner {
        ed: KeyPair,
        pq: PqKeyPair,
        pub_ed: [u8; 32],
    }

    fn committee_fixture() -> (Vec<ValSigner>, PinnedMysticetiCommittee) {
        let mut signers = Vec::new();
        let mut members = Vec::new();
        for seed in 1u8..=4 {
            let ed = KeyPair::from_seed(&[seed; 32]).expect("ed");
            let pq = PqKeyPair::generate();
            let pub_ed = ed.public_key_bytes();
            members.push(MysticetiMember {
                ed25519_pubkey: pub_ed,
                voting_weight: 250,
                pq_pubkey: pq.public_key_bytes().to_vec(),
            });
            signers.push(ValSigner { ed, pq, pub_ed });
        }
        let committee = PinnedMysticetiCommittee::new(EPOCH, members).expect("committee");
        (signers, committee)
    }

    fn sign_vertex(
        signer: &ValSigner,
        net: &str,
        round: u64,
        payload_digest: [u8; 32],
        parents: Vec<[u8; 32]>,
    ) -> MysticetiVertex {
        let mut v = MysticetiVertex {
            author: signer.pub_ed,
            epoch: EPOCH,
            round,
            payload_digest,
            parents,
            ed25519_sig: Vec::new(),
            pq_sig: Vec::new(),
        };
        let d = v.digest(net);
        v.ed25519_sig = signer.ed.sign(&d).to_vec();
        v.pq_sig = signer.pq.sign(ctx::CROSS_DOMAIN_V1, &d).expect("pq sign");
        v
    }

    fn wave_bundle(signers: &[ValSigner]) -> (MysticetiWaveEvidence, RawConsensusEvidence) {
        let commitment = MysticetiAnchorCommitment {
            state_root: [0x21; 32],
            tx_root: [0x22; 32],
            event_root: [0x23; 32],
            block_hash: [0x24; 32],
            parent_anchor_digest: [0x20; 32],
        };
        let leader = signers.first().expect("leader");
        let anchor = sign_vertex(
            leader,
            NET,
            ANCHOR_ROUND,
            commitment.digest(),
            vec![commitment.parent_anchor_digest],
        );
        let anchor_digest = anchor.digest(NET);

        let voting_vertices: Vec<MysticetiVertex> = signers
            .iter()
            .take(3)
            .enumerate()
            .map(|(idx, s)| {
                let offset = u8::try_from(idx).unwrap_or(0);
                sign_vertex(
                    s,
                    NET,
                    ANCHOR_ROUND + 1,
                    [0x30u8.saturating_add(offset); 32],
                    vec![anchor_digest],
                )
            })
            .collect();
        let vote_digests: Vec<[u8; 32]> = voting_vertices.iter().map(|v| v.digest(NET)).collect();

        let decision_vertices: Vec<MysticetiVertex> = signers
            .iter()
            .skip(1)
            .take(3)
            .enumerate()
            .map(|(idx, s)| {
                let offset = u8::try_from(idx).unwrap_or(0);
                sign_vertex(
                    s,
                    NET,
                    ANCHOR_ROUND + 2,
                    [0x40u8.saturating_add(offset); 32],
                    vote_digests.clone(),
                )
            })
            .collect();

        let declared_root = commitment.state_root;
        let wave = MysticetiWaveEvidence {
            commitment,
            anchor,
            voting_vertices,
            decision_vertices,
        };
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(MYSTICETI_DAG_ADAPTER_NAME),
            evidence_version: MYSTICETI_EVIDENCE_VERSION,
            network: NET.to_string(),
            payload: encode_mysticeti_evidence(&wave),
            declared_height: ANCHOR_ROUND,
            declared_root,
            submitter: Address::from([0x07; 32]),
        };
        (wave, raw)
    }

    fn wave_policy() -> VerificationPolicy {
        let mut p = VerificationPolicy::strict(0);
        p.require_slashable = false;
        p
    }

    #[test]
    fn mysticeti_three_round_wave_admits_and_binds_all_roots_and_parent() {
        let (signers, committee) = committee_fixture();
        let (wave, raw) = wave_bundle(&signers);
        let adapter = MysticetiDagAdapter::new(NET, Some(committee)).with_golden(raw.clone());
        let policy = wave_policy();
        let mut slash_policy = VerificationPolicy::strict(0);
        slash_policy.require_slashable = true;
        assert!(adapter.verify(&raw, &slash_policy).is_err());

        let report = admit(&adapter, &policy);
        assert!(report.admitted, "selftest failed: {report:?}");
        assert!(report
            .probes
            .iter()
            .all(|(_, o)| matches!(o, ProbeOutcome::Refused { .. })));

        let mut obs = CryptoFacts::default();
        let att = adapter
            .verify_observed(&raw, &policy, &mut obs)
            .expect("verify wave");
        assert_eq!(att.height, ANCHOR_ROUND);
        assert_eq!(att.finalized_at, ANCHOR_ROUND + 2);
        assert_eq!(att.state_root, wave.commitment.state_root);
        assert_eq!(att.attested_tx_root, Some(wave.commitment.tx_root));
        assert_eq!(att.attested_event_root, Some(wave.commitment.event_root));
        assert_eq!(att.attested_block_hash, Some(wave.commitment.block_hash));
        assert_eq!(
            att.security.observed_scheme(),
            Some(ObservedScheme::Scheme(SchemeId::ML_DSA_65))
        );
        assert_eq!(
            adapter.attested_parent(&raw),
            Some(wave.commitment.parent_anchor_digest)
        );
    }

    #[test]
    fn mysticeti_refuses_subquorum_broken_links_stripped_pq_and_slashes_equivocation() {
        let (signers, committee) = committee_fixture();
        let (wave, raw) = wave_bundle(&signers);
        let adapter = MysticetiDagAdapter::new(NET, Some(committee.clone()));
        let policy = wave_policy();

        let mut sub_vote = wave.clone();
        sub_vote.voting_vertices.truncate(2);
        let mut bad_raw = raw;
        bad_raw.payload = encode_mysticeti_evidence(&sub_vote);
        assert!(adapter.verify(&bad_raw, &policy).is_err());

        let mut unlinked_dec = wave.clone();
        let single_vote_digest = wave.voting_vertices.first().expect("v0").digest(NET);
        let s1 = signers.get(1).expect("s1");
        if let Some(first_dec) = unlinked_dec.decision_vertices.first_mut() {
            *first_dec = sign_vertex(
                s1,
                NET,
                ANCHOR_ROUND + 2,
                [0x55; 32],
                vec![single_vote_digest],
            );
        }
        bad_raw.payload = encode_mysticeti_evidence(&unlinked_dec);
        assert!(adapter.verify(&bad_raw, &policy).is_err());

        let mut stripped = wave;
        if let Some(first_dec) = stripped.decision_vertices.first_mut() {
            first_dec.pq_sig.clear();
        }
        bad_raw.payload = encode_mysticeti_evidence(&stripped);
        assert!(matches!(
            adapter.verify(&bad_raw, &policy),
            Err(AdapterError::Crypto { .. })
        ));

        let offender = signers.first().expect("s0");
        let fork_a = sign_vertex(offender, NET, ANCHOR_ROUND, [0xA1; 32], vec![[0x01; 32]]);
        let fork_b = sign_vertex(offender, NET, ANCHOR_ROUND, [0xB2; 32], vec![[0x01; 32]]);
        let (pubk, round, weight) = verify_mysticeti_equivocation(
            NET,
            &committee,
            &MysticetiEquivocationProof {
                vertex_a: fork_a.clone(),
                vertex_b: fork_b,
            },
        )
        .expect("equivocation");
        assert_eq!(pubk, offender.pub_ed);
        assert_eq!(round, ANCHOR_ROUND);
        assert_eq!(weight, 250);

        assert!(verify_mysticeti_equivocation(
            NET,
            &committee,
            &MysticetiEquivocationProof {
                vertex_a: fork_a.clone(),
                vertex_b: fork_a,
            },
        )
        .is_err());

        // Accountable safety invariant: a single round-(r + 1) voting vertex must
        // designate its voted anchor at `parents[0]`. Listing a second round-r
        // vertex in `parents[1..]` as causal DAG history must NEVER grant quorum
        // stake to a conflicting commitment at the same height without >1/3
        // round-(r + 1) equivocation.
        let rival_commitment = MysticetiAnchorCommitment {
            state_root: [0x99; 32],
            tx_root: [0x98; 32],
            event_root: [0x97; 32],
            block_hash: [0x96; 32],
            parent_anchor_digest: [0x20; 32],
        };
        let rival_proposer = signers.get(1).expect("s1");
        let rival_anchor = sign_vertex(
            rival_proposer,
            NET,
            ANCHOR_ROUND,
            rival_commitment.digest(),
            vec![rival_commitment.parent_anchor_digest],
        );
        let primary_anchor = sign_vertex(
            signers.first().expect("s0"),
            NET,
            ANCHOR_ROUND,
            MysticetiAnchorCommitment {
                state_root: [0x21; 32],
                tx_root: [0x22; 32],
                event_root: [0x23; 32],
                block_hash: [0x24; 32],
                parent_anchor_digest: [0x20; 32],
            }
            .digest(),
            vec![[0x20; 32]],
        );
        let primary_digest = primary_anchor.digest(NET);
        let rival_digest = rival_anchor.digest(NET);
        let honest_causal_votes: Vec<MysticetiVertex> = signers
            .iter()
            .take(3)
            .enumerate()
            .map(|(idx, s)| {
                let offset = u8::try_from(idx).unwrap_or(0);
                sign_vertex(
                    s,
                    NET,
                    ANCHOR_ROUND + 1,
                    [0x70u8.saturating_add(offset); 32],
                    vec![primary_digest, rival_digest],
                )
            })
            .collect();
        let honest_vote_digests: Vec<[u8; 32]> =
            honest_causal_votes.iter().map(|v| v.digest(NET)).collect();
        let honest_decisions: Vec<MysticetiVertex> = signers
            .iter()
            .take(3)
            .enumerate()
            .map(|(idx, s)| {
                let offset = u8::try_from(idx).unwrap_or(0);
                sign_vertex(
                    s,
                    NET,
                    ANCHOR_ROUND + 2,
                    [0x80u8.saturating_add(offset); 32],
                    honest_vote_digests.clone(),
                )
            })
            .collect();
        let primary_wave = MysticetiWaveEvidence {
            commitment: MysticetiAnchorCommitment {
                state_root: [0x21; 32],
                tx_root: [0x22; 32],
                event_root: [0x23; 32],
                block_hash: [0x24; 32],
                parent_anchor_digest: [0x20; 32],
            },
            anchor: primary_anchor,
            voting_vertices: honest_causal_votes.clone(),
            decision_vertices: honest_decisions.clone(),
        };
        let mut primary_raw = bad_raw.clone();
        primary_raw.declared_root = [0x21; 32];
        primary_raw.payload = encode_mysticeti_evidence(&primary_wave);
        assert!(
            adapter.verify(&primary_raw, &policy).is_ok(),
            "primary anchor at parents[0] with causal parents[1] must verify"
        );

        let rival_wave = MysticetiWaveEvidence {
            commitment: rival_commitment,
            anchor: rival_anchor,
            voting_vertices: honest_causal_votes,
            decision_vertices: honest_decisions,
        };
        let mut rival_raw = primary_raw;
        rival_raw.declared_root = [0x99; 32];
        rival_raw.payload = encode_mysticeti_evidence(&rival_wave);
        assert!(
            matches!(
                adapter.verify(&rival_raw, &policy),
                Err(AdapterError::ConsensusRule { .. })
            ),
            "secondary causal parent at parents[1] must not finalize a conflicting state_root"
        );
    }

    #[test]
    fn regression_intake_live_clock_skewed_stake_and_empty_network() {
        use crate::domain::finality_proof_model::FinalityProofShape;

        let (signers, committee) = committee_fixture();
        let (mut wave, raw) = wave_bundle(&signers);
        let adapter = MysticetiDagAdapter::new(NET, Some(committee));

        // 1. IntakeState::submit sets policy.now = last_accepted_height (> 0)
        // while policy.max_age == 0 (VerificationPolicy::strict(0)). Subsequent waves
        // (and even wave #1 when stored_now == ANCHOR_ROUND < decision_round) must not deadlock.
        let mut intake_live_policy = VerificationPolicy::strict(ANCHOR_ROUND - 4);
        intake_live_policy.max_age = 0;
        intake_live_policy.require_slashable = false;
        adapter.verify(&raw, &intake_live_policy).expect(
            "IntakeState live_policy_clock with max_age == 0 must not deadlock Mysticeti wave",
        );

        // When policy.max_age > 0, future decision_round > policy.now MUST still be refused.
        let mut clocked = intake_live_policy;
        clocked.max_age = 10;
        clocked.now = ANCHOR_ROUND + 1;
        assert!(adapter.verify(&raw, &clocked).is_err());

        // 2. Skewed stake [800, 100, 100, 100] (800/1100 > 2/3) signed by validator 0 alone.
        let skewed_members: Vec<MysticetiMember> = signers
            .iter()
            .enumerate()
            .map(|(i, s)| MysticetiMember {
                ed25519_pubkey: s.pub_ed,
                voting_weight: if i == 0 { 800 } else { 100 },
                pq_pubkey: s.pq.public_key_bytes().to_vec(),
            })
            .collect();
        let skewed_committee =
            PinnedMysticetiCommittee::new(EPOCH, skewed_members).expect("skewed committee");
        wave.voting_vertices.truncate(1);
        let v0_digest = wave.voting_vertices.first().expect("v0").digest(NET);
        wave.decision_vertices = vec![sign_vertex(
            signers.first().expect("s0"),
            NET,
            ANCHOR_ROUND + 2,
            [0x33; 32],
            vec![v0_digest],
        )];
        let mut skewed_raw = raw;
        skewed_raw.payload = encode_mysticeti_evidence(&wave);
        let skewed_adapter = MysticetiDagAdapter::new(NET, Some(skewed_committee.clone()));
        let skewed_att = skewed_adapter
            .verify(&skewed_raw, &wave_policy())
            .expect("single >2/3 Mysticeti validator verifies");
        FinalityProofShape::from_external_attestation(&skewed_adapter.descriptor(), &skewed_att)
            .expect("skewed >2/3 Mysticeti quorum must pass FinalityProofShape");

        // 3. Empty/whitespace network must be refused.
        let blank_adapter = MysticetiDagAdapter::new("  ", Some(skewed_committee));
        let mut blank_raw = skewed_raw;
        blank_raw.adapter = blank_adapter.descriptor().id;
        blank_raw.network = "  ".to_string();
        assert!(matches!(
            blank_adapter.verify(&blank_raw, &wave_policy()),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }
}
