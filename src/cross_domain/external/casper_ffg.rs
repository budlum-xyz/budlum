//! Casper FFG checkpoint finality over a governance-pinned epoch committee,
//! with objective Rule-1 (`DoubleVote`) and Rule-2 (`SurroundVote`) slashing
//! evidence verification.
//!
//! A Casper FFG chain calls a checkpoint *justified* when strictly more than
//! two thirds of the active stake voted for `(source, target)` with
//! `target.epoch == source.epoch + 1`, and *final* when two adjacent
//! checkpoints are justified. Because external Casper FFG validator stake is
//! held on the remote chain rather than escrowed locally on Budlum, this
//! adapter reports [`SecurityBacking::SignatureSet`] with `slashable: false`
//! and refuses policies that set `require_slashable: true` unless paired with
//! locally escrowed prover or restaking bonds, while exposing
//! [`verify_ffg_slashing_evidence`] so objective equivocations freeze the
//! registered domain immediately through `IntakeState`.
//!
//! Four consensus rules are enforced fail-closed before any attestation is
//! emitted:
//!
//! 1. **Epoch-bound committee pin.** `PinnedFfgCommittee` pins an explicit
//!    `epoch > 0`, and `parsed.target_epoch` must equal `committee.epoch`;
//!    when a caller clock is supplied (`policy.max_age > 0 || policy.now > 0`),
//!    future-dated target epochs (`parsed.target_epoch > policy.now`) are
//!    refused.
//! 2. **Adjacency.** `target.epoch == source.epoch + 1`.
//! 3. **Network-bound vote digest.** Every signature is verified over a
//!    domain-separated digest (`BDLM_CASPER_FFG_V1`) that binds `network`,
//!    preventing cross-network replay across testnets or sister forks sharing
//!    validator keys.
//! 4. **Supermajority & mandatory PQ co-signing.** Distinct committee stakes
//!    are summed in `u128` (`signed * 3 > total * 2`), duplicate voters are
//!    refused, and any validator with a pinned FIPS 204 `ML-DSA-65` public key
//!    must supply a valid `CROSS_DOMAIN_V1`-bound co-signature; `ML-DSA-65` is
//!    reported as the observed scheme only when **both** the source and target
//!    quorums are 100% PQ-co-signed.
//!
//! WIRING: re-exported by `crate::cross_domain::external`, constructible via
//! `AdapterSpec::CasperFfg` in `intake.rs`, and verified by `selftest::admit`.

use std::collections::BTreeMap;

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

/// Canonical adapter identifier for Casper FFG checkpoint finality.
///
/// WIRING: registered with [`AdapterId::from_name`] in [`CasperFfgAdapter::new`].
pub const CASPER_FFG_ADAPTER_NAME: &str = "casper-ffg-epoch-finality-v1";

/// Vote digest domain-separation tag.
pub const CASPER_FFG_VOTE_TAG: &[u8] = b"BDLM_CASPER_FFG_V1";

const ADAPTER_VERSION: u32 = 1;
/// Canonical wire version for Casper FFG checkpoint finality payloads.
pub const FFG_EVIDENCE_VERSION: u32 = 1;
/// Two adjacent justified checkpoints, so the adapter always reports depth `2`.
const FINALITY_DEPTH: u64 = 2;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMCF01";
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_COMMITTEE: usize = 1024;
const MAX_VOTES: usize = 1024;

/// One validator in the governance-pinned Casper FFG epoch committee.
///
/// WIRING: listed in [`PinnedFfgCommittee`] and checked on every vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfgValidator {
    /// Ed25519 verifying key (`32` bytes).
    pub pubkey: [u8; 32],
    /// Active stake in the remote chain's smallest unit (`> 0`).
    pub stake: u64,
    /// Enrolled FIPS 204 `ML-DSA-65` public key (`1952` bytes when non-empty).
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned Casper FFG committee bound to a single target `epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedFfgCommittee {
    /// Exact target checkpoint epoch this committee is authorized to finalize (`> 0`).
    pub epoch: u64,
    /// Members sorted deterministically by `pubkey` upon validation.
    pub validators: Vec<FfgValidator>,
}

impl PinnedFfgCommittee {
    /// Check and canonicalise a pinned epoch committee.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::ConsensusRule`] for `epoch == 0`, an empty or
    /// oversized set, a zero key, zero stake, a duplicate key, or a malformed
    /// `ML-DSA-65` public key.
    pub fn new(epoch: u64, mut validators: Vec<FfgValidator>) -> Result<Self, AdapterError> {
        if epoch == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "the pinned Casper FFG committee epoch must be non-zero".to_string(),
            });
        }
        if validators.is_empty() || validators.len() > MAX_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: "the pinned committee size is out of range".to_string(),
            });
        }
        validators.sort_by_key(|v| v.pubkey);
        for pair in validators.windows(2) {
            if let [left, right] = pair {
                if left.pubkey == right.pubkey {
                    return Err(AdapterError::ConsensusRule {
                        rule: "the pinned committee lists a key twice".to_string(),
                    });
                }
            }
        }
        for member in &validators {
            if member.pubkey == [0u8; 32] || member.stake == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "a pinned member has an unset key or no stake".to_string(),
                });
            }
            if !member.pq_pubkey.is_empty() {
                crate::crypto::primitives::PqKeyPair::validate_public_key(&member.pq_pubkey)
                    .map_err(|_| AdapterError::ConsensusRule {
                        rule: "a pinned member carries a malformed ML-DSA-65 public key"
                            .to_string(),
                    })?;
            }
        }
        Ok(Self { epoch, validators })
    }

    /// Re-validate a deserialized committee (`serde` bypasses [`Self::new`]).
    ///
    /// # Errors
    ///
    /// Propagates any [`Self::new`] refusal.
    pub fn validate(&self) -> Result<Self, AdapterError> {
        Self::new(self.epoch, self.validators.clone())
    }

    /// The committee's total active stake.
    #[must_use]
    pub fn total_stake(&self) -> u128 {
        self.validators
            .iter()
            .map(|v| u128::from(v.stake))
            .fold(0u128, u128::saturating_add)
    }

    /// Smallest stake strictly exceeding two thirds: `floor(2 * total / 3) + 1`.
    #[must_use]
    pub fn threshold_stake(&self) -> u128 {
        (self.total_stake().saturating_mul(2)) / 3 + 1
    }
}

/// A checkpoint pair vote: from `source` towards `target`.
///
/// WIRING: carried in Casper FFG evidence payloads and [`FfgEquivocationProof`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfgVote {
    /// Ed25519 verifying key of the voting validator.
    pub signer: [u8; 32],
    /// Source checkpoint epoch.
    pub source_epoch: u64,
    /// Source checkpoint root (`!= 0`).
    pub source_root: [u8; 32],
    /// Target checkpoint epoch (`> source_epoch`).
    pub target_epoch: u64,
    /// Target checkpoint root (`!= 0`).
    pub target_root: [u8; 32],
    /// Ed25519 signature over [`Self::digest`].
    pub signature: Vec<u8>,
    /// Optional `ML-DSA-65` co-signature over [`Self::digest`].
    #[serde(default)]
    pub pq_signature: Vec<u8>,
}

impl FfgVote {
    /// Network-bound, domain-separated digest signed by the validator.
    #[must_use]
    pub fn digest(&self, network: &str) -> [u8; 32] {
        let source = self.source_epoch.to_le_bytes();
        let target = self.target_epoch.to_le_bytes();
        crate::core::hash::hash_fields_bytes(&[
            CASPER_FFG_VOTE_TAG,
            network.as_bytes(),
            &self.signer,
            &source,
            &self.source_root,
            &target,
            &self.target_root,
        ])
    }
}

/// Objective Buterin-Griffith (2017) Casper FFG slashing violation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FfgSlashingKind {
    /// Rule 1: `target_epoch_1 == target_epoch_2` with distinct vote tuples.
    DoubleVote,
    /// Rule 2: `source_epoch_1 < source_epoch_2 && target_epoch_2 < target_epoch_1`.
    SurroundVote,
}

/// Self-contained pair of signed Casper FFG votes proving objective validator equivocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfgEquivocationProof {
    /// First signed checkpoint vote.
    pub vote_a: FfgVote,
    /// Second signed checkpoint vote by the same committee member.
    pub vote_b: FfgVote,
}

fn verify_single_vote_crypto(
    network: &str,
    member: &FfgValidator,
    vote: &FfgVote,
    label: &str,
) -> Result<bool, AdapterError> {
    let digest = vote.digest(network);
    crate::crypto::primitives::verify_signature(&digest, &vote.signature, &vote.signer).map_err(
        |_| AdapterError::Crypto {
            what: format!("invalid Ed25519 signature in a {label} vote"),
        },
    )?;
    if member.pq_pubkey.is_empty() {
        Ok(false)
    } else {
        if vote.pq_signature.is_empty() {
            return Err(AdapterError::Crypto {
                what: format!("a {label} vote is missing its ML-DSA-65 co-signature"),
            });
        }
        crate::crypto::primitives::PqKeyPair::verify(
            &member.pq_pubkey,
            ctx::CROSS_DOMAIN_V1,
            &digest,
            &vote.pq_signature,
        )
        .map_err(|_| AdapterError::Crypto {
            what: format!("invalid ML-DSA-65 co-signature in a {label} vote"),
        })?;
        Ok(true)
    }
}

/// Verify Casper FFG Rule-1 or Rule-2 equivocation against a pinned committee.
///
/// Returns `(violation_kind, offender_stake)` when objective slashing holds.
///
/// # Errors
///
/// Returns [`AdapterError`] if the committee is invalid, the two votes come
/// from different signers or an outsider, either vote fails structural or
/// hybrid cryptographic verification, or neither slashing rule holds.
pub fn verify_ffg_slashing_evidence(
    network: &str,
    committee: &PinnedFfgCommittee,
    proof: &FfgEquivocationProof,
) -> Result<(FfgSlashingKind, u64), AdapterError> {
    let canonical = committee.validate()?;
    let a = &proof.vote_a;
    let b = &proof.vote_b;
    if a.signer != b.signer {
        return Err(AdapterError::ConsensusRule {
            rule: "FFG equivocation proof names two different signers".to_string(),
        });
    }
    let Some(member) = canonical.validators.iter().find(|v| v.pubkey == a.signer) else {
        return Err(AdapterError::ConsensusRule {
            rule: "FFG equivocation signer is outside the pinned committee".to_string(),
        });
    };
    for v in [a, b] {
        if v.target_epoch <= v.source_epoch
            || v.source_root == [0u8; 32]
            || v.target_root == [0u8; 32]
        {
            return Err(AdapterError::ConsensusRule {
                rule: "FFG equivocation vote carries invalid checkpoint epochs or zero roots"
                    .to_string(),
            });
        }
        let _ = verify_single_vote_crypto(network, member, v, "slashing")?;
    }

    let same_transition = a.source_epoch == b.source_epoch
        && a.source_root == b.source_root
        && a.target_epoch == b.target_epoch
        && a.target_root == b.target_root;
    if a.target_epoch == b.target_epoch && !same_transition {
        return Ok((FfgSlashingKind::DoubleVote, member.stake));
    }
    let a_surrounds_b = a.source_epoch < b.source_epoch && b.target_epoch < a.target_epoch;
    let b_surrounds_a = b.source_epoch < a.source_epoch && a.target_epoch < b.target_epoch;
    if a_surrounds_b || b_surrounds_a {
        return Ok((FfgSlashingKind::SurroundVote, member.stake));
    }
    Err(AdapterError::ConsensusRule {
        rule:
            "vote pair satisfies neither Casper FFG Rule-1 (DoubleVote) nor Rule-2 (SurroundVote)"
                .to_string(),
    })
}

/// Parsed Casper FFG checkpoint finality payload.
struct FfgEvidence {
    source_epoch: u64,
    source_root: [u8; 32],
    parent_root: [u8; 32],
    target_epoch: u64,
    target_root: [u8; 32],
    source_votes: Vec<FfgVote>,
    target_votes: Vec<FfgVote>,
}

/// Bounds-checked cursor over the Casper FFG wire payload.
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
                reason: "length overflow".to_string(),
            })?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| AdapterError::Malformed {
                offset,
                reason: format!("needs {len} bytes past the end"),
            })?;
        self.at = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, AdapterError> {
        let raw = self.take(4)?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(raw);
        Ok(u32::from_le_bytes(buf))
    }

    fn u64(&mut self) -> Result<u64, AdapterError> {
        let raw = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(raw);
        Ok(u64::from_le_bytes(buf))
    }

    fn root(&mut self) -> Result<[u8; 32], AdapterError> {
        let raw = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(raw);
        Ok(out)
    }

    fn blob(&mut self) -> Result<Vec<u8>, AdapterError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
}

/// Decode a binary Casper FFG payload into [`FfgEvidence`].
///
/// # Errors
///
/// Returns [`AdapterError`] on bad magic, unsupported version, trailing bytes,
/// empty/oversized vote sets, or truncated reads.
fn parse_payload(payload: &[u8]) -> Result<FfgEvidence, AdapterError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "payload is larger than this adapter reads".to_string(),
        });
    }
    let mut reader = Reader::new(payload);
    let magic = reader.take(PAYLOAD_MAGIC.len())?;
    if magic != PAYLOAD_MAGIC {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "payload magic is not a Casper FFG bundle".to_string(),
        });
    }
    let version = reader.u32()?;
    if version != FFG_EVIDENCE_VERSION {
        return Err(AdapterError::UnsupportedEvidenceVersion {
            version,
            accepted: FFG_EVIDENCE_VERSION.to_string(),
        });
    }
    let target_epoch = reader.u64()?;
    let target_root = reader.root()?;
    let source_epoch = reader.u64()?;
    let source_root = reader.root()?;
    let parent_root = reader.root()?;
    let read_votes = |reader: &mut Reader<'_>| -> Result<Vec<FfgVote>, AdapterError> {
        let count = reader.u32()? as usize;
        if count == 0 || count > MAX_VOTES {
            return Err(AdapterError::ConsensusRule {
                rule: "a vote set is empty or larger than this adapter reads".to_string(),
            });
        }
        let mut votes = Vec::with_capacity(count);
        for _ in 0..count {
            votes.push(FfgVote {
                signer: reader.root()?,
                source_epoch: reader.u64()?,
                source_root: reader.root()?,
                target_epoch: reader.u64()?,
                target_root: reader.root()?,
                signature: reader.blob()?,
                pq_signature: reader.blob()?,
            });
        }
        Ok(votes)
    };
    let source_votes = read_votes(&mut reader)?;
    let target_votes = read_votes(&mut reader)?;
    if reader.at != payload.len() {
        return Err(AdapterError::Malformed {
            offset: reader.at,
            reason: "payload carries trailing bytes this format does not define".to_string(),
        });
    }
    Ok(FfgEvidence {
        source_epoch,
        source_root,
        parent_root,
        target_epoch,
        target_root,
        source_votes,
        target_votes,
    })
}

/// Casper FFG finality adapter over a governance-pinned epoch committee.
pub struct CasperFfgAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    committee: Option<PinnedFfgCommittee>,
    members: BTreeMap<[u8; 32], FfgValidator>,
    golden: Option<RawConsensusEvidence>,
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

impl CasperFfgAdapter {
    /// Build an adapter for `network` over a validated [`PinnedFfgCommittee`].
    ///
    /// # Errors
    ///
    /// Propagates any [`PinnedFfgCommittee::validate`] refusal or empty network name.
    pub fn new(
        network: &str,
        committee: &PinnedFfgCommittee,
        golden: Option<RawConsensusEvidence>,
    ) -> Result<Self, AdapterError> {
        if network.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "Casper FFG network identifier must not be empty".to_string(),
            });
        }
        let canonical = committee.validate()?;
        Ok(Self::from_validated(network, Some(canonical), golden))
    }

    /// Build an adapter from an optional committee (used by `AdapterSpec::build`;
    /// an absent or invalid committee fails closed on `verify`).
    #[must_use]
    pub fn new_optional(network: &str, committee: Option<PinnedFfgCommittee>) -> Self {
        let validated = committee.and_then(|c| c.validate().ok());
        Self::from_validated(network, validated, None)
    }

    /// Attach a golden sample for `selftest::admit`.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn from_validated(
        network: &str,
        committee: Option<PinnedFfgCommittee>,
        golden: Option<RawConsensusEvidence>,
    ) -> Self {
        let set_size = committee
            .as_ref()
            .map_or(0, |c| u64::try_from(c.validators.len()).unwrap_or(u64::MAX));
        let id = AdapterId::from_name(CASPER_FFG_ADAPTER_NAME);
        let descriptor = AdapterDescriptor {
            id,
            name: CASPER_FFG_ADAPTER_NAME.to_string(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![FFG_EVIDENCE_VERSION],
            consensus_kind: "casper-ffg-checkpoint".to_string(),
            finality_kind: FinalityKind::EconomicFinality,
            required_depth: FINALITY_DEPTH,
            time_unit: TimeUnit::Epoch,
            trust_model: TrustModel::HonestMajority { set_size },
        };
        let members = committee
            .as_ref()
            .map(|c| c.validators.iter().map(|v| (v.pubkey, v.clone())).collect())
            .unwrap_or_default();
        Self {
            descriptor,
            network: network.to_string(),
            committee,
            members,
            golden,
        }
    }

    fn check_vote_set(
        &self,
        committee: &PinnedFfgCommittee,
        label: &str,
        votes: &[FfgVote],
        expected: (u64, [u8; 32], u64, [u8; 32]),
    ) -> Result<(u64, bool), AdapterError> {
        let (source_epoch, source_root, target_epoch, target_root) = expected;
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(votes.len());
        let mut signed = 0u128;
        let mut all_pq = true;
        for vote in votes {
            if vote.source_epoch != source_epoch
                || vote.target_epoch != target_epoch
                || vote.source_root != source_root
                || vote.target_root != target_root
            {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "a {label} vote names another checkpoint pair than the one being justified"
                    ),
                });
            }
            let Some(member) = self.members.get(&vote.signer) else {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("a {label} vote comes from outside the pinned committee"),
                });
            };
            if seen.contains(&vote.signer) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("a {label} vote set lists one signer twice"),
                });
            }
            seen.push(vote.signer);
            let used_pq = verify_single_vote_crypto(&self.network, member, vote, label)?;
            all_pq &= used_pq;
            signed = signed.saturating_add(u128::from(member.stake));
        }
        let threshold = committee.threshold_stake();
        if signed < threshold {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "the {label} vote set signed {signed} stake, below the {threshold} needed to exceed two thirds of {}",
                    committee.total_stake()
                ),
            });
        }
        Ok((u64::try_from(seen.len()).unwrap_or(u64::MAX), all_pq))
    }

    fn validate_clock_and_depth(
        target_epoch: u64,
        policy: &VerificationPolicy,
    ) -> Result<(), AdapterError> {
        if policy.min_depth > FINALITY_DEPTH {
            return Err(AdapterError::InsufficientDepth {
                observed: FINALITY_DEPTH,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 && target_epoch > policy.now {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "target checkpoint epoch {target_epoch} is ahead of caller clock {}",
                    policy.now
                ),
            });
        }
        if policy.max_age > 0 && policy.now > target_epoch {
            let age = policy.now - target_epoch;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }
        Ok(())
    }

    fn validate_envelope_and_epochs(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(&PinnedFfgCommittee, FfgEvidence), AdapterError> {
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
            let accepted = self
                .descriptor
                .accepted_evidence_versions
                .first()
                .copied()
                .unwrap_or(FFG_EVIDENCE_VERSION);
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: accepted.to_string(),
            });
        }
        if self.network.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "Casper FFG network identifier must not be empty".to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "evidence names network {:?}, this adapter serves {:?}",
                    evidence.network, self.network
                ),
            });
        }
        let Some(committee) = self.committee.as_ref() else {
            return Err(AdapterError::ConsensusRule {
                rule: "Casper FFG adapter has no valid governance-pinned epoch committee"
                    .to_string(),
            });
        };

        let parsed = parse_payload(&evidence.payload)?;
        if parsed.target_epoch <= parsed.source_epoch {
            return Err(AdapterError::ConsensusRule {
                rule: "the target checkpoint does not follow the source checkpoint".to_string(),
            });
        }
        if parsed.target_epoch != parsed.source_epoch.saturating_add(1) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "checkpoints {} and {} are not adjacent, so finality does not follow",
                    parsed.source_epoch, parsed.target_epoch
                ),
            });
        }
        if parsed.target_epoch != committee.epoch {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "target checkpoint epoch {} does not match pinned committee epoch {}",
                    parsed.target_epoch, committee.epoch
                ),
            });
        }
        if parsed.target_root == [0u8; 32]
            || parsed.source_root == [0u8; 32]
            || parsed.parent_root == [0u8; 32]
        {
            return Err(AdapterError::ConsensusRule {
                rule: "a checkpoint root is unset".to_string(),
            });
        }
        if policy.require_declared_match
            && (evidence.declared_height != parsed.target_epoch
                || evidence.declared_root != parsed.target_root)
        {
            return Err(AdapterError::DeclarationMismatch {
                field: "checkpoint",
            });
        }
        Self::validate_clock_and_depth(parsed.target_epoch, policy)?;
        Ok((committee, parsed))
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, bool), AdapterError> {
        if policy.require_slashable {
            return Err(AdapterError::ConsensusRule {
                rule: "the policy requires slashable backing; external Casper FFG committee stake is not escrowed locally".to_string(),
            });
        }
        let (committee, parsed) = self.validate_envelope_and_epochs(evidence, policy)?;
        let (source_signers, source_all_pq) = self.check_vote_set(
            committee,
            "source",
            &parsed.source_votes,
            (
                parsed.source_epoch.saturating_sub(1),
                parsed.parent_root,
                parsed.source_epoch,
                parsed.source_root,
            ),
        )?;
        let (target_signers, target_all_pq) = self.check_vote_set(
            committee,
            "target",
            &parsed.target_votes,
            (
                parsed.source_epoch,
                parsed.source_root,
                parsed.target_epoch,
                parsed.target_root,
            ),
        )?;

        let signers = source_signers.min(target_signers);
        let total_stake = committee.total_stake();
        let required =
            min_signers_for_quorum(committee.validators.iter().map(|v| v.stake), total_stake);
        let both_quorums_pq = source_all_pq && target_all_pq;
        let scheme = if both_quorums_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: parsed.target_epoch,
            state_root: parsed.target_root,
            finalized_at: parsed.target_epoch,
            time_unit: TimeUnit::Epoch,
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
            attested_block_hash: None,
            attested_event_root: None,
            attested_tx_root: None,
        };
        Ok((attestation, both_quorums_pq))
    }
}

impl ExternalFinalityAdapter for CasperFfgAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        !self.network.trim().is_empty() && self.committee.is_some()
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
        let (attestation, all_pq) = self.verify_inner(evidence, policy)?;
        if all_pq {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        } else {
            observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        }
        Ok(attestation)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        vec![
            FaultProbe {
                name: "refuses unknown Casper FFG evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 7 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign Casper FFG network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared checkpoint epoch".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared checkpoint root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xfe; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted Casper FFG payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"XXXXXXXX".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses a truncated Casper FFG payload".into(),
                patch: BytePatch::TruncatePayload { keep: 12 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }

    fn attested_parent(&self, evidence: &RawConsensusEvidence) -> Option<[u8; 32]> {
        parse_payload(&evidence.payload)
            .ok()
            .map(|parsed| parsed.parent_root)
            .filter(|root| *root != [0u8; 32])
    }
}

/// Encode a canonical Casper FFG two-epoch finality payload.
///
/// WIRING: wire encoder for `CasperFfgAdapter` payloads used by `intake.rs` and tests.
#[must_use]
pub fn encode_ffg_payload(
    source_epoch: u64,
    source_root: [u8; 32],
    parent_root: [u8; 32],
    target_epoch: u64,
    target_root: [u8; 32],
    source_votes: &[FfgVote],
    target_votes: &[FfgVote],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&FFG_EVIDENCE_VERSION.to_le_bytes());
    out.extend_from_slice(&target_epoch.to_le_bytes());
    out.extend_from_slice(&target_root);
    out.extend_from_slice(&source_epoch.to_le_bytes());
    out.extend_from_slice(&source_root);
    out.extend_from_slice(&parent_root);
    for set in [source_votes, target_votes] {
        out.extend_from_slice(&u32::try_from(set.len()).unwrap_or(u32::MAX).to_le_bytes());
        for v in set {
            out.extend_from_slice(&v.signer);
            out.extend_from_slice(&v.source_epoch.to_le_bytes());
            out.extend_from_slice(&v.source_root);
            out.extend_from_slice(&v.target_epoch.to_le_bytes());
            out.extend_from_slice(&v.target_root);
            out.extend_from_slice(
                &u32::try_from(v.signature.len())
                    .unwrap_or(u32::MAX)
                    .to_le_bytes(),
            );
            out.extend_from_slice(&v.signature);
            out.extend_from_slice(
                &u32::try_from(v.pq_signature.len())
                    .unwrap_or(u32::MAX)
                    .to_le_bytes(),
            );
            out.extend_from_slice(&v.pq_signature);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::admit;
    use crate::crypto::facts::CryptoFacts;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    const NETWORK: &str = "budlum-ffg";
    const SOURCE_EPOCH: u64 = 10;
    const TARGET_EPOCH: u64 = 11;
    const SOURCE_ROOT: [u8; 32] = [0x11; 32];
    const PARENT_ROOT: [u8; 32] = [0x10; 32];
    const TARGET_ROOT: [u8; 32] = [0x12; 32];

    struct Signer {
        key: KeyPair,
        pubkey: [u8; 32],
        pq: Option<PqKeyPair>,
    }

    fn signers() -> (Vec<Signer>, PinnedFfgCommittee) {
        let mut signers = Vec::new();
        let mut members = Vec::new();
        for seed in 1u8..=4 {
            let key = KeyPair::from_seed(&[seed; 32]).expect("key");
            let pubkey = key.public_key_bytes();
            members.push(FfgValidator {
                pubkey,
                stake: 100,
                pq_pubkey: Vec::new(),
            });
            signers.push(Signer {
                key,
                pubkey,
                pq: None,
            });
        }
        (
            signers,
            PinnedFfgCommittee::new(TARGET_EPOCH, members).expect("committee"),
        )
    }

    fn vote_on(
        network: &str,
        signer: &Signer,
        source: u64,
        source_root: [u8; 32],
        target: u64,
        target_root: [u8; 32],
    ) -> FfgVote {
        let mut v = FfgVote {
            signer: signer.pubkey,
            source_epoch: source,
            source_root,
            target_epoch: target,
            target_root,
            signature: Vec::new(),
            pq_signature: Vec::new(),
        };
        let digest = v.digest(network);
        v.signature = signer.key.sign(&digest).to_vec();
        if let Some(pq) = &signer.pq {
            v.pq_signature = pq.sign(ctx::CROSS_DOMAIN_V1, &digest).expect("pq sign");
        }
        v
    }

    fn vote(
        signer: &Signer,
        source: u64,
        source_root: [u8; 32],
        target: u64,
        target_root: [u8; 32],
    ) -> FfgVote {
        vote_on(NETWORK, signer, source, source_root, target, target_root)
    }

    fn encode(
        source_epoch: u64,
        source_root: [u8; 32],
        parent_root: [u8; 32],
        target_epoch: u64,
        target_root: [u8; 32],
        source_votes: &[FfgVote],
        target_votes: &[FfgVote],
    ) -> Vec<u8> {
        encode_ffg_payload(
            source_epoch,
            source_root,
            parent_root,
            target_epoch,
            target_root,
            source_votes,
            target_votes,
        )
    }

    fn evidence_with(
        signers: &[Signer],
        source_take: usize,
        target_take: usize,
    ) -> RawConsensusEvidence {
        let source_votes: Vec<FfgVote> = signers
            .iter()
            .take(source_take)
            .map(|s| vote(s, SOURCE_EPOCH - 1, PARENT_ROOT, SOURCE_EPOCH, SOURCE_ROOT))
            .collect();
        let target_votes: Vec<FfgVote> = signers
            .iter()
            .take(target_take)
            .map(|s| vote(s, SOURCE_EPOCH, SOURCE_ROOT, TARGET_EPOCH, TARGET_ROOT))
            .collect();
        let payload = encode(
            SOURCE_EPOCH,
            SOURCE_ROOT,
            PARENT_ROOT,
            TARGET_EPOCH,
            TARGET_ROOT,
            &source_votes,
            &target_votes,
        );
        RawConsensusEvidence {
            adapter: AdapterId::from_name(CASPER_FFG_ADAPTER_NAME),
            evidence_version: FFG_EVIDENCE_VERSION,
            network: NETWORK.to_string(),
            payload,
            declared_height: TARGET_EPOCH,
            declared_root: TARGET_ROOT,
            submitter: Address::from([0x09; 32]),
        }
    }

    fn adapter_with(signers: &[Signer], committee: &PinnedFfgCommittee) -> CasperFfgAdapter {
        let golden = evidence_with(signers, 3, 3);
        CasperFfgAdapter::new(NETWORK, committee, Some(golden)).expect("adapter")
    }

    fn policy() -> VerificationPolicy {
        let mut p = VerificationPolicy::strict(0);
        p.require_slashable = false;
        p
    }

    #[test]
    fn a_two_checkpoint_chain_with_two_thirds_stake_finalises() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let evidence = evidence_with(&signers, 3, 3);
        let attestation = adapter.verify(&evidence, &policy()).expect("finalises");
        assert_eq!(attestation.height, TARGET_EPOCH);
        assert_eq!(attestation.state_root, TARGET_ROOT);
        assert_eq!(attestation.time_unit, TimeUnit::Epoch);
        assert_eq!(
            attestation.security.observed_scheme(),
            Some(ObservedScheme::Scheme(SchemeId::ED25519))
        );
        match attestation.security {
            SecurityBacking::SignatureSet {
                slashable,
                total_weight,
                ..
            } => {
                assert!(
                    !slashable,
                    "external Casper FFG committee stake is not escrowed locally"
                );
                assert_eq!(total_weight, committee.total_stake());
            }
            other => panic!("unexpected backing: {other:?}"),
        }
        assert_eq!(
            attestation.adapter,
            AdapterId::from_name(CASPER_FFG_ADAPTER_NAME)
        );
    }

    #[test]
    fn the_pinned_committee_threshold_is_strictly_more_than_two_thirds() {
        let (_signers, committee) = signers();
        assert_eq!(committee.total_stake(), 400);
        assert_eq!(committee.threshold_stake(), 267);
    }

    #[test]
    fn exactly_two_thirds_of_stake_is_refused() {
        let (mut signers, mut committee) = signers();
        for member in &mut committee.validators {
            member.stake = 99;
        }
        committee =
            PinnedFfgCommittee::new(TARGET_EPOCH, committee.validators.clone()).expect("committee");
        for s in &mut signers {
            assert!(!s.pubkey.is_empty());
        }
        let adapter = adapter_with(&signers, &committee);
        let evidence = evidence_with(&signers, 2, 2);
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        assert!(
            matches!(err, AdapterError::ConsensusRule { .. }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn non_adjacent_checkpoints_are_refused() {
        let (signers, committee) = signers();
        let shifted =
            PinnedFfgCommittee::new(TARGET_EPOCH + 1, committee.validators).expect("committee");
        let adapter = adapter_with(&signers, &shifted);
        let source_votes: Vec<FfgVote> = signers
            .iter()
            .take(3)
            .map(|s| {
                vote(
                    s,
                    SOURCE_EPOCH - 2,
                    PARENT_ROOT,
                    SOURCE_EPOCH - 1,
                    SOURCE_ROOT,
                )
            })
            .collect();
        let target_votes: Vec<FfgVote> = signers
            .iter()
            .take(3)
            .map(|s| vote(s, SOURCE_EPOCH, SOURCE_ROOT, TARGET_EPOCH + 1, TARGET_ROOT))
            .collect();
        let payload = encode(
            SOURCE_EPOCH,
            SOURCE_ROOT,
            PARENT_ROOT,
            TARGET_EPOCH + 1,
            TARGET_ROOT,
            &source_votes,
            &target_votes,
        );
        let mut evidence = evidence_with(&signers, 3, 3);
        evidence.payload = payload;
        evidence.declared_height = TARGET_EPOCH + 1;
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("not adjacent"), "unexpected: {rule}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_signer_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let mut evidence = evidence_with(&signers, 3, 3);
        let parsed = parse_payload(&evidence.payload).expect("payload");
        let mut duplicated = parsed.target_votes.clone();
        if let Some(first) = parsed.target_votes.first() {
            duplicated.push(first.clone());
        }
        evidence.payload = encode(
            SOURCE_EPOCH,
            SOURCE_ROOT,
            PARENT_ROOT,
            TARGET_EPOCH,
            TARGET_ROOT,
            &parsed.source_votes,
            &duplicated,
        );
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("twice"), "unexpected: {rule}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_vote_from_outside_the_committee_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let outsider_key = KeyPair::from_seed(&[0x77; 32]).expect("key");
        let outsider = Signer {
            pubkey: outsider_key.public_key_bytes(),
            key: outsider_key,
            pq: None,
        };
        let parsed = parse_payload(&evidence_with(&signers, 3, 3).payload).expect("payload");
        let mut target_votes = parsed.target_votes.clone();
        target_votes.push(vote(
            &outsider,
            SOURCE_EPOCH,
            SOURCE_ROOT,
            TARGET_EPOCH,
            TARGET_ROOT,
        ));
        let mut evidence = evidence_with(&signers, 3, 3);
        evidence.payload = encode(
            SOURCE_EPOCH,
            SOURCE_ROOT,
            PARENT_ROOT,
            TARGET_EPOCH,
            TARGET_ROOT,
            &parsed.source_votes,
            &target_votes,
        );
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => assert!(
                rule.contains("outside the pinned committee"),
                "unexpected: {rule}"
            ),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_vote_for_another_source_root_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let source_votes: Vec<FfgVote> = signers
            .iter()
            .take(3)
            .map(|s| vote(s, SOURCE_EPOCH - 1, PARENT_ROOT, SOURCE_EPOCH, SOURCE_ROOT))
            .collect();
        let target_votes: Vec<FfgVote> = signers
            .iter()
            .take(3)
            .map(|s| vote(s, SOURCE_EPOCH, [0x99; 32], TARGET_EPOCH, TARGET_ROOT))
            .collect();
        let mut evidence = evidence_with(&signers, 3, 3);
        evidence.payload = encode(
            SOURCE_EPOCH,
            SOURCE_ROOT,
            PARENT_ROOT,
            TARGET_EPOCH,
            TARGET_ROOT,
            &source_votes,
            &target_votes,
        );
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => assert!(
                rule.contains("another checkpoint pair"),
                "unexpected: {rule}"
            ),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let parsed = parse_payload(&evidence_with(&signers, 3, 3).payload).expect("payload");
        let mut target_votes = parsed.target_votes.clone();
        if let Some(first) = target_votes.first_mut() {
            if let Some(byte) = first.signature.first_mut() {
                *byte ^= 0xff;
            }
        }
        let mut evidence = evidence_with(&signers, 3, 3);
        evidence.payload = encode(
            SOURCE_EPOCH,
            SOURCE_ROOT,
            PARENT_ROOT,
            TARGET_EPOCH,
            TARGET_ROOT,
            &parsed.source_votes,
            &target_votes,
        );
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        assert!(
            matches!(err, AdapterError::Crypto { .. }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn a_declared_height_that_does_not_match_the_payload_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let mut evidence = evidence_with(&signers, 3, 3);
        evidence.declared_height = TARGET_EPOCH + 5;
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        assert!(
            matches!(err, AdapterError::DeclarationMismatch { field } if field == "checkpoint"),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn a_depth_requirement_above_two_epochs_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let mut strict = policy();
        strict.min_depth = 3;
        let err = adapter
            .verify(&evidence_with(&signers, 3, 3), &strict)
            .unwrap_err();
        assert!(
            matches!(
                err,
                AdapterError::InsufficientDepth {
                    observed: 2,
                    required: 3
                }
            ),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn stale_evidence_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let mut aged = policy();
        aged.max_age = 2;
        aged.now = TARGET_EPOCH + 9;
        let err = adapter
            .verify(&evidence_with(&signers, 3, 3), &aged)
            .unwrap_err();
        assert!(
            matches!(err, AdapterError::Stale { age: 9, max_age: 2 }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn unpinned_checkpoint_epoch_is_refused_by_epoch_bound_committee() {
        let (signers, committee) = signers();
        let wrong_epoch_committee =
            PinnedFfgCommittee::new(TARGET_EPOCH + 5, committee.validators).expect("committee");
        let adapter = adapter_with(&signers, &wrong_epoch_committee);
        let err = adapter
            .verify(&evidence_with(&signers, 3, 3), &policy())
            .unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(
                    rule.contains("pinned committee epoch"),
                    "unexpected: {rule}"
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn future_dated_target_epoch_is_refused_when_clock_is_supplied() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let mut clocked = policy();
        clocked.max_age = 4;
        clocked.now = TARGET_EPOCH - 1;
        let err = adapter
            .verify(&evidence_with(&signers, 3, 3), &clocked)
            .unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => {
                assert!(rule.contains("ahead of caller clock"), "unexpected: {rule}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn cross_network_replayed_vote_signatures_are_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let foreign_source: Vec<FfgVote> = signers
            .iter()
            .take(3)
            .map(|s| {
                vote_on(
                    "sister-ffg-testnet",
                    s,
                    SOURCE_EPOCH - 1,
                    PARENT_ROOT,
                    SOURCE_EPOCH,
                    SOURCE_ROOT,
                )
            })
            .collect();
        let foreign_target: Vec<FfgVote> = signers
            .iter()
            .take(3)
            .map(|s| {
                vote_on(
                    "sister-ffg-testnet",
                    s,
                    SOURCE_EPOCH,
                    SOURCE_ROOT,
                    TARGET_EPOCH,
                    TARGET_ROOT,
                )
            })
            .collect();
        let mut replayed = evidence_with(&signers, 3, 3);
        replayed.payload = encode(
            SOURCE_EPOCH,
            SOURCE_ROOT,
            PARENT_ROOT,
            TARGET_EPOCH,
            TARGET_ROOT,
            &foreign_source,
            &foreign_target,
        );
        let err = adapter.verify(&replayed, &policy()).unwrap_err();
        assert!(
            matches!(err, AdapterError::Crypto { .. }),
            "cross-network replay must fail signature check: {err:?}"
        );
    }

    #[test]
    fn require_slashable_policy_refuses_unbonded_external_committee_stake() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let mut strict = VerificationPolicy::strict(0);
        strict.require_slashable = true;
        let err = adapter
            .verify(&evidence_with(&signers, 3, 3), &strict)
            .unwrap_err();
        assert!(matches!(err, AdapterError::ConsensusRule { .. }));
    }

    #[test]
    fn hybrid_ml_dsa_committee_observes_pq_and_refuses_stripped_cosignature() {
        let mut pq_signers = Vec::new();
        let mut members = Vec::new();
        for seed in 1u8..=4 {
            let key = KeyPair::from_seed(&[seed; 32]).expect("ed25519");
            let pubkey = key.public_key_bytes();
            let pq = PqKeyPair::generate();
            members.push(FfgValidator {
                pubkey,
                stake: 100,
                pq_pubkey: pq.public_key_bytes().to_vec(),
            });
            pq_signers.push(Signer {
                key,
                pubkey,
                pq: Some(pq),
            });
        }
        let committee = PinnedFfgCommittee::new(TARGET_EPOCH, members).expect("pq committee");
        let adapter = adapter_with(&pq_signers, &committee);
        let ev = evidence_with(&pq_signers, 3, 3);
        let mut obs = CryptoFacts::default();
        let att = adapter
            .verify_observed(&ev, &policy(), &mut obs)
            .expect("hybrid verify");
        assert_eq!(
            att.security.observed_scheme(),
            Some(ObservedScheme::Scheme(SchemeId::ML_DSA_65))
        );

        let mut parsed = parse_payload(&ev.payload).expect("parse");
        if let Some(first) = parsed.source_votes.first_mut() {
            first.pq_signature.clear();
        }
        let mut stripped = ev;
        stripped.payload = encode(
            SOURCE_EPOCH,
            SOURCE_ROOT,
            PARENT_ROOT,
            TARGET_EPOCH,
            TARGET_ROOT,
            &parsed.source_votes,
            &parsed.target_votes,
        );
        let err = adapter.verify(&stripped, &policy()).unwrap_err();
        assert!(matches!(err, AdapterError::Crypto { .. }));
    }

    #[test]
    fn slashing_verifier_proves_rule1_double_vote_and_rule2_surround_vote() {
        let (signers, committee) = signers();
        let offender = signers.first().expect("offender");

        let v1 = vote(offender, 10, [0x21; 32], 11, [0x31; 32]);
        let v2 = vote(offender, 10, [0x21; 32], 11, [0x32; 32]);
        let (kind, stake) = verify_ffg_slashing_evidence(
            NETWORK,
            &committee,
            &FfgEquivocationProof {
                vote_a: v1.clone(),
                vote_b: v2,
            },
        )
        .expect("double vote");
        assert_eq!(kind, FfgSlashingKind::DoubleVote);
        assert_eq!(stake, 100);

        assert!(verify_ffg_slashing_evidence(
            NETWORK,
            &committee,
            &FfgEquivocationProof {
                vote_a: v1.clone(),
                vote_b: v1,
            },
        )
        .is_err());

        let outer = vote(offender, 8, [0x41; 32], 13, [0x51; 32]);
        let inner = vote(offender, 9, [0x42; 32], 12, [0x52; 32]);
        let (kind2, _) = verify_ffg_slashing_evidence(
            NETWORK,
            &committee,
            &FfgEquivocationProof {
                vote_a: outer,
                vote_b: inner,
            },
        )
        .expect("surround vote");
        assert_eq!(kind2, FfgSlashingKind::SurroundVote);

        let step1 = vote(offender, 9, [0x61; 32], 10, [0x62; 32]);
        let step2 = vote(offender, 10, [0x62; 32], 11, [0x63; 32]);
        assert!(verify_ffg_slashing_evidence(
            NETWORK,
            &committee,
            &FfgEquivocationProof {
                vote_a: step1,
                vote_b: step2,
            },
        )
        .is_err());
    }

    #[test]
    fn the_fault_probe_suite_admits_the_adapter() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);
        let report = admit(&adapter, &policy());
        assert!(report.golden_verified, "the golden sample must verify");
        for (name, outcome) in &report.probes {
            assert!(
                matches!(
                    outcome,
                    crate::cross_domain::external::selftest::ProbeOutcome::Refused { .. }
                ),
                "probe {name} did not refuse: {outcome:?}"
            );
        }
        assert!(report.admitted, "admission failed: {report:?}");
    }

    #[test]
    fn regression_intake_live_clock_skewed_stake_and_empty_network() {
        use crate::domain::finality_proof_model::FinalityProofShape;

        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, &committee);

        // 1. IntakeState::submit sets policy.now = last_accepted_height (> 0)
        // while policy.max_age == 0 (VerificationPolicy::strict(0)). Subsequent epochs
        // must advance cleanly without deadlocking on "ahead of caller clock".
        let mut intake_live_policy = VerificationPolicy::strict(SOURCE_EPOCH);
        intake_live_policy.max_age = 0;
        intake_live_policy.require_slashable = false;
        let att_3_4 = adapter
            .verify(&evidence_with(&signers, 3, 4), &intake_live_policy)
            .expect("IntakeState live_policy_clock with max_age == 0 must not deadlock epoch N+1");

        // 2. Weakest-link signer count across source (3) and target (4) checkpoints.
        assert!(
            matches!(
                att_3_4.security,
                SecurityBacking::SignatureSet {
                    signers: 3,
                    required: 3,
                    ..
                }
            ),
            "Casper FFG must report weakest-link min(source_signers, target_signers), got {:?}",
            att_3_4.security
        );

        // 3. Skewed stake [800, 100, 100, 100] (800/1100 > 2/3) signed by validator 0 alone.
        let skewed_members: Vec<FfgValidator> = signers
            .iter()
            .enumerate()
            .map(|(i, s)| FfgValidator {
                pubkey: s.pubkey,
                stake: if i == 0 { 800 } else { 100 },
                pq_pubkey: Vec::new(),
            })
            .collect();
        let skewed_committee =
            PinnedFfgCommittee::new(TARGET_EPOCH, skewed_members).expect("skewed committee");
        let skewed_ev = evidence_with(&signers, 1, 1);
        let skewed_adapter =
            CasperFfgAdapter::new(NETWORK, &skewed_committee, None).expect("skewed adapter");
        let skewed_att = skewed_adapter
            .verify(&skewed_ev, &policy())
            .expect("single >2/3 Casper validator verifies");
        FinalityProofShape::from_external_attestation(&skewed_adapter.descriptor(), &skewed_att)
            .expect("skewed >2/3 Casper FFG quorum must pass FinalityProofShape");

        // 4. Empty/whitespace network must be refused.
        assert!(CasperFfgAdapter::new("   ", &skewed_committee, None).is_err());
    }

    #[test]
    fn casper_ffg_preserves_lattice_quantum_class_and_suppresses_zero_attested_parent() {
        use crate::crypto::facts::QuantumClass;

        let mut pq_signers = Vec::new();
        let mut pq_members = Vec::new();
        for seed in 1u8..=4 {
            let key = KeyPair::from_seed(&[seed; 32]).expect("key");
            let pubkey = key.public_key_bytes();
            let pq = PqKeyPair::generate();
            pq_members.push(FfgValidator {
                pubkey,
                stake: 100,
                pq_pubkey: pq.public_key_bytes().to_vec(),
            });
            pq_signers.push(Signer {
                key,
                pubkey,
                pq: Some(pq),
            });
        }
        let pq_committee = PinnedFfgCommittee::new(TARGET_EPOCH, pq_members).expect("committee");
        let pq_adapter = adapter_with(&pq_signers, &pq_committee);
        let pq_ev = evidence_with(&pq_signers, 3, 3);
        let mut facts = CryptoFacts::default();
        pq_adapter
            .verify_observed(&pq_ev, &policy(), &mut facts)
            .expect("hybrid PQ Casper FFG verifies");
        assert_eq!(
            facts.quantum_class(),
            Some(QuantumClass::Lattice),
            "100% ML-DSA-65 Casper FFG committee must preserve QuantumClass::Lattice"
        );

        let mut zero_parent_ev = pq_ev;
        zero_parent_ev.payload = encode(
            SOURCE_EPOCH,
            SOURCE_ROOT,
            [0u8; 32],
            TARGET_EPOCH,
            TARGET_ROOT,
            &[],
            &[],
        );
        assert_eq!(
            pq_adapter.attested_parent(&zero_parent_ev),
            None,
            "all-zero parent_root must not be reported as a bound parent"
        );
    }
}
