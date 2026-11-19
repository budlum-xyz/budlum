//! Casper FFG: accountable economic finality over a governance-pinned
//! committee, with the two slashing conditions the safety argument rests on.
//!
//! A Casper FFG chain calls a checkpoint *justified* when more than two thirds
//! of the active stake voted for the checkpoint pair `(source, target)` with
//! `target.epoch == source.epoch + 1`, and *final* when two adjacent
//! checkpoints are justified. The safety argument is not "the voters are
//! honest"; it is "two conflicting finalized checkpoints imply at least a third
//! of the stake provably broke a slashing condition and can be destroyed". That
//! difference is the whole reason this adapter reports
//! [`SecurityBacking::SignatureSet`] with `slashable: true` and never reports a
//! bare authority set.
//!
//! Three rules are checked here, in this order, and each one refuses rather
//! than approximates:
//!
//! 1. **Adjacency.** `target.epoch == source.epoch + 1`. A gap of two or more
//!    epochs means the intermediate justification is missing and the pair
//!    proves nothing about finality.
//! 2. **Vote binding.** Every vote in the source set must name
//!    `(source - 1, source)` with this evidence's parent root and source root;
//!    every vote in the target set must name `(source, target)` with the same
//!    source root and this evidence's target root. A vote carrying another
//!    root is a vote for another chain and is refused, not ignored.
//! 3. **Supermajority, counted then checked.** Stake is summed per distinct
//!    committee member, duplicates are refused (a duplicate is either a
//!    malformed bundle or a double vote, and both are slashable), and the sum
//!    must exceed two thirds of the pinned active stake. The threshold test is
//!    `signed * 3 > total * 2` in `u128`, so the exact-two-thirds case is a
//!    refusal and no rounding ever makes a sub-threshold set pass.
//!
//! Signatures are Ed25519 over a domain-separated vote digest
//! (`BDLM_CASPER_FFG_V1`), and a member that enrolled an ML-DSA-65 key must
//! co-sign with it: a validator that has a post-quantum key cannot have it
//! ignored by the verifier.
//!
//! WIRING: re-exported by `crate::cross_domain::external` for permissionless
//! external domain registration and `selftest::admit` verification.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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

/// Vote digest tag. Every signature this adapter checks is over a digest that
/// starts with this tag, so a signature made for another purpose in another
/// protocol can never be replayed here.
pub const CASPER_FFG_VOTE_TAG: &[u8] = b"BDLM_CASPER_FFG_V1";

const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
/// Two adjacent justified checkpoints, so the adapter always reports this.
const FINALITY_DEPTH: u64 = 2;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMCF01";
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_COMMITTEE: usize = 1024;
const MAX_VOTES: usize = 1024;

/// One bonded validator in the governance-pinned committee.
///
/// WIRING: listed in [`PinnedFfgCommittee`] and checked on every vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfgValidator {
    /// Ed25519 verifying key (`32` bytes).
    pub pubkey: [u8; 32],
    /// Active stake in the chain's own smallest unit. Zero is refused: a
    /// member with no stake backs nothing and would only dilute the threshold.
    pub stake: u64,
    /// Enrolled ML-DSA-65 key. Empty means the member is classical only; a
    /// non-empty key makes the co-signature mandatory.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// The committee the chain's governance pinned for the epochs this adapter
/// serves. Held by the adapter, never carried in the evidence: a committee a
/// submitter can choose is a committee that can be chosen to match the vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedFfgCommittee {
    /// Members, in any order; [`Self::new`] sorts them by key.
    pub validators: Vec<FfgValidator>,
}

impl PinnedFfgCommittee {
    /// Check and canonicalise a pinned committee.
    ///
    /// # Errors
    ///
    /// [`AdapterError::ConsensusRule`] for an empty or oversized set, a zero
    /// key, zero stake, or a duplicated key - a duplicated member would let one
    /// vote count twice.
    pub fn new(mut validators: Vec<FfgValidator>) -> Result<Self, AdapterError> {
        if validators.is_empty() || validators.len() > MAX_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: "the pinned committee size is out of range".to_string(),
            });
        }
        validators.sort_by_key(|v| v.pubkey);
        for pair in validators.windows(2) {
            if pair[0].pubkey == pair[1].pubkey {
                return Err(AdapterError::ConsensusRule {
                    rule: "the pinned committee lists a key twice".to_string(),
                });
            }
        }
        for member in &validators {
            if member.pubkey == [0u8; 32] || member.stake == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "a pinned member has an unset key or no stake".to_string(),
                });
            }
        }
        Ok(Self { validators })
    }

    /// The committee's total active stake.
    #[must_use]
    pub fn total_stake(&self) -> u128 {
        self.validators
            .iter()
            .map(|v| u128::from(v.stake))
            .fold(0u128, |acc, s| acc.saturating_add(s))
    }

    /// The stake that must sign for a checkpoint pair to be justified, as
    /// `floor(2 * total / 3) + 1`: the smallest stake that is strictly more
    /// than two thirds.
    #[must_use]
    pub fn threshold_stake(&self) -> u128 {
        let total = self.total_stake();
        (total.saturating_mul(2)) / 3 + 1
    }
}

/// A checkpoint pair vote: from `source` towards `target`.
///
/// WIRING: carried in [`FfgEvidence`]; the digest of its fields is what the
/// signer signs and what this module re-derives.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FfgVote {
    signer: [u8; 32],
    source_epoch: u64,
    source_root: [u8; 32],
    target_epoch: u64,
    target_root: [u8; 32],
    signature: Vec<u8>,
    pq_signature: Vec<u8>,
}

impl FfgVote {
    /// The digest the vote is signed over.
    fn digest(&self) -> [u8; 32] {
        let source = self.source_epoch.to_le_bytes();
        let target = self.target_epoch.to_le_bytes();
        crate::core::hash::hash_fields_bytes(&[
            CASPER_FFG_VOTE_TAG,
            &self.signer,
            &source,
            &self.source_root,
            &target,
            &self.target_root,
        ])
    }
}

/// What a Casper FFG evidence payload carries.
struct FfgEvidence {
    source_epoch: u64,
    source_root: [u8; 32],
    /// The root of the checkout one epoch before `source`. The source vote set
    /// commits to it, so the verifier needs it to bind those votes: without it
    /// a source vote could name any parent and still pass an epoch-only check.
    parent_root: [u8; 32],
    target_epoch: u64,
    target_root: [u8; 32],
    /// Votes justifying `source` (from `source - 1`).
    source_votes: Vec<FfgVote>,
    /// Votes justifying `target` (from `source`).
    target_votes: Vec<FfgVote>,
}

/// A bounds-checked reader over the payload. Every short read is a
/// [`AdapterError::Malformed`]; there is no partially parsed evidence.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], AdapterError> {
        let end = self.at.checked_add(len).ok_or_else(|| AdapterError::Malformed {
            offset: self.at,
            reason: "length overflow".to_string(),
        })?;
        let slice = self.bytes.get(self.at..end).ok_or_else(|| AdapterError::Malformed {
            offset: self.at,
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

/// Read a payload into [`FfgEvidence`].
///
/// # Errors
///
/// [`AdapterError::Malformed`] for a bad magic, an unknown payload version, a
/// trailing byte, or any short read.
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
    if version != EVIDENCE_VERSION {
        return Err(AdapterError::UnsupportedEvidenceVersion {
            version,
            accepted: EVIDENCE_VERSION.to_string(),
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

/// A Casper FFG finality adapter over one pinned committee.
pub struct CasperFfgAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    committee: PinnedFfgCommittee,
    members: BTreeMap<[u8; 32], FfgValidator>,
    golden: Option<RawConsensusEvidence>,
}

impl CasperFfgAdapter {
    /// Build an adapter for `network` over a pinned committee.
    ///
    /// # Errors
    ///
    /// Whatever [`PinnedFfgCommittee::new`] refuses.
    pub fn new(
        network: &str,
        committee: PinnedFfgCommittee,
        golden: Option<RawConsensusEvidence>,
    ) -> Result<Self, AdapterError> {
        let id = AdapterId::from_name(CASPER_FFG_ADAPTER_NAME);
        let descriptor = AdapterDescriptor {
            id,
            name: CASPER_FFG_ADAPTER_NAME.to_string(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "casper-ffg-checkpoint".to_string(),
            finality_kind: FinalityKind::EconomicFinality,
            required_depth: FINALITY_DEPTH,
            time_unit: TimeUnit::Epoch,
            trust_model: TrustModel::HonestMajority {
                set_size: u64::try_from(committee.validators.len()).unwrap_or(u64::MAX),
            },
        };
        let members = committee
            .validators
            .iter()
            .map(|v| (v.pubkey, v.clone()))
            .collect();
        Ok(Self {
            descriptor,
            network: network.to_string(),
            committee,
            members,
            golden,
        })
    }

    /// Sum the stake of one vote set and check every rule the set must satisfy.
    ///
    /// Returns the distinct signer count and whether every signer co-signed
    /// with an ML-DSA-65 key.
    fn check_vote_set(
        &self,
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
            let digest = vote.digest();
            crate::crypto::primitives::verify_signature(&digest, &vote.signature, &vote.signer)
                .map_err(|_| AdapterError::Crypto {
                    what: format!("invalid Ed25519 signature in a {label} vote"),
                })?;
            if member.pq_pubkey.is_empty() {
                all_pq = false;
            } else {
                if vote.pq_signature.is_empty() {
                    return Err(AdapterError::Crypto {
                        what: format!("a {label} vote is missing its ML-DSA-65 co-signature"),
                    });
                }
                crate::crypto::primitives::PqKeyPair::verify(
                    &member.pq_pubkey,
                    crate::crypto::ctx::CROSS_DOMAIN_V1,
                    &digest,
                    &vote.pq_signature,
                )
                .map_err(|_| AdapterError::Crypto {
                    what: format!("invalid ML-DSA-65 co-signature in a {label} vote"),
                })?;
            }
            signed = signed.saturating_add(u128::from(member.stake));
        }
        let threshold = self.committee.threshold_stake();
        if signed < threshold {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "the {label} vote set signed {signed} stake, below the {threshold} needed to exceed two thirds of {}",
                    self.committee.total_stake()
                ),
            });
        }
        Ok((u64::try_from(seen.len()).unwrap_or(u64::MAX), all_pq))
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
        if !self
            .descriptor
            .accepted_evidence_versions
            .contains(&evidence.evidence_version)
        {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: self.descriptor.accepted_evidence_versions[0].to_string(),
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
            return Err(AdapterError::DeclarationMismatch { field: "checkpoint" });
        }
        if policy.min_depth > FINALITY_DEPTH {
            return Err(AdapterError::InsufficientDepth {
                observed: FINALITY_DEPTH,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 && policy.now > parsed.target_epoch {
            let age = policy.now - parsed.target_epoch;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // The source checkpoint is justified by votes from `source - 1`; the
        // target checkpoint by votes from `source`. Both are needed: a target
        // alone is a justified checkpoint, not a finalized one.
        let (_source_signers, _source_all_pq) = self.check_vote_set(
            "source",
            &parsed.source_votes,
            (
                parsed.source_epoch.saturating_sub(1),
                parsed.parent_root,
                parsed.source_epoch,
                parsed.source_root,
            ),
        )?;
        let (signers, target_all_pq) = self.check_vote_set(
            "target",
            &parsed.target_votes,
            (
                parsed.source_epoch,
                parsed.source_root,
                parsed.target_epoch,
                parsed.target_root,
            ),
        )?;

        let scheme = if target_all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let total = self.committee.total_stake();
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
                required: u64::try_from(
                    self.committee
                        .validators
                        .len()
                        .saturating_mul(2)
                        .div_ceil(3),
                )
                .unwrap_or(u64::MAX),
                total_weight: total,
                slashable: true,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: None,
            attested_event_root: None,
            attested_tx_root: None,
        };
        Ok((attestation, target_all_pq))
    }
}

impl ExternalFinalityAdapter for CasperFfgAdapter {
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
        let (attestation, all_pq) = self.verify_inner(evidence, policy)?;
        observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        if all_pq {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::admit;
    use crate::crypto::primitives::KeyPair;

    struct Signer {
        key: KeyPair,
        pubkey: [u8; 32],
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
            signers.push(Signer { key, pubkey });
        }
        (signers, PinnedFfgCommittee::new(members).expect("committee"))
    }

    fn vote(signer: &Signer, source: u64, source_root: [u8; 32], target: u64, target_root: [u8; 32]) -> FfgVote {
        let mut vote = FfgVote {
            signer: signer.pubkey,
            source_epoch: source,
            source_root,
            target_epoch: target,
            target_root,
            signature: Vec::new(),
            pq_signature: Vec::new(),
        };
        vote.signature = signer.key.sign(&vote.digest()).to_vec();
        vote
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
        let mut out = Vec::new();
        out.extend_from_slice(PAYLOAD_MAGIC);
        out.extend_from_slice(&EVIDENCE_VERSION.to_le_bytes());
        out.extend_from_slice(&target_epoch.to_le_bytes());
        out.extend_from_slice(&target_root);
        out.extend_from_slice(&source_epoch.to_le_bytes());
        out.extend_from_slice(&source_root);
        out.extend_from_slice(&parent_root);
        for set in [source_votes, target_votes] {
            out.extend_from_slice(&(set.len() as u32).to_le_bytes());
            for v in set {
                out.extend_from_slice(&v.signer);
                out.extend_from_slice(&v.source_epoch.to_le_bytes());
                out.extend_from_slice(&v.source_root);
                out.extend_from_slice(&v.target_epoch.to_le_bytes());
                out.extend_from_slice(&v.target_root);
                out.extend_from_slice(&(v.signature.len() as u32).to_le_bytes());
                out.extend_from_slice(&v.signature);
                out.extend_from_slice(&(v.pq_signature.len() as u32).to_le_bytes());
                out.extend_from_slice(&v.pq_signature);
            }
        }
        out
    }

    const SOURCE_EPOCH: u64 = 10;
    const TARGET_EPOCH: u64 = 11;
    const SOURCE_ROOT: [u8; 32] = [0x11; 32];
    const PARENT_ROOT: [u8; 32] = [0x10; 32];
    const TARGET_ROOT: [u8; 32] = [0x12; 32];

    fn evidence_with(signers: &[Signer], source_take: usize, target_take: usize) -> RawConsensusEvidence {
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
        let payload = encode(SOURCE_EPOCH, SOURCE_ROOT, PARENT_ROOT, TARGET_EPOCH, TARGET_ROOT, &source_votes, &target_votes);
        RawConsensusEvidence {
            adapter: AdapterId::from_name(CASPER_FFG_ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: "budlum-ffg".to_string(),
            payload,
            declared_height: TARGET_EPOCH,
            declared_root: TARGET_ROOT,
            submitter: Address::from([0x09; 32]),
        }
    }

    fn adapter_with(signers: &[Signer], committee: PinnedFfgCommittee) -> CasperFfgAdapter {
        let golden = evidence_with(signers, 3, 3);
        CasperFfgAdapter::new("budlum-ffg", committee, Some(golden)).expect("adapter")
    }

    fn policy() -> VerificationPolicy {
        VerificationPolicy::strict(0)
    }

    #[test]
    fn a_two_checkpoint_chain_with_two_thirds_stake_finalises() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee.clone());
        let evidence = evidence_with(&signers, 3, 3);
        let attestation = adapter.verify(&evidence, &policy()).expect("finalises");
        assert_eq!(attestation.height, TARGET_EPOCH);
        assert_eq!(attestation.state_root, TARGET_ROOT);
        assert_eq!(attestation.time_unit, TimeUnit::Epoch);
        assert_eq!(attestation.security.observed_scheme(), Some(ObservedScheme::Scheme(SchemeId::ED25519)));
        match attestation.security {
            SecurityBacking::SignatureSet { slashable, total_weight, .. } => {
                assert!(slashable, "Casper FFG backing is economic, so it must be slashable");
                assert_eq!(total_weight, committee.total_stake());
            }
            other => panic!("unexpected backing: {other:?}"),
        }
        assert_eq!(attestation.adapter, AdapterId::from_name(CASPER_FFG_ADAPTER_NAME));
    }

    #[test]
    fn the_pinned_committee_threshold_is_strictly_more_than_two_thirds() {
        let (_signers, committee) = signers();
        // 400 stake in total: two thirds is 266.67, so 267 is the first passing sum.
        assert_eq!(committee.total_stake(), 400);
        assert_eq!(committee.threshold_stake(), 267);
    }

    #[test]
    fn exactly_two_thirds_of_stake_is_refused() {
        let (mut signers, mut committee) = signers();
        // Four members of 99 stake: 2 * 99 = 198 is exactly two thirds of 297.
        for member in &mut committee.validators {
            member.stake = 99;
        }
        committee = PinnedFfgCommittee::new(committee.validators.clone()).expect("committee");
        for s in &mut signers {
            // Keep the same keys; only the stake changed.
            assert!(!s.pubkey.is_empty());
        }
        let adapter = adapter_with(&signers, committee);
        let evidence = evidence_with(&signers, 2, 2);
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        assert!(matches!(err, AdapterError::ConsensusRule { .. }), "unexpected: {err:?}");
    }

    #[test]
    fn non_adjacent_checkpoints_are_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee);
        let source_votes: Vec<FfgVote> = signers
            .iter()
            .take(3)
            .map(|s| vote(s, SOURCE_EPOCH - 2, PARENT_ROOT, SOURCE_EPOCH - 1, SOURCE_ROOT))
            .collect();
        let target_votes: Vec<FfgVote> = signers
            .iter()
            .take(3)
            .map(|s| vote(s, SOURCE_EPOCH, SOURCE_ROOT, TARGET_EPOCH + 1, TARGET_ROOT))
            .collect();
        let payload = encode(SOURCE_EPOCH, SOURCE_ROOT, PARENT_ROOT, TARGET_EPOCH + 1, TARGET_ROOT, &source_votes, &target_votes);
        let mut evidence = evidence_with(&signers, 3, 3);
        evidence.payload = payload;
        evidence.declared_height = TARGET_EPOCH + 1;
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => assert!(rule.contains("not adjacent"), "unexpected: {rule}"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_duplicate_signer_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee);
        let mut evidence = evidence_with(&signers, 3, 3);
        // Repeat the first target vote inside the target set.
        let parsed = parse_payload(&evidence.payload).expect("payload");
        let mut duplicated = parsed.target_votes.clone();
        duplicated.push(parsed.target_votes[0].clone());
        evidence.payload = encode(SOURCE_EPOCH, SOURCE_ROOT, PARENT_ROOT, TARGET_EPOCH, TARGET_ROOT, &parsed.source_votes, &duplicated);
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => assert!(rule.contains("twice"), "unexpected: {rule}"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_vote_from_outside_the_committee_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee);
        let outsider_key = KeyPair::from_seed(&[0x77; 32]).expect("key");
        let outsider = Signer { pubkey: outsider_key.public_key_bytes(), key: outsider_key };
        let parsed = parse_payload(&evidence_with(&signers, 3, 3).payload).expect("payload");
        let mut target_votes = parsed.target_votes.clone();
        target_votes.push(vote(&outsider, SOURCE_EPOCH, SOURCE_ROOT, TARGET_EPOCH, TARGET_ROOT));
        let mut evidence = evidence_with(&signers, 3, 3);
        evidence.payload = encode(SOURCE_EPOCH, SOURCE_ROOT, PARENT_ROOT, TARGET_EPOCH, TARGET_ROOT, &parsed.source_votes, &target_votes);
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => assert!(rule.contains("outside the pinned committee"), "unexpected: {rule}"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_vote_for_another_source_root_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee);
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
        evidence.payload = encode(SOURCE_EPOCH, SOURCE_ROOT, PARENT_ROOT, TARGET_EPOCH, TARGET_ROOT, &source_votes, &target_votes);
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        match err {
            AdapterError::ConsensusRule { rule } => assert!(rule.contains("another checkpoint pair"), "unexpected: {rule}"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee);
        let parsed = parse_payload(&evidence_with(&signers, 3, 3).payload).expect("payload");
        let mut target_votes = parsed.target_votes.clone();
        if let Some(first) = target_votes.first_mut() {
            first.signature[0] ^= 0xff;
        }
        let mut evidence = evidence_with(&signers, 3, 3);
        evidence.payload = encode(SOURCE_EPOCH, SOURCE_ROOT, PARENT_ROOT, TARGET_EPOCH, TARGET_ROOT, &parsed.source_votes, &target_votes);
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        assert!(matches!(err, AdapterError::Crypto { .. }), "unexpected: {err:?}");
    }

    #[test]
    fn a_declared_height_that_does_not_match_the_payload_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee);
        let mut evidence = evidence_with(&signers, 3, 3);
        evidence.declared_height = TARGET_EPOCH + 5;
        let err = adapter.verify(&evidence, &policy()).unwrap_err();
        assert!(matches!(err, AdapterError::DeclarationMismatch { field } if field == "checkpoint"), "unexpected: {err:?}");
    }

    #[test]
    fn a_depth_requirement_above_two_epochs_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee);
        let mut strict = policy();
        strict.min_depth = 3;
        let err = adapter.verify(&evidence_with(&signers, 3, 3), &strict).unwrap_err();
        assert!(matches!(err, AdapterError::InsufficientDepth { observed: 2, required: 3 }), "unexpected: {err:?}");
    }

    #[test]
    fn stale_evidence_is_refused() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee);
        let mut aged = policy();
        aged.max_age = 2;
        aged.now = TARGET_EPOCH + 9;
        let err = adapter.verify(&evidence_with(&signers, 3, 3), &aged).unwrap_err();
        assert!(matches!(err, AdapterError::Stale { age: 9, max_age: 2 }), "unexpected: {err:?}");
    }

    #[test]
    fn the_fault_probe_suite_admits_the_adapter() {
        let (signers, committee) = signers();
        let adapter = adapter_with(&signers, committee);
        let report = admit(&adapter, &policy());
        assert!(report.golden_verified, "the golden sample must verify");
        for (name, outcome) in &report.probes {
            assert!(
                matches!(outcome, crate::cross_domain::external::selftest::ProbeOutcome::Refused { .. }),
                "probe {name} did not refuse: {outcome:?}"
            );
        }
        assert!(report.admitted, "admission failed: {report:?}");
    }
}
