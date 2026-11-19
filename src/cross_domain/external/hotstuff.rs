//! Linear chained BFT (`HotStuff` / `Jolteon` / `DiemBFT` / `MonadBFT`)
//! external finality adapter verifying the consecutive three-chain commit rule.
//!
//! WIRING: `AdapterSpec::HotStuffQc` runs in `external_tx`; pacemaker timeout-certificate and double-vote equivocation
//! verifiers land with their governance-gated external slashing intake door.
//!
//! Under Yin et al. (PODC 2019), a block `B_0` at view `v` is deterministically
//! committed once three certified blocks `(B_0, B_1, B_2)` form an unbroken
//! parent chain across three strictly consecutive views `(v, v + 1, v + 2)`:
//!
//! 1. `B_0` (prepare phase, view `v`, height `h`) carries a valid quorum
//!    certificate `QC_0` signed by strictly more than two-thirds of the pinned
//!    epoch validator stake.
//! 2. `B_1` (pre-commit phase, view `v + 1`, height `h + 1`) links directly to
//!    `B_0` (`B_1.parent_hash == B_0.block_hash`) and carries a valid quorum
//!    certificate `QC_1` (> 2/3 stake), locking every honest quorum on `B_0`.
//! 3. `B_2` (commit phase, view `v + 2`, height `h + 2`) links directly to
//!    `B_1` (`B_2.parent_hash == B_1.block_hash`) and carries a valid quorum
//!    certificate `QC_2` (> 2/3 stake), irrevocably committing `B_0` under
//!    partial synchrony with accountable slashing for any `< 1/3`-exceeding
//!    conflicting quorum.
//!
//! Any view gap (`v_1 != v_0 + 1` or `v_2 != v_1 + 1`), broken parent link,
//! mismatched epoch, non-canonical self-derived block digest, duplicate signer,
//! non-member signer, sub-supermajority stake, or stripped ML-DSA-65
//! co-signature on a PQ-enrolled validator causes fail-closed rejection.

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

/// Canonical adapter name for `HotStuff` three-chain finality.
const ADAPTER_NAME: &str = "hotstuff-3chain-v1";
/// Adapter implementation version.
const ADAPTER_VERSION: u32 = 1;
/// Wire evidence version accepted by [`HotStuffThreeChainAdapter`].
const EVIDENCE_VERSION: u32 = 1;
/// Committed confirmation depth of a 3-chain (`B_0 <- B_1 <- B_2`).
const THREE_CHAIN_DEPTH: u64 = 3;

const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMHS01";
const MAX_HOTSTUFF_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_HOTSTUFF_COMMITTEE: usize = 256;

/// One bonded validator in a governance-pinned `HotStuff` epoch committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffValidator {
    /// Classical Ed25519 verifying key (32 bytes).
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero bonded voting weight.
    pub voting_weight: u64,
    /// Optional ML-DSA-65 post-quantum public key; when non-empty, every QC
    /// signature from this validator MUST include a valid ML-DSA-65
    /// co-signature under [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned epoch validator set for a `HotStuff` chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedHotStuffCommittee {
    /// Consensus epoch served by this validator set.
    pub epoch: u64,
    /// Active bonded validators for `epoch`.
    pub members: Vec<HotStuffValidator>,
}

/// One proposed block in a `HotStuff` 3-chain bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HotStuffBlock {
    pub epoch: u64,
    pub view: u64,
    pub height: u64,
    pub timestamp_secs: u64,
    pub parent_hash: Hash32,
    pub state_root: Hash32,
    pub tx_root: Hash32,
    pub event_root: Hash32,
    pub block_hash: Hash32,
}

impl HotStuffBlock {
    /// Canonical self-derived block digest bound to `network`.
    #[must_use]
    pub(crate) fn compute_hash(&self, network: &str) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_HOTSTUFF_BLOCK_V1",
            network.as_bytes(),
            &self.epoch.to_le_bytes(),
            &self.view.to_le_bytes(),
            &self.height.to_le_bytes(),
            &self.timestamp_secs.to_le_bytes(),
            &self.parent_hash,
            &self.state_root,
            &self.tx_root,
            &self.event_root,
        ])
    }
}

/// One validator's vote inside a `HotStuff` quorum certificate or equivocation proof.
/// WIRING: exposed for `HotStuff` equivocation slashing submission surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffVoteSig {
    pub signer_pubkey: [u8; 32],
    pub ed25519_sig: Vec<u8>,
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Quorum certificate over one `HotStuff` block at `(epoch, view)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HotStuffQc {
    pub epoch: u64,
    pub view: u64,
    pub block_hash: Hash32,
    pub signatures: Vec<HotStuffVoteSig>,
}

/// Complete three-chain finality bundle committing `prepare_block`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HotStuffThreeChainEvidence {
    pub prepare_block: HotStuffBlock,
    pub prepare_qc: HotStuffQc,
    pub precommit_block: HotStuffBlock,
    pub precommit_qc: HotStuffQc,
    pub commit_block: HotStuffBlock,
    pub commit_qc: HotStuffQc,
}

/// Canonical domain-separated signing digest for a `HotStuff` vote.
#[must_use]
fn hotstuff_vote_sign_bytes(network: &str, epoch: u64, view: u64, block_hash: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_HOTSTUFF_VOTE_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &view.to_le_bytes(),
        block_hash,
    ])
}

/// Encode a [`HotStuffThreeChainEvidence`] bundle with its magic header.
#[cfg(test)]
#[cfg(test)]
fn encode_hotstuff_evidence(bundle: &HotStuffThreeChainEvidence) -> Result<Vec<u8>, String> {
    let body = bincode::serialize(bundle).map_err(|e| format!("HotStuff encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_HOTSTUFF_PAYLOAD_BYTES {
        return Err(format!(
            "HotStuff payload size {total} exceeds ceiling {MAX_HOTSTUFF_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_hotstuff_evidence(payload: &[u8]) -> Result<HotStuffThreeChainEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "HotStuff payload shorter than 8-byte magic prefix".into(),
        });
    }
    if payload.len() > MAX_HOTSTUFF_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_HOTSTUFF_PAYLOAD_BYTES,
            reason: format!("HotStuff payload exceeds {MAX_HOTSTUFF_PAYLOAD_BYTES} bytes"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "HotStuff payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing HotStuff payload body".into(),
    })?;
    let decoded: HotStuffThreeChainEvidence =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_HOTSTUFF_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
            offset: 8,
            reason: format!("invalid HotStuff 3-chain evidence: {e}"),
        })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical HotStuff 3-chain evidence".to_string(),
        });
    }
    Ok(decoded)
}

fn verify_single_qc(
    network: &str,
    phase: &str,
    block: &HotStuffBlock,
    qc: &HotStuffQc,
    member_map: &BTreeMap<[u8; 32], &HotStuffValidator>,
    total_stake: u128,
) -> Result<(u64, bool), AdapterError> {
    if qc.epoch != block.epoch
        || qc.view != block.view
        || !bool::from(qc.block_hash.ct_eq(&block.block_hash))
    {
        return Err(AdapterError::ConsensusRule {
            rule: format!("HotStuff {phase} QC does not match its block epoch, view, or hash"),
        });
    }
    if qc.signatures.is_empty() || qc.signatures.len() > MAX_HOTSTUFF_COMMITTEE {
        return Err(AdapterError::ConsensusRule {
            rule: format!("HotStuff {phase} QC signature count outside valid bounds"),
        });
    }
    let vote_digest = hotstuff_vote_sign_bytes(network, qc.epoch, qc.view, &qc.block_hash);
    let mut seen = BTreeSet::new();
    let mut signed_stake = 0u128;
    let mut all_pq = true;

    for sig in &qc.signatures {
        if !seen.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate validator signature in HotStuff {phase} QC"),
            });
        }
        let Some(member) = member_map.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("non-committee signer in HotStuff {phase} QC"),
            });
        };
        crate::crypto::primitives::verify_signature(
            &vote_digest,
            &sig.ed25519_sig,
            &sig.signer_pubkey,
        )
        .map_err(|_| AdapterError::Crypto {
            what: format!("invalid Ed25519 signature in HotStuff {phase} QC"),
        })?;
        if member.pq_pubkey.is_empty() {
            all_pq = false;
        } else {
            if sig.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: format!(
                        "missing mandatory ML-DSA-65 co-signature in HotStuff {phase} QC"
                    ),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &member.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &vote_digest,
                &sig.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: format!("invalid ML-DSA-65 co-signature in HotStuff {phase} QC"),
            })?;
        }
        signed_stake = signed_stake
            .checked_add(u128::from(member.voting_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: format!("HotStuff {phase} QC signed stake overflows u128"),
            })?;
    }

    if signed_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "HotStuff {phase} QC signed stake {signed_stake}/{total_stake} does not exceed 2/3"
            ),
        });
    }
    Ok((seen.len() as u64, all_pq))
}

/// Domain-separation tag for HotStuff/Jolteon pacemaker timeout votes.
/// WIRING: exposed for external `HotStuff` pacemaker timeout signers and verifiers.
pub const DOMAIN_HOTSTUFF_TIMEOUT: &[u8] = b"BDLM_HOTSTUFF_TIMEOUT_V1";

/// Canonical timeout-vote signing digest binding `(network, epoch, view, high_qc_view)`.
///
/// Convenience: exposed for `HotStuff` pacemaker signers and TC verifiers.
#[must_use]
pub fn hotstuff_timeout_sign_bytes(
    network: &str,
    epoch: u64,
    view: u64,
    high_qc_view: u64,
) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[
        DOMAIN_HOTSTUFF_TIMEOUT,
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &view.to_le_bytes(),
        &high_qc_view.to_le_bytes(),
    ])
}

/// Individual validator timeout vote carrying its highest locked QC view.
/// WIRING: exposed for `HotStuff` pacemaker view-change intake surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffTimeoutVote {
    /// Validator Ed25519 public key.
    pub signer_pubkey: [u8; 32],
    /// Highest certified QC view reported by this validator (`< timeout.view`).
    pub high_qc_view: u64,
    /// Ed25519 signature over `hotstuff_timeout_sign_bytes`.
    pub ed25519_sig: Vec<u8>,
    /// Mandatory ML-DSA-65 co-signature when the validator enrolled a PQ key.
    pub pq_sig: Vec<u8>,
}

/// Jolteon / `DiemBFT` / `AptosBFT` `TimeoutCertificate` authorizing a safe jump
/// past a stalled view while preserving the highest locked QC across `> 2/3` stake.
/// WIRING: exposed for `HotStuff` pacemaker view-change verification surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStuffTimeoutCertificate {
    /// Committee epoch.
    pub epoch: u64,
    /// Timed-out view number.
    pub view: u64,
    /// Claimed `max(vote.high_qc_view)` across all included votes.
    pub max_high_qc_view: u64,
    /// Distinct committee timeout votes summing to strictly greater than `2/3` stake.
    pub votes: Vec<HotStuffTimeoutVote>,
}

#[path = "hotstuff_faults.rs"]
mod faults;

pub use faults::{
    verify_hotstuff_equivocation, verify_hotstuff_timeout_certificate, HotStuffEquivocationProof,
};

/// External finality adapter for linear chained BFT (`HotStuff` 3-chain rule).
pub struct HotStuffThreeChainAdapter {
    network: String,
    pinned: Option<PinnedHotStuffCommittee>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl HotStuffThreeChainAdapter {
    /// Construct a `HotStuffThreeChainAdapter` bound to `network` and its pinned committee.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedHotStuffCommittee>) -> Self {
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
                consensus_kind: "hotstuff-chained-bft".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                required_depth: THREE_CHAIN_DEPTH,
                time_unit: TimeUnit::Height,
                trust_model: TrustModel::HonestMajority { set_size },
            },
        }
    }

    /// Attach a golden evidence sample for self-test admission replay.
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
                    "HotStuff evidence network '{}' does not match pinned network '{}'",
                    evidence.network, self.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no pinned HotStuff committee; admission is closed".into(),
            });
        };
        if pinned.members.is_empty() || pinned.members.len() > MAX_HOTSTUFF_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned HotStuff committee size outside valid bounds".into(),
            });
        }

        let mut member_map = BTreeMap::new();
        let mut total_stake = 0u128;
        for member in &pinned.members {
            if member.ed25519_pubkey == [0u8; 32] || member.voting_weight == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "pinned HotStuff committee contains zero pubkey or zero voting weight"
                        .into(),
                });
            }
            if member_map.insert(member.ed25519_pubkey, member).is_some() {
                return Err(AdapterError::ConsensusRule {
                    rule: "pinned HotStuff committee contains duplicate validator pubkey".into(),
                });
            }
            total_stake = total_stake
                .checked_add(u128::from(member.voting_weight))
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "pinned HotStuff committee total voting weight overflows u128".into(),
                })?;
        }

        let bundle = decode_hotstuff_evidence(&evidence.payload)?;
        let b0 = &bundle.prepare_block;
        let b1 = &bundle.precommit_block;
        let b2 = &bundle.commit_block;

        if policy.require_declared_match {
            if evidence.declared_height != b0.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&b0.state_root)) {
                return Err(AdapterError::DeclarationMismatch { field: "root" });
            }
        }
        if policy.min_depth > THREE_CHAIN_DEPTH {
            return Err(AdapterError::InsufficientDepth {
                observed: THREE_CHAIN_DEPTH,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 && policy.now > b0.height {
            let age = policy.now - b0.height;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // 1. Verify epoch binding, non-zero committed root, and canonical block digests.
        if b0.height == 0 || b0.state_root == [0u8; 32] || b0.parent_hash == [0u8; 32] {
            return Err(AdapterError::ConsensusRule {
                rule: "HotStuff prepare block has zero height, zero state_root, or zero parent"
                    .into(),
            });
        }
        for (phase, blk) in [("prepare", b0), ("precommit", b1), ("commit", b2)] {
            if blk.epoch != pinned.epoch {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "HotStuff {phase} block epoch {} mismatches pinned epoch {}",
                        blk.epoch, pinned.epoch
                    ),
                });
            }
            let expected_hash = blk.compute_hash(&self.network);
            if !bool::from(blk.block_hash.ct_eq(&expected_hash)) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "HotStuff {phase} block_hash does not match canonical header digest"
                    ),
                });
            }
        }

        // 2. Enforce strict HotStuff 3-chain consecutive views, heights, timestamps, and parents.
        let expected_v1 = b0
            .view
            .checked_add(1)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "HotStuff prepare view overflows u64".into(),
            })?;
        let expected_v2 = b1
            .view
            .checked_add(1)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "HotStuff precommit view overflows u64".into(),
            })?;
        if b1.view != expected_v1 || b2.view != expected_v2 {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "HotStuff 3-chain views ({}, {}, {}) are not strictly consecutive",
                    b0.view, b1.view, b2.view
                ),
            });
        }
        if Some(b1.height) != b0.height.checked_add(1)
            || Some(b2.height) != b1.height.checked_add(1)
        {
            return Err(AdapterError::ConsensusRule {
                rule: "HotStuff 3-chain heights are not strictly consecutive".into(),
            });
        }
        if b1.timestamp_secs < b0.timestamp_secs || b2.timestamp_secs < b1.timestamp_secs {
            return Err(AdapterError::ConsensusRule {
                rule: "HotStuff 3-chain timestamps regress across phases".into(),
            });
        }
        if !bool::from(b1.parent_hash.ct_eq(&b0.block_hash))
            || !bool::from(b2.parent_hash.ct_eq(&b1.block_hash))
        {
            return Err(AdapterError::ConsensusRule {
                rule: "HotStuff 3-chain parent_hash links do not form B0 <- B1 <- B2".into(),
            });
        }

        // 3. Cryptographically verify all three phase Quorum Certificates.
        let (s0, pq0) = verify_single_qc(
            &self.network,
            "prepare",
            b0,
            &bundle.prepare_qc,
            &member_map,
            total_stake,
        )?;
        let (s1, pq1) = verify_single_qc(
            &self.network,
            "precommit",
            b1,
            &bundle.precommit_qc,
            &member_map,
            total_stake,
        )?;
        let (s2, pq2) = verify_single_qc(
            &self.network,
            "commit",
            b2,
            &bundle.commit_qc,
            &member_map,
            total_stake,
        )?;

        let all_pq = pq0 && pq1 && pq2;
        let min_signers = s0.min(s1).min(s2);
        let required_signers = ((pinned.members.len() as u64) * 2).div_ceil(3).max(1);
        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: b0.height,
            state_root: b0.state_root,
            finalized_at: b0.height,
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
            attested_block_hash: Some(b0.block_hash),
            attested_event_root: Some(b0.event_root),
            attested_tx_root: Some(b0.tx_root),
        };
        Ok((attestation, all_pq))
    }
}

impl ExternalFinalityAdapter for HotStuffThreeChainAdapter {
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
                name: "refuses unknown HotStuff evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 9 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign HotStuff network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared HotStuff height".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared HotStuff state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xFE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted HotStuff payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0x00, 0x00],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated HotStuff prepare epoch".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xFF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted HotStuff commit QC signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail_offset,
                    bytes: vec![0xA5, 0x5A, 0xA5, 0x5A],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated HotStuff payload".into(),
                patch: BytePatch::TruncatePayload { keep: 4 },
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

    fn make_block(
        network: &str,
        epoch: u64,
        view: u64,
        height: u64,
        timestamp_secs: u64,
        parent_hash: Hash32,
        seed: u8,
    ) -> HotStuffBlock {
        let mut blk = HotStuffBlock {
            epoch,
            view,
            height,
            timestamp_secs,
            parent_hash,
            state_root: [seed; 32],
            tx_root: [seed.wrapping_add(1); 32],
            event_root: [seed.wrapping_add(2); 32],
            block_hash: [0u8; 32],
        };
        blk.block_hash = blk.compute_hash(network);
        blk
    }

    fn sign_qc(
        network: &str,
        blk: &HotStuffBlock,
        keys: &[(KeyPair, PqKeyPair)],
        count: usize,
    ) -> HotStuffQc {
        let msg = hotstuff_vote_sign_bytes(network, blk.epoch, blk.view, &blk.block_hash);
        let signatures = keys
            .iter()
            .take(count)
            .map(|(ek, pk)| HotStuffVoteSig {
                signer_pubkey: ek.public_key_bytes(),
                ed25519_sig: ek.sign(&msg).to_vec(),
                pq_sig: pk
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg)
                    .expect("pq sign"),
            })
            .collect();
        HotStuffQc {
            epoch: blk.epoch,
            view: blk.view,
            block_hash: blk.block_hash,
            signatures,
        }
    }

    fn hotstuff_fixture() -> (
        PinnedHotStuffCommittee,
        Vec<(KeyPair, PqKeyPair)>,
        HotStuffThreeChainEvidence,
        RawConsensusEvidence,
    ) {
        let network = "aptos-jolteon-1";
        let epoch = 7;
        let mut keys = Vec::new();
        let mut members = Vec::new();
        for _ in 0..4 {
            let ek = KeyPair::generate().expect("ed25519 keypair");
            let pk = PqKeyPair::generate();
            members.push(HotStuffValidator {
                ed25519_pubkey: ek.public_key_bytes(),
                voting_weight: 100,
                pq_pubkey: pk.public_key_bytes().to_vec(),
            });
            keys.push((ek, pk));
        }

        let b0 = make_block(network, epoch, 40, 1_000, 1_750_000_000, [0x10; 32], 0x21);
        let b1 = make_block(
            network,
            epoch,
            41,
            1_001,
            1_750_000_001,
            b0.block_hash,
            0x31,
        );
        let b2 = make_block(
            network,
            epoch,
            42,
            1_002,
            1_750_000_002,
            b1.block_hash,
            0x41,
        );
        let qc0 = sign_qc(network, &b0, &keys, 3);
        let qc1 = sign_qc(network, &b1, &keys, 3);
        let qc2 = sign_qc(network, &b2, &keys, 3);

        let bundle = HotStuffThreeChainEvidence {
            prepare_block: b0.clone(),
            prepare_qc: qc0,
            precommit_block: b1,
            precommit_qc: qc1,
            commit_block: b2,
            commit_qc: qc2,
        };
        let ev = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: network.to_string(),
            payload: encode_hotstuff_evidence(&bundle).expect("encode"),
            declared_height: b0.height,
            declared_root: b0.state_root,
            submitter: Address::from([0x09; 32]),
        };
        (PinnedHotStuffCommittee { epoch, members }, keys, bundle, ev)
    }

    #[test]
    fn hotstuff_three_chain_passes_selftest_and_refuses_forgery_vectors() {
        let (pinned, keys, bundle, golden) = hotstuff_fixture();
        let adapter = HotStuffThreeChainAdapter::new("aptos-jolteon-1", Some(pinned))
            .with_golden(golden.clone());
        let policy = VerificationPolicy::strict(1_010);

        let report = admit(&adapter, &policy);
        assert!(report.admitted, "HotStuff admission failed: {report:?}");
        assert_eq!(report.passed(), 8);

        let mut facts = CryptoFacts::new();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .expect("valid 3-chain commits B0");
        assert_eq!(att.height, 1_000);
        assert_eq!(att.state_root, bundle.prepare_block.state_root);
        assert_eq!(att.attested_tx_root, Some(bundle.prepare_block.tx_root));
        assert_eq!(
            att.attested_event_root,
            Some(bundle.prepare_block.event_root)
        );
        assert_eq!(
            att.attested_block_hash,
            Some(bundle.prepare_block.block_hash)
        );
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);

        // 1. Forgery: non-consecutive view gap (40, 41, 43) breaks the 3-chain lock rule.
        let mut gapped = bundle.clone();
        let b2_gap = make_block(
            "aptos-jolteon-1",
            7,
            43,
            1_002,
            1_750_000_003,
            gapped.precommit_block.block_hash,
            0x51,
        );
        gapped.commit_qc = sign_qc("aptos-jolteon-1", &b2_gap, &keys, 3);
        gapped.commit_block = b2_gap;
        let mut gapped_ev = golden.clone();
        gapped_ev.payload = encode_hotstuff_evidence(&gapped).expect("encode");
        assert!(matches!(
            adapter.verify(&gapped_ev, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 2. Forgery: broken parent link between B1 and B2 even with valid >2/3 QCs.
        let mut unlinked = bundle.clone();
        let b2_bad_parent = make_block(
            "aptos-jolteon-1",
            7,
            42,
            1_002,
            1_750_000_002,
            [0xEE; 32],
            0x61,
        );
        unlinked.commit_qc = sign_qc("aptos-jolteon-1", &b2_bad_parent, &keys, 3);
        unlinked.commit_block = b2_bad_parent;
        let mut unlinked_ev = golden.clone();
        unlinked_ev.payload = encode_hotstuff_evidence(&unlinked).expect("encode");
        assert!(matches!(
            adapter.verify(&unlinked_ev, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 3. Forgery: sub-supermajority (2 of 4 = 50% <= 2/3) on precommit QC.
        let mut sub_quorum = bundle.clone();
        sub_quorum.precommit_qc.signatures.truncate(2);
        let mut sub_ev = golden.clone();
        sub_ev.payload = encode_hotstuff_evidence(&sub_quorum).expect("encode");
        assert!(matches!(
            adapter.verify(&sub_ev, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 4. Forgery: stripping ML-DSA-65 co-signature on a PQ-enrolled validator.
        let mut stripped_pq = bundle;
        stripped_pq.commit_qc.signatures[0].pq_sig.clear();
        let mut stripped_ev = golden;
        stripped_ev.payload = encode_hotstuff_evidence(&stripped_pq).expect("encode");
        assert!(matches!(
            adapter.verify(&stripped_ev, &policy),
            Err(AdapterError::Crypto { .. })
        ));
    }

    #[test]
    fn hotstuff_verifies_pacemaker_timeout_certificate_and_double_vote_equivocation() {
        let keys: Vec<(KeyPair, PqKeyPair)> = (0..4)
            .map(|_| (KeyPair::generate().unwrap(), PqKeyPair::generate()))
            .collect();
        let pinned = PinnedHotStuffCommittee {
            epoch: 7,
            members: keys
                .iter()
                .map(|(ed, pq)| HotStuffValidator {
                    ed25519_pubkey: ed.public_key_bytes(),
                    pq_pubkey: pq.public_key_bytes().to_vec(),
                    voting_weight: 25,
                })
                .collect(),
        };

        // 1. Valid >2/3 TimeoutCertificate at view 50 preserving max_high_qc_view = 48.
        let high_qcs = [46u64, 48, 47];
        let votes: Vec<HotStuffTimeoutVote> = keys
            .iter()
            .take(3)
            .zip(high_qcs)
            .map(|((ed, pq), hqc)| {
                let d = hotstuff_timeout_sign_bytes("aptos-jolteon-1", 7, 50, hqc);
                HotStuffTimeoutVote {
                    signer_pubkey: ed.public_key_bytes(),
                    high_qc_view: hqc,
                    ed25519_sig: ed.sign(&d).to_vec(),
                    pq_sig: pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &d).unwrap(),
                }
            })
            .collect();
        let tc = HotStuffTimeoutCertificate {
            epoch: 7,
            view: 50,
            max_high_qc_view: 48,
            votes,
        };
        let (max_hqc, stake, all_pq) =
            verify_hotstuff_timeout_certificate("aptos-jolteon-1", &pinned, &tc).unwrap();
        assert_eq!(max_hqc, 48);
        assert_eq!(stake, 75);
        assert!(all_pq);

        // Lying about max_high_qc_view (safety-lock downgrade attack) is refused.
        let mut downgraded_tc = tc;
        downgraded_tc.max_high_qc_view = 46;
        assert!(matches!(
            verify_hotstuff_timeout_certificate("aptos-jolteon-1", &pinned, &downgraded_tc),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("max_high_qc_view")
        ));

        // 2. Slashable same-view double-vote equivocation extracts exact culprit & weight,
        //    and refuses classical-only framing lacking ML-DSA-65 co-signature.
        let (culprit_ed, culprit_pq) = &keys[1];
        let ha = [0xA1; 32];
        let hb = [0xB2; 32];
        let ma = hotstuff_vote_sign_bytes("aptos-jolteon-1", 7, 51, &ha);
        let mb = hotstuff_vote_sign_bytes("aptos-jolteon-1", 7, 51, &hb);
        let eq_proof = HotStuffEquivocationProof {
            epoch: 7,
            view: 51,
            block_hash_a: ha,
            block_hash_b: hb,
            vote_a: HotStuffVoteSig {
                signer_pubkey: culprit_ed.public_key_bytes(),
                ed25519_sig: culprit_ed.sign(&ma).to_vec(),
                pq_sig: culprit_pq
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &ma)
                    .unwrap(),
            },
            vote_b: HotStuffVoteSig {
                signer_pubkey: culprit_ed.public_key_bytes(),
                ed25519_sig: culprit_ed.sign(&mb).to_vec(),
                pq_sig: culprit_pq
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &mb)
                    .unwrap(),
            },
        };
        let (slashed_pk, weight) =
            verify_hotstuff_equivocation("aptos-jolteon-1", &pinned, &eq_proof).unwrap();
        assert_eq!(slashed_pk, culprit_ed.public_key_bytes());
        assert_eq!(weight, 25);

        let mut framed = eq_proof;
        framed.vote_b.pq_sig.clear();
        assert!(matches!(
            verify_hotstuff_equivocation("aptos-jolteon-1", &pinned, &framed),
            Err(AdapterError::Crypto { ref what }) if what.contains("ML-DSA-65")
        ));
    }
}
