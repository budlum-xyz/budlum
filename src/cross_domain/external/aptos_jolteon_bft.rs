//! `AptosBFT` / `Jolteon` Two-Chain Pipelined Quorum Certificate + Timeout
//! Certificate (`TC`) Round-Skip + `EpochState` Rotation + Equivocation Slash
//! Proof + Post-Quantum `ML-DSA-65` Hybrid Finality Adapter.
//!
//! Serves as the consensus-layer twin of `EeId::MOVE` (`0x04`):
//! 1. Under Gelashvili et al. (*Jolteon and Ditto*, FC 2022), a proposed block
//!    `B_0` at `(epoch, round = r_0)` is deterministically committed in **two**
//!    certified rounds (`REQUIRED_DEPTH = 2`) once `B_1` at `r_1 = r_0 + 1`
//!    directly extends `B_0` (`B_1.parent_hash == B_0.block_hash`) and a
//!    `CommitQC` over `(epoch, r_0, B_0.block_hash, B_0.state_root)` carries
//!    strictly more than `2/3` of epoch voting power.
//! 2. Whenever view/round progress skips timed-out rounds (`B_0.round > B_0.parent_round + 1`),
//!    Jolteon requires an explicit [`JolteonTimeoutCertificate`] (`TC`) signed
//!    by `> 2/3` of epoch voting power for `B_0.round - 1` with
//!    `highest_qc_round >= B_0.parent_round`, proving no conflicting 2-chain
//!    commit could have formed in the skipped gap.
//! 3. Epoch boundaries carry an optional `next_epoch_validators_digest` committed
//!    directly into `B_0.block_hash`, and [`verify_jolteon_equivocation`]
//!    verifies cryptographic double-vote slashing evidence in the same `(epoch, round)`.
//!
//! WIRING: re-exported by `crate::cross_domain::external` for permissionless
//! external domain registration and `selftest::admit` verification.

use crate::core::hash::{hash_fields_bytes, presence_tagged};
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

/// Canonical adapter identifier for `AptosBFT` / `Jolteon` 2-chain finality.
///
/// WIRING: registered with [`AdapterId::from_name`] in [`AptosJolteonAdapter::new`].
pub const APTOS_JOLTEON_ADAPTER_NAME: &str = "aptos-jolteon-2chain-v1";

const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
const TWO_CHAIN_DEPTH: u64 = 2;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMAJ01";
const MAX_JOLTEON_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_JOLTEON_COMMITTEE: usize = 256;

/// One bonded validator in a governance-pinned `AptosBFT` / `Jolteon` `EpochState`.
///
/// WIRING: listed in [`PinnedJolteonEpochState`] and verified on every QC/TC vote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JolteonValidator {
    /// Classical Ed25519 verifying key (32 bytes).
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero bonded voting power in this epoch.
    pub voting_power: u64,
    /// Mandatory or enrolled `ML-DSA-65` post-quantum public key (`CROSS_DOMAIN_V1`).
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned `EpochState` validator set for an `AptosBFT` / `Jolteon` chain.
///
/// WIRING: supplied to [`AptosJolteonAdapter::new`] and [`verify_jolteon_equivocation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedJolteonEpochState {
    /// Active consensus epoch.
    pub epoch: u64,
    /// Bonded validators for `epoch`.
    pub validators: Vec<JolteonValidator>,
}

impl PinnedJolteonEpochState {
    /// Canonical domain-separated commitment over `(epoch, ordered validators)`.
    ///
    /// WIRING: committed in `next_epoch_validators_digest` on epoch-boundary blocks.
    #[must_use]
    pub fn epoch_state_digest(&self) -> Hash32 {
        let epoch_le = self.epoch.to_le_bytes();
        let count_le = u64::try_from(self.validators.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes();
        let mut acc = hash_fields_bytes(&[b"BDLM_APTOS_JOLTEON_EPOCH_V1", &epoch_le, &count_le]);
        for v in &self.validators {
            let vp_le = v.voting_power.to_le_bytes();
            acc = hash_fields_bytes(&[
                b"BDLM_APTOS_JOLTEON_EPOCH_V1",
                &acc,
                &v.ed25519_pubkey,
                &vp_le,
                &v.pq_pubkey,
            ]);
        }
        acc
    }
}

/// One proposed `Jolteon` block header in a 2-chain commit bundle.
///
/// WIRING: verified inside [`JolteonTwoChainEvidence`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JolteonBlock {
    /// Consensus epoch.
    pub epoch: u64,
    /// Proposal round (`r_1 == r_0 + 1` for 2-chain commit).
    pub round: u64,
    /// Round of `parent_hash` (`round == parent_round + 1` unless accompanied by a valid TC).
    pub parent_round: u64,
    /// Committed ledger version / block height.
    pub height: u64,
    /// Monotonic microsecond timestamp.
    pub timestamp_usecs: u64,
    /// Parent block digest.
    pub parent_hash: Hash32,
    /// Jellyfish Merkle Tree state root after executing this block.
    pub state_root: Hash32,
    /// Transaction accumulator root.
    pub tx_accumulator_root: Hash32,
    /// Event accumulator root.
    pub event_root: Hash32,
    /// Optional next-epoch validator set digest on reconfiguration blocks.
    pub next_epoch_state_digest: Option<Hash32>,
    /// Self-derived canonical block digest.
    pub block_hash: Hash32,
}

impl JolteonBlock {
    /// Computes the canonical self-derived `Jolteon` block digest bound to `network`.
    ///
    /// WIRING: checked on both `b0` and `b1` before accepting any QC.
    #[must_use]
    pub fn compute_hash(&self, network: &str) -> Hash32 {
        let epoch_le = self.epoch.to_le_bytes();
        let round_le = self.round.to_le_bytes();
        let parent_round_le = self.parent_round.to_le_bytes();
        let height_le = self.height.to_le_bytes();
        let ts_le = self.timestamp_usecs.to_le_bytes();
        let next_opt = presence_tagged(self.next_epoch_state_digest);
        hash_fields_bytes(&[
            b"BDLM_APTOS_JOLTEON_BLOCK_V1",
            network.as_bytes(),
            &epoch_le,
            &round_le,
            &parent_round_le,
            &height_le,
            &ts_le,
            &self.parent_hash,
            &self.state_root,
            &self.tx_accumulator_root,
            &self.event_root,
            &next_opt,
        ])
    }
}

/// One validator's hybrid Ed25519 + `ML-DSA-65` signature inside a Jolteon QC or TC.
///
/// WIRING: verified by [`AptosJolteonAdapter`] and [`verify_jolteon_equivocation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JolteonValidatorSig {
    /// Validator Ed25519 public key identifying the committee member.
    pub signer_pubkey: [u8; 32],
    /// 64-byte Ed25519 signature.
    pub ed25519_sig: Vec<u8>,
    /// `ML-DSA-65` co-signature under `CROSS_DOMAIN_V1`.
    pub pq_sig: Vec<u8>,
}

/// Quorum certificate over `(epoch, round, block_hash, certified_state_root)`.
///
/// WIRING: carried for both `b0` (`ordered_qc`) and `b1` (`commit_qc`) in [`JolteonTwoChainEvidence`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JolteonQuorumCert {
    /// Consensus epoch.
    pub epoch: u64,
    /// Certified block round.
    pub round: u64,
    /// Certified block digest.
    pub block_hash: Hash32,
    /// Certified state root (`LedgerInfo.executed_state_id`).
    pub certified_state_root: Hash32,
    /// Distinct committee signatures exceeding `2/3` total voting power.
    pub signatures: Vec<JolteonValidatorSig>,
}

/// Timeout certificate (`TC`) proving `> 2/3` stake timed out `skipped_round`.
///
/// WIRING: mandatory in [`JolteonTwoChainEvidence`] whenever `b0.round > b0.parent_round + 1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JolteonTimeoutCert {
    /// Consensus epoch.
    pub epoch: u64,
    /// Timed-out round (`must equal b0.round - 1`).
    pub skipped_round: u64,
    /// Highest certified QC round observed by the `> 2/3` timeout quorum (`>= b0.parent_round`).
    pub highest_qc_round: u64,
    /// Distinct committee timeout signatures exceeding `2/3` total voting power.
    pub signatures: Vec<JolteonValidatorSig>,
}

/// Complete Jolteon 2-chain finality bundle committing `ordered_block` (`B_0`).
///
/// WIRING: serialized after `BDLMAJ01` magic inside [`RawConsensusEvidence::payload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JolteonTwoChainEvidence {
    /// Committed block `B_0` at round `r_0`.
    pub ordered_block: JolteonBlock,
    /// Quorum certificate `QC_0` over `B_0`.
    pub ordered_qc: JolteonQuorumCert,
    /// Optional TimeoutCertificate justifying `B_0.round > B_0.parent_round + 1`.
    pub round_skip_tc: Option<JolteonTimeoutCert>,
    /// Direct child block `B_1` at round `r_0 + 1` (`B_1.parent_hash == B_0.block_hash`).
    pub commit_block: JolteonBlock,
    /// Quorum certificate `QC_1` over `B_1` completing the 2-chain commit of `B_0`.
    pub commit_qc: JolteonQuorumCert,
}

/// Accountable double-vote evidence proving a validator signed two conflicting blocks in one `(epoch, round)`.
///
/// WIRING: verified by [`verify_jolteon_equivocation`] for external prover/validator slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JolteonEquivocationProof {
    /// Epoch in which double-signing occurred.
    pub epoch: u64,
    /// Round in which double-signing occurred.
    pub round: u64,
    /// First voted block hash + state root.
    pub first_target: (Hash32, Hash32),
    /// Second conflicting voted block hash + state root.
    pub second_target: (Hash32, Hash32),
    /// First hybrid vote signature.
    pub first_sig: JolteonValidatorSig,
    /// Second hybrid vote signature by the same validator.
    pub second_sig: JolteonValidatorSig,
}

/// Domain-separated vote signing digest for a Jolteon QC.
///
/// WIRING: used by [`AptosJolteonAdapter`] and [`verify_jolteon_equivocation`].
#[must_use]
pub fn jolteon_vote_sign_bytes(
    network: &str,
    epoch: u64,
    round: u64,
    block_hash: &Hash32,
    state_root: &Hash32,
) -> Hash32 {
    let epoch_le = epoch.to_le_bytes();
    let round_le = round.to_le_bytes();
    hash_fields_bytes(&[
        b"BDLM_APTOS_JOLTEON_VOTE_V1",
        network.as_bytes(),
        &epoch_le,
        &round_le,
        block_hash,
        state_root,
    ])
}

/// Domain-separated timeout signing digest for a [`JolteonTimeoutCert`].
///
/// WIRING: used by [`AptosJolteonAdapter`] when verifying skipped-round TCs.
#[must_use]
pub fn jolteon_tc_sign_bytes(
    network: &str,
    epoch: u64,
    skipped_round: u64,
    highest_qc_round: u64,
) -> Hash32 {
    let epoch_le = epoch.to_le_bytes();
    let skip_le = skipped_round.to_le_bytes();
    let hqc_le = highest_qc_round.to_le_bytes();
    hash_fields_bytes(&[
        b"BDLM_APTOS_JOLTEON_TC_V1",
        network.as_bytes(),
        &epoch_le,
        &skip_le,
        &hqc_le,
    ])
}

/// Encodes a [`JolteonTwoChainEvidence`] bundle with its 8-byte `BDLMAJ01` magic header.
///
/// WIRING: exposed for external domain producers and `selftest` golden sample builders.
///
/// # Errors
///
/// Returns an error if serialization fails or exceeds `MAX_JOLTEON_PAYLOAD_BYTES`.
pub fn encode_jolteon_evidence(bundle: &JolteonTwoChainEvidence) -> Result<Vec<u8>, String> {
    let body = bincode::serialize(bundle).map_err(|e| format!("Jolteon encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_JOLTEON_PAYLOAD_BYTES {
        return Err(format!(
            "Jolteon payload {total} exceeds ceiling {MAX_JOLTEON_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_jolteon_evidence(payload: &[u8]) -> Result<JolteonTwoChainEvidence, AdapterError> {
    if payload.len() > MAX_JOLTEON_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_JOLTEON_PAYLOAD_BYTES,
            reason: format!("Jolteon payload exceeds {MAX_JOLTEON_PAYLOAD_BYTES} bytes"),
        });
    }
    let Some((magic, body)) = payload.split_at_checked(PAYLOAD_MAGIC.len()) else {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "Jolteon payload shorter than 8-byte magic prefix".into(),
        });
    };
    if magic != PAYLOAD_MAGIC {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "Jolteon payload magic mismatch".into(),
        });
    }
    let decoded: JolteonTwoChainEvidence =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_JOLTEON_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: PAYLOAD_MAGIC.len(),
                reason: format!("invalid Jolteon 2-chain evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: "trailing bytes after canonical Jolteon 2-chain evidence".into(),
        });
    }
    Ok(decoded)
}

fn verify_validator_sig_set(
    label: &str,
    digest: &Hash32,
    sigs: &[JolteonValidatorSig],
    member_map: &BTreeMap<[u8; 32], &JolteonValidator>,
    total_power: u128,
) -> Result<(u64, bool), AdapterError> {
    if sigs.is_empty() || sigs.len() > MAX_JOLTEON_COMMITTEE {
        return Err(AdapterError::ConsensusRule {
            rule: format!("Jolteon {label} signature count outside valid bounds"),
        });
    }
    let mut seen = BTreeSet::new();
    let mut signed_power = 0u128;
    let mut all_pq = true;

    for sig in sigs {
        if !seen.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate validator signature in Jolteon {label}"),
            });
        }
        let Some(member) = member_map.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("non-committee signer in Jolteon {label}"),
            });
        };
        crate::crypto::primitives::verify_signature(digest, &sig.ed25519_sig, &sig.signer_pubkey)
            .map_err(|_| AdapterError::Crypto {
            what: format!("invalid Ed25519 signature in Jolteon {label}"),
        })?;
        if member.pq_pubkey.is_empty() {
            all_pq = false;
        } else {
            if sig.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: format!("missing mandatory ML-DSA-65 co-signature in Jolteon {label}"),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &member.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                digest,
                &sig.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: format!("invalid ML-DSA-65 co-signature in Jolteon {label}"),
            })?;
        }
        signed_power = signed_power.saturating_add(u128::from(member.voting_power));
    }

    if signed_power.saturating_mul(3) <= total_power.saturating_mul(2) {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Jolteon {label} signed power {signed_power}/{total_power} does not exceed 2/3"
            ),
        });
    }
    Ok((u64::try_from(seen.len()).unwrap_or(u64::MAX), all_pq))
}

fn verify_jolteon_bundle_chain(
    network: &str,
    pinned: &PinnedJolteonEpochState,
    bundle: &JolteonTwoChainEvidence,
    member_map: &BTreeMap<[u8; 32], &JolteonValidator>,
    total_power: u128,
) -> Result<(u64, bool), AdapterError> {
    let b0 = &bundle.ordered_block;
    let b1 = &bundle.commit_block;

    if b0.height == 0 || b0.state_root == [0u8; 32] || b0.parent_hash == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "Jolteon ordered block has zero height, zero state_root, or zero parent".into(),
        });
    }
    for (phase, blk) in [("ordered", b0), ("commit", b1)] {
        if blk.epoch != pinned.epoch {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Jolteon {phase} block epoch mismatches pinned EpochState"),
            });
        }
        if blk.round <= blk.parent_round {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Jolteon {phase} block round must exceed parent_round"),
            });
        }
        let expected_hash = blk.compute_hash(network);
        if !bool::from(blk.block_hash.ct_eq(&expected_hash)) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Jolteon {phase} block_hash mismatches canonical header digest"),
            });
        }
    }

    // 2-chain direct adjacency: B_1.round == B_0.round + 1, B_1.parent_round == B_0.round,
    // B_1.parent_hash == B_0.block_hash, B_1.height == B_0.height + 1, monotonic timestamp.
    if Some(b1.round) != b0.round.checked_add(1) || b1.parent_round != b0.round {
        return Err(AdapterError::ConsensusRule {
            rule: "Jolteon 2-chain commit requires B_1.round == B_0.round + 1".into(),
        });
    }
    if !bool::from(b1.parent_hash.ct_eq(&b0.block_hash))
        || Some(b1.height) != b0.height.checked_add(1)
        || b1.timestamp_usecs < b0.timestamp_usecs
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Jolteon B_1 does not directly extend B_0 parent/height/timestamp".into(),
        });
    }

    // Round-skip TimeoutCertificate rule when B_0 skipped rounds after parent_round.
    let mut tc_pq = true;
    if b0.round > b0.parent_round.saturating_add(1) {
        let Some(tc) = &bundle.round_skip_tc else {
            return Err(AdapterError::ConsensusRule {
                rule: "Jolteon round skip requires a valid TimeoutCertificate".into(),
            });
        };
        if tc.epoch != pinned.epoch
            || Some(b0.round) != tc.skipped_round.checked_add(1)
            || tc.highest_qc_round < b0.parent_round
            || tc.highest_qc_round >= tc.skipped_round
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Jolteon TimeoutCertificate epoch/round bounds invalid".into(),
            });
        }
        let tc_digest =
            jolteon_tc_sign_bytes(network, tc.epoch, tc.skipped_round, tc.highest_qc_round);
        let (_, pq_ok) = verify_validator_sig_set(
            "timeout_cert",
            &tc_digest,
            &tc.signatures,
            member_map,
            total_power,
        )?;
        tc_pq = pq_ok;
    }

    // Verify QC_0 over B_0 and QC_1 over B_1.
    for (phase, blk, qc) in [
        ("ordered_qc", b0, &bundle.ordered_qc),
        ("commit_qc", b1, &bundle.commit_qc),
    ] {
        if qc.epoch != blk.epoch
            || qc.round != blk.round
            || !bool::from(qc.block_hash.ct_eq(&blk.block_hash))
            || !bool::from(qc.certified_state_root.ct_eq(&blk.state_root))
        {
            return Err(AdapterError::ConsensusRule {
                rule: format!("Jolteon {phase} header fields disagree with certified block"),
            });
        }
    }
    let d0 = jolteon_vote_sign_bytes(network, b0.epoch, b0.round, &b0.block_hash, &b0.state_root);
    let d1 = jolteon_vote_sign_bytes(network, b1.epoch, b1.round, &b1.block_hash, &b1.state_root);
    let (s0, pq0) = verify_validator_sig_set(
        "ordered_qc",
        &d0,
        &bundle.ordered_qc.signatures,
        member_map,
        total_power,
    )?;
    let (s1, pq1) = verify_validator_sig_set(
        "commit_qc",
        &d1,
        &bundle.commit_qc.signatures,
        member_map,
        total_power,
    )?;
    Ok((s0.min(s1), pq0 && pq1 && tc_pq))
}

/// Verifies accountable `Jolteon` double-vote slashing evidence and returns `(offender_pubkey, slashed_voting_power)`.
///
/// WIRING: exposed for external consensus equivocation slashers and dispute resolvers.
///
/// # Errors
///
/// Returns [`AdapterError`] if the two targets are identical, signers differ, the signer is not
/// in `epoch_state`, or either hybrid vote signature fails verification.
pub fn verify_jolteon_equivocation(
    network: &str,
    epoch_state: &PinnedJolteonEpochState,
    proof: &JolteonEquivocationProof,
) -> Result<([u8; 32], u64), AdapterError> {
    if proof.epoch != epoch_state.epoch {
        return Err(AdapterError::ConsensusRule {
            rule: "Jolteon equivocation epoch mismatches pinned EpochState".into(),
        });
    }
    if proof.first_target == proof.second_target {
        return Err(AdapterError::ConsensusRule {
            rule: "Jolteon equivocation targets are identical (not a double vote)".into(),
        });
    }
    if !bool::from(
        proof
            .first_sig
            .signer_pubkey
            .ct_eq(&proof.second_sig.signer_pubkey),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "Jolteon equivocation signatures belong to different validators".into(),
        });
    }
    let offender = proof.first_sig.signer_pubkey;
    let Some(member) = epoch_state
        .validators
        .iter()
        .find(|v| v.ed25519_pubkey == offender)
    else {
        return Err(AdapterError::ConsensusRule {
            rule: "Jolteon equivocation signer absent from EpochState".into(),
        });
    };

    for (label, target, sig) in [
        ("first", &proof.first_target, &proof.first_sig),
        ("second", &proof.second_target, &proof.second_sig),
    ] {
        let digest =
            jolteon_vote_sign_bytes(network, proof.epoch, proof.round, &target.0, &target.1);
        crate::crypto::primitives::verify_signature(&digest, &sig.ed25519_sig, &offender).map_err(
            |_| AdapterError::Crypto {
                what: format!("invalid Ed25519 signature on {label} Jolteon equivocation vote"),
            },
        )?;
        if !member.pq_pubkey.is_empty() {
            crate::crypto::primitives::PqKeyPair::verify(
                &member.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &digest,
                &sig.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: format!("invalid ML-DSA-65 signature on {label} Jolteon equivocation vote"),
            })?;
        }
    }
    Ok((offender, member.voting_power))
}

/// External finality adapter for `AptosBFT` / `Jolteon` 2-chain pipelined BFT.
///
/// WIRING: registered via `crate::cross_domain::external` and admitted through `selftest::admit`.
pub struct AptosJolteonAdapter {
    network: String,
    pinned: Option<PinnedJolteonEpochState>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl AptosJolteonAdapter {
    /// Constructs an [`AptosJolteonAdapter`] bound to `network` and its pinned `EpochState`.
    ///
    /// WIRING: called by external domain registrars and self-test harnesses.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedJolteonEpochState>) -> Self {
        let set_size = pinned
            .as_ref()
            .map_or(0, |p| u64::try_from(p.validators.len()).unwrap_or(u64::MAX));
        Self {
            network: network.into(),
            pinned,
            golden: None,
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(APTOS_JOLTEON_ADAPTER_NAME),
                name: APTOS_JOLTEON_ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "aptos-jolteon-2chain-bft".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                required_depth: TWO_CHAIN_DEPTH,
                time_unit: TimeUnit::Height,
                trust_model: TrustModel::HonestMajority { set_size },
            },
        }
    }

    /// Attaches a golden evidence sample for deterministic `selftest::admit` replay.
    ///
    /// Convenience: chained onto [`Self::new`] before registration.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn build_committee_map(
        pinned: &PinnedJolteonEpochState,
    ) -> Result<(BTreeMap<[u8; 32], &JolteonValidator>, u128), AdapterError> {
        if pinned.validators.is_empty() || pinned.validators.len() > MAX_JOLTEON_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned Jolteon EpochState validator count outside valid bounds".into(),
            });
        }
        let mut map = BTreeMap::new();
        let mut total = 0u128;
        for val in &pinned.validators {
            if val.ed25519_pubkey == [0u8; 32] || val.voting_power == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "pinned Jolteon EpochState contains zero pubkey or zero voting power"
                        .into(),
                });
            }
            if map.insert(val.ed25519_pubkey, val).is_some() {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate validator pubkey in pinned Jolteon EpochState".into(),
                });
            }
            total = total
                .checked_add(u128::from(val.voting_power))
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "pinned Jolteon EpochState voting power overflows u128".into(),
                })?;
        }
        Ok((map, total))
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, bool), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::ConsensusRule {
                rule: "evidence adapter ID does not match AptosJolteonAdapter".into(),
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
                rule: "Jolteon evidence network does not match pinned network".into(),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no pinned Jolteon EpochState; admission is closed".into(),
            });
        };
        let (member_map, total_power) = Self::build_committee_map(pinned)?;
        let bundle = decode_jolteon_evidence(&evidence.payload)?;
        let b0 = &bundle.ordered_block;

        if policy.require_declared_match {
            if evidence.declared_height != b0.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&b0.state_root)) {
                return Err(AdapterError::DeclarationMismatch { field: "root" });
            }
        }
        if policy.min_depth > TWO_CHAIN_DEPTH {
            return Err(AdapterError::InsufficientDepth {
                observed: TWO_CHAIN_DEPTH,
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

        let (min_signers, all_pq) =
            verify_jolteon_bundle_chain(&self.network, pinned, &bundle, &member_map, total_power)?;
        let required_signers = (u64::try_from(pinned.validators.len())
            .unwrap_or(1)
            .saturating_mul(2))
        .div_ceil(3)
        .max(1);
        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let att = FinalityAttestation {
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
                total_weight: total_power,
                slashable: true,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(b0.block_hash),
            attested_event_root: Some(b0.event_root),
            attested_tx_root: Some(b0.tx_accumulator_root),
        };
        Ok((att, all_pq))
    }
}

impl ExternalFinalityAdapter for AptosJolteonAdapter {
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
            .map_or(32, |g| g.payload.len().saturating_sub(20));
        vec![
            FaultProbe {
                name: "refuses unknown Jolteon evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 9 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign Jolteon network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared Jolteon height".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared Jolteon state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xFE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted Jolteon payload magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0x00, 0x00],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated Jolteon ordered block epoch".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xFF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted Jolteon commit QC signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail_offset,
                    bytes: vec![0xA5, 0x5A, 0xA5, 0x5A],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated Jolteon payload".into(),
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
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    struct TestSigner {
        ed: KeyPair,
        ed_pk: [u8; 32],
        pq: PqKeyPair,
    }

    fn make_signers() -> (Vec<TestSigner>, PinnedJolteonEpochState) {
        let mut signers = Vec::new();
        let mut validators = Vec::new();
        for i in 1u8..=4 {
            let ed = KeyPair::from_seed(&[i; 32]).unwrap();
            let ed_pk = ed.public_key_bytes();
            let pq = PqKeyPair::generate();
            validators.push(JolteonValidator {
                ed25519_pubkey: ed_pk,
                voting_power: 100,
                pq_pubkey: pq.public_key_bytes().to_vec(),
            });
            signers.push(TestSigner { ed, ed_pk, pq });
        }
        (
            signers,
            PinnedJolteonEpochState {
                epoch: 4,
                validators,
            },
        )
    }

    fn sign_digest(signers: &[TestSigner], digest: &Hash32) -> Vec<JolteonValidatorSig> {
        signers
            .iter()
            .take(3)
            .map(|s| JolteonValidatorSig {
                signer_pubkey: s.ed_pk,
                ed25519_sig: s.ed.sign(digest).to_vec(),
                pq_sig: s
                    .pq
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, digest)
                    .unwrap(),
            })
            .collect()
    }

    fn sample_adapter_with_round_skip_tc() -> (
        Vec<TestSigner>,
        PinnedJolteonEpochState,
        AptosJolteonAdapter,
        RawConsensusEvidence,
    ) {
        let network = "aptos-mainnet";
        let (signers, epoch_state) = make_signers();
        let next_epoch = PinnedJolteonEpochState {
            epoch: 5,
            validators: epoch_state.validators.clone(),
        };

        // Round 11 timed out after parent_round 10 -> B_0 proposes at round 12 with TC(11)!
        let mut b0 = JolteonBlock {
            epoch: 4,
            round: 12,
            parent_round: 10,
            height: 9_000,
            timestamp_usecs: 1_770_000_000_000_000,
            parent_hash: [0x11; 32],
            state_root: [0x22; 32],
            tx_accumulator_root: [0x33; 32],
            event_root: [0x44; 32],
            next_epoch_state_digest: Some(next_epoch.epoch_state_digest()),
            block_hash: [0u8; 32],
        };
        b0.block_hash = b0.compute_hash(network);

        let mut b1 = JolteonBlock {
            epoch: 4,
            round: 13,
            parent_round: 12,
            height: 9_001,
            timestamp_usecs: 1_770_000_000_500_000,
            parent_hash: b0.block_hash,
            state_root: [0x55; 32],
            tx_accumulator_root: [0x66; 32],
            event_root: [0x77; 32],
            next_epoch_state_digest: None,
            block_hash: [0u8; 32],
        };
        b1.block_hash = b1.compute_hash(network);

        let tc_digest = jolteon_tc_sign_bytes(network, 4, 11, 10);
        let tc = JolteonTimeoutCert {
            epoch: 4,
            skipped_round: 11,
            highest_qc_round: 10,
            signatures: sign_digest(&signers, &tc_digest),
        };

        let d0 = jolteon_vote_sign_bytes(network, 4, 12, &b0.block_hash, &b0.state_root);
        let d1 = jolteon_vote_sign_bytes(network, 4, 13, &b1.block_hash, &b1.state_root);
        let bundle = JolteonTwoChainEvidence {
            ordered_qc: JolteonQuorumCert {
                epoch: 4,
                round: 12,
                block_hash: b0.block_hash,
                certified_state_root: b0.state_root,
                signatures: sign_digest(&signers, &d0),
            },
            ordered_block: b0,
            round_skip_tc: Some(tc),
            commit_qc: JolteonQuorumCert {
                epoch: 4,
                round: 13,
                block_hash: b1.block_hash,
                certified_state_root: b1.state_root,
                signatures: sign_digest(&signers, &d1),
            },
            commit_block: b1,
        };
        let payload = encode_jolteon_evidence(&bundle).unwrap();
        let evidence = RawConsensusEvidence {
            adapter: AdapterId::from_name(APTOS_JOLTEON_ADAPTER_NAME),
            network: network.to_string(),
            evidence_version: EVIDENCE_VERSION,
            declared_height: 9_000,
            declared_root: [0x22; 32],
            payload,
            submitter: Address::from([0x01; 32]),
        };
        let adapter = AptosJolteonAdapter::new(network, Some(epoch_state.clone()))
            .with_golden(evidence.clone());
        (signers, epoch_state, adapter, evidence)
    }

    #[test]
    fn aptos_jolteon_2chain_adapter_passes_full_selftest_admission() {
        let (_, _, adapter, _) = sample_adapter_with_round_skip_tc();
        let report = admit(&adapter, &VerificationPolicy::strict(0));
        assert!(report.admitted, "selftest failed: {report:?}");
        assert_eq!(report.probes.len(), 8);
    }

    #[test]
    fn aptos_jolteon_refuses_unjustified_round_skip_and_slashes_equivocation() {
        let (signers, epoch_state, adapter, mut ev) = sample_adapter_with_round_skip_tc();
        let mut bundle = decode_jolteon_evidence(&ev.payload).unwrap();
        bundle.round_skip_tc = None;
        ev.payload = encode_jolteon_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &VerificationPolicy::strict(0)),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // Double-vote slashing proof in (epoch = 4, round = 12).
        let t1 = ([0xA1; 32], [0xB1; 32]);
        let t2 = ([0xA2; 32], [0xB2; 32]);
        let m1 = jolteon_vote_sign_bytes("aptos-mainnet", 4, 12, &t1.0, &t1.1);
        let m2 = jolteon_vote_sign_bytes("aptos-mainnet", 4, 12, &t2.0, &t2.1);
        let s = &signers[0];
        let eq_proof = JolteonEquivocationProof {
            epoch: 4,
            round: 12,
            first_target: t1,
            second_target: t2,
            first_sig: JolteonValidatorSig {
                signer_pubkey: s.ed_pk,
                ed25519_sig: s.ed.sign(&m1).to_vec(),
                pq_sig: s.pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &m1).unwrap(),
            },
            second_sig: JolteonValidatorSig {
                signer_pubkey: s.ed_pk,
                ed25519_sig: s.ed.sign(&m2).to_vec(),
                pq_sig: s.pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &m2).unwrap(),
            },
        };
        let (offender, power) =
            verify_jolteon_equivocation("aptos-mainnet", &epoch_state, &eq_proof).unwrap();
        assert_eq!(offender, s.ed_pk);
        assert_eq!(power, 100);
    }
}
