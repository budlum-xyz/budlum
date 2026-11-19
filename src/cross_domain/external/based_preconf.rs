//! Based rollup preconfirmation, shared sequencer supermajority, and EIP-7805
//! FOCIL censorship-resistant inclusion-list external finality adapter.
//!
//! Under Justin Drake's based-sequencing architecture (2023) combined with
//! EIP-7805 Fork-Choice Enforced Inclusion Lists (`FOCIL`, 2024), an external
//! rollup delegates transaction ordering to L1-aligned slashable preconfer
//! committees while preventing sequencer censorship and anchoring final
//! settlement on L1. A batch at `l2_sequence` is accepted only when all five
//! cryptographic conditions hold under a governance-pinned epoch committee of
//! total stake `S`:
//!
//! 1. **Self-derived batch & proposer preconfirmation**: `batch.digest` equals
//!    the domain-separated hash of `(network, l1_chain_id, epoch, l1_slot,
//!    l2_sequence, proposer, timestamp_secs, pre_state_root, state_root,
//!    tx_root, event_root, il_root, l1_anchor_root)`, and `proposer` is an
//!    active bonded committee member carrying a valid signature (plus mandatory
//!    ML-DSA-65 co-signature when `pq_pubkey` is registered).
//! 2. **Shared-sequencer preconfer quorum**: distinct committee validators
//!    with combined stake strictly greater than `2/3 * S` sign the canonical
//!    preconfirmation certificate binding `batch.digest` to `(l1_slot,
//!    l2_sequence)`.
//! 3. **FOCIL inclusion-list quorum & Merkle inclusion**: when the slot carries
//!    a non-empty inclusion list (`1..=128` strictly ordered transaction
//!    hashes), `il_root` matches their canonical fold, strictly more than
//!    `2/3 * S` committee stake attests `il_root` for `l1_slot`, and EVERY
//!    mandated transaction hash carries a valid binary Merkle inclusion proof
//!    resolving to `batch.tx_root`. Censoring even one FOCIL entry fails closed.
//! 4. **L1 settlement anchor upgrade**: `l1_anchor_slot >= l1_slot`,
//!    `l1_confirmations >= 1`, `l1_anchor_root != [0; 32]`, and strictly more
//!    than `2/3 * S` committee stake certifies that `batch.digest` settled in
//!    `l1_anchor_root` at `l1_anchor_slot`.
//! 5. **Hybrid post-quantum non-downgrade**: every validator carrying a
//!    non-empty ML-DSA-65 public key MUST attach a valid ML-DSA-65 signature
//!    under [`crate::crypto::ctx::CROSS_DOMAIN_V1`]; stripping the PQ half is
//!    unconditionally refused.
//!
//! WIRING: implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`
//! admission/submission/slashing; `AdapterSpec` tag append joins `intake.rs`
//! after concurrent intake hardening merges.

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

const ADAPTER_NAME: &str = "based-preconf-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
const MIN_L1_SETTLEMENT_CONFIRMATIONS: u64 = 2;

const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMBP01";
const MAX_BASED_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_BASED_COMMITTEE: usize = 256;
const MAX_FOCIL_ENTRIES: usize = 128;
const MAX_TX_MERKLE_DEPTH: usize = 32;

/// One slashable preconfer / inclusion-list committee member in a based domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasedPreconfValidator {
    /// Classical Ed25519 verifying key (32 bytes).
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero slashable voting weight denominated in L1 restaked / bonded units.
    pub voting_weight: u64,
    /// Optional ML-DSA-65 public key; when non-empty, every proposal,
    /// preconfirmation, FOCIL vote, and L1 settlement signature MUST carry a
    /// valid ML-DSA-65 co-signature.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned epoch committee and L1 settlement binding for a based
/// rollup / shared-sequencer domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedBasedPreconfCommittee {
    /// Consensus epoch served by this preconfer / FOCIL committee.
    pub epoch: u64,
    /// Canonical L1 settlement chain identifier (must be non-zero).
    pub l1_chain_id: u64,
    /// Whether every slot batch MUST include a non-empty verified FOCIL
    /// inclusion list certified by `> 2/3` committee stake.
    pub require_focil: bool,
    /// Bonded committee members for `epoch`.
    pub members: Vec<BasedPreconfValidator>,
}

impl PinnedBasedPreconfCommittee {
    /// Canonical length-prefixed SHA3-256 commitment over all pinned epoch,
    /// L1 settlement, FOCIL requirement, and committee parameters.
    ///
    /// WIRING: checked in constant time by `crate::cross_domain::economic_guard`
    /// on both backing refreshes and contradiction submissions.
    #[must_use]
    pub fn canonical_pin_digest(&self) -> Hash32 {
        let mut acc = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_BASED_PIN_V1",
            &self.epoch.to_le_bytes(),
            &self.l1_chain_id.to_le_bytes(),
            &[u8::from(self.require_focil)],
            &(self.members.len() as u64).to_le_bytes(),
        ]);
        for m in &self.members {
            acc = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_BASED_PIN_V1",
                &[1u8],
                &acc,
                &m.ed25519_pubkey,
                &m.voting_weight.to_le_bytes(),
                &m.pq_pubkey,
            ]);
        }
        acc
    }

    /// Return the slashable voting weight and whether an ML-DSA-65 co-signing
    /// key is bound for `pubkey`.
    ///
    /// WIRING: used by `crate::cross_domain::economic_guard` for incremental
    /// per-offender preconfirmation slashing accounting.
    #[must_use]
    pub fn member_info(&self, pubkey: &[u8; 32]) -> Option<(u128, bool)> {
        self.members
            .iter()
            .find(|m| bool::from(m.ed25519_pubkey.ct_eq(pubkey)))
            .map(|m| (u128::from(m.voting_weight), !m.pq_pubkey.is_empty()))
    }
}

/// Detached hybrid signature on a based preconfirmation statement or slashing proof.
///
/// WIRING: verified by [`BasedPreconfAdapter`] and [`verify_based_preconf_equivocation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasedSig {
    /// Signer Ed25519 verifying key (32 bytes).
    pub signer_pubkey: [u8; 32],
    /// Detached Ed25519 signature bytes.
    pub ed25519_sig: Vec<u8>,
    /// Mandatory ML-DSA-65 co-signature when `pq_pubkey` is configured.
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Permissionless double-preconfirmation slashing evidence proving one or more
/// pinned preconfers certified two distinct batch digests at the same
/// `(epoch, l1_slot, l2_sequence)`.
///
/// WIRING: verified in production by [`verify_based_preconf_equivocation`] via
/// `crate::cross_domain::economic_guard::BridgeEconomicGuard::submit_contradiction`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasedPreconfEquivocationProof {
    /// Epoch of both conflicting preconfirmations.
    pub epoch: u64,
    /// L1 slot of both conflicting preconfirmations (`> 0`).
    pub l1_slot: u64,
    /// Sequencer batch index of both conflicting preconfirmations (`> 0`).
    pub l2_sequence: u64,
    /// First attested batch digest (non-zero).
    pub batch_digest_a: Hash32,
    /// Hybrid preconfirmer signatures on `batch_digest_a`.
    pub sigs_a: Vec<BasedSig>,
    /// Second conflicting batch digest (non-zero, `!= batch_digest_a`).
    pub batch_digest_b: Hash32,
    /// Hybrid preconfirmer signatures on `batch_digest_b`.
    pub sigs_b: Vec<BasedSig>,
}

/// Verified outcome of [`verify_based_preconf_equivocation`].
///
/// WIRING: consumed by `crate::cross_domain::economic_guard` when freezing a
/// faulted based-rollup domain and accounting for slashed preconfirmer weight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBasedPreconfSlash {
    /// Canonical order-independent digest of the proven double-preconfirmation.
    pub evidence_digest: Hash32,
    /// L1 slot at which the equivocation occurred.
    pub l1_slot: u64,
    /// L2 sequence number at which the equivocation occurred.
    pub l2_sequence: u64,
    /// Sorted unique Ed25519 keys of proven equivocating preconfers.
    pub offenders: Vec<[u8; 32]>,
    /// Aggregate slashable voting weight attributable to `offenders`.
    pub slashed_voting_weight: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FocilInclusionProof {
    tx_hash: Hash32,
    leaf_index: u64,
    siblings: Vec<Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BasedBatchHeader {
    epoch: u64,
    l1_chain_id: u64,
    l1_slot: u64,
    l2_sequence: u64,
    proposer: [u8; 32],
    timestamp_secs: u64,
    pre_state_root: Hash32,
    state_root: Hash32,
    tx_root: Hash32,
    event_root: Hash32,
    il_root: Hash32,
    l1_anchor_slot: u64,
    l1_confirmations: u64,
    l1_anchor_root: Hash32,
    digest: Hash32,
}

impl BasedBatchHeader {
    #[must_use]
    fn compute_digest(&self, network: &str) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_BASED_BATCH_V1",
            network.as_bytes(),
            &self.epoch.to_le_bytes(),
            &self.l1_chain_id.to_le_bytes(),
            &self.l1_slot.to_le_bytes(),
            &self.l2_sequence.to_le_bytes(),
            &self.proposer,
            &self.timestamp_secs.to_le_bytes(),
            &self.pre_state_root,
            &self.state_root,
            &self.tx_root,
            &self.event_root,
            &self.il_root,
            &self.l1_anchor_slot.to_le_bytes(),
            &self.l1_confirmations.to_le_bytes(),
            &self.l1_anchor_root,
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BasedPreconfEvidence {
    batch: BasedBatchHeader,
    proposer_ed25519_sig: Vec<u8>,
    #[serde(default)]
    proposer_pq_sig: Vec<u8>,
    preconf_sigs: Vec<BasedSig>,
    focil_proofs: Vec<FocilInclusionProof>,
    focil_sigs: Vec<BasedSig>,
    l1_settle_sigs: Vec<BasedSig>,
}

#[must_use]
fn compute_focil_root(tx_hashes: &[Hash32]) -> Hash32 {
    if tx_hashes.is_empty() {
        return [0u8; 32];
    }
    let count_le = u64::try_from(tx_hashes.len())
        .unwrap_or(u64::MAX)
        .to_le_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(tx_hashes.len().saturating_add(2));
    parts.push(b"BDLM_BASED_FOCIL_ROOT_V1");
    parts.push(&count_le);
    for tx in tx_hashes {
        parts.push(tx);
    }
    crate::core::hash::hash_fields_bytes(&parts)
}

#[must_use]
fn tx_merkle_leaf(tx_hash: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[b"BDLM_BASED_TX_LEAF_V1", tx_hash])
}

#[must_use]
fn tx_merkle_node(left: &Hash32, right: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[b"BDLM_BASED_TX_NODE_V1", left, right])
}

fn verify_tx_merkle_inclusion(
    proof: &FocilInclusionProof,
    expected_root: &Hash32,
) -> Result<(), AdapterError> {
    if proof.tx_hash == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "FOCIL transaction digest cannot be all-zero".into(),
        });
    }
    if proof.siblings.len() > MAX_TX_MERKLE_DEPTH {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "FOCIL Merkle proof depth {} exceeds {MAX_TX_MERKLE_DEPTH}",
                proof.siblings.len()
            ),
        });
    }
    if proof.siblings.len() < 64 && (proof.leaf_index >> proof.siblings.len()) != 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "FOCIL Merkle leaf_index has non-zero bits above tree depth".into(),
        });
    }
    let mut acc = tx_merkle_leaf(&proof.tx_hash);
    let mut idx = proof.leaf_index;
    for sib in &proof.siblings {
        acc = if idx & 1 == 0 {
            tx_merkle_node(&acc, sib)
        } else {
            tx_merkle_node(sib, &acc)
        };
        idx >>= 1;
    }
    if !bool::from(acc.ct_eq(expected_root)) {
        return Err(AdapterError::ConsensusRule {
            rule: "FOCIL inclusion violation: mandated transaction absent from batch tx_root"
                .into(),
        });
    }
    Ok(())
}

#[must_use]
fn proposal_sign_bytes(network: &str, batch_digest: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_BASED_PROPOSE_V1",
        network.as_bytes(),
        batch_digest,
    ])
}

/// Compute canonical preconfirmation-certificate signing digest for
/// `(network, epoch, l1_slot, l2_sequence, batch_digest)`.
///
/// WIRING: shared between [`BasedPreconfAdapter`] and
/// [`verify_based_preconf_equivocation`].
#[must_use]
pub fn preconf_cert_sign_bytes(
    network: &str,
    epoch: u64,
    l1_slot: u64,
    l2_sequence: u64,
    batch_digest: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_BASED_CERT_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &l1_slot.to_le_bytes(),
        &l2_sequence.to_le_bytes(),
        batch_digest,
    ])
}

#[must_use]
fn focil_vote_sign_bytes(network: &str, epoch: u64, l1_slot: u64, il_root: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_BASED_FOCIL_VOTE_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &l1_slot.to_le_bytes(),
        il_root,
    ])
}

#[must_use]
fn l1_settle_sign_bytes(
    network: &str,
    l1_chain_id: u64,
    l1_anchor_slot: u64,
    l1_confirmations: u64,
    l1_anchor_root: &Hash32,
    batch_digest: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_BASED_L1_SETTLE_V1",
        network.as_bytes(),
        &l1_chain_id.to_le_bytes(),
        &l1_anchor_slot.to_le_bytes(),
        &l1_confirmations.to_le_bytes(),
        l1_anchor_root,
        batch_digest,
    ])
}

#[must_use]
const fn has_bft_supermajority(signed: u128, total: u128) -> bool {
    total > 0 && signed.saturating_mul(3) > total.saturating_mul(2)
}

#[must_use]
fn min_supermajority_weight(total: u128) -> u64 {
    let required = (total.saturating_mul(2) / 3).saturating_add(1);
    u64::try_from(required).unwrap_or(u64::MAX)
}

fn verify_validator_sig(
    member: &BasedPreconfValidator,
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

fn verify_quorum_sigs(
    committee: &BTreeMap<[u8; 32], &BasedPreconfValidator>,
    total_weight: u128,
    sigs: &[BasedSig],
    msg: &Hash32,
    what: &str,
) -> Result<(u64, u128, bool), AdapterError> {
    if sigs.is_empty() || sigs.len() > committee.len() {
        return Err(AdapterError::ConsensusRule {
            rule: format!("invalid {what} signer count {}", sigs.len()),
        });
    }
    let mut seen = BTreeSet::new();
    let mut signed_weight = 0u128;
    let mut all_pq = true;
    for sig in sigs {
        if !seen.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate signer in {what}"),
            });
        }
        let Some(member) = committee.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("unknown committee signer in {what}"),
            });
        };
        let pq_ok = verify_validator_sig(member, msg, &sig.ed25519_sig, &sig.pq_sig, what)?;
        all_pq &= pq_ok;
        signed_weight = signed_weight
            .checked_add(u128::from(member.voting_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: format!("{what} weight overflow"),
            })?;
    }
    if !has_bft_supermajority(signed_weight, total_weight) {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "{what} stake {signed_weight} does not exceed 2/3 of total {total_weight}"
            ),
        });
    }
    Ok((seen.len() as u64, signed_weight, all_pq))
}

#[cfg(test)]
fn encode_based_evidence(bundle: &BasedPreconfEvidence) -> Result<Vec<u8>, String> {
    let body =
        bincode::serialize(bundle).map_err(|e| format!("based-preconf encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_BASED_PAYLOAD_BYTES {
        return Err(format!(
            "based-preconf payload {total} exceeds ceiling {MAX_BASED_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_based_evidence(payload: &[u8]) -> Result<BasedPreconfEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "based-preconf payload shorter than 8-byte magic prefix".into(),
        });
    }
    if payload.len() > MAX_BASED_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_BASED_PAYLOAD_BYTES,
            reason: format!("based-preconf payload exceeds {MAX_BASED_PAYLOAD_BYTES} bytes"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "based-preconf payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing based-preconf payload body".into(),
    })?;
    let decoded =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_BASED_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("invalid based-preconf evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical based-preconf evidence".into(),
        });
    }
    Ok(decoded)
}

fn verify_based_slash_side(
    committee: &BTreeMap<[u8; 32], &BasedPreconfValidator>,
    sigs: &[BasedSig],
    msg: &Hash32,
    what: &str,
) -> Result<BTreeSet<[u8; 32]>, AdapterError> {
    if sigs.is_empty() || sigs.len() > committee.len() {
        return Err(AdapterError::ConsensusRule {
            rule: format!("invalid {what} signer count {}", sigs.len()),
        });
    }
    let mut seen = BTreeSet::new();
    for sig in sigs {
        if !seen.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate signer in {what}"),
            });
        }
        let Some(member) = committee.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("unknown committee signer in {what}"),
            });
        };
        let _ = verify_validator_sig(member, msg, &sig.ed25519_sig, &sig.pq_sig, what)?;
    }
    Ok(seen)
}

/// Verify permissionless based-preconfirmation equivocation evidence against a
/// governance-pinned [`PinnedBasedPreconfCommittee`].
///
/// WIRING: invoked in production by
/// `crate::cross_domain::economic_guard::BridgeEconomicGuard::submit_contradiction`.
///
/// # Errors
///
/// Returns [`AdapterError`] when the pinned committee is invalid, the epoch
/// mismatches, the slot or sequence is zero, the batch digests match or are
/// zero, any signature fails Ed25519 or mandatory ML-DSA-65 verification, or
/// no committee member signed both conflicting preconfirmations.
pub fn verify_based_preconf_equivocation(
    network: &str,
    pinned: &PinnedBasedPreconfCommittee,
    proof: &BasedPreconfEquivocationProof,
) -> Result<VerifiedBasedPreconfSlash, AdapterError> {
    if network.trim().is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "based-preconf equivocation network cannot be empty".into(),
        });
    }
    if pinned.l1_chain_id == 0
        || pinned.members.is_empty()
        || pinned.members.len() > MAX_BASED_COMMITTEE
    {
        return Err(AdapterError::ConsensusRule {
            rule: "invalid pinned based-preconf committee".into(),
        });
    }
    let mut committee = BTreeMap::new();
    for member in &pinned.members {
        if member.ed25519_pubkey == [0u8; 32] || member.voting_weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "based-preconf member requires non-zero key and positive weight".into(),
            });
        }
        if !member.pq_pubkey.is_empty() {
            crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, &member.pq_pubkey)
                .map_err(|_| AdapterError::ConsensusRule {
                    rule: "invalid ML-DSA-65 public key in based-preconf committee".into(),
                })?;
        }
        if committee.insert(member.ed25519_pubkey, member).is_some() {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate Ed25519 key in based-preconf committee".into(),
            });
        }
    }
    if proof.epoch != pinned.epoch || proof.l1_slot == 0 || proof.l2_sequence == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "based-preconf equivocation epoch mismatch or zero slot/sequence".into(),
        });
    }
    if bool::from(proof.batch_digest_a.ct_eq(&[0u8; 32]))
        || bool::from(proof.batch_digest_b.ct_eq(&[0u8; 32]))
        || bool::from(proof.batch_digest_a.ct_eq(&proof.batch_digest_b))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "based-preconf equivocation requires two distinct non-zero batch digests".into(),
        });
    }
    let msg_a = preconf_cert_sign_bytes(
        network,
        proof.epoch,
        proof.l1_slot,
        proof.l2_sequence,
        &proof.batch_digest_a,
    );
    let msg_b = preconf_cert_sign_bytes(
        network,
        proof.epoch,
        proof.l1_slot,
        proof.l2_sequence,
        &proof.batch_digest_b,
    );
    let set_a = verify_based_slash_side(&committee, &proof.sigs_a, &msg_a, "based-slash-a")?;
    let set_b = verify_based_slash_side(&committee, &proof.sigs_b, &msg_b, "based-slash-b")?;
    let offenders: Vec<[u8; 32]> = set_a.intersection(&set_b).copied().collect();
    if offenders.is_empty() {
        return Err(AdapterError::ConsensusRule {
            rule: "based-preconf equivocation has no overlapping offending preconfer".into(),
        });
    }
    let mut slashed = 0u128;
    for pk in &offenders {
        if let Some(m) = committee.get(pk) {
            slashed = slashed.saturating_add(u128::from(m.voting_weight));
        }
    }
    let (lo_digest, hi_digest) = if proof.batch_digest_a <= proof.batch_digest_b {
        (&proof.batch_digest_a, &proof.batch_digest_b)
    } else {
        (&proof.batch_digest_b, &proof.batch_digest_a)
    };
    let epoch_le = proof.epoch.to_le_bytes();
    let slot_le = proof.l1_slot.to_le_bytes();
    let seq_le = proof.l2_sequence.to_le_bytes();
    let cid_le = pinned.l1_chain_id.to_le_bytes();
    let count_le = (offenders.len() as u64).to_le_bytes();
    let mut fields: Vec<&[u8]> = Vec::with_capacity(offenders.len().saturating_add(9));
    fields.push(b"BDLM_BASED_SLASH_V1");
    fields.push(network.as_bytes());
    fields.push(&cid_le);
    fields.push(&epoch_le);
    fields.push(&slot_le);
    fields.push(&seq_le);
    fields.push(lo_digest);
    fields.push(hi_digest);
    fields.push(&count_le);
    for pk in &offenders {
        fields.push(pk);
    }
    Ok(VerifiedBasedPreconfSlash {
        evidence_digest: crate::core::hash::hash_fields_bytes(&fields),
        l1_slot: proof.l1_slot,
        l2_sequence: proof.l2_sequence,
        offenders,
        slashed_voting_weight: slashed,
    })
}

/// External finality adapter for based rollups, shared sequencers, and
/// EIP-7805 FOCIL censorship-resistant L1-settled batch commitments.
pub struct BasedPreconfAdapter {
    network: String,
    pinned: Option<PinnedBasedPreconfCommittee>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl BasedPreconfAdapter {
    /// Construct a `BasedPreconfAdapter` bound to `network` and its pinned
    /// preconfer / FOCIL committee.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedBasedPreconfCommittee>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(ADAPTER_NAME);
        let set_size = pinned.as_ref().map_or(0, |p| p.members.len() as u64);
        let descriptor = AdapterDescriptor {
            id,
            name: ADAPTER_NAME.into(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "based-preconf-focil".into(),
            finality_kind: FinalityKind::EconomicFinality,
            required_depth: MIN_L1_SETTLEMENT_CONFIRMATIONS,
            time_unit: TimeUnit::Height,
            trust_model: TrustModel::HonestMajority { set_size },
        };
        Self {
            network,
            pinned,
            golden: None,
            descriptor,
        }
    }

    /// Attach a canonical golden sample for [`super::selftest::admit`].
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn build_committee_index(
        pinned: &PinnedBasedPreconfCommittee,
    ) -> Result<(BTreeMap<[u8; 32], &BasedPreconfValidator>, u128), AdapterError> {
        if pinned.l1_chain_id == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "based-preconf pinned l1_chain_id cannot be zero".into(),
            });
        }
        if pinned.members.is_empty() || pinned.members.len() > MAX_BASED_COMMITTEE {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "based-preconf committee size {} outside 1..={MAX_BASED_COMMITTEE}",
                    pinned.members.len()
                ),
            });
        }
        let mut by_key = BTreeMap::new();
        let mut total = 0u128;
        for member in &pinned.members {
            if member.ed25519_pubkey == [0u8; 32] {
                return Err(AdapterError::ConsensusRule {
                    rule: "based-preconf validator pubkey cannot be all-zero".into(),
                });
            }
            if member.voting_weight == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "based-preconf validator voting_weight must be positive".into(),
                });
            }
            if !member.pq_pubkey.is_empty() {
                crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, &member.pq_pubkey)
                    .map_err(|_| AdapterError::ConsensusRule {
                        rule: "invalid pinned ML-DSA-65 public key in based-preconf committee"
                            .into(),
                    })?;
            }
            if by_key.insert(member.ed25519_pubkey, member).is_some() {
                return Err(AdapterError::ConsensusRule {
                    rule: "duplicate validator pubkey in pinned based-preconf committee".into(),
                });
            }
            total = total
                .checked_add(u128::from(member.voting_weight))
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "based-preconf total stake overflow".into(),
                })?;
        }
        Ok((by_key, total))
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
                    "based-preconf network mismatch: expected {}, got {}",
                    self.network, evidence.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no governance-pinned based-preconf committee configured".into(),
            });
        };
        let (committee, total_weight) = Self::build_committee_index(pinned)?;

        let decoded = decode_based_evidence(&evidence.payload)?;
        let batch = &decoded.batch;

        if batch.epoch != pinned.epoch {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "based-preconf batch epoch {} does not match pinned epoch {}",
                    batch.epoch, pinned.epoch
                ),
            });
        }
        if batch.l1_chain_id != pinned.l1_chain_id {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "based-preconf l1_chain_id {} does not match pinned {}",
                    batch.l1_chain_id, pinned.l1_chain_id
                ),
            });
        }
        if batch.l2_sequence == 0 || batch.l1_slot == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "based-preconf l1_slot and l2_sequence must be positive".into(),
            });
        }
        if batch.state_root == [0u8; 32]
            || batch.tx_root == [0u8; 32]
            || batch.l1_anchor_root == [0u8; 32]
        {
            return Err(AdapterError::ConsensusRule {
                rule: "based-preconf state_root, tx_root, and l1_anchor_root must be non-zero"
                    .into(),
            });
        }
        if batch.l1_anchor_slot < batch.l1_slot || batch.l1_confirmations == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "based-preconf L1 anchor must be at or after batch l1_slot with positive confirmations".into(),
            });
        }

        if policy.require_declared_match {
            if evidence.declared_height != batch.l2_sequence {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&batch.state_root)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }

        let required_depth = policy.min_depth.max(self.descriptor.required_depth);
        if batch.l1_confirmations < required_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: batch.l1_confirmations,
                required: required_depth,
            });
        }
        if policy.max_age > 0 && policy.now > batch.l2_sequence {
            let age = policy.now.saturating_sub(batch.l2_sequence);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let expected_digest = batch.compute_digest(&self.network);
        if !bool::from(batch.digest.ct_eq(&expected_digest)) {
            return Err(AdapterError::ConsensusRule {
                rule: "based-preconf batch digest does not match self-derived fields".into(),
            });
        }

        // 1. Proposer preconfirmation signature.
        let Some(proposer_member) = committee.get(&batch.proposer) else {
            return Err(AdapterError::ConsensusRule {
                rule: "based-preconf proposer is not in pinned committee".into(),
            });
        };
        let prop_msg = proposal_sign_bytes(&self.network, &batch.digest);
        let mut all_pq = verify_validator_sig(
            proposer_member,
            &prop_msg,
            &decoded.proposer_ed25519_sig,
            &decoded.proposer_pq_sig,
            "based-preconf proposal",
        )?;

        // 2. Shared-sequencer preconfer supermajority certificate.
        let cert_msg = preconf_cert_sign_bytes(
            &self.network,
            batch.epoch,
            batch.l1_slot,
            batch.l2_sequence,
            &batch.digest,
        );
        let (preconf_signers, _, cert_pq) = verify_quorum_sigs(
            &committee,
            total_weight,
            &decoded.preconf_sigs,
            &cert_msg,
            "based-preconf quorum",
        )?;
        all_pq &= cert_pq;

        // 3. EIP-7805 FOCIL inclusion-list quorum and full Merkle inclusion check.
        if decoded.focil_proofs.len() > MAX_FOCIL_ENTRIES {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "FOCIL inclusion list count {} exceeds {MAX_FOCIL_ENTRIES}",
                    decoded.focil_proofs.len()
                ),
            });
        }
        if pinned.require_focil && decoded.focil_proofs.is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned based-preconf domain requires a non-empty FOCIL inclusion list"
                    .into(),
            });
        }
        if decoded.focil_proofs.is_empty() {
            if batch.il_root != [0u8; 32] || !decoded.focil_sigs.is_empty() {
                return Err(AdapterError::ConsensusRule {
                    rule: "empty FOCIL list must carry zero il_root and empty focil_sigs".into(),
                });
            }
        } else {
            let mut ordered_txs = Vec::with_capacity(decoded.focil_proofs.len());
            let mut prev_tx: Option<Hash32> = None;
            for proof in &decoded.focil_proofs {
                if prev_tx.is_some_and(|prev| proof.tx_hash <= prev) {
                    return Err(AdapterError::ConsensusRule {
                        rule: "FOCIL transaction hashes must be strictly ascending and unique"
                            .into(),
                    });
                }
                verify_tx_merkle_inclusion(proof, &batch.tx_root)?;
                prev_tx = Some(proof.tx_hash);
                ordered_txs.push(proof.tx_hash);
            }
            let expected_il_root = compute_focil_root(&ordered_txs);
            if !bool::from(batch.il_root.ct_eq(&expected_il_root)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "FOCIL inclusion list root mismatch".into(),
                });
            }
            let il_msg =
                focil_vote_sign_bytes(&self.network, batch.epoch, batch.l1_slot, &batch.il_root);
            let (_, _, il_pq) = verify_quorum_sigs(
                &committee,
                total_weight,
                &decoded.focil_sigs,
                &il_msg,
                "FOCIL inclusion-list quorum",
            )?;
            all_pq &= il_pq;
        }

        // 4. L1 settlement anchor upgrade certificate.
        let settle_msg = l1_settle_sign_bytes(
            &self.network,
            batch.l1_chain_id,
            batch.l1_anchor_slot,
            batch.l1_confirmations,
            &batch.l1_anchor_root,
            &batch.digest,
        );
        let (settle_signers, _, settle_pq) = verify_quorum_sigs(
            &committee,
            total_weight,
            &decoded.l1_settle_sigs,
            &settle_msg,
            "based-preconf L1 settlement quorum",
        )?;
        all_pq &= settle_pq;

        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let attested_event_root = (batch.event_root != [0u8; 32]).then_some(batch.event_root);

        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: batch.l2_sequence,
            state_root: batch.state_root,
            attested_block_hash: Some(batch.digest),
            attested_event_root,
            attested_tx_root: Some(batch.tx_root),
            finalized_at: batch.l2_sequence,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers: preconf_signers.min(settle_signers),
                required: min_supermajority_weight(total_weight),
                total_weight,
                slashable: true,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
        };
        Ok((attestation, all_pq))
    }
}

impl ExternalFinalityAdapter for BasedPreconfAdapter {
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
        let sig_tail = self
            .golden
            .as_ref()
            .map_or(32, |g| g.payload.len().saturating_sub(16));
        vec![
            FaultProbe {
                name: "refuses unsupported based-preconf evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 9 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign based-preconf network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared L2 sequence".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared based state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted based-preconf magic header".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0x00, 0xFF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated based-preconf batch epoch".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0x7E],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted L1 settlement signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![0xBA, 0xAD, 0xF0, 0x0D],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated based-preconf payload".into(),
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

    struct TestSigner {
        ed: KeyPair,
        pq: Option<PqKeyPair>,
        weight: u64,
    }

    impl TestSigner {
        fn new(seed: u8, weight: u64, with_pq: bool) -> Self {
            let ed = KeyPair::from_seed(&[seed; 32]).unwrap();
            let pq = with_pq.then(PqKeyPair::generate);
            Self { ed, pq, weight }
        }

        fn to_validator(&self) -> BasedPreconfValidator {
            BasedPreconfValidator {
                ed25519_pubkey: self.ed.public_key_bytes(),
                voting_weight: self.weight,
                pq_pubkey: self
                    .pq
                    .as_ref()
                    .map_or_else(Vec::new, |pk| pk.public_key_bytes().to_vec()),
            }
        }

        fn sign(&self, msg: &Hash32) -> BasedSig {
            let ed_sig = self.ed.sign(msg).to_vec();
            let pq_sig = self.pq.as_ref().map_or_else(Vec::new, |pq| {
                pq.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, msg).unwrap()
            });
            BasedSig {
                signer_pubkey: self.ed.public_key_bytes(),
                ed25519_sig: ed_sig,
                pq_sig,
            }
        }
    }

    fn four_leaf_tree(txs: [Hash32; 4]) -> (Hash32, Vec<FocilInclusionProof>) {
        let l0 = tx_merkle_leaf(&txs[0]);
        let l1 = tx_merkle_leaf(&txs[1]);
        let l2 = tx_merkle_leaf(&txs[2]);
        let l3 = tx_merkle_leaf(&txs[3]);
        let n01 = tx_merkle_node(&l0, &l1);
        let n23 = tx_merkle_node(&l2, &l3);
        let root = tx_merkle_node(&n01, &n23);
        let proofs = vec![
            FocilInclusionProof {
                tx_hash: txs[0],
                leaf_index: 0,
                siblings: vec![l1, n23],
            },
            FocilInclusionProof {
                tx_hash: txs[2],
                leaf_index: 2,
                siblings: vec![l3, n01],
            },
        ];
        (root, proofs)
    }

    fn build_fixture(
        network: &str,
        state_root: Hash32,
        with_pq: bool,
    ) -> (
        PinnedBasedPreconfCommittee,
        Vec<TestSigner>,
        BasedPreconfEvidence,
        RawConsensusEvidence,
    ) {
        let signers = vec![
            TestSigner::new(1, 30, with_pq),
            TestSigner::new(2, 30, with_pq),
            TestSigner::new(3, 25, with_pq),
            TestSigner::new(4, 15, with_pq),
        ];
        let pinned = PinnedBasedPreconfCommittee {
            epoch: 5,
            l1_chain_id: 1,
            require_focil: true,
            members: signers.iter().map(TestSigner::to_validator).collect(),
        };
        let txs = [[0x10; 32], [0x20; 32], [0x30; 32], [0x40; 32]];
        let (tx_root, mut focil_proofs) = four_leaf_tree(txs);
        focil_proofs.sort_by_key(|p| p.tx_hash);
        let il_txs: Vec<Hash32> = focil_proofs.iter().map(|p| p.tx_hash).collect();
        let il_root = compute_focil_root(&il_txs);

        let mut batch = BasedBatchHeader {
            epoch: 5,
            l1_chain_id: 1,
            l1_slot: 900,
            l2_sequence: 1_500,
            proposer: signers[0].ed.public_key_bytes(),
            timestamp_secs: 1_750_000_000,
            pre_state_root: [0xAA; 32],
            state_root,
            tx_root,
            event_root: [0xCC; 32],
            il_root,
            l1_anchor_slot: 902,
            l1_confirmations: 4,
            l1_anchor_root: [0xDD; 32],
            digest: [0u8; 32],
        };
        batch.digest = batch.compute_digest(network);

        let prop_sig = signers[0].sign(&proposal_sign_bytes(network, &batch.digest));
        let cert_msg = preconf_cert_sign_bytes(network, 5, 900, 1_500, &batch.digest);
        let il_msg = focil_vote_sign_bytes(network, 5, 900, &il_root);
        let settle_msg = l1_settle_sign_bytes(network, 1, 902, 4, &[0xDD; 32], &batch.digest);

        // First 3 signers carry 85/100 > 2/3 stake.
        let quorum = |m: &Hash32| vec![signers[0].sign(m), signers[1].sign(m), signers[2].sign(m)];
        let bundle = BasedPreconfEvidence {
            batch: batch.clone(),
            proposer_ed25519_sig: prop_sig.ed25519_sig,
            proposer_pq_sig: prop_sig.pq_sig,
            preconf_sigs: quorum(&cert_msg),
            focil_proofs,
            focil_sigs: quorum(&il_msg),
            l1_settle_sigs: quorum(&settle_msg),
        };
        let payload = encode_based_evidence(&bundle).unwrap();
        let ev = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: network.into(),
            payload,
            declared_height: batch.l2_sequence,
            declared_root: batch.state_root,
            submitter: Address::from([0x09; 32]),
        };
        (pinned, signers, bundle, ev)
    }

    #[test]
    fn hybrid_based_preconf_focil_and_l1_settlement_passes_selftest_and_records_pq() {
        let (pinned, _, _, golden) = build_fixture("taiko-based-1", [0xBB; 32], true);
        let adapter =
            BasedPreconfAdapter::new("taiko-based-1", Some(pinned)).with_golden(golden.clone());
        let policy = VerificationPolicy::strict(1_510);

        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&golden, &policy, &mut facts)
            .unwrap();
        assert_eq!(att.height, 1_500);
        assert_eq!(att.state_root, [0xBB; 32]);
        assert_eq!(att.attested_event_root, Some([0xCC; 32]));
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ED25519)), 1);
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 1);

        let report = admit(&adapter, &policy);
        assert!(
            report.admitted,
            "based-preconf selftest failed: {:?}",
            report.probes
        );
    }

    #[test]
    fn focil_censorship_pq_stripping_and_sub_quorum_are_refused() {
        let (pinned, signers, mut bundle, mut ev) =
            build_fixture("taiko-based-1", [0xBB; 32], true);
        let adapter = BasedPreconfAdapter::new("taiko-based-1", Some(pinned));
        let policy = VerificationPolicy::strict(1_510);

        // 1. Censoring a FOCIL-mandated tx by corrupting its Merkle path fails closed.
        let saved_sib = bundle.focil_proofs[1].siblings[0];
        bundle.focil_proofs[1].siblings[0] = [0x99; 32];
        ev.payload = encode_based_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("FOCIL inclusion violation")
        ));
        bundle.focil_proofs[1].siblings[0] = saved_sib;

        // 2. Stripping mandatory ML-DSA-65 co-signature from any signer fails closed.
        let saved_pq = std::mem::take(&mut bundle.preconf_sigs[0].pq_sig);
        ev.payload = encode_based_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::Crypto { .. })
        ));
        bundle.preconf_sigs[0].pq_sig = saved_pq;

        // 3. Sub-quorum 60/100 <= 2/3 stake is refused.
        let saved_sigs = bundle.preconf_sigs.clone();
        bundle.preconf_sigs.truncate(2);
        ev.payload = encode_based_evidence(&bundle).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("2/3")
        ));
        bundle.preconf_sigs = saved_sigs;

        // 4. Omitting FOCIL when require_focil == true is refused even if re-signed.
        let mut censored = bundle.clone();
        censored.batch.il_root = [0u8; 32];
        censored.batch.digest = censored.batch.compute_digest("taiko-based-1");
        let prop = signers[0].sign(&proposal_sign_bytes(
            "taiko-based-1",
            &censored.batch.digest,
        ));
        censored.proposer_ed25519_sig = prop.ed25519_sig;
        censored.proposer_pq_sig = prop.pq_sig;
        let cm = preconf_cert_sign_bytes("taiko-based-1", 5, 900, 1_500, &censored.batch.digest);
        let sm = l1_settle_sign_bytes(
            "taiko-based-1",
            1,
            902,
            4,
            &[0xDD; 32],
            &censored.batch.digest,
        );
        censored.preconf_sigs = vec![
            signers[0].sign(&cm),
            signers[1].sign(&cm),
            signers[2].sign(&cm),
        ];
        censored.focil_proofs.clear();
        censored.focil_sigs.clear();
        censored.l1_settle_sigs = vec![
            signers[0].sign(&sm),
            signers[1].sign(&sm),
            signers[2].sign(&sm),
        ];
        ev.payload = encode_based_evidence(&censored).unwrap();
        assert!(matches!(
            adapter.verify(&ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("non-empty FOCIL")
        ));
    }

    #[test]
    fn registry_lifecycle_contradiction_slash_and_pq_cosig_tracking() {
        use crate::cross_domain::external::{
            ChallengeReward, DomainEconomics, DomainState, ExternalDomainRegistry, VersionPolicy,
        };

        let net = "taiko-based-1";
        let (pinned, signers, mut bundle_b, ev_a) = build_fixture(net, [0xB1; 32], true);
        let prover = ev_a.submitter;
        let challenger = Address::from([0x0A; 32]);

        // Same pinned committee equivocates on a conflicting state_root at l2_sequence 1500.
        bundle_b.batch.state_root = [0xB2; 32];
        bundle_b.batch.digest = bundle_b.batch.compute_digest(net);
        let prop_sig = signers[0].sign(&proposal_sign_bytes(net, &bundle_b.batch.digest));
        bundle_b.proposer_ed25519_sig = prop_sig.ed25519_sig;
        bundle_b.proposer_pq_sig = prop_sig.pq_sig;
        let cert_msg = preconf_cert_sign_bytes(net, 5, 900, 1_500, &bundle_b.batch.digest);
        bundle_b.preconf_sigs = signers[0..3].iter().map(|s| s.sign(&cert_msg)).collect();
        let settle_msg = l1_settle_sign_bytes(net, 1, 902, 4, &[0xDD; 32], &bundle_b.batch.digest);
        bundle_b.l1_settle_sigs = signers[0..3].iter().map(|s| s.sign(&settle_msg)).collect();
        let mut ev_b = ev_a.clone();
        ev_b.declared_root = [0xB2; 32];
        ev_b.submitter = challenger;
        ev_b.payload = encode_based_evidence(&bundle_b).unwrap();

        let adapter = BasedPreconfAdapter::new(net, Some(pinned)).with_golden(ev_a.clone());
        let policy = VerificationPolicy::strict(1_510);
        let admission = admit(&adapter, &policy);
        assert!(admission.admitted);

        let econ = DomainEconomics {
            routing_ceiling_atoms: 1_000_000,
            challenge: ChallengeReward {
                bps_of_slash: 1_000,
                floor_atoms: 0,
            },
            ..DomainEconomics::default()
        };
        let bond_atoms = econ.required_bond_atoms();
        let mut registry = ExternalDomainRegistry::new();
        let domain = registry
            .register(
                net,
                adapter.descriptor(),
                econ,
                VersionPolicy::single(adapter.descriptor().id, EVIDENCE_VERSION, 0),
                &admission,
                bond_atoms,
                prover,
            )
            .unwrap();
        registry
            .bond_prover(&domain, challenger, bond_atoms)
            .unwrap();

        let att = registry.submit(&adapter, &ev_a, &policy).unwrap();
        assert_eq!(
            registry
                .domain(&domain)
                .unwrap()
                .record
                .crypto_facts
                .count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)),
            1
        );

        // Equivocating batch at identical sequence verifies cryptographically, is rejected on
        // duplicate height, freezes the domain, and slashes the dishonest carrier's bond.
        let conflict = adapter.verify(&ev_b, &policy).unwrap();
        assert_eq!(conflict.height, att.height);
        assert_ne!(conflict.state_root, att.state_root);
        assert!(registry.submit(&adapter, &ev_b, &policy).is_err());
        registry
            .mark_faulted(&domain, "based-preconf conflicting batch proof")
            .unwrap();
        assert_eq!(
            registry.domain(&domain).unwrap().record.state,
            DomainState::Faulted
        );
        let (slashed, reward) = registry
            .slash(
                &domain,
                prover,
                att.evidence_digest,
                econ.routing_ceiling_atoms,
                challenger,
            )
            .unwrap();
        assert!(slashed > 0 && reward > 0 && reward <= slashed);
        assert!(!registry
            .domain(&domain)
            .unwrap()
            .attestations
            .contains_key(&(att.height, EVIDENCE_VERSION)));
    }
}
