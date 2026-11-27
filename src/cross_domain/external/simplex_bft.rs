//! Chan-Pass Simplex (2023) and `MonadBFT` (2025) 2-round tail-forking-resistant
//! Byzantine fault-tolerant external finality adapter with No-Endorsement
//! Certificate (`NEC`) gap proofs and safety-theorem slashing verification.
//!
//! Simplex achieves optimal 2-round optimistic finality under partial synchrony
//! by pairing a first-round `Notarize(view, block)` quorum (`> 2/3` stake) with
//! a second-round `Finalize(view, block)` quorum (`> 2/3` stake) while allowing
//! stalled views to emit a `Skip(view)` certificate (`> 2/3` stake) with the
//! protocol rule that an honest validator NEVER signs both `Finalize(v, b)` and
//! `Skip(v)`. `MonadBFT` closes the leader tail-forking attack across skipped
//! views by requiring any proposal jumping from `parent_view` to
//! `view > parent_view + 1` to carry both contiguous `Skip` certificates for
//! every intermediate view AND a `> 2/3` `NoEndorsementCertificate` (`NEC`)
//! proving no uncertified intermediate tip was dropped without reproposal:
//!
//! 1. **Self-derived block & optional epoch rotation**: `block.digest` binds
//!    `(network, epoch, view, parent_view, height, proposer, timestamp_ms,
//!    parent_hash, state_root, tx_root, event_root, next_committee_hash)`.
//!    Evidence may verify either directly under `pinned.epoch` or under
//!    `pinned.epoch + 1` when accompanied by a verified `EpochTransition` whose
//!    finalized checkpoint under `pinned.epoch` commits the exact
//!    `committee_hash` of the successor committee.
//! 2. **Same-view 2-round Notarize + Finalize**: distinct committee members
//!    with combined stake strictly exceeding `2/3 * total_stake` must sign both
//!    `Notarize(epoch, view, block.digest)` and `Finalize(epoch, view,
//!    block.digest)`.
//! 3. **`MonadBFT` tail-forking protection**: when `block.view >
//!    block.parent_view + 1`, the gap `(block.view - block.parent_view - 1)` is
//!    bounded (`<= 32`), every skipped view `v` in
//!    `(block.parent_view + 1)..block.view` must carry a valid `> 2/3`
//!    `SkipCertificate`, and a valid `> 2/3` `NoEndorsementCertificate` must
//!    bind `(epoch, block.parent_view, block.view, block.parent_hash)`. Missing
//!    skip or NEC proofs fail closed with [`AdapterError::ConsensusRule`].
//! 4. **Hybrid post-quantum non-downgrade**: every validator carrying a
//!    non-empty ML-DSA-65 public key MUST attach a valid ML-DSA-65 co-signature
//!    under [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
//! 5. **Dual safety-theorem slashing ([`verify_simplex_slashing`])**: verifies
//!    either `DoubleNotarize` (two distinct blocks notarized in the same view)
//!    or `FinalizeAndSkip` (signing both `Finalize(view, block)` and
//!    `Skip(view)` in the same view).
//!
//! WIRING: implements [`ExternalFinalityAdapter`] and is invoked in production
//! by [`crate::cross_domain::economic_guard`] for Simplex/`MonadBFT` ceiling
//! checks and safety-violation slashing.

use crate::core::hash::hash_fields_bytes;
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::pq;
use crate::crypto::primitives::verify_signature;
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

const ADAPTER_NAME: &str = "simplex-bft-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMSPX1";
const MAX_SIMPLEX_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_SIMPLEX_COMMITTEE: usize = 1_024;
const MAX_SIMPLEX_SKIP_VIEWS: usize = 128;

/// One validator in a Simplex / `MonadBFT` epoch committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplexValidator {
    /// Classical Ed25519 verifying key (32 bytes, non-zero).
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero slashable stake weight.
    pub stake_weight: u64,
    /// Optional ML-DSA-65 public key; when non-empty, ML-DSA-65 co-signatures
    /// under `CROSS_DOMAIN_V1` are mandatory on every vote.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned epoch validator committee for a Simplex/`MonadBFT` domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedSimplexCommittee {
    /// Consensus epoch served by `validators`.
    pub epoch: u64,
    /// Active validator set for `epoch`.
    pub validators: Vec<SimplexValidator>,
}

impl PinnedSimplexCommittee {
    /// Canonical length-prefixed SHA3-256 commitment over the pinned epoch and
    /// ordered validator committee.
    ///
    /// WIRING: checked in constant time by `crate::cross_domain::economic_guard`
    /// on both backing refreshes and contradiction submissions.
    #[must_use]
    pub fn canonical_pin_digest(&self) -> Hash32 {
        let mut acc = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_SIMPLEX_PIN_V1",
            &self.epoch.to_le_bytes(),
            &(self.validators.len() as u64).to_le_bytes(),
        ]);
        for v in &self.validators {
            acc = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_SIMPLEX_PIN_V1",
                &[1u8],
                &acc,
                &v.ed25519_pubkey,
                &v.stake_weight.to_le_bytes(),
                &v.pq_pubkey,
            ]);
        }
        acc
    }

    /// Return the slashable stake weight and whether an ML-DSA-65 key is bound
    /// for `pubkey`.
    ///
    /// WIRING: used by `crate::cross_domain::economic_guard` for incremental
    /// per-offender Simplex slashing accounting.
    #[must_use]
    pub fn validator_member_info(&self, pubkey: &[u8; 32]) -> Option<(u128, bool)> {
        self.validators
            .iter()
            .find(|v| bool::from(v.ed25519_pubkey.ct_eq(pubkey)))
            .map(|v| (u128::from(v.stake_weight), !v.pq_pubkey.is_empty()))
    }
}

/// Detached hybrid vote signature for Simplex Notarize, Finalize, Skip, or NEC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplexSignature {
    /// Validator Ed25519 verifying key.
    pub signer_pubkey: [u8; 32],
    /// Detached Ed25519 signature bytes.
    pub ed25519_sig: Vec<u8>,
    /// Mandatory ML-DSA-65 co-signature when `pq_pubkey` is non-empty.
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Self-derived Simplex / `MonadBFT` finalized block header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplexBlockHeader {
    /// Consensus epoch.
    pub epoch: u64,
    /// View number in which this block was proposed and finalized (`>= 1`).
    pub view: u64,
    /// View number of `parent_hash` (`< view`).
    pub parent_view: u64,
    /// Monotonic block height (`>= 1`).
    pub height: u64,
    /// Proposer validator Ed25519 public key.
    pub proposer: [u8; 32],
    /// Block timestamp in Unix milliseconds.
    pub timestamp_ms: u64,
    /// Parent block digest (non-zero).
    pub parent_hash: Hash32,
    /// Committed post-state root (non-zero).
    pub state_root: Hash32,
    /// Committed transaction root (non-zero).
    pub tx_root: Hash32,
    /// Optional bridge event root (`[0; 32]` when absent).
    pub event_root: Hash32,
    /// Optional successor epoch committee hash (`[0; 32]` outside boundary).
    pub next_committee_hash: Hash32,
    /// Self-derived domain-separated block digest.
    pub digest: Hash32,
}

impl SimplexBlockHeader {
    /// Compute the canonical domain-separated digest for this block header.
    #[must_use]
    pub fn compute_digest(&self, network: &str) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_SIMPLEX_BLOCK_V1",
            network.as_bytes(),
            &self.epoch.to_le_bytes(),
            &self.view.to_le_bytes(),
            &self.parent_view.to_le_bytes(),
            &self.height.to_le_bytes(),
            &self.proposer,
            &self.timestamp_ms.to_le_bytes(),
            &self.parent_hash,
            &self.state_root,
            &self.tx_root,
            &self.event_root,
            &self.next_committee_hash,
        ])
    }
}

/// Certified skipped view in `(parent_view + 1)..view`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplexSkipCertificate {
    /// Skipped view number.
    pub view: u64,
    /// Distinct committee signatures exceeding `2/3` total stake.
    pub sigs: Vec<SimplexSignature>,
}

/// `MonadBFT` No-Endorsement Certificate (`NEC`) protecting the highest certified
/// tip `high_tip_hash` against tail-forking across skipped views.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoEndorsementCertificate {
    /// View of the preserved certified parent (`== block.parent_view`).
    pub from_view: u64,
    /// Resuming proposal view (`== block.view`).
    pub to_view: u64,
    /// Certified parent tip digest preserved across the gap (`== block.parent_hash`).
    pub high_tip_hash: Hash32,
    /// Distinct committee signatures exceeding `2/3` total stake.
    pub sigs: Vec<SimplexSignature>,
}

/// Verified single-epoch committee rotation proof (`pinned.epoch -> pinned.epoch + 1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplexEpochTransition {
    /// Finalized boundary block in `pinned.epoch` carrying `next_committee_hash`.
    pub boundary_block: SimplexBlockHeader,
    /// Finalize quorum signatures from `pinned.validators`.
    pub finalize_sigs: Vec<SimplexSignature>,
    /// Successor committee for `pinned.epoch + 1`.
    pub next_validators: Vec<SimplexValidator>,
}

/// Canonical wire bundle carried in [`RawConsensusEvidence::payload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplexBftEvidence {
    /// Finalized target block header.
    pub block: SimplexBlockHeader,
    /// First-round `Notarize(epoch, view, block.digest)` quorum (`> 2/3`).
    pub notarize_sigs: Vec<SimplexSignature>,
    /// Second-round `Finalize(epoch, view, block.digest)` quorum (`> 2/3`).
    pub finalize_sigs: Vec<SimplexSignature>,
    /// Contiguous `Skip` certificates for `(parent_view + 1)..view` when non-empty.
    #[serde(default)]
    pub skip_certs: Vec<SimplexSkipCertificate>,
    /// Mandatory `MonadBFT` `NEC` whenever `view > parent_view + 1`.
    pub nec: Option<NoEndorsementCertificate>,
    /// Optional committee handoff proof from `pinned.epoch` to `pinned.epoch + 1`.
    pub epoch_transition: Option<SimplexEpochTransition>,
}

/// Slashable safety-theorem violation in Simplex / `MonadBFT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimplexSlashingProof {
    /// Validator signed `Notarize` for two distinct block hashes in the same view.
    DoubleNotarize {
        /// Epoch of both votes.
        epoch: u64,
        /// View of both votes.
        view: u64,
        /// Height associated with the fault report.
        height: u64,
        /// First notarized block digest.
        block_digest_a: Hash32,
        /// Signatures on `block_digest_a`.
        sigs_a: Vec<SimplexSignature>,
        /// Second conflicting notarized block digest (`!= block_digest_a`).
        block_digest_b: Hash32,
        /// Signatures on `block_digest_b`.
        sigs_b: Vec<SimplexSignature>,
    },
    /// Validator signed both `Finalize(view, block_digest)` and `Skip(view)` in
    /// the same `(epoch, view)`, directly breaking Simplex 2-round safety.
    FinalizeAndSkip {
        /// Epoch of both votes.
        epoch: u64,
        /// View of both conflicting votes.
        view: u64,
        /// Height of the finalized block.
        height: u64,
        /// Block digest on the `Finalize` vote.
        block_digest: Hash32,
        /// Signatures on `Finalize(epoch, view, block_digest)`.
        finalize_sigs: Vec<SimplexSignature>,
        /// Signatures on `Skip(epoch, view)`.
        skip_sigs: Vec<SimplexSignature>,
    },
}

/// Verified outcome of [`verify_simplex_slashing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSimplexSlash {
    /// Canonical domain-separated digest of the proven safety fault.
    pub evidence_digest: Hash32,
    /// Reported block height of the safety violation.
    pub fault_height: u64,
    /// Sorted unique Ed25519 keys of proven equivocating validators.
    pub offenders: Vec<[u8; 32]>,
    /// Aggregate slashable stake weight of `offenders`.
    pub slashed_stake_weight: u128,
}

/// Canonical commitment hash over an ordered validator committee for `epoch`.
#[must_use]
pub fn simplex_committee_hash(
    network: &str,
    epoch: u64,
    validators: &[SimplexValidator],
) -> Hash32 {
    let mut leaves = Vec::with_capacity(validators.len());
    for v in validators {
        leaves.push(crate::core::hash::hash_fields_bytes(&[
            b"BDLM_SIMPLEX_COMMITTEE_V1",
            network.as_bytes(),
            &epoch.to_le_bytes(),
            &v.ed25519_pubkey,
            &v.stake_weight.to_le_bytes(),
            &v.pq_pubkey,
        ]));
    }
    let count_le = u64::try_from(leaves.len())
        .unwrap_or(u64::MAX)
        .to_le_bytes();
    let epoch_le = epoch.to_le_bytes();
    let mut fields: Vec<&[u8]> = Vec::with_capacity(leaves.len().saturating_add(4));
    fields.push(b"BDLM_SIMPLEX_COMMITTEE_V1");
    fields.push(network.as_bytes());
    fields.push(&epoch_le);
    fields.push(&count_le);
    for leaf in &leaves {
        fields.push(leaf);
    }
    crate::core::hash::hash_fields_bytes(&fields)
}

/// Canonical signing root for first-round `Notarize(epoch, view, block_digest)`.
#[must_use]
pub fn notarize_sign_bytes(network: &str, epoch: u64, view: u64, block_digest: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_SIMPLEX_NOTARIZE_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &view.to_le_bytes(),
        block_digest,
    ])
}

/// Canonical signing root for second-round `Finalize(epoch, view, block_digest)`.
#[must_use]
pub fn finalize_sign_bytes(network: &str, epoch: u64, view: u64, block_digest: &Hash32) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_SIMPLEX_FINALIZE_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &view.to_le_bytes(),
        block_digest,
    ])
}

/// Canonical signing root for stalled-view `Skip(epoch, view)`.
#[must_use]
pub fn skip_sign_bytes(network: &str, epoch: u64, view: u64) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_SIMPLEX_SKIP_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &view.to_le_bytes(),
    ])
}

/// Canonical signing root for `MonadBFT` `NoEndorsementCertificate`.
#[must_use]
pub fn nec_sign_bytes(
    network: &str,
    epoch: u64,
    from_view: u64,
    to_view: u64,
    high_tip_hash: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_SIMPLEX_NEC_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &from_view.to_le_bytes(),
        &to_view.to_le_bytes(),
        high_tip_hash,
    ])
}

/// Encode a [`SimplexBftEvidence`] bundle with its 8-byte magic header.
///
/// WIRING: used by Simplex/`MonadBFT` relayers and
/// [`crate::cross_domain::economic_guard`] verification tests.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] when serialization fails or exceeds the
/// payload byte ceiling.
pub fn encode_simplex_evidence(bundle: &SimplexBftEvidence) -> Result<Vec<u8>, AdapterError> {
    let body = bincode::serialize(bundle).map_err(|e| AdapterError::Malformed {
        offset: 0,
        reason: format!("simplex-bft encode failed: {e}"),
    })?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_SIMPLEX_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_SIMPLEX_PAYLOAD_BYTES,
            reason: format!("simplex-bft payload {total} exceeds {MAX_SIMPLEX_PAYLOAD_BYTES}"),
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_simplex_evidence(payload: &[u8]) -> Result<SimplexBftEvidence, AdapterError> {
    if payload.len() > MAX_SIMPLEX_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_SIMPLEX_PAYLOAD_BYTES,
            reason: format!(
                "simplex-bft payload {} exceeds {MAX_SIMPLEX_PAYLOAD_BYTES}",
                payload.len()
            ),
        });
    }
    let Some(magic) = payload.get(..PAYLOAD_MAGIC.len()) else {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "simplex-bft payload truncated before 8-byte magic header".into(),
        });
    };
    if !bool::from(magic.ct_eq(PAYLOAD_MAGIC)) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "invalid simplex-bft payload magic header".into(),
        });
    }
    let body = payload
        .get(PAYLOAD_MAGIC.len()..)
        .ok_or_else(|| AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: "missing simplex-bft payload body".into(),
        })?;
    let decoded: SimplexBftEvidence =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_SIMPLEX_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: PAYLOAD_MAGIC.len(),
                reason: format!("invalid simplex-bft evidence body: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: "non-canonical trailing bytes in simplex-bft evidence".into(),
        });
    }
    Ok(decoded)
}

const fn min_simplex_supermajority(total: u128) -> u128 {
    (total.saturating_mul(2) / 3).saturating_add(1)
}

type IndexedSimplexSet<'a> = BTreeMap<[u8; 32], (u64, &'a [u8])>;

fn index_simplex_committee<'a>(
    validators: &'a [SimplexValidator],
    label: &str,
) -> Result<(IndexedSimplexSet<'a>, u128), AdapterError> {
    if validators.is_empty() || validators.len() > MAX_SIMPLEX_COMMITTEE {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "{label} validator count {} outside 1..={MAX_SIMPLEX_COMMITTEE}",
                validators.len()
            ),
        });
    }
    let mut by_key = BTreeMap::new();
    let mut total = 0u128;
    for v in validators {
        if bool::from(v.ed25519_pubkey.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} validator pubkey cannot be all-zero"),
            });
        }
        if v.stake_weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} validator stake_weight must be positive"),
            });
        }
        if !v.pq_pubkey.is_empty() {
            pq::validate_public_key(SchemeId::ML_DSA_65, &v.pq_pubkey).map_err(|_| {
                AdapterError::ConsensusRule {
                    rule: format!("invalid ML-DSA-65 public key in {label}"),
                }
            })?;
        }
        if by_key
            .insert(v.ed25519_pubkey, (v.stake_weight, v.pq_pubkey.as_slice()))
            .is_some()
        {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate validator pubkey in {label}"),
            });
        }
        total = total
            .checked_add(u128::from(v.stake_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: format!("{label} total stake overflow"),
            })?;
    }
    Ok((by_key, total))
}

fn verify_simplex_sig(
    ed_pk: &[u8; 32],
    pq_pk: &[u8],
    msg: &Hash32,
    sig: &SimplexSignature,
    label: &str,
) -> Result<bool, AdapterError> {
    verify_signature(msg, &sig.ed25519_sig, ed_pk).map_err(|e| AdapterError::Crypto {
        what: format!("{label} Ed25519 verification failed: {e}"),
    })?;
    if pq_pk.is_empty() {
        if !sig.pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: format!("{label} carries unexpected ML-DSA-65 signature"),
            });
        }
        return Ok(false);
    }
    if sig.pq_sig.is_empty() {
        return Err(AdapterError::Crypto {
            what: format!("{label} missing mandatory ML-DSA-65 co-signature"),
        });
    }
    pq::verify(
        SchemeId::ML_DSA_65,
        pq_pk,
        msg,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &sig.pq_sig,
    )
    .map_err(|e| AdapterError::Crypto {
        what: format!("{label} ML-DSA-65 verification failed: {e}"),
    })?;
    Ok(true)
}

fn verify_simplex_quorum(
    index: &IndexedSimplexSet<'_>,
    total_weight: u128,
    sigs: &[SimplexSignature],
    msg: &Hash32,
    label: &str,
) -> Result<(u128, bool), AdapterError> {
    if sigs.is_empty() || sigs.len() > index.len() {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "{label} signature count {} outside 1..={}",
                sigs.len(),
                index.len()
            ),
        });
    }
    let mut seen = BTreeSet::new();
    let mut signed = 0u128;
    let mut all_pq = true;
    for sig in sigs {
        let Some(&(stake, pq_pk)) = index.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} signer is not in active Simplex committee"),
            });
        };
        if !seen.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate signer in {label}"),
            });
        }
        let has_pq = verify_simplex_sig(&sig.signer_pubkey, pq_pk, msg, sig, label)?;
        all_pq &= has_pq;
        signed =
            signed
                .checked_add(u128::from(stake))
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: format!("{label} signed stake overflow"),
                })?;
    }
    let required = min_simplex_supermajority(total_weight);
    if signed < required {
        return Err(AdapterError::ConsensusRule {
            rule: format!("{label} signed stake {signed} below required >2/3 threshold {required}"),
        });
    }
    Ok((signed, all_pq))
}

fn verify_simplex_slash_side(
    index: &IndexedSimplexSet<'_>,
    sigs: &[SimplexSignature],
    msg: &Hash32,
    label: &str,
) -> Result<BTreeSet<[u8; 32]>, AdapterError> {
    if sigs.is_empty() || sigs.len() > index.len() {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "{label} signature count {} outside 1..={}",
                sigs.len(),
                index.len()
            ),
        });
    }
    let mut signers = BTreeSet::new();
    for sig in sigs {
        let Some(&(_, pq_pk)) = index.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} references validator outside pinned committee"),
            });
        };
        if !signers.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate validator signature in {label}"),
            });
        }
        let _ = verify_simplex_sig(&sig.signer_pubkey, pq_pk, msg, sig, label)?;
    }
    Ok(signers)
}

/// Verify a [`SimplexSlashingProof`] against a governance-pinned committee.
///
/// # Errors
///
/// Returns [`AdapterError`] when the committee is invalid, the evidence fails
/// to show a genuine safety conflict, any signature or PQ half fails, or no
/// validator overlaps both conflicting vote sets.
pub fn verify_simplex_slashing(
    network: &str,
    pinned: &PinnedSimplexCommittee,
    proof: &SimplexSlashingProof,
) -> Result<VerifiedSimplexSlash, AdapterError> {
    let (idx, _) = index_simplex_committee(&pinned.validators, "simplex-bft pinned committee")?;
    match proof {
        SimplexSlashingProof::DoubleNotarize {
            epoch,
            view,
            height,
            block_digest_a,
            sigs_a,
            block_digest_b,
            sigs_b,
        } => {
            if *epoch != pinned.epoch || *view == 0 || *height == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "simplex DoubleNotarize epoch mismatch or zero view/height".into(),
                });
            }
            if bool::from(block_digest_a.ct_eq(&[0u8; 32]))
                || bool::from(block_digest_b.ct_eq(&[0u8; 32]))
                || bool::from(block_digest_a.ct_eq(block_digest_b))
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "simplex DoubleNotarize requires two distinct non-zero block digests"
                        .into(),
                });
            }
            let msg_a = notarize_sign_bytes(network, *epoch, *view, block_digest_a);
            let msg_b = notarize_sign_bytes(network, *epoch, *view, block_digest_b);
            let set_a = verify_simplex_slash_side(&idx, sigs_a, &msg_a, "simplex-notarize-a")?;
            let set_b = verify_simplex_slash_side(&idx, sigs_b, &msg_b, "simplex-notarize-b")?;
            let offenders: Vec<[u8; 32]> = set_a.intersection(&set_b).copied().collect();
            if offenders.is_empty() {
                return Err(AdapterError::ConsensusRule {
                    rule: "simplex DoubleNotarize has no overlapping offending validator".into(),
                });
            }
            let mut slashed = 0u128;
            for pk in &offenders {
                if let Some(&(stake, _)) = idx.get(pk) {
                    slashed = slashed.saturating_add(u128::from(stake));
                }
            }
            let epoch_le = epoch.to_le_bytes();
            let view_le = view.to_le_bytes();
            let height_le = height.to_le_bytes();
            let (lo_block, hi_block) = if block_digest_a <= block_digest_b {
                (block_digest_a, block_digest_b)
            } else {
                (block_digest_b, block_digest_a)
            };
            let count_le = u64::try_from(offenders.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes();
            let mut fields: Vec<&[u8]> = Vec::with_capacity(offenders.len().saturating_add(9));
            fields.push(b"BDLM_SIMPLEX_SLASH_V1");
            fields.push(&[1u8]);
            fields.push(network.as_bytes());
            fields.push(&epoch_le);
            fields.push(&view_le);
            fields.push(&height_le);
            fields.push(lo_block);
            fields.push(hi_block);
            fields.push(&count_le);
            for pk in &offenders {
                fields.push(pk);
            }
            Ok(VerifiedSimplexSlash {
                evidence_digest: hash_fields_bytes(&fields),
                fault_height: *height,
                offenders,
                slashed_stake_weight: slashed,
            })
        }
        SimplexSlashingProof::FinalizeAndSkip {
            epoch,
            view,
            height,
            block_digest,
            finalize_sigs,
            skip_sigs,
        } => {
            if *epoch != pinned.epoch || *view == 0 || *height == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "simplex FinalizeAndSkip epoch mismatch or zero view/height".into(),
                });
            }
            if bool::from(block_digest.ct_eq(&[0u8; 32])) {
                return Err(AdapterError::ConsensusRule {
                    rule: "simplex FinalizeAndSkip block_digest must be non-zero".into(),
                });
            }
            let fin_msg = finalize_sign_bytes(network, *epoch, *view, block_digest);
            let skp_msg = skip_sign_bytes(network, *epoch, *view);
            let fin_set =
                verify_simplex_slash_side(&idx, finalize_sigs, &fin_msg, "simplex-finalize-slash")?;
            let skp_set =
                verify_simplex_slash_side(&idx, skip_sigs, &skp_msg, "simplex-skip-slash")?;
            let offenders: Vec<[u8; 32]> = fin_set.intersection(&skp_set).copied().collect();
            if offenders.is_empty() {
                return Err(AdapterError::ConsensusRule {
                    rule: "simplex FinalizeAndSkip has no overlapping validator".into(),
                });
            }
            let mut slashed = 0u128;
            for pk in &offenders {
                if let Some(&(stake, _)) = idx.get(pk) {
                    slashed = slashed.saturating_add(u128::from(stake));
                }
            }
            let epoch_le = epoch.to_le_bytes();
            let view_le = view.to_le_bytes();
            let height_le = height.to_le_bytes();
            let count_le = u64::try_from(offenders.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes();
            let mut fields: Vec<&[u8]> = Vec::with_capacity(offenders.len().saturating_add(8));
            fields.push(b"BDLM_SIMPLEX_SLASH_V1");
            fields.push(&[2u8]);
            fields.push(network.as_bytes());
            fields.push(&epoch_le);
            fields.push(&view_le);
            fields.push(&height_le);
            fields.push(block_digest);
            fields.push(&count_le);
            for pk in &offenders {
                fields.push(pk);
            }
            Ok(VerifiedSimplexSlash {
                evidence_digest: hash_fields_bytes(&fields),
                fault_height: *height,
                offenders,
                slashed_stake_weight: slashed,
            })
        }
    }
}

/// External finality adapter for 2-round Simplex and tail-forking-resistant
/// `MonadBFT` domains.
pub struct SimplexBftAdapter {
    network: String,
    pinned: Option<PinnedSimplexCommittee>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl SimplexBftAdapter {
    /// Construct a `SimplexBftAdapter` bound to `network` and its pinned epoch
    /// committee.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedSimplexCommittee>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(ADAPTER_NAME);
        let set_size = pinned
            .as_ref()
            .map_or(0, |p| u64::try_from(p.validators.len()).unwrap_or(u64::MAX));
        let descriptor = AdapterDescriptor {
            id,
            name: ADAPTER_NAME.into(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "simplex-monadbft-2round".into(),
            finality_kind: FinalityKind::ProtocolFinality,
            required_depth: 1,
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
    ///
    /// WIRING: used during permissionless adapter registration self-tests.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn validate_header_basics(
        &self,
        hdr: &SimplexBlockHeader,
        committee: &IndexedSimplexSet<'_>,
        label: &str,
    ) -> Result<(), AdapterError> {
        if hdr.height == 0 || hdr.view == 0 || hdr.parent_view >= hdr.view {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} height/view ordering is invalid"),
            });
        }
        if bool::from(hdr.parent_hash.ct_eq(&[0u8; 32]))
            || bool::from(hdr.state_root.ct_eq(&[0u8; 32]))
            || bool::from(hdr.tx_root.ct_eq(&[0u8; 32]))
        {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} parent_hash, state_root, and tx_root must be non-zero"),
            });
        }
        if !committee.contains_key(&hdr.proposer) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} proposer is not a member of active committee"),
            });
        }
        let expected = hdr.compute_digest(&self.network);
        if !bool::from(hdr.digest.ct_eq(&expected)) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} digest does not match self-derived header fields"),
            });
        }
        Ok(())
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
                    "simplex-bft network mismatch: expected {}, got {}",
                    self.network, evidence.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no governance-pinned simplex-bft committee configured".into(),
            });
        };
        let (pinned_idx, pinned_total) =
            index_simplex_committee(&pinned.validators, "simplex-bft pinned committee")?;

        let decoded = decode_simplex_evidence(&evidence.payload)?;
        let block = &decoded.block;

        if policy.require_declared_match {
            if evidence.declared_height != block.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&block.state_root)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        if policy.min_depth > 1 {
            return Err(AdapterError::InsufficientDepth {
                observed: 1,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 {
            if block.height > policy.now {
                return Err(AdapterError::Stale {
                    age: block.height - policy.now,
                    max_age: policy.max_age,
                });
            }
            let age = policy.now - block.height;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let mut all_pq = true;
        let (active_idx, active_total) = match &decoded.epoch_transition {
            None => {
                if block.epoch != pinned.epoch {
                    return Err(AdapterError::ConsensusRule {
                        rule: format!(
                            "simplex-bft block epoch {} does not match pinned epoch {}",
                            block.epoch, pinned.epoch
                        ),
                    });
                }
                (pinned_idx, pinned_total)
            }
            Some(tr) => {
                let next_epoch =
                    pinned
                        .epoch
                        .checked_add(1)
                        .ok_or_else(|| AdapterError::ConsensusRule {
                            rule: "simplex-bft epoch rotation overflow".into(),
                        })?;
                if block.epoch != next_epoch || tr.boundary_block.epoch != pinned.epoch {
                    return Err(AdapterError::ConsensusRule {
                        rule: "simplex-bft epoch transition must step pinned.epoch -> pinned.epoch + 1".into(),
                    });
                }
                if block.height <= tr.boundary_block.height {
                    return Err(AdapterError::ConsensusRule {
                        rule: "simplex-bft target block height must advance past boundary block"
                            .into(),
                    });
                }
                self.validate_header_basics(
                    &tr.boundary_block,
                    &pinned_idx,
                    "simplex-bft boundary block",
                )?;
                let (next_idx, next_total) = index_simplex_committee(
                    &tr.next_validators,
                    "simplex-bft successor committee",
                )?;
                let want_next_hash =
                    simplex_committee_hash(&self.network, next_epoch, &tr.next_validators);
                if !bool::from(tr.boundary_block.next_committee_hash.ct_eq(&want_next_hash)) {
                    return Err(AdapterError::ConsensusRule {
                        rule: "simplex-bft boundary next_committee_hash mismatches successor set"
                            .into(),
                    });
                }
                let bf_msg = finalize_sign_bytes(
                    &self.network,
                    tr.boundary_block.epoch,
                    tr.boundary_block.view,
                    &tr.boundary_block.digest,
                );
                let (_, handoff_pq) = verify_simplex_quorum(
                    &pinned_idx,
                    pinned_total,
                    &tr.finalize_sigs,
                    &bf_msg,
                    "simplex-bft epoch handoff Finalize",
                )?;
                all_pq &= handoff_pq;
                (next_idx, next_total)
            }
        };

        self.validate_header_basics(block, &active_idx, "simplex-bft block")?;

        // Round 1: Notarize(epoch, view, block.digest) > 2/3 stake.
        let notarize_msg =
            notarize_sign_bytes(&self.network, block.epoch, block.view, &block.digest);
        let (notarize_signers, not_pq) = verify_simplex_quorum(
            &active_idx,
            active_total,
            &decoded.notarize_sigs,
            &notarize_msg,
            "simplex-bft Notarize certificate",
        )?;
        all_pq &= not_pq;

        // Round 2: Finalize(epoch, view, block.digest) > 2/3 stake.
        let finalize_msg =
            finalize_sign_bytes(&self.network, block.epoch, block.view, &block.digest);
        let (finalize_signers, fin_pq) = verify_simplex_quorum(
            &active_idx,
            active_total,
            &decoded.finalize_sigs,
            &finalize_msg,
            "simplex-bft Finalize certificate",
        )?;
        all_pq &= fin_pq;

        // Skipped-view chain + mandatory MonadBFT No-Endorsement Certificate.
        let gap = block
            .view
            .saturating_sub(block.parent_view)
            .saturating_sub(1);
        if gap == 0 {
            if !decoded.skip_certs.is_empty() || decoded.nec.is_some() {
                return Err(AdapterError::ConsensusRule {
                    rule: "contiguous simplex-bft view must not carry skip certificates or NEC"
                        .into(),
                });
            }
        } else {
            let max_gap = u64::try_from(MAX_SIMPLEX_SKIP_VIEWS).unwrap_or(128);
            if gap > max_gap {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("simplex-bft skipped view gap {gap} exceeds {max_gap}"),
                });
            }
            if u64::try_from(decoded.skip_certs.len()).ok() != Some(gap) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "simplex-bft view gap {gap} requires exact contiguous SkipCertificates, got {}",
                        decoded.skip_certs.len()
                    ),
                });
            }
            for (offset, skip_cert) in decoded.skip_certs.iter().enumerate() {
                let want_view = block
                    .parent_view
                    .saturating_add(1)
                    .saturating_add(u64::try_from(offset).unwrap_or(u64::MAX));
                if skip_cert.view != want_view {
                    return Err(AdapterError::ConsensusRule {
                        rule: format!(
                            "simplex-bft skip certificate view {} does not match expected {want_view}",
                            skip_cert.view
                        ),
                    });
                }
                let skp_msg = skip_sign_bytes(&self.network, block.epoch, skip_cert.view);
                let (_, skp_pq) = verify_simplex_quorum(
                    &active_idx,
                    active_total,
                    &skip_cert.sigs,
                    &skp_msg,
                    "simplex-bft SkipCertificate",
                )?;
                all_pq &= skp_pq;
            }
            let Some(nec) = &decoded.nec else {
                return Err(AdapterError::ConsensusRule {
                    rule: "simplex-bft skipped view gap requires MonadBFT NoEndorsementCertificate"
                        .into(),
                });
            };
            if nec.from_view != block.parent_view
                || nec.to_view != block.view
                || !bool::from(nec.high_tip_hash.ct_eq(&block.parent_hash))
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "simplex-bft NEC bounds or high_tip_hash mismatch block parent".into(),
                });
            }
            let nec_msg = nec_sign_bytes(
                &self.network,
                block.epoch,
                nec.from_view,
                nec.to_view,
                &nec.high_tip_hash,
            );
            let (_, nec_pq) = verify_simplex_quorum(
                &active_idx,
                active_total,
                &nec.sigs,
                &nec_msg,
                "simplex-bft MonadBFT NEC",
            )?;
            all_pq &= nec_pq;
        }

        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let attested_event_root =
            (!bool::from(block.event_root.ct_eq(&[0u8; 32]))).then_some(block.event_root);
        // Foreign Simplex committee stake has no local confiscation escrow,
        // so the backing is not slashable from Budlum.
        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }
        let min_signed = notarize_signers.min(finalize_signers);
        let required_weight = min_simplex_supermajority(active_total);
        let shift = 128u32
            .saturating_sub(active_total.leading_zeros())
            .saturating_sub(64);
        let signers = u64::try_from(min_signed >> shift).unwrap_or(u64::MAX);
        let required = u64::try_from(required_weight >> shift)
            .unwrap_or(u64::MAX)
            .max(1);
        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: block.height,
            state_root: block.state_root,
            finalized_at: block.height,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers,
                required,
                total_weight: active_total,
                slashable: false,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(block.digest),
            attested_event_root,
            attested_tx_root: Some(block.tx_root),
        };
        Ok((attestation, all_pq))
    }
}

impl ExternalFinalityAdapter for SimplexBftAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn has_pinned_trust_anchor(&self) -> bool {
        self.pinned
            .as_ref()
            .is_some_and(|p| !p.validators.is_empty())
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
        if all_pq {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        } else {
            observer.observe(ObservedScheme::Scheme(SchemeId::ED25519));
        }
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_tail = self
            .golden
            .as_ref()
            .map_or(32, |g| g.payload.len().saturating_sub(32));
        let flipped_epoch = self
            .golden
            .as_ref()
            .and_then(|g| g.payload.get(8).copied())
            .map_or(0x7B, |b| b ^ 0xFF);
        let flipped_sig = self
            .golden
            .as_ref()
            .and_then(|g| g.payload.get(sig_tail).copied())
            .map_or(0xFE, |b| b ^ 0xFF);
        vec![
            FaultProbe {
                name: "refuses unsupported simplex-bft evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 42 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign simplex-bft network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared simplex height".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared simplex state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted simplex-bft magic header".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0x00, 0x77],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated simplex block epoch".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![flipped_epoch],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted simplex finalize/NEC signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![flipped_sig],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated simplex-bft payload".into(),
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
    use crate::cross_domain::external::selftest::admit_observed;
    use crate::cross_domain::external::spec::SecurityBacking;
    use crate::crypto::facts::{CryptoFacts, ObservedScheme, QuantumClass};
    use crate::crypto::primitives::{KeyPair, PqKeyPair};
    use crate::crypto::scheme::SchemeId;

    const NET: &str = "monad-simplex-1";

    struct ValSigner {
        ed: KeyPair,
        pq: PqKeyPair,
        stake: u64,
    }

    impl ValSigner {
        fn new(seed: u8, stake: u64) -> Self {
            Self {
                ed: KeyPair::from_seed(&[seed; 32]).unwrap(),
                pq: PqKeyPair::generate(),
                stake,
            }
        }

        fn as_validator(&self) -> SimplexValidator {
            SimplexValidator {
                ed25519_pubkey: self.ed.public_key_bytes(),
                stake_weight: self.stake,
                pq_pubkey: self.pq.public_key_bytes().to_vec(),
            }
        }

        fn sign(&self, msg: &Hash32) -> SimplexSignature {
            SimplexSignature {
                signer_pubkey: self.ed.public_key_bytes(),
                ed25519_sig: self.ed.sign(msg).to_vec(),
                pq_sig: self
                    .pq
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, msg)
                    .unwrap(),
            }
        }
    }

    fn build_gap_fixture() -> (
        [ValSigner; 4],
        PinnedSimplexCommittee,
        SimplexBftEvidence,
        RawConsensusEvidence,
    ) {
        let vals = [
            ValSigner::new(41, 250),
            ValSigner::new(42, 250),
            ValSigner::new(43, 250),
            ValSigner::new(44, 250),
        ];
        let pinned = PinnedSimplexCommittee {
            epoch: 3,
            validators: vals.iter().map(ValSigner::as_validator).collect(),
        };
        let parent_hash = [0x88; 32];
        // Jump from parent_view=10 across skipped views 11 and 12 into view=13.
        let mut block = SimplexBlockHeader {
            epoch: 3,
            view: 13,
            parent_view: 10,
            height: 1_500,
            proposer: vals[0].ed.public_key_bytes(),
            timestamp_ms: 1_750_200_000_000,
            parent_hash,
            state_root: [0x61; 32],
            tx_root: [0x62; 32],
            event_root: [0x63; 32],
            next_committee_hash: [0u8; 32],
            digest: [0u8; 32],
        };
        block.digest = block.compute_digest(NET);

        let n_msg = notarize_sign_bytes(NET, 3, 13, &block.digest);
        let f_msg = finalize_sign_bytes(NET, 3, 13, &block.digest);
        let skip11 = skip_sign_bytes(NET, 3, 11);
        let skip12 = skip_sign_bytes(NET, 3, 12);
        let nec_msg = nec_sign_bytes(NET, 3, 10, 13, &parent_hash);

        let bundle = SimplexBftEvidence {
            block: block.clone(),
            notarize_sigs: vals[..3].iter().map(|v| v.sign(&n_msg)).collect(),
            finalize_sigs: vals[1..4].iter().map(|v| v.sign(&f_msg)).collect(),
            skip_certs: vec![
                SimplexSkipCertificate {
                    view: 11,
                    sigs: vals[..3].iter().map(|v| v.sign(&skip11)).collect(),
                },
                SimplexSkipCertificate {
                    view: 12,
                    sigs: vals[1..4].iter().map(|v| v.sign(&skip12)).collect(),
                },
            ],
            nec: Some(NoEndorsementCertificate {
                from_view: 10,
                to_view: 13,
                high_tip_hash: parent_hash,
                sigs: vals[..3].iter().map(|v| v.sign(&nec_msg)).collect(),
            }),
            epoch_transition: None,
        };
        let payload = encode_simplex_evidence(&bundle).unwrap();
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: NET.into(),
            declared_height: block.height,
            declared_root: block.state_root,
            payload,
            submitter: crate::core::address::Address::from([0x33; 32]),
        };
        (vals, pinned, bundle, raw)
    }

    #[test]
    fn simplex_bft_admits_fault_probes_and_verifies_nec_and_epoch_rotation() {
        let (vals, pinned, _, raw) = build_gap_fixture();
        let adapter = SimplexBftAdapter::new(NET, Some(pinned.clone())).with_golden(raw.clone());
        let policy = VerificationPolicy {
            min_depth: 1,
            max_age: 500,
            now: 1_600,
            require_declared_match: true,
            require_slashable: false,
        };
        let mut slash_policy = policy.clone();
        slash_policy.require_slashable = true;
        assert!(
            matches!(
                adapter.verify(&raw, &slash_policy),
                Err(AdapterError::UnslashableBacking)
            ),
            "foreign Simplex stake without local confiscation escrow must refuse require_slashable with the class that names the rule"
        );
        let mut facts = CryptoFacts::new();
        let att = adapter
            .verify_observed(&raw, &policy, &mut facts)
            .expect("valid 2-round Simplex + NEC evidence verifies");
        assert_eq!(att.height, 1_500);
        assert_eq!(att.attested_event_root, Some([0x63; 32]));
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Lattice));
        assert!(matches!(
            att.security,
            SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                total_weight: 1_000,
                slashable: false,
                ..
            }
        ));

        let (report, _) = admit_observed(&adapter, &policy);
        assert!(report.admitted, "simplex selftest must pass: {report:?}");

        crate::domain::finality_proof_model::FinalityProofShape::from_external_attestation(
            &adapter.descriptor(),
            &att,
        )
        .expect("stake-weighted Simplex BFT attestation must satisfy FinalityProofShape");
        let mut future_policy = policy.clone();
        future_policy.max_age = 500;
        future_policy.now = att.height.saturating_sub(1);
        assert!(
            matches!(
                adapter.verify(&raw, &future_policy),
                Err(AdapterError::Stale { .. })
            ),
            "future-dated Simplex block height above policy.now must fail closed when max_age > 0"
        );

        // Verify epoch rotation from epoch 3 -> epoch 4 with fresh committee.
        let next_vals = [
            ValSigner::new(51, 300),
            ValSigner::new(52, 300),
            ValSigner::new(53, 300),
            ValSigner::new(54, 300),
        ];
        let next_committee: Vec<_> = next_vals.iter().map(ValSigner::as_validator).collect();
        let next_hash = simplex_committee_hash(NET, 4, &next_committee);
        let mut boundary = SimplexBlockHeader {
            epoch: 3,
            view: 20,
            parent_view: 19,
            height: 1_510,
            proposer: vals[0].ed.public_key_bytes(),
            timestamp_ms: 1_750_200_010_000,
            parent_hash: [0x90; 32],
            state_root: [0x91; 32],
            tx_root: [0x92; 32],
            event_root: [0u8; 32],
            next_committee_hash: next_hash,
            digest: [0u8; 32],
        };
        boundary.digest = boundary.compute_digest(NET);
        let bf_msg = finalize_sign_bytes(NET, 3, 20, &boundary.digest);

        let mut e4_block = SimplexBlockHeader {
            epoch: 4,
            view: 1,
            parent_view: 0,
            height: 1_511,
            proposer: next_vals[0].ed.public_key_bytes(),
            timestamp_ms: 1_750_200_011_000,
            parent_hash: boundary.digest,
            state_root: [0x93; 32],
            tx_root: [0x94; 32],
            event_root: [0x95; 32],
            next_committee_hash: [0u8; 32],
            digest: [0u8; 32],
        };
        e4_block.digest = e4_block.compute_digest(NET);
        let e4_n = notarize_sign_bytes(NET, 4, 1, &e4_block.digest);
        let e4_f = finalize_sign_bytes(NET, 4, 1, &e4_block.digest);
        let rotated = SimplexBftEvidence {
            block: e4_block.clone(),
            notarize_sigs: next_vals[..3].iter().map(|v| v.sign(&e4_n)).collect(),
            finalize_sigs: next_vals[..3].iter().map(|v| v.sign(&e4_f)).collect(),
            skip_certs: vec![],
            nec: None,
            epoch_transition: Some(SimplexEpochTransition {
                boundary_block: boundary,
                finalize_sigs: vals[..3].iter().map(|v| v.sign(&bf_msg)).collect(),
                next_validators: next_committee,
            }),
        };
        let rotated_raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: NET.into(),
            declared_height: e4_block.height,
            declared_root: e4_block.state_root,
            payload: encode_simplex_evidence(&rotated).unwrap(),
            submitter: crate::core::address::Address::from([0x33; 32]),
        };
        let rot_att = adapter
            .verify(&rotated_raw, &VerificationPolicy::strict(1_600))
            .expect("certified epoch 3 -> 4 rotation verifies");
        assert_eq!(rot_att.height, 1_511);
    }

    #[test]
    fn simplex_bft_refuses_missing_skip_missing_nec_tail_fork_and_notarize_only_forgery() {
        let (_, pinned, bundle, raw) = build_gap_fixture();
        let adapter = SimplexBftAdapter::new(NET, Some(pinned));
        let policy = VerificationPolicy::strict(1_600);

        // 1. Missing intermediate skip certificate -> ConsensusRule.
        let mut missing_skip = bundle.clone();
        missing_skip.skip_certs.pop();
        let mut r = raw.clone();
        r.payload = encode_simplex_evidence(&missing_skip).unwrap();
        let err = adapter
            .verify(&r, &policy)
            .expect_err("skipped view gap without SkipCertificate must fail closed");
        assert!(matches!(err, AdapterError::ConsensusRule { .. }), "{err:?}");

        // 2. Missing MonadBFT NEC on view jump -> ConsensusRule (tail-fork defense).
        let mut missing_nec = bundle.clone();
        missing_nec.nec = None;
        r.payload = encode_simplex_evidence(&missing_nec).unwrap();
        let nerr = adapter
            .verify(&r, &policy)
            .expect_err("view jump without MonadBFT NEC must fail closed");
        assert!(
            matches!(nerr, AdapterError::ConsensusRule { .. }),
            "{nerr:?}"
        );

        // 3. Sub-2/3 Finalize quorum even with valid Notarize fails closed.
        let mut short_fin = bundle;
        short_fin.finalize_sigs.truncate(2); // 500 <= 2/3 of 1000
        r.payload = encode_simplex_evidence(&short_fin).unwrap();
        let ferr = adapter
            .verify(&r, &policy)
            .expect_err("Notarize without >2/3 Finalize must never finalize");
        assert!(
            matches!(ferr, AdapterError::ConsensusRule { .. }),
            "{ferr:?}"
        );
    }

    #[test]
    fn simplex_bft_slashing_catches_double_notarize_and_finalize_plus_skip_violation() {
        let (vals, pinned, _, _) = build_gap_fixture();
        let da = [0x31; 32];
        let db = [0x32; 32];

        // 1. DoubleNotarize in view 13 by validator 2 (stake 250).
        let na = notarize_sign_bytes(NET, 3, 13, &da);
        let nb = notarize_sign_bytes(NET, 3, 13, &db);
        let dn = SimplexSlashingProof::DoubleNotarize {
            epoch: 3,
            view: 13,
            height: 1_500,
            block_digest_a: da,
            sigs_a: vec![vals[0].sign(&na), vals[2].sign(&na)],
            block_digest_b: db,
            sigs_b: vec![vals[2].sign(&nb), vals[3].sign(&nb)],
        };
        let dn_res = verify_simplex_slashing(NET, &pinned, &dn)
            .expect("DoubleNotarize in same view must slash offender");
        assert_eq!(dn_res.offenders, vec![vals[2].ed.public_key_bytes()]);
        assert_eq!(dn_res.slashed_stake_weight, 250);

        // 2. Finalize(view=13, da) + Skip(view=13) by validators 0 and 1 (stake 500).
        let fm = finalize_sign_bytes(NET, 3, 13, &da);
        let sm = skip_sign_bytes(NET, 3, 13);
        let fs = SimplexSlashingProof::FinalizeAndSkip {
            epoch: 3,
            view: 13,
            height: 1_500,
            block_digest: da,
            finalize_sigs: vec![vals[0].sign(&fm), vals[1].sign(&fm)],
            skip_sigs: vec![vals[1].sign(&sm), vals[0].sign(&sm), vals[3].sign(&sm)],
        };
        let fs_res = verify_simplex_slashing(NET, &pinned, &fs)
            .expect("Finalize+Skip in same view violates Simplex safety and slashes");
        assert_eq!(fs_res.offenders.len(), 2);
        assert_eq!(fs_res.slashed_stake_weight, 500);

        // 3. Disjoint signer sets (honest split) must NEVER slash.
        let disjoint = SimplexSlashingProof::FinalizeAndSkip {
            epoch: 3,
            view: 13,
            height: 1_500,
            block_digest: da,
            finalize_sigs: vec![vals[0].sign(&fm)],
            skip_sigs: vec![vals[3].sign(&sm)],
        };
        assert!(verify_simplex_slashing(NET, &pinned, &disjoint).is_err());
    }
}
