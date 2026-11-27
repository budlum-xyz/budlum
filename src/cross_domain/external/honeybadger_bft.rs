//! `HoneyBadgerBFT` leaderless asynchronous common-subset external finality
//! adapter (`honeybadger-bft-v1`, Miller-Xia-Croman-Shi-Song 2016 lineage).
//!
//! Partially synchronous BFT protocols (`Tendermint`, `HotStuff`, `Simplex`)
//! rely on a designated leader and timeout progression after GST for liveness,
//! exposing a single leader slot to adaptive denial-of-service or censorship.
//! `HoneyBadgerBFT` operates in the purely asynchronous network model with zero leaders, zero
//! view-change timers, and zero timing assumptions: in each epoch `e`, all `N`
//! validators broadcast erasure-coded transaction batches via Bracha Reliable
//! Broadcast (`RBC`) and run `N` concurrent Asynchronous Binary Agreement
//! (`ABA`) instances to decide an Asynchronous Common Subset (`ACS`) holding at
//! least `N - f` distinct validator contributions (`f = floor((N - 1) / 3)`).
//!
//! [`HoneyBadgerBftAdapter`] verifies every finalized ACS epoch certificate with
//! pure NIST FIPS 204 ML-DSA-65 (`SchemeId::ML_DSA_65`, `CROSS_DOMAIN_V1`) so
//! the domain relies on zero classical elliptic-curve or pairing assumptions:
//!
//! 1. **Pinned committee sanity.** Requires `4 <= N <= MAX_HBBFT_VALIDATORS`,
//!    non-empty `network_id`, non-zero `genesis_hash`, strictly unique non-zero
//!    validator identifiers, non-empty ML-DSA-65 public keys, and positive
//!    overflow-free stake weights.
//! 2. **Bounded exact decoding.** Requires an explicit `HBBFTV01` framing tag,
//!    a strict `MAX_HBBFT_PAYLOAD_BYTES` cap, and trailing-byte rejection.
//! 3. **ACS subset completeness (`>= N - f`).** Contributions are strictly
//!    ascending by `proposer_index < N` (zero duplicates), carry non-zero
//!    Bracha `rbc_erasure_root` and `batch_tx_root` commitments with positive
//!    `tx_count`, reach at least `N - floor((N - 1) / 3)` distinct proposers,
//!    and rebuild `evidence.acs_root` and `evidence.tx_root` in constant time.
//! 4. **Pure post-quantum BFT certification.** Votes are strictly ascending by
//!    `voter_index < N` (zero double-counting), verify under `ML-DSA-65`
//!    (`CROSS_DOMAIN_V1`) over the canonical `BDLM_HBBFT_ACS_CERT_V1` digest,
//!    reach at least `N - f` distinct signers, and satisfy strict stake
//!    supermajority `signed_weight * 3 > total_weight * 2` in checked `u128`
//!    arithmetic.
//! 5. **Quantum-quarantine resilience.** `verify_observed` reports exclusively
//!    `SchemeId::ML_DSA_65` (`QuantumClass::Lattice`) and only after every
//!    protocol check succeeds.
//! 6. **Slashable Bracha RBC equivocation.** [`verify_rbc_equivocation`]
//!    verifies two conflicting ML-DSA-65 `BDLM_HBBFT_RBC_SHARE_V1` root
//!    commitments signed by the same validator for the same `(genesis_hash,
//!    committee_epoch, acs_epoch, proposer_index)`.
//!
//! WIRING: wired - `AdapterSpec::HoneyBadgerBft { network, committee }` (wire
//! tag 18) builds this adapter from an intake registration whose epoch
//! committee must equal the governance pin
//! (`IntakeState::pin_honeybadger_committee`, reachable in production through
//! `GovernanceAction::PinExternalAnchor`), and
//! `FinalityGuarantee::for_external_spec_declared` maps the pinned committee to
//! deterministic-quorum finality.

use std::collections::BTreeSet;

use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::ctx::CROSS_DOMAIN_V1;
use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::primitives::PqKeyPair;
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier for leaderless asynchronous `HoneyBadgerBFT`.
pub const ADAPTER_NAME: &str = "honeybadger-bft-v1";
/// Adapter implementation version.
pub const ADAPTER_VERSION: u32 = 1;
/// Accepted wire evidence format version.
pub const EVIDENCE_VERSION: u32 = 1;
/// Minimum BFT committee cardinality (`3f + 1` for `f = 1`).
pub const MIN_HBBFT_VALIDATORS: usize = 4;
/// Maximum committee cardinality accepted in a single certificate.
pub const MAX_HBBFT_VALIDATORS: usize = 128;
/// Hard ceiling on serialized `HoneyBadgerEvidence` bytes (1.5 MiB).
pub const MAX_HBBFT_PAYLOAD_BYTES: usize = 1_536 * 1024;
/// Canonical FIPS 204 ML-DSA-65 public key length in bytes.
pub const ML_DSA_65_PUBKEY_LEN: usize = 1_952;
/// Canonical FIPS 204 ML-DSA-65 signature length in bytes.
pub const ML_DSA_65_SIG_LEN: usize = 3_309;

const PAYLOAD_MAGIC: &[u8; 8] = b"HBBFTV01";
const TAG_ACS_CERT: &[u8] = b"BDLM_HBBFT_ACS_CERT_V1";
const TAG_BATCH_ROOT: &[u8] = b"BDLM_HBBFT_BATCH_ROOT_V1";
const TAG_RBC_SHARE: &[u8] = b"BDLM_HBBFT_RBC_SHARE_V1";

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

/// Minimum asynchronous common-subset cardinality `N - floor((N - 1) / 3)` for
/// a committee of size `n >= 4` (for example `3` of `4`, `5` of `7`).
///
/// Convenience: exposed for external-domain registrars and light-client tools.
#[must_use]
pub const fn required_acs_count(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let max_byzantine = (n - 1) / 3;
    n - max_byzantine
}

/// One validator inside a governance-pinned `HoneyBadgerBFT` epoch committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoneyBadgerValidator {
    /// Unique, non-zero canonical validator identity digest.
    pub validator_id: Hash32,
    /// NIST FIPS 204 ML-DSA-65 verification key (`1,952` bytes).
    pub mldsa65_pubkey: Vec<u8>,
    /// Positive consensus voting weight.
    pub weight: u64,
}

/// Governance-pinned epoch committee for an external `HoneyBadgerBFT` network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedHoneyBadgerCommittee {
    /// External network identifier bound into every signed message.
    pub network_id: String,
    /// Non-zero genesis commitment separating sibling deployments.
    pub genesis_hash: Hash32,
    /// Active validator-set epoch number.
    pub committee_epoch: u64,
    /// Lowest ACS epoch height accepted under this committee.
    pub min_acs_epoch: u64,
    /// Ordered validator table (`4 <= len <= MAX_HBBFT_VALIDATORS`).
    pub validators: Vec<HoneyBadgerValidator>,
}

impl PinnedHoneyBadgerCommittee {
    /// Validates committee structure and returns total voting weight.
    ///
    /// Convenience: exposed for registration prechecks and equivocation handlers.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::ConsensusRule`] when any committee bound, key
    /// size, uniqueness, or non-zero invariant is violated.
    pub fn validate(&self) -> Result<u128, AdapterError> {
        if self.network_id.trim().is_empty() {
            return Err(AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT pinned network_id is empty".into(),
            });
        }
        if bool::from(self.genesis_hash.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT pinned genesis_hash is zero".into(),
            });
        }
        let count = self.validators.len();
        if !(MIN_HBBFT_VALIDATORS..=MAX_HBBFT_VALIDATORS).contains(&count) {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "HoneyBadgerBFT validator count {count} outside [{MIN_HBBFT_VALIDATORS}, {MAX_HBBFT_VALIDATORS}]"
                ),
            });
        }
        let mut seen_ids = BTreeSet::new();
        let mut seen_keys = BTreeSet::new();
        let mut total_weight = 0u128;
        for (idx, val) in self.validators.iter().enumerate() {
            if bool::from(val.validator_id.ct_eq(&[0u8; 32])) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("HoneyBadgerBFT validator {idx} has zero validator_id"),
                });
            }
            if !seen_ids.insert(val.validator_id) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("HoneyBadgerBFT duplicate validator_id at index {idx}"),
                });
            }
            if val.mldsa65_pubkey.len() != ML_DSA_65_PUBKEY_LEN {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "HoneyBadgerBFT validator {idx} ML-DSA-65 pubkey is {} bytes, expected {ML_DSA_65_PUBKEY_LEN}",
                        val.mldsa65_pubkey.len()
                    ),
                });
            }
            if val.mldsa65_pubkey.iter().fold(0u8, |acc, &b| acc | b) == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("HoneyBadgerBFT validator {idx} has all-zero ML-DSA-65 pubkey"),
                });
            }
            PqKeyPair::validate_public_key(&val.mldsa65_pubkey).map_err(|_| {
                AdapterError::ConsensusRule {
                    rule: format!("HoneyBadgerBFT validator {idx} invalid ML-DSA-65 pubkey"),
                }
            })?;
            if !seen_keys.insert(val.mldsa65_pubkey.as_slice()) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("HoneyBadgerBFT duplicate ML-DSA-65 pubkey at index {idx}"),
                });
            }
            if val.weight == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("HoneyBadgerBFT validator {idx} has zero voting weight"),
                });
            }
            total_weight = total_weight
                .checked_add(u128::from(val.weight))
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "HoneyBadgerBFT total validator weight overflow".into(),
                })?;
        }
        Ok(total_weight)
    }

    /// Computes a domain-separated, length-prefixed SHA3-256 commitment over
    /// every pinned committee field and validator key for cross-module guard
    /// and intake pin verification.
    ///
    /// WIRING: exposed for `BridgeEconomicGuard`, `IntakeState`, and sentry pin binding.
    #[must_use]
    pub fn canonical_pin_digest(&self) -> Hash32 {
        let committee_epoch = self.committee_epoch.to_le_bytes();
        let min_acs_epoch = self.min_acs_epoch.to_le_bytes();
        let mut validator_digests = Vec::with_capacity(self.validators.len());
        for val in &self.validators {
            let weight = val.weight.to_le_bytes();
            validator_digests.push(crate::core::hash::hash_fields_bytes(&[
                b"BDLM_HBBFT_PIN_DIGEST_V1",
                &val.validator_id,
                &weight,
                &val.mldsa65_pubkey,
            ]));
        }
        let mut fields: Vec<&[u8]> = Vec::with_capacity(5 + validator_digests.len());
        fields.push(b"BDLM_HBBFT_PIN_DIGEST_V1");
        fields.push(self.network_id.as_bytes());
        fields.push(&self.genesis_hash);
        fields.push(&committee_epoch);
        fields.push(&min_acs_epoch);
        for d in &validator_digests {
            fields.push(d);
        }
        crate::core::hash::hash_fields_bytes(&fields)
    }
}

/// One validator's decided Bracha RBC contribution inside an ACS epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RbcBatchContribution {
    /// Index of the proposing validator inside `PinnedHoneyBadgerCommittee::validators`.
    pub proposer_index: u16,
    /// Merkle root over the erasure-coded Bracha RBC shares delivered in `ABA = 1`.
    pub rbc_erasure_root: Hash32,
    /// Canonical transaction root decrypted from the threshold-encrypted batch.
    pub batch_tx_root: Hash32,
    /// Number of transactions carried by this contribution (`>= 1`).
    pub tx_count: u32,
}

/// One validator's ML-DSA-65 certification over the decided ACS output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcsValidatorVote {
    /// Index of the signing validator inside `PinnedHoneyBadgerCommittee::validators`.
    pub voter_index: u16,
    /// FIPS 204 ML-DSA-65 signature over [`acs_certificate_digest`].
    pub mldsa65_sig: Vec<u8>,
}

/// Wire payload carrying one finalized `HoneyBadgerBFT` ACS epoch certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoneyBadgerEvidence {
    /// Genesis hash of the source network.
    pub genesis_hash: Hash32,
    /// Validator-set epoch matching the pinned committee.
    pub committee_epoch: u64,
    /// Monotonic asynchronous common-subset epoch (also the finalized height).
    pub acs_epoch: u64,
    /// Deterministic commitment over all decided `ABA = 1` RBC contributions.
    pub acs_root: Hash32,
    /// Post-execution state root after applying the merged ACS batch.
    pub state_root: Hash32,
    /// Aggregate transaction root over all decided `ABA = 1` contributions.
    pub tx_root: Hash32,
    /// Canonical cross-domain event root (`None` when the epoch emits none).
    pub event_root: Option<Hash32>,
    /// Canonical epoch block hash committing `(acs_epoch, acs_root, state_root)`.
    pub block_hash: Hash32,
    /// Strictly ascending list of `>= N - f` decided RBC batch contributions.
    pub contributions: Vec<RbcBatchContribution>,
    /// Strictly ascending list of `>= N - f` ML-DSA-65 validator certifications.
    pub votes: Vec<AcsValidatorVote>,
}

/// Derives `(acs_root, tx_root)` from strictly ordered `contributions`.
///
/// Convenience: exposed for relayers assembling `HoneyBadgerEvidence` bundles.
#[must_use]
pub fn derive_acs_roots(
    genesis_hash: &Hash32,
    committee_epoch: u64,
    acs_epoch: u64,
    contributions: &[RbcBatchContribution],
) -> (Hash32, Hash32) {
    let count = u64::try_from(contributions.len()).unwrap_or(u64::MAX);
    let mut acs_h = Sha256::new();
    acs_h.update(TAG_BATCH_ROOT);
    acs_h.update([0x01]);
    acs_h.update(genesis_hash);
    acs_h.update(committee_epoch.to_le_bytes());
    acs_h.update(acs_epoch.to_le_bytes());
    acs_h.update(count.to_le_bytes());

    let mut tx_h = Sha256::new();
    tx_h.update(TAG_BATCH_ROOT);
    tx_h.update([0x02]);
    tx_h.update(genesis_hash);
    tx_h.update(committee_epoch.to_le_bytes());
    tx_h.update(acs_epoch.to_le_bytes());
    tx_h.update(count.to_le_bytes());

    for item in contributions {
        acs_h.update(item.proposer_index.to_le_bytes());
        update_len_prefixed(&mut acs_h, &item.rbc_erasure_root);
        update_len_prefixed(&mut acs_h, &item.batch_tx_root);
        acs_h.update(item.tx_count.to_le_bytes());

        tx_h.update(item.proposer_index.to_le_bytes());
        update_len_prefixed(&mut tx_h, &item.batch_tx_root);
        tx_h.update(item.tx_count.to_le_bytes());
    }
    (acs_h.finalize().into(), tx_h.finalize().into())
}

/// Canonical domain-separated signing digest for an ACS finality certificate.
///
/// Convenience: exposed for external relayers and test fixture builders.
#[must_use]
pub fn acs_certificate_digest(network_id: &str, ev: &HoneyBadgerEvidence) -> Hash32 {
    let mut h = Sha256::new();
    h.update(TAG_ACS_CERT);
    update_len_prefixed(&mut h, network_id.as_bytes());
    h.update(ev.genesis_hash);
    h.update(ev.committee_epoch.to_le_bytes());
    h.update(ev.acs_epoch.to_le_bytes());
    update_len_prefixed(&mut h, &ev.acs_root);
    update_len_prefixed(&mut h, &ev.state_root);
    update_len_prefixed(&mut h, &ev.tx_root);
    match ev.event_root {
        Some(er) => {
            h.update([1u8]);
            update_len_prefixed(&mut h, &er);
        }
        None => h.update([0u8]),
    }
    update_len_prefixed(&mut h, &ev.block_hash);
    let contrib_len = u64::try_from(ev.contributions.len()).unwrap_or(u64::MAX);
    h.update(contrib_len.to_le_bytes());
    for item in &ev.contributions {
        h.update(item.proposer_index.to_le_bytes());
    }
    h.finalize().into()
}

/// Canonical domain-separated signing digest for one validator's Bracha RBC
/// `VAL`/`ECHO` erasure-tree root announcement.
///
/// Convenience: exposed for slashable RBC equivocation verification.
#[must_use]
pub fn rbc_root_announcement_digest(
    network_id: &str,
    genesis_hash: &Hash32,
    committee_epoch: u64,
    acs_epoch: u64,
    proposer_index: u16,
    rbc_erasure_root: &Hash32,
) -> Hash32 {
    let mut h = Sha256::new();
    h.update(TAG_RBC_SHARE);
    update_len_prefixed(&mut h, network_id.as_bytes());
    h.update(genesis_hash);
    h.update(committee_epoch.to_le_bytes());
    h.update(acs_epoch.to_le_bytes());
    h.update(proposer_index.to_le_bytes());
    h.update(rbc_erasure_root);
    h.finalize().into()
}

/// Cryptographic proof that one validator signed two conflicting Bracha RBC
/// erasure roots in the same `(committee_epoch, acs_epoch)` instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RbcEquivocationProof {
    /// Genesis commitment of the target network.
    pub genesis_hash: Hash32,
    /// Committee epoch in which the double-broadcast occurred.
    pub committee_epoch: u64,
    /// Asynchronous common-subset epoch of the double-broadcast.
    pub acs_epoch: u64,
    /// Equivocating proposer slot inside the pinned committee.
    pub proposer_index: u16,
    /// First signed Bracha RBC erasure root.
    pub first_root: Hash32,
    /// ML-DSA-65 signature over `first_root`.
    pub first_sig: Vec<u8>,
    /// Conflicting second signed Bracha RBC erasure root.
    pub second_root: Hash32,
    /// ML-DSA-65 signature over `second_root`.
    pub second_sig: Vec<u8>,
}

/// Verifies a slashable Bracha RBC double-root equivocation proof and returns
/// the offending validator's `(validator_id, weight)`.
///
/// Convenience: exposed for shared-security slashing and domain fault handlers.
///
/// # Errors
///
/// Returns [`AdapterError`] if the committee is invalid, the epoch or genesis
/// disagrees, the two roots are equal or zero, or either ML-DSA-65 signature fails.
pub fn verify_rbc_equivocation(
    pinned: &PinnedHoneyBadgerCommittee,
    proof: &RbcEquivocationProof,
) -> Result<(Hash32, u64), AdapterError> {
    let _total = pinned.validate()?;
    if !bool::from(proof.genesis_hash.ct_eq(&pinned.genesis_hash)) {
        return Err(AdapterError::ConsensusRule {
            rule: "HoneyBadgerBFT equivocation genesis_hash mismatches pinned committee".into(),
        });
    }
    if proof.committee_epoch != pinned.committee_epoch {
        return Err(AdapterError::ConsensusRule {
            rule: "HoneyBadgerBFT equivocation committee_epoch mismatches pinned committee".into(),
        });
    }
    if bool::from(proof.first_root.ct_eq(&[0u8; 32]))
        || bool::from(proof.second_root.ct_eq(&[0u8; 32]))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "HoneyBadgerBFT equivocation cannot cite an all-zero RBC root".into(),
        });
    }
    if bool::from(proof.first_root.ct_eq(&proof.second_root)) {
        return Err(AdapterError::ConsensusRule {
            rule: "HoneyBadgerBFT equivocation roots are identical".into(),
        });
    }
    let idx = usize::from(proof.proposer_index);
    let Some(val) = pinned.validators.get(idx) else {
        return Err(AdapterError::ConsensusRule {
            rule: format!("HoneyBadgerBFT proposer_index {idx} out of committee range"),
        });
    };
    if proof.first_sig.len() != ML_DSA_65_SIG_LEN || proof.second_sig.len() != ML_DSA_65_SIG_LEN {
        return Err(AdapterError::Crypto {
            what: "HoneyBadgerBFT equivocation signature length invalid".into(),
        });
    }
    let msg_a = rbc_root_announcement_digest(
        &pinned.network_id,
        &proof.genesis_hash,
        proof.committee_epoch,
        proof.acs_epoch,
        proof.proposer_index,
        &proof.first_root,
    );
    let msg_b = rbc_root_announcement_digest(
        &pinned.network_id,
        &proof.genesis_hash,
        proof.committee_epoch,
        proof.acs_epoch,
        proof.proposer_index,
        &proof.second_root,
    );
    PqKeyPair::verify(
        &val.mldsa65_pubkey,
        CROSS_DOMAIN_V1,
        &msg_a,
        &proof.first_sig,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "invalid first ML-DSA-65 signature in HoneyBadgerBFT RBC equivocation".into(),
    })?;
    PqKeyPair::verify(
        &val.mldsa65_pubkey,
        CROSS_DOMAIN_V1,
        &msg_b,
        &proof.second_sig,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "invalid second ML-DSA-65 signature in HoneyBadgerBFT RBC equivocation".into(),
    })?;
    Ok((val.validator_id, val.weight))
}

/// Encodes `HoneyBadgerEvidence` with its canonical `HBBFTV01` wire prefix.
///
/// Convenience: exposed for external relayers and admission golden builders.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] when serialization fails or exceeds
/// [`MAX_HBBFT_PAYLOAD_BYTES`].
pub fn encode_honeybadger_evidence(ev: &HoneyBadgerEvidence) -> Result<Vec<u8>, AdapterError> {
    let body = bincode::options()
        .with_fixint_encoding()
        .serialize(ev)
        .map_err(|e| AdapterError::Malformed {
            offset: 0,
            reason: format!("HoneyBadgerBFT encode failed: {e}"),
        })?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_HBBFT_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: total,
            reason: format!(
                "HoneyBadgerBFT payload is {total} bytes, above {MAX_HBBFT_PAYLOAD_BYTES}"
            ),
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decodes a canonical `HBBFTV01`-framed `HoneyBadgerEvidence` payload.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] on size overflow, wrong magic, or
/// malformed/trailing bincode bytes.
pub fn decode_honeybadger_evidence(payload: &[u8]) -> Result<HoneyBadgerEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "HoneyBadgerBFT payload shorter than 8-byte magic header".into(),
        });
    }
    if payload.len() > MAX_HBBFT_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: payload.len(),
            reason: format!(
                "HoneyBadgerBFT payload is {} bytes, above {MAX_HBBFT_PAYLOAD_BYTES}",
                payload.len()
            ),
        });
    }
    let Some(body) = payload.strip_prefix(PAYLOAD_MAGIC) else {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "HoneyBadgerBFT payload magic mismatch".into(),
        });
    };
    let limit = u64::try_from(body.len()).unwrap_or(MAX_HBBFT_PAYLOAD_BYTES as u64);
    bincode::options()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
        .deserialize(body)
        .map_err(|e| AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: format!("HoneyBadgerBFT payload decode failed: {e}"),
        })
}

/// External finality adapter for leaderless asynchronous `HoneyBadgerBFT`.
pub struct HoneyBadgerBftAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    pinned: Option<PinnedHoneyBadgerCommittee>,
    golden: Option<RawConsensusEvidence>,
}

impl HoneyBadgerBftAdapter {
    /// Constructs a `HoneyBadgerBFT` adapter for `network` pinned to `pinned`.
    /// Passing `None` keeps admission closed until governance pins a committee.
    ///
    /// Convenience: exposed for external-domain registration and verification.
    #[must_use]
    pub fn new(network: &str, pinned: Option<PinnedHoneyBadgerCommittee>) -> Self {
        let set_size = pinned
            .as_ref()
            .and_then(|c| u64::try_from(c.validators.len()).ok())
            .unwrap_or(0);
        Self {
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(ADAPTER_NAME),
                name: ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "asynchronous-common-subset-bft".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                required_depth: 1,
                time_unit: TimeUnit::Epoch,
                trust_model: TrustModel::HonestMajority { set_size },
            },
            network: network.to_string(),
            pinned,
            golden: None,
        }
    }

    /// Attaches a golden evidence sample for [`super::selftest::admit_observed`].
    ///
    /// Convenience: exposed for self-test admission harnesses.
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }
}

impl ExternalFinalityAdapter for HoneyBadgerBftAdapter {
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
        let mut sink = crate::crypto::facts::NullObserver;
        self.verify_observed(evidence, policy, &mut sink)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::WrongAdapter {
                expected: self.descriptor.name.clone(),
                found: "foreign-adapter".to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::WrongAdapter {
                expected: self.network.clone(),
                found: evidence.network.clone(),
            });
        }
        if evidence.evidence_version != EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: EVIDENCE_VERSION.to_string(),
            });
        }

        let ev = decode_honeybadger_evidence(&evidence.payload)?;

        if policy.require_declared_match {
            if evidence.declared_height != ev.acs_epoch {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&ev.state_root)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }
        // Instant single-epoch protocol finality delivers depth 1.
        if policy.min_depth > 1 {
            return Err(AdapterError::InsufficientDepth {
                observed: 1,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 {
            if ev.acs_epoch > policy.now {
                return Err(AdapterError::Stale {
                    age: ev.acs_epoch - policy.now,
                    max_age: policy.max_age,
                });
            }
            let age = policy.now - ev.acs_epoch;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let Some(pinned) = self.pinned.as_ref() else {
            return Err(AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT committee is not pinned; admission is closed".into(),
            });
        };
        let total_weight = pinned.validate()?;
        if pinned.network_id != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT pinned network_id mismatches adapter network".into(),
            });
        }
        if !bool::from(ev.genesis_hash.ct_eq(&pinned.genesis_hash)) {
            return Err(AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT evidence genesis_hash mismatches pinned committee".into(),
            });
        }
        if ev.committee_epoch != pinned.committee_epoch {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "HoneyBadgerBFT committee_epoch {} mismatches pinned {}",
                    ev.committee_epoch, pinned.committee_epoch
                ),
            });
        }
        if ev.acs_epoch < pinned.min_acs_epoch {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "HoneyBadgerBFT acs_epoch {} below pinned floor {}",
                    ev.acs_epoch, pinned.min_acs_epoch
                ),
            });
        }
        if bool::from(ev.state_root.ct_eq(&[0u8; 32]))
            || bool::from(ev.block_hash.ct_eq(&[0u8; 32]))
            || bool::from(ev.acs_root.ct_eq(&[0u8; 32]))
            || bool::from(ev.tx_root.ct_eq(&[0u8; 32]))
        {
            return Err(AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT committed roots and block_hash must be non-zero".into(),
            });
        }
        if let Some(er) = ev.event_root.as_ref() {
            if bool::from(er.ct_eq(&[0u8; 32])) {
                return Err(AdapterError::ConsensusRule {
                    rule: "HoneyBadgerBFT optional event_root cannot be Some(zero)".into(),
                });
            }
        }

        let n = pinned.validators.len();
        let min_subset = required_acs_count(n);
        if ev.contributions.len() < min_subset || ev.contributions.len() > n {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "HoneyBadgerBFT ACS subset size {} outside [{min_subset}, {n}]",
                    ev.contributions.len()
                ),
            });
        }
        let mut prev_proposer: Option<u16> = None;
        for c in &ev.contributions {
            if let Some(prev) = prev_proposer {
                if c.proposer_index <= prev {
                    return Err(AdapterError::ConsensusRule {
                        rule: "HoneyBadgerBFT contributions must be strictly ascending by proposer_index"
                            .into(),
                    });
                }
            }
            if usize::from(c.proposer_index) >= n {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "HoneyBadgerBFT proposer_index {} out of bounds for committee size {n}",
                        c.proposer_index
                    ),
                });
            }
            if bool::from(c.rbc_erasure_root.ct_eq(&[0u8; 32]))
                || bool::from(c.batch_tx_root.ct_eq(&[0u8; 32]))
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "HoneyBadgerBFT contribution carries an all-zero RBC or batch tx root"
                        .into(),
                });
            }
            if c.tx_count == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "HoneyBadgerBFT contribution must carry at least one transaction".into(),
                });
            }
            prev_proposer = Some(c.proposer_index);
        }

        let (derived_acs, derived_tx) = derive_acs_roots(
            &ev.genesis_hash,
            ev.committee_epoch,
            ev.acs_epoch,
            &ev.contributions,
        );
        if !bool::from(derived_acs.ct_eq(&ev.acs_root)) {
            return Err(AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT derived ACS root mismatches declared acs_root".into(),
            });
        }
        if !bool::from(derived_tx.ct_eq(&ev.tx_root)) {
            return Err(AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT derived tx_root mismatches declared tx_root".into(),
            });
        }

        if ev.votes.len() < min_subset || ev.votes.len() > n {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "HoneyBadgerBFT vote count {} outside [{min_subset}, {n}]",
                    ev.votes.len()
                ),
            });
        }
        let cert_digest = acs_certificate_digest(&self.network, &ev);
        let mut prev_voter: Option<u16> = None;
        let mut signed_weight = 0u128;
        for vote in &ev.votes {
            if let Some(prev) = prev_voter {
                if vote.voter_index <= prev {
                    return Err(AdapterError::ConsensusRule {
                        rule: "HoneyBadgerBFT votes must be strictly ascending by voter_index"
                            .into(),
                    });
                }
            }
            let idx = usize::from(vote.voter_index);
            let Some(val) = pinned.validators.get(idx) else {
                return Err(AdapterError::ConsensusRule {
                    rule: format!("HoneyBadgerBFT voter_index {idx} out of committee bounds"),
                });
            };
            if vote.mldsa65_sig.len() != ML_DSA_65_SIG_LEN {
                return Err(AdapterError::Crypto {
                    what: format!(
                        "HoneyBadgerBFT voter {idx} ML-DSA-65 signature is {} bytes, expected {ML_DSA_65_SIG_LEN}",
                        vote.mldsa65_sig.len()
                    ),
                });
            }
            PqKeyPair::verify(
                &val.mldsa65_pubkey,
                CROSS_DOMAIN_V1,
                &cert_digest,
                &vote.mldsa65_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: format!("HoneyBadgerBFT invalid ML-DSA-65 signature from voter index {idx}"),
            })?;
            signed_weight = signed_weight
                .checked_add(u128::from(val.weight))
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "HoneyBadgerBFT signed weight overflow".into(),
                })?;
            prev_voter = Some(vote.voter_index);
        }

        // Strict > 2/3 stake supermajority: signed_weight * 3 > total_weight * 2.
        let lhs = signed_weight
            .checked_mul(3)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT quorum multiplication overflow".into(),
            })?;
        let rhs = total_weight
            .checked_mul(2)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "HoneyBadgerBFT total-weight multiplication overflow".into(),
            })?;
        if lhs <= rhs {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "HoneyBadgerBFT signed weight {signed_weight}/{total_weight} does not exceed 2/3"
                ),
            });
        }

        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }

        // Record only pure post-quantum ML-DSA-65 after every check succeeds.
        for _ in 0..ev.votes.len() {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        }

        let signers = u64::try_from(ev.votes.len()).unwrap_or(u64::MAX);
        let required = u64::try_from(min_subset).unwrap_or(u64::MAX);
        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: ev.acs_epoch,
            state_root: ev.state_root,
            finalized_at: ev.acs_epoch,
            time_unit: TimeUnit::Epoch,
            security: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers,
                required,
                total_weight,
                // External HoneyBadgerBFT committees have no local Budlum
                // confiscation bond or BridgeEconomicGuard arm yet.
                slashable: false,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(ev.block_hash),
            attested_event_root: ev.event_root,
            attested_tx_root: Some(ev.tx_root),
        })
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        // Fixed byte offsets inside HBBFTV01 + fixint bincode:
        // [0..8]   = magic "HBBFTV01"
        // [8..40]  = genesis_hash
        // [40..48] = committee_epoch
        // [48..56] = acs_epoch
        // [56..88] = acs_root
        let sig_tail_offset = self
            .golden
            .as_ref()
            .map_or(96, |g| g.payload.len().saturating_sub(32));
        vec![
            FaultProbe {
                name: "empty payload refused as malformed".into(),
                patch: BytePatch::TruncatePayload { keep: 0 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "corrupt framing magic refused before decode".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"BADMAGIC".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "forged genesis hash refused by pinned committee".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xA5; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "tampered ACS root refused against recomputed RBC subset".into(),
                patch: BytePatch::InPayload {
                    offset: 56,
                    bytes: vec![0x5A; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "corrupted ML-DSA-65 certification signature refused".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail_offset,
                    bytes: vec![0xFF; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "lying declared height refused".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "lying declared state root refused".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "unsupported evidence version and foreign network refused".into(),
                patch: BytePatch::EvidenceVersion { value: 99 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
        ]
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::admit_observed;
    use crate::crypto::facts::{CryptoFacts, QuantumClass};

    /// The fixture committee's network name, shared with `intake.rs`'s tests.
    pub(crate) const FIXTURE_NETWORK: &str = "hbbft-testnet";

    pub(crate) fn fixture() -> (
        Vec<PqKeyPair>,
        PinnedHoneyBadgerCommittee,
        HoneyBadgerEvidence,
        RawConsensusEvidence,
    ) {
        let keys: Vec<PqKeyPair> = (0u8..4)
            .map(|i| {
                let mut seed = [0x31u8; 32];
                seed[0] = i.wrapping_add(1);
                seed[31] = i.wrapping_mul(17).wrapping_add(9);
                let pk = crate::crypto::pq::ml_dsa_public_key(SchemeId::ML_DSA_65, &seed)
                    .expect("derives ML-DSA-65 pubkey");
                PqKeyPair::from_bytes(&pk, &seed).expect("deterministic ML-DSA-65 keypair")
            })
            .collect();
        let validators: Vec<HoneyBadgerValidator> = keys
            .iter()
            .enumerate()
            .map(|(i, kp)| {
                let id_byte = u8::try_from(i + 1).expect("fits u8");
                HoneyBadgerValidator {
                    validator_id: [id_byte; 32],
                    mldsa65_pubkey: kp.public_key_bytes().to_vec(),
                    weight: 25,
                }
            })
            .collect();
        let genesis = [0x42; 32];
        let pinned = PinnedHoneyBadgerCommittee {
            network_id: "hbbft-testnet".to_string(),
            genesis_hash: genesis,
            committee_epoch: 3,
            min_acs_epoch: 10,
            validators,
        };
        // N = 4, f = 1 -> N - f = 3 contributions delivered in the common subset.
        let contributions = vec![
            RbcBatchContribution {
                proposer_index: 0,
                rbc_erasure_root: [0x11; 32],
                batch_tx_root: [0x21; 32],
                tx_count: 14,
            },
            RbcBatchContribution {
                proposer_index: 2,
                rbc_erasure_root: [0x12; 32],
                batch_tx_root: [0x22; 32],
                tx_count: 9,
            },
            RbcBatchContribution {
                proposer_index: 3,
                rbc_erasure_root: [0x13; 32],
                batch_tx_root: [0x23; 32],
                tx_count: 27,
            },
        ];
        let (acs_root, tx_root) = derive_acs_roots(&genesis, 3, 12, &contributions);
        let state_root = [0x77; 32];
        let block_hash = [0x88; 32];
        let mut ev = HoneyBadgerEvidence {
            genesis_hash: genesis,
            committee_epoch: 3,
            acs_epoch: 12,
            acs_root,
            state_root,
            tx_root,
            event_root: Some([0x99; 32]),
            block_hash,
            contributions,
            votes: Vec::new(),
        };
        let digest = acs_certificate_digest("hbbft-testnet", &ev);
        for idx in [0u16, 1, 3] {
            let sig = keys[usize::from(idx)]
                .sign(CROSS_DOMAIN_V1, &digest)
                .expect("signs");
            ev.votes.push(AcsValidatorVote {
                voter_index: idx,
                mldsa65_sig: sig,
            });
        }
        let payload = encode_honeybadger_evidence(&ev).expect("encodes");
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: "hbbft-testnet".to_string(),
            payload,
            declared_height: 12,
            declared_root: state_root,
            submitter: Address([0xAA; 32]),
        };
        (keys, pinned, ev, raw)
    }

    #[test]
    fn honeybadger_passes_selftest_admission_and_observes_pure_lattice_crypto() {
        let (_keys, pinned, ev, raw) = fixture();
        let adapter = HoneyBadgerBftAdapter::new("hbbft-testnet", Some(pinned)).with_golden(raw);
        let mut policy = VerificationPolicy::strict(15);
        policy.require_slashable = false;
        policy.max_age = 10;

        let (report, facts) = admit_observed(&adapter, &policy);
        assert!(report.admitted, "admission must pass: {report:#?}");
        assert_eq!(report.passed(), 8);
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Lattice));
        assert_eq!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)), 3);

        let mut verify_facts = CryptoFacts::new();
        let att = adapter
            .verify_observed(
                &adapter.golden_evidence().expect("golden"),
                &policy,
                &mut verify_facts,
            )
            .expect("verifies");
        crate::domain::finality_proof_model::FinalityProofShape::from_external_attestation(
            &adapter.descriptor(),
            &att,
        )
        .expect("HoneyBadger BFT shape");
        assert_eq!(att.height, 12);
        assert_eq!(att.state_root, ev.state_root);
        assert_eq!(att.attested_block_hash, Some(ev.block_hash));
        assert_eq!(att.attested_tx_root, Some(ev.tx_root));
        assert_eq!(att.attested_event_root, ev.event_root);
    }

    #[test]
    fn honeybadger_rejects_undersized_subset_duplicate_signer_and_trailing_bytes() {
        let (keys, pinned, mut ev, mut raw) = fixture();
        let adapter = HoneyBadgerBftAdapter::new("hbbft-testnet", Some(pinned));
        let policy = VerificationPolicy::strict(12);

        // Trailing byte malleability must be rejected at decode.
        raw.payload.push(0x00);
        assert!(matches!(
            adapter.verify(&raw, &policy),
            Err(AdapterError::Malformed { .. })
        ));

        // Fewer than N - f = 3 ACS contributions cannot finalize even if 3 signers sign it.
        ev.contributions.pop();
        let (short_acs, short_tx) = derive_acs_roots(&ev.genesis_hash, 3, 12, &ev.contributions);
        ev.acs_root = short_acs;
        ev.tx_root = short_tx;
        let d = acs_certificate_digest("hbbft-testnet", &ev);
        ev.votes = [0u16, 1, 2]
            .into_iter()
            .map(|i| AcsValidatorVote {
                voter_index: i,
                mldsa65_sig: keys[usize::from(i)]
                    .sign(CROSS_DOMAIN_V1, &d)
                    .expect("signs"),
            })
            .collect();
        raw.payload = encode_honeybadger_evidence(&ev).expect("encodes");
        assert!(matches!(
            adapter.verify(&raw, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // Duplicate voter slot cannot manufacture 3-of-4 threshold.
        let (keys, pinned, mut ev2, mut raw2) = fixture();
        let adapter2 = HoneyBadgerBftAdapter::new("hbbft-testnet", Some(pinned));
        let d2 = acs_certificate_digest("hbbft-testnet", &ev2);
        let dup_sig = keys[1].sign(CROSS_DOMAIN_V1, &d2).expect("signs");
        ev2.votes = vec![
            ev2.votes[0].clone(),
            AcsValidatorVote {
                voter_index: 1,
                mldsa65_sig: dup_sig.clone(),
            },
            AcsValidatorVote {
                voter_index: 1,
                mldsa65_sig: dup_sig,
            },
        ];
        raw2.payload = encode_honeybadger_evidence(&ev2).expect("encodes");
        assert!(matches!(
            adapter2.verify(&raw2, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // Regression 1: All-zero 1952-byte ML-DSA-65 public key must be rejected by
        // PinnedHoneyBadgerCommittee::validate.
        let (_keys3, mut zero_pk_committee, _ev3, _raw3) = fixture();
        zero_pk_committee.validators[0].mldsa65_pubkey = vec![0x00; ML_DSA_65_PUBKEY_LEN];
        assert!(
            zero_pk_committee.validate().is_err(),
            "all-zero 1952-byte ML-DSA-65 pubkey must be rejected by committee validation"
        );

        // Regression 2: Future acs_epoch > policy.now (e.g. u64::MAX height-exhaustion attack)
        // when policy.max_age > 0 must NOT bypass freshness via saturating_sub(u64::MAX) == 0.
        let (keys4, pinned4, mut future_ev, mut future_raw) = fixture();
        future_ev.acs_epoch = u64::MAX;
        let (f_acs, f_tx) = derive_acs_roots(
            &future_ev.genesis_hash,
            future_ev.committee_epoch,
            future_ev.acs_epoch,
            &future_ev.contributions,
        );
        future_ev.acs_root = f_acs;
        future_ev.tx_root = f_tx;
        let fd = acs_certificate_digest("hbbft-testnet", &future_ev);
        future_ev.votes = [0u16, 1, 3]
            .into_iter()
            .map(|i| AcsValidatorVote {
                voter_index: i,
                mldsa65_sig: keys4[usize::from(i)]
                    .sign(CROSS_DOMAIN_V1, &fd)
                    .expect("signs"),
            })
            .collect();
        future_raw.declared_height = u64::MAX;
        future_raw.payload = encode_honeybadger_evidence(&future_ev).expect("encodes");
        let adapter4 = HoneyBadgerBftAdapter::new("hbbft-testnet", Some(pinned4));
        let mut bounded_policy = VerificationPolicy::strict(15);
        bounded_policy.require_slashable = false;
        bounded_policy.max_age = 10;
        assert!(
            matches!(
                adapter4.verify(&future_raw, &bounded_policy),
                Err(AdapterError::Stale { .. })
            ),
            "future acs_epoch = u64::MAX must not bypass max_age via saturating_sub underflow"
        );
    }

    #[test]
    fn honeybadger_verifies_slashable_rbc_equivocation_and_rejects_identical_roots() {
        let (keys, pinned, _ev, _raw) = fixture();
        let root_a = [0xC1; 32];
        let root_b = [0xC2; 32];
        let msg_a = rbc_root_announcement_digest(
            &pinned.network_id,
            &pinned.genesis_hash,
            3,
            12,
            2,
            &root_a,
        );
        let msg_b = rbc_root_announcement_digest(
            &pinned.network_id,
            &pinned.genesis_hash,
            3,
            12,
            2,
            &root_b,
        );
        let proof = RbcEquivocationProof {
            genesis_hash: pinned.genesis_hash,
            committee_epoch: 3,
            acs_epoch: 12,
            proposer_index: 2,
            first_root: root_a,
            first_sig: keys[2].sign(CROSS_DOMAIN_V1, &msg_a).expect("signs"),
            second_root: root_b,
            second_sig: keys[2].sign(CROSS_DOMAIN_V1, &msg_b).expect("signs"),
        };
        let (offender, weight) = verify_rbc_equivocation(&pinned, &proof).expect("equivocation");
        assert_eq!(offender, [3u8; 32]);
        assert_eq!(weight, 25);

        // Identical roots must never slash an honest rebroadcast.
        let mut same = proof.clone();
        same.second_root = root_a;
        same.second_sig = same.first_sig.clone();
        assert!(verify_rbc_equivocation(&pinned, &same).is_err());

        // Signature from another validator must be rejected.
        let mut forged = proof;
        forged.second_sig = keys[0].sign(CROSS_DOMAIN_V1, &msg_b).expect("signs");
        assert!(verify_rbc_equivocation(&pinned, &forged).is_err());

        let (_keys2, pinned2, _ev2, raw2) = fixture();
        let adapter2 = HoneyBadgerBftAdapter::new("hbbft-testnet", Some(pinned2));
        let mut unbonded_policy = VerificationPolicy::strict(15);
        unbonded_policy.max_age = 10;
        let att = adapter2
            .verify(&raw2, &unbonded_policy)
            .expect("valid HoneyBadgerBFT evidence verifies when slashability is not required");
        assert!(
            matches!(
                att.security,
                SecurityBacking::SignatureSet {
                    slashable: false,
                    ..
                }
            ),
            "bare HoneyBadgerBFT committee without a local Budlum confiscation arm must report slashable=false"
        );
        let mut slash_policy = unbonded_policy;
        slash_policy.require_slashable = true;
        assert!(
            matches!(
                adapter2.verify(&raw2, &slash_policy),
                Err(AdapterError::UnslashableBacking)
            ),
            "require_slashable=true must fail closed with UnslashableBacking"
        );
    }
}
