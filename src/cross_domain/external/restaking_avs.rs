//! Dual-quorum restaking AVS and extractable one-time signature (`EOTS`)
//! external finality adapter with shared-consumer over-leverage haircut and
//! dual slashing verification.
//!
//! Under EigenLayer-class actively validated services (`AVS`, 2023) combined
//! with Babylon-class Bitcoin finality staking (`EOTS`, 2024), an external
//! domain imports economic security from restaked collateral while enforcing
//! a two-quorum safety rule so neither the native validator set nor the
//! restaked operator set can finalize a state transition alone:
//!
//! 1. **Self-derived finality batch & unbonding horizon**: `batch.digest`
//!    matches the length-prefixed hash of `(network, epoch, height,
//!    timestamp_secs, unbonding_horizon_height, state_root, tx_root,
//!    event_root, eots_rand_root)`, and `unbonding_horizon_height >=
//!    height + pinned.min_withdrawal_delay` so operators remain slashable
//!    throughout the settlement challenge window.
//! 2. **Independent native quorum (`> 2/3`)**: distinct pinned native
//!    validators with combined stake strictly exceeding `2/3` of total native
//!    stake certify `batch.digest`.
//! 3. **Independent restaked AVS quorum (`> 2/3`) with over-leverage haircut**:
//!    each restaked operator carries `raw_stake` and declared/observed
//!    `shared_avs_count` (`>= 1`); its effective slashable weight is
//!    `raw_stake / shared_avs_count` (rejected when `shared_avs_count` exceeds
//!    `pinned.max_shared_avs_per_operator`). Distinct restaked operators must
//!    exceed `2/3` of total effective restaked stake, and aggregate signed
//!    effective restaked stake must meet `pinned.min_effective_restaked_stake`.
//! 4. **Optional/mandatory EOTS finality quorum (`> 2/3`)**: when the pinned
//!    configuration includes `eots_providers`, distinct finality providers
//!    exceeding `2/3` of total EOTS stake must sign the randomness-committed
//!    finality digest binding `(epoch, height, eots_rand_root, batch.digest)`.
//! 5. **Hybrid post-quantum non-downgrade**: every signer in any quorum with a
//!    non-empty ML-DSA-65 public key MUST attach a valid ML-DSA-65 signature
//!    under [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
//! 6. **Dual slashing verification ([`verify_restaking_slashing`])**: proves
//!    either restaked-quorum double-attestation at the same `(epoch, height)`
//!    or EOTS finality double-signing under the same `(epoch, height)` across
//!    two distinct finality targets, returning verified offending operators
//!    and their exact haircut-adjusted slashable weight.
//!
//! WIRING: implements [`ExternalFinalityAdapter`] and is invoked in production
//! by [`crate::cross_domain::economic_guard`] for external attestation ceiling
//! derivation and contradiction-driven bond slashing.

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

const ADAPTER_NAME: &str = "restaking-avs-v1";
const ADAPTER_VERSION: u32 = 1;
const EVIDENCE_VERSION: u32 = 1;
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMAVS1";
const MAX_AVS_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_AVS_QUORUM_MEMBERS: usize = 1_024;
const MAX_SHARED_AVS_LIMIT: u32 = 64;

/// One member of the native validator quorum or EOTS finality-provider quorum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvsQuorumMember {
    /// Classical Ed25519 verifying key (32 bytes, non-zero).
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero bonded stake weight in atomic units.
    pub stake_weight: u64,
    /// Optional ML-DSA-65 public key; when non-empty, every signature by this
    /// member MUST carry a valid ML-DSA-65 co-signature.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// One restaked AVS operator subject to shared-consumer over-leverage haircut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestakedOperator {
    /// Classical Ed25519 verifying key (32 bytes, non-zero).
    pub ed25519_pubkey: [u8; 32],
    /// Gross slashable restaked collateral in atomic units (must be positive).
    pub raw_stake: u64,
    /// Number of concurrent AVS consumers sharing this collateral (`>= 1`).
    pub shared_avs_count: u32,
    /// Optional ML-DSA-65 public key for mandatory hybrid PQ co-signing.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

impl RestakedOperator {
    /// Effective uniquely attributable slashable weight after shared-consumer
    /// haircut (`floor(raw_stake / shared_avs_count)`). Returns `0` when
    /// `shared_avs_count == 0`.
    ///
    /// WIRING: consumed by [`RestakingAvsAdapter`] quorum and slashing checks.
    #[must_use]
    pub const fn haircut_stake(&self) -> u64 {
        if self.shared_avs_count == 0 {
            0
        } else {
            self.raw_stake / (self.shared_avs_count as u64)
        }
    }
}

/// Governance-pinned dual-quorum + EOTS committee for a restaking AVS domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedRestakingAvsSet {
    /// Active staking epoch served by these quorums.
    pub epoch: u64,
    /// Minimum blocks past `height` during which restaked collateral must
    /// remain locked against withdrawal (`>= 1`).
    pub min_withdrawal_delay: u64,
    /// Maximum concurrent AVS count tolerated per operator (`1..=64`).
    pub max_shared_avs_per_operator: u32,
    /// Minimum aggregate haircut-adjusted restaked stake that must sign each
    /// batch (`>= 1`).
    pub min_effective_restaked_stake: u128,
    /// Native domain validator quorum.
    pub native_validators: Vec<AvsQuorumMember>,
    /// Restaked AVS operator quorum.
    pub restaked_operators: Vec<RestakedOperator>,
    /// Optional Babylon-class EOTS finality providers. When non-empty, a
    /// third `> 2/3` EOTS finality quorum is mandatory on every batch.
    #[serde(default)]
    pub eots_providers: Vec<AvsQuorumMember>,
}

impl PinnedRestakingAvsSet {
    /// Canonical length-prefixed SHA3-256 commitment over every pinned quorum
    /// parameter, validator key, operator haircut, and EOTS finality provider.
    ///
    /// WIRING: checked in constant time by `crate::cross_domain::economic_guard`
    /// on both backing refreshes and contradiction submissions.
    #[must_use]
    pub fn canonical_pin_digest(&self) -> Hash32 {
        let mut acc = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_AVS_PIN_V1",
            &self.epoch.to_le_bytes(),
            &self.min_withdrawal_delay.to_le_bytes(),
            &self.max_shared_avs_per_operator.to_le_bytes(),
            &self.min_effective_restaked_stake.to_le_bytes(),
            &(self.native_validators.len() as u64).to_le_bytes(),
            &(self.restaked_operators.len() as u64).to_le_bytes(),
            &(self.eots_providers.len() as u64).to_le_bytes(),
        ]);
        for v in &self.native_validators {
            acc = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_AVS_PIN_V1",
                &[1u8],
                &acc,
                &v.ed25519_pubkey,
                &v.stake_weight.to_le_bytes(),
                &v.pq_pubkey,
            ]);
        }
        for op in &self.restaked_operators {
            acc = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_AVS_PIN_V1",
                &[2u8],
                &acc,
                &op.ed25519_pubkey,
                &op.raw_stake.to_le_bytes(),
                &op.shared_avs_count.to_le_bytes(),
                &op.pq_pubkey,
            ]);
        }
        for ep in &self.eots_providers {
            acc = crate::core::hash::hash_fields_bytes(&[
                b"BDLM_AVS_PIN_V1",
                &[3u8],
                &acc,
                &ep.ed25519_pubkey,
                &ep.stake_weight.to_le_bytes(),
                &ep.pq_pubkey,
            ]);
        }
        acc
    }

    /// Return the haircut-adjusted restaked stake and whether an ML-DSA-65
    /// co-signing key is bound for `pubkey`.
    ///
    /// WIRING: used by `crate::cross_domain::economic_guard` for incremental
    /// per-offender slashing accounting.
    #[must_use]
    pub fn restaked_member_info(&self, pubkey: &[u8; 32]) -> Option<(u128, bool)> {
        self.restaked_operators
            .iter()
            .find(|op| bool::from(op.ed25519_pubkey.ct_eq(pubkey)))
            .map(|op| (u128::from(op.haircut_stake()), !op.pq_pubkey.is_empty()))
    }

    /// Return the EOTS finality stake and whether an ML-DSA-65 co-signing key
    /// is bound for `pubkey`.
    ///
    /// WIRING: used by `crate::cross_domain::economic_guard` for incremental
    /// per-offender EOTS slashing accounting.
    #[must_use]
    pub fn eots_member_info(&self, pubkey: &[u8; 32]) -> Option<(u128, bool)> {
        self.eots_providers
            .iter()
            .find(|ep| bool::from(ep.ed25519_pubkey.ct_eq(pubkey)))
            .map(|ep| (u128::from(ep.stake_weight), !ep.pq_pubkey.is_empty()))
    }
}

/// Detached hybrid signature attached to an AVS quorum vote or slashing proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvsSignature {
    /// Signer Ed25519 public key (32 bytes).
    pub signer_pubkey: [u8; 32],
    /// Detached Ed25519 signature bytes.
    pub ed25519_sig: Vec<u8>,
    /// Mandatory ML-DSA-65 co-signature when the signer registers `pq_pubkey`.
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Self-derived restaking AVS finality batch header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestakingBatchHeader {
    /// Active epoch matching [`PinnedRestakingAvsSet::epoch`].
    pub epoch: u64,
    /// Finalized domain height (`>= 1`).
    pub height: u64,
    /// Block timestamp in Unix seconds.
    pub timestamp_secs: u64,
    /// Earliest domain height at which signing operators can finish withdrawal.
    pub unbonding_horizon_height: u64,
    /// Committed post-state root (non-zero).
    pub state_root: Hash32,
    /// Committed transaction root (non-zero).
    pub tx_root: Hash32,
    /// Optional committed bridge event root (`[0; 32]` when absent).
    pub event_root: Hash32,
    /// Public EOTS randomness commitment (`[0; 32]` iff `eots_providers` empty).
    pub eots_rand_root: Hash32,
    /// Self-derived digest binding every field above plus `network`.
    pub digest: Hash32,
}

impl RestakingBatchHeader {
    /// Compute the canonical domain-separated digest for this batch header.
    #[must_use]
    pub fn compute_digest(&self, network: &str) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            b"BDLM_AVS_BATCH_V1",
            network.as_bytes(),
            &self.epoch.to_le_bytes(),
            &self.height.to_le_bytes(),
            &self.timestamp_secs.to_le_bytes(),
            &self.unbonding_horizon_height.to_le_bytes(),
            &self.state_root,
            &self.tx_root,
            &self.event_root,
            &self.eots_rand_root,
        ])
    }
}

/// Canonical wire bundle carried inside [`RawConsensusEvidence::payload`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestakingAvsEvidence {
    /// Finalized batch header.
    pub batch: RestakingBatchHeader,
    /// Native quorum signatures (`> 2/3` native stake).
    pub native_sigs: Vec<AvsSignature>,
    /// Restaked AVS operator signatures (`> 2/3` effective restaked stake).
    pub restaked_sigs: Vec<AvsSignature>,
    /// EOTS finality provider signatures (`> 2/3` EOTS stake when configured).
    #[serde(default)]
    pub eots_sigs: Vec<AvsSignature>,
}

/// Slashable protocol violation in a restaking AVS / EOTS domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestakingSlashingProof {
    /// One or more restaked operators attested two conflicting batch digests
    /// at the same `(epoch, height)`.
    RestakedEquivocation {
        /// Epoch of both conflicting votes.
        epoch: u64,
        /// Finalized height of both conflicting votes.
        height: u64,
        /// Unbonding horizon signed under the first vote.
        horizon_a: u64,
        /// First batch digest.
        batch_digest_a: Hash32,
        /// Signatures on the first restaked vote.
        sigs_a: Vec<AvsSignature>,
        /// Unbonding horizon signed under the second vote.
        horizon_b: u64,
        /// Second conflicting batch digest (`!= batch_digest_a`).
        batch_digest_b: Hash32,
        /// Signatures on the second restaked vote.
        sigs_b: Vec<AvsSignature>,
    },
    /// One or more Babylon-class EOTS providers finalized two distinct batch
    /// digests at the same `(epoch, height)`, exposing their extractable key.
    EotsDoubleSign {
        /// Epoch of both conflicting finality votes.
        epoch: u64,
        /// Height of both conflicting finality votes.
        height: u64,
        /// EOTS public randomness root on the first vote.
        rand_root_a: Hash32,
        /// First batch digest.
        batch_digest_a: Hash32,
        /// EOTS signatures on the first target.
        sigs_a: Vec<AvsSignature>,
        /// EOTS public randomness root on the second vote.
        rand_root_b: Hash32,
        /// Second conflicting batch digest (`!= batch_digest_b`).
        batch_digest_b: Hash32,
        /// EOTS signatures on the second target.
        sigs_b: Vec<AvsSignature>,
    },
}

/// Verified outcome of [`verify_restaking_slashing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRestakingSlash {
    /// Canonical domain-separated digest of the proven fault.
    pub evidence_digest: Hash32,
    /// Height at which the equivocation occurred.
    pub fault_height: u64,
    /// Sorted unique Ed25519 public keys of proven equivocating signers.
    pub offenders: Vec<[u8; 32]>,
    /// Total haircut-adjusted slashable weight attributable to `offenders`.
    pub slashed_effective_weight: u128,
}

/// Compute canonical native-quorum vote signing bytes.
#[must_use]
pub fn native_vote_sign_bytes(
    network: &str,
    epoch: u64,
    height: u64,
    batch_digest: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_AVS_NATIVE_VOTE_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &height.to_le_bytes(),
        batch_digest,
    ])
}

/// Compute canonical restaked-operator quorum signing bytes.
#[must_use]
pub fn restake_vote_sign_bytes(
    network: &str,
    epoch: u64,
    height: u64,
    unbonding_horizon_height: u64,
    batch_digest: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_AVS_RESTAKE_VOTE_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &height.to_le_bytes(),
        &unbonding_horizon_height.to_le_bytes(),
        batch_digest,
    ])
}

/// Compute canonical EOTS finality-provider signing bytes.
#[must_use]
pub fn eots_vote_sign_bytes(
    network: &str,
    epoch: u64,
    height: u64,
    eots_rand_root: &Hash32,
    batch_digest: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_AVS_EOTS_VOTE_V1",
        network.as_bytes(),
        &epoch.to_le_bytes(),
        &height.to_le_bytes(),
        eots_rand_root,
        batch_digest,
    ])
}

/// Encode a [`RestakingAvsEvidence`] bundle with its 8-byte magic header.
///
/// WIRING: used by relayers and [`crate::cross_domain::economic_guard`] tests
/// to construct canonical `restaking-avs-v1` payloads.
///
/// # Errors
///
/// Returns an error if serialization fails or exceeds the payload size ceiling.
pub fn encode_restaking_evidence(bundle: &RestakingAvsEvidence) -> Result<Vec<u8>, AdapterError> {
    let body = bincode::serialize(bundle).map_err(|e| AdapterError::Malformed {
        offset: 0,
        reason: format!("restaking-avs encode failed: {e}"),
    })?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_AVS_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_AVS_PAYLOAD_BYTES,
            reason: format!("restaking-avs payload {total} exceeds {MAX_AVS_PAYLOAD_BYTES}"),
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_restaking_evidence(payload: &[u8]) -> Result<RestakingAvsEvidence, AdapterError> {
    if payload.len() > MAX_AVS_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_AVS_PAYLOAD_BYTES,
            reason: format!(
                "restaking-avs payload {} exceeds {MAX_AVS_PAYLOAD_BYTES}",
                payload.len()
            ),
        });
    }
    let Some(magic) = payload.get(..PAYLOAD_MAGIC.len()) else {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "restaking-avs payload truncated before 8-byte magic header".into(),
        });
    };
    if !bool::from(magic.ct_eq(PAYLOAD_MAGIC)) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "invalid restaking-avs payload magic header".into(),
        });
    }
    let body = payload
        .get(PAYLOAD_MAGIC.len()..)
        .ok_or_else(|| AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: "missing restaking-avs payload body".into(),
        })?;
    let decoded: RestakingAvsEvidence =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_AVS_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: PAYLOAD_MAGIC.len(),
                reason: format!("invalid restaking-avs evidence body: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: PAYLOAD_MAGIC.len(),
            reason: "non-canonical trailing bytes in restaking-avs evidence".into(),
        });
    }
    Ok(decoded)
}

const fn min_bft_supermajority(total_weight: u128) -> u128 {
    (total_weight.saturating_mul(2) / 3).saturating_add(1)
}

type IndexedQuorum<'a> = BTreeMap<[u8; 32], (u64, &'a [u8])>;

fn index_standard_quorum<'a>(
    members: &'a [AvsQuorumMember],
    label: &str,
) -> Result<(IndexedQuorum<'a>, u128), AdapterError> {
    if members.is_empty() || members.len() > MAX_AVS_QUORUM_MEMBERS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "{label} quorum size {} outside 1..={MAX_AVS_QUORUM_MEMBERS}",
                members.len()
            ),
        });
    }
    let mut by_key = BTreeMap::new();
    let mut total = 0u128;
    for member in members {
        if bool::from(member.ed25519_pubkey.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} member pubkey cannot be all-zero"),
            });
        }
        if member.stake_weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} member stake_weight must be positive"),
            });
        }
        if !member.pq_pubkey.is_empty() {
            pq::validate_public_key(SchemeId::ML_DSA_65, &member.pq_pubkey).map_err(|_| {
                AdapterError::ConsensusRule {
                    rule: format!("invalid ML-DSA-65 public key in {label} quorum"),
                }
            })?;
        }
        if by_key
            .insert(
                member.ed25519_pubkey,
                (member.stake_weight, member.pq_pubkey.as_slice()),
            )
            .is_some()
        {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate member pubkey in {label} quorum"),
            });
        }
        total = total
            .checked_add(u128::from(member.stake_weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: format!("{label} total stake overflow"),
            })?;
    }
    Ok((by_key, total))
}

fn index_restaked_quorum(
    pinned: &PinnedRestakingAvsSet,
) -> Result<(IndexedQuorum<'_>, u128), AdapterError> {
    if pinned.min_withdrawal_delay == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "restaking-avs min_withdrawal_delay must be positive".into(),
        });
    }
    if pinned.max_shared_avs_per_operator == 0
        || pinned.max_shared_avs_per_operator > MAX_SHARED_AVS_LIMIT
    {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "restaking-avs max_shared_avs_per_operator {} outside 1..={MAX_SHARED_AVS_LIMIT}",
                pinned.max_shared_avs_per_operator
            ),
        });
    }
    if pinned.min_effective_restaked_stake == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "restaking-avs min_effective_restaked_stake must be positive".into(),
        });
    }
    let ops = &pinned.restaked_operators;
    if ops.is_empty() || ops.len() > MAX_AVS_QUORUM_MEMBERS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "restaked operator count {} outside 1..={MAX_AVS_QUORUM_MEMBERS}",
                ops.len()
            ),
        });
    }
    let mut by_key = BTreeMap::new();
    let mut total = 0u128;
    for op in ops {
        if bool::from(op.ed25519_pubkey.ct_eq(&[0u8; 32])) {
            return Err(AdapterError::ConsensusRule {
                rule: "restaked operator pubkey cannot be all-zero".into(),
            });
        }
        if op.raw_stake == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "restaked operator raw_stake must be positive".into(),
            });
        }
        if op.shared_avs_count == 0 || op.shared_avs_count > pinned.max_shared_avs_per_operator {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "restaked operator shared_avs_count {} outside 1..={}",
                    op.shared_avs_count, pinned.max_shared_avs_per_operator
                ),
            });
        }
        let eff = op.haircut_stake();
        if eff == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "restaked operator haircut_stake diluted to zero after shared-AVS haircut"
                    .into(),
            });
        }
        if !op.pq_pubkey.is_empty() {
            pq::validate_public_key(SchemeId::ML_DSA_65, &op.pq_pubkey).map_err(|_| {
                AdapterError::ConsensusRule {
                    rule: "invalid ML-DSA-65 public key in restaked operator set".into(),
                }
            })?;
        }
        if by_key
            .insert(op.ed25519_pubkey, (eff, op.pq_pubkey.as_slice()))
            .is_some()
        {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate operator pubkey in restaked AVS quorum".into(),
            });
        }
        total = total
            .checked_add(u128::from(eff))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "restaked effective stake overflow".into(),
            })?;
    }
    Ok((by_key, total))
}

fn verify_hybrid_avs_sig(
    ed_pubkey: &[u8; 32],
    pq_pubkey: &[u8],
    msg: &Hash32,
    sig: &AvsSignature,
    label: &str,
) -> Result<bool, AdapterError> {
    verify_signature(msg, &sig.ed25519_sig, ed_pubkey).map_err(|e| AdapterError::Crypto {
        what: format!("{label} Ed25519 verification failed: {e}"),
    })?;
    if pq_pubkey.is_empty() {
        if !sig.pq_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: format!("{label} carries unexpected ML-DSA-65 signature for classical key"),
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
        pq_pubkey,
        msg,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &sig.pq_sig,
    )
    .map_err(|e| AdapterError::Crypto {
        what: format!("{label} ML-DSA-65 verification failed: {e}"),
    })?;
    Ok(true)
}

fn verify_quorum_certificate(
    index: &IndexedQuorum<'_>,
    total_weight: u128,
    sigs: &[AvsSignature],
    msg: &Hash32,
    label: &str,
) -> Result<(u64, u128, bool), AdapterError> {
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
    let mut signed_weight = 0u128;
    let mut all_pq = true;
    for sig in sigs {
        let Some(&(weight, pq_pk)) = index.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} signer is not in governance-pinned quorum"),
            });
        };
        if !seen.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate signer in {label}"),
            });
        }
        let has_pq = verify_hybrid_avs_sig(&sig.signer_pubkey, pq_pk, msg, sig, label)?;
        all_pq &= has_pq;
        signed_weight = signed_weight
            .checked_add(u128::from(weight))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: format!("{label} signed stake overflow"),
            })?;
    }
    let required = min_bft_supermajority(total_weight);
    if signed_weight < required {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "{label} signed stake {signed_weight} below required >2/3 threshold {required}"
            ),
        });
    }
    let count = u64::try_from(seen.len()).unwrap_or(u64::MAX);
    Ok((count, signed_weight, all_pq))
}

fn verify_slash_side(
    index: &IndexedQuorum<'_>,
    sigs: &[AvsSignature],
    msg: &Hash32,
    label: &str,
) -> Result<BTreeSet<[u8; 32]>, AdapterError> {
    if sigs.is_empty() || sigs.len() > index.len() {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "{label} slash signature set size {} outside 1..={}",
                sigs.len(),
                index.len()
            ),
        });
    }
    let mut signers = BTreeSet::new();
    for sig in sigs {
        let Some(&(_weight, pq_pk)) = index.get(&sig.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: format!("{label} slash proof references unknown signer"),
            });
        };
        if !signers.insert(sig.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("duplicate signer in {label} slash side"),
            });
        }
        let _ = verify_hybrid_avs_sig(&sig.signer_pubkey, pq_pk, msg, sig, label)?;
    }
    Ok(signers)
}

/// Verify a [`RestakingSlashingProof`] against a governance-pinned AVS quorum
/// configuration.
///
/// # Errors
///
/// Returns [`AdapterError`] when the pinned configuration is invalid, the two
/// targets are identical, any signature is invalid or missing its PQ half, or
/// no pinned member equivocated across both sides.
pub fn verify_restaking_slashing(
    network: &str,
    pinned: &PinnedRestakingAvsSet,
    proof: &RestakingSlashingProof,
) -> Result<VerifiedRestakingSlash, AdapterError> {
    let _ = index_standard_quorum(&pinned.native_validators, "restaking-avs native")?;
    let (restaked_idx, _) = index_restaked_quorum(pinned)?;

    match proof {
        RestakingSlashingProof::RestakedEquivocation {
            epoch,
            height,
            horizon_a,
            batch_digest_a,
            sigs_a,
            horizon_b,
            batch_digest_b,
            sigs_b,
        } => {
            if *epoch != pinned.epoch || *height == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "restaked equivocation epoch mismatch or zero height".into(),
                });
            }
            if bool::from(batch_digest_a.ct_eq(&[0u8; 32]))
                || bool::from(batch_digest_b.ct_eq(&[0u8; 32]))
                || bool::from(batch_digest_a.ct_eq(batch_digest_b))
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "restaked equivocation requires two distinct non-zero batch digests"
                        .into(),
                });
            }
            let msg_a =
                restake_vote_sign_bytes(network, *epoch, *height, *horizon_a, batch_digest_a);
            let msg_b =
                restake_vote_sign_bytes(network, *epoch, *height, *horizon_b, batch_digest_b);
            let set_a = verify_slash_side(&restaked_idx, sigs_a, &msg_a, "restaked-slash-a")?;
            let set_b = verify_slash_side(&restaked_idx, sigs_b, &msg_b, "restaked-slash-b")?;
            let offenders: Vec<[u8; 32]> = set_a.intersection(&set_b).copied().collect();
            if offenders.is_empty() {
                return Err(AdapterError::ConsensusRule {
                    rule: "restaked equivocation has no overlapping offending operator".into(),
                });
            }
            let mut slashed = 0u128;
            for pk in &offenders {
                if let Some(&(eff, _)) = restaked_idx.get(pk) {
                    slashed = slashed.saturating_add(u128::from(eff));
                }
            }
            let epoch_le = epoch.to_le_bytes();
            let height_le = height.to_le_bytes();
            let ha_le = horizon_a.to_le_bytes();
            let hb_le = horizon_b.to_le_bytes();
            // Order the conflicting statements canonically so swapping sides A and B
            // produces the exact same evidence digest and cannot bypass replay checks.
            let ((lo_h, lo_digest), (hi_h, hi_digest)) =
                if (batch_digest_a.as_slice(), ha_le.as_slice())
                    <= (batch_digest_b.as_slice(), hb_le.as_slice())
                {
                    ((&ha_le, batch_digest_a), (&hb_le, batch_digest_b))
                } else {
                    ((&hb_le, batch_digest_b), (&ha_le, batch_digest_a))
                };
            let count_le = u64::try_from(offenders.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes();
            let mut fields: Vec<&[u8]> = Vec::with_capacity(offenders.len().saturating_add(10));
            fields.push(b"BDLM_AVS_SLASH_V1");
            fields.push(&[1u8]);
            fields.push(network.as_bytes());
            fields.push(&epoch_le);
            fields.push(&height_le);
            fields.push(lo_h);
            fields.push(lo_digest);
            fields.push(hi_h);
            fields.push(hi_digest);
            fields.push(&count_le);
            for pk in &offenders {
                fields.push(pk);
            }
            Ok(VerifiedRestakingSlash {
                evidence_digest: hash_fields_bytes(&fields),
                fault_height: *height,
                offenders,
                slashed_effective_weight: slashed,
            })
        }
        RestakingSlashingProof::EotsDoubleSign {
            epoch,
            height,
            rand_root_a,
            batch_digest_a,
            sigs_a,
            rand_root_b,
            batch_digest_b,
            sigs_b,
        } => {
            let (eots_idx, _) =
                index_standard_quorum(&pinned.eots_providers, "restaking-avs EOTS")?;
            if *epoch != pinned.epoch || *height == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "EOTS double-sign epoch mismatch or zero height".into(),
                });
            }
            if bool::from(rand_root_a.ct_eq(&[0u8; 32]))
                || bool::from(rand_root_b.ct_eq(&[0u8; 32]))
                || bool::from(batch_digest_a.ct_eq(&[0u8; 32]))
                || bool::from(batch_digest_b.ct_eq(&[0u8; 32]))
                || bool::from(batch_digest_a.ct_eq(batch_digest_b))
            {
                return Err(AdapterError::ConsensusRule {
                    rule:
                        "EOTS double-sign requires non-zero randomness roots and distinct digests"
                            .into(),
                });
            }
            let msg_a = eots_vote_sign_bytes(network, *epoch, *height, rand_root_a, batch_digest_a);
            let msg_b = eots_vote_sign_bytes(network, *epoch, *height, rand_root_b, batch_digest_b);
            let set_a = verify_slash_side(&eots_idx, sigs_a, &msg_a, "eots-slash-a")?;
            let set_b = verify_slash_side(&eots_idx, sigs_b, &msg_b, "eots-slash-b")?;
            let offenders: Vec<[u8; 32]> = set_a.intersection(&set_b).copied().collect();
            if offenders.is_empty() {
                return Err(AdapterError::ConsensusRule {
                    rule: "EOTS double-sign has no overlapping finality provider".into(),
                });
            }
            let mut slashed = 0u128;
            for pk in &offenders {
                if let Some(&(w, _)) = eots_idx.get(pk) {
                    slashed = slashed.saturating_add(u128::from(w));
                }
            }
            let epoch_le = epoch.to_le_bytes();
            let height_le = height.to_le_bytes();
            let ((lo_rand, lo_digest), (hi_rand, hi_digest)) =
                if (batch_digest_a.as_slice(), rand_root_a.as_slice())
                    <= (batch_digest_b.as_slice(), rand_root_b.as_slice())
                {
                    ((rand_root_a, batch_digest_a), (rand_root_b, batch_digest_b))
                } else {
                    ((rand_root_b, batch_digest_b), (rand_root_a, batch_digest_a))
                };
            let count_le = u64::try_from(offenders.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes();
            let mut fields: Vec<&[u8]> = Vec::with_capacity(offenders.len().saturating_add(10));
            fields.push(b"BDLM_AVS_SLASH_V1");
            fields.push(&[2u8]);
            fields.push(network.as_bytes());
            fields.push(&epoch_le);
            fields.push(&height_le);
            fields.push(lo_rand);
            fields.push(lo_digest);
            fields.push(hi_rand);
            fields.push(hi_digest);
            fields.push(&count_le);
            for pk in &offenders {
                fields.push(pk);
            }
            Ok(VerifiedRestakingSlash {
                evidence_digest: hash_fields_bytes(&fields),
                fault_height: *height,
                offenders,
                slashed_effective_weight: slashed,
            })
        }
    }
}

/// External finality adapter for dual-quorum restaking AVS and EOTS domains.
pub struct RestakingAvsAdapter {
    network: String,
    pinned: Option<PinnedRestakingAvsSet>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl RestakingAvsAdapter {
    /// Construct a `RestakingAvsAdapter` bound to `network` and its pinned
    /// dual-quorum + EOTS set.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedRestakingAvsSet>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(ADAPTER_NAME);
        let set_size = pinned.as_ref().map_or(0, |p| {
            u64::try_from(p.restaked_operators.len()).unwrap_or(u64::MAX)
        });
        let required_depth = pinned.as_ref().map_or(1, |p| p.min_withdrawal_delay.max(1));
        let descriptor = AdapterDescriptor {
            id,
            name: ADAPTER_NAME.into(),
            adapter_version: ADAPTER_VERSION,
            accepted_evidence_versions: vec![EVIDENCE_VERSION],
            consensus_kind: "restaking-avs-eots".into(),
            finality_kind: FinalityKind::EconomicFinality,
            required_depth,
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
                    "restaking-avs network mismatch: expected {}, got {}",
                    self.network, evidence.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no governance-pinned restaking-avs quorum configured".into(),
            });
        };
        let (native_idx, native_total) =
            index_standard_quorum(&pinned.native_validators, "restaking-avs native")?;
        let (restaked_idx, restaked_total) = index_restaked_quorum(pinned)?;
        let eots_indexed = if pinned.eots_providers.is_empty() {
            None
        } else {
            Some(index_standard_quorum(
                &pinned.eots_providers,
                "restaking-avs EOTS",
            )?)
        };

        let decoded = decode_restaking_evidence(&evidence.payload)?;
        let batch = &decoded.batch;

        if batch.epoch != pinned.epoch {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "restaking-avs batch epoch {} does not match pinned epoch {}",
                    batch.epoch, pinned.epoch
                ),
            });
        }
        if batch.height == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "restaking-avs batch height must be positive".into(),
            });
        }
        if bool::from(batch.state_root.ct_eq(&[0u8; 32]))
            || bool::from(batch.tx_root.ct_eq(&[0u8; 32]))
        {
            return Err(AdapterError::ConsensusRule {
                rule: "restaking-avs state_root and tx_root must be non-zero".into(),
            });
        }
        if policy.require_declared_match {
            if evidence.declared_height != batch.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(evidence.declared_root.ct_eq(&batch.state_root)) {
                return Err(AdapterError::DeclarationMismatch {
                    field: "state_root",
                });
            }
        }

        if batch.unbonding_horizon_height <= batch.height {
            return Err(AdapterError::ConsensusRule {
                rule: "restaking-avs unbonding_horizon_height must strictly exceed batch height"
                    .into(),
            });
        }
        let lock_margin = batch.unbonding_horizon_height.saturating_sub(batch.height);
        let required_depth = policy.min_depth.max(pinned.min_withdrawal_delay);
        if lock_margin < required_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: lock_margin,
                required: required_depth,
            });
        }

        if policy.max_age > 0 && policy.now > batch.height {
            let age = policy.now.saturating_sub(batch.height);
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
                rule: "restaking-avs batch digest does not match self-derived fields".into(),
            });
        }

        let native_msg =
            native_vote_sign_bytes(&self.network, batch.epoch, batch.height, &batch.digest);
        let (native_signers, _, native_pq) = verify_quorum_certificate(
            &native_idx,
            native_total,
            &decoded.native_sigs,
            &native_msg,
            "restaking-avs native quorum",
        )?;

        let restake_msg = restake_vote_sign_bytes(
            &self.network,
            batch.epoch,
            batch.height,
            batch.unbonding_horizon_height,
            &batch.digest,
        );
        let (restaked_signers, restaked_signed, restake_pq) = verify_quorum_certificate(
            &restaked_idx,
            restaked_total,
            &decoded.restaked_sigs,
            &restake_msg,
            "restaking-avs operator quorum",
        )?;
        if restaked_signed < pinned.min_effective_restaked_stake {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "restaking-avs effective signed stake {restaked_signed} below minimum {}",
                    pinned.min_effective_restaked_stake
                ),
            });
        }

        let mut all_pq = native_pq & restake_pq;
        let mut min_signers = native_signers.min(restaked_signers);
        let mut conservative_total = restaked_total;

        match &eots_indexed {
            None => {
                if !bool::from(batch.eots_rand_root.ct_eq(&[0u8; 32]))
                    || !decoded.eots_sigs.is_empty()
                {
                    return Err(AdapterError::ConsensusRule {
                        rule: "unexpected EOTS randomness or signatures without pinned providers"
                            .into(),
                    });
                }
            }
            Some((eots_idx, eots_total)) => {
                if bool::from(batch.eots_rand_root.ct_eq(&[0u8; 32])) {
                    return Err(AdapterError::ConsensusRule {
                        rule: "pinned EOTS finality requires non-zero eots_rand_root".into(),
                    });
                }
                let eots_msg = eots_vote_sign_bytes(
                    &self.network,
                    batch.epoch,
                    batch.height,
                    &batch.eots_rand_root,
                    &batch.digest,
                );
                let (eots_signers, _, eots_pq) = verify_quorum_certificate(
                    eots_idx,
                    *eots_total,
                    &decoded.eots_sigs,
                    &eots_msg,
                    "restaking-avs EOTS quorum",
                )?;
                all_pq &= eots_pq;
                min_signers = min_signers.min(eots_signers);
                conservative_total = conservative_total.min(*eots_total);
            }
        }

        let scheme = if all_pq {
            ObservedScheme::Scheme(SchemeId::ML_DSA_65)
        } else {
            ObservedScheme::Scheme(SchemeId::ED25519)
        };
        let attested_event_root =
            (!bool::from(batch.event_root.ct_eq(&[0u8; 32]))).then_some(batch.event_root);

        let attestation = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: batch.height,
            state_root: batch.state_root,
            finalized_at: batch.height,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers: min_signers,
                required: u64::try_from(min_bft_supermajority(conservative_total))
                    .unwrap_or(u64::MAX),
                total_weight: conservative_total,
                slashable: true,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(batch.digest),
            attested_event_root,
            attested_tx_root: Some(batch.tx_root),
        };
        Ok((attestation, all_pq))
    }
}

impl ExternalFinalityAdapter for RestakingAvsAdapter {
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
            .map_or(32, |g| g.payload.len().saturating_sub(16));
        let flipped_epoch = self
            .golden
            .as_ref()
            .and_then(|g| g.payload.get(8).copied())
            .map_or(0x77, |b| b ^ 0xFF);
        let flipped_sig = self
            .golden
            .as_ref()
            .and_then(|g| g.payload.get(sig_tail).copied())
            .map_or(0xDE, |b| b ^ 0xFF);
        vec![
            FaultProbe {
                name: "refuses unsupported restaking-avs evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 7 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign restaking-avs network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-foreign", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared restaking height".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared restaking state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted restaking-avs magic header".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0x00, 0xFF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated restaking-avs epoch".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![flipped_epoch],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted EOTS finality signature".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![flipped_sig],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            },
            FaultProbe {
                name: "refuses truncated restaking-avs payload".into(),
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
    use crate::cross_domain::external::selftest::admit_observed;
    use crate::crypto::facts::{CryptoFacts, ObservedScheme, QuantumClass};
    use crate::crypto::primitives::{KeyPair, PqKeyPair};
    use crate::crypto::scheme::SchemeId;

    const NET: &str = "eigen-babylon-mainnet";

    struct HybridSigner {
        ed: KeyPair,
        pq: PqKeyPair,
        weight: u64,
        shared_avs: u32,
    }

    impl HybridSigner {
        fn new(seed: u8, weight: u64, shared_avs: u32) -> Self {
            Self {
                ed: KeyPair::from_seed(&[seed; 32]).unwrap(),
                pq: PqKeyPair::generate(),
                weight,
                shared_avs,
            }
        }

        fn as_member(&self) -> AvsQuorumMember {
            AvsQuorumMember {
                ed25519_pubkey: self.ed.public_key_bytes(),
                stake_weight: self.weight,
                pq_pubkey: self.pq.public_key_bytes().to_vec(),
            }
        }

        fn as_restaked(&self) -> RestakedOperator {
            RestakedOperator {
                ed25519_pubkey: self.ed.public_key_bytes(),
                raw_stake: self.weight,
                shared_avs_count: self.shared_avs,
                pq_pubkey: self.pq.public_key_bytes().to_vec(),
            }
        }

        fn sign(&self, msg: &Hash32) -> AvsSignature {
            AvsSignature {
                signer_pubkey: self.ed.public_key_bytes(),
                ed25519_sig: self.ed.sign(msg).to_vec(),
                pq_sig: self
                    .pq
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, msg)
                    .unwrap(),
            }
        }
    }

    struct Fixture {
        restaked: [HybridSigner; 4],
        eots: [HybridSigner; 4],
        pinned: PinnedRestakingAvsSet,
        bundle: RestakingAvsEvidence,
        raw: RawConsensusEvidence,
    }

    fn build_fixture() -> Fixture {
        let native = [
            HybridSigner::new(1, 300, 1),
            HybridSigner::new(2, 300, 1),
            HybridSigner::new(3, 300, 1),
            HybridSigner::new(4, 300, 1),
        ];
        // Restaked raw=1200 shared across 2, 2, 3, 4 -> effective = 600, 600, 400, 300 (sum=1900).
        // First 3 signers = 1600 > 1266 (2/3 of 1900).
        let restaked = [
            HybridSigner::new(11, 1_200, 2),
            HybridSigner::new(12, 1_200, 2),
            HybridSigner::new(13, 1_200, 3),
            HybridSigner::new(14, 1_200, 4),
        ];
        let eots = [
            HybridSigner::new(21, 500, 1),
            HybridSigner::new(22, 500, 1),
            HybridSigner::new(23, 500, 1),
            HybridSigner::new(24, 500, 1),
        ];
        let pinned = PinnedRestakingAvsSet {
            epoch: 5,
            min_withdrawal_delay: 100,
            max_shared_avs_per_operator: 8,
            min_effective_restaked_stake: 1_200,
            native_validators: native.iter().map(HybridSigner::as_member).collect(),
            restaked_operators: restaked.iter().map(HybridSigner::as_restaked).collect(),
            eots_providers: eots.iter().map(HybridSigner::as_member).collect(),
        };
        let mut batch = RestakingBatchHeader {
            epoch: 5,
            height: 420,
            timestamp_secs: 1_750_000_000,
            unbonding_horizon_height: 600,
            state_root: [0xA1; 32],
            tx_root: [0xB2; 32],
            event_root: [0xC3; 32],
            eots_rand_root: [0xD4; 32],
            digest: [0u8; 32],
        };
        batch.digest = batch.compute_digest(NET);

        let n_msg = native_vote_sign_bytes(NET, batch.epoch, batch.height, &batch.digest);
        let r_msg = restake_vote_sign_bytes(
            NET,
            batch.epoch,
            batch.height,
            batch.unbonding_horizon_height,
            &batch.digest,
        );
        let e_msg = eots_vote_sign_bytes(
            NET,
            batch.epoch,
            batch.height,
            &batch.eots_rand_root,
            &batch.digest,
        );
        let bundle = RestakingAvsEvidence {
            batch: batch.clone(),
            native_sigs: native[..3].iter().map(|s| s.sign(&n_msg)).collect(),
            restaked_sigs: restaked[..3].iter().map(|s| s.sign(&r_msg)).collect(),
            eots_sigs: eots[..3].iter().map(|s| s.sign(&e_msg)).collect(),
        };
        let payload = encode_restaking_evidence(&bundle).unwrap();
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            evidence_version: EVIDENCE_VERSION,
            network: NET.into(),
            declared_height: batch.height,
            declared_root: batch.state_root,
            payload,
            submitter: Address::from([0x11; 32]),
        };
        Fixture {
            restaked,
            eots,
            pinned,
            bundle,
            raw,
        }
    }

    #[test]
    fn restaking_avs_admits_all_fault_probes_and_reports_haircut_security() {
        let fx = build_fixture();
        let adapter =
            RestakingAvsAdapter::new(NET, Some(fx.pinned.clone())).with_golden(fx.raw.clone());
        let policy = VerificationPolicy {
            min_depth: 100,
            max_age: 1_000,
            now: 500,
            require_declared_match: true,
            require_slashable: true,
        };
        let mut facts = CryptoFacts::new();
        let att = adapter
            .verify_observed(&fx.raw, &policy, &mut facts)
            .expect("valid triple-quorum restaking-avs evidence verifies");
        assert_eq!(att.height, 420);
        assert_eq!(att.state_root, [0xA1; 32]);
        assert_eq!(att.attested_event_root, Some([0xC3; 32]));
        assert_eq!(att.attested_tx_root, Some([0xB2; 32]));
        assert_eq!(facts.quantum_class(), Some(QuantumClass::Lattice));
        match att.security {
            SecurityBacking::SignatureSet {
                scheme,
                total_weight,
                slashable,
                ..
            } => {
                assert_eq!(scheme, ObservedScheme::Scheme(SchemeId::ML_DSA_65));
                assert!(slashable);
                // Conservative min of total effective restaked (1900) and EOTS (2000) = 1900.
                assert_eq!(total_weight, 1_900);
            }
            other => panic!("unexpected backing: {other:?}"),
        }

        let (report, selftest_facts) = admit_observed(&adapter, &policy);
        assert!(report.admitted, "selftest must admit: {report:?}");
        assert_eq!(selftest_facts.quantum_class(), Some(QuantumClass::Lattice));
    }

    #[test]
    fn restaking_avs_refuses_single_quorum_short_horizon_overleverage_and_pq_strip_forgery() {
        let fx = build_fixture();
        let policy = VerificationPolicy::strict(500);

        // 1. Sub-2/3 restaked quorum even when native + EOTS pass.
        let mut short_restake = fx.bundle.clone();
        short_restake.restaked_sigs.truncate(2); // 600 + 600 = 1200 <= 2/3 of 1900 (1266)
        let mut raw = fx.raw.clone();
        raw.payload = encode_restaking_evidence(&short_restake).unwrap();
        let adapter = RestakingAvsAdapter::new(NET, Some(fx.pinned.clone()));
        let err = adapter
            .verify(&raw, &policy)
            .expect_err("sub-supermajority restaked quorum must fail closed");
        assert!(matches!(err, AdapterError::ConsensusRule { .. }), "{err:?}");

        // 2. Unbonding horizon shorter than min_withdrawal_delay.
        let mut short_horizon = fx.bundle.clone();
        short_horizon.batch.unbonding_horizon_height = short_horizon.batch.height + 50;
        short_horizon.batch.digest = short_horizon.batch.compute_digest(NET);
        raw.payload = encode_restaking_evidence(&short_horizon).unwrap();
        let herr = adapter
            .verify(&raw, &policy)
            .expect_err("premature withdrawal horizon must fail closed");
        assert!(
            matches!(
                herr,
                AdapterError::InsufficientDepth { .. } | AdapterError::ConsensusRule { .. }
            ),
            "{herr:?}"
        );

        // 3. Over-leveraged operator exceeding max_shared_avs_per_operator.
        let mut overlev_pin = fx.pinned.clone();
        overlev_pin.max_shared_avs_per_operator = 3; // operator #4 has shared_avs_count = 4
        let overlev_adapter = RestakingAvsAdapter::new(NET, Some(overlev_pin));
        let oerr = overlev_adapter
            .verify(&fx.raw, &policy)
            .expect_err("over-leveraged shared_avs_count must fail closed");
        assert!(
            matches!(oerr, AdapterError::ConsensusRule { .. }),
            "{oerr:?}"
        );

        // 4. Stripped ML-DSA-65 co-signature forgery fails closed.
        let mut pq_stripped = fx.bundle.clone();
        pq_stripped.native_sigs[0].pq_sig.clear();
        raw.payload = encode_restaking_evidence(&pq_stripped).unwrap();
        let perr = adapter
            .verify(&raw, &policy)
            .expect_err("stripping mandatory ML-DSA-65 signature must be refused");
        assert!(matches!(perr, AdapterError::Crypto { .. }), "{perr:?}");

        // 5. Missing EOTS quorum when pinned set carries EOTS providers.
        let mut no_eots = fx.bundle;
        no_eots.eots_sigs.clear();
        raw.payload = encode_restaking_evidence(&no_eots).unwrap();
        let eerr = adapter
            .verify(&raw, &policy)
            .expect_err("omitting EOTS quorum must fail closed");
        assert!(
            matches!(eerr, AdapterError::ConsensusRule { .. }),
            "{eerr:?}"
        );
    }

    #[test]
    fn restaking_avs_slashing_verifies_restaked_equivocation_and_eots_double_sign_and_refuses_forgery(
    ) {
        let fx = build_fixture();
        let digest_a = [0x11; 32];
        let digest_b = [0x22; 32];

        // 1. Restaked equivocation by operators 0 (eff 600) and 2 (eff 400) => 1000 slashed.
        let msg_ra = restake_vote_sign_bytes(NET, 5, 420, 600, &digest_a);
        let msg_rb = restake_vote_sign_bytes(NET, 5, 420, 610, &digest_b);
        let proof_r = RestakingSlashingProof::RestakedEquivocation {
            epoch: 5,
            height: 420,
            horizon_a: 600,
            batch_digest_a: digest_a,
            sigs_a: vec![fx.restaked[0].sign(&msg_ra), fx.restaked[2].sign(&msg_ra)],
            horizon_b: 610,
            batch_digest_b: digest_b,
            sigs_b: vec![fx.restaked[2].sign(&msg_rb), fx.restaked[0].sign(&msg_rb)],
        };
        let slash_r = verify_restaking_slashing(NET, &fx.pinned, &proof_r)
            .expect("valid restaked double-attestation slashes offenders");
        assert_eq!(slash_r.fault_height, 420);
        assert_eq!(slash_r.offenders.len(), 2);
        assert_eq!(slash_r.slashed_effective_weight, 1_000);

        // 2. Same digest is NOT equivocation.
        let non_fault = RestakingSlashingProof::RestakedEquivocation {
            epoch: 5,
            height: 420,
            horizon_a: 600,
            batch_digest_a: digest_a,
            sigs_a: vec![fx.restaked[0].sign(&msg_ra)],
            horizon_b: 600,
            batch_digest_b: digest_a,
            sigs_b: vec![fx.restaked[0].sign(&msg_ra)],
        };
        assert!(verify_restaking_slashing(NET, &fx.pinned, &non_fault).is_err());

        // 3. EOTS double-sign by provider 1 (stake 500) slashes 500; stripped PQ fails closed.
        let ea = eots_vote_sign_bytes(NET, 5, 420, &[0x91; 32], &digest_a);
        let eb = eots_vote_sign_bytes(NET, 5, 420, &[0x92; 32], &digest_b);
        let proof_e = RestakingSlashingProof::EotsDoubleSign {
            epoch: 5,
            height: 420,
            rand_root_a: [0x91; 32],
            batch_digest_a: digest_a,
            sigs_a: vec![fx.eots[1].sign(&ea)],
            rand_root_b: [0x92; 32],
            batch_digest_b: digest_b,
            sigs_b: vec![fx.eots[1].sign(&eb)],
        };
        let slash_e = verify_restaking_slashing(NET, &fx.pinned, &proof_e)
            .expect("valid EOTS finality double-sign slashes provider");
        assert_eq!(slash_e.offenders, vec![fx.eots[1].ed.public_key_bytes()]);
        assert_eq!(slash_e.slashed_effective_weight, 500);

        let mut forged_sig = fx.eots[1].sign(&eb);
        forged_sig.pq_sig.clear();
        let forged_e = RestakingSlashingProof::EotsDoubleSign {
            epoch: 5,
            height: 420,
            rand_root_a: [0x91; 32],
            batch_digest_a: digest_a,
            sigs_a: vec![fx.eots[1].sign(&ea)],
            rand_root_b: [0x92; 32],
            batch_digest_b: digest_b,
            sigs_b: vec![forged_sig],
        };
        assert!(verify_restaking_slashing(NET, &fx.pinned, &forged_e).is_err());
    }
}
