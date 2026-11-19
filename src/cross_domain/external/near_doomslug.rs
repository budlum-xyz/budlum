//! NEAR Protocol `Nightshade` + `Doomslug` BFT external finality adapter
//! (Skidanov & Polosukhin, 2019-2024; consensus twin of `execution/near`).
//!
//! NEAR separates fast optimistic irreversibility (`Doomslug` endorsements) from
//! full Byzantine finality (`Nightshade` BFT gadget) across a three-block light-
//! client chain `(B, B_1, B_2)`:
//!
//! 1. **Canonical block hash.** Each `NearBlockHeaderLite` derives
//!    `inner_lite_hash = H(height, epoch_id, next_epoch_id, prev_state_root,
//!    outcome_root, timestamp_ns, next_bp_hash, block_merkle_root)` and
//!    `block_hash = H(inner_lite_hash, inner_rest_hash, prev_hash)`, matching
//!    NEAR's `LightClientBlockView::current_block_hash` structure.
//! 2. **Doomslug consecutive pair (`B <- B_1`).** `B_1.prev_hash == B.block_hash`,
//!    `B_1.height == B.height + 1`, `B_1.timestamp_ns >= B.timestamp_ns`, and
//!    `B_1.last_ds_final_block == B.block_hash` (attesting that `> 1/2` stake
//!    endorsed `B` directly at `h + 1` with no skip).
//! 3. **Nightshade BFT finality (`B_1 .. B_2`).** `B_2.height == B_1.height + 1`
//!    (consecutive 3-block finality) and `B_2.last_final_block == B.block_hash`,
//!    with `approvals_after_next` signing
//!    `(ApprovalInner::Endorsement(B_2.block_hash), target_height = B_2.height + 1)`
//!    across strictly more than `2/3` (`signed_stake * 3 > total_stake * 2`) of
//!    the active epoch's pinned `block_producers` stake! Because `B` and `B_1`
//!    are consecutive Doomslug blocks and `> 2/3` stake endorsed `B_2` extending
//!    `B_1`, no competing fork bypassing `B` can ever finalize without at least
//!    `1/3` of total epoch stake committing a slashable Doomslug approval violation.
//! 4. **Hybrid PQ co-signature gate.** Every block producer with a registered
//!    `pq_pubkey` must supply BOTH a valid Ed25519 approval AND a valid NIST
//!    ML-DSA-65 co-signature under [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
//! 5. **Verified `next_bp_hash` epoch rotation.** [`advance_near_epoch`] rotates
//!    a [`PinnedNearEpoch`] to `next_epoch_id` only after verifying a finalized
//!    block in the current epoch AND matching `compute_near_bp_hash(next_bps)`
//!    against the finalized header's `next_bp_hash` in constant time.
//! 6. **Doomslug double & surround slashing.** [`verify_near_approval_slash`]
//!    verifies both canonical NEAR slashing conditions (double-vote at identical
//!    `target_height` and surround-vote `s_1 < s_2 < t_2 < t_1`).

//!
//! WIRING: implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`; `AdapterSpec` joins `intake.rs` in the follow-up merge.

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

/// Canonical adapter identifier for NEAR Nightshade / Doomslug finality.
pub const ADAPTER_NAME: &str = "near-doomslug-v1";
/// Adapter implementation version.
pub const ADAPTER_VERSION: u32 = 1;
/// Accepted wire evidence version.
pub const EVIDENCE_VERSION: u32 = 1;
/// Finality depth of the consecutive `(B, B_1, B_2)` + `approvals_after_next` rule.
pub const DOOMSLUG_BFT_DEPTH: u64 = 3;
/// Hard ceiling on active block producers per NEAR epoch.
pub const MAX_NEAR_BLOCK_PRODUCERS: usize = 256;

const PAYLOAD_MAGIC: &[u8; 8] = b"NEARDSV1";
const MAX_NEAR_PAYLOAD_BYTES: usize = 512 * 1024;
const BP_SET_TAG: &[u8] = b"bud-near-ds-bpset-v1";
const INNER_LITE_TAG: &[u8] = b"bud-near-ds-lite-v1";
const BLOCK_HASH_TAG: &[u8] = b"bud-near-ds-block-v1";
const APPROVAL_TAG: &[u8] = b"bud-near-ds-approval-v1";

/// One staked NEAR block producer (`ValidatorStakeView` equivalent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearBlockProducer {
    /// Canonical NEAR account identifier (e.g. `"figment.poolv1.near"`).
    pub account_id: String,
    /// Ed25519 verifying key (32 bytes).
    pub ed25519_pubkey: [u8; 32],
    /// Non-zero staked yoctoNEAR weight (`u128` native in NEAR consensus).
    pub stake: u128,
    /// Optional NIST ML-DSA-65 public key; mandatory co-sig when non-empty.
    #[serde(default)]
    pub pq_pubkey: Vec<u8>,
}

/// Governance-pinned (or epoch-rotated) NEAR epoch validator state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedNearEpoch {
    /// Active epoch identifier (`B_2.epoch_id`).
    pub epoch_id: Hash32,
    /// Scheduled successor epoch identifier (`B.next_epoch_id`).
    pub next_epoch_id: Hash32,
    /// Committed hash of the successor epoch's block-producer table.
    pub next_bp_hash: Hash32,
    /// Active block producers serving `epoch_id`.
    pub block_producers: Vec<NearBlockProducer>,
}

/// Canonical commitment `next_bp_hash` over an ordered NEAR block-producer list,
/// binding account IDs, Ed25519 keys, `u128` stakes, and PQ key commitments.
#[must_use]
pub fn compute_near_bp_hash(producers: &[NearBlockProducer]) -> Hash32 {
    let mut parts: Vec<Vec<u8>> = Vec::with_capacity(producers.len().saturating_mul(4) + 2);
    parts.push(BP_SET_TAG.to_vec());
    parts.push((producers.len() as u64).to_le_bytes().to_vec());
    for bp in producers {
        parts.push(bp.account_id.as_bytes().to_vec());
        parts.push(bp.ed25519_pubkey.to_vec());
        parts.push(bp.stake.to_le_bytes().to_vec());
        parts.push(bp.pq_pubkey.clone());
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    crate::core::hash::hash_fields_bytes(&refs)
}

/// NEAR light-client block header (`BlockHeaderInnerLiteView` + link hashes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearLightHeader {
    /// Block height in NEAR slots.
    pub height: u64,
    /// Epoch governing this block's validator set.
    pub epoch_id: Hash32,
    /// Next epoch identifier committed in the header.
    pub next_epoch_id: Hash32,
    /// Parent block hash.
    pub prev_hash: Hash32,
    /// Aggregate shard state root (`prev_state_root`).
    pub state_root: Hash32,
    /// Aggregate execution/receipt outcome Merkle root (`outcome_root`).
    pub outcome_root: Hash32,
    /// Canonical chunk transaction Merkle root (`block_merkle_root`).
    pub block_merkle_root: Hash32,
    /// Commitment to `next_epoch_id`'s block-producer list (`next_bp_hash`).
    pub next_bp_hash: Hash32,
    /// Hash of remaining header fields (`inner_rest_hash`).
    pub inner_rest_hash: Hash32,
    /// Highest Doomslug-final block hash recorded by this header.
    pub last_ds_final_block: Hash32,
    /// Highest Nightshade-BFT-final block hash recorded by this header.
    pub last_final_block: Hash32,
    /// Nanosecond block timestamp.
    pub timestamp_ns: u64,
    /// Self-derived canonical block hash.
    pub block_hash: Hash32,
}

impl NearLightHeader {
    /// Derive the canonical NEAR light-client `block_hash` bound to `network`.
    #[must_use]
    pub fn compute_block_hash(&self, network: &str) -> Hash32 {
        let inner_lite = crate::core::hash::hash_fields_bytes(&[
            INNER_LITE_TAG,
            network.as_bytes(),
            &self.height.to_le_bytes(),
            &self.epoch_id,
            &self.next_epoch_id,
            &self.state_root,
            &self.outcome_root,
            &self.timestamp_ns.to_le_bytes(),
            &self.next_bp_hash,
            &self.block_merkle_root,
            &self.last_ds_final_block,
            &self.last_final_block,
        ]);
        let inner_combined = crate::core::hash::hash_fields_bytes(&[
            BLOCK_HASH_TAG,
            &inner_lite,
            &self.inner_rest_hash,
        ]);
        crate::core::hash::hash_fields_bytes(&[BLOCK_HASH_TAG, &inner_combined, &self.prev_hash])
    }
}

/// NEAR Doomslug `ApprovalInner` distinguishing direct endorsements from skips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NearApprovalInner {
    /// Direct endorsement of `parent_hash` minted at `parent_height`.
    Endorsement {
        /// Hash of the directly endorsed parent block.
        parent_hash: Hash32,
        /// Height of `parent_hash` (enables stateless surround-slash verification).
        parent_height: u64,
    },
    /// Skip approval starting from `source_height` after timeout.
    Skip {
        /// Height of the block from which the skip timer originated.
        source_height: u64,
    },
}

impl NearApprovalInner {
    const fn reference_height(&self) -> u64 {
        match *self {
            Self::Endorsement { parent_height, .. } => parent_height,
            Self::Skip { source_height } => source_height,
        }
    }
}

/// Canonical domain-separated signing digest for a NEAR Doomslug approval.
#[must_use]
pub fn near_approval_sign_bytes(
    network: &str,
    epoch_id: &Hash32,
    inner: &NearApprovalInner,
    target_height: u64,
) -> Hash32 {
    match inner {
        NearApprovalInner::Endorsement {
            parent_hash,
            parent_height,
        } => crate::core::hash::hash_fields_bytes(&[
            APPROVAL_TAG,
            network.as_bytes(),
            epoch_id,
            &[0x00],
            parent_hash,
            &parent_height.to_le_bytes(),
            &target_height.to_le_bytes(),
        ]),
        NearApprovalInner::Skip { source_height } => crate::core::hash::hash_fields_bytes(&[
            APPROVAL_TAG,
            network.as_bytes(),
            epoch_id,
            &[0x01],
            &source_height.to_le_bytes(),
            &target_height.to_le_bytes(),
        ]),
    }
}

/// One validator's signature inside `approvals_after_next`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearApprovalSig {
    /// Signing block producer's Ed25519 verifying key.
    pub signer_pubkey: [u8; 32],
    /// Ed25519 signature over [`near_approval_sign_bytes`].
    pub ed25519_sig: Vec<u8>,
    /// Mandatory ML-DSA-65 co-signature when the producer has a `pq_pubkey`.
    #[serde(default)]
    pub pq_sig: Vec<u8>,
}

/// Wire payload carrying the finalized 3-block NEAR light-client bundle
/// `(final_block, ds_next_block, after_next_block)` plus `approvals_after_next`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NearDoomslugEvidence {
    final_block: NearLightHeader,
    ds_next_block: NearLightHeader,
    after_next_block: NearLightHeader,
    approval_target_height: u64,
    approvals_after_next: Vec<NearApprovalSig>,
}

/// Encode a NEAR Doomslug/Nightshade finality bundle into its wire payload.
///
/// # Errors
///
/// Returns an error if serialization fails or exceeds `MAX_NEAR_PAYLOAD_BYTES`.
///
/// Convenience: exposed for external NEAR Doomslug relayer encoders.
pub fn encode_near_doomslug_evidence(
    final_block: NearLightHeader,
    ds_next_block: NearLightHeader,
    after_next_block: NearLightHeader,
    approval_target_height: u64,
    approvals_after_next: Vec<NearApprovalSig>,
) -> Result<Vec<u8>, String> {
    let bundle = NearDoomslugEvidence {
        final_block,
        ds_next_block,
        after_next_block,
        approval_target_height,
        approvals_after_next,
    };
    let body =
        bincode::serialize(&bundle).map_err(|e| format!("NEAR Doomslug encode failed: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_NEAR_PAYLOAD_BYTES {
        return Err(format!(
            "NEAR Doomslug payload {total} exceeds ceiling {MAX_NEAR_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_near_doomslug_evidence(payload: &[u8]) -> Result<NearDoomslugEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "NEAR Doomslug payload shorter than 8-byte magic".into(),
        });
    }
    if payload.len() > MAX_NEAR_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_NEAR_PAYLOAD_BYTES,
            reason: format!("NEAR Doomslug payload exceeds {MAX_NEAR_PAYLOAD_BYTES} bytes"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "NEAR Doomslug payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing NEAR Doomslug body".into(),
    })?;
    let decoded: NearDoomslugEvidence =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_NEAR_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("invalid NEAR Doomslug evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical NEAR Doomslug evidence".into(),
        });
    }
    Ok(decoded)
}

fn validate_bp_table(
    producers: &[NearBlockProducer],
) -> Result<(BTreeMap<[u8; 32], &NearBlockProducer>, u128), AdapterError> {
    if producers.is_empty() || producers.len() > MAX_NEAR_BLOCK_PRODUCERS {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR block_producers count outside valid bounds".into(),
        });
    }
    let mut by_key = BTreeMap::new();
    let mut accounts = BTreeSet::new();
    let mut total_stake = 0u128;
    for bp in producers {
        if bp.account_id.is_empty()
            || bp.account_id.len() > 64
            || bp.account_id.chars().any(char::is_control)
            || bp.ed25519_pubkey == [0u8; 32]
            || bp.stake == 0
        {
            return Err(AdapterError::ConsensusRule {
                rule: "NEAR block producer has invalid account_id, zero pubkey, or zero stake"
                    .into(),
            });
        }
        if !accounts.insert(bp.account_id.as_str()) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate NEAR account_id in block_producers".into(),
            });
        }
        if by_key.insert(bp.ed25519_pubkey, bp).is_some() {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate Ed25519 pubkey in NEAR block_producers".into(),
            });
        }
        total_stake =
            total_stake
                .checked_add(bp.stake)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "NEAR epoch total stake overflows u128".into(),
                })?;
    }
    Ok((by_key, total_stake))
}

/// Overflow-free strict `signed_stake * 3 > total_stake * 2` check across `u128`.
const fn exceeds_two_thirds(signed_stake: u128, total_stake: u128) -> bool {
    if total_stake == 0 || signed_stake > total_stake {
        return false;
    }
    let q = total_stake / 3;
    let r = total_stake % 3;
    let two_thirds_floor = q.saturating_mul(2).saturating_add((r * 2) / 3);
    signed_stake > two_thirds_floor
}

fn verify_doomslug_bundle(
    network: &str,
    pinned: &PinnedNearEpoch,
    bundle: &NearDoomslugEvidence,
) -> Result<(u64, u64, u128, bool), AdapterError> {
    if pinned.epoch_id == [0u8; 32]
        || pinned.next_epoch_id == [0u8; 32]
        || pinned.next_bp_hash == [0u8; 32]
        || bool::from(
            pinned
                .epoch_id
                .as_slice()
                .ct_eq(pinned.next_epoch_id.as_slice()),
        )
    {
        return Err(AdapterError::ConsensusRule {
            rule: "pinned NEAR epoch has zero or self-referential epoch identifiers".into(),
        });
    }
    let (bp_map, total_stake) = validate_bp_table(&pinned.block_producers)?;

    let b0 = &bundle.final_block;
    let b1 = &bundle.ds_next_block;
    let b2 = &bundle.after_next_block;

    if b0.height == 0 || b0.state_root == [0u8; 32] || b0.prev_hash == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR final_block has zero height, zero state_root, or zero prev_hash".into(),
        });
    }

    // 1. Epoch identity, next_bp_hash consistency, and self-derived block hashes.
    for (label, hdr) in [
        ("final_block", b0),
        ("ds_next_block", b1),
        ("after_next_block", b2),
    ] {
        if !bool::from(hdr.epoch_id.as_slice().ct_eq(pinned.epoch_id.as_slice()))
            || !bool::from(
                hdr.next_epoch_id
                    .as_slice()
                    .ct_eq(pinned.next_epoch_id.as_slice()),
            )
            || !bool::from(
                hdr.next_bp_hash
                    .as_slice()
                    .ct_eq(pinned.next_bp_hash.as_slice()),
            )
        {
            return Err(AdapterError::ConsensusRule {
                rule: format!("NEAR {label} epoch_id/next_epoch_id/next_bp_hash mismatch"),
            });
        }
        let expected = hdr.compute_block_hash(network);
        if !bool::from(hdr.block_hash.as_slice().ct_eq(expected.as_slice())) {
            return Err(AdapterError::ConsensusRule {
                rule: format!("NEAR {label} block_hash mismatches canonical inner_lite digest"),
            });
        }
    }

    // 2. Doomslug consecutive 3-chain & finality pointer invariants:
    //    B0 (h) <- B1 (h+1, last_ds_final=B0) <- B2 (h+2, last_final=B0, last_ds_final=B1).
    let Some(h1) = b0.height.checked_add(1) else {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR final_block height overflows u64".into(),
        });
    };
    let Some(h2) = h1.checked_add(1) else {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR ds_next_block height overflows u64".into(),
        });
    };
    let Some(expected_target) = h2.checked_add(1) else {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR after_next_block height overflows u64".into(),
        });
    };
    if b1.height != h1 || b2.height != h2 {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR Doomslug light-client headers are not strictly consecutive (h, h+1, h+2)"
                .into(),
        });
    }
    if bundle.approval_target_height != expected_target {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR approvals_after_next target_height must equal B2.height + 1".into(),
        });
    }
    if b1.timestamp_ns < b0.timestamp_ns || b2.timestamp_ns < b1.timestamp_ns {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR Doomslug header timestamps regress across (B0, B1, B2)".into(),
        });
    }
    if !bool::from(b1.prev_hash.as_slice().ct_eq(b0.block_hash.as_slice()))
        || !bool::from(b2.prev_hash.as_slice().ct_eq(b1.block_hash.as_slice()))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR Doomslug prev_hash chain broken across (B0, B1, B2)".into(),
        });
    }
    if !bool::from(
        b1.last_ds_final_block
            .as_slice()
            .ct_eq(b0.block_hash.as_slice()),
    ) || !bool::from(
        b2.last_ds_final_block
            .as_slice()
            .ct_eq(b1.block_hash.as_slice()),
    ) || !bool::from(
        b2.last_final_block
            .as_slice()
            .ct_eq(b0.block_hash.as_slice()),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule:
                "NEAR last_ds_final_block / last_final_block pointers violate Nightshade BFT rule"
                    .into(),
        });
    }

    // 3. Verify `approvals_after_next` > 2/3 epoch stake over Endorsement(B2, h2 -> h2+1).
    if bundle.approvals_after_next.is_empty()
        || bundle.approvals_after_next.len() > MAX_NEAR_BLOCK_PRODUCERS
    {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR approvals_after_next signature count outside valid bounds".into(),
        });
    }
    let approval_inner = NearApprovalInner::Endorsement {
        parent_hash: b2.block_hash,
        parent_height: b2.height,
    };
    let sign_digest = near_approval_sign_bytes(
        network,
        &pinned.epoch_id,
        &approval_inner,
        bundle.approval_target_height,
    );

    let mut seen_signers = BTreeSet::new();
    let mut signed_stake = 0u128;
    let mut all_pq = true;

    for approval in &bundle.approvals_after_next {
        if !seen_signers.insert(approval.signer_pubkey) {
            return Err(AdapterError::ConsensusRule {
                rule: "duplicate validator approval in NEAR approvals_after_next".into(),
            });
        }
        let Some(bp) = bp_map.get(&approval.signer_pubkey) else {
            return Err(AdapterError::ConsensusRule {
                rule: "unknown block producer signed NEAR approvals_after_next".into(),
            });
        };
        crate::crypto::primitives::verify_signature(
            &sign_digest,
            &approval.ed25519_sig,
            &approval.signer_pubkey,
        )
        .map_err(|_| AdapterError::Crypto {
            what: "invalid Ed25519 approval signature in NEAR approvals_after_next".into(),
        })?;

        if bp.pq_pubkey.is_empty() {
            all_pq = false;
        } else {
            if approval.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: "missing mandatory ML-DSA-65 co-signature for PQ-enrolled NEAR producer"
                        .into(),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &bp.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &sign_digest,
                &approval.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "invalid ML-DSA-65 co-signature in NEAR approvals_after_next".into(),
            })?;
        }
        signed_stake =
            signed_stake
                .checked_add(bp.stake)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "NEAR signed approval stake overflows u128".into(),
                })?;
    }

    if !exceeds_two_thirds(signed_stake, total_stake) {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "NEAR approvals_after_next stake {signed_stake}/{total_stake} does not exceed 2/3"
            ),
        });
    }

    let required = ((pinned.block_producers.len() as u64) * 2)
        .div_ceil(3)
        .max(1);
    Ok((seen_signers.len() as u64, required, total_stake, all_pq))
}

/// Rotate a [`PinnedNearEpoch`] to `pinned.next_epoch_id` after verifying both
/// a finalized block bundle in `pinned.epoch_id` AND that `proposed_next_bps`
/// hashes to `final_block.next_bp_hash` in constant time.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the finality bundle fails, `proposed_next_bps`
/// is invalid or mismatches `next_bp_hash`, or the successor metadata is zero.
pub fn advance_near_epoch(
    network: &str,
    pinned: &PinnedNearEpoch,
    finality_payload: &[u8],
    proposed_next_bps: Vec<NearBlockProducer>,
    following_epoch_id: Hash32,
    following_next_bp_hash: Hash32,
) -> Result<PinnedNearEpoch, AdapterError> {
    if following_epoch_id == [0u8; 32]
        || following_next_bp_hash == [0u8; 32]
        || bool::from(
            following_epoch_id
                .as_slice()
                .ct_eq(pinned.next_epoch_id.as_slice()),
        )
    {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR epoch rotation carries zero or self-referential following epoch ID".into(),
        });
    }
    let bundle = decode_near_doomslug_evidence(finality_payload)?;
    verify_doomslug_bundle(network, pinned, &bundle)?;
    validate_bp_table(&proposed_next_bps)?;
    let computed_bp_hash = compute_near_bp_hash(&proposed_next_bps);
    if !bool::from(
        computed_bp_hash
            .as_slice()
            .ct_eq(bundle.final_block.next_bp_hash.as_slice()),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "proposed NEAR block_producers hash mismatches finalized next_bp_hash".into(),
        });
    }
    Ok(PinnedNearEpoch {
        epoch_id: pinned.next_epoch_id,
        next_epoch_id: following_epoch_id,
        next_bp_hash: following_next_bp_hash,
        block_producers: proposed_next_bps,
    })
}

/// Slashable NEAR Doomslug approval violation classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NearSlashKind {
    /// Two distinct `ApprovalInner` values signed for the same `target_height`.
    DoubleApproval,
    /// Outer approval `(s_outer, t_outer)` strictly surrounds `(s_inner, t_inner)`
    /// (`s_outer < s_inner` and `t_inner < t_outer`).
    SurroundApproval,
}

/// Cryptographic proof of a slashable NEAR Doomslug approval violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NearApprovalSlashProof {
    /// First signed approval body.
    pub inner_a: NearApprovalInner,
    /// Target height of the first approval.
    pub target_a: u64,
    /// Signature over `(inner_a, target_a)`.
    pub sig_a: NearApprovalSig,
    /// Second signed approval body.
    pub inner_b: NearApprovalInner,
    /// Target height of the second approval.
    pub target_b: u64,
    /// Signature over `(inner_b, target_b)` by the same producer.
    pub sig_b: NearApprovalSig,
}

/// Verify a [`NearApprovalSlashProof`] against `pinned`, returning the guilty
/// producer's account ID, staked weight, and violation kind.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the signer is unknown, signatures fail, or
/// the pair of approvals is legal under Doomslug rules.
pub fn verify_near_approval_slash(
    network: &str,
    pinned: &PinnedNearEpoch,
    proof: &NearApprovalSlashProof,
) -> Result<(String, u128, NearSlashKind), AdapterError> {
    let (bp_map, _) = validate_bp_table(&pinned.block_producers)?;
    if !bool::from(
        proof
            .sig_a
            .signer_pubkey
            .as_slice()
            .ct_eq(proof.sig_b.signer_pubkey.as_slice()),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR approval slash proof references two different signers".into(),
        });
    }
    let Some(bp) = bp_map.get(&proof.sig_a.signer_pubkey) else {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR approval slash signer is not an active epoch block producer".into(),
        });
    };
    let sa = proof.inner_a.reference_height();
    let sb = proof.inner_b.reference_height();
    if sa >= proof.target_a || sb >= proof.target_b {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR approval has reference height >= target height".into(),
        });
    }

    let kind = if proof.target_a == proof.target_b && proof.inner_a != proof.inner_b {
        NearSlashKind::DoubleApproval
    } else if (sa < sb && proof.target_b < proof.target_a)
        || (sb < sa && proof.target_a < proof.target_b)
    {
        NearSlashKind::SurroundApproval
    } else {
        return Err(AdapterError::ConsensusRule {
            rule: "NEAR approval pair satisfies Doomslug monotonicity (not slashable)".into(),
        });
    };

    for (inner, target, sig) in [
        (&proof.inner_a, proof.target_a, &proof.sig_a),
        (&proof.inner_b, proof.target_b, &proof.sig_b),
    ] {
        let digest = near_approval_sign_bytes(network, &pinned.epoch_id, inner, target);
        crate::crypto::primitives::verify_signature(&digest, &sig.ed25519_sig, &sig.signer_pubkey)
            .map_err(|_| AdapterError::Crypto {
                what: "invalid Ed25519 signature in NEAR approval slash proof".into(),
            })?;
        if !bp.pq_pubkey.is_empty() {
            if sig.pq_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: "missing ML-DSA-65 co-signature in NEAR approval slash proof".into(),
                });
            }
            crate::crypto::primitives::PqKeyPair::verify(
                &bp.pq_pubkey,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &digest,
                &sig.pq_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "invalid ML-DSA-65 co-signature in NEAR approval slash proof".into(),
            })?;
        }
    }

    Ok((bp.account_id.clone(), bp.stake, kind))
}

/// External finality adapter for NEAR `Nightshade` + `Doomslug` BFT consensus.
pub struct NearDoomslugAdapter {
    network: String,
    pinned: Option<PinnedNearEpoch>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl NearDoomslugAdapter {
    /// Construct a [`NearDoomslugAdapter`] bound to `network` and `pinned`.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedNearEpoch>) -> Self {
        let set_size = pinned
            .as_ref()
            .map_or(0, |p| p.block_producers.len() as u64);
        Self {
            network: network.into(),
            pinned,
            golden: None,
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(ADAPTER_NAME),
                name: ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "near-nightshade-doomslug-bft".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                required_depth: DOOMSLUG_BFT_DEPTH,
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
                    "NEAR Doomslug network '{}' mismatches pinned '{}'",
                    evidence.network, self.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no pinned NEAR epoch; admission is closed".into(),
            });
        };

        let bundle = decode_near_doomslug_evidence(&evidence.payload)?;
        let b0 = &bundle.final_block;
        if policy.require_declared_match {
            if evidence.declared_height != b0.height {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(
                evidence
                    .declared_root
                    .as_slice()
                    .ct_eq(b0.state_root.as_slice()),
            ) {
                return Err(AdapterError::DeclarationMismatch { field: "root" });
            }
        }
        if policy.min_depth > DOOMSLUG_BFT_DEPTH {
            return Err(AdapterError::InsufficientDepth {
                observed: DOOMSLUG_BFT_DEPTH,
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

        let (signers, required, total_weight, all_pq) =
            verify_doomslug_bundle(&self.network, pinned, &bundle)?;
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
            finalized_at: bundle.after_next_block.height,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme,
                signers,
                required,
                total_weight,
                slashable: true,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(b0.block_hash),
            attested_event_root: Some(b0.outcome_root),
            attested_tx_root: Some(b0.block_merkle_root),
        };
        Ok((attestation, all_pq))
    }
}

impl ExternalFinalityAdapter for NearDoomslugAdapter {
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
            .map_or(64, |g| g.payload.len().saturating_sub(24));
        vec![
            FaultProbe {
                name: "refuses unsupported NEAR Doomslug evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 99 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses mismatched NEAR network ID".into(),
                patch: BytePatch::Network {
                    value: "near-testnet-wrong".into(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted NEARDSV1 magic header".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"NOTNEARD".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses truncated NEAR Doomslug payload".into(),
                patch: BytePatch::TruncatePayload { keep: 14 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses tampered final_block height inside header".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xEE; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses lied declared NEAR height".into(),
                patch: BytePatch::DeclaredHeight { value: 1 },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses lied declared NEAR state_root".into(),
                patch: BytePatch::DeclaredRoot { value: [0x99; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted approval signature bytes".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![0xAA, 0x55, 0xAA, 0x55],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
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
    use crate::cross_domain::external::selftest;
    use crate::crypto::primitives::{KeyPair, PqKeyPair};

    const NET: &str = "near-mainnet";

    struct NearFixture {
        pinned: PinnedNearEpoch,
        ed_keys: Vec<KeyPair>,
        pq_keys: Vec<PqKeyPair>,
        next_bps: Vec<NearBlockProducer>,
        b0: NearLightHeader,
        b1: NearLightHeader,
        b2: NearLightHeader,
        golden: RawConsensusEvidence,
    }

    fn make_header(
        height: u64,
        epoch_id: Hash32,
        next_epoch_id: Hash32,
        next_bp_hash: Hash32,
        prev_hash: Hash32,
        last_ds_final: Hash32,
        last_final: Hash32,
        seed: u8,
    ) -> NearLightHeader {
        let mut h = NearLightHeader {
            height,
            epoch_id,
            next_epoch_id,
            prev_hash,
            state_root: [seed; 32],
            outcome_root: [seed.wrapping_add(0x10); 32],
            block_merkle_root: [seed.wrapping_add(0x20); 32],
            next_bp_hash,
            inner_rest_hash: [seed.wrapping_add(0x30); 32],
            last_ds_final_block: last_ds_final,
            last_final_block: last_final,
            timestamp_ns: 1_730_000_000_000_000_000 + height * 600_000_000,
            block_hash: [0u8; 32],
        };
        h.block_hash = h.compute_block_hash(NET);
        h
    }

    fn sign_approval(
        ed: &KeyPair,
        pq: &PqKeyPair,
        epoch_id: &Hash32,
        inner: &NearApprovalInner,
        target_height: u64,
    ) -> NearApprovalSig {
        let digest = near_approval_sign_bytes(NET, epoch_id, inner, target_height);
        NearApprovalSig {
            signer_pubkey: ed.public_key_bytes(),
            ed25519_sig: ed.sign(&digest).try_into().unwrap(),
            pq_sig: pq
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &digest)
                .expect("ML-DSA-65 sign"),
        }
    }

    fn build_near_fixture() -> NearFixture {
        let ed_keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate().unwrap()).collect();
        let pq_keys: Vec<PqKeyPair> = (0..4).map(|_| PqKeyPair::generate()).collect();
        let stakes = [300u128, 250, 250, 200]; // total = 1000; first 3 = 800 > 666

        let bps: Vec<NearBlockProducer> = (0..4)
            .map(|i| NearBlockProducer {
                account_id: format!("bp{i}.poolv1.near"),
                ed25519_pubkey: ed_keys[i].public_key_bytes(),
                stake: stakes[i],
                pq_pubkey: pq_keys[i].public_key_bytes().to_vec(),
            })
            .collect();

        let next_ed = KeyPair::generate().unwrap();
        let next_pq = PqKeyPair::generate();
        let next_bps = vec![NearBlockProducer {
            account_id: "next0.poolv1.near".into(),
            ed25519_pubkey: next_ed.public_key_bytes(),
            stake: 5_000,
            pq_pubkey: next_pq.public_key_bytes().to_vec(),
        }];
        let next_bp_hash = compute_near_bp_hash(&next_bps);

        let epoch_id = [0xE1; 32];
        let next_epoch_id = [0xE2; 32];
        let pinned = PinnedNearEpoch {
            epoch_id,
            next_epoch_id,
            next_bp_hash,
            block_producers: bps,
        };

        let b0 = make_header(
            130_000_000,
            epoch_id,
            next_epoch_id,
            next_bp_hash,
            [0x01; 32],
            [0x01; 32],
            [0x02; 32],
            0x41,
        );
        let b1 = make_header(
            130_000_001,
            epoch_id,
            next_epoch_id,
            next_bp_hash,
            b0.block_hash,
            b0.block_hash,
            [0x01; 32],
            0x42,
        );
        let b2 = make_header(
            130_000_002,
            epoch_id,
            next_epoch_id,
            next_bp_hash,
            b1.block_hash,
            b1.block_hash,
            b0.block_hash,
            0x43,
        );

        let inner = NearApprovalInner::Endorsement {
            parent_hash: b2.block_hash,
            parent_height: b2.height,
        };
        let target = b2.height + 1;
        let approvals: Vec<NearApprovalSig> = (0..3)
            .map(|i| sign_approval(&ed_keys[i], &pq_keys[i], &epoch_id, &inner, target))
            .collect();

        let payload =
            encode_near_doomslug_evidence(b0.clone(), b1.clone(), b2.clone(), target, approvals)
                .unwrap();
        let golden = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            network: NET.into(),
            evidence_version: EVIDENCE_VERSION,
            declared_height: b0.height,
            declared_root: b0.state_root,
            payload,
            submitter: Address::from([0x21; 32]),
        };

        NearFixture {
            pinned,
            ed_keys,
            pq_keys,
            next_bps,
            b0,
            b1,
            b2,
            golden,
        }
    }

    #[test]
    fn near_doomslug_passes_selftest_admission_and_rotates_next_bp_hash_epoch() {
        let fx = build_near_fixture();
        let adapter =
            NearDoomslugAdapter::new(NET, Some(fx.pinned.clone())).with_golden(fx.golden.clone());
        let policy = VerificationPolicy {
            require_slashable: true,
            min_depth: DOOMSLUG_BFT_DEPTH,
            max_age: 100,
            now: 130_000_010,
            require_declared_match: true,
        };

        let report = selftest::admit(&adapter, &policy);
        assert!(
            report.admitted,
            "NEAR Doomslug admission failed: {report:?}"
        );
        assert_eq!(report.passed(), adapter.fault_probes().len());

        let att = adapter.verify(&fx.golden, &policy).expect("verify golden");
        assert_eq!(att.height, 130_000_000);
        assert_eq!(att.finalized_at, 130_000_002);
        assert_eq!(att.state_root, fx.b0.state_root);
        assert_eq!(att.attested_event_root, Some(fx.b0.outcome_root));
        assert_eq!(att.attested_tx_root, Some(fx.b0.block_merkle_root));
        assert_eq!(att.attested_block_hash, Some(fx.b0.block_hash));

        // Forged next_bps must be rejected on epoch rotation.
        let mut wrong_next = fx.next_bps.clone();
        wrong_next[0].stake += 1;
        assert!(advance_near_epoch(
            NET,
            &fx.pinned,
            &fx.golden.payload,
            wrong_next,
            [0xE3; 32],
            [0xB3; 32],
        )
        .is_err());

        // Authentic next_bps matching committed next_bp_hash rotates cleanly!
        let rotated = advance_near_epoch(
            NET,
            &fx.pinned,
            &fx.golden.payload,
            fx.next_bps.clone(),
            [0xE3; 32],
            [0xB3; 32],
        )
        .expect("rotate NEAR epoch");
        assert_eq!(rotated.epoch_id, [0xE2; 32]);
        assert_eq!(rotated.next_epoch_id, [0xE3; 32]);
        assert_eq!(rotated.block_producers, fx.next_bps);
    }

    #[test]
    fn near_doomslug_refuses_stripped_pq_sig_subquorum_and_verifies_double_and_surround_slashes() {
        let fx = build_near_fixture();
        let adapter = NearDoomslugAdapter::new(NET, Some(fx.pinned.clone()));
        let policy = VerificationPolicy {
            require_slashable: true,
            min_depth: 1,
            max_age: 0,
            now: 0,
            require_declared_match: true,
        };
        let inner = NearApprovalInner::Endorsement {
            parent_hash: fx.b2.block_hash,
            parent_height: fx.b2.height,
        };
        let target = fx.b2.height + 1;

        // 1. Strip ML-DSA-65 co-signature on PQ-enrolled validator => Crypto refusal!
        let mut stripped: Vec<NearApprovalSig> = (0..3)
            .map(|i| {
                sign_approval(
                    &fx.ed_keys[i],
                    &fx.pq_keys[i],
                    &fx.pinned.epoch_id,
                    &inner,
                    target,
                )
            })
            .collect();
        stripped[1].pq_sig.clear();
        let stripped_ev = RawConsensusEvidence {
            payload: encode_near_doomslug_evidence(
                fx.b0.clone(),
                fx.b1.clone(),
                fx.b2.clone(),
                target,
                stripped,
            )
            .unwrap(),
            ..fx.golden.clone()
        };
        assert!(matches!(
            adapter.verify(&stripped_ev, &policy),
            Err(AdapterError::Crypto { .. })
        ));

        // 2. Sub-supermajority stake (300 + 250 = 550 / 1000 <= 2/3) => refused!
        let sub_sigs: Vec<NearApprovalSig> = (0..2)
            .map(|i| {
                sign_approval(
                    &fx.ed_keys[i],
                    &fx.pq_keys[i],
                    &fx.pinned.epoch_id,
                    &inner,
                    target,
                )
            })
            .collect();
        let sub_ev = RawConsensusEvidence {
            payload: encode_near_doomslug_evidence(
                fx.b0.clone(),
                fx.b1.clone(),
                fx.b2.clone(),
                target,
                sub_sigs,
            )
            .unwrap(),
            ..fx.golden.clone()
        };
        assert!(matches!(
            adapter.verify(&sub_ev, &policy),
            Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("2/3")
        ));

        // 3. Double-approval slash at same target_height!
        let fork_inner = NearApprovalInner::Endorsement {
            parent_hash: [0xDD; 32],
            parent_height: fx.b2.height,
        };
        let double_proof = NearApprovalSlashProof {
            inner_a: inner,
            target_a: target,
            sig_a: sign_approval(
                &fx.ed_keys[0],
                &fx.pq_keys[0],
                &fx.pinned.epoch_id,
                &inner,
                target,
            ),
            inner_b: fork_inner,
            target_b: target,
            sig_b: sign_approval(
                &fx.ed_keys[0],
                &fx.pq_keys[0],
                &fx.pinned.epoch_id,
                &fork_inner,
                target,
            ),
        };
        let (acct, stake, kind) =
            verify_near_approval_slash(NET, &fx.pinned, &double_proof).expect("double approval");
        assert_eq!(acct, "bp0.poolv1.near");
        assert_eq!(stake, 300);
        assert_eq!(kind, NearSlashKind::DoubleApproval);

        // 4. Surround-approval slash: Skip(100 -> 110) surrounds Endorsement(103 -> 104)!
        let outer = NearApprovalInner::Skip { source_height: 100 };
        let surrounded = NearApprovalInner::Endorsement {
            parent_hash: [0xCC; 32],
            parent_height: 103,
        };
        let surround_proof = NearApprovalSlashProof {
            inner_a: outer,
            target_a: 110,
            sig_a: sign_approval(
                &fx.ed_keys[2],
                &fx.pq_keys[2],
                &fx.pinned.epoch_id,
                &outer,
                110,
            ),
            inner_b: surrounded,
            target_b: 104,
            sig_b: sign_approval(
                &fx.ed_keys[2],
                &fx.pq_keys[2],
                &fx.pinned.epoch_id,
                &surrounded,
                104,
            ),
        };
        let (acct2, stake2, kind2) =
            verify_near_approval_slash(NET, &fx.pinned, &surround_proof).expect("surround slash");
        assert_eq!(acct2, "bp2.poolv1.near");
        assert_eq!(stake2, 250);
        assert_eq!(kind2, NearSlashKind::SurroundApproval);
    }
}
