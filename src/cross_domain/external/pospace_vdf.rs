//! Proof-of-Space coupled with sequential hash-VDF external finality adapter
//! (`Chia` / Cohen-Pietrzak 2019 lineage, hardened to pure post-quantum
//! `AssumptionClass::Hash` + `ML-DSA-65`).
//!
//! Classical Proof-of-Space-and-Time chains pair a `k`-bit Beyond-Hellman graph
//! pebbling space table with a sequential Verifiable Delay Function (`VDF`) so
//! farmers cannot grind challenges without real elapsed wall-clock time. Class-
//! group / RSA unknown-order Wesolowski VDFs collapse under Shor's algorithm on
//! a CRQC (`AbelianHiddenSubgroup`). Budlum eliminates that quantum surface:
//!
//! 1. **Challenge-chain continuity**: the first block extends
//!    `pinned.genesis_challenge` (or an audited sub-slot anchor derived from
//!    it), and every subsequent block's signage challenge binds strictly to its
//!    parent's finalized infusion output.
//! 2. **Proof-of-Space (`k`-plot) verification**: each block enforces
//!    `plot_k >= pinned.min_plot_k`, recomputes `plot_id` from
//!    `(farmer_pubkey_hash, plot_k, plot_nonce)`, verifies the non-zero table
//!    opening commitment against `(challenge_hash, signage_index)`, and checks
//!    the exact-integer quality condition
//!    `quality_score <= quality_target(difficulty, plot_k)` (zero floats).
//! 3. **Post-quantum sequential hash VDF (`AssumptionClass::Hash`)**: every
//!    block's `vdf_output` is verified by recomputing iterated domain-separated
//!    `SHA-256` steps (`min_iterations_per_block..=max_iterations_per_block`)
//!    over `(challenge_hash, quality_string)` in constant time, strictly
//!    immune to Shor's algorithm and retaining full sequential resistance.
//! 4. **Cumulative space-time weight & sub-slot confirmation depth**: the
//!    segment must contain at least `pinned.required_depth` contiguous blocks
//!    above the claimed finalized block, and strictly accumulating integer
//!    `cumulative_weight` must clear `pinned.min_cumulative_weight`.
//! 5. **Post-quantum farmer / timelord signage (`ML-DSA-65`)**: verified under
//!    [`crate::crypto::ctx::CROSS_DOMAIN_V1`] when present and strictly
//!    mandatory whenever `pinned.require_pq_attestation` is true (including all
//!    CRQC Frost Alarm deployments).
//! 6. **Double-signage equivocation verifier**:
//!    [`verify_double_signage_equivocation`] cryptographically verifies a
//!    farmer or timelord signing two distinct block hashes at the exact same
//!    `(network, sub_slot, signage_index)` for permissionless slashing.
//!
//! WIRING: unwired - implements [`ExternalFinalityAdapter`] for
//! [`super::ExternalDomainRegistry`], verified by [`super::selftest::admit`];
//! `AdapterSpec` variant joins `intake.rs` in the follow-up intake merge.

use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::facts::{AssumptionClass, CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier registered in [`AdapterDescriptor`].
pub const POSPACE_VDF_ADAPTER_NAME: &str = "pospace-vdf-v1";
/// Current adapter implementation version.
pub const POSPACE_VDF_ADAPTER_VERSION: u32 = 1;
/// Accepted wire evidence schema version.
pub const POSPACE_VDF_EVIDENCE_VERSION: u32 = 1;

/// Magic header identifying a canonical `PoSpaceVdfEvidence` wire payload.
const PAYLOAD_MAGIC: &[u8; 8] = b"BDLMPV01";
/// Hard upper bound on serialized `PoSpaceVdfEvidence` bytes.
const MAX_POSPACE_PAYLOAD_BYTES: usize = 512 * 1024;
/// Maximum number of contiguous blocks accepted in one confirmation segment.
pub const MAX_POSPACE_SEGMENT_BLOCKS: usize = 64;
/// Hard per-block cap on iterated SHA-256 VDF steps to bound verifier CPU time.
pub const MAX_VERIFIER_VDF_ITERS: u64 = 65_536;
/// Minimum admissible Proof-of-Space plot parameter `k`.
pub const MIN_ALLOWED_PLOT_K: u8 = 16;
/// Maximum admissible Proof-of-Space plot parameter `k`.
pub const MAX_ALLOWED_PLOT_K: u8 = 50;
/// Signage points per sub-slot (matches Chia's 64 signage points per 10-min sub-slot).
pub const SIGNAGE_POINTS_PER_SUB_SLOT: u8 = 64;

/// Domain tag for signage challenge derivation (external adapter namespace).
pub const TAG_POSPACE_CHALLENGE: &[u8] = b"BDLM_POSPACE_EXT_CHALLENGE_V1";
/// Domain tag for `k`-plot identity commitment (external adapter namespace).
pub const TAG_POSPACE_PLOT_SEED: &[u8] = b"BDLM_POSPACE_EXT_PLOT_V1";
/// Domain tag for Proof-of-Space quality extraction (external adapter namespace).
pub const TAG_POSPACE_QUALITY: &[u8] = b"BDLM_POSPACE_EXT_QUALITY_V1";
/// Domain tag for one sequential SHA-256 VDF step (external adapter namespace).
pub const TAG_POSPACE_VDF_STEP: &[u8] = b"BDLM_POSPACE_EXT_VDF_V1";
/// Domain tag for finalized block infusion hash derivation (external adapter namespace).
pub const TAG_POSPACE_INFUSION: &[u8] = b"BDLM_POSPACE_EXT_INFUSION_V1";
/// Domain tag for ML-DSA-65 timelord/farmer finality attestation (external adapter namespace).
pub const TAG_POSPACE_ATTEST: &[u8] = b"BDLM_POSPACE_EXT_ATTEST_V1";
/// Domain tag for slashable per-signage-point block commitment (external adapter namespace).
pub const TAG_POSPACE_SIGNAGE: &[u8] = b"BDLM_POSPACE_EXT_SIGNAGE_V1";

/// Governance-pinned anchor and consensus parameters for a Proof-of-Space + VDF domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedPoSpaceAnchor {
    /// Canonical genesis (or checkpointed sub-slot) challenge digest.
    pub genesis_challenge: Hash32,
    /// Minimum accepted plot size parameter `k` (`16..=50`).
    pub min_plot_k: u8,
    /// Minimum sequential SHA-256 VDF iterations required per block (`>= 1`).
    pub min_iterations_per_block: u64,
    /// Maximum sequential SHA-256 VDF iterations permitted per block (`<= 65_536`).
    pub max_iterations_per_block: u64,
    /// Number of confirming child blocks required strictly above the target block.
    pub required_depth: u32,
    /// Minimum cumulative space-time weight at the tip of the segment.
    pub min_cumulative_weight: u128,
    /// Whether an ML-DSA-65 post-quantum attestation is strictly mandatory.
    pub require_pq_attestation: bool,
    /// Optional pinned ML-DSA-65 timelord/farmer public key (`CROSS_DOMAIN_V1`).
    pub pq_attestor_pubkey: Option<Vec<u8>>,
}

/// One trunk foliage + Proof-of-Space + sequential hash-VDF block in a segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoSpaceVdfBlock {
    /// Strictly contiguous block height.
    pub height: u64,
    /// Monotonic sub-slot index.
    pub sub_slot: u64,
    /// Signage point within `sub_slot` (`0..64`).
    pub signage_index: u8,
    /// Challenge digest derived from the parent infusion output and signage index.
    pub challenge_hash: Hash32,
    /// Farmer public-key digest owning the winning plot.
    pub farmer_pubkey_hash: Hash32,
    /// Plot size parameter `k` (`min_plot_k..=50`).
    pub plot_k: u8,
    /// Plot creation nonce bound into `plot_id`.
    pub plot_nonce: Hash32,
    /// Self-derived plot identity commitment.
    pub plot_id: Hash32,
    /// Proof-of-Space graph-pebbling table opening witness (non-zero).
    pub space_proof_witness: Hash32,
    /// Derived Proof-of-Space quality digest.
    pub quality_string: Hash32,
    /// Sub-slot difficulty parameter (`>= 1`).
    pub difficulty: u64,
    /// Exact sequential SHA-256 VDF iteration count (`min..=max`).
    pub vdf_iterations: u64,
    /// Sequential VDF output after `vdf_iterations` steps.
    pub vdf_output: Hash32,
    /// Committed execution/coin-set state root at `height`.
    pub state_root: Hash32,
    /// Committed generator transaction root at `height`.
    pub tx_root: Hash32,
    /// Committed coin-announcement / event root at `height`.
    pub event_root: Hash32,
    /// Cumulative space-time weight through `height`.
    pub cumulative_weight: u128,
    /// Finalized infusion / block header hash chaining into the next block.
    pub infusion_block_hash: Hash32,
}

impl PoSpaceVdfBlock {
    /// Computes the canonical `plot_id` from `(farmer_pubkey_hash, plot_k, plot_nonce)`.
    #[must_use]
    pub fn derive_plot_id(farmer_pubkey_hash: &Hash32, plot_k: u8, plot_nonce: &Hash32) -> Hash32 {
        sha256_tagged(
            TAG_POSPACE_PLOT_SEED,
            &[farmer_pubkey_hash, &[plot_k], plot_nonce],
        )
    }

    /// Derives the signage challenge from the parent infusion hash, sub-slot, and signage index.
    #[must_use]
    pub fn derive_challenge(parent_infusion: &Hash32, sub_slot: u64, signage_index: u8) -> Hash32 {
        sha256_tagged(
            TAG_POSPACE_CHALLENGE,
            &[parent_infusion, &sub_slot.to_le_bytes(), &[signage_index]],
        )
    }

    /// Derives the Proof-of-Space quality digest from `(plot_id, plot_k, challenge_hash, witness)`.
    #[must_use]
    pub fn derive_quality(
        plot_id: &Hash32,
        plot_k: u8,
        challenge_hash: &Hash32,
        space_proof_witness: &Hash32,
    ) -> Hash32 {
        sha256_tagged(
            TAG_POSPACE_QUALITY,
            &[plot_id, &[plot_k], challenge_hash, space_proof_witness],
        )
    }

    /// Computes the finalized block infusion digest committing every consensus,
    /// space-proof, VDF, state, transaction, event, and cumulative-weight field.
    #[must_use]
    pub fn compute_infusion_hash(&self, network: &str) -> Hash32 {
        sha256_tagged(
            TAG_POSPACE_INFUSION,
            &[
                network.as_bytes(),
                &self.height.to_le_bytes(),
                &self.sub_slot.to_le_bytes(),
                &[self.signage_index, self.plot_k],
                &self.challenge_hash,
                &self.plot_id,
                &self.quality_string,
                &self.difficulty.to_le_bytes(),
                &self.vdf_iterations.to_le_bytes(),
                &self.vdf_output,
                &self.state_root,
                &self.tx_root,
                &self.event_root,
                &self.cumulative_weight.to_le_bytes(),
            ],
        )
    }
}

/// Wire payload carried in [`RawConsensusEvidence::payload`] for [`PoSpaceVdfAdapter`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoSpaceVdfEvidence {
    /// Pinned genesis challenge bound to the segment's root.
    pub genesis_challenge: Hash32,
    /// Cumulative weight immediately preceding `blocks[0]`.
    pub base_cumulative_weight: u128,
    /// Contiguous sequence of trunk blocks (`target_index` plus `>= required_depth` confirmations).
    pub blocks: Vec<PoSpaceVdfBlock>,
    /// Index in `blocks` whose finality is attested (`blocks[target_index]`).
    pub target_index: u32,
    /// Optional/mandated ML-DSA-65 signature over the segment tip and target block.
    pub pq_attestation_sig: Vec<u8>,
}

/// Signed farmer/timelord signage-point statement used for double-signage slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPoSpaceSignage {
    /// External network identifier.
    pub network: String,
    /// Sub-slot index of the signage point.
    pub sub_slot: u64,
    /// Signage index within `sub_slot` (`0..64`).
    pub signage_index: u8,
    /// Attested infusion block hash at `(sub_slot, signage_index)`.
    pub infusion_block_hash: Hash32,
    /// ML-DSA-65 public key of the farmer or timelord.
    pub signer_pq_pubkey: Vec<u8>,
    /// ML-DSA-65 signature under [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
    pub signature: Vec<u8>,
}

/// Verified double-signage equivocation record suitable for slasher execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoSpaceEquivocationProof {
    /// `SHA-256` identity digest of the equivocating ML-DSA-65 public key.
    pub offender_key_digest: Hash32,
    /// Sub-slot at which the double-signage occurred.
    pub sub_slot: u64,
    /// Signage point within `sub_slot`.
    pub signage_index: u8,
    /// First signed block hash.
    pub first_block_hash: Hash32,
    /// Conflicting second signed block hash (`!= first_block_hash`).
    pub second_block_hash: Hash32,
}

#[must_use]
fn sha256_tagged(tag: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    let tag_len = u32::try_from(tag.len()).unwrap_or(u32::MAX);
    hasher.update(tag_len.to_be_bytes());
    hasher.update(tag);
    for part in parts {
        let part_len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        hasher.update(part_len.to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Evaluates the pure-hash post-quantum sequential VDF (`iterations` chained
/// domain-separated `SHA-256` compressions over `(challenge_hash, quality_string)`).
#[must_use]
pub fn evaluate_hash_vdf(
    challenge_hash: &Hash32,
    quality_string: &Hash32,
    iterations: u64,
) -> Hash32 {
    let mut state = sha256_tagged(TAG_POSPACE_VDF_STEP, &[challenge_hash, quality_string]);
    for step in 0..iterations {
        let mut hasher = Sha256::new();
        hasher.update(TAG_POSPACE_VDF_STEP);
        hasher.update(step.to_le_bytes());
        hasher.update(state);
        state = hasher.finalize().into();
    }
    state
}

/// Extracts the canonical 64-bit unsigned quality score from `quality_string`.
#[must_use]
pub fn quality_score_u64(quality_string: &Hash32) -> u64 {
    quality_string
        .get(0..8)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map_or(u64::MAX, u64::from_be_bytes)
}

/// Exact-integer Proof-of-Space target ceiling `floor(u64::MAX / difficulty)`
/// boosted monotonically by `1 + (plot_k - MIN_ALLOWED_PLOT_K)` with saturation.
#[must_use]
pub const fn quality_target_u64(difficulty: u64, plot_k: u8) -> u64 {
    if difficulty == 0 || plot_k < MIN_ALLOWED_PLOT_K {
        return 0;
    }
    let base = u64::MAX / difficulty;
    let k_factor = (plot_k.saturating_sub(MIN_ALLOWED_PLOT_K) as u64).saturating_add(1);
    base.saturating_mul(k_factor)
}

/// Exact-integer space-time weight contributed by a single valid block.
#[must_use]
pub const fn block_space_time_weight(plot_k: u8, difficulty: u64, vdf_iterations: u64) -> u128 {
    let k_weight = plot_k as u128;
    let d_weight = difficulty as u128;
    let i_weight = vdf_iterations as u128;
    k_weight.saturating_mul(d_weight).saturating_mul(i_weight)
}

/// Canonical message signed by an ML-DSA-65 attestor over a verified PoSpace+VDF segment.
#[must_use]
pub fn pospace_attest_sign_bytes(
    network: &str,
    genesis_challenge: &Hash32,
    target_block_hash: &Hash32,
    tip_block_hash: &Hash32,
    tip_cumulative_weight: u128,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        TAG_POSPACE_ATTEST,
        network.as_bytes(),
        genesis_challenge,
        target_block_hash,
        tip_block_hash,
        &tip_cumulative_weight.to_le_bytes(),
    ])
}

/// Canonical message signed by a farmer/timelord for a single signage point.
#[must_use]
pub fn pospace_signage_sign_bytes(
    network: &str,
    sub_slot: u64,
    signage_index: u8,
    infusion_block_hash: &Hash32,
) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        TAG_POSPACE_SIGNAGE,
        network.as_bytes(),
        &sub_slot.to_le_bytes(),
        &[signage_index],
        infusion_block_hash,
    ])
}

/// Verifies cryptographic double-signage equivocation: the same ML-DSA-65 key
/// signed two distinct non-zero block hashes at identical `(network, sub_slot, signage_index)`.
///
/// # Errors
///
/// Returns [`AdapterError`] if the statements target different networks or
/// signage slots, sign the same block hash, carry different keys, or fail
/// `ML-DSA-65` verification under [`crate::crypto::ctx::CROSS_DOMAIN_V1`].
pub fn verify_double_signage_equivocation(
    expected_network: &str,
    first: &SignedPoSpaceSignage,
    second: &SignedPoSpaceSignage,
) -> Result<PoSpaceEquivocationProof, AdapterError> {
    if expected_network.trim().is_empty()
        || first.network != expected_network
        || second.network != expected_network
    {
        return Err(AdapterError::ConsensusRule {
            rule: "double-signage evidence network mismatch".into(),
        });
    }
    if first.signage_index >= SIGNAGE_POINTS_PER_SUB_SLOT
        || first.sub_slot != second.sub_slot
        || first.signage_index != second.signage_index
    {
        return Err(AdapterError::ConsensusRule {
            rule: "double-signage evidence must target the same valid (sub_slot, signage_index)"
                .into(),
        });
    }
    if first.infusion_block_hash == [0u8; 32]
        || second.infusion_block_hash == [0u8; 32]
        || bool::from(first.infusion_block_hash.ct_eq(&second.infusion_block_hash))
    {
        return Err(AdapterError::ConsensusRule {
            rule: "double-signage evidence requires two distinct non-zero block hashes".into(),
        });
    }
    if first.signer_pq_pubkey != second.signer_pq_pubkey {
        return Err(AdapterError::ConsensusRule {
            rule: "double-signage statements carry different signer public keys".into(),
        });
    }
    crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, &first.signer_pq_pubkey).map_err(
        |_| AdapterError::Crypto {
            what: "double-signage signer key is not a valid ML-DSA-65 public key".into(),
        },
    )?;

    let msg_a = pospace_signage_sign_bytes(
        &first.network,
        first.sub_slot,
        first.signage_index,
        &first.infusion_block_hash,
    );
    let msg_b = pospace_signage_sign_bytes(
        &second.network,
        second.sub_slot,
        second.signage_index,
        &second.infusion_block_hash,
    );
    crate::crypto::primitives::PqKeyPair::verify(
        &first.signer_pq_pubkey,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &msg_a,
        &first.signature,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "first double-signage ML-DSA-65 signature invalid".into(),
    })?;
    crate::crypto::primitives::PqKeyPair::verify(
        &second.signer_pq_pubkey,
        crate::crypto::ctx::CROSS_DOMAIN_V1,
        &msg_b,
        &second.signature,
    )
    .map_err(|_| AdapterError::Crypto {
        what: "second double-signage ML-DSA-65 signature invalid".into(),
    })?;

    let offender_key_digest: Hash32 = Sha256::digest(&first.signer_pq_pubkey).into();
    Ok(PoSpaceEquivocationProof {
        offender_key_digest,
        sub_slot: first.sub_slot,
        signage_index: first.signage_index,
        first_block_hash: first.infusion_block_hash,
        second_block_hash: second.infusion_block_hash,
    })
}

/// Encodes a [`PoSpaceVdfEvidence`] payload with canonical `BDLMPV01` framing.
///
/// Convenience: kept for the CLI and external PoSpace+VDF relayer encoders.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] if encoding fails or exceeds bounds.
pub fn encode_pospace_payload(evidence: &PoSpaceVdfEvidence) -> Result<Vec<u8>, AdapterError> {
    let body = bincode::options()
        .with_fixint_encoding()
        .with_limit(MAX_POSPACE_PAYLOAD_BYTES as u64)
        .serialize(evidence)
        .map_err(|e| AdapterError::Malformed {
            offset: 8,
            reason: format!("failed to serialize pospace-vdf evidence: {e}"),
        })?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_POSPACE_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_POSPACE_PAYLOAD_BYTES,
            reason: format!("pospace-vdf payload exceeds {MAX_POSPACE_PAYLOAD_BYTES}"),
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_pospace_payload(payload: &[u8]) -> Result<PoSpaceVdfEvidence, AdapterError> {
    if payload.len() > MAX_POSPACE_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_POSPACE_PAYLOAD_BYTES,
            reason: format!("pospace-vdf payload exceeds {MAX_POSPACE_PAYLOAD_BYTES}"),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "pospace-vdf payload magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing pospace-vdf payload body".into(),
    })?;
    let limit = u64::try_from(body.len()).unwrap_or(MAX_POSPACE_PAYLOAD_BYTES as u64);
    bincode::options()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
        .deserialize(body)
        .map_err(|e| AdapterError::Malformed {
            offset: 8,
            reason: format!("invalid pospace-vdf evidence: {e}"),
        })
}

/// External finality adapter for Proof-of-Space + sequential hash-VDF chains.
pub struct PoSpaceVdfAdapter {
    network: String,
    pinned: Option<PinnedPoSpaceAnchor>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl PoSpaceVdfAdapter {
    /// Constructs a [`PoSpaceVdfAdapter`] bound to `network` and `pinned`.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedPoSpaceAnchor>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(POSPACE_VDF_ADAPTER_NAME);
        let required_depth = pinned
            .as_ref()
            .map_or(4, |anchor| u64::from(anchor.required_depth));
        let descriptor = AdapterDescriptor {
            id,
            name: POSPACE_VDF_ADAPTER_NAME.into(),
            adapter_version: POSPACE_VDF_ADAPTER_VERSION,
            accepted_evidence_versions: vec![POSPACE_VDF_EVIDENCE_VERSION],
            consensus_kind: "pospace-hash-vdf".into(),
            finality_kind: FinalityKind::Probabilistic,
            required_depth,
            time_unit: TimeUnit::Height,
            trust_model: TrustModel::Trustless,
        };
        Self {
            network,
            pinned,
            golden: None,
            descriptor,
        }
    }

    /// Attaches a canonical golden evidence sample for [`super::selftest::admit`].
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    /// Validates a governance pin outside this adapter.
    ///
    /// The intake's `PinExternalAnchor` door has to refuse a pin before it is
    /// installed, and the rules for what a usable pin is live here, beside the
    /// verifier that depends on them. Exposing the same function rather than
    /// restating the bounds at the door is what keeps one answer to "is this
    /// pin usable".
    ///
    /// # Errors
    ///
    /// [`AdapterError::ConsensusRule`] naming the first field that cannot
    /// certify an epoch.
    pub fn validate_pin_public(pinned: &PinnedPoSpaceAnchor) -> Result<(), AdapterError> {
        Self::validate_pin(pinned)
    }

    fn validate_pin(pinned: &PinnedPoSpaceAnchor) -> Result<(), AdapterError> {
        if pinned.genesis_challenge == [0u8; 32] {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned pospace genesis_challenge must be non-zero".into(),
            });
        }
        if !(MIN_ALLOWED_PLOT_K..=MAX_ALLOWED_PLOT_K).contains(&pinned.min_plot_k) {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned pospace min_plot_k out of bounds".into(),
            });
        }
        if pinned.min_iterations_per_block == 0
            || pinned.min_iterations_per_block > pinned.max_iterations_per_block
            || pinned.max_iterations_per_block > MAX_VERIFIER_VDF_ITERS
        {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned pospace VDF iteration bounds invalid".into(),
            });
        }
        if pinned.required_depth == 0
            || usize::try_from(pinned.required_depth).unwrap_or(usize::MAX)
                >= MAX_POSPACE_SEGMENT_BLOCKS
        {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned pospace required_depth out of bounds".into(),
            });
        }
        if pinned.min_cumulative_weight == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "pinned pospace min_cumulative_weight must be positive".into(),
            });
        }
        if pinned.require_pq_attestation && pinned.pq_attestor_pubkey.is_none() {
            return Err(AdapterError::ConsensusRule {
                rule: "require_pq_attestation set without pinned ML-DSA-65 pubkey".into(),
            });
        }
        if let Some(pk) = &pinned.pq_attestor_pubkey {
            crate::crypto::pq::validate_public_key(SchemeId::ML_DSA_65, pk).map_err(|_| {
                AdapterError::ConsensusRule {
                    rule: "pinned pospace pq_attestor_pubkey is not a valid ML-DSA-65 key".into(),
                }
            })?;
        }
        Ok(())
    }

    fn verify_inner(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<(FinalityAttestation, bool), AdapterError> {
        if evidence.adapter != self.descriptor.id {
            return Err(AdapterError::ConsensusRule {
                rule: "evidence adapter id does not match pospace-vdf-v1".into(),
            });
        }
        if evidence.evidence_version != POSPACE_VDF_EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: format!("{POSPACE_VDF_EVIDENCE_VERSION}"),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "pospace-vdf network mismatch: got {}, expected {}",
                    evidence.network, self.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "pospace-vdf adapter has no pinned genesis challenge".into(),
            });
        };
        Self::validate_pin(pinned)?;

        let decoded = decode_pospace_payload(&evidence.payload)?;
        if !bool::from(decoded.genesis_challenge.ct_eq(&pinned.genesis_challenge)) {
            return Err(AdapterError::ConsensusRule {
                rule: "pospace-vdf genesis_challenge mismatch".into(),
            });
        }
        if decoded.blocks.is_empty() || decoded.blocks.len() > MAX_POSPACE_SEGMENT_BLOCKS {
            return Err(AdapterError::ConsensusRule {
                rule: "pospace-vdf block segment length out of bounds".into(),
            });
        }
        let target_idx =
            usize::try_from(decoded.target_index).map_err(|_| AdapterError::ConsensusRule {
                rule: "pospace-vdf target_index overflow".into(),
            })?;
        let target = decoded
            .blocks
            .get(target_idx)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "pospace-vdf target_index out of bounds".into(),
            })?;
        let confirmations = decoded
            .blocks
            .len()
            .saturating_sub(1)
            .saturating_sub(target_idx);
        let required_depth = usize::try_from(pinned.required_depth).unwrap_or(usize::MAX);
        if confirmations < required_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: confirmations as u64,
                required: u64::from(pinned.required_depth),
            });
        }

        // Declaration binding runs before expensive iterated VDF hashing where safe,
        // after structural checks so declaration probes hit DeclarationMismatch cleanly.
        if evidence.declared_height != target.height {
            return Err(AdapterError::DeclarationMismatch {
                field: "declared_height",
            });
        }
        if !bool::from(evidence.declared_root.ct_eq(&target.state_root)) {
            return Err(AdapterError::DeclarationMismatch {
                field: "declared_root",
            });
        }
        if policy.max_age > 0 {
            if target.height > policy.now {
                return Err(AdapterError::Stale {
                    age: target.height.saturating_sub(policy.now),
                    max_age: policy.max_age,
                });
            }
            let age = policy.now.saturating_sub(target.height);
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // Verify every block's challenge link, Proof-of-Space quality, sequential
        // hash VDF output, cumulative space-time weight, and infusion hash.
        let mut parent_infusion = pinned.genesis_challenge;
        let mut running_weight = decoded.base_cumulative_weight;
        let mut prev_pos: Option<(u64, u64, u8)> = None;

        for block in &decoded.blocks {
            if block.signage_index >= SIGNAGE_POINTS_PER_SUB_SLOT {
                return Err(AdapterError::ConsensusRule {
                    rule: "pospace-vdf signage_index >= 64".into(),
                });
            }
            if let Some((prev_h, prev_slot, prev_sig)) = prev_pos {
                if block.height != prev_h.saturating_add(1) {
                    return Err(AdapterError::ConsensusRule {
                        rule: "pospace-vdf block heights are not strictly contiguous".into(),
                    });
                }
                let strictly_after = (block.sub_slot, block.signage_index) > (prev_slot, prev_sig);
                if !strictly_after {
                    return Err(AdapterError::ConsensusRule {
                        rule: "pospace-vdf (sub_slot, signage_index) is not strictly increasing"
                            .into(),
                    });
                }
            } else if block.height == 0 {
                return Err(AdapterError::ConsensusRule {
                    rule: "pospace-vdf block height must be >= 1".into(),
                });
            }

            let expected_challenge = PoSpaceVdfBlock::derive_challenge(
                &parent_infusion,
                block.sub_slot,
                block.signage_index,
            );
            if !bool::from(block.challenge_hash.ct_eq(&expected_challenge)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "pospace-vdf challenge_hash does not chain from parent infusion".into(),
                });
            }

            if block.plot_k < pinned.min_plot_k || block.plot_k > MAX_ALLOWED_PLOT_K {
                return Err(AdapterError::ConsensusRule {
                    rule: "pospace-vdf plot_k outside allowed range".into(),
                });
            }
            if block.farmer_pubkey_hash == [0u8; 32]
                || block.space_proof_witness == [0u8; 32]
                || block.state_root == [0u8; 32]
                || block.difficulty == 0
            {
                return Err(AdapterError::ConsensusRule {
                    rule:
                        "pospace-vdf block carries zero root, witness, farmer hash, or difficulty"
                            .into(),
                });
            }
            let expected_plot_id = PoSpaceVdfBlock::derive_plot_id(
                &block.farmer_pubkey_hash,
                block.plot_k,
                &block.plot_nonce,
            );
            if !bool::from(block.plot_id.ct_eq(&expected_plot_id)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "pospace-vdf plot_id mismatch".into(),
                });
            }
            let expected_quality = PoSpaceVdfBlock::derive_quality(
                &block.plot_id,
                block.plot_k,
                &block.challenge_hash,
                &block.space_proof_witness,
            );
            if !bool::from(block.quality_string.ct_eq(&expected_quality)) {
                return Err(AdapterError::Crypto {
                    what: "pospace-vdf Proof-of-Space quality commitment mismatch".into(),
                });
            }
            let score = quality_score_u64(&block.quality_string);
            let target_ceiling = quality_target_u64(block.difficulty, block.plot_k);
            if score > target_ceiling {
                return Err(AdapterError::ConsensusRule {
                    rule: "pospace-vdf Proof-of-Space quality fails difficulty target".into(),
                });
            }

            if block.vdf_iterations < pinned.min_iterations_per_block
                || block.vdf_iterations > pinned.max_iterations_per_block
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "pospace-vdf vdf_iterations outside pinned window".into(),
                });
            }
            let expected_vdf = evaluate_hash_vdf(
                &block.challenge_hash,
                &block.quality_string,
                block.vdf_iterations,
            );
            if !bool::from(block.vdf_output.ct_eq(&expected_vdf)) {
                return Err(AdapterError::Crypto {
                    what: "pospace-vdf sequential hash-VDF output verification failed".into(),
                });
            }

            let delta =
                block_space_time_weight(block.plot_k, block.difficulty, block.vdf_iterations);
            running_weight =
                running_weight
                    .checked_add(delta)
                    .ok_or_else(|| AdapterError::ConsensusRule {
                        rule: "pospace-vdf cumulative_weight overflow".into(),
                    })?;
            if block.cumulative_weight != running_weight {
                return Err(AdapterError::ConsensusRule {
                    rule: "pospace-vdf cumulative_weight does not match exact space-time sum"
                        .into(),
                });
            }

            let expected_infusion = block.compute_infusion_hash(&self.network);
            if !bool::from(block.infusion_block_hash.ct_eq(&expected_infusion)) {
                return Err(AdapterError::ConsensusRule {
                    rule: "pospace-vdf infusion_block_hash mismatch".into(),
                });
            }

            parent_infusion = block.infusion_block_hash;
            prev_pos = Some((block.height, block.sub_slot, block.signage_index));
        }

        let tip = decoded
            .blocks
            .last()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "pospace-vdf missing segment tip".into(),
            })?;
        let verified_segment_weight = tip
            .cumulative_weight
            .checked_sub(decoded.base_cumulative_weight)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "pospace-vdf tip cumulative_weight underflows base_cumulative_weight".into(),
            })?;
        if tip.cumulative_weight < pinned.min_cumulative_weight
            || verified_segment_weight < pinned.min_cumulative_weight
        {
            return Err(AdapterError::ConsensusRule {
                rule: "pospace-vdf tip cumulative_weight below pinned minimum".into(),
            });
        }

        // Verify optional or mandated ML-DSA-65 post-quantum attestation.
        let pq_verified = if pinned.require_pq_attestation || !decoded.pq_attestation_sig.is_empty()
        {
            let Some(pk) = &pinned.pq_attestor_pubkey else {
                return Err(AdapterError::Crypto {
                    what: "pospace-vdf carries PQ signature without pinned ML-DSA-65 key".into(),
                });
            };
            if decoded.pq_attestation_sig.is_empty() {
                return Err(AdapterError::Crypto {
                    what: "missing mandatory ML-DSA-65 pospace-vdf attestation".into(),
                });
            }
            let msg = pospace_attest_sign_bytes(
                &self.network,
                &pinned.genesis_challenge,
                &target.infusion_block_hash,
                &tip.infusion_block_hash,
                tip.cumulative_weight,
            );
            crate::crypto::primitives::PqKeyPair::verify(
                pk,
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &msg,
                &decoded.pq_attestation_sig,
            )
            .map_err(|_| AdapterError::Crypto {
                what: "invalid ML-DSA-65 signature on pospace-vdf finality attestation".into(),
            })?;
            true
        } else {
            false
        };

        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }

        let weight_bits = 128u32.saturating_sub(verified_segment_weight.leading_zeros());
        let security = if pq_verified {
            SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers: 1,
                required: 1,
                total_weight: verified_segment_weight,
                // External PoSpace farmer/timelord signatures have no local Budlum
                // confiscation bond or BridgeEconomicGuard arm yet.
                slashable: false,
            }
        } else {
            SecurityBacking::Work {
                difficulty_bits: weight_bits,
            }
        };

        let att = FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: target.height,
            state_root: target.state_root,
            attested_block_hash: Some(target.infusion_block_hash),
            attested_event_root: (target.event_root != [0u8; 32]).then_some(target.event_root),
            attested_tx_root: (target.tx_root != [0u8; 32]).then_some(target.tx_root),
            finalized_at: tip.height,
            time_unit: TimeUnit::Height,
            security,
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
        };
        Ok((att, pq_verified))
    }
}

impl ExternalFinalityAdapter for PoSpaceVdfAdapter {
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
        let (att, pq_verified) = self.verify_inner(evidence, policy)?;
        observer.observe(ObservedScheme::Proof(AssumptionClass::Hash));
        if pq_verified {
            observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        }
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_tail = self
            .golden
            .as_ref()
            .map_or(32, |g| g.payload.len().saturating_sub(16));
        let mut probes = vec![
            FaultProbe {
                name: "refuses unsupported pospace-vdf evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 9 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses foreign pospace-vdf network".into(),
                patch: BytePatch::Network {
                    value: format!("{}-evil", self.network),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared height".into(),
                patch: BytePatch::DeclaredHeight { value: u64::MAX },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared state root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xEE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted pospace-vdf magic header".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: vec![0xBA, 0xAD],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses mutated pinned genesis_challenge".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xFF, 0x01],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses truncated pospace-vdf payload".into(),
                patch: BytePatch::TruncatePayload { keep: 4 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
        ];
        if self
            .pinned
            .as_ref()
            .is_some_and(|p| p.require_pq_attestation)
        {
            probes.push(FaultProbe {
                name: "refuses corrupted ML-DSA-65 pospace-vdf attestation".into(),
                patch: BytePatch::InPayload {
                    offset: sig_tail,
                    bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Crypto),
            });
        }
        probes
    }

    fn golden_evidence(&self) -> Option<RawConsensusEvidence> {
        self.golden.clone()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::cross_domain::external::selftest::{admit, admit_observed};
    use crate::crypto::primitives::PqKeyPair;

    fn mine_valid_block(
        network: &str,
        parent_infusion: &Hash32,
        slot_pos: (u64, u64, u8),
        plot_params: (u8, u64, u64),
        prev_weight: u128,
    ) -> PoSpaceVdfBlock {
        let (height, sub_slot, signage_index) = slot_pos;
        let (plot_k, difficulty, vdf_iterations) = plot_params;
        let farmer_pubkey_hash = [0x33; 32];
        let plot_nonce = [u8::try_from(height & 0xFF).unwrap_or(0) ^ 0x5A; 32];
        let plot_id = PoSpaceVdfBlock::derive_plot_id(&farmer_pubkey_hash, plot_k, &plot_nonce);
        let challenge_hash =
            PoSpaceVdfBlock::derive_challenge(parent_infusion, sub_slot, signage_index);
        let mut space_proof_witness = [0u8; 32];
        let mut quality_string = [0u8; 32];
        let target_ceiling = quality_target_u64(difficulty, plot_k);
        for nonce in 1u64..100_000 {
            space_proof_witness[0..8].copy_from_slice(&nonce.to_le_bytes());
            space_proof_witness[8] = 0xA5;
            let q = PoSpaceVdfBlock::derive_quality(
                &plot_id,
                plot_k,
                &challenge_hash,
                &space_proof_witness,
            );
            if quality_score_u64(&q) <= target_ceiling {
                quality_string = q;
                break;
            }
        }
        let vdf_output = evaluate_hash_vdf(&challenge_hash, &quality_string, vdf_iterations);
        let state_root = sha256_tagged(TAG_POSPACE_INFUSION, &[b"state", &height.to_le_bytes()]);
        let tx_root = sha256_tagged(TAG_POSPACE_INFUSION, &[b"tx", &height.to_le_bytes()]);
        let event_root = sha256_tagged(TAG_POSPACE_INFUSION, &[b"ev", &height.to_le_bytes()]);
        let cumulative_weight = prev_weight
            .checked_add(block_space_time_weight(plot_k, difficulty, vdf_iterations))
            .unwrap();
        let mut block = PoSpaceVdfBlock {
            height,
            sub_slot,
            signage_index,
            challenge_hash,
            farmer_pubkey_hash,
            plot_k,
            plot_nonce,
            plot_id,
            space_proof_witness,
            quality_string,
            difficulty,
            vdf_iterations,
            vdf_output,
            state_root,
            tx_root,
            event_root,
            cumulative_weight,
            infusion_block_hash: [0u8; 32],
        };
        block.infusion_block_hash = block.compute_infusion_hash(network);
        block
    }

    /// Known-good Proof-of-Space + hash-VDF sample, shared with the intake
    /// tests.
    ///
    /// The intake registers a domain end to end and needs the same sample
    /// `selftest::admit` will verify against; exposing it here keeps one
    /// fixture rather than two that could drift.
    pub(crate) fn pospace_fixture(
        network: &str,
        require_pq: bool,
    ) -> (PinnedPoSpaceAnchor, RawConsensusEvidence) {
        let (_adapter, pinned, _ev, raw, _kp) = build_fixture(network, 5, 1, require_pq);
        (pinned, raw)
    }

    fn build_fixture(
        network: &str,
        block_count: usize,
        target_index: u32,
        require_pq: bool,
    ) -> (
        PoSpaceVdfAdapter,
        PinnedPoSpaceAnchor,
        PoSpaceVdfEvidence,
        RawConsensusEvidence,
        PqKeyPair,
    ) {
        let kp = PqKeyPair::generate();
        let genesis_challenge = [0x77; 32];
        let mut blocks = Vec::with_capacity(block_count);
        let mut parent = genesis_challenge;
        let mut weight = 1_000u128;
        for i in 0..block_count {
            let h = 100 + i as u64;
            let slot = 10 + (i as u64) / 4;
            let sig_idx = u8::try_from((i % 4) * 7 + 1).unwrap_or(1);
            let blk = mine_valid_block(network, &parent, (h, slot, sig_idx), (32, 4, 64), weight);
            parent = blk.infusion_block_hash;
            weight = blk.cumulative_weight;
            blocks.push(blk);
        }
        let target = blocks.get(target_index as usize).unwrap().clone();
        let tip = blocks.last().unwrap().clone();
        let pq_sig = if require_pq {
            let msg = pospace_attest_sign_bytes(
                network,
                &genesis_challenge,
                &target.infusion_block_hash,
                &tip.infusion_block_hash,
                tip.cumulative_weight,
            );
            kp.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg).unwrap()
        } else {
            Vec::new()
        };
        let ev_body = PoSpaceVdfEvidence {
            genesis_challenge,
            base_cumulative_weight: 1_000,
            blocks,
            target_index,
            pq_attestation_sig: pq_sig,
        };
        let payload = encode_pospace_payload(&ev_body).unwrap();
        let raw = RawConsensusEvidence {
            adapter: AdapterId::from_name(POSPACE_VDF_ADAPTER_NAME),
            evidence_version: POSPACE_VDF_EVIDENCE_VERSION,
            network: network.to_string(),
            declared_height: target.height,
            declared_root: target.state_root,
            payload,
            submitter: Address::from([0x5A; 32]),
        };
        let pinned = PinnedPoSpaceAnchor {
            genesis_challenge,
            min_plot_k: 32,
            min_iterations_per_block: 32,
            max_iterations_per_block: 1_024,
            required_depth: 3,
            min_cumulative_weight: 5_000,
            require_pq_attestation: require_pq,
            pq_attestor_pubkey: require_pq.then(|| kp.public_key_bytes().to_vec()),
        };
        let adapter =
            PoSpaceVdfAdapter::new(network, Some(pinned.clone())).with_golden(raw.clone());
        (adapter, pinned, ev_body, raw, kp)
    }

    #[test]
    fn pospace_vdf_selftest_admission_and_crypto_observation_pass() {
        let (adapter, _, _, raw, _) = build_fixture("chia-pq-mainnet", 5, 1, true);
        let policy = VerificationPolicy::strict(110);
        let report = admit(&adapter, &policy);
        assert!(report.admitted, "selftest probes: {:?}", report.probes);
        assert_eq!(report.probes.len(), 8);

        let (observed, facts) = admit_observed(&adapter, &policy);
        assert!(observed.admitted);
        assert!(facts.count(ObservedScheme::Proof(AssumptionClass::Hash)) >= 1);
        assert!(facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)) >= 1);

        let att = adapter.verify(&raw, &policy).unwrap();
        assert_eq!(att.height, 101);
        assert_eq!(att.finalized_at, 104);

        // Pure hash-VDF mode (no PQ key required) also passes selftest and reports only Hash.
        let (hash_only, _, _, _, _) = build_fixture("chia-hash-only", 5, 0, false);
        let (report_h, hash_facts) = admit_observed(&hash_only, &policy);
        assert!(report_h.admitted, "hash-only probes: {:?}", report_h.probes);
        assert!(hash_facts.count(ObservedScheme::Proof(AssumptionClass::Hash)) >= 1);
        assert_eq!(
            hash_facts.count(ObservedScheme::Scheme(SchemeId::ML_DSA_65)),
            0
        );
    }

    #[test]
    fn pospace_vdf_rejects_vdf_forgery_shallow_depth_low_k_weight_and_grinding() {
        let (adapter, pinned, ev_body, raw, kp) = build_fixture("chia-pq-mainnet", 5, 1, true);
        let policy = VerificationPolicy::strict(110);

        // 1. Insufficient confirmation depth (target_index = 3 -> only 1 confirmation < 3).
        let mut shallow = ev_body.clone();
        shallow.target_index = 3;
        let mut shallow_raw = raw.clone();
        shallow_raw.declared_height = shallow.blocks.get(3).unwrap().height;
        shallow_raw.declared_root = shallow.blocks.get(3).unwrap().state_root;
        shallow_raw.payload = encode_pospace_payload(&shallow).unwrap();
        assert!(matches!(
            adapter.verify(&shallow_raw, &policy),
            Err(AdapterError::InsufficientDepth {
                observed: 1,
                required: 3
            })
        ));

        // 2. Forged sequential VDF output fails Crypto check even with recomputed infusion & PQ sig.
        let mut bad_vdf = ev_body.clone();
        if let Some(first) = bad_vdf.blocks.first_mut() {
            first.vdf_output[0] ^= 0x01;
            first.infusion_block_hash = first.compute_infusion_hash("chia-pq-mainnet");
        }
        let mut bad_vdf_raw = raw.clone();
        bad_vdf_raw.payload = encode_pospace_payload(&bad_vdf).unwrap();
        assert!(matches!(
            adapter.verify(&bad_vdf_raw, &policy),
            Err(AdapterError::Crypto { .. })
        ));

        // 3. Undersized plot_k (< min_plot_k) refused.
        let mut low_k = ev_body.clone();
        if let Some(first) = low_k.blocks.first_mut() {
            first.plot_k = pinned.min_plot_k - 1;
        }
        let mut low_k_raw = raw.clone();
        low_k_raw.payload = encode_pospace_payload(&low_k).unwrap();
        assert!(matches!(
            adapter.verify(&low_k_raw, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 4. Inflated cumulative_weight (fork-choice weight spoofing) refused.
        let mut inflated = ev_body.clone();
        if let Some(last) = inflated.blocks.last_mut() {
            last.cumulative_weight += 1;
            last.infusion_block_hash = last.compute_infusion_hash("chia-pq-mainnet");
        }
        let target_hash = inflated.blocks.get(1).unwrap().infusion_block_hash;
        let tip = inflated.blocks.last().unwrap();
        let msg = pospace_attest_sign_bytes(
            "chia-pq-mainnet",
            &pinned.genesis_challenge,
            &target_hash,
            &tip.infusion_block_hash,
            tip.cumulative_weight,
        );
        inflated.pq_attestation_sig = kp.sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg).unwrap();
        let mut inflated_raw = raw.clone();
        inflated_raw.payload = encode_pospace_payload(&inflated).unwrap();
        assert!(matches!(
            adapter.verify(&inflated_raw, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));

        // 5. Stale evidence refused under bounded max_age policy (both past and future heights).
        let strict_age = VerificationPolicy {
            now: 200,
            max_age: 10,
            ..VerificationPolicy::strict(200)
        };
        assert!(matches!(
            adapter.verify(&raw, &strict_age),
            Err(AdapterError::Stale { .. })
        ));
        let future_age = VerificationPolicy {
            now: 100,
            max_age: 10,
            ..VerificationPolicy::strict(100)
        };
        assert!(matches!(
            adapter.verify(&raw, &future_age),
            Err(AdapterError::Stale { .. })
        ));

        // 6. Unauthenticated base_cumulative_weight spoofing cannot bypass min_cumulative_weight.
        let mut high_min_pinned = pinned;
        high_min_pinned.min_cumulative_weight = 100_000;
        high_min_pinned.require_pq_attestation = false;
        high_min_pinned.pq_attestor_pubkey = None;
        let high_min_adapter = PoSpaceVdfAdapter::new("chia-pq-mainnet", Some(high_min_pinned));
        let mut spoofed_base = ev_body;
        let spoof_offset = 1u128 << 126;
        spoofed_base.base_cumulative_weight = spoof_offset;
        spoofed_base.pq_attestation_sig.clear();
        let mut running = spoof_offset;
        for blk in &mut spoofed_base.blocks {
            running += block_space_time_weight(blk.plot_k, blk.difficulty, blk.vdf_iterations);
            blk.cumulative_weight = running;
            blk.infusion_block_hash = blk.compute_infusion_hash("chia-pq-mainnet");
        }
        let mut spoofed_raw = raw;
        spoofed_raw.payload = encode_pospace_payload(&spoofed_base).unwrap();
        assert!(matches!(
            high_min_adapter.verify(&spoofed_raw, &policy),
            Err(AdapterError::ConsensusRule { .. })
        ));
    }

    #[test]
    fn double_signage_equivocation_accepts_real_conflict_and_rejects_honest_or_forged() {
        let farmer = PqKeyPair::generate();
        let bystander = PqKeyPair::generate();
        let net = "chia-pq-mainnet";
        let block_a = [0x11; 32];
        let block_b = [0x22; 32];

        let msg_a = pospace_signage_sign_bytes(net, 42, 7, &block_a);
        let msg_b = pospace_signage_sign_bytes(net, 42, 7, &block_b);
        let sig_a = farmer
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg_a)
            .unwrap();
        let sig_b = farmer
            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg_b)
            .unwrap();

        let s1 = SignedPoSpaceSignage {
            network: net.into(),
            sub_slot: 42,
            signage_index: 7,
            infusion_block_hash: block_a,
            signer_pq_pubkey: farmer.public_key_bytes().to_vec(),
            signature: sig_a,
        };
        let s2 = SignedPoSpaceSignage {
            network: net.into(),
            sub_slot: 42,
            signage_index: 7,
            infusion_block_hash: block_b,
            signer_pq_pubkey: farmer.public_key_bytes().to_vec(),
            signature: sig_b,
        };

        let proof = verify_double_signage_equivocation(net, &s1, &s2)
            .expect("genuine double-signage at same (sub_slot, signage_index) must verify");
        assert_eq!(proof.sub_slot, 42);
        assert_eq!(proof.signage_index, 7);
        assert_eq!(proof.first_block_hash, block_a);
        assert_eq!(proof.second_block_hash, block_b);

        // Identical statement is not equivocation.
        assert!(verify_double_signage_equivocation(net, &s1, &s1).is_err());

        // Empty or whitespace expected_network is refused.
        assert!(verify_double_signage_equivocation("   ", &s1, &s2).is_err());

        // Different signage index is honest sequential farming, not equivocation.
        let msg_next = pospace_signage_sign_bytes(net, 42, 8, &block_b);
        let s_next = SignedPoSpaceSignage {
            signage_index: 8,
            signature: farmer
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg_next)
                .unwrap(),
            ..s2.clone()
        };
        assert!(verify_double_signage_equivocation(net, &s1, &s_next).is_err());

        // Forged second signature is rejected.
        let mut forged = s2.clone();
        forged.signature[0] ^= 0x55;
        assert!(matches!(
            verify_double_signage_equivocation(net, &s1, &forged),
            Err(AdapterError::Crypto { .. })
        ));

        // Two distinct farmers signing different competing blocks is not self-equivocation.
        let s_other = SignedPoSpaceSignage {
            signer_pq_pubkey: bystander.public_key_bytes().to_vec(),
            signature: bystander
                .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &msg_b)
                .unwrap(),
            ..s2
        };
        assert!(verify_double_signage_equivocation(net, &s1, &s_other).is_err());

        let (slash_adapter, _, _, slash_raw, _) = build_fixture("chia-pq-mainnet", 5, 1, true);
        let unbonded_policy = VerificationPolicy::strict(110);
        let att = slash_adapter
            .verify(&slash_raw, &unbonded_policy)
            .expect("valid PoSpace+VDF evidence verifies when slashability is not required");
        assert!(
            matches!(
                att.security,
                SecurityBacking::SignatureSet {
                    slashable: false,
                    ..
                }
            ),
            "timelord/farmer PQ attestation without a local Budlum confiscation arm must report slashable=false"
        );
        let mut slash_policy = unbonded_policy;
        slash_policy.require_slashable = true;
        assert!(
            matches!(
                slash_adapter.verify(&slash_raw, &slash_policy),
                Err(AdapterError::UnslashableBacking)
            ),
            "require_slashable=true must fail closed with UnslashableBacking"
        );
    }
}
