//! Algorand Pure-PoS (`BA*` cryptographic sortition, Micali et al. 2017) +
//! Post-Quantum `StateProof` (Lazarovich et al. 2022) external finality adapter.
//!
//! Algorand `StateProof` certificates were the first production post-quantum
//! compact light-client certificates deployed on a public Layer-1 blockchain.
//! Instead of shipping the entire validator table inside every proof, governance
//! (or the preceding state-proof interval) pins a single 32-byte vector
//! commitment (`voters_commitment`) over ordered, disjoint participant stake
//! intervals `[lower_weight, upper_weight)` covering `[0, total_weight)`, where
//! each participant binds a forward-secure ephemeral post-quantum key valid only
//! over `[key_first_round, key_last_round]`.
//!
//! [`AlgorandStateProofAdapter`] verifies every certificate with **pure NIST
//! FIPS 204 ML-DSA-65** (`SchemeId::ML_DSA_65`) - zero classical elliptic-curve
//! or pairing assumptions on the verification path:
//!
//! 1. **Genesis & interval binding.** `genesis_hash == pinned.genesis_hash`,
//!    `interval_index == pinned.interval_index`, and
//!    `pinned.first_round <= first_attested_round <= last_attested_round <= pinned.last_round`.
//! 2. **Disjoint stake-interval vector opening.** Reveals are ordered by
//!    strictly ascending leaf `position` and non-overlapping stake intervals
//!    (`prev_upper <= lower < upper <= total_weight`), preventing stake
//!    double-counting; every leaf opens to `pinned.voters_commitment` via a
//!    domain-separated binary Merkle path checked in constant time.
//! 3. **Forward-secure key lifetime.** Each revealed key must cover the attested
//!    interval (`key_first_round <= first_attested_round` and
//!    `last_attested_round <= key_last_round`).
//! 4. **Pure post-quantum signature & BFT stake threshold.** Each revealed key
//!    matches `H(mldsa65_pubkey)` in constant time and verifies under
//!    `ML-DSA-65` (`CROSS_DOMAIN_V1`). Proven weight `sum(upper - lower)` must
//!    satisfy BOTH `proven_weight * 10_000 >= total_weight * threshold_bps`
//!    (`threshold_bps >= 6_667`) AND `proven_weight * 3 > total_weight * 2` in
//!    overflow-free integer arithmetic.
//! 5. **Header vector opening.** Opens the attested round header (`state_root`,
//!    `tx_root`, `event_root`, `block_hash`) against
//!    `message.block_headers_commitment` in constant time.
//! 6. **Quantum quarantine survival.** `verify_observed` records exclusively
//!    `SchemeId::ML_DSA_65`, so an active Algorand `StateProof` domain stays
//!    live when `QuantumRegistry` quarantines all classical asymmetric bridges.
//! 7. **Verified rotation & equivocation.** [`advance_algorand_verifier`]
//!    rotates to `interval_index + 1` using the authenticated
//!    `next_voters_commitment`, and [`verify_algorand_equivocation`] proves
//!    slashable double-signing across overlapping round intervals.

//!
//! WIRING: implements `ExternalFinalityAdapter` for `ExternalDomainRegistry`; `AdapterSpec` joins `intake.rs` in the follow-up merge.

use crate::crypto::facts::{CryptoObserver, ObservedScheme};
use crate::crypto::scheme::SchemeId;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier for Algorand post-quantum `StateProof`.
pub const ADAPTER_NAME: &str = "algorand-stateproof-pq-v1";
/// Adapter implementation version.
pub const ADAPTER_VERSION: u32 = 1;
/// Accepted wire evidence version.
pub const EVIDENCE_VERSION: u32 = 1;
/// Minimum stake threshold in basis points (`6667 bps > 2/3` supermajority).
pub const MIN_THRESHOLD_BPS: u16 = 6_667;
/// Maximum basis-point denominator (`100.00%`).
pub const MAX_THRESHOLD_BPS: u16 = 10_000;
/// Hard ceiling on voter reveals inside one compact `StateProof`.
pub const MAX_STATEPROOF_REVEALS: usize = 256;
/// Hard ceiling on binary Merkle inclusion path depth (`2^32` leaves).
pub const MAX_MERKLE_DEPTH: usize = 32;

const PAYLOAD_MAGIC: &[u8; 8] = b"ALGOSPV1";
const MAX_STATEPROOF_PAYLOAD_BYTES: usize = 1_536 * 1024;
const PUBKEY_TAG: &[u8] = b"bud-algorand-sp-pk-v1";
const VOTER_LEAF_TAG: &[u8] = b"bud-algorand-sp-voter-v1";
const VOTER_NODE_TAG: &[u8] = b"bud-algorand-sp-vnode-v1";
const VOTER_EMPTY_TAG: &[u8] = b"bud-algorand-sp-vempty-v1";
const HEADER_LEAF_TAG: &[u8] = b"bud-algorand-sp-hdr-v1";
const HEADER_NODE_TAG: &[u8] = b"bud-algorand-sp-hnode-v1";
const MESSAGE_TAG: &[u8] = b"bud-algorand-sp-msg-v1";
const SIGN_TAG: &[u8] = b"bud-algorand-sp-sign-v1";

/// One step in a domain-separated binary Merkle inclusion proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProofMerkleStep {
    /// Sibling node digest at this tree level.
    pub sibling: Hash32,
    /// True when `sibling` sits on the left (`H(tag || sibling || current)`).
    pub sibling_is_left: bool,
}

/// Governance-pinned (or interval-rotated) Algorand `StateProof` verifier root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedAlgorandVerifier {
    /// External chain genesis digest isolating networks.
    pub genesis_hash: Hash32,
    /// Monotonic state-proof interval index.
    pub interval_index: u64,
    /// Inclusive first consensus round covered by this interval.
    pub first_round: u64,
    /// Inclusive last consensus round covered by this interval.
    pub last_round: u64,
    /// Vector commitment root over the ordered stake-interval voter table.
    pub voters_commitment: Hash32,
    /// Number of committed leaves in the voter vector tree.
    pub voter_count: u32,
    /// Exact total online stake partitioned across the voter table.
    pub total_weight: u128,
    /// Required proven stake fraction in basis points (`6667..=10000`).
    pub threshold_bps: u16,
}

/// Canonical `StateProof` message signed by forward-secure ML-DSA-65 voters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorandStateProofMessage {
    /// Genesis digest of the Algorand chain.
    pub genesis_hash: Hash32,
    /// State-proof interval index matching [`PinnedAlgorandVerifier::interval_index`].
    pub interval_index: u64,
    /// First finalized BA* round attested by `block_headers_commitment`.
    pub first_attested_round: u64,
    /// Last finalized BA* round attested by `block_headers_commitment`.
    pub last_attested_round: u64,
    /// Vector commitment root over all finalized block headers in the interval.
    pub block_headers_commitment: Hash32,
    /// Committed voter vector root for `interval_index + 1` (enables rotation).
    pub next_voters_commitment: Hash32,
    /// Committed voter leaf count for `interval_index + 1`.
    pub next_voter_count: u32,
    /// Committed total online stake for `interval_index + 1`.
    pub next_total_weight: u128,
}

impl AlgorandStateProofMessage {
    /// Canonical collision-free message digest.
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            MESSAGE_TAG,
            &self.genesis_hash,
            &self.interval_index.to_le_bytes(),
            &self.first_attested_round.to_le_bytes(),
            &self.last_attested_round.to_le_bytes(),
            &self.block_headers_commitment,
            &self.next_voters_commitment,
            &self.next_voter_count.to_le_bytes(),
            &self.next_total_weight.to_le_bytes(),
        ])
    }
}

/// Finalized Algorand BA* round header opened from `block_headers_commitment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorandRoundHeader {
    /// Finalized BA* round number.
    pub round: u64,
    /// Block timestamp in Unix seconds.
    pub timestamp_secs: u64,
    /// Self-derived block hash.
    pub block_hash: Hash32,
    /// Account/application state commitment root at `round`.
    pub state_root: Hash32,
    /// Payset transaction Merkle root at `round`.
    pub tx_root: Hash32,
    /// Application/bridge event commitment root at `round`.
    pub event_root: Hash32,
}

impl AlgorandRoundHeader {
    /// Leaf hash inside `block_headers_commitment`.
    #[must_use]
    pub fn leaf_hash(&self) -> Hash32 {
        crate::core::hash::hash_fields_bytes(&[
            HEADER_LEAF_TAG,
            &self.round.to_le_bytes(),
            &self.timestamp_secs.to_le_bytes(),
            &self.block_hash,
            &self.state_root,
            &self.tx_root,
            &self.event_root,
        ])
    }
}

/// One voter's revealed stake interval, forward-secure ML-DSA-65 key, signature,
/// and Merkle membership path into `voters_commitment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorandVoterReveal {
    /// 0-based index in the voter vector tree.
    pub position: u32,
    /// Inclusive lower bound of the voter's stake interval.
    pub lower_weight: u128,
    /// Exclusive upper bound of the voter's stake interval (`upper > lower`).
    pub upper_weight: u128,
    /// First round for which this forward-secure ephemeral PQ key is valid.
    pub key_first_round: u64,
    /// Last round for which this forward-secure ephemeral PQ key is valid.
    pub key_last_round: u64,
    /// NIST FIPS 204 ML-DSA-65 public key bytes.
    pub mldsa65_pubkey: Vec<u8>,
    /// NIST FIPS 204 ML-DSA-65 signature over [`stateproof_sign_digest`].
    pub mldsa65_sig: Vec<u8>,
    /// Binary Merkle path opening this voter leaf to `voters_commitment`.
    pub merkle_path: Vec<StateProofMerkleStep>,
}

/// Voter entry used to compute a canonical `voters_commitment` tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorandVoterLeaf {
    /// 0-based leaf position.
    pub position: u32,
    /// Inclusive stake interval start.
    pub lower_weight: u128,
    /// Exclusive stake interval end.
    pub upper_weight: u128,
    /// Inclusive start of forward-secure key validity.
    pub key_first_round: u64,
    /// Inclusive end of forward-secure key validity.
    pub key_last_round: u64,
    /// Domain-separated SHA-256 commitment to the voter's ML-DSA-65 public key.
    pub pubkey_commitment: Hash32,
}

/// Domain-separated commitment over an ML-DSA-65 verifying key.
#[must_use]
pub fn algorand_pubkey_commitment(mldsa65_pubkey: &[u8]) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[PUBKEY_TAG, mldsa65_pubkey])
}

/// Canonical voter leaf digest binding position, stake interval, ephemeral key
/// lifetime, and ML-DSA-65 public-key commitment.
#[must_use]
pub fn algorand_voter_leaf_hash(leaf: &AlgorandVoterLeaf) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[
        VOTER_LEAF_TAG,
        &leaf.position.to_le_bytes(),
        &leaf.lower_weight.to_le_bytes(),
        &leaf.upper_weight.to_le_bytes(),
        &leaf.key_first_round.to_le_bytes(),
        &leaf.key_last_round.to_le_bytes(),
        &leaf.pubkey_commitment,
    ])
}

fn merkle_parent(node_tag: &[u8], left: &Hash32, right: &Hash32) -> Hash32 {
    let mut h = Sha256::new();
    h.update(node_tag);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Compute a canonical binary Merkle root and optional inclusion path for
/// `target_index`, promoting odd trailing nodes without duplicating them (so a
/// duplicated trailing leaf can never forge an odd-width collision).
#[must_use]
pub fn build_stateproof_merkle(
    node_tag: &[u8],
    leaves: &[Hash32],
    target_index: Option<usize>,
) -> (Hash32, Vec<StateProofMerkleStep>) {
    if leaves.is_empty() {
        return (
            crate::core::hash::hash_fields_bytes(&[VOTER_EMPTY_TAG]),
            Vec::new(),
        );
    }
    let mut level = leaves.to_vec();
    let mut idx = target_index;
    let mut path = Vec::new();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut pair_start = 0usize;
        while pair_start < level.len() {
            let Some(&left) = level.get(pair_start) else {
                break;
            };
            if let Some(&right) = level.get(pair_start.saturating_add(1)) {
                if let Some(cur) = idx {
                    if cur == pair_start {
                        path.push(StateProofMerkleStep {
                            sibling: right,
                            sibling_is_left: false,
                        });
                    } else if cur == pair_start.saturating_add(1) {
                        path.push(StateProofMerkleStep {
                            sibling: left,
                            sibling_is_left: true,
                        });
                    }
                }
                next.push(merkle_parent(node_tag, &left, &right));
            } else {
                next.push(left);
            }
            pair_start = pair_start.saturating_add(2);
        }
        idx = idx.map(|i| i / 2);
        level = next;
    }
    let root = level.first().copied().unwrap_or([0u8; 32]);
    (root, path)
}

/// Fold a Merkle path and verify exact structural alignment with `(leaf_count,
/// position)` so a left/right-swapped or odd-promoted sibling cannot forge a
/// second index.
fn fold_checked_merkle(
    node_tag: &[u8],
    leaf_count: usize,
    position: usize,
    leaf: Hash32,
    path: &[StateProofMerkleStep],
) -> Option<Hash32> {
    if leaf_count == 0 || position >= leaf_count || path.len() > MAX_MERKLE_DEPTH {
        return None;
    }
    let mut cur = leaf;
    let mut width = leaf_count;
    let mut idx = position;
    let mut step_iter = path.iter();
    while width > 1 {
        let is_odd_tail = idx.is_multiple_of(2) && idx.saturating_add(1) == width;
        if !is_odd_tail {
            let step = step_iter.next()?;
            let expect_left = (idx % 2) == 1;
            if step.sibling_is_left != expect_left {
                return None;
            }
            cur = if step.sibling_is_left {
                merkle_parent(node_tag, &step.sibling, &cur)
            } else {
                merkle_parent(node_tag, &cur, &step.sibling)
            };
        }
        idx /= 2;
        width = width.div_ceil(2);
    }
    if step_iter.next().is_some() {
        return None;
    }
    Some(cur)
}

/// Build the voter vector commitment root (and optional proof for `target`)
/// over a valid partition of `total_weight`.
#[must_use]
/// Convenience: exposed for external Algorand `StateProof` relayers and fixtures.
pub fn build_voters_commitment(
    voters: &[AlgorandVoterLeaf],
    target_index: Option<usize>,
) -> (Hash32, Vec<StateProofMerkleStep>) {
    let leaves: Vec<Hash32> = voters.iter().map(algorand_voter_leaf_hash).collect();
    build_stateproof_merkle(VOTER_NODE_TAG, &leaves, target_index)
}

/// Build the block-header vector commitment root and optional proof.
#[must_use]
/// Convenience: exposed for external Algorand `StateProof` relayers and fixtures.
pub fn build_headers_commitment(
    headers: &[AlgorandRoundHeader],
    target_index: Option<usize>,
) -> (Hash32, Vec<StateProofMerkleStep>) {
    let leaves: Vec<Hash32> = headers.iter().map(AlgorandRoundHeader::leaf_hash).collect();
    build_stateproof_merkle(HEADER_NODE_TAG, &leaves, target_index)
}

/// Canonical domain-separated signing digest bound to `network` and `message`.
#[must_use]
pub fn stateproof_sign_digest(network: &str, message: &AlgorandStateProofMessage) -> Hash32 {
    crate::core::hash::hash_fields_bytes(&[SIGN_TAG, network.as_bytes(), &message.digest()])
}

/// Overflow-free exact check for `proven * 10_000 >= total * threshold_bps` and
/// `proven * 3 > total * 2` across the entire `u128` domain using split
/// quotient/remainder arithmetic.
fn meets_stake_threshold(proven: u128, total: u128, threshold_bps: u16) -> bool {
    if total == 0 || proven == 0 || proven > total {
        return false;
    }
    if !(MIN_THRESHOLD_BPS..=MAX_THRESHOLD_BPS).contains(&threshold_bps) {
        return false;
    }
    // Strict > 2/3 BFT supermajority: proven > floor(2 * total / 3).
    // Write total = 3*q + r (r in 0..3): floor(2*total/3) = 2*q + (2*r)/3.
    let q3 = total / 3;
    let r3 = total % 3;
    let two_thirds_floor = q3.saturating_mul(2).saturating_add((r3 * 2) / 3);
    if proven <= two_thirds_floor {
        return false;
    }
    // Exact bps check: proven >= ceil(total * bps / 10_000).
    let bps = u128::from(threshold_bps);
    let denom = u128::from(MAX_THRESHOLD_BPS);
    let q = total / denom;
    let r = total % denom;
    // r < 10_000 and bps <= 10_000 => r * bps <= 100_000_000 (never overflows).
    let prod_r = r * bps;
    let rem_ceil = prod_r.div_ceil(denom);
    let Some(min_required) = q.checked_mul(bps).and_then(|v| v.checked_add(rem_ceil)) else {
        return false;
    };
    proven >= min_required
}

/// Wire payload carrying one Algorand post-quantum `StateProof` and its opened
/// finalized round header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AlgorandStateProofEvidence {
    message: AlgorandStateProofMessage,
    header: AlgorandRoundHeader,
    header_position: u32,
    header_count: u32,
    header_path: Vec<StateProofMerkleStep>,
    reveals: Vec<AlgorandVoterReveal>,
}

/// Encode an Algorand `StateProof` bundle into its canonical wire payload.
///
/// # Errors
///
/// Returns an error if serialization fails or exceeds the payload ceiling.
/// Convenience: exposed for external Algorand `StateProof` relayer encoders.
pub fn encode_algorand_stateproof(
    message: AlgorandStateProofMessage,
    header: AlgorandRoundHeader,
    header_position: u32,
    header_count: u32,
    header_path: Vec<StateProofMerkleStep>,
    reveals: Vec<AlgorandVoterReveal>,
) -> Result<Vec<u8>, String> {
    let bundle = AlgorandStateProofEvidence {
        message,
        header,
        header_position,
        header_count,
        header_path,
        reveals,
    };
    let body =
        bincode::serialize(&bundle).map_err(|e| format!("Algorand StateProof encode: {e}"))?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_STATEPROOF_PAYLOAD_BYTES {
        return Err(format!(
            "Algorand StateProof payload {total} exceeds ceiling {MAX_STATEPROOF_PAYLOAD_BYTES}"
        ));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_algorand_stateproof(payload: &[u8]) -> Result<AlgorandStateProofEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "Algorand StateProof payload shorter than 8-byte magic".into(),
        });
    }
    if payload.len() > MAX_STATEPROOF_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: MAX_STATEPROOF_PAYLOAD_BYTES,
            reason: format!(
                "Algorand StateProof payload exceeds {MAX_STATEPROOF_PAYLOAD_BYTES} bytes"
            ),
        });
    }
    if payload.get(0..8) != Some(PAYLOAD_MAGIC.as_slice()) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "Algorand StateProof magic mismatch".into(),
        });
    }
    let body = payload.get(8..).ok_or_else(|| AdapterError::Malformed {
        offset: 8,
        reason: "missing Algorand StateProof body".into(),
    })?;
    let decoded: AlgorandStateProofEvidence =
        crate::network::bounded_bincode::decode_bounded_bincode(body, MAX_STATEPROOF_PAYLOAD_BYTES)
            .map_err(|e| AdapterError::Malformed {
                offset: 8,
                reason: format!("invalid Algorand StateProof evidence: {e}"),
            })?;
    if bincode::serialized_size(&decoded).ok() != u64::try_from(body.len()).ok() {
        return Err(AdapterError::Malformed {
            offset: 8,
            reason: "trailing bytes after canonical Algorand StateProof evidence".into(),
        });
    }
    Ok(decoded)
}

fn verify_stateproof_bundle(
    network: &str,
    pinned: &PinnedAlgorandVerifier,
    bundle: &AlgorandStateProofEvidence,
) -> Result<(u64, u64), AdapterError> {
    if pinned.genesis_hash == [0u8; 32]
        || pinned.voters_commitment == [0u8; 32]
        || pinned.voter_count == 0
        || pinned.total_weight == 0
        || pinned.first_round == 0
        || pinned.first_round > pinned.last_round
    {
        return Err(AdapterError::ConsensusRule {
            rule: "pinned Algorand StateProof verifier has zero or inverted parameters".into(),
        });
    }
    if pinned.threshold_bps < MIN_THRESHOLD_BPS || pinned.threshold_bps > MAX_THRESHOLD_BPS {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "pinned Algorand threshold_bps {} outside {MIN_THRESHOLD_BPS}..={MAX_THRESHOLD_BPS}",
                pinned.threshold_bps
            ),
        });
    }

    let msg = &bundle.message;
    if !bool::from(
        msg.genesis_hash
            .as_slice()
            .ct_eq(pinned.genesis_hash.as_slice()),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand StateProof genesis_hash mismatches pinned chain".into(),
        });
    }
    if msg.interval_index != pinned.interval_index {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Algorand StateProof interval {} mismatches pinned {}",
                msg.interval_index, pinned.interval_index
            ),
        });
    }
    if msg.first_attested_round < pinned.first_round
        || msg.first_attested_round > msg.last_attested_round
        || msg.last_attested_round > pinned.last_round
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand StateProof attested round range falls outside pinned interval".into(),
        });
    }
    if msg.block_headers_commitment == [0u8; 32] {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand StateProof block_headers_commitment is zero".into(),
        });
    }

    // Verify opened round header lies inside the attested range and matches
    // `block_headers_commitment` in constant time.
    let hdr = &bundle.header;
    if hdr.round < msg.first_attested_round
        || hdr.round > msg.last_attested_round
        || hdr.state_root == [0u8; 32]
        || hdr.block_hash == [0u8; 32]
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand opened round header out of attested range or carries zero root".into(),
        });
    }
    let expected_hdr_count = msg
        .last_attested_round
        .checked_sub(msg.first_attested_round)
        .and_then(|d| d.checked_add(1))
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Algorand attested header span overflow".into(),
        })?;
    if u64::from(bundle.header_count) != expected_hdr_count {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand header_count mismatches inclusive attested round span".into(),
        });
    }
    let expected_hdr_pos = hdr.round - msg.first_attested_round;
    if u64::from(bundle.header_position) != expected_hdr_pos {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand header_position mismatches round offset in interval".into(),
        });
    }
    let hdr_count =
        usize::try_from(bundle.header_count).map_err(|_| AdapterError::ConsensusRule {
            rule: "Algorand header_count overflows usize".into(),
        })?;
    let hdr_pos =
        usize::try_from(bundle.header_position).map_err(|_| AdapterError::ConsensusRule {
            rule: "Algorand header_position overflows usize".into(),
        })?;
    let derived_hdr_root = fold_checked_merkle(
        HEADER_NODE_TAG,
        hdr_count,
        hdr_pos,
        hdr.leaf_hash(),
        &bundle.header_path,
    )
    .ok_or_else(|| AdapterError::ConsensusRule {
        rule: "invalid Algorand header Merkle path structure".into(),
    })?;
    if !bool::from(
        derived_hdr_root
            .as_slice()
            .ct_eq(msg.block_headers_commitment.as_slice()),
    ) {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand round header fails inclusion in block_headers_commitment".into(),
        });
    }

    // Verify ordered, non-overlapping stake-interval reveals + pure ML-DSA-65 sigs.
    if bundle.reveals.is_empty() || bundle.reveals.len() > MAX_STATEPROOF_REVEALS {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand StateProof reveal count outside valid bounds".into(),
        });
    }
    let voter_count =
        usize::try_from(pinned.voter_count).map_err(|_| AdapterError::ConsensusRule {
            rule: "Algorand voter_count overflows usize".into(),
        })?;
    let sign_digest = stateproof_sign_digest(network, msg);
    let mut prev_pos: Option<u32> = None;
    let mut prev_upper: u128 = 0;
    let mut proven_weight: u128 = 0;

    for reveal in &bundle.reveals {
        if prev_pos.is_some_and(|p| reveal.position <= p) {
            return Err(AdapterError::ConsensusRule {
                rule: "Algorand voter reveals must be strictly ascending by position".into(),
            });
        }
        prev_pos = Some(reveal.position);

        if reveal.lower_weight < prev_upper
            || reveal.lower_weight >= reveal.upper_weight
            || reveal.upper_weight > pinned.total_weight
        {
            return Err(AdapterError::ConsensusRule {
                rule:
                    "Algorand voter stake interval is empty, overlapping, or exceeds total_weight"
                        .into(),
            });
        }
        prev_upper = reveal.upper_weight;

        // Forward-secure ephemeral key lifetime check.
        if reveal.key_first_round > msg.first_attested_round
            || reveal.key_last_round < msg.last_attested_round
        {
            return Err(AdapterError::ConsensusRule {
                rule: "Algorand voter forward-secure PQ key expired or not yet active for round"
                    .into(),
            });
        }
        if reveal.mldsa65_pubkey.is_empty() || reveal.mldsa65_sig.is_empty() {
            return Err(AdapterError::Crypto {
                what: "Algorand StateProof reveal missing ML-DSA-65 key or signature".into(),
            });
        }

        let pk_commitment = algorand_pubkey_commitment(&reveal.mldsa65_pubkey);
        let leaf = AlgorandVoterLeaf {
            position: reveal.position,
            lower_weight: reveal.lower_weight,
            upper_weight: reveal.upper_weight,
            key_first_round: reveal.key_first_round,
            key_last_round: reveal.key_last_round,
            pubkey_commitment: pk_commitment,
        };
        let pos = usize::try_from(reveal.position).map_err(|_| AdapterError::ConsensusRule {
            rule: "Algorand voter position overflows usize".into(),
        })?;
        let derived_voter_root = fold_checked_merkle(
            VOTER_NODE_TAG,
            voter_count,
            pos,
            algorand_voter_leaf_hash(&leaf),
            &reveal.merkle_path,
        )
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "invalid Algorand voter Merkle path structure".into(),
        })?;
        if !bool::from(
            derived_voter_root
                .as_slice()
                .ct_eq(pinned.voters_commitment.as_slice()),
        ) {
            return Err(AdapterError::ConsensusRule {
                rule: "Algorand voter leaf does not open to pinned voters_commitment".into(),
            });
        }

        crate::crypto::primitives::PqKeyPair::verify(
            &reveal.mldsa65_pubkey,
            crate::crypto::ctx::CROSS_DOMAIN_V1,
            &sign_digest,
            &reveal.mldsa65_sig,
        )
        .map_err(|_| AdapterError::Crypto {
            what: "invalid ML-DSA-65 signature in Algorand StateProof reveal".into(),
        })?;

        let voter_weight = reveal.upper_weight - reveal.lower_weight;
        proven_weight =
            proven_weight
                .checked_add(voter_weight)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "Algorand proven stake weight overflows u128".into(),
                })?;
    }

    if !meets_stake_threshold(proven_weight, pinned.total_weight, pinned.threshold_bps) {
        return Err(AdapterError::ConsensusRule {
            rule: format!(
                "Algorand StateProof proven weight {proven_weight}/{} below {} bps supermajority",
                pinned.total_weight, pinned.threshold_bps
            ),
        });
    }

    let signers = bundle.reveals.len() as u64;
    let required = (u64::from(pinned.voter_count).saturating_mul(u64::from(pinned.threshold_bps)))
        .div_ceil(u64::from(MAX_THRESHOLD_BPS))
        .max(1);
    Ok((signers, required))
}

/// Verify a `StateProof` payload under `pinned` and rotate the verifier state
/// to `interval_index + 1` using the authenticated `next_voters_commitment`.
///
/// # Errors
///
/// Returns an [`AdapterError`] if the proof fails verification or omits a
/// well-formed next-interval commitment.
pub fn advance_algorand_verifier(
    network: &str,
    pinned: &PinnedAlgorandVerifier,
    payload: &[u8],
    next_interval_span: u64,
) -> Result<PinnedAlgorandVerifier, AdapterError> {
    if next_interval_span == 0 {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand next_interval_span must be non-zero".into(),
        });
    }
    let bundle = decode_algorand_stateproof(payload)?;
    verify_stateproof_bundle(network, pinned, &bundle)?;
    let msg = &bundle.message;
    if msg.next_voters_commitment == [0u8; 32]
        || msg.next_voter_count == 0
        || msg.next_total_weight == 0
    {
        return Err(AdapterError::ConsensusRule {
            rule: "Algorand StateProof carries empty next-interval verifier commitment".into(),
        });
    }
    let next_index =
        pinned
            .interval_index
            .checked_add(1)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "Algorand interval_index overflows u64".into(),
            })?;
    let next_first =
        pinned
            .last_round
            .checked_add(1)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "Algorand next first_round overflows u64".into(),
            })?;
    let next_last = next_first
        .checked_add(next_interval_span.saturating_sub(1))
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "Algorand next last_round overflows u64".into(),
        })?;
    Ok(PinnedAlgorandVerifier {
        genesis_hash: pinned.genesis_hash,
        interval_index: next_index,
        first_round: next_first,
        last_round: next_last,
        voters_commitment: msg.next_voters_commitment,
        voter_count: msg.next_voter_count,
        total_weight: msg.next_total_weight,
        threshold_bps: pinned.threshold_bps,
    })
}

#[path = "algorand_stateproof_faults.rs"]
mod faults;

pub use faults::{verify_algorand_equivocation, AlgorandEquivocationProof};

/// External finality adapter for Algorand Pure-PoS BA* + post-quantum `StateProof`.
pub struct AlgorandStateProofAdapter {
    network: String,
    pinned: Option<PinnedAlgorandVerifier>,
    golden: Option<RawConsensusEvidence>,
    descriptor: AdapterDescriptor,
}

impl AlgorandStateProofAdapter {
    /// Construct an [`AlgorandStateProofAdapter`] bound to `network` and `pinned`.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedAlgorandVerifier>) -> Self {
        let set_size = pinned.as_ref().map_or(0, |p| u64::from(p.voter_count));
        Self {
            network: network.into(),
            pinned,
            golden: None,
            descriptor: AdapterDescriptor {
                id: AdapterId::from_name(ADAPTER_NAME),
                name: ADAPTER_NAME.to_string(),
                adapter_version: ADAPTER_VERSION,
                accepted_evidence_versions: vec![EVIDENCE_VERSION],
                consensus_kind: "algorand-pure-pos-stateproof-pq".to_string(),
                finality_kind: FinalityKind::ProtocolFinality,
                required_depth: 1,
                time_unit: TimeUnit::Round,
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
    ) -> Result<FinalityAttestation, AdapterError> {
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
                    "Algorand StateProof network '{}' mismatches pinned '{}'",
                    evidence.network, self.network
                ),
            });
        }
        let Some(pinned) = &self.pinned else {
            return Err(AdapterError::ConsensusRule {
                rule: "no pinned Algorand StateProof verifier; admission is closed".into(),
            });
        };

        let bundle = decode_algorand_stateproof(&evidence.payload)?;
        let hdr = &bundle.header;
        if policy.require_declared_match {
            if evidence.declared_height != hdr.round {
                return Err(AdapterError::DeclarationMismatch { field: "height" });
            }
            if !bool::from(
                evidence
                    .declared_root
                    .as_slice()
                    .ct_eq(hdr.state_root.as_slice()),
            ) {
                return Err(AdapterError::DeclarationMismatch { field: "root" });
            }
        }
        // BA* achieves immediate single-round deterministic finality; depth
        // inside a StateProof is 1 + (last_attested_round - hdr.round).
        let observed_depth = bundle
            .message
            .last_attested_round
            .saturating_sub(hdr.round)
            .saturating_add(1);
        if observed_depth < policy.min_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: observed_depth,
                required: policy.min_depth,
            });
        }
        if policy.max_age > 0 && policy.now > hdr.round {
            let age = policy.now - hdr.round;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        let (signers, required) = verify_stateproof_bundle(&self.network, pinned, &bundle)?;

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &evidence.network),
            height: hdr.round,
            state_root: hdr.state_root,
            finalized_at: hdr.round,
            time_unit: TimeUnit::Round,
            security: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers,
                required,
                total_weight: pinned.total_weight,
                slashable: true,
            },
            evidence_digest: evidence.digest(),
            adapter_version: self.descriptor.adapter_version,
            evidence_version: evidence.evidence_version,
            attested_block_hash: Some(hdr.block_hash),
            attested_event_root: Some(hdr.event_root),
            attested_tx_root: Some(hdr.tx_root),
        })
    }
}

impl ExternalFinalityAdapter for AlgorandStateProofAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_inner(evidence, policy)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let att = self.verify_inner(evidence, policy)?;
        observer.observe(ObservedScheme::Scheme(SchemeId::ML_DSA_65));
        Ok(att)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let sig_offset = self
            .golden
            .as_ref()
            .map_or(64, |g| g.payload.len().saturating_sub(80));
        vec![
            FaultProbe {
                name: "refuses unsupported Algorand StateProof evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 42 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses wrong Algorand network identifier".into(),
                patch: BytePatch::Network {
                    value: "algorand-betanet-wrong".into(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted ALGOSPV1 magic prefix".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"BADMAGIC".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses truncated StateProof payload".into(),
                patch: BytePatch::TruncatePayload { keep: 12 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses forged genesis_hash inside StateProof message".into(),
                patch: BytePatch::InPayload {
                    offset: 8,
                    bytes: vec![0xFF; 8],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses lied declared round number".into(),
                patch: BytePatch::DeclaredHeight { value: 77_777_777 },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses lied declared state_root".into(),
                patch: BytePatch::DeclaredRoot { value: [0xCD; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses corrupted voter ML-DSA-65 signature / Merkle tail".into(),
                patch: BytePatch::InPayload {
                    offset: sig_offset,
                    bytes: vec![0x5C, 0xC5, 0x5C, 0xC5],
                },
                expect: ExpectedRefusal::Any,
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
    use crate::crypto::facts::CryptoFacts;
    use crate::crypto::primitives::PqKeyPair;

    const NET: &str = "algorand-mainnet-v1";

    struct Fixture {
        pinned: PinnedAlgorandVerifier,
        keys: Vec<PqKeyPair>,
        voters: Vec<AlgorandVoterLeaf>,
        message: AlgorandStateProofMessage,
        headers: Vec<AlgorandRoundHeader>,
        golden: RawConsensusEvidence,
    }

    fn build_fixture() -> Fixture {
        // 4 voters with disjoint stake intervals covering [0, 1000):
        // v0=[0,300), v1=[300,600), v2=[600,850), v3=[850,1000).
        // Reveals by {v0, v1, v2} prove 850/1000 = 8500 bps >= 7000 bps (> 2/3).
        let intervals = [(0u128, 300u128), (300, 600), (600, 850), (850, 1_000)];
        let keys: Vec<PqKeyPair> = (0..4).map(|_| PqKeyPair::generate()).collect();
        let voters: Vec<AlgorandVoterLeaf> = intervals
            .iter()
            .enumerate()
            .map(|(i, &(lo, hi))| AlgorandVoterLeaf {
                position: i as u32,
                lower_weight: lo,
                upper_weight: hi,
                key_first_round: 10_000,
                key_last_round: 10_255,
                pubkey_commitment: algorand_pubkey_commitment(keys[i].public_key_bytes()),
            })
            .collect();
        let (voters_commitment, _) = build_voters_commitment(&voters, None);

        let headers: Vec<AlgorandRoundHeader> = (10_100u64..=10_102)
            .map(|r| {
                let b = (r - 10_050) as u8;
                AlgorandRoundHeader {
                    round: r,
                    timestamp_secs: 1_730_000_000 + r,
                    block_hash: [b; 32],
                    state_root: [b.wrapping_add(0x10); 32],
                    tx_root: [b.wrapping_add(0x20); 32],
                    event_root: [b.wrapping_add(0x30); 32],
                }
            })
            .collect();
        let (hdr_root, hdr_path) = build_headers_commitment(&headers, Some(2));

        // Next interval committee commitment for rotation test.
        let next_key = PqKeyPair::generate();
        let next_voters = vec![AlgorandVoterLeaf {
            position: 0,
            lower_weight: 0,
            upper_weight: 2_000,
            key_first_round: 10_256,
            key_last_round: 10_511,
            pubkey_commitment: algorand_pubkey_commitment(next_key.public_key_bytes()),
        }];
        let (next_voters_commitment, _) = build_voters_commitment(&next_voters, None);

        let genesis_hash = [0xA1; 32];
        let pinned = PinnedAlgorandVerifier {
            genesis_hash,
            interval_index: 40,
            first_round: 10_000,
            last_round: 10_255,
            voters_commitment,
            voter_count: 4,
            total_weight: 1_000,
            threshold_bps: 7_000,
        };
        let message = AlgorandStateProofMessage {
            genesis_hash,
            interval_index: 40,
            first_attested_round: 10_100,
            last_attested_round: 10_102,
            block_headers_commitment: hdr_root,
            next_voters_commitment,
            next_voter_count: 1,
            next_total_weight: 2_000,
        };
        let sign_digest = stateproof_sign_digest(NET, &message);

        let reveals: Vec<AlgorandVoterReveal> = (0..3usize)
            .map(|i| {
                let (_, path) = build_voters_commitment(&voters, Some(i));
                let sig = keys[i]
                    .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sign_digest)
                    .expect("ML-DSA-65 sign");
                AlgorandVoterReveal {
                    position: voters[i].position,
                    lower_weight: voters[i].lower_weight,
                    upper_weight: voters[i].upper_weight,
                    key_first_round: voters[i].key_first_round,
                    key_last_round: voters[i].key_last_round,
                    mldsa65_pubkey: keys[i].public_key_bytes().to_vec(),
                    mldsa65_sig: sig,
                    merkle_path: path,
                }
            })
            .collect();

        let target_hdr = headers[2].clone();
        let payload = encode_algorand_stateproof(
            message.clone(),
            target_hdr.clone(),
            2,
            3,
            hdr_path,
            reveals,
        )
        .expect("encode");
        let golden = RawConsensusEvidence {
            adapter: AdapterId::from_name(ADAPTER_NAME),
            network: NET.into(),
            evidence_version: EVIDENCE_VERSION,
            declared_height: target_hdr.round,
            declared_root: target_hdr.state_root,
            payload,
            submitter: Address::from([0x12; 32]),
        };

        Fixture {
            pinned,
            keys,
            voters,
            message,
            headers,
            golden,
        }
    }

    #[test]
    fn algorand_pq_stateproof_passes_selftest_observes_only_mldsa65_and_rotates_interval() {
        let fx = build_fixture();
        let adapter = AlgorandStateProofAdapter::new(NET, Some(fx.pinned.clone()))
            .with_golden(fx.golden.clone());
        let policy = VerificationPolicy {
            require_slashable: false,
            min_depth: 1,
            max_age: 50,
            now: 10_110,
            require_declared_match: true,
        };

        let report = selftest::admit(&adapter, &policy);
        assert!(
            report.admitted,
            "Algorand StateProof admission failed: {report:?}"
        );
        assert_eq!(report.passed(), adapter.fault_probes().len());

        // Verify pure PQ scheme observation: ZERO classical schemes recorded, so
        // QuantumRegistry classical quarantine leaves this domain 100% active!
        let mut observed = CryptoFacts::new();
        let att = adapter
            .verify_observed(&fx.golden, &policy, &mut observed)
            .expect("verify_observed");
        assert_eq!(att.height, 10_102);
        assert_eq!(att.state_root, fx.headers[2].state_root);
        assert_eq!(att.attested_tx_root, Some(fx.headers[2].tx_root));
        assert_eq!(att.attested_event_root, Some(fx.headers[2].event_root));
        assert_eq!(
            observed.quantum_class(),
            Some(crate::crypto::facts::QuantumClass::Lattice)
        );
        assert_eq!(
            att.security.observed_scheme(),
            Some(ObservedScheme::Scheme(SchemeId::ML_DSA_65))
        );

        // Verified zero-trust interval rotation to interval 41!
        let next = advance_algorand_verifier(NET, &fx.pinned, &fx.golden.payload, 256)
            .expect("verified interval rotation");
        assert_eq!(next.interval_index, 41);
        assert_eq!(next.first_round, 10_256);
        assert_eq!(next.last_round, 10_511);
        assert_eq!(next.voters_commitment, fx.message.next_voters_commitment);
        assert_eq!(next.total_weight, 2_000);
    }

    #[test]
    fn algorand_refuses_subthreshold_overlapping_intervals_and_proves_voter_equivocation() {
        let fx = build_fixture();
        let adapter = AlgorandStateProofAdapter::new(NET, Some(fx.pinned.clone()));
        let policy = VerificationPolicy {
            require_slashable: false,
            min_depth: 1,
            max_age: 0,
            now: 0,
            require_declared_match: true,
        };

        // 1. Only {v0, v1} sign => 600/1000 = 6000 bps < 6667 bps & 7000 bps => refused!
        let sign_digest = stateproof_sign_digest(NET, &fx.message);
        let (_, hdr_path) = build_headers_commitment(&fx.headers, Some(2));
        let sub_reveals: Vec<AlgorandVoterReveal> = (0..2usize)
            .map(|i| {
                let (_, path) = build_voters_commitment(&fx.voters, Some(i));
                AlgorandVoterReveal {
                    position: fx.voters[i].position,
                    lower_weight: fx.voters[i].lower_weight,
                    upper_weight: fx.voters[i].upper_weight,
                    key_first_round: fx.voters[i].key_first_round,
                    key_last_round: fx.voters[i].key_last_round,
                    mldsa65_pubkey: fx.keys[i].public_key_bytes().to_vec(),
                    mldsa65_sig: fx.keys[i]
                        .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sign_digest)
                        .unwrap(),
                    merkle_path: path,
                }
            })
            .collect();
        let sub_ev = RawConsensusEvidence {
            payload: encode_algorand_stateproof(
                fx.message.clone(),
                fx.headers[2].clone(),
                2,
                3,
                hdr_path.clone(),
                sub_reveals.clone(),
            )
            .unwrap(),
            ..fx.golden.clone()
        };
        assert!(
            matches!(
                adapter.verify(&sub_ev, &policy),
                Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("supermajority")
            ),
            "60% stake must fail >2/3 & 7000 bps threshold"
        );

        // 2. Malicious tree committing overlapping intervals [0,500) and [200,700)
        // must be refused before double-counting weight!
        let bad_voters = vec![
            AlgorandVoterLeaf {
                position: 0,
                lower_weight: 0,
                upper_weight: 500,
                key_first_round: 10_000,
                key_last_round: 10_255,
                pubkey_commitment: algorand_pubkey_commitment(fx.keys[0].public_key_bytes()),
            },
            AlgorandVoterLeaf {
                position: 1,
                lower_weight: 200,
                upper_weight: 700,
                key_first_round: 10_000,
                key_last_round: 10_255,
                pubkey_commitment: algorand_pubkey_commitment(fx.keys[1].public_key_bytes()),
            },
        ];
        let (bad_root, p0) = build_voters_commitment(&bad_voters, Some(0));
        let (_, p1) = build_voters_commitment(&bad_voters, Some(1));
        let mut bad_pin = fx.pinned.clone();
        bad_pin.voters_commitment = bad_root;
        bad_pin.voter_count = 2;
        let overlap_adapter = AlgorandStateProofAdapter::new(NET, Some(bad_pin));
        let overlap_ev = RawConsensusEvidence {
            payload: encode_algorand_stateproof(
                fx.message.clone(),
                fx.headers[2].clone(),
                2,
                3,
                hdr_path,
                vec![
                    AlgorandVoterReveal {
                        position: 0,
                        lower_weight: 0,
                        upper_weight: 500,
                        key_first_round: 10_000,
                        key_last_round: 10_255,
                        mldsa65_pubkey: fx.keys[0].public_key_bytes().to_vec(),
                        mldsa65_sig: fx.keys[0]
                            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sign_digest)
                            .unwrap(),
                        merkle_path: p0,
                    },
                    AlgorandVoterReveal {
                        position: 1,
                        lower_weight: 200,
                        upper_weight: 700,
                        key_first_round: 10_000,
                        key_last_round: 10_255,
                        mldsa65_pubkey: fx.keys[1].public_key_bytes().to_vec(),
                        mldsa65_sig: fx.keys[1]
                            .sign(crate::crypto::ctx::CROSS_DOMAIN_V1, &sign_digest)
                            .unwrap(),
                        merkle_path: p1,
                    },
                ],
            )
            .unwrap(),
            ..fx.golden.clone()
        };
        assert!(
            matches!(
                overlap_adapter.verify(&overlap_ev, &policy),
                Err(AdapterError::ConsensusRule { ref rule }) if rule.contains("overlapping")
            ),
            "overlapping stake intervals must be rejected"
        );

        // 3. Accountable equivocation: v0 signs a conflicting header commitment for round 10_102!
        let mut conflicting_msg = fx.message.clone();
        conflicting_msg.block_headers_commitment = [0xFE; 32];
        let sig_b = fx.keys[0]
            .sign(
                crate::crypto::ctx::CROSS_DOMAIN_V1,
                &stateproof_sign_digest(NET, &conflicting_msg),
            )
            .unwrap();
        let eq_proof = AlgorandEquivocationProof {
            message_a: fx.message.clone(),
            reveal_a: sub_reveals[0].clone(),
            message_b: conflicting_msg,
            sig_b,
        };
        let slashed_weight =
            verify_algorand_equivocation(NET, &fx.pinned, &eq_proof).expect("equivocation valid");
        assert_eq!(slashed_weight, 300);

        // Identical message must NOT slash honest voter.
        let non_eq = AlgorandEquivocationProof {
            message_a: fx.message.clone(),
            reveal_a: sub_reveals[0].clone(),
            message_b: fx.message,
            sig_b: sub_reveals[0].mldsa65_sig.clone(),
        };
        assert!(verify_algorand_equivocation(NET, &fx.pinned, &non_eq).is_err());

        // Extreme u128::MAX stake arithmetic never overflows or false-passes.
        assert!(meets_stake_threshold(u128::MAX - 1, u128::MAX, 6_667));
        assert!(!meets_stake_threshold(
            (u128::MAX / 3) * 2,
            u128::MAX,
            6_667
        ));
    }
}
