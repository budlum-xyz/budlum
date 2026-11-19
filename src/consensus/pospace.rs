//! Proof of Space (PoSpace) consensus engine.
//!
//! PoSpace requires miners to commit balanced Merkle storage plots and answer
//! deterministic slot challenges by opening the challenged leaf against the
//! registered `plot_id` (Merkle root). Every produced block carries a
//! hash-covered Merkle opening witness in `vrf_proof` and a challenge-bound
//! response digest in `vrf_output`. Both `validate_block` and
//! `fork_choice_score` fail closed: any unregistered producer, unregistered
//! `plot_id`, mismatched `size_bytes`, wrong challenged leaf index, or invalid
//! Merkle opening is rejected (`score = 0`).

use crate::consensus::split_resolver::{resolve_split_tie, SplitCandidate, SplitDecision};
use crate::consensus::{ConsensusEngine, ConsensusError};
use crate::core::account::AccountState;
use crate::core::block::Block;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::RwLock;
use subtle::ConstantTimeEq;

/// Maximum registered storage plots retained by one `PoSpaceEngine`.
const MAX_POSPACE_PLOTS: usize = 4_096;
/// Maximum Merkle tree depth accepted for a plot proof (`2^24` leaves).
const MAX_PLOT_MERKLE_DEPTH: u8 = 24;
/// Maximum leaves accepted when building an in-memory local miner plot.
const MAX_LOCAL_MINER_LEAVES: usize = 1 << 16;
/// Maximum credible capacity credited to a single plot (1 PiB) so forged
/// `u64::MAX` witnesses cannot dominate fork choice.
const MAX_PLOT_SIZE_BYTES: u64 = 1_u64 << 50;
const POSPACE_WITNESS_MAGIC: &[u8; 8] = b"BDLMSPC2";
/// Fixed witness header (121 bytes): magic(8), plot_id(32), challenge(32),
/// size_bytes(8), tree_depth(1), leaf_index(8), and leaf_value(32), followed
/// by `tree_depth * 32` sibling hashes.
const POSPACE_WITNESS_HEADER_LEN: usize = 8 + 32 + 32 + 8 + 1 + 8 + 32;

/// PoSpace configuration.
#[derive(Debug, Clone)]
pub struct PoSpaceConfig {
    /// Minimum plot size in bytes required to participate.
    pub min_plot_size_bytes: u64,
    /// Number of blocks between challenge rotations.
    pub challenge_interval: u64,
}

impl Default for PoSpaceConfig {
    fn default() -> Self {
        Self {
            min_plot_size_bytes: 1_024 * 1_024,
            challenge_interval: 10,
        }
    }
}

/// Canonical Merkle inclusion proof for one committed 32-byte plot leaf.
/// WIRING: Proof envelope supplied to [`PoSpaceEngine::register_verified_plot`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlotMerkleProof {
    /// Zero-based leaf position inside the `2^tree_depth`-leaf plot tree.
    pub leaf_index: u64,
    /// Raw 32-byte committed plot leaf preimage (must be non-zero).
    pub leaf_value: [u8; 32],
    /// Bottom-up sibling hashes (`len == tree_depth`).
    pub siblings: Vec<[u8; 32]>,
}

/// Registered storage plot record.
#[derive(Debug, Clone)]
struct PlotRecord {
    plot_id: [u8; 32],
    size_bytes: u64,
    tree_depth: u8,
    /// Present on local block-producing nodes so `prepare_block` can open any
    /// slot-challenged leaf; `None` on verifier-only nodes registered via
    /// [`PoSpaceEngine::register_verified_plot`].
    local_leaves: Option<Vec<[u8; 32]>>,
}

/// Domain-separated PoSpace Merkle leaf digest (`BDLM_POSPACE_LEAF_V1`).
#[must_use]
fn pospace_leaf_hash(leaf_index: u64, leaf_value: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_POSPACE_LEAF_V1");
    hasher.update(leaf_index.to_le_bytes());
    hasher.update(leaf_value);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Domain-separated PoSpace Merkle internal node digest (`BDLM_POSPACE_NODE_V1`).
#[must_use]
fn pospace_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_POSPACE_NODE_V1");
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verify a [`PlotMerkleProof`] against `plot_root` and `tree_depth` in constant time.
///
/// WIRING: PoSpace plot registration and per-block witness verifier (`PoSpaceEngine`).
#[must_use]
pub fn verify_plot_merkle_proof(
    plot_root: &[u8; 32],
    tree_depth: u8,
    proof: &PlotMerkleProof,
) -> bool {
    let zero = [0u8; 32];
    if bool::from(plot_root.ct_eq(&zero))
        || bool::from(proof.leaf_value.ct_eq(&zero))
        || tree_depth > MAX_PLOT_MERKLE_DEPTH
        || proof.siblings.len() != usize::from(tree_depth)
    {
        return false;
    }
    let max_leaves = 1_u64 << u32::from(tree_depth);
    if proof.leaf_index >= max_leaves {
        return false;
    }
    let mut acc = pospace_leaf_hash(proof.leaf_index, &proof.leaf_value);
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let is_right = ((proof.leaf_index >> level) & 1) == 1;
        acc = if is_right {
            pospace_node_hash(sibling, &acc)
        } else {
            pospace_node_hash(&acc, sibling)
        };
    }
    bool::from(acc.ct_eq(plot_root))
}

/// Build the Merkle root and exact tree depth of a power-of-two non-zero leaf slice.
///
/// # Errors
///
/// Returns [`ConsensusError`] if `leaves` is empty, not a power of two, exceeds
/// `MAX_LOCAL_MINER_LEAVES`, or contains an all-zero leaf.
///
/// WIRING: Companion plot builder for [`PoSpaceEngine::register_verified_plot`].
pub fn build_plot_merkle_tree(leaves: &[[u8; 32]]) -> Result<([u8; 32], u8), ConsensusError> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err(ConsensusError(
            "PoSpace plot leaf count must be a non-zero power of two".into(),
        ));
    }
    if leaves.len() > MAX_LOCAL_MINER_LEAVES {
        return Err(ConsensusError(format!(
            "PoSpace local plot leaf count {} exceeds limit {MAX_LOCAL_MINER_LEAVES}",
            leaves.len()
        )));
    }
    let zero = [0u8; 32];
    if leaves.iter().any(|l| bool::from(l.ct_eq(&zero))) {
        return Err(ConsensusError(
            "PoSpace plot cannot contain an all-zero leaf".into(),
        ));
    }
    let depth_u32 = leaves.len().trailing_zeros();
    let tree_depth = u8::try_from(depth_u32)
        .ok()
        .filter(|&d| d <= MAX_PLOT_MERKLE_DEPTH)
        .ok_or_else(|| ConsensusError("PoSpace plot depth exceeds maximum".into()))?;
    let mut layer: Vec<[u8; 32]> = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| pospace_leaf_hash(i as u64, leaf))
        .collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            let Some(left) = pair.first() else {
                break;
            };
            let Some(right) = pair.get(1) else {
                break;
            };
            next.push(pospace_node_hash(left, right));
        }
        layer = next;
    }
    let root = layer
        .first()
        .copied()
        .ok_or_else(|| ConsensusError("PoSpace plot root missing".into()))?;
    Ok((root, tree_depth))
}

/// Open `leaf_index` inside a power-of-two committed plot leaf slice.
///
/// # Errors
///
/// Returns [`ConsensusError`] if `leaves` is malformed or `leaf_index` is out of range.
///
/// WIRING: Companion Merkle proof generator for [`PoSpaceEngine::register_verified_plot`].
pub fn open_plot_merkle_leaf(
    leaves: &[[u8; 32]],
    leaf_index: u64,
) -> Result<PlotMerkleProof, ConsensusError> {
    let _ = build_plot_merkle_tree(leaves)?;
    let idx = usize::try_from(leaf_index)
        .ok()
        .filter(|&i| i < leaves.len())
        .ok_or_else(|| ConsensusError("PoSpace leaf_index out of bounds".into()))?;
    let leaf_value = leaves
        .get(idx)
        .copied()
        .ok_or_else(|| ConsensusError("PoSpace leaf missing".into()))?;
    let mut layer: Vec<[u8; 32]> = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| pospace_leaf_hash(i as u64, leaf))
        .collect();
    let mut cur = idx;
    let mut siblings = Vec::new();
    while layer.len() > 1 {
        let sib_idx = cur ^ 1;
        let sib = layer
            .get(sib_idx)
            .copied()
            .ok_or_else(|| ConsensusError("PoSpace sibling missing".into()))?;
        siblings.push(sib);
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            if let (Some(l), Some(r)) = (pair.first(), pair.get(1)) {
                next.push(pospace_node_hash(l, r));
            }
        }
        layer = next;
        cur >>= 1;
    }
    Ok(PlotMerkleProof {
        leaf_index,
        leaf_value,
        siblings,
    })
}

/// Deterministically select the leaf index challenged for `(plot_id, challenge, tree_depth)`.
#[must_use]
fn challenged_leaf_index(plot_id: &[u8; 32], challenge: &[u8; 32], tree_depth: u8) -> u64 {
    if tree_depth == 0 {
        return 0;
    }
    let digest = compute_plot_response(plot_id, challenge);
    let raw = digest
        .get(..8)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map_or(0, u64::from_le_bytes);
    let mask = (1_u64 << u32::from(tree_depth)) - 1;
    raw & mask
}

/// Deterministic challenge used during [`PoSpaceEngine::register_verified_plot`]
/// so the registrant must open the exact protocol-selected leaf of `plot_id`.
///
/// WIRING: Companion challenge helper for [`PoSpaceEngine::register_verified_plot`].
#[must_use]
pub fn registration_challenge(address: &str, plot_id: &[u8; 32], size_bytes: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_POSPACE_CHALLENGE_V1");
    hasher.update(address.as_bytes());
    hasher.update(plot_id);
    hasher.update(size_bytes.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Derive the canonical expected challenge response for `(plot_id, challenge)`.
#[must_use]
pub fn compute_plot_response(plot_id: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_POSPACE_RESPONSE_V1");
    hasher.update(plot_id);
    hasher.update(challenge);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Derive the storage-bound response committing `(plot_id, challenge, leaf_index, leaf_value)`.
#[must_use]
fn compute_leaf_bound_response(
    plot_id: &[u8; 32],
    challenge: &[u8; 32],
    proof: &PlotMerkleProof,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_POSPACE_RESPONSE_V1");
    hasher.update(plot_id);
    hasher.update(challenge);
    hasher.update(proof.leaf_index.to_le_bytes());
    hasher.update(proof.leaf_value);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verify a PoSpace challenge response against `(plot_id, challenge)`.
#[must_use]
pub fn verify_plot_response(plot_id: &[u8; 32], challenge: &[u8; 32], response: &[u8; 32]) -> bool {
    let zero = [0u8; 32];
    if bool::from(plot_id.ct_eq(&zero))
        || bool::from(challenge.ct_eq(&zero))
        || bool::from(response.ct_eq(&zero))
    {
        return false;
    }
    let expected = compute_plot_response(plot_id, challenge);
    bool::from(expected.ct_eq(response))
}

fn encode_pospace_witness(
    plot_id: &[u8; 32],
    challenge: &[u8; 32],
    size_bytes: u64,
    tree_depth: u8,
    proof: &PlotMerkleProof,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(POSPACE_WITNESS_HEADER_LEN + proof.siblings.len() * 32);
    out.extend_from_slice(POSPACE_WITNESS_MAGIC);
    out.extend_from_slice(plot_id);
    out.extend_from_slice(challenge);
    out.extend_from_slice(&size_bytes.to_le_bytes());
    out.push(tree_depth);
    out.extend_from_slice(&proof.leaf_index.to_le_bytes());
    out.extend_from_slice(&proof.leaf_value);
    for sib in &proof.siblings {
        out.extend_from_slice(sib);
    }
    out
}

struct DecodedSpaceWitness {
    plot_id: [u8; 32],
    challenge: [u8; 32],
    size_bytes: u64,
    tree_depth: u8,
    proof: PlotMerkleProof,
    response: [u8; 32],
}

fn decode_pospace_witness(block: &Block) -> Result<DecodedSpaceWitness, ConsensusError> {
    if block.vrf_proof.len() < POSPACE_WITNESS_HEADER_LEN || block.vrf_output.len() != 32 {
        return Err(ConsensusError(
            "PoSpace block missing challenge-bound Merkle space proof".into(),
        ));
    }
    let Some(magic) = block.vrf_proof.get(0..8) else {
        return Err(ConsensusError("PoSpace proof header truncated".into()));
    };
    if magic != POSPACE_WITNESS_MAGIC {
        return Err(ConsensusError("PoSpace proof magic mismatch".into()));
    }
    let plot_id: [u8; 32] = block
        .vrf_proof
        .get(8..40)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoSpace proof plot_id truncated".into()))?;
    let challenge: [u8; 32] = block
        .vrf_proof
        .get(40..72)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoSpace proof challenge truncated".into()))?;
    let size_bytes_arr: [u8; 8] = block
        .vrf_proof
        .get(72..80)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoSpace proof size_bytes truncated".into()))?;
    let tree_depth = block
        .vrf_proof
        .get(80)
        .copied()
        .ok_or_else(|| ConsensusError("PoSpace proof tree_depth missing".into()))?;
    if tree_depth > MAX_PLOT_MERKLE_DEPTH {
        return Err(ConsensusError(
            "PoSpace proof tree_depth exceeds maximum".into(),
        ));
    }
    let leaf_index_arr: [u8; 8] = block
        .vrf_proof
        .get(81..89)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoSpace proof leaf_index truncated".into()))?;
    let leaf_value: [u8; 32] = block
        .vrf_proof
        .get(89..121)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| ConsensusError("PoSpace proof leaf_value truncated".into()))?;
    let expected_len = POSPACE_WITNESS_HEADER_LEN + usize::from(tree_depth) * 32;
    if block.vrf_proof.len() != expected_len {
        return Err(ConsensusError(
            "PoSpace proof Merkle sibling list length mismatch".into(),
        ));
    }
    let mut siblings = Vec::with_capacity(usize::from(tree_depth));
    for idx in 0..usize::from(tree_depth) {
        let start = POSPACE_WITNESS_HEADER_LEN + idx * 32;
        let sib: [u8; 32] = block
            .vrf_proof
            .get(start..start + 32)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| ConsensusError("PoSpace sibling truncated".into()))?;
        siblings.push(sib);
    }
    let response: [u8; 32] = block
        .vrf_output
        .as_slice()
        .try_into()
        .map_err(|_| ConsensusError("PoSpace proof response must be 32 bytes".into()))?;
    Ok(DecodedSpaceWitness {
        plot_id,
        challenge,
        size_bytes: u64::from_le_bytes(size_bytes_arr),
        tree_depth,
        proof: PlotMerkleProof {
            leaf_index: u64::from_le_bytes(leaf_index_arr),
            leaf_value,
            siblings,
        },
        response,
    })
}

fn verify_decoded_space_witness(w: &DecodedSpaceWitness, expected_challenge: &[u8; 32]) -> bool {
    if !bool::from(w.challenge.ct_eq(expected_challenge)) {
        return false;
    }
    let expected_leaf = challenged_leaf_index(&w.plot_id, &w.challenge, w.tree_depth);
    if w.proof.leaf_index != expected_leaf {
        return false;
    }
    if !verify_plot_merkle_proof(&w.plot_id, w.tree_depth, &w.proof) {
        return false;
    }
    let expected_resp = compute_leaf_bound_response(&w.plot_id, &w.challenge, &w.proof);
    bool::from(expected_resp.ct_eq(&w.response))
}

fn derive_block_challenge(previous_hash: &str, block_index: u64, challenge_epoch: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_POSPACE_CHALLENGE_V1");
    hasher.update(previous_hash.as_bytes());
    hasher.update(block_index.to_le_bytes());
    hasher.update(challenge_epoch.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// `PoSpace` engine: bounded Merkle-verified plot registry and challenge verifier.
pub struct PoSpaceEngine {
    pub config: PoSpaceConfig,
    plots: RwLock<BTreeMap<String, PlotRecord>>,
    challenge_counter: RwLock<u64>,
}

impl PoSpaceEngine {
    /// Create a new `PoSpace` consensus engine.
    #[must_use]
    pub const fn new(config: PoSpaceConfig) -> Self {
        Self {
            config,
            plots: RwLock::new(BTreeMap::new()),
            challenge_counter: RwLock::new(0),
        }
    }

    /// Register a validator's plot commitment in production after verifying a
    /// deterministic challenge-selected Merkle inclusion proof against `plot_id`
    ///.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError`] for empty addresses, zero plot roots, out-of-range
    /// capacities, invalid or unchallenged Merkle openings, registry exhaustion
    /// (`MAX_POSPACE_PLOTS`), or a poisoned lock.
    ///
    /// WIRING: Production plot commitment registration for `ConsensusKind::Pospace` domains.
    pub fn register_verified_plot(
        &self,
        address: &str,
        plot_id: [u8; 32],
        size_bytes: u64,
        tree_depth: u8,
        opening: &PlotMerkleProof,
    ) -> Result<(), ConsensusError> {
        self.insert_verified_plot(address, plot_id, size_bytes, tree_depth, opening, None)
    }

    /// Register a local miner's full power-of-two committed plot leaves after
    /// verifying its canonical Merkle root and registration opening, enabling
    /// [`ConsensusEngine::prepare_block`] to answer per-slot leaf challenges.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError`] if the plot leaves, size, or registry capacity fail validation.
    ///
    /// WIRING: Local miner plot commitment registration for `ConsensusKind::Pospace` block production.
    pub fn register_committed_plot(
        &self,
        address: &str,
        size_bytes: u64,
        leaves: Vec<[u8; 32]>,
    ) -> Result<[u8; 32], ConsensusError> {
        let (plot_id, tree_depth) = build_plot_merkle_tree(&leaves)?;
        let reg_chal = registration_challenge(address, &plot_id, size_bytes);
        let leaf_idx = challenged_leaf_index(&plot_id, &reg_chal, tree_depth);
        let opening = open_plot_merkle_leaf(&leaves, leaf_idx)?;
        self.insert_verified_plot(
            address,
            plot_id,
            size_bytes,
            tree_depth,
            &opening,
            Some(leaves),
        )?;
        Ok(plot_id)
    }

    fn insert_verified_plot(
        &self,
        address: &str,
        plot_id: [u8; 32],
        size_bytes: u64,
        tree_depth: u8,
        opening: &PlotMerkleProof,
        local_leaves: Option<Vec<[u8; 32]>>,
    ) -> Result<(), ConsensusError> {
        if address.trim().is_empty() {
            return Err(ConsensusError("PoSpace plot address is empty".into()));
        }
        if bool::from(plot_id.ct_eq(&[0u8; 32])) {
            return Err(ConsensusError("PoSpace plot_id cannot be zero".into()));
        }
        if size_bytes < self.config.min_plot_size_bytes || size_bytes > MAX_PLOT_SIZE_BYTES {
            return Err(ConsensusError(format!(
                "PoSpace plot size {size_bytes} outside permitted range [{}, {MAX_PLOT_SIZE_BYTES}]",
                self.config.min_plot_size_bytes
            )));
        }
        let reg_chal = registration_challenge(address, &plot_id, size_bytes);
        let expected_leaf = challenged_leaf_index(&plot_id, &reg_chal, tree_depth);
        if opening.leaf_index != expected_leaf {
            return Err(ConsensusError(format!(
                "PoSpace registration opening leaf {} does not match challenged leaf {expected_leaf}",
                opening.leaf_index
            )));
        }
        if !verify_plot_merkle_proof(&plot_id, tree_depth, opening) {
            return Err(ConsensusError(
                "PoSpace registration Merkle opening failed verification".into(),
            ));
        }
        let mut plots = self
            .plots
            .write()
            .map_err(|_| ConsensusError("PoSpace plot registry lock poisoned".into()))?;
        if !plots.contains_key(address) && plots.len() >= MAX_POSPACE_PLOTS {
            return Err(ConsensusError(
                "PoSpace plot registry capacity ceiling reached".into(),
            ));
        }
        plots.insert(
            address.to_string(),
            PlotRecord {
                plot_id,
                size_bytes,
                tree_depth,
                local_leaves,
            },
        );
        Ok(())
    }

    /// Issue the next domain-separated `PoSpace` challenge.
    fn issue_challenge(&self) -> Result<[u8; 32], ConsensusError> {
        let mut counter = self
            .challenge_counter
            .write()
            .map_err(|_| ConsensusError("PoSpace challenge counter lock poisoned".into()))?;
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| ConsensusError("PoSpace challenge counter overflow".into()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_POSPACE_CHALLENGE_V1");
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    #[must_use]
    fn total_capacity(&self) -> u64 {
        self.plots.read().map_or(0, |plots| {
            plots
                .values()
                .fold(0u64, |acc, p| acc.saturating_add(p.size_bytes))
        })
    }

    #[must_use]
    fn plot_count(&self) -> usize {
        self.plots.read().map_or(0, |plots| plots.len())
    }

    fn expected_challenge_for_block(&self, block: &Block) -> [u8; 32] {
        let interval = self.config.challenge_interval.max(1);
        let challenge_epoch = block.index / interval;
        derive_block_challenge(&block.previous_hash, block.index, challenge_epoch)
    }

    fn lookup_registered_capacity(
        plots: &BTreeMap<String, PlotRecord>,
        block: &Block,
        witness: &DecodedSpaceWitness,
    ) -> Option<u64> {
        let reg = if let Some(producer) = block.producer {
            let found = plots.get(&producer.to_hex())?;
            if !bool::from(found.plot_id.ct_eq(&witness.plot_id)) {
                return None;
            }
            found
        } else {
            plots
                .values()
                .find(|r| bool::from(r.plot_id.ct_eq(&witness.plot_id)))?
        };
        if reg.size_bytes != witness.size_bytes || reg.tree_depth != witness.tree_depth {
            return None;
        }
        Some(reg.size_bytes)
    }
}

impl ConsensusEngine for PoSpaceEngine {
    fn prepare_block(
        &self,
        block: &mut Block,
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        let plot = {
            let plots = self
                .plots
                .read()
                .map_err(|_| ConsensusError("PoSpace plot registry lock poisoned".into()))?;
            if let Some(producer) = block.producer {
                let key = producer.to_hex();
                plots.get(&key).cloned().ok_or_else(|| {
                    ConsensusError(format!("PoSpace producer {key} has no registered plot"))
                })?
            } else {
                plots.values().next().cloned().ok_or_else(|| {
                    ConsensusError("PoSpace engine has no registered plots".into())
                })?
            }
        };
        let Some(ref leaves) = plot.local_leaves else {
            return Err(ConsensusError(
                "PoSpace plot registered as verifier-only; local plot leaves unavailable".into(),
            ));
        };

        let challenge = self.expected_challenge_for_block(block);
        let leaf_idx = challenged_leaf_index(&plot.plot_id, &challenge, plot.tree_depth);
        let proof = open_plot_merkle_leaf(leaves, leaf_idx)?;
        let response = compute_leaf_bound_response(&plot.plot_id, &challenge, &proof);
        block.vrf_output = response.to_vec();
        block.vrf_proof = encode_pospace_witness(
            &plot.plot_id,
            &challenge,
            plot.size_bytes,
            plot.tree_depth,
            &proof,
        );
        block.hash = block.calculate_hash();
        Ok(())
    }

    fn validate_block(
        &self,
        block: &Block,
        _chain: &[Block],
        _state: &AccountState,
    ) -> Result<(), ConsensusError> {
        let calculated_hash = block.calculate_hash();
        if block.hash != calculated_hash {
            return Err(ConsensusError(format!(
                "Invalid PoSpace block hash. Calculated: {calculated_hash}, Existing: {}",
                block.hash
            )));
        }

        let witness = decode_pospace_witness(block)?;
        if witness.size_bytes < self.config.min_plot_size_bytes
            || witness.size_bytes > MAX_PLOT_SIZE_BYTES
        {
            return Err(ConsensusError(format!(
                "PoSpace proof plot size {} outside permitted range [{}, {MAX_PLOT_SIZE_BYTES}]",
                witness.size_bytes, self.config.min_plot_size_bytes
            )));
        }

        let expected_challenge = self.expected_challenge_for_block(block);
        if !verify_decoded_space_witness(&witness, &expected_challenge) {
            return Err(ConsensusError(
                "PoSpace block Merkle space proof failed cryptographic verification".into(),
            ));
        }

        let plots = self
            .plots
            .read()
            .map_err(|_| ConsensusError("PoSpace plot registry lock poisoned".into()))?;
        if Self::lookup_registered_capacity(&plots, block, &witness).is_none() {
            return Err(ConsensusError(
                "PoSpace block references an unregistered or mismatched plot commitment".into(),
            ));
        }

        Ok(())
    }

    fn record_block(
        &self,
        _block: &Block,
        _storage: Option<&crate::persistence::db::Storage>,
    ) -> Result<(), ConsensusError> {
        let _ = self.issue_challenge()?;
        Ok(())
    }

    fn consensus_type(&self) -> &'static str {
        "PoSpace"
    }

    fn info(&self) -> String {
        let challenges = self.challenge_counter.read().map_or(0, |c| *c);
        format!(
            "PoSpace (plots: {}, total_capacity: {} bytes, challenges: {challenges})",
            self.plot_count(),
            self.total_capacity(),
        )
    }

    fn domain_kind(&self) -> crate::domain::ConsensusKind {
        crate::domain::ConsensusKind::Pospace
    }

    fn shorter_chain_can_never_win(&self) -> bool {
        false
    }

    fn fork_choice_score(&self, chain: &[Block]) -> u128 {
        // fail closed unless every block links contiguously, passes
        // full challenge-selected Merkle plot opening verification, AND matches
        // a plot registered in `self.plots`. Unregistered capacity always scores 0.
        if chain.is_empty() {
            return 0;
        }
        let Ok(plots) = self.plots.read() else {
            return 0;
        };
        let mut proven_capacity = 0u128;
        let mut prev: Option<&Block> = None;
        for block in chain {
            if block.hash != block.calculate_hash() {
                return 0;
            }
            if let Some(parent) = prev {
                if block.index != parent.index.saturating_add(1)
                    || block.previous_hash != parent.hash
                {
                    return 0;
                }
            }
            prev = Some(block);
            let Ok(witness) = decode_pospace_witness(block) else {
                return 0;
            };
            let expected = self.expected_challenge_for_block(block);
            if witness.size_bytes < self.config.min_plot_size_bytes
                || witness.size_bytes > MAX_PLOT_SIZE_BYTES
                || !verify_decoded_space_witness(&witness, &expected)
            {
                return 0;
            }
            let Some(registered_size) = Self::lookup_registered_capacity(&plots, block, &witness)
            else {
                return 0;
            };
            proven_capacity = proven_capacity.saturating_add(u128::from(registered_size));
        }
        let height_weight = chain
            .last()
            .map_or(0u128, |b| u128::from(b.index))
            .saturating_mul(1_000);
        height_weight.saturating_add(proven_capacity)
    }

    fn is_better_chain(&self, current: &[Block], candidate: &[Block]) -> bool {
        let current_score = self.fork_choice_score(current);
        let candidate_score = self.fork_choice_score(candidate);
        if candidate_score != current_score {
            return candidate_score > current_score;
        }
        resolve_split_tie(
            &SplitCandidate::from_chain_tip(current, current_score),
            &SplitCandidate::from_chain_tip(candidate, candidate_score),
        ) == SplitDecision::RightWins
    }
}

/// Hard upper bound on synchronous sequential delay steps verified per proof.
const MAX_POSPACE_VDF_ITERATIONS: u64 = 65_536;

/// Maximum plot-filter difficulty prefix in bits (caps filter sparsity to `2^16`).
const MAX_PLOT_FILTER_BITS: u8 = 16;

/// Maximum number of intermediate checkpoints in a segmented delay proof.
const MAX_POSPACE_VDF_CHECKPOINTS: usize = 64;

/// Segmented sequential SHA-256 delay proof coupled to a verified `PoSpace`
/// Merkle leaf opening (eliminates costless history rewriting / grinding).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpaceTimeDelayProof {
    pub plot_id: [u8; 32],
    pub size_bytes: u64,
    pub tree_depth: u8,
    pub challenge: [u8; 32],
    pub signage_index: u32,
    pub filter_bits: u8,
    pub space_opening: PlotMerkleProof,
    pub iterations: u64,
    pub segment_stride: u64,
    pub checkpoints: Vec<[u8; 32]>,
    pub output: [u8; 32],
}

/// Evaluate the Chia-style signage-point plot filter for a sub-slot.
///
/// Requires the leading `filter_bits` of
/// `H("BDLM_POSPACE_FILTER_V1" || plot_id || challenge || signage_index)`
/// to be zero, preventing farmers from scanning every plot on every sub-slot.
///
/// WIRING: Sub-slot eligibility gate for `ConsensusKind::Pospace` and PoSpace+VDF pipelines.
#[must_use]
pub fn passes_plot_filter(
    plot_id: &[u8; 32],
    challenge: &[u8; 32],
    signage_index: u32,
    filter_bits: u8,
) -> bool {
    if filter_bits == 0 {
        return true;
    }
    if filter_bits > MAX_PLOT_FILTER_BITS {
        return false;
    }
    let digest = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_POSPACE_FILTER_V1",
        plot_id,
        challenge,
        &signage_index.to_le_bytes(),
    ]);
    let head = u16::from_be_bytes([
        digest.first().copied().unwrap_or(0xFF),
        digest.get(1).copied().unwrap_or(0xFF),
    ]);
    head.leading_zeros() >= u32::from(filter_bits)
}

/// Compute the required sequential delay iterations for a `PoSpace` quality hit.
///
/// Derives a canonical 32-byte digest over `(plot_id, challenge, signage_index, opened_leaf)`
/// and maps it into `1..=max_iterations` inversely weighted by verified `size_bytes`.
///
/// Pure integer math (zero floats); strictly bounded by `MAX_POSPACE_VDF_ITERATIONS`.
///
/// # Errors
///
/// Returns [`ConsensusError`] when `size_bytes == 0`, `difficulty == 0`, or
/// `max_iterations` is outside `1..=MAX_POSPACE_VDF_ITERATIONS`.
///
/// WIRING: Deterministic quality-to-delay schedule for [`evaluate_space_time_delay`]
/// and [`verify_space_time_delay`].
pub fn required_space_time_iterations(
    plot_id: &[u8; 32],
    challenge: &[u8; 32],
    signage_index: u32,
    opening: &PlotMerkleProof,
    size_bytes: u64,
    difficulty: u64,
    max_iterations: u64,
) -> Result<u64, ConsensusError> {
    if size_bytes == 0 || size_bytes > MAX_PLOT_SIZE_BYTES {
        return Err(ConsensusError(
            "PoSpace delay schedule requires non-zero bounded size_bytes".into(),
        ));
    }
    if difficulty == 0 {
        return Err(ConsensusError(
            "PoSpace delay schedule requires non-zero difficulty".into(),
        ));
    }
    if max_iterations == 0 || max_iterations > MAX_POSPACE_VDF_ITERATIONS {
        return Err(ConsensusError(format!(
            "PoSpace max_iterations {max_iterations} outside 1..={MAX_POSPACE_VDF_ITERATIONS}"
        )));
    }
    let quality = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_POSPACE_QUALITY_V1",
        plot_id,
        challenge,
        &signage_index.to_le_bytes(),
        &opening.leaf_index.to_le_bytes(),
        &opening.leaf_value,
    ]);
    let mut q_bytes = [0u8; 8];
    if let Some(prefix) = quality.get(..8) {
        q_bytes.copy_from_slice(prefix);
    }
    // Scale 64-bit quality ticket by difficulty / size_bytes into [1, max_iterations].
    let q_norm = u128::from(u64::from_be_bytes(q_bytes)) >> 32;
    let raw = q_norm
        .saturating_mul(u128::from(difficulty))
        .checked_div(u128::from(size_bytes))
        .unwrap_or(1);
    let capped = raw.clamp(1, u128::from(max_iterations));
    u64::try_from(capped).map_err(|_| ConsensusError("PoSpace iteration count overflow".into()))
}

fn delay_seed(
    plot_id: &[u8; 32],
    challenge: &[u8; 32],
    signage_index: u32,
    resp: &[u8; 32],
) -> [u8; 32] {
    crate::core::hash::hash_fields_bytes(&[
        b"BDLM_POSPACE_VDF_SEED_V1",
        plot_id,
        challenge,
        &signage_index.to_le_bytes(),
        resp,
    ])
}

fn step_delay_chain(mut state: [u8; 32], start_step: u64, count: u64) -> [u8; 32] {
    let mut i = 0u64;
    while i < count {
        let step = start_step.saturating_add(i);
        let mut h = Sha256::new();
        h.update(b"BDLM_POSPACE_VDF_STEP_V1");
        h.update(step.to_le_bytes());
        h.update(state);
        let d = h.finalize();
        state.copy_from_slice(&d);
        i += 1;
    }
    state
}

/// Schedule parameters governing a segmented `PoSpace` delay proof.
///
/// WIRING: Parameter bundle shared by [`evaluate_space_time_delay`],
/// [`verify_space_time_delay`], and [`crate::unification::UnificationLedger`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpaceTimeDelayParams {
    pub signage_index: u32,
    pub filter_bits: u8,
    pub difficulty: u64,
    pub max_iterations: u64,
    pub segment_stride: u64,
}

/// Construct a verified [`SpaceTimeDelayProof`] for an eligible `PoSpace` slot.
///
/// Links a committed Merkle leaf opening to an iterated sequential SHA-256 delay
/// chain with intermediate checkpoints every `params.segment_stride` steps.
///
/// # Errors
///
/// Returns [`ConsensusError`] if the plot fails the signage-point filter, the
/// Merkle opening is invalid, or iteration/checkpoint bounds are violated.
///
/// WIRING: Prover companion to [`verify_space_time_delay`] for PoSpace+VDF slots.
pub fn evaluate_space_time_delay(
    plot_id: [u8; 32],
    size_bytes: u64,
    tree_depth: u8,
    leaves: &[[u8; 32]],
    challenge: [u8; 32],
    params: SpaceTimeDelayParams,
) -> Result<SpaceTimeDelayProof, ConsensusError> {
    let signage_index = params.signage_index;
    let filter_bits = params.filter_bits;
    let difficulty = params.difficulty;
    let max_iterations = params.max_iterations;
    let segment_stride = params.segment_stride;
    if !passes_plot_filter(&plot_id, &challenge, signage_index, filter_bits) {
        return Err(ConsensusError(
            "PoSpace plot did not pass signage-point filter".into(),
        ));
    }
    let sub_challenge = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_POSPACE_SUBSLOT_V1",
        &challenge,
        &signage_index.to_le_bytes(),
    ]);
    let leaf_idx = challenged_leaf_index(&plot_id, &sub_challenge, tree_depth);
    let space_opening = open_plot_merkle_leaf(leaves, leaf_idx)?;
    if !verify_plot_merkle_proof(&plot_id, tree_depth, &space_opening) {
        return Err(ConsensusError(
            "PoSpace leaves do not match declared plot_id".into(),
        ));
    }
    let iterations = required_space_time_iterations(
        &plot_id,
        &challenge,
        signage_index,
        &space_opening,
        size_bytes,
        difficulty,
        max_iterations,
    )?;
    if segment_stride == 0 {
        return Err(ConsensusError(
            "PoSpace VDF segment_stride must be >= 1".into(),
        ));
    }
    let full_checkpoints = (iterations.saturating_sub(1)) / segment_stride;
    if full_checkpoints > MAX_POSPACE_VDF_CHECKPOINTS as u64 {
        return Err(ConsensusError(format!(
            "PoSpace VDF checkpoint count {full_checkpoints} exceeds {MAX_POSPACE_VDF_CHECKPOINTS}"
        )));
    }
    let resp = compute_leaf_bound_response(&plot_id, &sub_challenge, &space_opening);
    let mut cur = delay_seed(&plot_id, &challenge, signage_index, &resp);
    let mut done = 0u64;
    let mut checkpoints = Vec::new();
    while done < iterations {
        let step_cnt = segment_stride.min(iterations - done);
        cur = step_delay_chain(cur, done, step_cnt);
        done += step_cnt;
        if done < iterations {
            checkpoints.push(cur);
        }
    }
    Ok(SpaceTimeDelayProof {
        plot_id,
        size_bytes,
        tree_depth,
        challenge,
        signage_index,
        filter_bits,
        space_opening,
        iterations,
        segment_stride,
        checkpoints,
        output: cur,
    })
}

/// Deterministically verify a [`SpaceTimeDelayProof`] against `expected_challenge`.
///
/// Checks signage-point filter eligibility, challenge-derived Merkle leaf opening,
/// capacity-normalized iteration count, intermediate checkpoints, and final output.
///
/// # Errors
///
/// Returns [`ConsensusError`] on any filter, commitment, schedule, checkpoint, or
/// final output mismatch.
///
/// WIRING: Verifier for PoSpace+time sequential finality proofs.
pub fn verify_space_time_delay(
    proof: &SpaceTimeDelayProof,
    expected_challenge: &[u8; 32],
    min_plot_size_bytes: u64,
    expected_filter_bits: u8,
    difficulty: u64,
    max_iterations: u64,
) -> Result<(), ConsensusError> {
    if bool::from(proof.plot_id.ct_eq(&[0u8; 32])) {
        return Err(ConsensusError(
            "PoSpace delay proof has zero plot_id".into(),
        ));
    }
    if !bool::from(proof.challenge.ct_eq(expected_challenge)) {
        return Err(ConsensusError(
            "PoSpace delay proof challenge mismatch".into(),
        ));
    }
    if proof.filter_bits != expected_filter_bits
        || !passes_plot_filter(
            &proof.plot_id,
            &proof.challenge,
            proof.signage_index,
            expected_filter_bits,
        )
    {
        return Err(ConsensusError(
            "PoSpace delay proof failed signage-point filter".into(),
        ));
    }
    if proof.size_bytes < min_plot_size_bytes || proof.size_bytes > MAX_PLOT_SIZE_BYTES {
        return Err(ConsensusError(
            "PoSpace delay proof size_bytes outside permitted bounds".into(),
        ));
    }
    let sub_challenge = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_POSPACE_SUBSLOT_V1",
        &proof.challenge,
        &proof.signage_index.to_le_bytes(),
    ]);
    let expected_leaf = challenged_leaf_index(&proof.plot_id, &sub_challenge, proof.tree_depth);
    if proof.space_opening.leaf_index != expected_leaf
        || !verify_plot_merkle_proof(&proof.plot_id, proof.tree_depth, &proof.space_opening)
    {
        return Err(ConsensusError(
            "PoSpace delay proof Merkle leaf opening failed verification".into(),
        ));
    }
    let expected_iters = required_space_time_iterations(
        &proof.plot_id,
        &proof.challenge,
        proof.signage_index,
        &proof.space_opening,
        proof.size_bytes,
        difficulty,
        max_iterations,
    )?;
    if proof.iterations != expected_iters || proof.segment_stride == 0 {
        return Err(ConsensusError(
            "PoSpace delay proof iteration count or segment_stride mismatch".into(),
        ));
    }
    if proof.checkpoints.len() > MAX_POSPACE_VDF_CHECKPOINTS {
        return Err(ConsensusError(
            "PoSpace delay proof exceeds checkpoint limit".into(),
        ));
    }
    let expected_checkpoints = (expected_iters.saturating_sub(1)) / proof.segment_stride;
    if proof.checkpoints.len() as u64 != expected_checkpoints {
        return Err(ConsensusError(
            "PoSpace delay proof checkpoint count does not match segment_stride".into(),
        ));
    }
    let resp = compute_leaf_bound_response(&proof.plot_id, &sub_challenge, &proof.space_opening);
    let mut state = delay_seed(&proof.plot_id, &proof.challenge, proof.signage_index, &resp);
    let mut done = 0u64;
    for cp in &proof.checkpoints {
        let computed = step_delay_chain(state, done, proof.segment_stride);
        if !bool::from(computed.ct_eq(cp)) {
            return Err(ConsensusError(
                "PoSpace delay proof intermediate VDF checkpoint mismatch".into(),
            ));
        }
        state = *cp;
        done += proof.segment_stride;
    }
    let rem = expected_iters - done;
    let final_out = step_delay_chain(state, done, rem);
    if !bool::from(final_out.ct_eq(&proof.output)) {
        return Err(ConsensusError(
            "PoSpace delay proof final VDF output mismatch".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_leaves(seed: u8, count: usize) -> Vec<[u8; 32]> {
        (0..count)
            .map(|idx| {
                let mut h = Sha256::new();
                h.update([seed]);
                h.update((idx as u64).to_le_bytes());
                let d = h.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&d);
                out
            })
            .collect()
    }

    fn make_block(index: u64, previous_hash: &str) -> Block {
        Block::new(index, previous_hash.to_string(), Vec::new())
    }

    fn register_remote_plot(
        verifier: &PoSpaceEngine,
        address: &str,
        size_bytes: u64,
        leaves: &[[u8; 32]],
    ) -> [u8; 32] {
        let (root, depth) = build_plot_merkle_tree(leaves).expect("tree");
        let chal = registration_challenge(address, &root, size_bytes);
        let idx = challenged_leaf_index(&root, &chal, depth);
        let proof = open_plot_merkle_leaf(leaves, idx).expect("opening");
        verifier
            .register_verified_plot(address, root, size_bytes, depth, &proof)
            .expect("register verified plot");
        root
    }

    #[test]
    fn pospace_register_verified_plot_enforces_merkle_proof_and_bounds() {
        let engine = PoSpaceEngine::new(PoSpaceConfig::default());
        let leaves = sample_leaves(0x11, 8);
        let (root, depth) = build_plot_merkle_tree(&leaves).expect("tree");
        let chal = registration_challenge("validator-1", &root, 1_000_000_000);
        let idx = challenged_leaf_index(&root, &chal, depth);
        let proof = open_plot_merkle_leaf(&leaves, idx).expect("open");

        // Tampered sibling or tampered leaf MUST be refused.
        let mut bad_sib = proof.clone();
        bad_sib.siblings[0][0] ^= 0xff;
        assert!(engine
            .register_verified_plot("validator-1", root, 1_000_000_000, depth, &bad_sib)
            .is_err());

        // Valid proof targeting a non-challenged leaf index MUST be refused.
        let wrong_idx = (idx + 1) % (leaves.len() as u64);
        let wrong_leaf_proof = open_plot_merkle_leaf(&leaves, wrong_idx).expect("open wrong");
        assert!(engine
            .register_verified_plot("validator-1", root, 1_000_000_000, depth, &wrong_leaf_proof)
            .is_err());

        // Zero plot root, empty address, below-min, and > 1 PiB capacity MUST be refused.
        assert!(engine
            .register_verified_plot("", root, 1_000_000_000, depth, &proof)
            .is_err());
        assert!(engine
            .register_verified_plot("v", [0u8; 32], 1_000_000_000, depth, &proof)
            .is_err());
        assert!(engine
            .register_verified_plot("v", root, 0, depth, &proof)
            .is_err());
        assert!(engine
            .register_verified_plot("v", root, MAX_PLOT_SIZE_BYTES + 1, depth, &proof)
            .is_err());

        // Authentic opening for the challenged leaf succeeds.
        engine
            .register_verified_plot("validator-1", root, 1_000_000_000, depth, &proof)
            .expect("authentic Merkle registration succeeds");
        assert_eq!(engine.plot_count(), 1);
        assert_eq!(engine.total_capacity(), 1_000_000_000);
    }

    #[test]
    fn pospace_producer_block_validates_on_separate_verifier_node_and_refuses_forgery() {
        let zero = "0".repeat(64);
        let miner = PoSpaceEngine::new(PoSpaceConfig::default());
        let verifier = PoSpaceEngine::new(PoSpaceConfig::default());
        let empty = PoSpaceEngine::new(PoSpaceConfig::default());

        // Empty production engine fails closed on both prepare and validate.
        let mut unreg_blk = make_block(1, &zero);
        assert!(empty
            .prepare_block(&mut unreg_blk, &AccountState::new())
            .is_err());
        assert!(empty
            .validate_block(&unreg_blk, &[], &AccountState::new())
            .is_err());

        // Miner commits real plot leaves; separate verifier registers ONLY the
        // Merkle root via a single verified leaf opening (never holds full plot).
        let leaves = sample_leaves(0x22, 16);
        let plot_id = miner
            .register_committed_plot("miner-1", 10_000_000, leaves.clone())
            .expect("miner registers plot");
        assert_eq!(
            register_remote_plot(&verifier, "miner-1", 10_000_000, &leaves),
            plot_id
        );

        let mut block = make_block(1, &zero);
        miner
            .prepare_block(&mut block, &AccountState::new())
            .expect("miner produces Merkle-proven block");
        verifier
            .validate_block(&block, &[], &AccountState::new())
            .expect("verifier validates Merkle opening against registered root");
        verifier.record_block(&block, None).expect("record block");

        // Unregistered engine refuses the block.
        assert!(empty
            .validate_block(&block, &[], &AccountState::new())
            .is_err());

        // Corrupting a single bit of the Merkle leaf in vrf_proof MUST fail.
        let mut forged = block.clone();
        forged.vrf_proof[90] ^= 0x01;
        forged.hash = forged.calculate_hash();
        assert!(verifier
            .validate_block(&forged, &[], &AccountState::new())
            .is_err());
    }

    #[test]
    fn pospace_fork_choice_fails_closed_on_unregistered_1pib_and_ranks_registered_capacity() {
        let zero = "0".repeat(64);

        let small_leaves = sample_leaves(0x31, 8);
        let small_miner = PoSpaceEngine::new(PoSpaceConfig::default());
        small_miner
            .register_committed_plot("small-miner", 2_000_000, small_leaves.clone())
            .expect("small");
        let mut b_small = make_block(1, &zero);
        small_miner
            .prepare_block(&mut b_small, &AccountState::new())
            .expect("prepare small");

        let large_leaves = sample_leaves(0x42, 8);
        let large_miner = PoSpaceEngine::new(PoSpaceConfig::default());
        large_miner
            .register_committed_plot("large-miner", 200_000_000, large_leaves.clone())
            .expect("large");
        let mut b_large = make_block(1, &zero);
        large_miner
            .prepare_block(&mut b_large, &AccountState::new())
            .expect("prepare large");

        // Regression: attacker self-generates a valid 1 PiB Merkle plot
        // that was NEVER registered in consensus state -> scores 0 and NEVER wins!
        let sybil_leaves = sample_leaves(0x99, 8);
        let sybil_miner = PoSpaceEngine::new(PoSpaceConfig::default());
        sybil_miner
            .register_committed_plot("sybil", MAX_PLOT_SIZE_BYTES, sybil_leaves)
            .expect("local sybil");
        let mut b_sybil = make_block(1, &zero);
        sybil_miner
            .prepare_block(&mut b_sybil, &AccountState::new())
            .expect("prepare sybil");

        // Verifier node registers `small-miner` and `large-miner`, NOT `sybil`.
        let observer = PoSpaceEngine::new(PoSpaceConfig::default());
        register_remote_plot(&observer, "small-miner", 2_000_000, &small_leaves);
        register_remote_plot(&observer, "large-miner", 200_000_000, &large_leaves);

        let chain_small = vec![b_small];
        let chain_large = vec![b_large];
        let chain_sybil = vec![b_sybil];

        assert_eq!(
            observer.fork_choice_score(&chain_sybil),
            0,
            "unregistered 1 PiB chain must score 0"
        );
        assert!(
            !observer.is_better_chain(&chain_small, &chain_sybil),
            "unregistered 1 PiB chain must never beat registered 2 MB chain"
        );
        assert!(observer.is_better_chain(&chain_small, &chain_large));
        assert!(!observer.is_better_chain(&chain_large, &chain_small));
        assert!(!observer.is_better_chain(&chain_small, &chain_small));

        // Registered plot lying about its size_bytes scores 0.
        let mut inflated = chain_small[0].clone();
        inflated.vrf_proof[72..80].copy_from_slice(&999_000_000_u64.to_le_bytes());
        inflated.hash = inflated.calculate_hash();
        assert_eq!(observer.fork_choice_score(&[inflated]), 0);

        // Duplicated/unlinked chain and tampered hash score 0.
        assert_eq!(
            observer.fork_choice_score(&[chain_small[0].clone(), chain_small[0].clone()]),
            0
        );
        let mut tampered = chain_small[0].clone();
        tampered.hash = "f".repeat(64);
        assert_eq!(observer.fork_choice_score(&[tampered]), 0);
    }

    #[test]
    fn space_time_delay_enforces_plot_filter_merkle_binding_and_vdf_checkpoints() {
        let leaves = sample_leaves(0x42, 16);
        let (plot_id, depth) = build_plot_merkle_tree(&leaves).expect("plot tree");
        let challenge = [0x7A; 32];
        let size_bytes = 4 * 1024 * 1024;
        let filter_bits = 2u8;

        // Find the first eligible signage point and also a rejected signage point.
        let pass_idx = (0..256u32)
            .find(|&idx| passes_plot_filter(&plot_id, &challenge, idx, filter_bits))
            .expect("eligible signage point exists");
        let fail_idx = (0..256u32)
            .find(|&idx| !passes_plot_filter(&plot_id, &challenge, idx, filter_bits))
            .expect("filtered signage point exists");

        assert!(evaluate_space_time_delay(
            plot_id,
            size_bytes,
            depth,
            &leaves,
            challenge,
            SpaceTimeDelayParams {
                signage_index: fail_idx,
                filter_bits,
                difficulty: 100,
                max_iterations: 256,
                segment_stride: 32,
            },
        )
        .is_err());

        let proof = evaluate_space_time_delay(
            plot_id,
            size_bytes,
            depth,
            &leaves,
            challenge,
            SpaceTimeDelayParams {
                signage_index: pass_idx,
                filter_bits,
                difficulty: 100,
                max_iterations: 256,
                segment_stride: 32,
            },
        )
        .expect("evaluate space-time proof");
        verify_space_time_delay(&proof, &challenge, 1024 * 1024, filter_bits, 100, 256)
            .expect("verify space-time proof");

        // Larger verified plot capacity requires no more sequential VDF iterations
        // than a smaller plot with the same quality.
        let small_iters = required_space_time_iterations(
            &plot_id,
            &challenge,
            pass_idx,
            &proof.space_opening,
            1024 * 1024,
            1_000,
            4_096,
        )
        .expect("small iters");
        let large_iters = required_space_time_iterations(
            &plot_id,
            &challenge,
            pass_idx,
            &proof.space_opening,
            16 * 1024 * 1024,
            1_000,
            4_096,
        )
        .expect("large iters");
        assert!(large_iters <= small_iters);

        // Shortcutting iterations, tampering a checkpoint, or tampering output all fail closed.
        let mut short = proof.clone();
        short.iterations = short.iterations.saturating_sub(1);
        assert!(
            verify_space_time_delay(&short, &challenge, 1024 * 1024, filter_bits, 100, 256)
                .is_err()
        );
        if let Some(first_cp) = proof.checkpoints.first().copied() {
            let mut bad_cp = proof.clone();
            bad_cp.checkpoints[0] = {
                let mut c = first_cp;
                c[0] ^= 0x55;
                c
            };
            assert!(verify_space_time_delay(
                &bad_cp,
                &challenge,
                1024 * 1024,
                filter_bits,
                100,
                256
            )
            .is_err());
        }
        let mut bad_out = proof;
        bad_out.output[31] ^= 0x01;
        assert!(
            verify_space_time_delay(&bad_out, &challenge, 1024 * 1024, filter_bits, 100, 256)
                .is_err()
        );
    }
}
