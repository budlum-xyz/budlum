//! PHANTOM-GHOSTDAG `k`-cluster blockDAG Proof-of-Work external finality
//! adapter (`ghostdag-pow-v1`, Kaspa / Sompolinsky-Wyborski-Zohar 2021 lineage).
//!
//! Unlike a linear Nakamoto chain where concurrent blocks orphan one another, a
//! PHANTOM-GHOSTDAG ledger retains every valid parallel Proof-of-Work block in
//! a directed acyclic graph and extracts a total topological order by greedily
//! constructing a maximal `k`-cluster (`blue` subgraph whose internal anticones
//! never exceed `k`) along the highest-cumulative-blue-work selected-parent
//! chain. Verification enforces seven protocol invariants:
//!
//! 1. **Bounded canonical decoding**: enforces explicit `GHDAGV01` framing,
//!    strict payload ceiling (`MAX_GHOSTDAG_PAYLOAD_BYTES`), and exact
//!    `bincode::serialized_size` trailing-byte rejection.
//! 2. **Compact-target `SHA-256d` Proof-of-Work (`AssumptionClass::Hash`)**:
//!    decodes each header's compact difficulty word (`bits`), rejects negative,
//!    zero, overflowing, or easier-than-`pinned.max_target_bits` targets,
//!    recomputes the canonical header hash in constant time, and verifies
//!    `sha256d(header) <= target` in exact 256-bit arithmetic (quantum-immune
//!    to Shor's algorithm; survives CRQC isolation).
//! 3. **Strict DAG topology and parent antichain**: begins at the governance-
//!    pinned pruning-point / checkpoint anchor (`anchor_hash`) and verifies
//!    every subsequent header references `1..=pinned.max_parents` strictly
//!    sorted, unique, already-verified parents forming a true antichain (no
//!    parent lies in the causal past of any sibling parent).
//! 4. **Merge-depth and DAA monotonicity**: every header advances `daa_score`
//!    strictly past all parents, maintains non-decreasing `timestamp_secs`
//!    relative to its selected parent within `policy.now + max_future_drift_secs`,
//!    and enforces `daa_score(selected_parent) - daa_score(c) <= merge_depth_bound`
//!    across every non-selected mergeset candidate `c`.
//! 5. **Exact PHANTOM-GHOSTDAG greedy `k`-cluster coloring**: verifies
//!    `selected_parent == argmax_{p in parents} (blue_work(p), block_hash(p))`,
//!    orders `mergeset(B) \ {selected_parent}` deterministically by topological
//!    `(blue_work, block_hash)`, colors candidate `C` blue if and only if
//!    `|blue_set(B) \ past(C)| <= k` and every incomparable `D in blue_set(B)`
//!    retains `|blue_anticone(D, blue_set(B) U {C})| <= k`, and rejects any
//!    mismatch against `claimed_mergeset_blues`, `claimed_blue_score`, or
//!    exact 256-bit `claimed_blue_work` (red blocks contribute zero blue work).
//! 6. **Virtual selected-parent chain and confirmation depth**: selects the
//!    globally maximal sink tip `argmax_{sink V} (blue_work(V), block_hash(V))`
//!    (refusing non-sink tips), verifies `finalized_hash` lies on the tip's
//!    selected-parent chain, and requires `blue_score(tip) - blue_score(fin) >=
//!    max(pinned.required_blue_depth, policy.min_depth)`.
//! 7. **Honest root surface**: attests `utxo_commitment` (`state_root`),
//!    `block_hash`, and `accepted_id_merkle_root` (`tx_root`), while leaving
//!    `attested_event_root = None` because UTXO blockDAG headers commit no
//!    cross-domain event tree.
//!
//! WIRING: wired - `AdapterSpec::Ghostdag { network, anchor }` (wire tag 17)
//! builds this adapter from an intake registration whose checkpoint anchor and
//! `k`-cluster parameters must equal the governance pin
//! (`IntakeState::pin_ghostdag_anchor`, reachable in production through
//! `GovernanceAction::PinExternalAnchor`), and
//! `FinalityGuarantee::for_external_spec_declared` maps the pinned blue depth to
//! probabilistic-work finality.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::core::hash::hash_fields_bytes;
use crate::crypto::facts::{AssumptionClass, CryptoObserver, ObservedScheme};
use crate::domain::types::Hash32;
use crate::network::bounded_bincode::decode_bounded_bincode;

use super::selftest::{BytePatch, ExpectedRefusal, FaultProbe, RefusalKind};
use super::spec::{
    AdapterDescriptor, AdapterError, AdapterId, DomainKey, ExternalFinalityAdapter,
    FinalityAttestation, FinalityKind, RawConsensusEvidence, SecurityBacking, TimeUnit, TrustModel,
    VerificationPolicy,
};

/// Canonical adapter identifier registered in [`AdapterDescriptor`].
pub const GHOSTDAG_ADAPTER_NAME: &str = "ghostdag-pow-v1";
/// Adapter implementation version.
pub const GHOSTDAG_ADAPTER_VERSION: u32 = 1;
/// Wire schema version for [`GhostdagEvidence`].
pub const GHOSTDAG_EVIDENCE_VERSION: u32 = 1;
/// Maximum DAG vertices (including index 0 = pinned anchor) per evidence window.
pub const MAX_GHOSTDAG_WINDOW_VERTICES: usize = 128;
/// Maximum non-anchor headers accepted in one [`GhostdagEvidence`] payload.
pub const MAX_GHOSTDAG_HEADERS: usize = MAX_GHOSTDAG_WINDOW_VERTICES - 1;
/// Maximum direct parents permitted on a single blockDAG header.
pub const MAX_GHOSTDAG_PARENTS: u8 = 16;
/// Maximum PHANTOM-GHOSTDAG anticone parameter `k` verified in-window.
pub const MAX_GHOSTDAG_K: u8 = 64;

const PAYLOAD_MAGIC: &[u8; 8] = b"GHDAGV01";
const MAX_GHOSTDAG_PAYLOAD_BYTES: usize = 256 * 1024;
const HEADER_TAG: &[u8] = b"bud-ghostdag-header-v1";

/// Fixed 128-vertex bitset for deterministic zero-allocation causal-past and
/// blue-cluster set algebra within a single verification window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct VertexSet(u128);

impl VertexSet {
    #[inline]
    const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    fn singleton(idx: usize) -> Option<Self> {
        let shift = u32::try_from(idx).ok()?;
        1u128.checked_shl(shift).map(Self)
    }

    #[inline]
    fn insert(&mut self, idx: usize) -> bool {
        if let Some(bit) = Self::singleton(idx) {
            self.0 |= bit.0;
            true
        } else {
            false
        }
    }

    #[inline]
    fn contains(self, idx: usize) -> bool {
        Self::singleton(idx).is_some_and(|bit| (self.0 & bit.0) != 0)
    }

    #[inline]
    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[inline]
    const fn len(self) -> u32 {
        self.0.count_ones()
    }

    fn iter(self) -> impl Iterator<Item = usize> {
        let mut bits = self.0;
        core::iter::from_fn(move || {
            if bits == 0 {
                return None;
            }
            let tz = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            Some(tz)
        })
    }
}

/// Exact 256-bit unsigned integer (little-endian 64-bit limbs) used for `PoW`
/// target decoding, hash comparison, and cumulative `blue_work` accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
struct U256([u64; 4]);

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        let [a0, a1, a2, a3] = self.0;
        let [b0, b1, b2, b3] = other.0;
        a3.cmp(&b3)
            .then_with(|| a2.cmp(&b2))
            .then_with(|| a1.cmp(&b1))
            .then_with(|| a0.cmp(&b0))
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl U256 {
    const ZERO: Self = Self([0; 4]);
    const ONE: Self = Self([1, 0, 0, 0]);

    const fn is_zero(self) -> bool {
        let [a0, a1, a2, a3] = self.0;
        a0 == 0 && a1 == 0 && a2 == 0 && a3 == 0
    }

    const fn bit_len(self) -> u32 {
        let [a0, a1, a2, a3] = self.0;
        if a3 != 0 {
            256 - a3.leading_zeros()
        } else if a2 != 0 {
            192 - a2.leading_zeros()
        } else if a1 != 0 {
            128 - a1.leading_zeros()
        } else {
            64 - a0.leading_zeros()
        }
    }

    fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let read_limb = |start: usize| -> u64 {
            let mut buf = [0u8; 8];
            if let Some(slice) = bytes.get(start..start + 8) {
                buf.copy_from_slice(slice);
            }
            u64::from_be_bytes(buf)
        };
        Self([read_limb(24), read_limb(16), read_limb(8), read_limb(0)])
    }

    fn checked_add(self, rhs: Self) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for ((slot, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (s1, c1) = a.overflowing_add(*b);
            let (s2, c2) = s1.overflowing_add(carry);
            *slot = s2;
            carry = u64::from(c1 || c2);
        }
        if carry == 0 {
            Some(Self(out))
        } else {
            None
        }
    }

    fn checked_sub(self, rhs: Self) -> Option<Self> {
        if self < rhs {
            return None;
        }
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for ((slot, a), b) in out.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            let (d1, b1) = a.overflowing_sub(*b);
            let (d2, b2) = d1.overflowing_sub(borrow);
            *slot = d2;
            borrow = u64::from(b1 || b2);
        }
        Some(Self(out))
    }

    const fn bitnot(self) -> Self {
        let [a0, a1, a2, a3] = self.0;
        Self([!a0, !a1, !a2, !a3])
    }

    fn bit(self, idx: u32) -> bool {
        let limb_idx = (idx / 64) as usize;
        let bit_idx = idx % 64;
        self.0
            .get(limb_idx)
            .is_some_and(|limb| ((*limb >> bit_idx) & 1) != 0)
    }

    fn shl1_with_bit(self, lsb: bool) -> Self {
        let [a0, a1, a2, a3] = self.0;
        let c0 = a0 >> 63;
        let c1 = a1 >> 63;
        let c2 = a2 >> 63;
        Self([
            (a0 << 1) | u64::from(lsb),
            (a1 << 1) | c0,
            (a2 << 1) | c1,
            (a3 << 1) | c2,
        ])
    }

    fn set_bit(&mut self, idx: u32) {
        let limb_idx = (idx / 64) as usize;
        let bit_idx = idx % 64;
        if let Some(slot) = self.0.get_mut(limb_idx) {
            *slot |= 1u64 << bit_idx;
        }
    }

    /// Exact binary long division `self / divisor`; returns `None` when `divisor == 0`.
    fn checked_div(self, divisor: Self) -> Option<Self> {
        if divisor.is_zero() {
            return None;
        }
        let mut quotient = Self::ZERO;
        let mut rem = Self::ZERO;
        for bit_idx in (0..256u32).rev() {
            rem = rem.shl1_with_bit(self.bit(bit_idx));
            if rem >= divisor {
                rem = rem.checked_sub(divisor)?;
                quotient.set_bit(bit_idx);
            }
        }
        Some(quotient)
    }

    /// Decodes a Bitcoin/Kaspa compact 32-bit target representation into an
    /// exact 256-bit target threshold, rejecting zero, sign-flagged, or >256-bit
    /// encodings.
    fn from_compact_bits(bits: u32) -> Option<Self> {
        let exponent = bits >> 24;
        let mantissa = bits & 0x007f_ffff;
        if mantissa == 0 || (bits & 0x0080_0000) != 0 {
            return None;
        }
        if exponent > 34 {
            return None;
        }
        let mut be = [0u8; 32];
        let m_bytes = [
            ((mantissa >> 16) & 0xff) as u8,
            ((mantissa >> 8) & 0xff) as u8,
            (mantissa & 0xff) as u8,
        ];
        for (i, byte) in m_bytes.iter().copied().enumerate() {
            if byte == 0 {
                continue;
            }
            // Value is mantissa * 256^(exponent - 3); m_bytes[i] sits at byte
            // significance (exponent - 1 - i) counted from least-significant 0.
            let offset_from_msb = 32i64 - i64::from(exponent) + i64::try_from(i).ok()?;
            if offset_from_msb < 0 {
                return None;
            }
            if offset_from_msb < 32 {
                let idx = usize::try_from(offset_from_msb).ok()?;
                if let Some(slot) = be.get_mut(idx) {
                    *slot = byte;
                }
            }
        }
        let out = Self::from_be_bytes(&be);
        if out.is_zero() {
            None
        } else {
            Some(out)
        }
    }

    /// Exact expected hash attempts `floor(2^256 / (target + 1))` using the
    /// overflow-free identity `(!target / (target + 1)) + 1`.
    fn work_for_target(target: Self) -> Self {
        let Some(denom) = target.checked_add(Self::ONE) else {
            // target == 2^256 - 1 -> floor(2^256 / 2^256) == 1.
            return Self::ONE;
        };
        target
            .bitnot()
            .checked_div(denom)
            .and_then(|q| q.checked_add(Self::ONE))
            .unwrap_or(Self::ONE)
    }
}

/// Governance-pinned checkpoint / pruning-point anchor for a PHANTOM-GHOSTDAG
/// Proof-of-Work external domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedGhostdagAnchor {
    /// Block hash of the pinned pruning-point / checkpoint vertex.
    pub anchor_hash: Hash32,
    /// DAA (difficulty-adjustment) monotonic score of the pinned anchor.
    pub anchor_daa_score: u64,
    /// Cumulative GHOSTDAG `blue_score` at the pinned anchor.
    pub anchor_blue_score: u64,
    /// Cumulative 256-bit `blue_work` (little-endian `u64` limbs) at the anchor.
    pub anchor_blue_work: [u64; 4],
    /// Timestamp (Unix seconds) of the pinned anchor header.
    pub anchor_timestamp_secs: u64,
    /// PHANTOM-GHOSTDAG anticone parameter `k` (`1..=MAX_GHOSTDAG_K`).
    pub k: u8,
    /// Maximum direct parents permitted per block (`1..=MAX_GHOSTDAG_PARENTS`).
    pub max_parents: u8,
    /// Maximum allowed `daa_score(selected_parent) - daa_score(candidate)` for
    /// blocks admitted into a header's mergeset (`>= 1`).
    pub merge_depth_bound: u64,
    /// Easiest (largest) allowed compact `PoW` difficulty target on this network.
    pub max_target_bits: u32,
    /// Minimum blue-score confirmation depth from finalized block to sink tip.
    pub required_blue_depth: u64,
    /// Maximum header timestamp drift ahead of `policy.now` in seconds.
    pub max_future_drift_secs: u64,
}

impl PinnedGhostdagAnchor {
    fn validate(&self) -> Result<U256, AdapterError> {
        if self.anchor_hash == [0u8; 32] {
            return Err(AdapterError::ConsensusRule {
                rule: "ghostdag anchor_hash must be non-zero".into(),
            });
        }
        if self.k == 0 || self.k > MAX_GHOSTDAG_K {
            return Err(AdapterError::ConsensusRule {
                rule: format!("ghostdag k={} outside 1..={MAX_GHOSTDAG_K}", self.k),
            });
        }
        if self.max_parents == 0 || self.max_parents > MAX_GHOSTDAG_PARENTS {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "ghostdag max_parents={} outside 1..={MAX_GHOSTDAG_PARENTS}",
                    self.max_parents
                ),
            });
        }
        if self.merge_depth_bound == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "ghostdag merge_depth_bound must be at least 1".into(),
            });
        }
        if self.required_blue_depth == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "ghostdag required_blue_depth must be at least 1".into(),
            });
        }
        U256::from_compact_bits(self.max_target_bits).ok_or_else(|| AdapterError::ConsensusRule {
            rule: "ghostdag max_target_bits is not a valid compact PoW target".into(),
        })
    }
}

/// One blockDAG header in topological order following the pinned anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhostdagHeader {
    /// Canonical `SHA-256d` header hash (must equal [`Self::compute_pow_hash`]).
    pub block_hash: Hash32,
    /// Direct parent block hashes in strictly ascending byte order (antichain).
    pub parents: Vec<Hash32>,
    /// Claimed GHOSTDAG selected parent (`argmax_{p in parents} (blue_work, hash)`).
    pub selected_parent: Hash32,
    /// Merkle root of accepted transaction identifiers (non-zero).
    pub accepted_id_merkle_root: Hash32,
    /// Rolling UTXO set commitment (`MuHash` / state root, non-zero).
    pub utxo_commitment: Hash32,
    /// Header timestamp in Unix seconds.
    pub timestamp_secs: u64,
    /// Compact `PoW` target word.
    pub bits: u32,
    /// 64-bit Proof-of-Work nonce.
    pub nonce: u64,
    /// Monotonic difficulty-adjustment score (strictly above all parents).
    pub daa_score: u64,
    /// Claimed cumulative GHOSTDAG `blue_score` (recomputed and checked).
    pub claimed_blue_score: u64,
    /// Claimed cumulative 256-bit `blue_work` in little-endian `u64` limbs.
    pub claimed_blue_work: [u64; 4],
    /// Claimed ordered blue mergeset starting with `selected_parent`.
    pub claimed_mergeset_blues: Vec<Hash32>,
}

impl GhostdagHeader {
    /// Computes the domain-separated `SHA-256d` Proof-of-Work hash committing
    /// to every consensus header field (including parent set, GHOSTDAG blue
    /// commitments, DAA score, compact target, timestamp, roots, and nonce).
    ///
    /// Convenience: exposed for external relayers and blockDAG evidence builders.
    #[must_use]
    pub fn compute_pow_hash(&self, network: &str) -> Hash32 {
        let mut parent_buf = Vec::with_capacity(self.parents.len().saturating_mul(32));
        for p in &self.parents {
            parent_buf.extend_from_slice(p);
        }
        let mut blues_buf =
            Vec::with_capacity(self.claimed_mergeset_blues.len().saturating_mul(32));
        for b in &self.claimed_mergeset_blues {
            blues_buf.extend_from_slice(b);
        }
        let mut work_bytes = [0u8; 32];
        for (idx, limb) in self.claimed_blue_work.iter().enumerate() {
            if let Some(slot) = work_bytes.get_mut(idx * 8..idx * 8 + 8) {
                slot.copy_from_slice(&limb.to_le_bytes());
            }
        }
        let parent_count = (self.parents.len() as u64).to_le_bytes();
        let blues_count = (self.claimed_mergeset_blues.len() as u64).to_le_bytes();
        let ts = self.timestamp_secs.to_le_bytes();
        let bits = self.bits.to_le_bytes();
        let nonce = self.nonce.to_le_bytes();
        let daa = self.daa_score.to_le_bytes();
        let blue_score = self.claimed_blue_score.to_le_bytes();

        let inner = hash_fields_bytes(&[
            HEADER_TAG,
            network.as_bytes(),
            &parent_count,
            &parent_buf,
            &self.selected_parent,
            &self.accepted_id_merkle_root,
            &self.utxo_commitment,
            &ts,
            &bits,
            &nonce,
            &daa,
            &blue_score,
            &work_bytes,
            &blues_count,
            &blues_buf,
        ]);
        let second = Sha256::digest(inner);
        let mut out = [0u8; 32];
        out.copy_from_slice(&second);
        out
    }
}

/// Wire payload proving PHANTOM-GHOSTDAG finality of `finalized_hash` beneath
/// `tip_hash` across a topologically ordered sub-DAG rooted at `anchor_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhostdagEvidence {
    /// Topologically sorted headers descending from `pinned.anchor_hash`.
    pub headers: Vec<GhostdagHeader>,
    /// Claimed finalized block hash on the `tip_hash` selected-parent chain.
    pub finalized_hash: Hash32,
    /// Maximal highest-blue-work sink vertex crowning the confirmation window.
    pub tip_hash: Hash32,
}

/// Encodes [`GhostdagEvidence`] with canonical `GHDAGV01` magic framing.
///
/// Convenience: exposed for external GHOSTDAG relayer encoders and self-tests.
///
/// # Errors
///
/// Returns [`AdapterError::Malformed`] if serialization fails or exceeds
/// `MAX_GHOSTDAG_PAYLOAD_BYTES`.
pub fn encode_ghostdag_evidence(evidence: &GhostdagEvidence) -> Result<Vec<u8>, AdapterError> {
    let body = bincode::serialize(evidence).map_err(|e| AdapterError::Malformed {
        offset: 0,
        reason: format!("ghostdag encode failed: {e}"),
    })?;
    let total = PAYLOAD_MAGIC.len().saturating_add(body.len());
    if total > MAX_GHOSTDAG_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: format!("ghostdag payload {total} exceeds {MAX_GHOSTDAG_PAYLOAD_BYTES}"),
        });
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAYLOAD_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_ghostdag_evidence(payload: &[u8]) -> Result<GhostdagEvidence, AdapterError> {
    if payload.len() < PAYLOAD_MAGIC.len() || payload.len() > MAX_GHOSTDAG_PAYLOAD_BYTES {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: format!(
                "ghostdag payload length {} outside {}..={MAX_GHOSTDAG_PAYLOAD_BYTES}",
                payload.len(),
                PAYLOAD_MAGIC.len()
            ),
        });
    }
    let magic = payload
        .get(..PAYLOAD_MAGIC.len())
        .ok_or_else(|| AdapterError::Malformed {
            offset: 0,
            reason: "ghostdag missing payload magic".into(),
        })?;
    if !bool::from(magic.ct_eq(PAYLOAD_MAGIC.as_slice())) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "ghostdag invalid payload magic".into(),
        });
    }
    let body = payload
        .get(PAYLOAD_MAGIC.len()..)
        .ok_or_else(|| AdapterError::Malformed {
            offset: 0,
            reason: "ghostdag empty body".into(),
        })?;
    let decoded: GhostdagEvidence = decode_bounded_bincode(body, MAX_GHOSTDAG_PAYLOAD_BYTES)
        .map_err(|e| AdapterError::Malformed {
            offset: 0,
            reason: format!("ghostdag bincode decode failed: {e}"),
        })?;
    let exact_len = bincode::serialized_size(&decoded).map_err(|e| AdapterError::Malformed {
        offset: 0,
        reason: format!("ghostdag size check failed: {e}"),
    })?;
    if exact_len != u64::try_from(body.len()).unwrap_or(u64::MAX) {
        return Err(AdapterError::Malformed {
            offset: 0,
            reason: "ghostdag trailing bytes rejected".into(),
        });
    }
    Ok(decoded)
}

#[derive(Debug, Clone)]
struct VerifiedVertex {
    hash: Hash32,
    selected_parent: Option<usize>,
    daa_score: u64,
    blue_score: u64,
    blue_work: U256,
    timestamp_secs: u64,
    bits: u32,
    utxo_commitment: Hash32,
    accepted_id_merkle_root: Hash32,
    /// Strict causal past of this vertex (excludes self).
    past: VertexSet,
    /// Cumulative in-window blue cluster up to and including this vertex.
    blue_set: VertexSet,
    has_child: bool,
}

/// Checks whether candidate `cand_idx` can join `current_blues` without any
/// vertex in `current_blues U {cand_idx}` having more than `k` incomparable
/// blue peers (Sompolinsky-Wyborski-Zohar 2021, Algorithm 1 `checkBlue`).
fn can_color_blue(
    vertices: &[VerifiedVertex],
    current_blues: VertexSet,
    cand_idx: usize,
    cand_past: VertexSet,
    k: u32,
) -> bool {
    // Because `cand_idx` is processed in causal order and no member of
    // `current_blues` can lie in `future(cand_idx)` (if `d` had `cand_idx` in
    // `past(d)`, then since `d` is ordered before `cand_idx` in the mergeset,
    // topological sorting places `cand_idx` before `d`), still check both
    // `cand_past.contains(d)` and `d.past.contains(cand_idx)` defensively.
    let mut cand_blue_anticone = 0u32;
    let mut incomparable = VertexSet::empty();
    for d_idx in current_blues.iter() {
        let Some(d_v) = vertices.get(d_idx) else {
            return false;
        };
        if !cand_past.contains(d_idx) && !d_v.past.contains(cand_idx) {
            cand_blue_anticone = cand_blue_anticone.saturating_add(1);
            if cand_blue_anticone > k {
                return false;
            }
            let _ = incomparable.insert(d_idx);
        }
    }
    // Verify every existing blue block `d` that is incomparable with `cand_idx`
    // keeps its own blue anticone within `current_blues U {cand_idx}` <= k.
    for d_idx in incomparable.iter() {
        let Some(d_v) = vertices.get(d_idx) else {
            return false;
        };
        let mut d_anticone = 1u32; // `cand_idx` itself
        for other_idx in current_blues.iter() {
            if other_idx == d_idx {
                continue;
            }
            let Some(other_v) = vertices.get(other_idx) else {
                return false;
            };
            if !d_v.past.contains(other_idx) && !other_v.past.contains(d_idx) {
                d_anticone = d_anticone.saturating_add(1);
                if d_anticone > k {
                    return false;
                }
            }
        }
    }
    true
}

struct GhostdagColoring {
    selected_parent: usize,
    past: VertexSet,
    blue_set: VertexSet,
    mergeset_blues: Vec<Hash32>,
    blue_score: u64,
    blue_work: U256,
}

/// Computes the deterministic PHANTOM-GHOSTDAG blue mergeset, `blue_score`, and
/// cumulative `blue_work` for a candidate header given the already-verified
/// window vertices.
fn compute_ghostdag_coloring(
    vertices: &[VerifiedVertex],
    parent_indices: &[usize],
    block_work: U256,
    pinned: &PinnedGhostdagAnchor,
) -> Result<GhostdagColoring, AdapterError> {
    // 1. Selected parent = argmax_{p in parents} (blue_work(p), block_hash(p)).
    let mut sp_idx_opt: Option<usize> = None;
    for &p_idx in parent_indices {
        let pv = vertices
            .get(p_idx)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag parent index out of range".into(),
            })?;
        let replace = match sp_idx_opt {
            None => true,
            Some(cur_idx) => {
                let cv = vertices
                    .get(cur_idx)
                    .ok_or_else(|| AdapterError::ConsensusRule {
                        rule: "ghostdag selected parent out of range".into(),
                    })?;
                (pv.blue_work, pv.hash) > (cv.blue_work, cv.hash)
            }
        };
        if replace {
            sp_idx_opt = Some(p_idx);
        }
    }
    let sp_idx = sp_idx_opt.ok_or_else(|| AdapterError::ConsensusRule {
        rule: "ghostdag header must reference at least one parent".into(),
    })?;

    // 2. Strict causal past = union_{p in parents} (past(p) U {p}).
    let mut past = VertexSet::empty();
    for &p_idx in parent_indices {
        let pv = vertices
            .get(p_idx)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag parent index out of range".into(),
            })?;
        let p_bit = VertexSet::singleton(p_idx).ok_or_else(|| AdapterError::ConsensusRule {
            rule: "ghostdag window bitset overflow".into(),
        })?;
        past = past.union(pv.past).union(p_bit);
    }

    // 3. Enforce parent antichain: no direct parent may lie in another's past.
    for &p_idx in parent_indices {
        for &q_idx in parent_indices {
            if p_idx == q_idx {
                continue;
            }
            let qv = vertices
                .get(q_idx)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "ghostdag parent index out of range".into(),
                })?;
            if qv.past.contains(p_idx) {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag direct parents violate antichain invariant".into(),
                });
            }
        }
    }

    let sp = vertices
        .get(sp_idx)
        .ok_or_else(|| AdapterError::ConsensusRule {
            rule: "ghostdag selected parent missing".into(),
        })?;
    let sp_bit = VertexSet::singleton(sp_idx).ok_or_else(|| AdapterError::ConsensusRule {
        rule: "ghostdag selected parent bit overflow".into(),
    })?;

    // 4. Non-selected mergeset = past(B) \ (past(sp) U {sp}).
    let mergeset_others = past.difference(sp.past.union(sp_bit));

    // Topological sort of `mergeset_others` with deterministic `(blue_work, hash)`
    // tie-breaking among causally ready candidates (Kahn's algorithm).
    let mut remaining = mergeset_others;
    let mut ordered_candidates = Vec::with_capacity(mergeset_others.len() as usize);
    while remaining.len() > 0 {
        let mut best_ready: Option<usize> = None;
        for c_idx in remaining.iter() {
            let cv = vertices
                .get(c_idx)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "ghostdag mergeset index missing".into(),
                })?;
            // Enforce merge-depth bound relative to selected parent.
            if sp.daa_score.saturating_sub(cv.daa_score) > pinned.merge_depth_bound {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "ghostdag mergeset vertex violates merge_depth_bound {}",
                        pinned.merge_depth_bound
                    ),
                });
            }
            // Ready iff no unscheduled mergeset ancestor remains in `past(c)`.
            if cv.past.0 & remaining.0 != 0 {
                continue;
            }
            let take = match best_ready {
                None => true,
                Some(prev_idx) => {
                    let pv = vertices
                        .get(prev_idx)
                        .ok_or_else(|| AdapterError::ConsensusRule {
                            rule: "ghostdag mergeset tie candidate missing".into(),
                        })?;
                    (cv.blue_work, cv.hash) < (pv.blue_work, pv.hash)
                }
            };
            if take {
                best_ready = Some(c_idx);
            }
        }
        let next_idx = best_ready.ok_or_else(|| AdapterError::ConsensusRule {
            rule: "ghostdag cycle detected in mergeset".into(),
        })?;
        let next_bit =
            VertexSet::singleton(next_idx).ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag bit overflow".into(),
            })?;
        remaining = remaining.difference(next_bit);
        ordered_candidates.push(next_idx);
    }

    // 5. Greedy k-cluster coloring. Note: `sp.blue_set` already includes `sp_idx`.
    let mut blue_set = sp.blue_set;
    let mut mergeset_blues = Vec::with_capacity(1 + ordered_candidates.len());
    mergeset_blues.push(sp.hash);
    let mut added_blue_count = 1u64; // counts `sp` transition -> new block B
    let mut cumulative_blue_work =
        sp.blue_work
            .checked_add(block_work)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag cumulative blue_work overflow".into(),
            })?;

    let k = u32::from(pinned.k);
    for c_idx in ordered_candidates {
        let cv = vertices
            .get(c_idx)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag candidate vertex missing".into(),
            })?;
        if can_color_blue(vertices, blue_set, c_idx, cv.past, k) {
            let _ = blue_set.insert(c_idx);
            mergeset_blues.push(cv.hash);
            added_blue_count =
                added_blue_count
                    .checked_add(1)
                    .ok_or_else(|| AdapterError::ConsensusRule {
                        rule: "ghostdag blue_score overflow".into(),
                    })?;
            // Anchor (idx 0) work is already baked into anchor_blue_work.
            if c_idx != 0 {
                let target = U256::from_compact_bits(cv.bits).ok_or_else(|| {
                    AdapterError::ConsensusRule {
                        rule: "ghostdag mergeset blue compact bits invalid".into(),
                    }
                })?;
                let c_work = U256::work_for_target(target);
                cumulative_blue_work =
                    cumulative_blue_work.checked_add(c_work).ok_or_else(|| {
                        AdapterError::ConsensusRule {
                            rule: "ghostdag mergeset blue_work overflow".into(),
                        }
                    })?;
            }
        }
    }

    let blue_score =
        sp.blue_score
            .checked_add(added_blue_count)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag blue_score u64 overflow".into(),
            })?;

    Ok(GhostdagColoring {
        selected_parent: sp_idx,
        past,
        blue_set,
        mergeset_blues,
        blue_score,
        blue_work: cumulative_blue_work,
    })
}

/// External finality adapter for PHANTOM-GHOSTDAG `k`-cluster blockDAG `PoW`
/// domains (`Kaspa` family).
#[derive(Debug, Clone)]
pub struct GhostdagPowAdapter {
    descriptor: AdapterDescriptor,
    network: String,
    pinned: Option<PinnedGhostdagAnchor>,
    golden: Option<RawConsensusEvidence>,
}

impl GhostdagPowAdapter {
    /// Constructs a new `ghostdag-pow-v1` adapter for `network` with an
    /// optional governance-pinned pruning-point / checkpoint anchor.
    #[must_use]
    pub fn new(network: impl Into<String>, pinned: Option<PinnedGhostdagAnchor>) -> Self {
        let network = network.into();
        let id = AdapterId::from_name(GHOSTDAG_ADAPTER_NAME);
        let min_depth = pinned.as_ref().map_or(10, |p| p.required_blue_depth);
        let descriptor = AdapterDescriptor {
            id,
            name: GHOSTDAG_ADAPTER_NAME.to_string(),
            adapter_version: GHOSTDAG_ADAPTER_VERSION,
            accepted_evidence_versions: vec![GHOSTDAG_EVIDENCE_VERSION],
            consensus_kind: "ghostdag-k-cluster-pow".to_string(),
            finality_kind: FinalityKind::Probabilistic,
            required_depth: min_depth,
            time_unit: TimeUnit::UnixSeconds,
            trust_model: TrustModel::Trustless,
        };
        Self {
            descriptor,
            network,
            pinned,
            golden: None,
        }
    }

    /// Attaches a golden self-test sample enabling byte-exact interior
    /// [`FaultProbe`] offsets during [`super::selftest::admit_observed`].
    #[must_use]
    pub fn with_golden(mut self, golden: RawConsensusEvidence) -> Self {
        self.golden = Some(golden);
        self
    }

    fn verify_dag(
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
        if evidence.evidence_version != GHOSTDAG_EVIDENCE_VERSION {
            return Err(AdapterError::UnsupportedEvidenceVersion {
                version: evidence.evidence_version,
                accepted: GHOSTDAG_EVIDENCE_VERSION.to_string(),
            });
        }
        if evidence.network != self.network {
            return Err(AdapterError::ConsensusRule {
                rule: format!(
                    "ghostdag network mismatch: expected {}, got {}",
                    self.network, evidence.network
                ),
            });
        }
        if policy.require_slashable {
            return Err(AdapterError::UnslashableBacking);
        }
        let pinned = self
            .pinned
            .as_ref()
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag adapter requires a governance-pinned anchor".into(),
            })?;
        let max_target = pinned.validate()?;

        let decoded = decode_ghostdag_evidence(&evidence.payload)?;
        if decoded.headers.is_empty() || decoded.headers.len() > MAX_GHOSTDAG_HEADERS {
            return Err(AdapterError::Malformed {
                offset: 0,
                reason: format!(
                    "ghostdag header count {} outside 1..={MAX_GHOSTDAG_HEADERS}",
                    decoded.headers.len()
                ),
            });
        }

        // Seed vertex 0 = pinned anchor.
        let mut anchor_blue = VertexSet::empty();
        let _ = anchor_blue.insert(0);
        let mut vertices = Vec::with_capacity(1 + decoded.headers.len());
        vertices.push(VerifiedVertex {
            hash: pinned.anchor_hash,
            selected_parent: None,
            daa_score: pinned.anchor_daa_score,
            blue_score: pinned.anchor_blue_score,
            blue_work: U256(pinned.anchor_blue_work),
            timestamp_secs: pinned.anchor_timestamp_secs,
            bits: pinned.max_target_bits,
            utxo_commitment: [0u8; 32],
            accepted_id_merkle_root: [0u8; 32],
            past: VertexSet::empty(),
            blue_set: anchor_blue,
            has_child: false,
        });
        let mut index_by_hash: BTreeMap<Hash32, usize> = BTreeMap::new();
        index_by_hash.insert(pinned.anchor_hash, 0);

        for hdr in &decoded.headers {
            if hdr.block_hash == [0u8; 32]
                || hdr.utxo_commitment == [0u8; 32]
                || hdr.accepted_id_merkle_root == [0u8; 32]
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag zero hash or commitment rejected".into(),
                });
            }
            if index_by_hash.contains_key(&hdr.block_hash) {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag duplicate block_hash in window".into(),
                });
            }
            if hdr.parents.is_empty() || hdr.parents.len() > usize::from(pinned.max_parents) {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "ghostdag parent count {} outside 1..={}",
                        hdr.parents.len(),
                        pinned.max_parents
                    ),
                });
            }

            // Enforce strictly ascending unique parent list and resolve indices.
            let mut parent_indices = Vec::with_capacity(hdr.parents.len());
            let mut prev_parent: Option<&Hash32> = None;
            let mut max_parent_daa = 0u64;
            for p_hash in &hdr.parents {
                if let Some(prev) = prev_parent {
                    if p_hash <= prev {
                        return Err(AdapterError::ConsensusRule {
                            rule: "ghostdag parents must be strictly sorted and unique".into(),
                        });
                    }
                }
                prev_parent = Some(p_hash);
                let &p_idx =
                    index_by_hash
                        .get(p_hash)
                        .ok_or_else(|| AdapterError::ConsensusRule {
                            rule: "ghostdag header references unknown or out-of-order parent"
                                .into(),
                        })?;
                let pv = vertices
                    .get(p_idx)
                    .ok_or_else(|| AdapterError::ConsensusRule {
                        rule: "ghostdag parent index missing".into(),
                    })?;
                max_parent_daa = max_parent_daa.max(pv.daa_score);
                parent_indices.push(p_idx);
            }

            if hdr.daa_score <= max_parent_daa {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag daa_score must strictly advance past every parent".into(),
                });
            }

            // Verify compact PoW target and SHA-256d Proof-of-Work.
            let target =
                U256::from_compact_bits(hdr.bits).ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "ghostdag compact difficulty bits malformed".into(),
                })?;
            if target > max_target {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag header target easier than pinned network floor".into(),
                });
            }
            let computed_hash = hdr.compute_pow_hash(&self.network);
            if !bool::from(computed_hash.as_slice().ct_eq(hdr.block_hash.as_slice())) {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag block_hash does not match header preimage".into(),
                });
            }
            if U256::from_be_bytes(&computed_hash) > target {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag header fails SHA-256d Proof-of-Work target".into(),
                });
            }

            let block_work = U256::work_for_target(target);
            let GhostdagColoring {
                selected_parent: sp_idx,
                past,
                mut blue_set,
                mergeset_blues,
                blue_score,
                blue_work,
            } = compute_ghostdag_coloring(&vertices, &parent_indices, block_work, pinned)?;

            let sp_vertex = vertices
                .get(sp_idx)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "ghostdag selected parent missing".into(),
                })?;
            if !bool::from(
                sp_vertex
                    .hash
                    .as_slice()
                    .ct_eq(hdr.selected_parent.as_slice()),
            ) {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag selected_parent disagrees with highest-blue-work parent".into(),
                });
            }
            if hdr.timestamp_secs < sp_vertex.timestamp_secs {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag timestamp regresses behind selected parent".into(),
                });
            }
            let max_allowed_ts = policy.now.saturating_add(pinned.max_future_drift_secs);
            if hdr.timestamp_secs > max_allowed_ts {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag header timestamp exceeds future drift bound".into(),
                });
            }
            if hdr.claimed_blue_score != blue_score {
                return Err(AdapterError::ConsensusRule {
                    rule: format!(
                        "ghostdag claimed_blue_score {} != computed {blue_score}",
                        hdr.claimed_blue_score
                    ),
                });
            }
            if U256(hdr.claimed_blue_work) != blue_work {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag claimed_blue_work mismatches computed k-cluster work".into(),
                });
            }
            if hdr.claimed_mergeset_blues.len() != mergeset_blues.len()
                || hdr
                    .claimed_mergeset_blues
                    .iter()
                    .zip(mergeset_blues.iter())
                    .any(|(a, b)| !bool::from(a.as_slice().ct_eq(b.as_slice())))
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag claimed_mergeset_blues mismatches k-cluster selection".into(),
                });
            }

            let new_idx = vertices.len();
            if !blue_set.insert(new_idx) {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag window vertex cap exceeded".into(),
                });
            }
            for &p_idx in &parent_indices {
                if let Some(pv) = vertices.get_mut(p_idx) {
                    pv.has_child = true;
                }
            }
            vertices.push(VerifiedVertex {
                hash: hdr.block_hash,
                selected_parent: Some(sp_idx),
                daa_score: hdr.daa_score,
                blue_score,
                blue_work,
                timestamp_secs: hdr.timestamp_secs,
                bits: hdr.bits,
                utxo_commitment: hdr.utxo_commitment,
                accepted_id_merkle_root: hdr.accepted_id_merkle_root,
                past,
                blue_set,
                has_child: false,
            });
            index_by_hash.insert(hdr.block_hash, new_idx);
        }

        // Verify `tip_hash` is a maximal sink and equals the global virtual
        // selected parent across all sinks in the window.
        let &tip_idx =
            index_by_hash
                .get(&decoded.tip_hash)
                .ok_or_else(|| AdapterError::ConsensusRule {
                    rule: "ghostdag tip_hash absent from verified DAG window".into(),
                })?;
        let tip = vertices
            .get(tip_idx)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag tip vertex missing".into(),
            })?;
        if tip_idx == 0 || tip.has_child {
            return Err(AdapterError::ConsensusRule {
                rule: "ghostdag tip_hash is not a maximal DAG sink".into(),
            });
        }
        for (idx, v) in vertices.iter().enumerate() {
            if idx != 0
                && !v.has_child
                && idx != tip_idx
                && (v.blue_work, v.hash) > (tip.blue_work, tip.hash)
            {
                return Err(AdapterError::ConsensusRule {
                    rule: "ghostdag tip_hash is dominated by a heavier sink in window".into(),
                });
            }
        }

        // Verify `finalized_hash` is a non-anchor header on the selected-parent
        // chain descending from `tip_hash`.
        let &fin_idx = index_by_hash.get(&decoded.finalized_hash).ok_or_else(|| {
            AdapterError::ConsensusRule {
                rule: "ghostdag finalized_hash absent from verified DAG window".into(),
            }
        })?;
        if fin_idx == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "ghostdag cannot re-attest the pinned anchor itself".into(),
            });
        }
        let mut on_selected_chain = false;
        let mut cursor = Some(tip_idx);
        let mut steps = 0usize;
        while let Some(c_idx) = cursor {
            if c_idx == fin_idx {
                on_selected_chain = true;
                break;
            }
            steps = steps.saturating_add(1);
            if steps > vertices.len() {
                break;
            }
            cursor = vertices.get(c_idx).and_then(|v| v.selected_parent);
        }
        if !on_selected_chain {
            return Err(AdapterError::ConsensusRule {
                rule: "ghostdag finalized_hash does not lie on virtual selected-parent chain"
                    .into(),
            });
        }

        let fin = vertices
            .get(fin_idx)
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag finalized vertex missing".into(),
            })?;

        // Check confirmation depth in GHOSTDAG blue-score units.
        let blue_depth = tip.blue_score.saturating_sub(fin.blue_score);
        let required_depth = pinned.required_blue_depth.max(policy.min_depth);
        if blue_depth < required_depth {
            return Err(AdapterError::InsufficientDepth {
                observed: blue_depth,
                required: required_depth,
            });
        }

        // Freshness gate against `policy.max_age` (0 means disabled).
        if policy.max_age > 0 {
            if fin.timestamp_secs > policy.now {
                return Err(AdapterError::Stale {
                    age: fin.timestamp_secs - policy.now,
                    max_age: policy.max_age,
                });
            }
            let age = policy.now - fin.timestamp_secs;
            if age > policy.max_age {
                return Err(AdapterError::Stale {
                    age,
                    max_age: policy.max_age,
                });
            }
        }

        // Declaration parity checks (never trust undeclared fields).
        if evidence.declared_height != fin.daa_score {
            return Err(AdapterError::DeclarationMismatch { field: "height" });
        }
        if !bool::from(
            evidence
                .declared_root
                .as_slice()
                .ct_eq(fin.utxo_commitment.as_slice()),
        ) {
            return Err(AdapterError::DeclarationMismatch {
                field: "state_root",
            });
        }

        let window_blue_work = tip
            .blue_work
            .checked_sub(U256(pinned.anchor_blue_work))
            .ok_or_else(|| AdapterError::ConsensusRule {
                rule: "ghostdag tip blue_work regressed below pinned anchor".into(),
            })?;
        let difficulty_bits = window_blue_work.bit_len();
        if difficulty_bits == 0 {
            return Err(AdapterError::ConsensusRule {
                rule: "ghostdag window cumulative blue_work must be non-zero".into(),
            });
        }

        Ok(FinalityAttestation {
            adapter: self.descriptor.id,
            domain: DomainKey::from_parts(&self.descriptor.id, &self.network),
            height: fin.daa_score,
            state_root: fin.utxo_commitment,
            finalized_at: fin.timestamp_secs,
            time_unit: TimeUnit::UnixSeconds,
            security: SecurityBacking::Work { difficulty_bits },
            evidence_digest: evidence.digest(),
            adapter_version: GHOSTDAG_ADAPTER_VERSION,
            evidence_version: GHOSTDAG_EVIDENCE_VERSION,
            attested_block_hash: Some(fin.hash),
            // UTXO blockDAG headers carry no Budlum cross-domain event root.
            attested_event_root: None,
            attested_tx_root: Some(fin.accepted_id_merkle_root),
        })
    }
}

impl ExternalFinalityAdapter for GhostdagPowAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn verify(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
    ) -> Result<FinalityAttestation, AdapterError> {
        self.verify_dag(evidence, policy)
    }

    fn verify_observed(
        &self,
        evidence: &RawConsensusEvidence,
        policy: &VerificationPolicy,
        observer: &mut dyn CryptoObserver,
    ) -> Result<FinalityAttestation, AdapterError> {
        let attestation = self.verify_dag(evidence, policy)?;
        observer.observe(ObservedScheme::Proof(AssumptionClass::Hash));
        Ok(attestation)
    }

    fn fault_probes(&self) -> Vec<FaultProbe> {
        let hash_offset = PAYLOAD_MAGIC.len() + 8;
        let tail_offset = self
            .golden
            .as_ref()
            .map_or(24, |g| g.payload.len().saturating_sub(8));
        vec![
            FaultProbe {
                name: "refuses empty ghostdag payload".into(),
                patch: BytePatch::TruncatePayload { keep: 0 },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses corrupted GHDAGV01 magic".into(),
                patch: BytePatch::InPayload {
                    offset: 0,
                    bytes: b"BADMAGIC".to_vec(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::Malformed),
            },
            FaultProbe {
                name: "refuses unsupported ghostdag evidence version".into(),
                patch: BytePatch::EvidenceVersion { value: 99 },
                expect: ExpectedRefusal::Kind(RefusalKind::UnsupportedEvidenceVersion),
            },
            FaultProbe {
                name: "refuses wrong ghostdag network label".into(),
                patch: BytePatch::Network {
                    value: "kaspa-wrongnet".into(),
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses mismatched declared DAA height".into(),
                patch: BytePatch::DeclaredHeight { value: 99_999_999 },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses mismatched declared UTXO commitment".into(),
                patch: BytePatch::DeclaredRoot { value: [0xFE; 32] },
                expect: ExpectedRefusal::Kind(RefusalKind::DeclarationMismatch),
            },
            FaultProbe {
                name: "refuses forged first header PoW block_hash".into(),
                patch: BytePatch::InPayload {
                    offset: hash_offset,
                    bytes: vec![0xFF, 0xEE, 0xDD, 0xCC],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
            },
            FaultProbe {
                name: "refuses corrupted tip_hash at payload tail".into(),
                patch: BytePatch::InPayload {
                    offset: tail_offset,
                    bytes: vec![0xAA, 0x55, 0xAA, 0x55],
                },
                expect: ExpectedRefusal::Kind(RefusalKind::ConsensusRule),
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
    use crate::crypto::facts::CryptoFacts;

    // Easy compact target (0x207fffff => target ~ 0x7fffff * 2^232, ~50% pass
    // per nonce, deterministic single-microsecond mining in unit tests).
    const TEST_BITS: u32 = 0x207f_ffff;
    const NETWORK: &str = "kaspa-testnet-11";

    pub(crate) fn test_anchor(k: u8, required_blue_depth: u64) -> PinnedGhostdagAnchor {
        PinnedGhostdagAnchor {
            anchor_hash: [0xA0; 32],
            anchor_daa_score: 1_000,
            anchor_blue_score: 5_000,
            anchor_blue_work: [100, 0, 0, 0],
            anchor_timestamp_secs: 1_700_000_000,
            k,
            max_parents: 8,
            merge_depth_bound: 64,
            max_target_bits: TEST_BITS,
            required_blue_depth,
            max_future_drift_secs: 120,
        }
    }

    struct TestDagBuilder {
        pinned: PinnedGhostdagAnchor,
        vertices: Vec<VerifiedVertex>,
        headers: Vec<GhostdagHeader>,
        by_hash: BTreeMap<Hash32, usize>,
    }

    impl TestDagBuilder {
        fn new(pinned: PinnedGhostdagAnchor) -> Self {
            let mut anchor_blue = VertexSet::empty();
            let _ = anchor_blue.insert(0);
            let mut by_hash = BTreeMap::new();
            by_hash.insert(pinned.anchor_hash, 0);
            Self {
                vertices: vec![VerifiedVertex {
                    hash: pinned.anchor_hash,
                    selected_parent: None,
                    daa_score: pinned.anchor_daa_score,
                    blue_score: pinned.anchor_blue_score,
                    blue_work: U256(pinned.anchor_blue_work),
                    timestamp_secs: pinned.anchor_timestamp_secs,
                    bits: pinned.max_target_bits,
                    utxo_commitment: [0u8; 32],
                    accepted_id_merkle_root: [0u8; 32],
                    past: VertexSet::empty(),
                    blue_set: anchor_blue,
                    has_child: false,
                }],
                headers: Vec::new(),
                by_hash,
                pinned,
            }
        }

        fn mine_block(
            &mut self,
            mut parents: Vec<Hash32>,
            utxo_seed: u8,
            tx_seed: u8,
            ts_offset: u64,
            bits: u32,
        ) -> GhostdagHeader {
            parents.sort_unstable();
            parents.dedup();
            let p_indices: Vec<usize> = parents.iter().map(|h| self.by_hash[h]).collect();
            let max_daa = p_indices
                .iter()
                .map(|&i| self.vertices[i].daa_score)
                .max()
                .unwrap();
            let target = U256::from_compact_bits(bits).unwrap();
            let work = U256::work_for_target(target);
            let GhostdagColoring {
                selected_parent: sp_idx,
                past,
                mut blue_set,
                mergeset_blues,
                blue_score,
                blue_work,
            } = compute_ghostdag_coloring(&self.vertices, &p_indices, work, &self.pinned).unwrap();
            let sp_hash = self.vertices[sp_idx].hash;
            let mut hdr = GhostdagHeader {
                block_hash: [0u8; 32],
                parents,
                selected_parent: sp_hash,
                accepted_id_merkle_root: [tx_seed; 32],
                utxo_commitment: [utxo_seed; 32],
                timestamp_secs: self.pinned.anchor_timestamp_secs + ts_offset,
                bits,
                nonce: 0,
                daa_score: max_daa + 1,
                claimed_blue_score: blue_score,
                claimed_blue_work: blue_work.0,
                claimed_mergeset_blues: mergeset_blues,
            };
            loop {
                let h = hdr.compute_pow_hash(NETWORK);
                if U256::from_be_bytes(&h) <= target && h != [0u8; 32] {
                    hdr.block_hash = h;
                    break;
                }
                hdr.nonce += 1;
            }
            let idx = self.vertices.len();
            let _ = blue_set.insert(idx);
            self.vertices.push(VerifiedVertex {
                hash: hdr.block_hash,
                selected_parent: Some(sp_idx),
                daa_score: hdr.daa_score,
                blue_score,
                blue_work,
                timestamp_secs: hdr.timestamp_secs,
                bits: hdr.bits,
                utxo_commitment: hdr.utxo_commitment,
                accepted_id_merkle_root: hdr.accepted_id_merkle_root,
                past,
                blue_set,
                has_child: false,
            });
            self.by_hash.insert(hdr.block_hash, idx);
            self.headers.push(hdr.clone());
            hdr
        }
    }

    /// A complete golden fixture: the pinned anchor, the DAG evidence and the
    /// raw evidence envelope an intake registration would carry.
    ///
    /// Shared with `intake.rs`'s tests so the fail-closed pin door is exercised
    /// against evidence that actually verifies, not against a shape.
    pub(crate) fn make_golden_fixture(
    ) -> (PinnedGhostdagAnchor, GhostdagEvidence, RawConsensusEvidence) {
        let pinned = test_anchor(2, 4);
        let mut dag = TestDagBuilder::new(pinned.clone());
        let anchor = pinned.anchor_hash;
        let b1 = dag.mine_block(vec![anchor], 0x11, 0x21, 1, TEST_BITS);
        let b2 = dag.mine_block(vec![anchor], 0x12, 0x22, 2, TEST_BITS);
        let b3 = dag.mine_block(vec![anchor], 0x13, 0x23, 3, TEST_BITS);
        let b4 = dag.mine_block(vec![anchor], 0x14, 0x24, 4, TEST_BITS);
        let merge = dag.mine_block(
            vec![b1.block_hash, b2.block_hash, b3.block_hash, b4.block_hash],
            0x30,
            0x40,
            5,
            TEST_BITS,
        );
        let c1 = dag.mine_block(vec![merge.block_hash], 0x31, 0x41, 6, TEST_BITS);
        let c2 = dag.mine_block(vec![merge.block_hash], 0x32, 0x42, 7, TEST_BITS);
        let c3 = dag.mine_block(vec![c1.block_hash, c2.block_hash], 0x33, 0x43, 8, TEST_BITS);
        let tip = dag.mine_block(vec![c3.block_hash], 0x34, 0x44, 9, TEST_BITS);
        let ev = GhostdagEvidence {
            headers: dag.headers.clone(),
            finalized_hash: merge.block_hash,
            tip_hash: tip.block_hash,
        };
        let base = GhostdagPowAdapter::new(NETWORK, Some(pinned.clone()));
        let raw = wrap_evidence(&base, &ev, merge.daa_score, merge.utxo_commitment);
        (pinned, ev, raw)
    }

    fn wrap_evidence(
        adapter: &GhostdagPowAdapter,
        ev: &GhostdagEvidence,
        declared_height: u64,
        declared_root: Hash32,
    ) -> RawConsensusEvidence {
        RawConsensusEvidence {
            adapter: adapter.descriptor().id,
            evidence_version: GHOSTDAG_EVIDENCE_VERSION,
            network: NETWORK.to_string(),
            payload: encode_ghostdag_evidence(ev).expect("encode"),
            declared_height,
            declared_root,
            submitter: Address([0x44; 32]),
        }
    }

    fn test_policy() -> VerificationPolicy {
        let mut p = VerificationPolicy::strict(1_700_000_100);
        p.require_slashable = false;
        p.min_depth = 3;
        p.max_age = 3_600;
        p
    }

    #[test]
    fn ghostdag_verifies_parallel_k_cluster_with_blue_and_red_blocks_and_passes_selftest() {
        // With k = 2, mining 4 concurrent blocks (b1, b2, b3, b4) directly on
        // anchor produces a 4-block anticone: the merging block `m` MUST color
        // its selected parent + 2 siblings BLUE (anticone 2 <= k) and color the
        // 4th concurrent block RED (excluding its work and blue_score!).
        let pinned = test_anchor(2, 4);
        let mut dag = TestDagBuilder::new(pinned.clone());
        let anchor = pinned.anchor_hash;
        let b1 = dag.mine_block(vec![anchor], 0x11, 0x21, 1, TEST_BITS);
        let b2 = dag.mine_block(vec![anchor], 0x12, 0x22, 2, TEST_BITS);
        let b3 = dag.mine_block(vec![anchor], 0x13, 0x23, 3, TEST_BITS);
        let b4 = dag.mine_block(vec![anchor], 0x14, 0x24, 4, TEST_BITS);

        let merge = dag.mine_block(
            vec![b1.block_hash, b2.block_hash, b3.block_hash, b4.block_hash],
            0x30,
            0x40,
            5,
            TEST_BITS,
        );
        // Exactly 3 of the 4 parallel parents are blue; 1 is colored RED!
        assert_eq!(merge.claimed_mergeset_blues.len(), 3);
        // Anchor (5000) + 3 blue parents + merge itself = 5004.
        assert_eq!(merge.claimed_blue_score, 5_004);

        // Extend with parallel confirming blocks above `merge` so blue_depth >= 4.
        let c1 = dag.mine_block(vec![merge.block_hash], 0x31, 0x41, 6, TEST_BITS);
        let c2 = dag.mine_block(vec![merge.block_hash], 0x32, 0x42, 7, TEST_BITS);
        let c3 = dag.mine_block(vec![c1.block_hash, c2.block_hash], 0x33, 0x43, 8, TEST_BITS);
        let tip = dag.mine_block(vec![c3.block_hash], 0x34, 0x44, 9, TEST_BITS);
        assert_eq!(tip.claimed_blue_score - merge.claimed_blue_score, 4);

        let ev = GhostdagEvidence {
            headers: dag.headers.clone(),
            finalized_hash: merge.block_hash,
            tip_hash: tip.block_hash,
        };
        let base = GhostdagPowAdapter::new(NETWORK, Some(pinned));
        let golden = wrap_evidence(&base, &ev, merge.daa_score, merge.utxo_commitment);
        let adapter = base.with_golden(golden.clone());

        let mut facts = CryptoFacts::default();
        let att = adapter
            .verify_observed(&golden, &test_policy(), &mut facts)
            .expect("valid GHOSTDAG proof verifies");
        assert_eq!(att.height, merge.daa_score);
        assert_eq!(att.state_root, merge.utxo_commitment);
        assert_eq!(att.attested_block_hash, Some(merge.block_hash));
        assert_eq!(att.attested_tx_root, Some(merge.accepted_id_merkle_root));
        assert_eq!(att.attested_event_root, None);
        assert!(
            facts.quantum_class() == Some(crate::crypto::facts::QuantumClass::Hash),
            "SHA-256d GHOSTDAG PoW must carry zero Shor-breakable classical assumptions"
        );

        // Full selftest admission across all byte-level fault probes.
        let (report, observed) = admit_observed(&adapter, &test_policy());
        assert!(report.golden_verified);
        let failed: Vec<_> = report.probes.iter().filter(|(_, o)| !o.passed()).collect();
        assert!(failed.is_empty(), "probes failed: {failed:?}");
        assert!(report.admitted);
        assert_eq!(
            observed.quantum_class(),
            Some(crate::crypto::facts::QuantumClass::Hash)
        );
    }

    #[test]
    fn ghostdag_refuses_red_block_forged_as_blue_and_antichain_violation() {
        let pinned = test_anchor(1, 1);
        let mut dag = TestDagBuilder::new(pinned.clone());
        let a = pinned.anchor_hash;
        let b1 = dag.mine_block(vec![a], 0x11, 0x21, 1, TEST_BITS);
        let b2 = dag.mine_block(vec![a], 0x12, 0x22, 2, TEST_BITS);
        let b3 = dag.mine_block(vec![a], 0x13, 0x23, 3, TEST_BITS);
        let merge = dag.mine_block(
            vec![b1.block_hash, b2.block_hash, b3.block_hash],
            0x20,
            0x30,
            4,
            TEST_BITS,
        );
        // k = 1 => only 2 of {b1, b2, b3} can be blue; the 3rd MUST be red.
        assert_eq!(merge.claimed_mergeset_blues.len(), 2);

        // Attacker re-mines `merge` claiming the red 3rd block is also blue.
        let red_hash = [b1.block_hash, b2.block_hash, b3.block_hash]
            .into_iter()
            .find(|h| !merge.claimed_mergeset_blues.contains(h))
            .unwrap();
        let mut forged = merge.clone();
        forged.claimed_mergeset_blues.push(red_hash);
        forged.claimed_blue_score += 1;
        let target = U256::from_compact_bits(TEST_BITS).unwrap();
        forged.nonce = 0;
        loop {
            let h = forged.compute_pow_hash(NETWORK);
            if U256::from_be_bytes(&h) <= target {
                forged.block_hash = h;
                break;
            }
            forged.nonce += 1;
        }
        let mut bad_headers = dag.headers[..3].to_vec();
        bad_headers.push(forged.clone());
        let adapter = GhostdagPowAdapter::new(NETWORK, Some(pinned.clone()));
        let bad_ev = GhostdagEvidence {
            headers: bad_headers,
            finalized_hash: b1.block_hash,
            tip_hash: forged.block_hash,
        };
        let err = adapter
            .verify(
                &wrap_evidence(&adapter, &bad_ev, b1.daa_score, b1.utxo_commitment),
                &test_policy(),
            )
            .expect_err("red block claimed as blue must be rejected");
        assert!(matches!(err, AdapterError::ConsensusRule { .. }), "{err:?}");

        // Direct-parent antichain violation: referencing BOTH `a` and `b1` (where `a in past(b1)`).
        let mut anti_parents = vec![a, b1.block_hash];
        anti_parents.sort_unstable();
        let mut anti = GhostdagHeader {
            block_hash: [0u8; 32],
            parents: anti_parents,
            selected_parent: b1.block_hash,
            accepted_id_merkle_root: [0x51; 32],
            utxo_commitment: [0x61; 32],
            timestamp_secs: pinned.anchor_timestamp_secs + 5,
            bits: TEST_BITS,
            nonce: 0,
            daa_score: b1.daa_score + 1,
            claimed_blue_score: b1.claimed_blue_score + 1,
            claimed_blue_work: [200, 0, 0, 0],
            claimed_mergeset_blues: vec![b1.block_hash],
        };
        loop {
            let h = anti.compute_pow_hash(NETWORK);
            if U256::from_be_bytes(&h) <= target {
                anti.block_hash = h;
                break;
            }
            anti.nonce += 1;
        }
        let anti_ev = GhostdagEvidence {
            headers: vec![b1.clone(), anti.clone()],
            finalized_hash: b1.block_hash,
            tip_hash: anti.block_hash,
        };
        let err = adapter
            .verify(
                &wrap_evidence(&adapter, &anti_ev, b1.daa_score, b1.utxo_commitment),
                &test_policy(),
            )
            .expect_err("non-antichain parent set must be rejected");
        assert!(
            format!("{err:?}").contains("antichain"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn ghostdag_refuses_side_chain_block_non_maximal_tip_and_slashable_policy() {
        let pinned = test_anchor(2, 2);
        let mut dag = TestDagBuilder::new(pinned.clone());
        let a = pinned.anchor_hash;
        // Side block `side` is merged as blue, NOT on selected-parent chain.
        // Give `main1` harder bits so `main1` strictly wins `blue_work` over `side`.
        let harder_bits: u32 = 0x203f_ffff;
        let side = dag.mine_block(vec![a], 0x11, 0x21, 1, TEST_BITS);
        let main1 = dag.mine_block(vec![a], 0x12, 0x22, 2, harder_bits);
        let main2 = dag.mine_block(
            vec![side.block_hash, main1.block_hash],
            0x13,
            0x23,
            3,
            TEST_BITS,
        );
        assert_eq!(main2.selected_parent, main1.block_hash);
        let tip = dag.mine_block(vec![main2.block_hash], 0x14, 0x24, 4, TEST_BITS);

        let adapter = GhostdagPowAdapter::new(NETWORK, Some(pinned));
        let mut policy = test_policy();
        policy.min_depth = 2;

        // `main1` IS on the selected-parent chain and verifies cleanly.
        let ok_ev = GhostdagEvidence {
            headers: dag.headers.clone(),
            finalized_hash: main1.block_hash,
            tip_hash: tip.block_hash,
        };
        let ok_raw = wrap_evidence(&adapter, &ok_ev, main1.daa_score, main1.utxo_commitment);
        let ok_att = adapter
            .verify(&ok_raw, &policy)
            .expect("selected-parent chain block verifies");
        assert_eq!(
            ok_att.evidence_digest,
            ok_raw.digest(),
            "attestation evidence_digest must equal canonical RawConsensusEvidence::digest()"
        );
        crate::domain::finality_proof_model::FinalityProofShape::from_external_attestation(
            &adapter.descriptor(),
            &ok_att,
        )
        .expect("verified GHOSTDAG attestation must satisfy FinalityProofShape");
        match ok_att.security {
            SecurityBacking::Work { difficulty_bits } => {
                assert!(
                    (1..=256).contains(&difficulty_bits),
                    "Work difficulty_bits must be cumulative log2 work in 1..=256, not raw compact nBits ({difficulty_bits})"
                );
            }
            other => panic!("expected Work security backing, got {other:?}"),
        }
        let mut future_policy = policy.clone();
        future_policy.max_age = 3_600;
        future_policy.now = main1.timestamp_secs.saturating_sub(10);
        assert!(
            matches!(
                adapter.verify(&ok_raw, &future_policy),
                Err(AdapterError::Stale { .. })
            ),
            "future-dated block timestamp above policy.now must fail closed when max_age > 0"
        );

        // `side` is NOT on selected-parent chain -> rejected.
        let side_ev = GhostdagEvidence {
            headers: dag.headers.clone(),
            finalized_hash: side.block_hash,
            tip_hash: tip.block_hash,
        };
        assert!(adapter
            .verify(
                &wrap_evidence(&adapter, &side_ev, side.daa_score, side.utxo_commitment),
                &policy,
            )
            .is_err());

        // Non-sink `main2` claimed as tip while `tip` descends from it -> rejected.
        let nonsink_ev = GhostdagEvidence {
            headers: dag.headers,
            finalized_hash: main1.block_hash,
            tip_hash: main2.block_hash,
        };
        assert!(adapter
            .verify(
                &wrap_evidence(
                    &adapter,
                    &nonsink_ev,
                    main1.daa_score,
                    main1.utxo_commitment
                ),
                &policy,
            )
            .is_err());

        // `require_slashable = true` is honestly refused for PoW.
        let mut slash_policy = policy;
        slash_policy.require_slashable = true;
        assert!(matches!(
            adapter.verify(
                &wrap_evidence(&adapter, &ok_ev, main1.daa_score, main1.utxo_commitment),
                &slash_policy,
            ),
            Err(AdapterError::UnslashableBacking)
        ));
    }
}
