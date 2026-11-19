//! Universal Light Proof (`ULP-1`) succinct multi-domain aggregation (`GOREV-21`).
//!
//! Folds `1..=MAX_ULP_DOMAINS` external finality snapshots over 128-bit `BudAir`
//! FRI-STARKs, `StarkBackend` `MasterProof`, and split-STARK PCS verification.
//!
//! WIRING: consumed by [`crate::light_client::LightClient::verify_multi_hop_light_route`]
//! to verify `1..=MAX_ULP_DOMAINS` heterogeneous external domains in one bundle.
//!
//! # Architecture
//!
//! A [`UniversalLightProofBundle`] folds `D` (`1 <= D <= MAX_ULP_DOMAINS`)
//! finalized [`UlpDomainSnapshot`] records committed under a settlement hub
//! checkpoint into:
//!
//! 1. An in-circuit `BudVM` program ([`compile_ulp_program`]) that range-checks
//!    every 32-bit witness limb, enforces strict 64-bit finality height
//!    monotonicity (`prev_height < finalized_height`), positive security weight,
//!    and the 25% (`2_500` bps) per-domain outflow ceiling, and computes both
//!    `input_hash` and `output_hash` inside the `BudAir` trace (`SWrite[0..16]`).
//! 2. A Phase 4 [`Claim::Prog`] proven by a real 128-bit Plonky3 `BudAir` STARK
//!    ([`prove_vm_program`]).
//! 3. A Phase 5 split-STARK [`UlpPcsBundle`] extracted via
//!    [`PcsOpeningObject::from_bud_envelope`]: the heavy FRI + Merkle opening
//!    proof folds off-chain into [`Claim::Poly`], leaving only compact Stage-2
//!    commitments and opened rows ([`VerifyStarkTx`]) evaluated against
//!    [`AirRegistry::with_builtins`] (`BudAirEvaluator`).
//! 4. A single production [`StarkBackend`] `ClaimFrame` (`AggFoldAir` STARK +
//!    ML-DSA-87 segment attestation) aggregating `[Claim::Prog, Claim::Poly]`
//!    alongside index-free `O(log C)` [`ClaimMerkleProof`] witnesses and
//!    `O(log D)` binary Merkle domain inclusion proofs
//!    ([`UlpDomainInclusionProof`]).

use std::collections::BTreeSet;
use std::time::Instant;

use bincode::Options;
use bud_vm::{poseidon4_hash, Vm};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::air_registry::{bud_air_id, AirRegistry, MAX_BUD_AIR_AUX_BYTES};
use super::backend::{AggBackend, AggError, TickCtx};
use super::claim::{Claim, GOLDILOCKS_MODULUS};
use super::envelope::{Envelope, ObjectKind};
use super::frame::{ClaimFrame, FrameLimits};
use super::hash::{h, TAG_ULP_EMPTY, TAG_ULP_INPUT, TAG_ULP_LEAF, TAG_ULP_NODE, TAG_ULP_OUTPUT};
use super::merkle::{claims_root, prove_claim_inclusion, verify_claim_inclusion, ClaimMerkleProof};
use super::object::derive_claim;
use super::params::AggParams;
use super::pool::PoolItem;
use super::programs::agg_merge::{program_hash_of, published_writes_digest_many};
use super::programs::asm::{Asm, Program, Reg, R};
use super::programs::pcs_claim::{BudAirAuxData, PcsOpeningObject, VerifyStarkTx};
use super::programs::prog_claim::{
    prove_vm_program, write_cell, write_digest_cells, ProgClaimError, DIGEST_LIMBS,
    DIGEST_LIMBS_U32,
};
use super::stark::{StarkBackend, STARK_PARAMETER_SET};
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use crate::domain::types::{DomainId, Hash32};
use zeroize::Zeroizing;

/// Maximum number of external domains aggregated inside a single `ULP-1` circuit.
pub const MAX_ULP_DOMAINS: usize = 6;
/// Maximum Merkle path depth accepted for a [`UlpDomainInclusionProof`].
pub const MAX_ULP_MERKLE_DEPTH: usize = 8;
/// Hard per-domain and per-route settlement outflow ceiling in basis points (25%).
pub const MAX_ULP_OUTFLOW_BPS: u16 = 2_500;
/// Canonical 32-bit unsigned limb bitmask enforced inside `BudVM`.
const U32_MASK: u64 = 0xFFFF_FFFF;
/// Gas ceiling allocated to `BudVM` when proving a `ULP-1` guest trace.
const ULP_VM_GAS_LIMIT: u64 = 200_000;

/// Consensus family attested by one external domain leaf inside `ULP-1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UlpDomainKind {
    /// Tendermint / CometBFT instant finality.
    TendermintBft = 1,
    /// Nakamoto proof-of-work cumulative work (`SHA-256d`, hash-only).
    BitcoinSpv = 2,
    /// Ethereum Beacon sync-committee finality.
    EthereumSync = 3,
    /// Narwhal / Bullshark / Mysticeti DAG-BFT finality.
    DagBft = 4,
    /// Constant-size recursive hash-STARK finality (Mina / Samasika lineage).
    SuccinctRecursive = 5,
    /// Proof-of-Space coupled with sequential hash VDF finality (Chia lineage).
    PoSpaceVdf = 6,
}

impl UlpDomainKind {
    /// Canonical numeric code bound into the `ULP-1` leaf hash and `BudAir` trace.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns whether a domain of this consensus family remains sound under an
    /// active CRQC Frost Alarm emergency given whether it carried a verified
    /// post-quantum (`ML-DSA-65` / `ML-DSA-87` / hash-STARK) attestation.
    ///
    /// Pure hash-work (`BitcoinSpv`) retains Grover-halved preimage/work
    /// resistance without elliptic-curve signatures when paired with a PQ relay
    /// binding; `SuccinctRecursive` and `PoSpaceVdf` rely on hash-STARKs /
    /// iterated SHA-256 plus PQ attestation; classical elliptic-curve committee
    /// families (`TendermintBft`, `EthereumSync`, `DagBft`) are accepted under
    /// Frost Alarm ONLY when upgraded with an explicit PQ quorum attestation.
    #[must_use]
    pub const fn is_post_quantum_safe(self, pq_attested: bool) -> bool {
        match self {
            Self::BitcoinSpv
            | Self::SuccinctRecursive
            | Self::PoSpaceVdf
            | Self::TendermintBft
            | Self::EthereumSync
            | Self::DagBft => pq_attested,
        }
    }
}

/// Verified finality snapshot for a single external domain aggregated into `ULP-1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UlpDomainSnapshot {
    /// Settlement domain identifier (unique within a `ULP-1` bundle).
    pub domain_id: DomainId,
    /// External network chain identifier.
    pub external_chain_id: u64,
    /// External consensus family.
    pub kind: UlpDomainKind,
    /// Previously anchored finalized height (`< finalized_height`).
    pub prev_height: u64,
    /// Newly finalized external block height.
    pub finalized_height: u64,
    /// Finalized external state root.
    pub state_root: Hash32,
    /// Finalized external event/receipt root.
    pub event_root: Hash32,
    /// Pinned validator-set, genesis, or difficulty-anchor commitment.
    pub anchor_hash: Hash32,
    /// Positive stake, work, or cumulative space-time security weight.
    pub security_weight: u64,
    /// Whether finality is bound by a verified post-quantum attestation.
    pub pq_attested: bool,
    /// Rolling window outflow utilization in basis points (`0..=2_500`).
    pub outflow_bps: u16,
}

impl UlpDomainSnapshot {
    /// Canonical domain-separated `Keccak-256` leaf digest committed inside
    /// [`UniversalLightProofBundle::domains_merkle_root`].
    #[must_use]
    pub fn leaf_hash(&self) -> Hash32 {
        let flags = [self.kind.code(), u8::from(self.pq_attested)];
        let outflow = self.outflow_bps.to_be_bytes();
        h(&[
            TAG_ULP_LEAF,
            &self.domain_id.to_be_bytes(),
            &self.external_chain_id.to_be_bytes(),
            &flags,
            &self.prev_height.to_be_bytes(),
            &self.finalized_height.to_be_bytes(),
            &self.state_root,
            &self.event_root,
            &self.anchor_hash,
            &self.security_weight.to_be_bytes(),
            &outflow,
        ])
    }

    /// Validates local invariant bounds before proving or verification.
    ///
    /// # Errors
    ///
    /// Returns [`UlpError`] if heights are not strictly increasing, roots are
    /// zero, security weight is zero, or outflow exceeds [`MAX_ULP_OUTFLOW_BPS`].
    pub fn validate(&self) -> Result<(), UlpError> {
        if self.domain_id == 0 {
            return Err(UlpError::InvalidDomain("domain_id cannot be zero"));
        }
        if self.finalized_height <= self.prev_height {
            return Err(UlpError::InvalidDomain(
                "finalized_height must strictly exceed prev_height",
            ));
        }
        if self.state_root == [0u8; 32] || self.anchor_hash == [0u8; 32] {
            return Err(UlpError::InvalidDomain(
                "state_root and anchor_hash must be non-zero",
            ));
        }
        if self.security_weight == 0 {
            return Err(UlpError::InvalidDomain("security_weight must be positive"));
        }
        if self.outflow_bps > MAX_ULP_OUTFLOW_BPS {
            return Err(UlpError::OutflowCeilingExceeded {
                observed_bps: self.outflow_bps,
                ceiling_bps: MAX_ULP_OUTFLOW_BPS,
            });
        }
        Ok(())
    }
}

/// Errors produced during `ULP-1` proving, decoding, or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UlpError {
    /// Domain count outside `1..=MAX_ULP_DOMAINS` or duplicate `domain_id`.
    InvalidDomainSet(&'static str),
    /// A single [`UlpDomainSnapshot`] failed structural/security validation.
    InvalidDomain(&'static str),
    /// Domain or route outflow exceeded the 25% ceiling.
    OutflowCeilingExceeded {
        /// Observed outflow in basis points.
        observed_bps: u16,
        /// Configured ceiling in basis points.
        ceiling_bps: u16,
    },
    /// `BudVM` guest assembly or `BudAir` STARK proving failed.
    ProgramProof(String),
    /// Phase 5 split-STARK PCS extraction or Stage-2 algebra verification failed.
    PcsVerification(String),
    /// `StarkBackend` frame generation or verification failed.
    MasterProof(String),
    /// Bound public header, program hash, or hub checkpoint root mismatch.
    BindingMismatch(&'static str),
    /// Claim or domain Merkle inclusion proof failed.
    InvalidInclusion(&'static str),
}

impl std::fmt::Display for UlpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDomainSet(msg) => write!(f, "ULP-1 invalid domain set: {msg}"),
            Self::InvalidDomain(msg) => write!(f, "ULP-1 invalid domain snapshot: {msg}"),
            Self::OutflowCeilingExceeded {
                observed_bps,
                ceiling_bps,
            } => write!(
                f,
                "ULP-1 outflow {observed_bps} bps exceeds ceiling {ceiling_bps} bps"
            ),
            Self::ProgramProof(msg) => write!(f, "ULP-1 BudAir proof failed: {msg}"),
            Self::PcsVerification(msg) => write!(f, "ULP-1 split-STARK PCS failed: {msg}"),
            Self::MasterProof(msg) => write!(f, "ULP-1 MasterProof failed: {msg}"),
            Self::BindingMismatch(msg) => write!(f, "ULP-1 binding mismatch: {msg}"),
            Self::InvalidInclusion(msg) => write!(f, "ULP-1 inclusion proof invalid: {msg}"),
        }
    }
}

impl std::error::Error for UlpError {}

/// Single sibling step of an `O(log D)` [`UlpDomainInclusionProof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UlpMerkleStep {
    /// Sibling node digest at this level.
    pub sibling: Hash32,
    /// `true` when `sibling` is the left child (`H(TAG_ULP_NODE, sibling, cur)`).
    pub sibling_is_left: bool,
}

/// Succinct `O(log D)` inclusion proof for one [`UlpDomainSnapshot`] under
/// [`UniversalLightProofBundle::domains_merkle_root`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UlpDomainInclusionProof {
    steps: Vec<UlpMerkleStep>,
}

impl UlpDomainInclusionProof {
    /// Number of sibling hashes in this inclusion path (`ceil(log2(D))`).
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.steps.len()
    }

    /// Serialized proof footprint in bytes (`33 * depth`).
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.steps.len().saturating_mul(33)
    }

    /// Verifies that `snapshot` is committed inside `expected_root` in `O(log D)`
    /// hashes, checking snapshot invariants and rejecting over-deep paths.
    ///
    /// # Errors
    ///
    /// Returns [`UlpError`] if `snapshot` fails validation, the proof exceeds
    /// [`MAX_ULP_MERKLE_DEPTH`], or the folded root does not equal `expected_root`.
    pub fn verify(
        &self,
        snapshot: &UlpDomainSnapshot,
        expected_root: &Hash32,
    ) -> Result<(), UlpError> {
        snapshot.validate()?;
        if self.steps.len() > MAX_ULP_MERKLE_DEPTH {
            return Err(UlpError::InvalidInclusion(
                "domain Merkle proof exceeds MAX_ULP_MERKLE_DEPTH",
            ));
        }
        let mut cur = snapshot.leaf_hash();
        for step in &self.steps {
            cur = if step.sibling_is_left {
                ulp_node_hash(&step.sibling, &cur)
            } else {
                ulp_node_hash(&cur, &step.sibling)
            };
        }
        if bool::from(cur.ct_eq(expected_root)) {
            Ok(())
        } else {
            Err(UlpError::InvalidInclusion(
                "domain leaf Merkle path does not match domains_merkle_root",
            ))
        }
    }
}

#[must_use]
fn ulp_node_hash(left: &Hash32, right: &Hash32) -> Hash32 {
    h(&[TAG_ULP_NODE, left, right])
}

/// Computes the canonical `ULP-1` binary Merkle root over domain snapshots
/// sorted canonically by `domain_id`.
#[must_use]
pub fn ulp_domains_root(snapshots: &[UlpDomainSnapshot]) -> Hash32 {
    if snapshots.is_empty() {
        return h(&[TAG_ULP_EMPTY]);
    }
    let mut level: Vec<Hash32> = snapshots.iter().map(UlpDomainSnapshot::leaf_hash).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [l, r] => next.push(ulp_node_hash(l, r)),
                [only] => next.push(*only),
                _ => {}
            }
        }
        level = next;
    }
    level
        .first()
        .copied()
        .unwrap_or_else(|| h(&[TAG_ULP_EMPTY]))
}

/// Builds an `O(log D)` [`UlpDomainInclusionProof`] for `target_domain_id`
/// against a slice of domain snapshots.
#[must_use]
pub fn prove_ulp_domain_inclusion(
    snapshots: &[UlpDomainSnapshot],
    target_domain_id: DomainId,
) -> Option<UlpDomainInclusionProof> {
    let mut pos = snapshots
        .iter()
        .position(|s| s.domain_id == target_domain_id)?;
    let mut level: Vec<Hash32> = snapshots.iter().map(UlpDomainSnapshot::leaf_hash).collect();
    let mut steps = Vec::new();
    while level.len() > 1 {
        let base = pos & !1;
        if pos & 1 == 1 {
            let left = *level.get(base)?;
            steps.push(UlpMerkleStep {
                sibling: left,
                sibling_is_left: true,
            });
        } else if let Some(&right) = level.get(base + 1) {
            steps.push(UlpMerkleStep {
                sibling: right,
                sibling_is_left: false,
            });
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            match pair {
                [l, r] => next.push(ulp_node_hash(l, r)),
                [only] => next.push(*only),
                _ => {}
            }
        }
        level = next;
        pos /= 2;
    }
    Some(UlpDomainInclusionProof { steps })
}

#[must_use]
fn tag_seeds(tag: &[u8]) -> (u64, u64, u64) {
    let digest = h(&[tag]);
    let word = |start: usize| -> u64 {
        let mut bytes = [0u8; 8];
        if let Some(slice) = digest.get(start..start + 8) {
            bytes.copy_from_slice(slice);
        }
        u64::from_le_bytes(bytes) % GOLDILOCKS_MODULUS
    };
    (word(0), word(8), word(16))
}

#[must_use]
const fn split_u64_limbs(value: u64) -> [u64; 2] {
    [value & U32_MASK, value >> 32]
}

#[must_use]
fn digest_limbs(digest: &Hash32) -> [u64; DIGEST_LIMBS] {
    let mut out = [0u64; DIGEST_LIMBS];
    for (slot, chunk) in out.iter_mut().zip(digest.chunks_exact(4)) {
        if let [b0, b1, b2, b3] = *chunk {
            *slot = u64::from(u32::from_le_bytes([b0, b1, b2, b3]));
        }
    }
    out
}

#[must_use]
fn poseidon_sponge_256(tag: &[u8], limbs: &[u64]) -> Hash32 {
    let (seed_a, seed_b, squeeze_base) = tag_seeds(tag);
    let mut acc_a = seed_a;
    for &limb in limbs {
        acc_a = poseidon4_hash(acc_a, limb);
    }
    let mut acc_b = seed_b;
    for &limb in limbs.iter().rev() {
        acc_b = poseidon4_hash(acc_b, limb);
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
        let domain_i = squeeze_base.wrapping_add(i as u64) % GOLDILOCKS_MODULUS;
        let mixed = poseidon4_hash(poseidon4_hash(acc_a, domain_i), acc_b);
        let limb32 = (mixed & U32_MASK) as u32;
        chunk.copy_from_slice(&limb32.to_le_bytes());
    }
    out
}

/// Computes the canonical in-circuit `ULP-1` `input_hash` binding the settlement
/// hub anchor and every aggregated domain's pre-state anchor.
#[must_use]
pub fn ulp_input_hash(
    hub_chain_id: DomainId,
    settlement_epoch: u64,
    hub_checkpoint_root: &Hash32,
    snapshots: &[UlpDomainSnapshot],
) -> Hash32 {
    let epoch = split_u64_limbs(settlement_epoch);
    let mut limbs = Vec::with_capacity(4 + DIGEST_LIMBS + snapshots.len() * 5);
    limbs.push(u64::from(hub_chain_id));
    limbs.extend_from_slice(&epoch);
    limbs.push(snapshots.len() as u64);
    limbs.extend_from_slice(&digest_limbs(hub_checkpoint_root));
    for snap in snapshots {
        limbs.push(u64::from(snap.domain_id));
        limbs.extend_from_slice(&split_u64_limbs(snap.external_chain_id));
        limbs.extend_from_slice(&split_u64_limbs(snap.prev_height));
    }
    poseidon_sponge_256(TAG_ULP_INPUT, &limbs)
}

/// Computes the canonical in-circuit `ULP-1` `output_hash` binding the
/// multi-domain Merkle root, per-domain finalized heights and roots, minimum
/// post-quantum flag, and maximum outflow utilization.
#[must_use]
pub fn ulp_output_hash(
    hub_chain_id: DomainId,
    settlement_epoch: u64,
    domains_merkle_root: &Hash32,
    all_pq_attested: bool,
    max_outflow_bps: u16,
    snapshots: &[UlpDomainSnapshot],
) -> Hash32 {
    let epoch = split_u64_limbs(settlement_epoch);
    let mut limbs = Vec::with_capacity(6 + DIGEST_LIMBS + snapshots.len() * (6 + DIGEST_LIMBS));
    limbs.push(u64::from(hub_chain_id));
    limbs.extend_from_slice(&epoch);
    limbs.push(snapshots.len() as u64);
    limbs.push(u64::from(all_pq_attested));
    limbs.push(u64::from(max_outflow_bps));
    limbs.extend_from_slice(&digest_limbs(domains_merkle_root));
    for snap in snapshots {
        limbs.push(u64::from(snap.domain_id));
        limbs.extend_from_slice(&split_u64_limbs(snap.finalized_height));
        limbs.extend_from_slice(&split_u64_limbs(snap.security_weight));
        limbs.push(u64::from(snap.outflow_bps));
        limbs.push(u64::from(snap.pq_attested));
        limbs.extend_from_slice(&digest_limbs(&snap.state_root));
    }
    poseidon_sponge_256(TAG_ULP_OUTPUT, &limbs)
}

#[derive(Clone, Copy)]
enum LimbSource {
    Const(u64),
    Cell(u64),
}

fn emit_load_source(a: &mut Asm, dst: Reg, src: LimbSource) {
    match src {
        LimbSource::Const(v) => a.li(dst, v),
        LimbSource::Cell(cell) => a.load_abs(dst, cell),
    }
}

fn emit_dual_poseidon_swrite(a: &mut Asm, tag: &[u8], sources: &[LimbSource], start_slot: u32) {
    let (seed_a, seed_b, squeeze_base) = tag_seeds(tag);
    a.li(R[10], seed_a);
    for &src in sources {
        emit_load_source(a, R[1], src);
        a.poseidon(R[10], R[10], R[1]);
    }
    a.li(R[11], seed_b);
    for &src in sources.iter().rev() {
        emit_load_source(a, R[1], src);
        a.poseidon(R[11], R[11], R[1]);
    }
    a.li(R[12], U32_MASK);
    for i in 0..DIGEST_LIMBS_U32 {
        let domain_i = squeeze_base.wrapping_add(u64::from(i)) % GOLDILOCKS_MODULUS;
        a.li(R[1], domain_i);
        a.poseidon(R[2], R[10], R[1]);
        a.poseidon(R[2], R[2], R[11]);
        a.and(R[2], R[2], R[12]);
        a.swrite(start_slot + i, R[2]);
    }
}

fn push_cells(out: &mut Vec<LimbSource>, base: u64, count: usize) {
    for i in 0..count as u64 {
        out.push(LimbSource::Cell(base + i));
    }
}

#[derive(Debug, Clone, Copy)]
struct DomainCells {
    domain_id: u64,
    ext_chain_id: u64,
    prev_height: u64,
    finalized_height: u64,
    security_weight: u64,
    outflow_bps: u64,
    pq_flag: u64,
    state_root: u64,
}

#[derive(Debug, Clone)]
struct UlpCells {
    first_cell: u64,
    total_cells: u64,
    epoch: u64,
    hub_checkpoint_root: u64,
    domains_merkle_root: u64,
    all_pq_flag: u64,
    max_outflow_bps: u64,
    domains: Vec<DomainCells>,
}

/// Compiled `BudVM` `ULP-1` aggregation circuit for `(hub_chain_id, domain_count)`.
#[derive(Debug, Clone)]
pub struct UlpProgram {
    /// Compiled `BudVM` bytecode words.
    pub program: Program,
    /// Canonical `Keccak-256` hash of `program.code`.
    pub program_hash: Hash32,
    /// Settlement hub chain identifier baked into the bytecode.
    pub hub_chain_id: DomainId,
    /// Exact number of external domains constrained by this circuit (`1..=6`).
    pub domain_count: usize,
    cells: UlpCells,
}

/// Compiles the canonical `ULP-1` `BudVM` verifier circuit for `hub_chain_id`
/// and `domain_count` external consensus domains (`1..=MAX_ULP_DOMAINS`).
///
/// # Errors
///
/// Returns [`UlpError`] if `domain_count` is outside `1..=MAX_ULP_DOMAINS` or
/// `BudVM` assembly fails.
pub fn compile_ulp_program(
    hub_chain_id: DomainId,
    domain_count: usize,
) -> Result<UlpProgram, UlpError> {
    if domain_count == 0 || domain_count > MAX_ULP_DOMAINS {
        return Err(UlpError::InvalidDomainSet(
            "domain_count must be within 1..=MAX_ULP_DOMAINS",
        ));
    }
    let mut a = Asm::new();
    let epoch = a.alloc(2);
    let hub_checkpoint_root = a.alloc(DIGEST_LIMBS as u64);
    let domains_merkle_root = a.alloc(DIGEST_LIMBS as u64);
    let all_pq_flag = a.alloc(1);
    let max_outflow_bps = a.alloc(1);
    let mut domains = Vec::with_capacity(domain_count);
    for _ in 0..domain_count {
        domains.push(DomainCells {
            domain_id: a.alloc(1),
            ext_chain_id: a.alloc(2),
            prev_height: a.alloc(2),
            finalized_height: a.alloc(2),
            security_weight: a.alloc(2),
            outflow_bps: a.alloc(1),
            pq_flag: a.alloc(1),
            state_root: a.alloc(DIGEST_LIMBS as u64),
        });
    }
    let end_cell = a.alloc(0);
    let total_cells = end_cell.saturating_sub(epoch);

    // 1. Canonical 32-bit range check on every witness cell.
    a.li(R[12], U32_MASK);
    for offset in 0..total_cells {
        a.load_abs(R[1], epoch + offset);
        a.and(R[2], R[1], R[12]);
        a.eq(R[3], R[1], R[2]);
        a.assert(R[3]);
    }

    // 2. Per-domain invariants + aggregate all_pq_flag (R[8]) and max_outflow_bps (R[9]).
    a.li(R[8], 1);
    a.li(R[9], 0);
    a.li(R[13], u64::from(MAX_ULP_OUTFLOW_BPS) + 1);
    a.li(R[14], 1u64 << 32);
    let mut prev_domain_id_reg_set = false;
    for dc in &domains {
        // Strictly ascending non-zero domain_id prevents duplicate domains in-circuit.
        a.load_abs(R[1], dc.domain_id);
        a.li(R[2], 0);
        a.lt(R[3], R[2], R[1]);
        a.assert(R[3]);
        if prev_domain_id_reg_set {
            a.lt(R[3], R[7], R[1]);
            a.assert(R[3]);
        }
        a.mov(R[7], R[1]);
        prev_domain_id_reg_set = true;

        // Reconstruct full 64-bit prev_height < finalized_height (safe since limbs < 2^32).
        a.load_abs(R[1], dc.prev_height);
        a.load_abs(R[2], dc.prev_height + 1);
        a.mul(R[2], R[2], R[14]);
        a.add(R[1], R[1], R[2]);

        a.load_abs(R[3], dc.finalized_height);
        a.load_abs(R[4], dc.finalized_height + 1);
        a.mul(R[4], R[4], R[14]);
        a.add(R[3], R[3], R[4]);

        a.lt(R[5], R[1], R[3]);
        a.assert(R[5]);

        // Positive 64-bit security_weight > 0 (since both limbs < 2^32, lo + hi > 0 iff weight > 0).
        a.load_abs(R[1], dc.security_weight);
        a.load_abs(R[2], dc.security_weight + 1);
        a.add(R[3], R[1], R[2]);
        a.li(R[4], 0);
        a.lt(R[5], R[4], R[3]);
        a.assert(R[5]);

        // Outflow ceiling: outflow_bps <= MAX_ULP_OUTFLOW_BPS (i.e. < MAX + 1).
        a.load_abs(R[1], dc.outflow_bps);
        a.lt(R[5], R[1], R[13]);
        a.assert(R[5]);
        // Update running max_outflow_bps in R[9]: assert witnessed max >= outflow_bps.
        a.load_abs(R[2], max_outflow_bps);
        a.li(R[4], 1);
        a.add(R[2], R[2], R[4]);
        a.lt(R[5], R[1], R[2]);
        a.assert(R[5]);

        // Boolean pq_flag in {0, 1} and all_pq_flag &= pq_flag.
        a.load_abs(R[1], dc.pq_flag);
        a.li(R[2], 2);
        a.lt(R[5], R[1], R[2]);
        a.assert(R[5]);
        a.and(R[8], R[8], R[1]);
    }

    // Bind aggregate all_pq_flag exactly and bound max_outflow_bps <= MAX_ULP_OUTFLOW_BPS.
    a.load_abs(R[1], all_pq_flag);
    a.eq(R[5], R[1], R[8]);
    a.assert(R[5]);
    a.load_abs(R[1], max_outflow_bps);
    a.lt(R[5], R[1], R[13]);
    a.assert(R[5]);

    // 3. Compute and publish input_hash to SWrite[0..8].
    let mut in_sources = Vec::with_capacity(4 + DIGEST_LIMBS + domain_count * 5);
    in_sources.push(LimbSource::Const(u64::from(hub_chain_id)));
    push_cells(&mut in_sources, epoch, 2);
    in_sources.push(LimbSource::Const(domain_count as u64));
    push_cells(&mut in_sources, hub_checkpoint_root, DIGEST_LIMBS);
    for dc in &domains {
        in_sources.push(LimbSource::Cell(dc.domain_id));
        push_cells(&mut in_sources, dc.ext_chain_id, 2);
        push_cells(&mut in_sources, dc.prev_height, 2);
    }
    emit_dual_poseidon_swrite(&mut a, TAG_ULP_INPUT, &in_sources, 0);

    // 4. Compute and publish output_hash to SWrite[8..16].
    let mut out_sources = Vec::with_capacity(6 + DIGEST_LIMBS + domain_count * (7 + DIGEST_LIMBS));
    out_sources.push(LimbSource::Const(u64::from(hub_chain_id)));
    push_cells(&mut out_sources, epoch, 2);
    out_sources.push(LimbSource::Const(domain_count as u64));
    out_sources.push(LimbSource::Cell(all_pq_flag));
    out_sources.push(LimbSource::Cell(max_outflow_bps));
    push_cells(&mut out_sources, domains_merkle_root, DIGEST_LIMBS);
    for dc in &domains {
        out_sources.push(LimbSource::Cell(dc.domain_id));
        push_cells(&mut out_sources, dc.finalized_height, 2);
        push_cells(&mut out_sources, dc.security_weight, 2);
        out_sources.push(LimbSource::Cell(dc.outflow_bps));
        out_sources.push(LimbSource::Cell(dc.pq_flag));
        push_cells(&mut out_sources, dc.state_root, DIGEST_LIMBS);
    }
    emit_dual_poseidon_swrite(&mut a, TAG_ULP_OUTPUT, &out_sources, DIGEST_LIMBS_U32);
    a.halt();

    let program = a
        .finish()
        .map_err(|e| UlpError::ProgramProof(e.to_string()))?;
    let program_hash = program_hash_of(&program.code);
    Ok(UlpProgram {
        program,
        program_hash,
        hub_chain_id,
        domain_count,
        cells: UlpCells {
            first_cell: epoch,
            total_cells,
            epoch,
            hub_checkpoint_root,
            domains_merkle_root,
            all_pq_flag,
            max_outflow_bps,
            domains,
        },
    })
}

fn write_u64_cells(vm: &mut Vm, base: u64, value: u64) {
    let [lo, hi] = split_u64_limbs(value);
    write_cell(vm, base, lo);
    write_cell(vm, base + 1, hi);
}

/// Compact Phase 5 split-STARK witness carried in [`UniversalLightProofBundle`].
///
/// The heavy FRI + Merkle opening proof is omitted: Stage 1 ran once inside the
/// aggregator and folded into `poly_claim`, while Stage 2 runs directly on
/// `statement` via [`AirRegistry::with_builtins`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlpPcsBundle {
    /// Lightweight commitments, public inputs, and opened trace/quotient rows.
    pub statement: VerifyStarkTx,
    /// Derived `Claim::Poly` included in `master_frame`.
    pub poly_claim: Claim,
    /// Index-free `O(log C)` Merkle inclusion of `poly_claim` in `master_frame`.
    pub poly_claim_inclusion: ClaimMerkleProof,
}

/// Succinct `ULP-1` multi-domain light-client proof bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniversalLightProofBundle {
    /// Compiled `ULP-1` guest program hash.
    pub program_hash: Hash32,
    /// Settlement hub chain identifier.
    pub hub_chain_id: DomainId,
    /// Settlement checkpoint epoch.
    pub settlement_epoch: u64,
    /// Finalized `GlobalBlockHeader` hash of the settlement hub checkpoint.
    pub hub_checkpoint_root: Hash32,
    /// Number of aggregated domains (`1..=MAX_ULP_DOMAINS`).
    pub domain_count: u32,
    /// Canonical Merkle root over all sorted [`UlpDomainSnapshot`] leaves.
    pub domains_merkle_root: Hash32,
    /// Saturating sum of verified security weights across all domains.
    pub total_security_weight: u64,
    /// `true` iff every aggregated domain carried a verified PQ attestation.
    pub all_pq_attested: bool,
    /// Maximum per-domain outflow in basis points (`<= MAX_ULP_OUTFLOW_BPS`).
    pub max_outflow_bps: u16,
    /// In-circuit Poseidon256 `input_hash` of `Claim::Prog`.
    pub input_hash: Hash32,
    /// In-circuit Poseidon256 `output_hash` of `Claim::Prog`.
    pub output_hash: Hash32,
    /// Merkle root of `master_frame.claims` for `O(log C)` claim-inclusion checks.
    pub claims_merkle_root: Hash32,
    /// Index-free `O(log C)` inclusion of `Claim::Prog` inside `claims_merkle_root`.
    pub prog_claim_inclusion: ClaimMerkleProof,
    /// Phase 5 split-STARK Stage-2 statement and `Claim::Poly` inclusion witness.
    pub pcs_bundle: UlpPcsBundle,
    /// Production `StarkBackend` `MasterProof` covering `Claim::Prog` + `Claim::Poly`.
    pub master_frame: ClaimFrame,
}

/// Measured proof sizes and latencies returned alongside a proven `ULP-1` bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UlpMetrics {
    /// Number of external domains folded into the proof.
    pub domain_count: usize,
    /// Wall-clock proving latency (guest + `BudAir` + split-STARK + `MasterProof`) in ms.
    pub prove_ms: u128,
    /// Compressed Phase 4 `StarkProofObject` size in bytes (full FRI proof).
    pub stark_object_bytes: usize,
    /// Off-chain Phase 5 `PcsOpeningObject` size in bytes (absorbed by aggregator).
    pub pcs_object_bytes: usize,
    /// On-chain / light-client Phase 5 `VerifyStarkTx` size in bytes (no FRI proof).
    pub verify_stark_tx_bytes: usize,
    /// Wire-encoded `StarkBackend` `ClaimFrame` (`MasterProof`) size in bytes.
    pub master_frame_bytes: usize,
    /// `BudVM` trace step count before power-of-two padding.
    pub vm_trace_steps: usize,
}

/// Verified header extracted after [`verify_universal_light_proof`] succeeds.
///
/// Subsequent per-domain inclusion checks run against `domains_merkle_root` in
/// strictly `O(log D)` hashes with zero further STARK verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedUlpHeader {
    /// Settlement hub chain identifier.
    pub hub_chain_id: DomainId,
    /// Settlement checkpoint epoch.
    pub settlement_epoch: u64,
    /// Finalized hub `GlobalBlockHeader` digest bound into `input_hash`.
    pub hub_checkpoint_root: Hash32,
    /// Verified root over all `domain_count` external domain leaves.
    pub domains_merkle_root: Hash32,
    /// Number of external domains aggregated.
    pub domain_count: u32,
    /// Aggregate security weight across all aggregated domains.
    pub total_security_weight: u64,
    /// Whether every domain in the bundle is PQ-attested.
    pub all_pq_attested: bool,
    /// Maximum per-domain outflow observed in basis points.
    pub max_outflow_bps: u16,
}

/// Canonicalizes, sorts by `domain_id`, and validates a slice of domain snapshots.
///
/// # Errors
///
/// Returns [`UlpError`] if empty, larger than [`MAX_ULP_DOMAINS`], containing
/// duplicate `domain_id` values, or failing per-domain validation.
pub fn canonicalize_ulp_domains(
    snapshots: &[UlpDomainSnapshot],
) -> Result<Vec<UlpDomainSnapshot>, UlpError> {
    if snapshots.is_empty() || snapshots.len() > MAX_ULP_DOMAINS {
        return Err(UlpError::InvalidDomainSet(
            "ULP-1 requires between 1 and MAX_ULP_DOMAINS snapshots",
        ));
    }
    let mut sorted = snapshots.to_vec();
    sorted.sort_by_key(|s| s.domain_id);
    let mut seen = BTreeSet::new();
    for snap in &sorted {
        snap.validate()?;
        if !seen.insert(snap.domain_id) {
            return Err(UlpError::InvalidDomainSet(
                "duplicate domain_id in ULP-1 bundle",
            ));
        }
    }
    Ok(sorted)
}

/// Proves a full `ULP-1` bundle over `1..=MAX_ULP_DOMAINS` finalized external
/// domain snapshots, producing:
/// - a real 128-bit `BudAir` FRI-STARK `Claim::Prog`,
/// - a real Phase 5 split-STARK `UlpPcsBundle` (`Claim::Poly` + `VerifyStarkTx`),
/// - a production `StarkBackend` `MasterProof` (`ClaimFrame`) with `O(log C)`
///   inclusion proofs, and
/// - sorted canonical domain snapshots ready for [`prove_ulp_domain_inclusion`].
///
/// Convenience: kept for the CLI and `ULP-1` relayer prover pipeline.
///
/// # Errors
///
/// Returns [`UlpError`] if any snapshot invariant fails, `BudAir` proving fails,
/// PCS extraction fails, or `StarkBackend` tick aggregation fails.
pub fn prove_universal_light_proof(
    compiled: &UlpProgram,
    settlement_epoch: u64,
    hub_checkpoint_root: Hash32,
    snapshots: &[UlpDomainSnapshot],
    aggregator_seed: &Hash32,
    tick_number: u64,
    registry: &SchemeStatusRegistry,
) -> Result<
    (
        UniversalLightProofBundle,
        Vec<UlpDomainSnapshot>,
        UlpMetrics,
    ),
    UlpError,
> {
    let started = Instant::now();
    if hub_checkpoint_root == [0u8; 32] {
        return Err(UlpError::BindingMismatch(
            "hub_checkpoint_root cannot be zero",
        ));
    }
    let sorted = canonicalize_ulp_domains(snapshots)?;
    if sorted.len() != compiled.domain_count {
        return Err(UlpError::InvalidDomainSet(
            "snapshot count does not match compiled UlpProgram domain_count",
        ));
    }

    let domains_merkle_root = ulp_domains_root(&sorted);
    let all_pq_attested = sorted.iter().all(|s| s.pq_attested);
    let max_outflow_bps = sorted.iter().map(|s| s.outflow_bps).max().unwrap_or(0);
    let total_security_weight = sorted
        .iter()
        .fold(0u64, |acc, s| acc.saturating_add(s.security_weight));

    let input_hash = ulp_input_hash(
        compiled.hub_chain_id,
        settlement_epoch,
        &hub_checkpoint_root,
        &sorted,
    );
    let output_hash = ulp_output_hash(
        compiled.hub_chain_id,
        settlement_epoch,
        &domains_merkle_root,
        all_pq_attested,
        max_outflow_bps,
        &sorted,
    );

    // Populate witness cells and prove real 128-bit BudAir FRI-STARK.
    let mut vm = Vm::new(usize::try_from(ULP_VM_GAS_LIMIT).unwrap_or(usize::MAX));
    let _ = compiled.cells.first_cell;
    let _ = compiled.cells.total_cells;
    write_u64_cells(&mut vm, compiled.cells.epoch, settlement_epoch);
    write_digest_cells(
        &mut vm,
        compiled.cells.hub_checkpoint_root,
        &hub_checkpoint_root,
    );
    write_digest_cells(
        &mut vm,
        compiled.cells.domains_merkle_root,
        &domains_merkle_root,
    );
    write_cell(
        &mut vm,
        compiled.cells.all_pq_flag,
        u64::from(all_pq_attested),
    );
    write_cell(
        &mut vm,
        compiled.cells.max_outflow_bps,
        u64::from(max_outflow_bps),
    );
    for (dc, snap) in compiled.cells.domains.iter().zip(sorted.iter()) {
        write_cell(&mut vm, dc.domain_id, u64::from(snap.domain_id));
        write_u64_cells(&mut vm, dc.ext_chain_id, snap.external_chain_id);
        write_u64_cells(&mut vm, dc.prev_height, snap.prev_height);
        write_u64_cells(&mut vm, dc.finalized_height, snap.finalized_height);
        write_u64_cells(&mut vm, dc.security_weight, snap.security_weight);
        write_cell(&mut vm, dc.outflow_bps, u64::from(snap.outflow_bps));
        write_cell(&mut vm, dc.pq_flag, u64::from(snap.pq_attested));
        write_digest_cells(&mut vm, dc.state_root, &snap.state_root);
    }

    let stark_obj = prove_vm_program(
        &compiled.program.code,
        &mut vm,
        input_hash,
        output_hash,
        compiled.hub_chain_id,
    )
    .map_err(|e: ProgClaimError| UlpError::ProgramProof(e.to_string()))?;
    let vm_trace_steps = vm.trace.len();
    let stark_payload = stark_obj
        .encode()
        .map_err(|e| UlpError::ProgramProof(e.to_string()))?;
    let stark_object_bytes = stark_payload.len();

    // Extract Phase 5 split-STARK PCS opening and lightweight VerifyStarkTx.
    let pcs_obj = PcsOpeningObject::from_bud_envelope(
        &stark_obj.proof_envelope,
        &stark_obj.program,
        &stark_obj.public_inputs,
    )
    .map_err(|e| UlpError::PcsVerification(format!("from_bud_envelope: {e:?}")))?;
    let pcs_payload = pcs_obj
        .encode()
        .map_err(|e| UlpError::PcsVerification(format!("pcs encode: {e:?}")))?;
    let pcs_object_bytes = pcs_payload.len();

    let aux = BudAirAuxData {
        program: stark_obj.program.clone(),
        expected_inputs: stark_obj.public_inputs,
    };
    let aux_bytes = bincode::DefaultOptions::new()
        .with_limit(MAX_BUD_AIR_AUX_BYTES)
        .serialize(&aux)
        .map_err(|e| UlpError::PcsVerification(format!("aux encode: {e}")))?;
    let statement = pcs_obj.to_verify_stark_tx(bud_air_id(), aux_bytes);
    let verify_stark_tx_bytes = bincode::DefaultOptions::new()
        .with_limit(MAX_BUD_AIR_AUX_BYTES * 2)
        .serialize(&statement)
        .map_or(0, |b| b.len());

    let anchor_tx_hash = h(&[
        TAG_ULP_OUTPUT,
        &compiled.hub_chain_id.to_be_bytes(),
        &settlement_epoch.to_be_bytes(),
        &hub_checkpoint_root,
        &domains_merkle_root,
    ]);
    let prog_env = Envelope {
        domain: compiled.hub_chain_id,
        tx_hash: anchor_tx_hash,
        kind: ObjectKind::StarkProof,
        scheme: SchemeId(0),
        payload: stark_payload,
    };
    let pcs_env = Envelope {
        domain: compiled.hub_chain_id,
        tx_hash: anchor_tx_hash,
        kind: ObjectKind::PcsOpening,
        scheme: SchemeId(0),
        payload: pcs_payload,
    };
    let prog_claim = derive_claim(registry, &prog_env)
        .map_err(|e| UlpError::ProgramProof(format!("derive Claim::Prog: {e:?}")))?;
    let poly_claim = derive_claim(registry, &pcs_env)
        .map_err(|e| UlpError::PcsVerification(format!("derive Claim::Poly: {e:?}")))?;

    let _ = tick_number;
    let items = vec![
        PoolItem {
            envelope: prog_env,
            claim: prog_claim.clone(),
        },
        PoolItem {
            envelope: pcs_env,
            claim: poly_claim.clone(),
        },
    ];

    let default_params = AggParams::default();
    let backend = StarkBackend::new(
        registry.clone(),
        FrameLimits::from(&default_params),
        STARK_PARAMETER_SET,
    );
    let ctx = TickCtx::from_seed(compiled.hub_chain_id, Zeroizing::new(*aggregator_seed))
        .map_err(|e| UlpError::MasterProof(format!("TickCtx::from_seed: {e}")))?;
    let master_frame = backend
        .prove_tick(&ctx, &items)
        .map_err(|e: AggError| UlpError::MasterProof(e.to_string()))?;
    let master_frame_bytes = master_frame.encode().len();

    let claim_digests: Vec<Hash32> = master_frame
        .claims
        .iter()
        .map(|c| c.digest(compiled.hub_chain_id))
        .collect();
    let claims_merkle_root = claims_root(&claim_digests)
        .map_err(|_| UlpError::InvalidInclusion("empty claims in MasterProof"))?;
    let prog_digest = prog_claim.digest(compiled.hub_chain_id);
    let poly_digest = poly_claim.digest(compiled.hub_chain_id);
    let prog_idx = claim_digests
        .iter()
        .position(|d| *d == prog_digest)
        .ok_or(UlpError::InvalidInclusion("missing Claim::Prog in frame"))?;
    let poly_idx = claim_digests
        .iter()
        .position(|d| *d == poly_digest)
        .ok_or(UlpError::InvalidInclusion("missing Claim::Poly in frame"))?;
    let prog_claim_inclusion = prove_claim_inclusion(&claim_digests, prog_idx)
        .map_err(|_| UlpError::InvalidInclusion("failed proving Claim::Prog inclusion"))?;
    let poly_claim_inclusion = prove_claim_inclusion(&claim_digests, poly_idx)
        .map_err(|_| UlpError::InvalidInclusion("failed proving Claim::Poly inclusion"))?;

    let domain_count = u32::try_from(sorted.len())
        .map_err(|_| UlpError::InvalidDomainSet("domain_count overflow"))?;
    let prove_ms = started.elapsed().as_millis();

    let bundle = UniversalLightProofBundle {
        program_hash: compiled.program_hash,
        hub_chain_id: compiled.hub_chain_id,
        settlement_epoch,
        hub_checkpoint_root,
        domain_count,
        domains_merkle_root,
        total_security_weight,
        all_pq_attested,
        max_outflow_bps,
        input_hash,
        output_hash,
        claims_merkle_root,
        prog_claim_inclusion,
        pcs_bundle: UlpPcsBundle {
            statement,
            poly_claim,
            poly_claim_inclusion,
        },
        master_frame,
    };
    let metrics = UlpMetrics {
        domain_count: sorted.len(),
        prove_ms,
        stark_object_bytes,
        pcs_object_bytes,
        verify_stark_tx_bytes,
        master_frame_bytes,
        vm_trace_steps,
    };
    Ok((bundle, sorted, metrics))
}

/// Opens and cryptographically verifies a [`UniversalLightProofBundle`] against
/// the pinned `ULP-1` program hash, settlement hub chain id, and finalized hub
/// checkpoint root.
///
/// Checks:
/// 1. Domain count bounds (`1..=MAX_ULP_DOMAINS`), 25% outflow ceiling, and
///    constant-time binding to `expected_program_hash`, `expected_hub_chain_id`,
///    and `expected_hub_checkpoint_root`.
/// 2. Production [`StarkBackend::verify`] on `bundle.master_frame` (128-bit
///    `AggFoldAir` STARK + ML-DSA-87 segment attestation).
/// 3. `O(log C)` Merkle inclusion of both `Claim::Prog` and `Claim::Poly`
///    inside `bundle.claims_merkle_root == claims_root(master_frame.claims)`.
/// 4. Phase 5 Stage-2 `BudAirEvaluator` constraint evaluation via
///    [`AirRegistry::with_builtins`], verifying that the exact `ULP-1` program
///    executed with `exit_code == 0`, `chain_id == expected_hub_chain_id`, and
///    published `(input_hash, output_hash)` to `SWrite[0..16]`.
///
/// # Errors
///
/// Returns [`UlpError`] on any failed binding, STARK proof, Merkle inclusion,
/// outflow bound, or `BudAir` algebraic constraint check.
pub fn open_universal_light_proof(
    bundle: &UniversalLightProofBundle,
    expected_program_hash: &Hash32,
    expected_hub_chain_id: DomainId,
    expected_hub_checkpoint_root: &Hash32,
    registry: &SchemeStatusRegistry,
) -> Result<VerifiedUlpHeader, UlpError> {
    if bundle.domain_count == 0
        || usize::try_from(bundle.domain_count).unwrap_or(usize::MAX) > MAX_ULP_DOMAINS
    {
        return Err(UlpError::InvalidDomainSet(
            "bundle domain_count outside 1..=MAX_ULP_DOMAINS",
        ));
    }
    if bundle.max_outflow_bps > MAX_ULP_OUTFLOW_BPS {
        return Err(UlpError::OutflowCeilingExceeded {
            observed_bps: bundle.max_outflow_bps,
            ceiling_bps: MAX_ULP_OUTFLOW_BPS,
        });
    }
    if bundle.total_security_weight == 0 || bundle.domains_merkle_root == [0u8; 32] {
        return Err(UlpError::BindingMismatch(
            "bundle security weight and domains_merkle_root must be non-zero",
        ));
    }
    if bundle.hub_chain_id != expected_hub_chain_id {
        return Err(UlpError::BindingMismatch("hub_chain_id mismatch"));
    }
    if !bool::from(bundle.program_hash.ct_eq(expected_program_hash)) {
        return Err(UlpError::BindingMismatch("ULP-1 program_hash mismatch"));
    }
    if !bool::from(
        bundle
            .hub_checkpoint_root
            .ct_eq(expected_hub_checkpoint_root),
    ) {
        return Err(UlpError::BindingMismatch(
            "hub_checkpoint_root does not match finalized GlobalBlockHeader",
        ));
    }

    // 1. Verify the succinct StarkBackend MasterProof.
    let default_params = AggParams::default();
    let backend = StarkBackend::new(
        registry.clone(),
        FrameLimits::from(&default_params),
        STARK_PARAMETER_SET,
    );
    backend
        .verify(&bundle.master_frame, expected_hub_chain_id)
        .map_err(|e| UlpError::MasterProof(e.to_string()))?;

    // 2. Verify canonical claims root and O(log C) inclusions for Claim::Prog & Claim::Poly.
    let frame_digests: Vec<Hash32> = bundle
        .master_frame
        .claims
        .iter()
        .map(|c| c.digest(expected_hub_chain_id))
        .collect();
    let actual_claims_root = claims_root(&frame_digests)
        .map_err(|_| UlpError::InvalidInclusion("empty claims in verified MasterProof"))?;
    if !bool::from(actual_claims_root.ct_eq(&bundle.claims_merkle_root)) {
        return Err(UlpError::InvalidInclusion(
            "claims_merkle_root does not match verified MasterProof",
        ));
    }
    let expected_prog_claim = Claim::Prog {
        program_hash: bundle.program_hash,
        input_hash: bundle.input_hash,
        output_hash: bundle.output_hash,
    };
    let prog_digest = expected_prog_claim.digest(expected_hub_chain_id);
    if !verify_claim_inclusion(
        &prog_digest,
        &bundle.prog_claim_inclusion,
        &bundle.claims_merkle_root,
    ) {
        return Err(UlpError::InvalidInclusion(
            "Claim::Prog inclusion proof failed against MasterProof",
        ));
    }
    if !matches!(bundle.pcs_bundle.poly_claim, Claim::Poly { .. }) {
        return Err(UlpError::InvalidInclusion(
            "pcs_bundle.poly_claim is not Claim::Poly",
        ));
    }
    let poly_digest = bundle.pcs_bundle.poly_claim.digest(expected_hub_chain_id);
    if !verify_claim_inclusion(
        &poly_digest,
        &bundle.pcs_bundle.poly_claim_inclusion,
        &bundle.claims_merkle_root,
    ) {
        return Err(UlpError::InvalidInclusion(
            "Claim::Poly inclusion proof failed against MasterProof",
        ));
    }

    // 3. Bind BudAirAuxData inside VerifyStarkTx to exact program_hash, hub_chain_id,
    //    exit_code == 0, and SWrite commitment to (input_hash, output_hash).
    if bundle.pcs_bundle.statement.air_id != bud_air_id() {
        return Err(UlpError::PcsVerification(
            "VerifyStarkTx air_id is not bud_air_id".into(),
        ));
    }
    let aux_len = u64::try_from(bundle.pcs_bundle.statement.air_aux_data.len())
        .map_err(|_| UlpError::PcsVerification("aux len overflow".into()))?;
    if aux_len == 0 || aux_len > MAX_BUD_AIR_AUX_BYTES {
        return Err(UlpError::PcsVerification("aux len out of bounds".into()));
    }
    let aux: BudAirAuxData = bincode::DefaultOptions::new()
        .with_limit(aux_len)
        .reject_trailing_bytes()
        .deserialize(&bundle.pcs_bundle.statement.air_aux_data)
        .map_err(|e| UlpError::PcsVerification(format!("aux decode: {e}")))?;
    let aux_prog_hash = program_hash_of(&aux.program);
    let expected_writes = published_writes_digest_many(&[&bundle.input_hash, &bundle.output_hash]);
    if !bool::from(aux_prog_hash.ct_eq(expected_program_hash))
        || !bool::from(
            aux.expected_inputs
                .program_hash
                .ct_eq(expected_program_hash),
        )
        || aux.expected_inputs.chain_id != u64::from(expected_hub_chain_id)
        || aux.expected_inputs.exit_code != 0
        || !bool::from(
            aux.expected_inputs
                .state_writes_digest
                .ct_eq(&expected_writes),
        )
        || !bool::from(aux.expected_inputs.final_state_root.ct_eq(&expected_writes))
    {
        return Err(UlpError::PcsVerification(
            "BudAir public inputs do not bind (program_hash, hub_chain_id, input_hash, output_hash)"
                .into(),
        ));
    }

    // 4. Run Stage-2 BudAir algebra verification and match re-derived Claim::Poly.
    let air_registry = AirRegistry::with_builtins();
    let mut proven = BTreeSet::new();
    proven.insert(poly_digest);
    let derived_poly = air_registry
        .verify_stark_tx(
            expected_hub_chain_id,
            &bundle.pcs_bundle.statement,
            &[poly_digest],
            &proven,
        )
        .map_err(|e| UlpError::PcsVerification(e.to_string()))?;
    if derived_poly != bundle.pcs_bundle.poly_claim {
        return Err(UlpError::PcsVerification(
            "re-derived Claim::Poly does not match proven Claim::Poly".into(),
        ));
    }

    Ok(VerifiedUlpHeader {
        hub_chain_id: bundle.hub_chain_id,
        settlement_epoch: bundle.settlement_epoch,
        hub_checkpoint_root: bundle.hub_checkpoint_root,
        domains_merkle_root: bundle.domains_merkle_root,
        domain_count: bundle.domain_count,
        total_security_weight: bundle.total_security_weight,
        all_pq_attested: bundle.all_pq_attested,
        max_outflow_bps: bundle.max_outflow_bps,
    })
}
