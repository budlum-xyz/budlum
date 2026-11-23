//! Universal Light Proof (`ULP-1`) succinct multi-domain aggregation.
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
use crate::core::chain_config::epoch_len_for_chain_id;
use crate::crypto::scheme::{SchemeId, SchemeStatusRegistry};
use crate::domain::types::{DomainId, Hash32};
use zeroize::Zeroizing;

/// Maximum number of external domains aggregated inside a single `ULP-1` circuit.
pub const MAX_ULP_DOMAINS: usize = 6;
/// Maximum Merkle path depth accepted for a [`UlpDomainInclusionProof`].
pub const MAX_ULP_MERKLE_DEPTH: usize = 8;
/// Hard per-domain and per-route settlement outflow ceiling in basis points (25%).
pub const MAX_ULP_OUTFLOW_BPS: u16 = 2_500;
/// Highest assigned [`UlpDomainKind`] wire/circuit discriminator (`1..=14`).
///
/// WIRING: range-checked inside `compile_ulp_program` and [`UlpDomainKind::from_code`].
pub const MAX_ULP_DOMAIN_KIND_CODE: u8 = 14;
/// Canonical 32-bit unsigned limb bitmask enforced inside `BudVM`.
const U32_MASK: u64 = 0xFFFF_FFFF;
/// Gas ceiling allocated to `BudVM` when proving a `ULP-1` guest trace.
const ULP_VM_GAS_LIMIT: u64 = 400_000;

/// Consensus family attested by one external domain leaf inside `ULP-1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UlpDomainKind {
    /// Tendermint / `CometBFT` instant finality.
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
    /// L1-sequenced based rollup preconfirmation and FOCIL inclusion finality.
    BasedPreconf = 7,
    /// TON Masterchain Catchain BFT and dynamic Shardchain Merkle finality.
    TonCatchain = 8,
    /// Federated Byzantine Agreement / Stellar Consensus Protocol finality.
    StellarScp = 9,
    /// Dual-quorum restaking AVS + EOTS slashable finality.
    RestakingAvs = 10,
    /// Merged-mining `AuxPoW` + bonded Proof-of-Proof anchor finality.
    AuxPowPop = 11,
    /// 2-round Simplex / tail-forking-resistant `MonadBFT` finality.
    SimplexBft = 12,
    /// Forward-secure post-quantum ML-DSA-65 Algorand `StateProof` finality.
    AlgorandStateProof = 13,
    /// Hash-based STARK / zkVM validity-rollup state-transition finality.
    ZkValidityRollup = 14,
}

impl UlpDomainKind {
    /// Exhaustive table of every registered `ULP-1` consensus family (`1..=14`).
    ///
    /// WIRING: exercised by round-trip discriminator and circuit-binding checks.
    pub const ALL: [Self; 14] = [
        Self::TendermintBft,
        Self::BitcoinSpv,
        Self::EthereumSync,
        Self::DagBft,
        Self::SuccinctRecursive,
        Self::PoSpaceVdf,
        Self::BasedPreconf,
        Self::TonCatchain,
        Self::StellarScp,
        Self::RestakingAvs,
        Self::AuxPowPop,
        Self::SimplexBft,
        Self::AlgorandStateProof,
        Self::ZkValidityRollup,
    ];

    /// Canonical numeric code bound into the `ULP-1` leaf hash and `BudAir` trace.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Decode a canonical `ULP-1` consensus-family discriminator (`1..=14`).
    ///
    /// WIRING: validates serialized domain-kind codes against [`Self::ALL`].
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::TendermintBft),
            2 => Some(Self::BitcoinSpv),
            3 => Some(Self::EthereumSync),
            4 => Some(Self::DagBft),
            5 => Some(Self::SuccinctRecursive),
            6 => Some(Self::PoSpaceVdf),
            7 => Some(Self::BasedPreconf),
            8 => Some(Self::TonCatchain),
            9 => Some(Self::StellarScp),
            10 => Some(Self::RestakingAvs),
            11 => Some(Self::AuxPowPop),
            12 => Some(Self::SimplexBft),
            13 => Some(Self::AlgorandStateProof),
            14 => Some(Self::ZkValidityRollup),
            _ => None,
        }
    }

    /// Returns whether a domain of this consensus family remains sound under an
    /// active CRQC Frost Alarm emergency given whether it carried a verified
    /// post-quantum (`ML-DSA-65` / `ML-DSA-87` / hash-STARK) attestation.
    ///
    /// Every family fails closed under Frost Alarm unless `pq_attested` is
    /// `true`: hash-work, recursive hash-STARK, validity-rollup, and ML-DSA-65
    /// `StateProof` domains must attach their verified PQ attestation or relay
    /// binding, and hybrid committee domains (`TendermintBft`, `EthereumSync`,
    /// `DagBft`, `BasedPreconf`, `TonCatchain`, `StellarScp`, `RestakingAvs`,
    /// `AuxPowPop`, `SimplexBft`) must carry full PQ co-signature quorums.
    #[must_use]
    pub const fn is_post_quantum_safe(self, pq_attested: bool) -> bool {
        match self {
            Self::BitcoinSpv
            | Self::SuccinctRecursive
            | Self::PoSpaceVdf
            | Self::TendermintBft
            | Self::EthereumSync
            | Self::DagBft
            | Self::BasedPreconf
            | Self::TonCatchain
            | Self::StellarScp
            | Self::RestakingAvs
            | Self::AuxPowPop
            | Self::SimplexBft
            | Self::AlgorandStateProof
            | Self::ZkValidityRollup => pq_attested,
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
    /// Canonical domain-separated `Poseidon` leaf digest committed inside
    /// [`UniversalLightProofBundle::domains_merkle_root`] and reproduced limb
    /// for limb inside [`compile_ulp_program`].
    #[must_use]
    pub fn leaf_hash(&self) -> Hash32 {
        let mut limbs = Vec::with_capacity(12 + 3 * DIGEST_LIMBS);
        limbs.push(u64::from(self.domain_id));
        limbs.push(u64::from(self.kind.code()));
        limbs.extend_from_slice(&split_u64_limbs(self.external_chain_id));
        limbs.extend_from_slice(&split_u64_limbs(self.prev_height));
        limbs.extend_from_slice(&split_u64_limbs(self.finalized_height));
        limbs.extend_from_slice(&split_u64_limbs(self.security_weight));
        limbs.push(u64::from(self.outflow_bps));
        limbs.push(u64::from(self.pq_attested));
        limbs.extend_from_slice(&digest_limbs(&self.state_root));
        limbs.extend_from_slice(&digest_limbs(&self.event_root));
        limbs.extend_from_slice(&digest_limbs(&self.anchor_hash));
        poseidon_sponge_256(TAG_ULP_LEAF, &limbs)
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
    let mut limbs = Vec::with_capacity(2 * DIGEST_LIMBS);
    limbs.extend_from_slice(&digest_limbs(left));
    limbs.extend_from_slice(&digest_limbs(right));
    poseidon_sponge_256(TAG_ULP_NODE, &limbs)
}

#[must_use]
fn ulp_empty_root() -> Hash32 {
    poseidon_sponge_256(TAG_ULP_EMPTY, &[])
}

/// Computes the canonical `ULP-1` binary Merkle root over domain snapshots
/// sorted canonically by `domain_id`.
#[must_use]
pub fn ulp_domains_root(snapshots: &[UlpDomainSnapshot]) -> Hash32 {
    if snapshots.is_empty() {
        return ulp_empty_root();
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
    level.first().copied().unwrap_or_else(ulp_empty_root)
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
    for (slot, chunk) in out.iter_mut().zip(digest.as_chunks::<4>().0) {
        let [b0, b1, b2, b3] = *chunk;
        *slot = u64::from(u32::from_le_bytes([b0, b1, b2, b3]));
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
    for (i, chunk) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let domain_i = squeeze_base.wrapping_add(i as u64) % GOLDILOCKS_MODULUS;
        let mixed = poseidon4_hash(poseidon4_hash(acc_a, domain_i), acc_b);
        let limb32 = (mixed & U32_MASK) as u32;
        chunk.copy_from_slice(&limb32.to_le_bytes());
    }
    out
}

/// Computes the canonical in-circuit `ULP-1` `input_hash` binding the
/// settlement hub chain id, canonical settlement epoch, aggregated domain
/// count, and finalized hub checkpoint root in `O(1)`.
#[must_use]
pub fn ulp_input_hash(
    hub_chain_id: DomainId,
    settlement_epoch: u64,
    domain_count: u32,
    hub_checkpoint_root: &Hash32,
) -> Hash32 {
    let epoch = split_u64_limbs(settlement_epoch);
    let mut limbs = Vec::with_capacity(4 + DIGEST_LIMBS);
    limbs.push(u64::from(hub_chain_id));
    limbs.extend_from_slice(&epoch);
    limbs.push(u64::from(domain_count));
    limbs.extend_from_slice(&digest_limbs(hub_checkpoint_root));
    poseidon_sponge_256(TAG_ULP_INPUT, &limbs)
}

/// Computes the canonical in-circuit `ULP-1` `output_hash` binding the
/// settlement hub chain id, canonical settlement epoch, aggregated domain
/// count, in-circuit `Poseidon` `domains_merkle_root`, saturating
/// `total_security_weight`, aggregate `all_pq_attested` flag, and exact
/// `max_outflow_bps` in `O(1)`.
#[must_use]
pub fn ulp_output_hash(
    hub_chain_id: DomainId,
    settlement_epoch: u64,
    domain_count: u32,
    domains_merkle_root: &Hash32,
    total_security_weight: u64,
    all_pq_attested: bool,
    max_outflow_bps: u16,
) -> Hash32 {
    let epoch = split_u64_limbs(settlement_epoch);
    let weight = split_u64_limbs(total_security_weight);
    let mut limbs = Vec::with_capacity(8 + DIGEST_LIMBS);
    limbs.push(u64::from(hub_chain_id));
    limbs.extend_from_slice(&epoch);
    limbs.push(u64::from(domain_count));
    limbs.push(u64::from(all_pq_attested));
    limbs.push(u64::from(max_outflow_bps));
    limbs.extend_from_slice(&weight);
    limbs.extend_from_slice(&digest_limbs(domains_merkle_root));
    poseidon_sponge_256(TAG_ULP_OUTPUT, &limbs)
}

/// Derives the canonical settlement epoch of a hub checkpoint from the chain's
/// own epoch length: `checkpoint_height / epoch_len_for_chain_id(chain_id)`.
///
/// This is the same derivation the consensus layer uses for checkpoint
/// certificates (`Blockchain::epoch_for_checkpoint_height`), so a ULP-1 bundle's
/// declared `settlement_epoch` can be re-derived from the trusted anchor's
/// `checkpoint_height` instead of being accepted as a prover-declared value.
/// `epoch_len_for_chain_id` is at least 1 for every `chain_id`, so the division
/// is total and deterministic.
#[must_use]
pub fn ulp_expected_settlement_epoch(chain_id: u64, checkpoint_height: u64) -> u64 {
    checkpoint_height / epoch_len_for_chain_id(chain_id).max(1)
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
    let [_, r1, r2, _, _, _, _, _, _, _, r10, r11, r12, ..] = R;
    let (seed_a, seed_b, squeeze_base) = tag_seeds(tag);
    a.li(r10, seed_a);
    for &src in sources {
        emit_load_source(a, r1, src);
        a.poseidon(r10, r10, r1);
    }
    a.li(r11, seed_b);
    for &src in sources.iter().rev() {
        emit_load_source(a, r1, src);
        a.poseidon(r11, r11, r1);
    }
    a.li(r12, U32_MASK);
    for i in 0..DIGEST_LIMBS_U32 {
        let domain_i = squeeze_base.wrapping_add(u64::from(i)) % GOLDILOCKS_MODULUS;
        a.li(r1, domain_i);
        a.poseidon(r2, r10, r1);
        a.poseidon(r2, r2, r11);
        a.and(r2, r2, r12);
        a.swrite(start_slot + i, r2);
    }
}

fn emit_nonzero_digest_sub(a: &mut Asm, ptr_reg: Reg) {
    let [_, r1, r2, r3, ..] = R;
    a.li(r1, 0);
    for offset in 0..DIGEST_LIMBS as u64 {
        a.load(r2, ptr_reg, offset);
        a.add(r1, r1, r2);
    }
    a.li(r2, 0);
    a.lt(r3, r2, r1);
    a.assert(r3);
    a.ret();
}

fn emit_leaf_poseidon_sub(a: &mut Asm, src_ptr: Reg, dst_ptr: Reg, leaf_cells: u64) {
    let [_, r1, r2, _, _, _, _, _, _, _, r10, r11, r12, ..] = R;
    let (seed_a, seed_b, squeeze_base) = tag_seeds(TAG_ULP_LEAF);
    a.li(r10, seed_a);
    for idx in 0..leaf_cells {
        a.load(r1, src_ptr, idx);
        a.poseidon(r10, r10, r1);
    }
    a.li(r11, seed_b);
    for idx in (0..leaf_cells).rev() {
        a.load(r1, src_ptr, idx);
        a.poseidon(r11, r11, r1);
    }
    a.li(r12, U32_MASK);
    for i in 0..DIGEST_LIMBS_U32 {
        let domain_i = squeeze_base.wrapping_add(u64::from(i)) % GOLDILOCKS_MODULUS;
        a.li(r1, domain_i);
        a.poseidon(r2, r10, r1);
        a.poseidon(r2, r2, r11);
        a.and(r2, r2, r12);
        a.store(dst_ptr, u64::from(i), r2);
    }
    a.ret();
}

fn emit_node_poseidon_sub(a: &mut Asm, left_ptr: Reg, right_ptr: Reg, dst_ptr: Reg) {
    let [_, r1, r2, _, _, _, _, _, _, _, r10, r11, r12, ..] = R;
    let (seed_a, seed_b, squeeze_base) = tag_seeds(TAG_ULP_NODE);
    a.li(r10, seed_a);
    for idx in 0..DIGEST_LIMBS as u64 {
        a.load(r1, left_ptr, idx);
        a.poseidon(r10, r10, r1);
    }
    for idx in 0..DIGEST_LIMBS as u64 {
        a.load(r1, right_ptr, idx);
        a.poseidon(r10, r10, r1);
    }
    a.li(r11, seed_b);
    for idx in (0..DIGEST_LIMBS as u64).rev() {
        a.load(r1, right_ptr, idx);
        a.poseidon(r11, r11, r1);
    }
    for idx in (0..DIGEST_LIMBS as u64).rev() {
        a.load(r1, left_ptr, idx);
        a.poseidon(r11, r11, r1);
    }
    a.li(r12, U32_MASK);
    for i in 0..DIGEST_LIMBS_U32 {
        let domain_i = squeeze_base.wrapping_add(u64::from(i)) % GOLDILOCKS_MODULUS;
        a.li(r1, domain_i);
        a.poseidon(r2, r10, r1);
        a.poseidon(r2, r2, r11);
        a.and(r2, r2, r12);
        a.store(dst_ptr, u64::from(i), r2);
    }
    a.ret();
}

fn push_cells(out: &mut Vec<LimbSource>, base: u64, count: usize) {
    for i in 0..count as u64 {
        out.push(LimbSource::Cell(base + i));
    }
}

#[derive(Debug, Clone, Copy)]
struct DomainCells {
    domain_id: u64,
    kind_code: u64,
    ext_chain_id: u64,
    prev_height: u64,
    finalized_height: u64,
    security_weight: u64,
    outflow_bps: u64,
    pq_flag: u64,
    state_root: u64,
    event_root: u64,
    anchor_hash: u64,
}

#[derive(Debug, Clone)]
struct UlpCells {
    first_cell: u64,
    total_cells: u64,
    epoch: u64,
    hub_checkpoint_root: u64,
    domains_merkle_root: u64,
    total_security_weight: u64,
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
    let domain_count_u32 = u32::try_from(domain_count)
        .map_err(|_| UlpError::InvalidDomainSet("domain_count overflow"))?;
    let [_, r1, r2, r3, r4, r5, r6, r7, r8, r9, _, _, r12, r13, r14, r15, r16, _, _, _, r20, r21, r22, r23, ..] =
        R;
    let domain_leaf_cells = 12u64 + 3 * (DIGEST_LIMBS as u64);

    let mut a = Asm::new();
    let nonzero_sub = a.label();
    let leaf_sub = a.label();
    let node_sub = a.label();

    let epoch = a.alloc(2);
    let hub_checkpoint_root = a.alloc(DIGEST_LIMBS as u64);
    let domains_merkle_root = a.alloc(DIGEST_LIMBS as u64);
    let total_security_weight = a.alloc(2);
    let all_pq_flag = a.alloc(1);
    let max_outflow_bps = a.alloc(1);
    let mut domains = Vec::with_capacity(domain_count);
    for _ in 0..domain_count {
        domains.push(DomainCells {
            domain_id: a.alloc(1),
            kind_code: a.alloc(1),
            ext_chain_id: a.alloc(2),
            prev_height: a.alloc(2),
            finalized_height: a.alloc(2),
            security_weight: a.alloc(2),
            outflow_bps: a.alloc(1),
            pq_flag: a.alloc(1),
            state_root: a.alloc(DIGEST_LIMBS as u64),
            event_root: a.alloc(DIGEST_LIMBS as u64),
            anchor_hash: a.alloc(DIGEST_LIMBS as u64),
        });
    }
    let end_cell = a.alloc(0);
    let total_cells = end_cell.saturating_sub(epoch);

    // 1. Compact pointer loop range-checking every witness cell < 2^32.
    let range_loop = a.label();
    a.li(r12, U32_MASK);
    a.li(r20, Asm::address(epoch));
    a.li(r21, total_cells);
    a.li(r22, 8);
    a.li(r23, 1);
    a.bind(range_loop);
    a.load(r1, r20, 0);
    a.and(r2, r1, r12);
    a.eq(r3, r1, r2);
    a.assert(r3);
    a.add(r20, r20, r22);
    a.sub(r21, r21, r23);
    a.jnz(r21, range_loop);

    // 2. Non-zero hub_checkpoint_root commitment.
    a.li(r20, Asm::address(hub_checkpoint_root));
    a.call(nonzero_sub);

    // 3. Per-domain invariants + exact aggregates:
    //    r8 = all_pq_flag, r9 = max_outflow_bps, (r15, r16) = saturating total_security_weight.
    a.li(r8, 1);
    a.li(r9, 0);
    a.li(r13, u64::from(MAX_ULP_OUTFLOW_BPS) + 1);
    a.li(r14, 1u64 << 32);
    a.li(r15, 0);
    a.li(r16, 0);
    let mut prev_domain_id_reg_set = false;
    for dc in &domains {
        // Strictly ascending non-zero domain_id prevents duplicate domains in-circuit.
        a.load_abs(r1, dc.domain_id);
        a.li(r2, 0);
        a.lt(r3, r2, r1);
        a.assert(r3);
        if prev_domain_id_reg_set {
            a.lt(r3, r7, r1);
            a.assert(r3);
        }
        a.mov(r7, r1);
        prev_domain_id_reg_set = true;

        // Enforce registered consensus family code in 1..=MAX_ULP_DOMAIN_KIND_CODE.
        a.load_abs(r1, dc.kind_code);
        a.li(r2, 0);
        a.lt(r3, r2, r1);
        a.assert(r3);
        a.li(r2, u64::from(MAX_ULP_DOMAIN_KIND_CODE) + 1);
        a.lt(r3, r1, r2);
        a.assert(r3);

        // Exact 64-bit prev_height < finalized_height on 32-bit limbs without Goldilocks wrap:
        // (prev_hi < fin_hi) || (prev_hi == fin_hi && prev_lo < fin_lo).
        a.load_abs(r1, dc.prev_height);
        a.load_abs(r2, dc.prev_height + 1);
        a.load_abs(r3, dc.finalized_height);
        a.load_abs(r4, dc.finalized_height + 1);
        a.lt(r5, r2, r4);
        a.eq(r6, r2, r4);
        a.lt(r2, r1, r3);
        a.mul(r6, r6, r2);
        a.add(r5, r5, r6);
        a.assert(r5);

        // Non-zero state_root and anchor_hash commitments.
        a.li(r20, Asm::address(dc.state_root));
        a.call(nonzero_sub);
        a.li(r20, Asm::address(dc.anchor_hash));
        a.call(nonzero_sub);

        // Positive 64-bit security_weight > 0 and exact saturating 64-bit accumulation.
        a.load_abs(r1, dc.security_weight);
        a.load_abs(r2, dc.security_weight + 1);
        a.add(r3, r1, r2);
        a.li(r4, 0);
        a.lt(r5, r4, r3);
        a.assert(r5);

        a.add(r3, r15, r1);
        a.gte(r4, r3, r14);
        a.mul(r5, r4, r14);
        a.sub(r3, r3, r5);
        a.add(r5, r16, r2);
        a.add(r5, r5, r4);
        a.gte(r4, r5, r14);
        a.li(r6, 1);
        a.sub(r6, r6, r4);
        a.mul(r3, r6, r3);
        a.mul(r1, r4, r12);
        a.add(r15, r3, r1);
        a.mul(r5, r6, r5);
        a.add(r16, r5, r1);

        // Outflow ceiling: outflow_bps <= MAX_ULP_OUTFLOW_BPS and exact running max in r9.
        a.load_abs(r1, dc.outflow_bps);
        a.lt(r5, r1, r13);
        a.assert(r5);
        a.gt(r2, r1, r9);
        a.li(r3, 1);
        a.sub(r3, r3, r2);
        a.mul(r4, r2, r1);
        a.mul(r5, r3, r9);
        a.add(r9, r4, r5);

        // Boolean pq_flag in {0, 1} and all_pq_flag &= pq_flag.
        a.load_abs(r1, dc.pq_flag);
        a.li(r2, 2);
        a.lt(r5, r1, r2);
        a.assert(r5);
        a.and(r8, r8, r1);
    }

    // Bind aggregate all_pq_flag, exact max_outflow_bps, and exact total_security_weight.
    a.load_abs(r1, all_pq_flag);
    a.eq(r5, r1, r8);
    a.assert(r5);

    a.lt(r5, r9, r13);
    a.assert(r5);
    a.load_abs(r1, max_outflow_bps);
    a.eq(r5, r1, r9);
    a.assert(r5);

    a.load_abs(r1, total_security_weight);
    a.eq(r5, r1, r15);
    a.assert(r5);
    a.load_abs(r1, total_security_weight + 1);
    a.eq(r5, r1, r16);
    a.assert(r5);

    // 4. In-circuit Poseidon leaf hashing and binary Merkle fold -> assert == domains_merkle_root.
    let mut level_bases = Vec::with_capacity(domain_count);
    for dc in &domains {
        let leaf_base = a.alloc(DIGEST_LIMBS as u64);
        a.li(r20, Asm::address(dc.domain_id));
        a.li(r22, Asm::address(leaf_base));
        a.call(leaf_sub);
        level_bases.push(leaf_base);
    }
    while level_bases.len() > 1 {
        let mut next_bases = Vec::with_capacity(level_bases.len().div_ceil(2));
        for pair in level_bases.chunks(2) {
            match pair {
                [left_base, right_base] => {
                    let parent_base = a.alloc(DIGEST_LIMBS as u64);
                    a.li(r20, Asm::address(*left_base));
                    a.li(r21, Asm::address(*right_base));
                    a.li(r22, Asm::address(parent_base));
                    a.call(node_sub);
                    next_bases.push(parent_base);
                }
                [only_base] => next_bases.push(*only_base),
                _ => {}
            }
        }
        level_bases = next_bases;
    }
    let computed_root_base = level_bases
        .first()
        .copied()
        .ok_or(UlpError::InvalidDomainSet("empty Merkle level"))?;
    for offset in 0..DIGEST_LIMBS as u64 {
        a.load_abs(r1, computed_root_base + offset);
        a.load_abs(r2, domains_merkle_root + offset);
        a.eq(r3, r1, r2);
        a.assert(r3);
    }

    // 5. Compute and publish O(1) input_hash to SWrite[0..8].
    let mut in_sources = Vec::with_capacity(4 + DIGEST_LIMBS);
    in_sources.push(LimbSource::Const(u64::from(hub_chain_id)));
    push_cells(&mut in_sources, epoch, 2);
    in_sources.push(LimbSource::Const(u64::from(domain_count_u32)));
    push_cells(&mut in_sources, hub_checkpoint_root, DIGEST_LIMBS);
    emit_dual_poseidon_swrite(&mut a, TAG_ULP_INPUT, &in_sources, 0);

    // 6. Compute and publish O(1) output_hash to SWrite[8..16].
    let mut out_sources = Vec::with_capacity(8 + DIGEST_LIMBS);
    out_sources.push(LimbSource::Const(u64::from(hub_chain_id)));
    push_cells(&mut out_sources, epoch, 2);
    out_sources.push(LimbSource::Const(u64::from(domain_count_u32)));
    out_sources.push(LimbSource::Cell(all_pq_flag));
    out_sources.push(LimbSource::Cell(max_outflow_bps));
    push_cells(&mut out_sources, total_security_weight, 2);
    push_cells(&mut out_sources, domains_merkle_root, DIGEST_LIMBS);
    emit_dual_poseidon_swrite(&mut a, TAG_ULP_OUTPUT, &out_sources, DIGEST_LIMBS_U32);
    a.halt();

    // Shared helper subroutines emitted once per program after `halt`.
    a.bind(nonzero_sub);
    emit_nonzero_digest_sub(&mut a, r20);
    a.bind(leaf_sub);
    emit_leaf_poseidon_sub(&mut a, r20, r22, domain_leaf_cells);
    a.bind(node_sub);
    emit_node_poseidon_sub(&mut a, r20, r21, r22);

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
            total_security_weight,
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

/// Verified header extracted after `verify_universal_light_proof` succeeds.
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

    let domain_count = u32::try_from(sorted.len())
        .map_err(|_| UlpError::InvalidDomainSet("domain_count overflow"))?;
    let domains_merkle_root = ulp_domains_root(&sorted);
    let all_pq_attested = sorted.iter().all(|s| s.pq_attested);
    let max_outflow_bps = sorted.iter().map(|s| s.outflow_bps).max().unwrap_or(0);
    let total_security_weight = sorted
        .iter()
        .fold(0u64, |acc, s| acc.saturating_add(s.security_weight));

    let input_hash = ulp_input_hash(
        compiled.hub_chain_id,
        settlement_epoch,
        domain_count,
        &hub_checkpoint_root,
    );
    let output_hash = ulp_output_hash(
        compiled.hub_chain_id,
        settlement_epoch,
        domain_count,
        &domains_merkle_root,
        total_security_weight,
        all_pq_attested,
        max_outflow_bps,
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
    write_u64_cells(
        &mut vm,
        compiled.cells.total_security_weight,
        total_security_weight,
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
        write_cell(&mut vm, dc.kind_code, u64::from(snap.kind.code()));
        write_u64_cells(&mut vm, dc.ext_chain_id, snap.external_chain_id);
        write_u64_cells(&mut vm, dc.prev_height, snap.prev_height);
        write_u64_cells(&mut vm, dc.finalized_height, snap.finalized_height);
        write_u64_cells(&mut vm, dc.security_weight, snap.security_weight);
        write_cell(&mut vm, dc.outflow_bps, u64::from(snap.outflow_bps));
        write_cell(&mut vm, dc.pq_flag, u64::from(snap.pq_attested));
        write_digest_cells(&mut vm, dc.state_root, &snap.state_root);
        write_digest_cells(&mut vm, dc.event_root, &snap.event_root);
        write_digest_cells(&mut vm, dc.anchor_hash, &snap.anchor_hash);
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
/// [`open_universal_light_proof`] with the full snapshot set: every header
/// field the bundle declares is re-derived through the canonical mirror
/// hashes and required to equal the in-circuit published statement, so
/// `settlement_epoch`, the hub anchor, the domain-set root, the aggregate
/// PQ flag and the outflow ceiling come out PROVEN rather than declared.
///
/// The route light client cannot call this (it holds only the hops'
/// snapshots); callers that admit a bundle alongside its snapshot set must.
///
/// # Errors
///
/// Every refusal of [`open_universal_light_proof`], plus
/// [`UlpError::BindingMismatch`] when any declared header field is not the
/// one the proof's statement actually witnessed.
///
/// WIRING: the multi-hop route verifier adopts this opener once the route
/// packet carries the bundle's full snapshot set; today the packet's hops
/// carry only their own two endpoints, so the route still opens through
/// the snapshotless door and the domain-tree slice closes the gap.
pub fn open_universal_light_proof_with_snapshots(
    bundle: &UniversalLightProofBundle,
    expected_program_hash: &Hash32,
    expected_hub_chain_id: DomainId,
    expected_hub_checkpoint_root: &Hash32,
    expected_settlement_epoch: u64,
    snapshots: &[UlpDomainSnapshot],
    registry: &SchemeStatusRegistry,
) -> Result<VerifiedUlpHeader, UlpError> {
    let sorted = canonicalize_ulp_domains(snapshots)?;
    if sorted.len() != usize::try_from(bundle.domain_count).unwrap_or(usize::MAX) {
        return Err(UlpError::BindingMismatch(
            "snapshot count does not match bundle domain_count",
        ));
    }
    if !bool::from(ulp_domains_root(&sorted).ct_eq(&bundle.domains_merkle_root)) {
        return Err(UlpError::BindingMismatch(
            "domains_merkle_root is not the root of the presented snapshots",
        ));
    }
    let expected_pq = sorted.iter().all(|s| s.pq_attested);
    let expected_max_outflow = sorted.iter().map(|s| s.outflow_bps).max().unwrap_or(0);
    let expected_weight = sorted
        .iter()
        .fold(0u64, |acc, s| acc.saturating_add(s.security_weight));
    if bundle.all_pq_attested != expected_pq
        || bundle.max_outflow_bps != expected_max_outflow
        || bundle.total_security_weight != expected_weight
    {
        return Err(UlpError::BindingMismatch(
            "declared aggregate flags/weights do not match presented snapshots",
        ));
    }
    open_universal_light_proof(
        bundle,
        expected_program_hash,
        expected_hub_chain_id,
        expected_hub_checkpoint_root,
        expected_settlement_epoch,
        registry,
    )
}

/// Opens and cryptographically verifies a [`UniversalLightProofBundle`] in
/// succinct `O(1)` time against the pinned `ULP-1` program hash, settlement hub
/// chain id, finalized hub checkpoint root, and canonical settlement epoch.
///
/// Re-derives both `input_hash` and `output_hash` directly from the trusted
/// anchor and the declared [`VerifiedUlpHeader`] fields, binding every outer
/// header field (`hub_chain_id`, `settlement_epoch`, `hub_checkpoint_root`,
/// `domain_count`, `domains_merkle_root`, `total_security_weight`,
/// `all_pq_attested`, `max_outflow_bps`) directly to `BudAir` `SWrite[0..16]`
/// without requiring full snapshot leaves.
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
    expected_settlement_epoch: u64,
    registry: &SchemeStatusRegistry,
) -> Result<VerifiedUlpHeader, UlpError> {
    if bundle.settlement_epoch != expected_settlement_epoch {
        return Err(UlpError::BindingMismatch(
            "declared settlement_epoch is not the anchor-derived epoch",
        ));
    }
    if *expected_hub_checkpoint_root == [0u8; 32] {
        return Err(UlpError::BindingMismatch(
            "expected_hub_checkpoint_root cannot be zero",
        ));
    }
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

    // Recompute O(1) canonical statement digests from trusted anchor + header fields;
    // any outer header mutation without re-proving fails closed before STARK opening.
    let expected_input = ulp_input_hash(
        expected_hub_chain_id,
        expected_settlement_epoch,
        bundle.domain_count,
        expected_hub_checkpoint_root,
    );
    if !bool::from(expected_input.ct_eq(&bundle.input_hash)) {
        return Err(UlpError::BindingMismatch(
            "bundle input_hash does not match trusted hub anchor and settlement_epoch",
        ));
    }
    let expected_output = ulp_output_hash(
        expected_hub_chain_id,
        expected_settlement_epoch,
        bundle.domain_count,
        &bundle.domains_merkle_root,
        bundle.total_security_weight,
        bundle.all_pq_attested,
        bundle.max_outflow_bps,
    );
    if !bool::from(expected_output.ct_eq(&bundle.output_hash)) {
        return Err(UlpError::BindingMismatch(
            "bundle output_hash does not match declared header fields",
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
        program_hash: *expected_program_hash,
        input_hash: expected_input,
        output_hash: expected_output,
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
    //    exit_code == 0, and SWrite commitment to (expected_input, expected_output).
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
    let expected_writes = published_writes_digest_many(&[&expected_input, &expected_output]);
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
        hub_chain_id: expected_hub_chain_id,
        settlement_epoch: expected_settlement_epoch,
        hub_checkpoint_root: *expected_hub_checkpoint_root,
        domains_merkle_root: bundle.domains_merkle_root,
        domain_count: bundle.domain_count,
        total_security_weight: bundle.total_security_weight,
        all_pq_attested: bundle.all_pq_attested,
        max_outflow_bps: bundle.max_outflow_bps,
    })
}

#[cfg(test)]
mod modern_domain_kind_tests {
    use super::*;

    #[test]
    fn ulp_expected_settlement_epoch_matches_consensus_derivation() {
        // Devnet (45262) epoch length is 10: checkpoint height 25 -> epoch 2.
        assert_eq!(ulp_expected_settlement_epoch(45_262, 25), 2);
        assert_eq!(ulp_expected_settlement_epoch(45_262, 30), 3);
        // Testnet (45261) epoch length is 50: checkpoint height 100 -> epoch 2.
        assert_eq!(ulp_expected_settlement_epoch(45_261, 100), 2);
        // Mainnet (45260) epoch length is 100.
        assert_eq!(ulp_expected_settlement_epoch(45_260, 250), 2);
        // An unknown chain id falls back to the default epoch length.
        assert_eq!(ulp_expected_settlement_epoch(999_999, 100), 1);
        // Deterministic: same inputs always produce the same epoch.
        assert_eq!(
            ulp_expected_settlement_epoch(45_262, 25),
            ulp_expected_settlement_epoch(45_262, 25)
        );
    }

    #[test]
    fn ulp_verifier_refuses_declared_epoch_not_derived_from_anchor() {
        // Regression: a prover that declares a settlement_epoch different from
        // the epoch derived from the trusted hub checkpoint height must be
        // refused. The verifier re-derives the epoch from the anchor, so the
        // declared value cannot drift the statement.
        let families = [
            (71u32, UlpDomainKind::BasedPreconf, 7_100u64),
            (72u32, UlpDomainKind::TonCatchain, 8_200u64),
        ];
        let snapshots: Vec<UlpDomainSnapshot> = families
            .iter()
            .enumerate()
            .map(|(i, &(domain_id, kind, weight))| {
                let tag = u8::try_from(i + 0x41).expect("fits u8");
                UlpDomainSnapshot {
                    domain_id,
                    external_chain_id: u64::from(domain_id) * 100,
                    kind,
                    prev_height: 1_000 + i as u64,
                    finalized_height: 1_010 + i as u64,
                    state_root: [tag; 32],
                    event_root: [tag.wrapping_add(0x10); 32],
                    anchor_hash: [tag.wrapping_add(0x20); 32],
                    security_weight: weight,
                    pq_attested: true,
                    outflow_bps: 400,
                }
            })
            .collect();

        let compiled = compile_ulp_program(45_262, snapshots.len()).expect("compile ULP-1");
        let hub_root = [0xAB; 32];
        let seed = [0xCD; 32];
        let registry = SchemeStatusRegistry::genesis();

        // Hub checkpoint height 25 on devnet (epoch length 10) -> canonical epoch 2.
        const CHECKPOINT_HEIGHT: u64 = 25;
        let expected_epoch = ulp_expected_settlement_epoch(45_262, CHECKPOINT_HEIGHT);
        assert_eq!(expected_epoch, 2);

        // Prove with the canonical epoch.
        let (bundle, _sorted, _metrics) = prove_universal_light_proof(
            &compiled,
            expected_epoch,
            hub_root,
            &snapshots,
            &seed,
            12,
            &registry,
        )
        .expect("prove ULP-1");

        // Honest epoch verifies.
        open_universal_light_proof(
            &bundle,
            &compiled.program_hash,
            45_262,
            &hub_root,
            expected_epoch,
            &registry,
        )
        .expect("canonical epoch verifies");

        // A prover that declares a different epoch is refused.
        let mut lied = bundle.clone();
        lied.settlement_epoch = expected_epoch + 1;
        let result = open_universal_light_proof(
            &lied,
            &compiled.program_hash,
            45_262,
            &hub_root,
            expected_epoch,
            &registry,
        );
        assert!(
            result.is_err(),
            "a declared settlement_epoch that is not the anchor-derived epoch must be refused"
        );
        assert!(
            matches!(result, Err(UlpError::BindingMismatch(_))),
            "epoch drift must surface as BindingMismatch"
        );

        // And the verifier itself derives the epoch from the anchor, so the
        // declared epoch cannot be used to move the statement.
        let derived = ulp_expected_settlement_epoch(45_262, CHECKPOINT_HEIGHT);
        assert_eq!(derived, expected_epoch);
    }

    #[test]
    fn ulp_proves_and_verifies_extended_2026_consensus_families_and_binds_kind_code() {
        // 1. All 14 discriminators round-trip uniquely and enforce strict Frost Alarm PQ gating.
        assert_eq!(UlpDomainKind::from_code(0), None);
        assert_eq!(
            UlpDomainKind::from_code(MAX_ULP_DOMAIN_KIND_CODE.saturating_add(1)),
            None
        );
        for (idx, kind) in UlpDomainKind::ALL.iter().copied().enumerate() {
            let expected = u8::try_from(idx + 1).expect("14 fits in u8");
            assert_eq!(kind.code(), expected);
            assert_eq!(UlpDomainKind::from_code(expected), Some(kind));
            assert!(kind.is_post_quantum_safe(true));
            assert!(!kind.is_post_quantum_safe(false));
        }

        // 2. Prove and verify a real 128-bit BudAir FRI-STARK + Phase 5 split-STARK bundle
        //    aggregating 6 modern external consensus families (codes 7..=14).
        let families = [
            (71u32, UlpDomainKind::BasedPreconf, 7_100u64),
            (72u32, UlpDomainKind::TonCatchain, 8_200u64),
            (73u32, UlpDomainKind::StellarScp, 9_300u64),
            (74u32, UlpDomainKind::RestakingAvs, 10_400u64),
            (75u32, UlpDomainKind::AlgorandStateProof, 13_500u64),
            (76u32, UlpDomainKind::ZkValidityRollup, 14_600u64),
        ];
        let snapshots: Vec<UlpDomainSnapshot> = families
            .iter()
            .enumerate()
            .map(|(i, &(domain_id, kind, weight))| {
                let tag = u8::try_from(i + 0x41).expect("fits u8");
                UlpDomainSnapshot {
                    domain_id,
                    external_chain_id: u64::from(domain_id) * 100,
                    kind,
                    prev_height: 1_000 + i as u64,
                    finalized_height: 1_010 + i as u64,
                    state_root: [tag; 32],
                    event_root: [tag.wrapping_add(0x10); 32],
                    anchor_hash: [tag.wrapping_add(0x20); 32],
                    security_weight: weight,
                    pq_attested: true,
                    outflow_bps: 400 + u16::try_from(i * 50).expect("fits u16"),
                }
            })
            .collect();

        // Changing a domain's consensus family (e.g. AuxPowPop vs SimplexBft) mutates
        // leaf_hash, ulp_domains_root, and ulp_output_hash even with identical roots/heights.
        let mut alt_a = snapshots[0].clone();
        alt_a.kind = UlpDomainKind::AuxPowPop;
        let mut alt_b = alt_a.clone();
        alt_b.kind = UlpDomainKind::SimplexBft;
        assert_ne!(alt_a.leaf_hash(), alt_b.leaf_hash());
        let root_a = ulp_domains_root(std::slice::from_ref(&alt_a));
        let root_b = ulp_domains_root(std::slice::from_ref(&alt_b));
        assert_ne!(root_a, root_b);
        assert_ne!(
            ulp_input_hash(45_261, 77, 1, &[0x99; 32]),
            ulp_input_hash(45_261, 77, 2, &[0x99; 32])
        );
        assert_ne!(
            ulp_output_hash(45_261, 77, 1, &root_a, alt_a.security_weight, true, 400),
            ulp_output_hash(45_261, 77, 1, &root_b, alt_b.security_weight, true, 400)
        );

        let compiled = compile_ulp_program(45_261, snapshots.len()).expect("compile ULP-1");
        let hub_root = [0xAB; 32];
        let seed = [0xCD; 32];
        let registry = SchemeStatusRegistry::genesis();
        let (bundle, sorted, _metrics) =
            prove_universal_light_proof(&compiled, 77, hub_root, &snapshots, &seed, 12, &registry)
                .expect("prove real BudAir STARK over 6 modern consensus families");
        let verified = open_universal_light_proof(
            &bundle,
            &compiled.program_hash,
            45_261,
            &hub_root,
            77,
            &registry,
        )
        .expect("verify split-STARK bundle over extended families");
        // The epoch binding rejects a declared epoch off the anchor-derived one.
        let mut drifted = bundle.clone();
        drifted.settlement_epoch = 78;
        assert!(
            matches!(
                open_universal_light_proof(
                    &drifted,
                    &compiled.program_hash,
                    45_261,
                    &hub_root,
                    77,
                    &registry,
                ),
                Err(UlpError::BindingMismatch(_))
            ),
            "a settlement_epoch off the anchor-derived value must be refused"
        );
        assert_eq!(verified.domain_count, 6);
        assert!(verified.all_pq_attested);
        assert_eq!(
            verified.total_security_weight,
            families.iter().map(|(_, _, w)| *w).sum::<u64>()
        );

        // Verify domain inclusion fails if a relayer lies about UlpDomainKind.
        let inc = prove_ulp_domain_inclusion(&sorted, 75).expect("Algorand inclusion proof");
        let algo_snap = sorted
            .iter()
            .find(|s| s.domain_id == 75)
            .expect("Algorand snapshot")
            .clone();
        inc.verify(&algo_snap, &verified.domains_merkle_root)
            .expect("honest Algorand inclusion verifies");
        let mut spoofed = algo_snap;
        spoofed.kind = UlpDomainKind::SimplexBft;
        assert!(inc.verify(&spoofed, &verified.domains_merkle_root).is_err());

        // Snapshotless `open_universal_light_proof` rejects any forged outer
        // header field (`domains_merkle_root`, `total_security_weight`, `all_pq_attested`,
        // `max_outflow_bps`, or `hub_checkpoint_root` + `settlement_epoch`).
        let mut forged_root = bundle.clone();
        forged_root.domains_merkle_root = [0xDE; 32];
        assert!(matches!(
            open_universal_light_proof(
                &forged_root,
                &compiled.program_hash,
                45_261,
                &hub_root,
                77,
                &registry,
            ),
            Err(UlpError::BindingMismatch(_))
        ));

        let mut forged_weight = bundle.clone();
        forged_weight.total_security_weight = u64::MAX;
        assert!(matches!(
            open_universal_light_proof(
                &forged_weight,
                &compiled.program_hash,
                45_261,
                &hub_root,
                77,
                &registry,
            ),
            Err(UlpError::BindingMismatch(_))
        ));

        let mut forged_pq = bundle.clone();
        forged_pq.all_pq_attested = false;
        assert!(matches!(
            open_universal_light_proof(
                &forged_pq,
                &compiled.program_hash,
                45_261,
                &hub_root,
                77,
                &registry,
            ),
            Err(UlpError::BindingMismatch(_))
        ));

        let mut forged_outflow = bundle;
        forged_outflow.max_outflow_bps = 1;
        assert!(matches!(
            open_universal_light_proof(
                &forged_outflow,
                &compiled.program_hash,
                45_261,
                &hub_root,
                77,
                &registry,
            ),
            Err(UlpError::BindingMismatch(_))
        ));

        // Direct malicious witness injection (`forged domains_merkle_root`,
        // inflated `max_outflow_bps`, forged `total_security_weight`, zero `state_root`,
        // and Goldilocks-modulus height rollback) is rejected inside `BudVM`.
        let compiled1 = compile_ulp_program(45_261, 1).expect("compile 1-domain circuit");
        let single = UlpDomainSnapshot {
            domain_id: 7,
            external_chain_id: 700,
            kind: UlpDomainKind::TendermintBft,
            prev_height: 10,
            finalized_height: 20,
            state_root: [0x11; 32],
            event_root: [0x22; 32],
            anchor_hash: [0x33; 32],
            security_weight: 1_000,
            pq_attested: true,
            outflow_bps: 500,
        };
        let single_root = ulp_domains_root(std::slice::from_ref(&single));
        let make_vm = || {
            let mut vm = Vm::new(usize::try_from(ULP_VM_GAS_LIMIT).unwrap_or(usize::MAX));
            write_u64_cells(&mut vm, compiled1.cells.epoch, 77);
            write_digest_cells(&mut vm, compiled1.cells.hub_checkpoint_root, &[0x99; 32]);
            write_digest_cells(&mut vm, compiled1.cells.domains_merkle_root, &single_root);
            write_u64_cells(&mut vm, compiled1.cells.total_security_weight, 1_000);
            write_cell(&mut vm, compiled1.cells.all_pq_flag, 1);
            write_cell(&mut vm, compiled1.cells.max_outflow_bps, 500);
            let dc = &compiled1.cells.domains[0];
            write_cell(&mut vm, dc.domain_id, 7);
            write_cell(&mut vm, dc.kind_code, u64::from(single.kind.code()));
            write_u64_cells(&mut vm, dc.ext_chain_id, single.external_chain_id);
            write_u64_cells(&mut vm, dc.prev_height, single.prev_height);
            write_u64_cells(&mut vm, dc.finalized_height, single.finalized_height);
            write_u64_cells(&mut vm, dc.security_weight, single.security_weight);
            write_cell(&mut vm, dc.outflow_bps, u64::from(single.outflow_bps));
            write_cell(&mut vm, dc.pq_flag, u64::from(single.pq_attested));
            write_digest_cells(&mut vm, dc.state_root, &single.state_root);
            write_digest_cells(&mut vm, dc.event_root, &single.event_root);
            write_digest_cells(&mut vm, dc.anchor_hash, &single.anchor_hash);
            vm
        };

        let mut vm_bad_root = make_vm();
        write_digest_cells(
            &mut vm_bad_root,
            compiled1.cells.domains_merkle_root,
            &[0xBA; 32],
        );
        assert!(prove_vm_program(
            &compiled1.program.code,
            &mut vm_bad_root,
            [1; 32],
            [2; 32],
            45_261
        )
        .is_err());

        let mut vm_loose_outflow = make_vm();
        write_cell(
            &mut vm_loose_outflow,
            compiled1.cells.max_outflow_bps,
            2_400,
        );
        assert!(prove_vm_program(
            &compiled1.program.code,
            &mut vm_loose_outflow,
            [1; 32],
            [2; 32],
            45_261
        )
        .is_err());

        let mut vm_bad_weight = make_vm();
        write_u64_cells(
            &mut vm_bad_weight,
            compiled1.cells.total_security_weight,
            9_999,
        );
        assert!(prove_vm_program(
            &compiled1.program.code,
            &mut vm_bad_weight,
            [1; 32],
            [2; 32],
            45_261
        )
        .is_err());

        let mut zero_snap = single.clone();
        zero_snap.state_root = [0u8; 32];
        let zero_root = ulp_domains_root(std::slice::from_ref(&zero_snap));
        let mut vm_zero_state = make_vm();
        write_digest_cells(
            &mut vm_zero_state,
            compiled1.cells.domains[0].state_root,
            &[0u8; 32],
        );
        write_digest_cells(
            &mut vm_zero_state,
            compiled1.cells.domains_merkle_root,
            &zero_root,
        );
        assert!(prove_vm_program(
            &compiled1.program.code,
            &mut vm_zero_state,
            [1; 32],
            [2; 32],
            45_261
        )
        .is_err());

        let mut wrap_snap = single.clone();
        wrap_snap.prev_height = 0xFFFF_FFFF_0000_0005;
        wrap_snap.finalized_height = 10;
        let wrap_root = ulp_domains_root(std::slice::from_ref(&wrap_snap));
        let mut vm_wrap = make_vm();
        write_u64_cells(
            &mut vm_wrap,
            compiled1.cells.domains[0].prev_height,
            wrap_snap.prev_height,
        );
        write_u64_cells(
            &mut vm_wrap,
            compiled1.cells.domains[0].finalized_height,
            wrap_snap.finalized_height,
        );
        write_digest_cells(
            &mut vm_wrap,
            compiled1.cells.domains_merkle_root,
            &wrap_root,
        );
        assert!(prove_vm_program(
            &compiled1.program.code,
            &mut vm_wrap,
            [1; 32],
            [2; 32],
            45_261
        )
        .is_err());
    }
}
