//! Zero-knowledge shielded note transfer protocol (`private_transfer_v1`).
//!
//! WIRING: exposed for shielded wallet proving, devnet pool execution, and protocol verification.
//!
//! Public inputs carry strictly `(anchor_root, nullifiers, output_commitments,
//! fee, context_digest)` plus `chain_id`. No sender account, public key, nonce,
//! or account-level signature exists anywhere in the statement or proof; the
//! transaction fee is paid directly out of spent note value.
//!
//! Every transfer proves, inside a single witness-hiding Plonky3 STARK
//! (`ProofClass::Hiding`) over a verifier-reconstructed straight-line `BudZKVM`
//! circuit:
//!
//! 1. **Arity bounds:** `1..=16` spent input notes and `1..=16` created output
//!    notes ([`MAX_TRANSFER_V1_IO`]).
//! 2. **Strict 59-bit range bounds:** every input value, every output value,
//!    and `fee` decomposes into 59 boolean-constrained bits (`b * (1 - b) == 0`),
//!    enforcing `0 <= value < 2^59` ([`MAX_NOTE_VALUE_V1`]) so sums of up to 16
//!    notes plus fee never wrap modulo the Goldilocks prime `2^64 - 2^32 + 1`.
//! 3. **Spend-key ownership:** `owner_pk == derive_owner_pk(spend_key)` over
//!    full 256-bit four-limb Goldilocks digests ([`Digest4`]).
//! 4. **Depth-32 Merkle membership:** every input note commitment folds across
//!    32 boolean-directed, level-domain-separated wide-pipe Poseidon steps to
//!    the public `anchor_root` ([`NOTE_TREE_DEPTH`]).
//! 5. **Nullifier uniqueness binding:** every public `nullifiers[i]` equals
//!    `derive_note_nullifier(spend_key[i], rho[i], leaf_position[i])` where
//!    `leaf_position[i]` is reconstructed from the verified Merkle path bits.
//! 6. **Deterministic output `rho`:** every output note `j` uses
//!    `rho_out[j] == derive_output_rho(nullifiers[0], j)`, inheriting global
//!    uniqueness from the non-repeatable first nullifier.
//! 7. **Value conservation with note-paid fee:**
//!    `sum(input_values) == sum(output_values) + fee`.
//! 8. **Context and chain binding:** `chain_id`, `context_digest`,
//!    `anchor_root`, `nullifiers`, `output_commitments`, and `fee` are all
//!    committed directly inside the verifier-rebuilt program hash (256-bit
//!    Keccak-256 enforced by Program CTL) and logged into `event_digest`.

use bud_isa::{Instruction, Opcode};
use bud_proof::hiding::{prove_hiding, verify_with_class, HidingProofPackage, ProofClass};
use bud_proof::ExecutionPublicInputs;
use bud_vm::{poseidon4_hash, Vm, GOLDILOCKS_P};
use budlum_note_packing::{Digest4, HashSuiteId, SuiteTaggedCommitment};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Depth of the append-only shielded note commitment Merkle tree (`2^32` leaves).
///
/// Convenience: exposed for wallet tree sync and circuit callers.
pub const NOTE_TREE_DEPTH: usize = 32;

/// Bit width of every shielded note value and note-paid fee (`< 2^59`).
///
/// Convenience: exposed for range-bound validation callers.
pub const NOTE_VALUE_BITS: usize = 59;

/// Maximum value of any single shielded note or note-paid fee (`2^59 - 1`).
///
/// Convenience: exposed for wallet note builders and pool validators.
pub const MAX_NOTE_VALUE_V1: u64 = (1u64 << NOTE_VALUE_BITS) - 1;

/// Maximum number of spent inputs or created outputs in one transfer (`1..=16`).
///
/// Convenience: exposed for transfer admission bounds.
pub const MAX_TRANSFER_V1_IO: usize = 16;

/// Maximum number of recent Merkle roots retained as valid spend anchors.
///
/// Convenience: exposed for shielded pool anchor window callers.
pub const MAX_ANCHOR_HISTORY: usize = 256;

/// Maximum tree leaf count (`2^32`).
const MAX_TREE_LEAVES: u64 = 1u64 << NOTE_TREE_DEPTH;

/// Word width in `BudZKVM` guest memory (8 bytes per canonical Goldilocks limb).
const WORD_BYTES: usize = 8;

/// Domain tag for the empty leaf sentinel at level 0.
const DOMAIN_EMPTY_LEAF: u64 = 0x4244_4C4D_5056_3030;
/// Domain tag for spend-key -> owner-public-key derivation.
const DOMAIN_OWNER_PK: u64 = 0x4244_4C4D_5056_3031;
/// Domain tag for note commitment Phase A `(value, owner_pk)`.
const DOMAIN_NOTE_COMMIT_A: u64 = 0x4244_4C4D_5056_3032;
/// Domain tag for note commitment Phase B `(rho, rcm)`.
const DOMAIN_NOTE_COMMIT_B: u64 = 0x4244_4C4D_5056_3033;
/// Domain tag for note commitment finalizer.
const DOMAIN_NOTE_COMMIT_FINAL: u64 = 0x4244_4C4D_5056_3034;
/// Domain tag for nullifier derivation `(spend_key, rho, leaf_position)`.
const DOMAIN_NULLIFIER_A: u64 = 0x4244_4C4D_5056_3035;
/// Domain tag for nullifier position binding.
const DOMAIN_NULLIFIER_B: u64 = 0x4244_4C4D_5056_3036;
/// Domain tag for deterministic output `rho` derivation `(nullifiers[0], out_idx)`.
const DOMAIN_OUTPUT_RHO: u64 = 0x4244_4C4D_5056_3037;
/// Domain tag for public transcript rolling accumulator.
const DOMAIN_TRANSCRIPT: u64 = 0x4244_4C4D_5056_3038;
/// Base domain tag for internal Merkle tree nodes (`base + level`, `level in 0..32`).
const DOMAIN_MERKLE_LEVEL_BASE: u64 = 0x4244_4C4D_5056_3100;

// Straight-line guest register allocation (32 registers, zero aliasing).
const R_ZERO: u8 = 1;
const R_ONE: u8 = 2;
const R_POW32: u8 = 3;
const R_T0: u8 = 4;
const R_T1: u8 = 5;
const R_T2: u8 = 6;
const R_T3: u8 = 7;
const R_A0: u8 = 8;
const R_A1: u8 = 9;
const R_A2: u8 = 10;
const R_A3: u8 = 11;
const R_B0: u8 = 12;
const R_B1: u8 = 13;
const R_B2: u8 = 14;
const R_B3: u8 = 15;
const R_C0: u8 = 16;
const R_C1: u8 = 17;
const R_C2: u8 = 18;
const R_C3: u8 = 19;
const R_NF0_0: u8 = 20;
const R_NF0_1: u8 = 21;
const R_NF0_2: u8 = 22;
const R_NF0_3: u8 = 23;
const R_SUM_IN: u8 = 24;
const R_SUM_OUT: u8 = 25;
const R_VAL: u8 = 26;
const R_POS: u8 = 27;
const R_POW2: u8 = 28;
const R_TAG: u8 = 29;
const R_LOG: u8 = 30;
const R_SCRATCH: u8 = 31;

/// Errors returned by `private_transfer_v1` construction, proving, verification,
/// or shielded pool settlement.
///
/// Convenience: exposed for wallet and shielded pool callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateTransferV1Error {
    /// Chain disallows shielded transfer settlement (for example testnet/mainnet).
    ChainClosed(u64),
    /// Input or output list is empty or exceeds [`MAX_TRANSFER_V1_IO`].
    InvalidArity { inputs: usize, outputs: usize },
    /// Note value or fee is at or above `2^59`.
    ValueOutOfRange(u64),
    /// `sum(inputs) != sum(outputs) + fee`.
    BalanceMismatch {
        input_sum: u64,
        output_sum: u64,
        fee: u64,
    },
    /// Spend key does not match input note's `owner_pk`.
    OwnershipMismatch { input_index: usize },
    /// Merkle authentication path has wrong depth or does not reconstruct `anchor_root`.
    InvalidMerklePath { input_index: usize },
    /// Output note's `rho` does not equal `derive_output_rho(nullifiers[0], output_index)`.
    NonDeterministicOutputRho { output_index: usize },
    /// Commitment uses a non-Poseidon suite or 64-bit truncated digest.
    InvalidCommitmentEncoding,
    /// Duplicate nullifier or duplicate output commitment inside one transfer,
    /// or collision between nullifiers and outputs.
    DuplicateIdentifier(&'static str),
    /// Spend anchor root is not in the pool's valid anchor history.
    UnknownAnchor,
    /// Nullifier has already been spent in the shielded pool.
    NullifierAlreadySpent,
    /// Output commitment already exists in the tree or collides with a spent nullifier.
    OutputCollision,
    /// Note commitment tree is full or leaf index is out of bounds.
    TreeCapacityExceeded,
    /// Fee accumulation overflowed `u128`.
    FeeOverflow,
    /// Public input `chain_id` or `context_digest` does not match expected context.
    ContextMismatch(&'static str),
    /// Witness blinding salt was all zeros or witness assembly failed.
    InvalidWitness(String),
    /// VM execution or Plonky3 hiding STARK proving/verification failed.
    ProofRejected(String),
}

/// Wide-pipe 256-bit (four Goldilocks limb) compression built exclusively from
/// `poseidon4_hash`, matching the in-circuit `Opcode::Poseidon` gadget bit-for-bit
/// without narrowing the internal state below 256 bits.
#[must_use]
fn wide_compress4(tag: u64, left: [u64; 4], right: [u64; 4]) -> Digest4 {
    let [l0, l1, l2, l3] = left;
    let [r0, r1, r2, r3] = right;
    let t0 = poseidon4_hash(poseidon4_hash(l0, r0), tag);
    let t1 = poseidon4_hash(poseidon4_hash(l1, r1), t0);
    let t2 = poseidon4_hash(poseidon4_hash(l2, r2), t1);
    let t3 = poseidon4_hash(poseidon4_hash(l3, r3), t2);
    let o0 = poseidon4_hash(t0, t3);
    let o1 = poseidon4_hash(t1, o0);
    let o2 = poseidon4_hash(t2, o1);
    let o3 = poseidon4_hash(t3, o2);
    Digest4::try_new([o0, o1, o2, o3]).unwrap_or_else(left_fallback)
}

const fn left_fallback() -> Digest4 {
    match Digest4::try_new([1, 1, 1, 1]) {
        Some(d) => d,
        None => unreachable!(),
    }
}

/// Derive the 256-bit owner public key corresponding to a private `spend_key`.
///
/// Convenience: exposed for shielded wallet address derivation.
#[must_use]
pub fn derive_owner_pk(spend_key: &Digest4) -> Digest4 {
    let sk = spend_key.limbs();
    wide_compress4(DOMAIN_OWNER_PK, sk, [DOMAIN_OWNER_PK, 1, 2, 3])
}

/// Compute the canonical 256-bit commitment of a shielded note.
///
/// Convenience: exposed for shielded wallet note commitment computation.
///
/// # Errors
///
/// Returns [`PrivateTransferV1Error::ValueOutOfRange`] when `note.value > MAX_NOTE_VALUE_V1`.
pub fn compute_note_commitment(
    note: &ShieldedNoteV1,
) -> Result<SuiteTaggedCommitment, PrivateTransferV1Error> {
    if note.value > MAX_NOTE_VALUE_V1 {
        return Err(PrivateTransferV1Error::ValueOutOfRange(note.value));
    }
    let left_a = [note.value, 0, 0, 0];
    let phase_a = wide_compress4(DOMAIN_NOTE_COMMIT_A, left_a, note.owner_pk.limbs());
    let phase_b = wide_compress4(DOMAIN_NOTE_COMMIT_B, note.rho.limbs(), note.rcm.limbs());
    let digest = wide_compress4(DOMAIN_NOTE_COMMIT_FINAL, phase_a.limbs(), phase_b.limbs());
    SuiteTaggedCommitment::from_poseidon_digest4(digest)
        .ok_or(PrivateTransferV1Error::InvalidCommitmentEncoding)
}

/// Extract and validate the canonical non-truncated `Digest4` from a
/// [`SuiteTaggedCommitment`] tagged with `HashSuiteId::PoseidonG12V1`.
fn unpack_poseidon_commitment(
    c: &SuiteTaggedCommitment,
) -> Result<Digest4, PrivateTransferV1Error> {
    if c.suite != HashSuiteId::PoseidonG12V1 {
        return Err(PrivateTransferV1Error::InvalidCommitmentEncoding);
    }
    let d = Digest4::from_bytes_checked(&c.digest)
        .ok_or(PrivateTransferV1Error::InvalidCommitmentEncoding)?;
    if d.is_single_limb_truncated() {
        return Err(PrivateTransferV1Error::InvalidCommitmentEncoding);
    }
    Ok(d)
}

/// Derive the canonical 256-bit nullifier for spending a note at `leaf_position`.
///
/// Convenience: exposed for wallet nullifier tracking.
///
/// # Errors
///
/// Returns [`PrivateTransferV1Error::TreeCapacityExceeded`] when `leaf_position >= 2^32`.
pub fn derive_note_nullifier(
    spend_key: &Digest4,
    rho: &Digest4,
    leaf_position: u64,
) -> Result<Digest4, PrivateTransferV1Error> {
    if leaf_position >= MAX_TREE_LEAVES {
        return Err(PrivateTransferV1Error::TreeCapacityExceeded);
    }
    let inner = wide_compress4(DOMAIN_NULLIFIER_A, spend_key.limbs(), rho.limbs());
    Ok(wide_compress4(
        DOMAIN_NULLIFIER_B,
        inner.limbs(),
        [leaf_position, 0, 0, 0],
    ))
}

/// Deterministically derive output note `output_index`'s `rho` from the first spent nullifier.
///
/// Ensures every created note across chain history receives a unique nullifier seed.
///
/// Convenience: exposed for shielded wallet output note construction.
#[must_use]
pub fn derive_output_rho(first_nullifier: &Digest4, output_index: u16) -> Digest4 {
    wide_compress4(
        DOMAIN_OUTPUT_RHO,
        first_nullifier.limbs(),
        [u64::from(output_index), 0, 0, 0],
    )
}

/// Compute a level-separated internal Merkle node digest for `level in 0..32`.
///
/// Convenience: exposed for Merkle opening verification.
#[must_use]
pub fn merkle_parent_v1(level: usize, left: &Digest4, right: &Digest4) -> Digest4 {
    let tag = DOMAIN_MERKLE_LEVEL_BASE.saturating_add(level as u64);
    wide_compress4(tag, left.limbs(), right.limbs())
}

/// Compute the canonical empty-leaf digest at level 0.
#[must_use]
fn empty_leaf_digest() -> Digest4 {
    wide_compress4(DOMAIN_EMPTY_LEAF, [0, 0, 0, 0], [0, 0, 0, 0])
}

/// Precompute the 33 zero-subtree roots (`level 0` empty leaf through `level 32`
/// empty tree root) so a depth-32 tree operates in `O(32)` time and memory.
fn zero_subtree_hashes() -> [Digest4; NOTE_TREE_DEPTH + 1] {
    let empty = empty_leaf_digest();
    let mut zeros = [empty; NOTE_TREE_DEPTH + 1];
    let mut cur = empty;
    for lvl in 0..NOTE_TREE_DEPTH {
        cur = merkle_parent_v1(lvl, &cur, &cur);
        if let Some(slot) = zeros.get_mut(lvl + 1) {
            *slot = cur;
        }
    }
    zeros
}

/// A private note in the `private_transfer_v1` shielded pool.
///
/// Convenience: exposed for shielded wallet note management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShieldedNoteV1 {
    /// Note value in base units; must satisfy `value <= MAX_NOTE_VALUE_V1` (`< 2^59`).
    pub value: u64,
    /// Recipient owner public key (`derive_owner_pk(&spend_key)`).
    pub owner_pk: Digest4,
    /// Nullifier uniqueness seed (deterministic for transfer outputs).
    pub rho: Digest4,
    /// Random commitment trapdoor hiding `(value, owner_pk, rho)`.
    pub rcm: Digest4,
}

/// Depth-32 Merkle authentication path for a single shielded note commitment.
///
/// Convenience: exposed for shielded wallet spend witness generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePathV1 {
    /// Zero-based leaf position in `[0, 2^32)`.
    pub leaf_position: u64,
    /// Sibling digests from level `0` (leaf sibling) up to level `31`.
    pub siblings: [Digest4; NOTE_TREE_DEPTH],
}

impl MerklePathV1 {
    /// Recompute the depth-32 Merkle root implied by `leaf` and `self`.
    ///
    /// Convenience: exposed for client-side path checks.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateTransferV1Error::TreeCapacityExceeded`] when `leaf_position >= 2^32`.
    pub fn compute_root(&self, leaf: &Digest4) -> Result<Digest4, PrivateTransferV1Error> {
        if self.leaf_position >= MAX_TREE_LEAVES {
            return Err(PrivateTransferV1Error::TreeCapacityExceeded);
        }
        let mut cur = *leaf;
        for (lvl, sib) in self.siblings.iter().enumerate() {
            let is_right = ((self.leaf_position >> lvl) & 1) == 1;
            cur = if is_right {
                merkle_parent_v1(lvl, sib, &cur)
            } else {
                merkle_parent_v1(lvl, &cur, sib)
            };
        }
        Ok(cur)
    }

    /// Return `true` iff `self` authenticates `leaf` under `expected_root`.
    ///
    /// Convenience: exposed for wallet and light-client verification.
    #[must_use]
    pub fn verifies(&self, leaf: &Digest4, expected_root: &Digest4) -> bool {
        self.compute_root(leaf)
            .is_ok_and(|computed| &computed == expected_root)
    }
}

/// Sparse depth-32 append-only Poseidon Merkle tree supporting `O(depth)` leaf
/// appends, exact historical root calculation, and `O(depth)` membership paths
/// for any previously inserted leaf.
///
/// Convenience: exposed for shielded pool state and wallet tree tracking.
#[derive(Debug, Clone)]
pub struct NoteCommitmentTreeV1 {
    next_index: u64,
    zeros: [Digest4; NOTE_TREE_DEPTH + 1],
    /// Non-default nodes keyed by `(level, index_at_level)`.
    nodes: BTreeMap<(u8, u64), Digest4>,
    root: Digest4,
}

impl Default for NoteCommitmentTreeV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteCommitmentTreeV1 {
    /// Create an empty depth-32 note commitment tree.
    ///
    /// Convenience: exposed for shielded pool initialization.
    #[must_use]
    pub fn new() -> Self {
        let zeros = zero_subtree_hashes();
        let root = zeros
            .get(NOTE_TREE_DEPTH)
            .copied()
            .unwrap_or_else(empty_leaf_digest);
        Self {
            next_index: 0,
            zeros,
            nodes: BTreeMap::new(),
            root,
        }
    }

    /// Current depth-32 Merkle root.
    ///
    /// Convenience: exposed for anchor root queries.
    #[must_use]
    pub const fn root(&self) -> Digest4 {
        self.root
    }

    /// Number of leaves appended so far.
    ///
    /// Convenience: exposed for pool inspection and tests.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.next_index
    }

    fn node_or_zero(&self, level: usize, index: u64) -> Digest4 {
        let key = (level as u8, index);
        self.nodes.get(&key).copied().unwrap_or_else(|| {
            self.zeros
                .get(level)
                .copied()
                .unwrap_or_else(empty_leaf_digest)
        })
    }

    /// Append a validated Poseidon note commitment, returning its assigned leaf
    /// position in `[0, 2^32)` and advancing [`Self::root`].
    ///
    /// Convenience: exposed for note insertion and transfer settlement.
    ///
    /// # Errors
    ///
    /// Refuses full trees or non-canonical/wrong-suite commitments without mutating state.
    pub fn append(
        &mut self,
        commitment: &SuiteTaggedCommitment,
    ) -> Result<u64, PrivateTransferV1Error> {
        if self.next_index >= MAX_TREE_LEAVES {
            return Err(PrivateTransferV1Error::TreeCapacityExceeded);
        }
        let leaf = unpack_poseidon_commitment(commitment)?;
        let pos = self.next_index;
        let mut idx = pos;
        let mut cur = leaf;
        self.nodes.insert((0, idx), cur);
        for lvl in 0..NOTE_TREE_DEPTH {
            let sib_idx = idx ^ 1;
            let sib = self.node_or_zero(lvl, sib_idx);
            let parent = if (idx & 1) == 1 {
                merkle_parent_v1(lvl, &sib, &cur)
            } else {
                merkle_parent_v1(lvl, &cur, &sib)
            };
            idx >>= 1;
            self.nodes.insert(((lvl + 1) as u8, idx), parent);
            cur = parent;
        }
        self.root = cur;
        self.next_index = pos + 1;
        Ok(pos)
    }

    /// Produce the depth-32 [`MerklePathV1`] for an appended leaf against the
    /// current [`Self::root`].
    ///
    /// Convenience: exposed for shielded wallet spend witness builders.
    ///
    /// # Errors
    ///
    /// Refuses `leaf_position >= self.leaf_count()`.
    pub fn open(&self, leaf_position: u64) -> Result<MerklePathV1, PrivateTransferV1Error> {
        if leaf_position >= self.next_index {
            return Err(PrivateTransferV1Error::TreeCapacityExceeded);
        }
        let empty = empty_leaf_digest();
        let mut siblings = [empty; NOTE_TREE_DEPTH];
        let mut idx = leaf_position;
        for (lvl, slot) in siblings.iter_mut().enumerate() {
            *slot = self.node_or_zero(lvl, idx ^ 1);
            idx >>= 1;
        }
        Ok(MerklePathV1 {
            leaf_position,
            siblings,
        })
    }
}

/// Private witness for one spent note (never serialized onto the wire).
///
/// Convenience: exposed for local wallet transfer proving.
#[derive(Debug, Clone)]
pub struct SpendWitnessV1 {
    pub spend_key: Digest4,
    pub note: ShieldedNoteV1,
    pub merkle_path: MerklePathV1,
}

/// Private specification for one newly created output note (`rho` is derived
/// deterministically from `nullifiers[0]` and the output index).
///
/// Convenience: exposed for local wallet transfer proving.
#[derive(Debug, Clone, Copy)]
pub struct OutputNoteDraftV1 {
    pub value: u64,
    pub recipient_owner_pk: Digest4,
    pub rcm: Digest4,
}

/// Public statement of a `private_transfer_v1` transaction.
///
mod serde_cm33_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S>(items: &[[u8; 33]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let slices: Vec<&[u8]> = items.iter().map(<[u8; 33]>::as_slice).collect();
        slices.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 33]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<Vec<u8>> = Vec::deserialize(deserializer)?;
        raw.into_iter()
            .map(|v| {
                let len = v.len();
                <[u8; 33]>::try_from(v)
                    .map_err(|_| serde::de::Error::invalid_length(len, &"33-byte suite commitment"))
            })
            .collect()
    }
}

/// Public statement of a `private_transfer_v1` spend.
///
/// Carries zero sender account identity and zero account signature; `fee` is
/// deducted directly from the conserved note balance inside the STARK.
///
/// Convenience: exposed for transaction encoding and consensus verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTransferV1PublicInputs {
    /// Target chain identifier preventing cross-network proof replay.
    pub chain_id: u64,
    /// Depth-32 note commitment tree root (`4 * 64 = 256` bits).
    pub anchor_root: [u8; 32],
    /// Nullifiers of the spent input notes (`1..=16`, each 256-bit canonical `Digest4`).
    pub nullifiers: Vec<[u8; 32]>,
    /// Suite-tagged 33-byte Poseidon commitments of created output notes (`1..=16`).
    #[serde(with = "serde_cm33_vec")]
    pub output_commitments: Vec<[u8; 33]>,
    /// Public fee paid directly out of the spent notes (`< 2^59`).
    pub fee: u64,
    /// 32-byte application/transaction context binding digest (for example
    /// expiry window, relayer fee recipient tag, or memo commitment).
    pub context_digest: [u8; 32],
}

/// Self-contained witness-hiding STARK proof for a `private_transfer_v1` spend.
///
/// Contains only public statement fields, `BudZKVM` execution public inputs,
/// and the blinded Plonky3 FRI package; no private keys, amounts, leaf indices,
/// or Merkle siblings appear anywhere in this struct.
///
/// Convenience: exposed for shielded transfer submission and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateTransferV1Proof {
    pub public_inputs: PrivateTransferV1PublicInputs,
    pub stark_inputs: ExecutionPublicInputs,
    pub hiding_package: HidingProofPackage,
}

struct ParsedPublicInputs {
    chain_id: u64,
    anchor: Digest4,
    nullifiers: Vec<Digest4>,
    outputs: Vec<(SuiteTaggedCommitment, Digest4)>,
    fee: u64,
    context_digest: [u8; 32],
}

impl PrivateTransferV1PublicInputs {
    fn parse_and_validate(&self) -> Result<ParsedPublicInputs, PrivateTransferV1Error> {
        let n_in = self.nullifiers.len();
        let n_out = self.output_commitments.len();
        if n_in == 0 || n_in > MAX_TRANSFER_V1_IO || n_out == 0 || n_out > MAX_TRANSFER_V1_IO {
            return Err(PrivateTransferV1Error::InvalidArity {
                inputs: n_in,
                outputs: n_out,
            });
        }
        if self.fee > MAX_NOTE_VALUE_V1 {
            return Err(PrivateTransferV1Error::ValueOutOfRange(self.fee));
        }
        let anchor = Digest4::from_bytes_checked(&self.anchor_root)
            .ok_or(PrivateTransferV1Error::InvalidCommitmentEncoding)?;
        if anchor.is_single_limb_truncated() {
            return Err(PrivateTransferV1Error::InvalidCommitmentEncoding);
        }

        let mut seen_nf = BTreeSet::new();
        let mut nullifiers = Vec::with_capacity(n_in);
        for raw_nf in &self.nullifiers {
            if !seen_nf.insert(*raw_nf) {
                return Err(PrivateTransferV1Error::DuplicateIdentifier("nullifier"));
            }
            let d = Digest4::from_bytes_checked(raw_nf)
                .ok_or(PrivateTransferV1Error::InvalidCommitmentEncoding)?;
            if d.is_single_limb_truncated() {
                return Err(PrivateTransferV1Error::InvalidCommitmentEncoding);
            }
            nullifiers.push(d);
        }

        let mut seen_out = BTreeSet::new();
        let mut outputs = Vec::with_capacity(n_out);
        for raw_cm in &self.output_commitments {
            let tagged = SuiteTaggedCommitment::decode(raw_cm)
                .ok_or(PrivateTransferV1Error::InvalidCommitmentEncoding)?;
            let d = unpack_poseidon_commitment(&tagged)?;
            if !seen_out.insert(tagged.digest) {
                return Err(PrivateTransferV1Error::DuplicateIdentifier(
                    "output_commitment",
                ));
            }
            if seen_nf.contains(&tagged.digest) {
                return Err(PrivateTransferV1Error::DuplicateIdentifier(
                    "output_collides_with_nullifier",
                ));
            }
            outputs.push((tagged, d));
        }

        Ok(ParsedPublicInputs {
            chain_id: self.chain_id,
            anchor,
            nullifiers,
            outputs,
            fee: self.fee,
            context_digest: self.context_digest,
        })
    }
}

/// Memory word layout for private witness seeding.
struct WitnessMemoryWriter {
    bytes: Vec<u8>,
    cursor: usize,
}

impl WitnessMemoryWriter {
    fn new(total_words: usize) -> Self {
        Self {
            bytes: vec![0u8; total_words.saturating_mul(WORD_BYTES)],
            cursor: 0,
        }
    }

    fn push_word(&mut self, value: u64) -> Result<(), PrivateTransferV1Error> {
        if value >= GOLDILOCKS_P {
            return Err(PrivateTransferV1Error::InvalidWitness(
                "non-canonical Goldilocks witness word".into(),
            ));
        }
        let start = self.cursor.checked_mul(WORD_BYTES).ok_or_else(|| {
            PrivateTransferV1Error::InvalidWitness("witness offset overflow".into())
        })?;
        let slice = self
            .bytes
            .get_mut(start..start + WORD_BYTES)
            .ok_or_else(|| PrivateTransferV1Error::InvalidWitness("witness buffer full".into()))?;
        slice.copy_from_slice(&value.to_le_bytes());
        self.cursor += 1;
        Ok(())
    }

    fn push_digest4(&mut self, d: &Digest4) -> Result<(), PrivateTransferV1Error> {
        for limb in d.limbs() {
            self.push_word(limb)?;
        }
        Ok(())
    }

    fn push_value_with_59_bits(&mut self, v: u64) -> Result<(), PrivateTransferV1Error> {
        if v > MAX_NOTE_VALUE_V1 {
            return Err(PrivateTransferV1Error::ValueOutOfRange(v));
        }
        self.push_word(v)?;
        for bit in 0..NOTE_VALUE_BITS {
            self.push_word((v >> bit) & 1)?;
        }
        Ok(())
    }
}

const fn words_per_input() -> usize {
    // value(1) + bits(59) + spend_key(4) + owner_pk(4) + rho(4) + rcm(4)
    // + 32 * (dir_bit(1) + sibling(4)) = 76 + 160 = 236 words
    1 + NOTE_VALUE_BITS + 16 + NOTE_TREE_DEPTH * 5
}

const fn words_per_output() -> usize {
    // value(1) + bits(59) + recipient_owner_pk(4) + rcm(4) = 68 words
    1 + NOTE_VALUE_BITS + 8
}

fn total_witness_words(n_in: usize, n_out: usize) -> usize {
    // inputs + outputs + fee_bits(59) + 4 guard words
    n_in * words_per_input() + n_out * words_per_output() + NOTE_VALUE_BITS + 4
}

#[inline]
fn enc(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
    Instruction {
        opcode,
        rd,
        rs1,
        rs2,
        imm,
    }
    .encode()
}

/// Emit straight-line instructions loading a canonical 64-bit constant into `dst`
/// (`R_ONE = 1` and `R_POW32 = 2^32` must be initialized; `R_T2` and `R_SCRATCH`
/// are clobbered).
fn emit_const_u64(prog: &mut Vec<u64>, dst: u8, value: u64) {
    let hi = (value >> 32) as u32;
    let lo = (value & 0xFFFF_FFFF) as u32;
    let emit_u32 = |half: u32, out: &mut Vec<u64>, reg: u8| {
        if let Ok(pos) = i32::try_from(half) {
            out.push(enc(Opcode::Load, reg, 0, 0, pos));
        } else {
            let low31 = i32::try_from(half - (1u32 << 31)).unwrap_or(0);
            out.push(enc(Opcode::Load, reg, 0, 0, low31));
            out.push(enc(Opcode::Load, R_SCRATCH, 0, 0, i32::MAX));
            out.push(enc(Opcode::Add, R_SCRATCH, R_SCRATCH, R_ONE, 0));
            out.push(enc(Opcode::Add, reg, reg, R_SCRATCH, 0));
        }
    };
    emit_u32(hi, prog, dst);
    prog.push(enc(Opcode::Mul, dst, dst, R_POW32, 0));
    emit_u32(lo, prog, R_T2);
    prog.push(enc(Opcode::Add, dst, dst, R_T2, 0));
}

/// Emit memory load of one 8-byte word at `word_cursor` and advance cursor.
fn emit_read_word(
    prog: &mut Vec<u64>,
    dst: u8,
    word_cursor: &mut usize,
) -> Result<(), PrivateTransferV1Error> {
    let byte_off = word_cursor
        .checked_mul(WORD_BYTES)
        .and_then(|b| i32::try_from(b).ok())
        .ok_or_else(|| {
            PrivateTransferV1Error::InvalidWitness("guest memory address overflow".into())
        })?;
    prog.push(enc(Opcode::Load, dst, R_ZERO, 0, byte_off));
    *word_cursor += 1;
    Ok(())
}

/// Emit `Assert(a == b)` using `Eq` + `Assert`.
fn emit_assert_eq(prog: &mut Vec<u64>, lhs: u8, rhs: u8) {
    prog.push(enc(Opcode::Eq, R_SCRATCH, lhs, rhs, 0));
    prog.push(enc(Opcode::Assert, 0, R_SCRATCH, 0, 0));
}

/// Emit `Assert(reg in {0, 1})` via `reg * (1 - reg) == 0`.
fn emit_assert_bit(prog: &mut Vec<u64>, bit_reg: u8) {
    prog.push(enc(Opcode::Sub, R_T2, R_ONE, bit_reg, 0));
    prog.push(enc(Opcode::Mul, R_T2, bit_reg, R_T2, 0));
    emit_assert_eq(prog, R_T2, R_ZERO);
}

/// Emit strict 59-bit range check verifying that `val_reg` equals the weighted
/// sum of the next 59 boolean-constrained witness words (`0 <= val < 2^59`).
fn emit_range_check_59(
    prog: &mut Vec<u64>,
    val_reg: u8,
    word_cursor: &mut usize,
) -> Result<(), PrivateTransferV1Error> {
    // R_T0 = reconstructed sum (0), R_POW2 = 2^0 (1).
    prog.push(enc(Opcode::Add, R_T0, R_ZERO, R_ZERO, 0));
    prog.push(enc(Opcode::Add, R_POW2, R_ONE, R_ZERO, 0));
    for bit in 0..NOTE_VALUE_BITS {
        emit_read_word(prog, R_T1, word_cursor)?;
        emit_assert_bit(prog, R_T1);
        prog.push(enc(Opcode::Mul, R_T3, R_T1, R_POW2, 0));
        prog.push(enc(Opcode::Add, R_T0, R_T0, R_T3, 0));
        if bit + 1 < NOTE_VALUE_BITS {
            prog.push(enc(Opcode::Add, R_POW2, R_POW2, R_POW2, 0));
        }
    }
    emit_assert_eq(prog, val_reg, R_T0);
    Ok(())
}

/// Emit the exact wide-pipe 4-limb compression `C = wide_compress4(tag, A, B)`.
///
/// Reads `left` from `R_A0..R_A3` and `right` from `R_B0..R_B3`, writes output
/// to `R_C0..R_C3` (`R_TAG`, `R_T0..R_T3`, `R_SCRATCH` are clobbered).
fn emit_wide_compress4(prog: &mut Vec<u64>, tag: u64) {
    emit_const_u64(prog, R_TAG, tag);
    prog.push(enc(Opcode::Poseidon, R_T0, R_A0, R_B0, 0));
    prog.push(enc(Opcode::Poseidon, R_T0, R_T0, R_TAG, 0));

    prog.push(enc(Opcode::Poseidon, R_T1, R_A1, R_B1, 0));
    prog.push(enc(Opcode::Poseidon, R_T1, R_T1, R_T0, 0));

    prog.push(enc(Opcode::Poseidon, R_T2, R_A2, R_B2, 0));
    prog.push(enc(Opcode::Poseidon, R_T2, R_T2, R_T1, 0));

    prog.push(enc(Opcode::Poseidon, R_T3, R_A3, R_B3, 0));
    prog.push(enc(Opcode::Poseidon, R_T3, R_T3, R_T2, 0));

    prog.push(enc(Opcode::Poseidon, R_C0, R_T0, R_T3, 0));
    prog.push(enc(Opcode::Poseidon, R_C1, R_T1, R_C0, 0));
    prog.push(enc(Opcode::Poseidon, R_C2, R_T2, R_C1, 0));
    prog.push(enc(Opcode::Poseidon, R_C3, R_T3, R_C2, 0));
}

/// Assert `R_C0..R_C3` equals a public 4-limb `Digest4` and fold each limb into
/// the rolling `R_LOG` transcript register.
fn emit_assert_and_log_digest4(prog: &mut Vec<u64>, expected: &Digest4, rolling_log: &mut u64) {
    let regs = [R_C0, R_C1, R_C2, R_C3];
    for (reg, limb) in regs.into_iter().zip(expected.limbs()) {
        emit_const_u64(prog, R_T0, limb);
        emit_assert_eq(prog, reg, R_T0);
        prog.push(enc(Opcode::Poseidon, R_LOG, R_LOG, reg, 0));
        *rolling_log = poseidon4_hash(*rolling_log, limb);
    }
}

/// Absorb a canonical public constant limb into both the guest's `R_LOG` and the
/// host's `rolling_log`.
fn emit_absorb_public_word(prog: &mut Vec<u64>, word: u64, rolling_log: &mut u64) {
    emit_const_u64(prog, R_T0, word);
    prog.push(enc(Opcode::Poseidon, R_LOG, R_LOG, R_T0, 0));
    *rolling_log = poseidon4_hash(*rolling_log, word);
}

/// Build the canonical straight-line `BudZKVM` circuit and expected `event_digest`
/// determined purely by `parsed` public inputs.
///
/// Both prover and verifier execute this identical builder: the verifier never
/// accepts program bytecode from the network.
fn build_transfer_v1_circuit(
    parsed: &ParsedPublicInputs,
) -> Result<(Vec<u64>, [u8; 32]), PrivateTransferV1Error> {
    let n_in = parsed.nullifiers.len();
    let n_out = parsed.outputs.len();
    let mut prog = Vec::with_capacity(n_in * 1_650 + n_out * 520 + 600);
    let mut cursor = 0usize;

    // Prologue: R_ZERO = 0, R_ONE = 1, R_POW32 = 2^32, R_SUM_IN = 0, R_SUM_OUT = 0.
    prog.push(enc(Opcode::Load, R_ZERO, 0, 0, 0));
    prog.push(enc(Opcode::Sub, R_ZERO, R_ZERO, R_ZERO, 0));
    prog.push(enc(Opcode::Load, R_ONE, 0, 0, 1));
    prog.push(enc(Opcode::Load, R_POW32, 0, 0, i32::MAX));
    prog.push(enc(Opcode::Add, R_POW32, R_POW32, R_ONE, 0));
    prog.push(enc(Opcode::Add, R_POW32, R_POW32, R_POW32, 0));
    prog.push(enc(Opcode::Add, R_SUM_IN, R_ZERO, R_ZERO, 0));
    prog.push(enc(Opcode::Add, R_SUM_OUT, R_ZERO, R_ZERO, 0));
    emit_const_u64(&mut prog, R_LOG, DOMAIN_TRANSCRIPT);
    let mut rolling_log = DOMAIN_TRANSCRIPT;

    // Bind chain_id, input/output counts, and all 256 bits of context_digest.
    emit_absorb_public_word(&mut prog, parsed.chain_id % GOLDILOCKS_P, &mut rolling_log);
    emit_absorb_public_word(
        &mut prog,
        u64::from(parsed.chain_id >= GOLDILOCKS_P),
        &mut rolling_log,
    );
    emit_absorb_public_word(&mut prog, n_in as u64, &mut rolling_log);
    emit_absorb_public_word(&mut prog, n_out as u64, &mut rolling_log);
    for chunk in parsed.context_digest.chunks_exact(8) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        let raw = u64::from_le_bytes(buf);
        emit_absorb_public_word(&mut prog, raw % GOLDILOCKS_P, &mut rolling_log);
        emit_absorb_public_word(&mut prog, u64::from(raw >= GOLDILOCKS_P), &mut rolling_log);
    }

    // Per-input ownership, < 2^59 range, commitment, depth-32 Merkle membership,
    // and nullifier derivation checks.
    for (in_idx, expected_nf) in parsed.nullifiers.iter().enumerate() {
        // 1. Read value and constrain 0 <= value < 2^59; accumulate sum_in.
        emit_read_word(&mut prog, R_VAL, &mut cursor)?;
        emit_range_check_59(&mut prog, R_VAL, &mut cursor)?;
        prog.push(enc(Opcode::Add, R_SUM_IN, R_SUM_IN, R_VAL, 0));

        // 2. Read spend_key (remember word offset so we can reload it for nullifier).
        let sk_word_base = cursor;
        emit_read_word(&mut prog, R_A0, &mut cursor)?;
        emit_read_word(&mut prog, R_A1, &mut cursor)?;
        emit_read_word(&mut prog, R_A2, &mut cursor)?;
        emit_read_word(&mut prog, R_A3, &mut cursor)?;
        emit_const_u64(&mut prog, R_B0, DOMAIN_OWNER_PK);
        prog.push(enc(Opcode::Load, R_B1, 0, 0, 1));
        prog.push(enc(Opcode::Load, R_B2, 0, 0, 2));
        prog.push(enc(Opcode::Load, R_B3, 0, 0, 3));
        emit_wide_compress4(&mut prog, DOMAIN_OWNER_PK);

        // 3. Read owner_pk and enforce owner_pk == derive_owner_pk(spend_key).
        emit_read_word(&mut prog, R_B0, &mut cursor)?;
        emit_read_word(&mut prog, R_B1, &mut cursor)?;
        emit_read_word(&mut prog, R_B2, &mut cursor)?;
        emit_read_word(&mut prog, R_B3, &mut cursor)?;
        emit_assert_eq(&mut prog, R_C0, R_B0);
        emit_assert_eq(&mut prog, R_C1, R_B1);
        emit_assert_eq(&mut prog, R_C2, R_B2);
        emit_assert_eq(&mut prog, R_C3, R_B3);

        // 4. Compute note commitment phase_a = compress(NOTE_COMMIT_A, [val,0,0,0], owner_pk).
        prog.push(enc(Opcode::Add, R_A0, R_VAL, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A1, R_ZERO, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A2, R_ZERO, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A3, R_ZERO, R_ZERO, 0));
        emit_wide_compress4(&mut prog, DOMAIN_NOTE_COMMIT_A);
        // Temporarily stash phase_a in R_POS/R_POW2? No: compute phase_b after moving phase_a.
        // We save phase_a into R_NF0_0..R_NF0_3 only for in_idx == 0 before nullifier is set,
        // or reload phase_a via owner_pk offset. Easier: compute phase_b first, keep it in B,
        // wait: wide_compress4 reads A and B and writes C! So read rho & rcm, compute phase_b -> C,
        // save phase_b into memory? No memory writes needed: remember owner_pk offset!
        let rho_word_base = cursor;
        emit_read_word(&mut prog, R_A0, &mut cursor)?;
        emit_read_word(&mut prog, R_A1, &mut cursor)?;
        emit_read_word(&mut prog, R_A2, &mut cursor)?;
        emit_read_word(&mut prog, R_A3, &mut cursor)?;
        emit_read_word(&mut prog, R_B0, &mut cursor)?;
        emit_read_word(&mut prog, R_B1, &mut cursor)?;
        emit_read_word(&mut prog, R_B2, &mut cursor)?;
        emit_read_word(&mut prog, R_B3, &mut cursor)?;
        // Save phase_a limbs (currently in R_C0..R_C3): recompute phase_b into C,
        // so first compute phase_a -> reload owner_pk? Instead, do phase_b now -> C,
        // move C -> B won't survive phase_a. We have 4 spare words only if we reload!
        // Let's keep guest state_writes_digest == 0 and reload phase_a? No, simply
        // save phase_a into R_POS, R_POW2, R_VAL (val already added to R_SUM_IN!) and
        // reload the 4th limb? Even cleaner: compute phase_a and save its 3 limbs in
        // R_VAL, R_POS, R_POW2 - wait we need 4 limbs! Use `Opcode::Push` / `Opcode::Pop`!
        // No: check if Push/Pop is simpler than Store to scratch memory at end of buffer.
        // Scratch memory after all witness words is already allocated (4 guard words)!
        let scratch_base = total_witness_words(n_in, n_out) - 4;
        for (k, c_reg) in [R_C0, R_C1, R_C2, R_C3].into_iter().enumerate() {
            let off = i32::try_from((scratch_base + k) * WORD_BYTES)
                .map_err(|_| PrivateTransferV1Error::InvalidWitness("scratch offset".into()))?;
            prog.push(enc(Opcode::Store, 0, R_ZERO, c_reg, off));
        }
        // Now R_A0..3 = rho, R_B0..3 = rcm -> phase_b in R_C0..3.
        emit_wide_compress4(&mut prog, DOMAIN_NOTE_COMMIT_B);
        // Move phase_b -> R_B0..3 and load phase_a -> R_A0..3.
        prog.push(enc(Opcode::Add, R_B0, R_C0, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B1, R_C1, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B2, R_C2, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B3, R_C3, R_ZERO, 0));
        for (k, a_reg) in [R_A0, R_A1, R_A2, R_A3].into_iter().enumerate() {
            let off = i32::try_from((scratch_base + k) * WORD_BYTES)
                .map_err(|_| PrivateTransferV1Error::InvalidWitness("scratch offset".into()))?;
            prog.push(enc(Opcode::Load, a_reg, R_ZERO, 0, off));
        }
        // note_commitment in R_C0..R_C3.
        emit_wide_compress4(&mut prog, DOMAIN_NOTE_COMMIT_FINAL);

        // 5. Depth-32 branchless Merkle fold + exact leaf_position reconstruction.
        prog.push(enc(Opcode::Add, R_POS, R_ZERO, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_POW2, R_ONE, R_ZERO, 0));
        for lvl in 0..NOTE_TREE_DEPTH {
            // Read direction bit `dir` into R_VAL and constrain dir in {0, 1}.
            emit_read_word(&mut prog, R_VAL, &mut cursor)?;
            emit_assert_bit(&mut prog, R_VAL);
            // pos += dir * 2^lvl; pow2 *= 2.
            prog.push(enc(Opcode::Mul, R_T0, R_VAL, R_POW2, 0));
            prog.push(enc(Opcode::Add, R_POS, R_POS, R_T0, 0));
            if lvl + 1 < NOTE_TREE_DEPTH {
                prog.push(enc(Opcode::Add, R_POW2, R_POW2, R_POW2, 0));
            }
            // Branchless 4-lane swap between current node (R_C0..3) and sibling:
            //   diff = sib - cur
            //   sel  = dir * diff
            //   left  = cur + sel   (= cur if dir==0, sib if dir==1)
            //   right = sib - sel   (= sib if dir==0, cur if dir==1)
            let pairs = [
                (R_C0, R_A0, R_B0),
                (R_C1, R_A1, R_B1),
                (R_C2, R_A2, R_B2),
                (R_C3, R_A3, R_B3),
            ];
            for (cur_r, left_r, right_r) in pairs {
                emit_read_word(&mut prog, R_T0, &mut cursor)?; // sibling limb
                prog.push(enc(Opcode::Sub, R_T1, R_T0, cur_r, 0));
                prog.push(enc(Opcode::Mul, R_T1, R_VAL, R_T1, 0));
                prog.push(enc(Opcode::Add, left_r, cur_r, R_T1, 0));
                prog.push(enc(Opcode::Sub, right_r, R_T0, R_T1, 0));
            }
            let level_tag = DOMAIN_MERKLE_LEVEL_BASE.saturating_add(lvl as u64);
            emit_wide_compress4(&mut prog, level_tag);
        }
        // Assert computed root == public anchor_root and bind into transcript.
        emit_assert_and_log_digest4(&mut prog, &parsed.anchor, &mut rolling_log);

        // 6. Nullifier derivation from SAME spend_key, SAME rho, and verified R_POS.
        let mut reload_sk = sk_word_base;
        emit_read_word(&mut prog, R_A0, &mut reload_sk)?;
        emit_read_word(&mut prog, R_A1, &mut reload_sk)?;
        emit_read_word(&mut prog, R_A2, &mut reload_sk)?;
        emit_read_word(&mut prog, R_A3, &mut reload_sk)?;
        let mut reload_rho = rho_word_base;
        emit_read_word(&mut prog, R_B0, &mut reload_rho)?;
        emit_read_word(&mut prog, R_B1, &mut reload_rho)?;
        emit_read_word(&mut prog, R_B2, &mut reload_rho)?;
        emit_read_word(&mut prog, R_B3, &mut reload_rho)?;
        emit_wide_compress4(&mut prog, DOMAIN_NULLIFIER_A);
        prog.push(enc(Opcode::Add, R_A0, R_C0, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A1, R_C1, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A2, R_C2, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A3, R_C3, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B0, R_POS, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B1, R_ZERO, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B2, R_ZERO, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B3, R_ZERO, R_ZERO, 0));
        emit_wide_compress4(&mut prog, DOMAIN_NULLIFIER_B);

        // Assert derived nullifier == public nullifiers[in_idx] and bind into transcript.
        emit_assert_and_log_digest4(&mut prog, expected_nf, &mut rolling_log);

        // Latch nullifiers[0] in dedicated registers for deterministic output rho.
        if in_idx == 0 {
            prog.push(enc(Opcode::Add, R_NF0_0, R_C0, R_ZERO, 0));
            prog.push(enc(Opcode::Add, R_NF0_1, R_C1, R_ZERO, 0));
            prog.push(enc(Opcode::Add, R_NF0_2, R_C2, R_ZERO, 0));
            prog.push(enc(Opcode::Add, R_NF0_3, R_C3, R_ZERO, 0));
        }
    }

    let scratch_base = total_witness_words(n_in, n_out) - 4;

    // Per-output < 2^59 range, deterministic output rho, and commitment checks.
    for (out_idx, (_tagged, expected_out_cm)) in parsed.outputs.iter().enumerate() {
        // 1. Read out_value, prove 0 <= out_value < 2^59, accumulate sum_out.
        emit_read_word(&mut prog, R_VAL, &mut cursor)?;
        emit_range_check_59(&mut prog, R_VAL, &mut cursor)?;
        prog.push(enc(Opcode::Add, R_SUM_OUT, R_SUM_OUT, R_VAL, 0));

        // 2. Read recipient_owner_pk -> compute phase_a and park in scratch.
        emit_read_word(&mut prog, R_B0, &mut cursor)?;
        emit_read_word(&mut prog, R_B1, &mut cursor)?;
        emit_read_word(&mut prog, R_B2, &mut cursor)?;
        emit_read_word(&mut prog, R_B3, &mut cursor)?;
        prog.push(enc(Opcode::Add, R_A0, R_VAL, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A1, R_ZERO, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A2, R_ZERO, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A3, R_ZERO, R_ZERO, 0));
        emit_wide_compress4(&mut prog, DOMAIN_NOTE_COMMIT_A);
        for (k, c_reg) in [R_C0, R_C1, R_C2, R_C3].into_iter().enumerate() {
            let off = i32::try_from((scratch_base + k) * WORD_BYTES)
                .map_err(|_| PrivateTransferV1Error::InvalidWitness("scratch offset".into()))?;
            prog.push(enc(Opcode::Store, 0, R_ZERO, c_reg, off));
        }

        // 3. Derive deterministic out_rho = derive_output_rho(nullifiers[0], out_idx).
        prog.push(enc(Opcode::Add, R_A0, R_NF0_0, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A1, R_NF0_1, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A2, R_NF0_2, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A3, R_NF0_3, R_ZERO, 0));
        prog.push(enc(Opcode::Load, R_B0, 0, 0, out_idx as i32));
        prog.push(enc(Opcode::Add, R_B1, R_ZERO, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B2, R_ZERO, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B3, R_ZERO, R_ZERO, 0));
        emit_wide_compress4(&mut prog, DOMAIN_OUTPUT_RHO);

        // 4. Move out_rho -> R_A0..3, read out_rcm -> R_B0..3, compute phase_b.
        prog.push(enc(Opcode::Add, R_A0, R_C0, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A1, R_C1, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A2, R_C2, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_A3, R_C3, R_ZERO, 0));
        emit_read_word(&mut prog, R_B0, &mut cursor)?;
        emit_read_word(&mut prog, R_B1, &mut cursor)?;
        emit_read_word(&mut prog, R_B2, &mut cursor)?;
        emit_read_word(&mut prog, R_B3, &mut cursor)?;
        emit_wide_compress4(&mut prog, DOMAIN_NOTE_COMMIT_B);

        // 5. Combine phase_a (from scratch) and phase_b -> final output commitment.
        prog.push(enc(Opcode::Add, R_B0, R_C0, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B1, R_C1, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B2, R_C2, R_ZERO, 0));
        prog.push(enc(Opcode::Add, R_B3, R_C3, R_ZERO, 0));
        for (k, a_reg) in [R_A0, R_A1, R_A2, R_A3].into_iter().enumerate() {
            let off = i32::try_from((scratch_base + k) * WORD_BYTES)
                .map_err(|_| PrivateTransferV1Error::InvalidWitness("scratch offset".into()))?;
            prog.push(enc(Opcode::Load, a_reg, R_ZERO, 0, off));
        }
        emit_wide_compress4(&mut prog, DOMAIN_NOTE_COMMIT_FINAL);
        emit_assert_and_log_digest4(&mut prog, expected_out_cm, &mut rolling_log);
    }

    // Fee range check (0 <= fee < 2^59) + balance conservation sum_in == sum_out + fee.
    emit_const_u64(&mut prog, R_VAL, parsed.fee);
    emit_range_check_59(&mut prog, R_VAL, &mut cursor)?;
    prog.push(enc(Opcode::Poseidon, R_LOG, R_LOG, R_VAL, 0));
    rolling_log = poseidon4_hash(rolling_log, parsed.fee);

    prog.push(enc(Opcode::Add, R_SUM_OUT, R_SUM_OUT, R_VAL, 0));
    emit_assert_eq(&mut prog, R_SUM_IN, R_SUM_OUT);

    // Emit rolling public transcript commitment and halt cleanly.
    prog.push(enc(Opcode::Log, 0, R_LOG, 0, 0));
    prog.push(enc(Opcode::Halt, 0, 0, 0, 0));

    let expected_event = bud_proof::event_digest_from_events(&[rolling_log]);
    Ok((prog, expected_event))
}

fn stark_program_hash(words: &[u64]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for w in words {
        h.update(w.to_le_bytes());
    }
    h.finalize().into()
}

/// Construct concrete output notes (with deterministically derived `rho`),
/// public inputs, and a witness-hiding Plonky3 STARK proof for a shielded
/// `private_transfer_v1` spend.
///
/// Fee is deducted directly from spent note values (`sum(inputs) == sum(outputs) + fee`);
/// no sender account or signature is accepted or emitted.
///
/// Convenience: exposed for shielded wallet transfer builders.
///
/// # Errors
///
/// Refuses invalid arities, values `>= 2^59`, unbalanced transfers, invalid
/// ownership or depth-32 Merkle paths, duplicate nullifiers/outputs, zero
/// blinding salt, or STARK proving failure.
pub fn prove_private_transfer_v1(
    chain_id: u64,
    anchor_root: Digest4,
    spends: &[SpendWitnessV1],
    output_drafts: &[OutputNoteDraftV1],
    fee: u64,
    context_digest: [u8; 32],
    blinding_salt: &[u8; 32],
) -> Result<(PrivateTransferV1Proof, Vec<ShieldedNoteV1>), PrivateTransferV1Error> {
    if *blinding_salt == [0u8; 32] {
        return Err(PrivateTransferV1Error::InvalidWitness(
            "blinding_salt must be non-zero".into(),
        ));
    }
    let n_in = spends.len();
    let n_out = output_drafts.len();
    if n_in == 0 || n_in > MAX_TRANSFER_V1_IO || n_out == 0 || n_out > MAX_TRANSFER_V1_IO {
        return Err(PrivateTransferV1Error::InvalidArity {
            inputs: n_in,
            outputs: n_out,
        });
    }
    if fee > MAX_NOTE_VALUE_V1 {
        return Err(PrivateTransferV1Error::ValueOutOfRange(fee));
    }

    let mut input_sum = 0u64;
    let mut nullifier_bytes = Vec::with_capacity(n_in);
    let mut first_nf: Option<Digest4> = None;

    for (idx, sp) in spends.iter().enumerate() {
        if sp.note.value > MAX_NOTE_VALUE_V1 {
            return Err(PrivateTransferV1Error::ValueOutOfRange(sp.note.value));
        }
        let derived_pk = derive_owner_pk(&sp.spend_key);
        if derived_pk != sp.note.owner_pk {
            return Err(PrivateTransferV1Error::OwnershipMismatch { input_index: idx });
        }
        let cm = compute_note_commitment(&sp.note)?;
        let cm_digest = unpack_poseidon_commitment(&cm)?;
        if !sp.merkle_path.verifies(&cm_digest, &anchor_root) {
            return Err(PrivateTransferV1Error::InvalidMerklePath { input_index: idx });
        }
        let nf = derive_note_nullifier(&sp.spend_key, &sp.note.rho, sp.merkle_path.leaf_position)?;
        if idx == 0 {
            first_nf = Some(nf);
        }
        nullifier_bytes.push(nf.to_bytes());
        input_sum = input_sum.saturating_add(sp.note.value);
    }

    let Some(nf0) = first_nf else {
        return Err(PrivateTransferV1Error::InvalidArity {
            inputs: n_in,
            outputs: n_out,
        });
    };

    let mut output_sum = 0u64;
    let mut created_notes = Vec::with_capacity(n_out);
    let mut output_cm_bytes = Vec::with_capacity(n_out);
    for (j, draft) in output_drafts.iter().enumerate() {
        if draft.value > MAX_NOTE_VALUE_V1 {
            return Err(PrivateTransferV1Error::ValueOutOfRange(draft.value));
        }
        let rho = derive_output_rho(&nf0, j as u16);
        let note = ShieldedNoteV1 {
            value: draft.value,
            owner_pk: draft.recipient_owner_pk,
            rho,
            rcm: draft.rcm,
        };
        let cm = compute_note_commitment(&note)?;
        created_notes.push(note);
        output_cm_bytes.push(cm.encode());
        output_sum = output_sum.saturating_add(draft.value);
    }

    let required_in =
        output_sum
            .checked_add(fee)
            .ok_or(PrivateTransferV1Error::BalanceMismatch {
                input_sum,
                output_sum,
                fee,
            })?;
    if input_sum != required_in {
        return Err(PrivateTransferV1Error::BalanceMismatch {
            input_sum,
            output_sum,
            fee,
        });
    }

    let public_inputs = PrivateTransferV1PublicInputs {
        chain_id,
        anchor_root: anchor_root.to_bytes(),
        nullifiers: nullifier_bytes,
        output_commitments: output_cm_bytes,
        fee,
        context_digest,
    };
    let parsed = public_inputs.parse_and_validate()?;

    // Populate private witness memory (never exported in the returned proof).
    let words = total_witness_words(n_in, n_out);
    let mut writer = WitnessMemoryWriter::new(words);
    for sp in spends {
        writer.push_value_with_59_bits(sp.note.value)?;
        writer.push_digest4(&sp.spend_key)?;
        writer.push_digest4(&sp.note.owner_pk)?;
        writer.push_digest4(&sp.note.rho)?;
        writer.push_digest4(&sp.note.rcm)?;
        for (lvl, sib) in sp.merkle_path.siblings.iter().enumerate() {
            writer.push_word((sp.merkle_path.leaf_position >> lvl) & 1)?;
            writer.push_digest4(sib)?;
        }
    }
    for note in &created_notes {
        writer.push_value_with_59_bits(note.value)?;
        writer.push_digest4(&note.owner_pk)?;
        writer.push_digest4(&note.rcm)?;
    }
    // Fee 59 bits (the fee scalar itself is a public immediate).
    for bit in 0..NOTE_VALUE_BITS {
        writer.push_word((fee >> bit) & 1)?;
    }

    let (program, expected_event) = build_transfer_v1_circuit(&parsed)?;
    let mem_bytes = writer.bytes.len().max(1024);
    let gas_limit = (program.len() as u64).saturating_mul(20).max(1_000_000);
    let mut vm = Vm::with_mainnet_mode(mem_bytes, gas_limit, true);
    if let Some(prefix) = vm.memory.get_mut(..writer.bytes.len()) {
        prefix.copy_from_slice(&writer.bytes);
    } else {
        return Err(PrivateTransferV1Error::InvalidWitness(
            "VM memory smaller than witness image".into(),
        ));
    }

    let receipt = vm.run_receipt(&program);
    if !receipt.success || receipt.exit_code != 0 {
        return Err(PrivateTransferV1Error::ProofRejected(format!(
            "circuit VM execution failed: {:?}",
            receipt.error
        )));
    }
    let event_digest = bud_proof::event_digest_from_events(&receipt.events);
    if event_digest != expected_event {
        return Err(PrivateTransferV1Error::ProofRejected(
            "circuit transcript event digest mismatch".into(),
        ));
    }

    let stark_inputs = ExecutionPublicInputs {
        chain_id,
        program_hash: stark_program_hash(&program),
        initial_state_root: bud_proof::initial_state_root_of(
            bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(
                &vm.trace,
            )),
            bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
                &vm.trace,
            )),
        ),
        final_state_root: receipt.state_writes_digest,
        sender: 0,
        nonce: 0,
        block_height: 0,
        gas_limit: vm.gas_limit,
        gas_used: receipt.gas_used,
        exit_code: receipt.exit_code,
        trace_len: receipt.trace_len,
        event_digest,
        state_writes_digest: receipt.state_writes_digest,
    };
    let hiding_package = prove_hiding(&vm.trace, &stark_inputs, &program, blinding_salt)
        .map_err(|e| PrivateTransferV1Error::ProofRejected(format!("{e:?}")))?;

    Ok((
        PrivateTransferV1Proof {
            public_inputs,
            stark_inputs,
            hiding_package,
        },
        created_notes,
    ))
}

/// Verify a `private_transfer_v1` zero-knowledge proof against `expected_chain_id`
/// and `expected_context_digest` using only public inputs and the verifier-rebuilt
/// circuit program.
///
/// Convenience: exposed for consensus verifiers, relayers, and pool settlement.
///
/// # Errors
///
/// Refuses invalid arities, range violations, duplicate nullifiers/outputs,
/// chain/context mismatch, sender/account metadata leakage, non-canonical
/// program hash or event digest, unblinded (`Open`) proofs, or invalid STARKs.
pub fn verify_private_transfer_v1(
    proof: &PrivateTransferV1Proof,
    expected_chain_id: u64,
    expected_context_digest: &[u8; 32],
) -> Result<(), PrivateTransferV1Error> {
    if proof.public_inputs.chain_id != expected_chain_id
        || proof.stark_inputs.chain_id != expected_chain_id
    {
        return Err(PrivateTransferV1Error::ContextMismatch("chain_id"));
    }
    if &proof.public_inputs.context_digest != expected_context_digest {
        return Err(PrivateTransferV1Error::ContextMismatch("context_digest"));
    }
    // Enforce zero sender account / nonce / block metadata leakage.
    if proof.stark_inputs.sender != 0
        || proof.stark_inputs.nonce != 0
        || proof.stark_inputs.block_height != 0
    {
        return Err(PrivateTransferV1Error::ContextMismatch(
            "unexpected sender or account context in stark_inputs",
        ));
    }
    if proof.stark_inputs.exit_code != 0 || proof.stark_inputs.trace_len == 0 {
        return Err(PrivateTransferV1Error::ProofRejected(
            "non-zero exit_code or empty trace".into(),
        ));
    }
    if proof.stark_inputs.state_writes_digest != [0u8; 32]
        || proof.stark_inputs.final_state_root != [0u8; 32]
    {
        return Err(PrivateTransferV1Error::ProofRejected(
            "unexpected storage writes in shielded transfer circuit".into(),
        ));
    }
    if proof.stark_inputs.initial_state_root == [0u8; 32] {
        return Err(PrivateTransferV1Error::ProofRejected(
            "missing private witness memory commitment".into(),
        ));
    }

    let parsed = proof.public_inputs.parse_and_validate()?;
    let (canonical_program, expected_event) = build_transfer_v1_circuit(&parsed)?;
    let canonical_hash = stark_program_hash(&canonical_program);

    if proof.stark_inputs.program_hash != canonical_hash {
        return Err(PrivateTransferV1Error::ProofRejected(
            "stark_inputs.program_hash does not match canonical transfer circuit".into(),
        ));
    }
    if proof.stark_inputs.event_digest != expected_event {
        return Err(PrivateTransferV1Error::ProofRejected(
            "stark_inputs.event_digest does not match public transcript".into(),
        ));
    }

    verify_with_class(
        &proof.hiding_package,
        &proof.stark_inputs,
        &canonical_program,
        ProofClass::Hiding,
    )
    .map_err(|e| PrivateTransferV1Error::ProofRejected(format!("{e:?}")))
}

/// Shielded pool state machine coupling a depth-32 [`NoteCommitmentTreeV1`] and nullifier set.
///
/// Tracks a bounded historical anchor ring and cumulative note-paid fees behind
/// the chain's privacy activation boundary.
///
/// Convenience: exposed for devnet shielded pool execution and opening audits.
#[derive(Debug, Clone)]
pub struct ShieldedPoolV1 {
    tree: NoteCommitmentTreeV1,
    anchor_history: VecDeque<[u8; 32]>,
    anchor_set: BTreeSet<[u8; 32]>,
    spent_nullifiers: BTreeSet<[u8; 32]>,
    known_commitments: BTreeSet<[u8; 32]>,
    collected_fees: u128,
}

impl Default for ShieldedPoolV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldedPoolV1 {
    /// Initialize an empty shielded pool seeded with the empty depth-32 root.
    ///
    /// Convenience: exposed for pool instantiation.
    #[must_use]
    pub fn new() -> Self {
        let tree = NoteCommitmentTreeV1::new();
        let initial = tree.root().to_bytes();
        let mut anchor_history = VecDeque::with_capacity(MAX_ANCHOR_HISTORY);
        anchor_history.push_back(initial);
        let mut anchor_set = BTreeSet::new();
        anchor_set.insert(initial);
        Self {
            tree,
            anchor_history,
            anchor_set,
            spent_nullifiers: BTreeSet::new(),
            known_commitments: BTreeSet::new(),
            collected_fees: 0,
        }
    }

    fn record_anchor(&mut self, root_bytes: [u8; 32]) {
        if self.anchor_set.insert(root_bytes) {
            self.anchor_history.push_back(root_bytes);
            while self.anchor_history.len() > MAX_ANCHOR_HISTORY {
                if let Some(evicted) = self.anchor_history.pop_front() {
                    self.anchor_set.remove(&evicted);
                }
            }
        }
    }

    /// Current depth-32 note commitment root.
    ///
    /// Convenience: exposed for wallet anchor selection.
    #[must_use]
    pub const fn current_anchor(&self) -> Digest4 {
        self.tree.root()
    }

    /// Whether `anchor` is currently accepted as a valid spend anchor.
    ///
    /// Convenience: exposed for mempool pre-checks.
    #[must_use]
    pub fn is_valid_anchor(&self, anchor: &[u8; 32]) -> bool {
        self.anchor_set.contains(anchor)
    }

    /// Whether `nullifier` has already been spent.
    ///
    /// Convenience: exposed for wallet and RPC nullifier queries.
    #[must_use]
    pub fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.spent_nullifiers.contains(nullifier)
    }

    /// Total fees collected directly from spent shielded notes.
    ///
    /// Convenience: exposed for fee accounting checks.
    #[must_use]
    pub const fn collected_fees(&self) -> u128 {
        self.collected_fees
    }

    /// Number of note commitments appended to the tree.
    ///
    /// Convenience: exposed for pool state inspection.
    #[must_use]
    pub const fn note_count(&self) -> u64 {
        self.tree.leaf_count()
    }

    /// Open the depth-32 Merkle path for `leaf_position` against the current root.
    ///
    /// Convenience: exposed for wallet spend witness construction.
    ///
    /// # Errors
    ///
    /// Refuses out-of-range leaf indices.
    pub fn open_note(&self, leaf_position: u64) -> Result<MerklePathV1, PrivateTransferV1Error> {
        self.tree.open(leaf_position)
    }

    /// Shield (deposit) a validated note commitment into the pool on an enabled chain.
    ///
    /// Convenience: exposed for initial note shielding on devnet.
    ///
    /// # Errors
    ///
    /// Fails closed without state mutation if `chain_id` has privacy closed, the
    /// commitment encoding is invalid, or the commitment already exists.
    pub fn shield_commitment(
        &mut self,
        chain_id: u64,
        commitment: &SuiteTaggedCommitment,
    ) -> Result<u64, PrivateTransferV1Error> {
        if !crate::core::chain_config::privacy_transfers_enabled(chain_id) {
            return Err(PrivateTransferV1Error::ChainClosed(chain_id));
        }
        let _ = unpack_poseidon_commitment(commitment)?;
        if self.known_commitments.contains(&commitment.digest)
            || self.spent_nullifiers.contains(&commitment.digest)
        {
            return Err(PrivateTransferV1Error::OutputCollision);
        }
        let pos = self.tree.append(commitment)?;
        self.known_commitments.insert(commitment.digest);
        self.record_anchor(self.tree.root().to_bytes());
        Ok(pos)
    }

    /// Atomically verify and apply a `private_transfer_v1` spend to the pool.
    ///
    /// Every gate (chain enablement, anchor validity, nullifier freshness, output
    /// uniqueness, tree capacity, fee arithmetic, and full Plonky3 hiding STARK
    /// verification) completes before a single set entry or Merkle node changes.
    ///
    /// Convenience: exposed for shielded pool settlement.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateTransferV1Error`] leaving the pool bit-for-bit unchanged.
    pub fn apply_transfer(
        &mut self,
        proof: &PrivateTransferV1Proof,
        expected_chain_id: u64,
        expected_context_digest: &[u8; 32],
    ) -> Result<Vec<u64>, PrivateTransferV1Error> {
        if !crate::core::chain_config::privacy_transfers_enabled(expected_chain_id) {
            return Err(PrivateTransferV1Error::ChainClosed(expected_chain_id));
        }
        let parsed = proof.public_inputs.parse_and_validate()?;
        if !self.is_valid_anchor(&proof.public_inputs.anchor_root) {
            return Err(PrivateTransferV1Error::UnknownAnchor);
        }
        for nf in &proof.public_inputs.nullifiers {
            if self.spent_nullifiers.contains(nf) || self.known_commitments.contains(nf) {
                return Err(PrivateTransferV1Error::NullifierAlreadySpent);
            }
        }
        for (tagged, _) in &parsed.outputs {
            if self.known_commitments.contains(&tagged.digest)
                || self.spent_nullifiers.contains(&tagged.digest)
            {
                return Err(PrivateTransferV1Error::OutputCollision);
            }
        }
        let projected_leaves = self
            .tree
            .leaf_count()
            .checked_add(parsed.outputs.len() as u64)
            .ok_or(PrivateTransferV1Error::TreeCapacityExceeded)?;
        if projected_leaves > MAX_TREE_LEAVES {
            return Err(PrivateTransferV1Error::TreeCapacityExceeded);
        }
        let next_fees = self
            .collected_fees
            .checked_add(u128::from(parsed.fee))
            .ok_or(PrivateTransferV1Error::FeeOverflow)?;

        // Full cryptographic proof check before any mutation.
        verify_private_transfer_v1(proof, expected_chain_id, expected_context_digest)?;

        // Commit phase: infallible given all pre-checks above.
        for nf in &proof.public_inputs.nullifiers {
            self.spent_nullifiers.insert(*nf);
        }
        let mut positions = Vec::with_capacity(parsed.outputs.len());
        for (tagged, _) in &parsed.outputs {
            let pos = self.tree.append(tagged)?;
            self.known_commitments.insert(tagged.digest);
            positions.push(pos);
        }
        self.collected_fees = next_fees;
        self.record_anchor(self.tree.root().to_bytes());
        Ok(positions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::chain_config::Network;

    fn sample_digest(seed: u64) -> Digest4 {
        Digest4::try_new([
            seed.wrapping_add(11),
            seed.wrapping_mul(17).wrapping_add(23),
            seed.wrapping_mul(31).wrapping_add(47),
            seed.wrapping_mul(53).wrapping_add(89),
        ])
        .expect("canonical sample digest")
    }

    #[test]
    fn depth32_tree_and_two_hop_private_transfer_with_note_paid_fee() {
        let devnet = Network::Devnet.chain_id().value();
        let testnet = Network::Testnet.chain_id().value();
        let mainnet = Network::Mainnet.chain_id().value();

        let mut pool = ShieldedPoolV1::new();

        // Alice holds two notes (700 + 300 = 1_000).
        let alice_sk = sample_digest(100);
        let alice_pk = derive_owner_pk(&alice_sk);
        let bob_sk = sample_digest(200);
        let bob_pk = derive_owner_pk(&bob_sk);

        let note0 = ShieldedNoteV1 {
            value: 700,
            owner_pk: alice_pk,
            rho: sample_digest(301),
            rcm: sample_digest(401),
        };
        let note1 = ShieldedNoteV1 {
            value: 300,
            owner_pk: alice_pk,
            rho: sample_digest(302),
            rcm: sample_digest(402),
        };
        let cm0 = compute_note_commitment(&note0).unwrap();
        let cm1 = compute_note_commitment(&note1).unwrap();

        // Public networks stay fail-closed with zero pool mutation.
        assert_eq!(
            pool.shield_commitment(testnet, &cm0),
            Err(PrivateTransferV1Error::ChainClosed(testnet))
        );
        assert_eq!(
            pool.shield_commitment(mainnet, &cm0),
            Err(PrivateTransferV1Error::ChainClosed(mainnet))
        );
        assert_eq!(pool.note_count(), 0);

        // Shield both notes on devnet and open genuine depth-32 paths.
        let pos0 = pool.shield_commitment(devnet, &cm0).unwrap();
        let pos1 = pool.shield_commitment(devnet, &cm1).unwrap();
        assert_eq!((pos0, pos1), (0, 1));
        let anchor = pool.current_anchor();
        let path0 = pool.open_note(pos0).unwrap();
        let path1 = pool.open_note(pos1).unwrap();
        assert_eq!(path0.siblings.len(), NOTE_TREE_DEPTH);

        // Alice spends (700 + 300) -> Bob (620) + Alice change (355) + fee (25).
        // Zero sender account, zero signature; fee comes out of the notes.
        let ctx1 = [0xA1u8; 32];
        let salt1 = [0x71u8; 32];
        let (proof1, created1) = prove_private_transfer_v1(
            devnet,
            anchor,
            &[
                SpendWitnessV1 {
                    spend_key: alice_sk,
                    note: note0,
                    merkle_path: path0,
                },
                SpendWitnessV1 {
                    spend_key: alice_sk,
                    note: note1,
                    merkle_path: path1,
                },
            ],
            &[
                OutputNoteDraftV1 {
                    value: 620,
                    recipient_owner_pk: bob_pk,
                    rcm: sample_digest(501),
                },
                OutputNoteDraftV1 {
                    value: 355,
                    recipient_owner_pk: alice_pk,
                    rcm: sample_digest(502),
                },
            ],
            25,
            ctx1,
            &salt1,
        )
        .expect("2-in-2-out transfer proof succeeds");

        // Verify deterministic output rho derivation from nullifiers[0].
        let nf0 = Digest4::from_bytes_checked(&proof1.public_inputs.nullifiers[0]).unwrap();
        assert_eq!(created1[0].rho, derive_output_rho(&nf0, 0));
        assert_eq!(created1[1].rho, derive_output_rho(&nf0, 1));
        assert_ne!(created1[0].rho, created1[1].rho);
        assert_eq!(proof1.stark_inputs.sender, 0);
        assert_eq!(proof1.stark_inputs.nonce, 0);

        // Tampered context, chain_id, fee, or anchor are refused.
        assert_eq!(
            verify_private_transfer_v1(&proof1, devnet, &[0xA2u8; 32]),
            Err(PrivateTransferV1Error::ContextMismatch("context_digest"))
        );
        assert_eq!(
            verify_private_transfer_v1(&proof1, testnet, &ctx1),
            Err(PrivateTransferV1Error::ContextMismatch("chain_id"))
        );
        let mut tampered_fee = proof1.clone();
        tampered_fee.public_inputs.fee = 24;
        assert!(verify_private_transfer_v1(&tampered_fee, devnet, &ctx1).is_err());

        // Settle transfer 1 and verify double-spend is refused without mutation.
        let out_positions = pool.apply_transfer(&proof1, devnet, &ctx1).unwrap();
        assert_eq!(out_positions, vec![2, 3]);
        assert_eq!(pool.collected_fees(), 25);
        assert_eq!(
            pool.apply_transfer(&proof1, devnet, &ctx1),
            Err(PrivateTransferV1Error::NullifierAlreadySpent)
        );
        assert_eq!(pool.collected_fees(), 25);

        // Hop 2: Bob spends his received 620 note -> 600 + fee 20.
        let anchor2 = pool.current_anchor();
        let bob_path = pool.open_note(out_positions[0]).unwrap();
        let ctx2 = [0xB2u8; 32];
        let (proof2, _) = prove_private_transfer_v1(
            devnet,
            anchor2,
            &[SpendWitnessV1 {
                spend_key: bob_sk,
                note: created1[0],
                merkle_path: bob_path,
            }],
            &[OutputNoteDraftV1 {
                value: 600,
                recipient_owner_pk: alice_pk,
                rcm: sample_digest(601),
            }],
            20,
            ctx2,
            &[0x72u8; 32],
        )
        .expect("Bob hop-2 spend succeeds");
        pool.apply_transfer(&proof2, devnet, &ctx2).unwrap();
        assert_eq!(pool.collected_fees(), 45);
        assert_eq!(pool.note_count(), 5);
    }

    #[test]
    fn refuses_range_overflow_wrong_key_bad_path_unbalanced_and_open_proof() {
        let devnet = Network::Devnet.chain_id().value();
        let mut pool = ShieldedPoolV1::new();
        let sk = sample_digest(1);
        let wrong_sk = sample_digest(2);
        let pk = derive_owner_pk(&sk);

        // Value at 2^59 is refused at note commitment and transfer boundary.
        let overflow_note = ShieldedNoteV1 {
            value: MAX_NOTE_VALUE_V1 + 1,
            owner_pk: pk,
            rho: sample_digest(10),
            rcm: sample_digest(11),
        };
        assert_eq!(
            compute_note_commitment(&overflow_note),
            Err(PrivateTransferV1Error::ValueOutOfRange(
                MAX_NOTE_VALUE_V1 + 1
            ))
        );

        let valid_note = ShieldedNoteV1 {
            value: 500,
            owner_pk: pk,
            rho: sample_digest(12),
            rcm: sample_digest(13),
        };
        let cm = compute_note_commitment(&valid_note).unwrap();
        let pos = pool.shield_commitment(devnet, &cm).unwrap();
        let anchor = pool.current_anchor();
        let path = pool.open_note(pos).unwrap();
        let draft = OutputNoteDraftV1 {
            value: 490,
            recipient_owner_pk: pk,
            rcm: sample_digest(14),
        };

        // Empty inputs and > 16 outputs are refused.
        assert_eq!(
            prove_private_transfer_v1(devnet, anchor, &[], &[draft], 10, [1u8; 32], &[9u8; 32])
                .unwrap_err(),
            PrivateTransferV1Error::InvalidArity {
                inputs: 0,
                outputs: 1,
            }
        );
        let too_many_outs = vec![draft; MAX_TRANSFER_V1_IO + 1];
        assert_eq!(
            prove_private_transfer_v1(
                devnet,
                anchor,
                &[SpendWitnessV1 {
                    spend_key: sk,
                    note: valid_note,
                    merkle_path: path.clone(),
                }],
                &too_many_outs,
                10,
                [1u8; 32],
                &[9u8; 32],
            )
            .unwrap_err(),
            PrivateTransferV1Error::InvalidArity {
                inputs: 1,
                outputs: MAX_TRANSFER_V1_IO + 1,
            }
        );

        // Wrong spend key is refused.
        assert_eq!(
            prove_private_transfer_v1(
                devnet,
                anchor,
                &[SpendWitnessV1 {
                    spend_key: wrong_sk,
                    note: valid_note,
                    merkle_path: path.clone(),
                }],
                &[draft],
                10,
                [1u8; 32],
                &[9u8; 32],
            )
            .unwrap_err(),
            PrivateTransferV1Error::OwnershipMismatch { input_index: 0 }
        );

        // Corrupted Merkle sibling is refused.
        let mut bad_path = path.clone();
        bad_path.siblings[17] = sample_digest(999);
        assert_eq!(
            prove_private_transfer_v1(
                devnet,
                anchor,
                &[SpendWitnessV1 {
                    spend_key: sk,
                    note: valid_note,
                    merkle_path: bad_path,
                }],
                &[draft],
                10,
                [1u8; 32],
                &[9u8; 32],
            )
            .unwrap_err(),
            PrivateTransferV1Error::InvalidMerklePath { input_index: 0 }
        );

        // Inflation (490 + 11 != 500) is refused.
        assert_eq!(
            prove_private_transfer_v1(
                devnet,
                anchor,
                &[SpendWitnessV1 {
                    spend_key: sk,
                    note: valid_note,
                    merkle_path: path.clone(),
                }],
                &[draft],
                11,
                [1u8; 32],
                &[9u8; 32],
            )
            .unwrap_err(),
            PrivateTransferV1Error::BalanceMismatch {
                input_sum: 500,
                output_sum: 490,
                fee: 11,
            }
        );

        // Downgrading the hiding package to `ProofClass::Open` is refused.
        let (mut valid_proof, _) = prove_private_transfer_v1(
            devnet,
            anchor,
            &[SpendWitnessV1 {
                spend_key: sk,
                note: valid_note,
                merkle_path: path,
            }],
            &[draft],
            10,
            [1u8; 32],
            &[9u8; 32],
        )
        .unwrap();
        valid_proof.hiding_package.class = ProofClass::Open;
        assert!(verify_private_transfer_v1(&valid_proof, devnet, &[1u8; 32]).is_err());
    }
}
