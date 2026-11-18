//! `AggMerge`: Phase 3 recursive merge program for `BudZKVM` (`BudAir`).
//!
//! Takes two child statements `(left_prog, left_pi)` and `(right_prog, right_pi)`
//! plus a `merge_pi` claim, checks inside `BudVM` that:
//! 1. Both child program hashes belong to the strict Phase 3 allowlist
//!    `{tick_program_hash, self_program_hash}` (an unauthorized child program
//!    hash fails the guest `Assert` instruction and never produces a valid proof).
//! 2. `left_pi`, `right_pi`, and `merge_pi` are published verbatim to the
//!    `BudAir` `state_writes_digest` commitment (24 `SWrite` slots = 96 bytes),
//!    while the single `Keccak-f[1600]` compression
//!    `merge_pi = H(TAG_AGG_MERGE || left_pi || right_pi)` is offloaded and
//!    cryptographically proven by [`bud_proof::chips::keccak::prove_bound_keccak_f`].
//!
//! Storing each 32-byte digest as 8 little-endian `u32` limbs keeps the guest
//! trace at **~208 VM steps** (`2^10 = 1,024` `BudAir` rows), proving in ~1.2 s
//! and verifying in ~57 ms under `MainnetActivation::default()`.
//!
//! WIRING: `StarkBackend` binds `agg_merge(&agg_tick_program_hash())` to derive
//! `agg_merge_program_hash()`.

use bud_vm::{poseidon_full_state, POSEIDON_WIDTH};
use sha3::{Digest, Keccak256};

pub use super::agg_merge_proof::{
    prove_agg_merge, run_agg_merge, verify_agg_merge, AggMergeProof, AggMergeRun, AggMergeWitness,
};
use super::asm::{Asm, AsmError, Program, R};
use crate::domain::types::Hash32;

/// Number of 32-bit little-endian limbs per 32-byte digest.
const LIMBS: usize = 8;

/// Cell offsets inside `AggMerge` guest memory.
#[derive(Debug, Clone, Copy)]
pub(super) struct MergeCells {
    pub(super) left_prog: u64,
    pub(super) left_pi: u64,
    pub(super) right_prog: u64,
    pub(super) right_pi: u64,
    pub(super) merge_pi: u64,
    pub(super) tick_prog: u64,
    pub(super) self_prog: u64,
}

/// Compiled `AggMerge` `BudVM` program together with its canonical program hash.
#[derive(Debug, Clone)]
pub struct AggMergeProgram {
    /// Compiled `BudVM` bytecode.
    pub program: Program,
    /// `Keccak-256` hash of `program.code` (little-endian `u64` instruction words).
    pub self_program_hash: Hash32,
    /// Allowlisted `AggTick` program hash baked into the guest contract.
    pub tick_program_hash: Hash32,
    pub(super) cells: MergeCells,
}

/// Errors produced by `AggMerge` compilation, execution, proving, or verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggMergeError {
    /// Guest assembly failed.
    Assemble(AsmError),
    /// Child program hash was not in `{tick_program_hash, self_program_hash}`.
    UnauthorizedChildProgram,
    /// `BudVM` halted with an error.
    VmFailed(String),
    /// `BudAir` or `BoundKeccakAir` proving failed.
    ProveFailed(String),
    /// Proof verification or commitment binding failed.
    VerifyFailed(String),
}

/// Computes the canonical `Keccak-256` hash of a compiled `BudVM` program's
/// `code` words (little-endian `u64` encoding).
#[must_use]
pub fn program_hash_of(code: &[u64]) -> Hash32 {
    let mut hasher = Keccak256::new();
    for word in code {
        hasher.update(word.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Computes the `BudVM` `receipt.state_writes_digest` for a digest list.
///
/// Each 32-byte digest is published consecutively as 8 little-endian 32-bit
/// `SWrite` calls (`slot 0..8`, `slot 8..16`, `slot 16..24`, ...).
#[must_use]
pub fn published_writes_digest_many(digests: &[&Hash32]) -> Hash32 {
    let mut acc = [0u64; 4];
    let mut slot = 0u64;
    for digest in digests {
        for chunk in digest.chunks_exact(4) {
            if let [b0, b1, b2, b3] = *chunk {
                let limb = u32::from_le_bytes([b0, b1, b2, b3]);
                let mut st = [0u64; POSEIDON_WIDTH];
                if let Some(first) = st.get_mut(0) {
                    *first = slot;
                }
                if let Some(second) = st.get_mut(1) {
                    *second = u64::from(limb);
                }
                for (dst, src) in st.iter_mut().skip(2).zip(acc.iter()) {
                    *dst = *src;
                }
                let out = poseidon_full_state(st);
                for (dst, src) in acc.iter_mut().zip(out.iter()) {
                    *dst = *src;
                }
                slot += 1;
            }
        }
    }
    let mut out = [0u8; 32];
    for (chunk, lane) in out.chunks_exact_mut(8).zip(acc.iter()) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// Emits guest instructions asserting that the 8-limb digest at `prog_cell`
/// equals either `tick_cell` or `self_cell`.
fn emit_check_allowlisted(a: &mut Asm, prog_cell: u64, tick_cell: u64, self_cell: u64) {
    let check_self = a.label();
    let ok_label = a.label();

    // Check equality with tick_prog.
    a.li(R[4], 0);
    for i in 0..LIMBS as u64 {
        a.load_abs(R[1], prog_cell + i);
        a.load_abs(R[2], tick_cell + i);
        a.neq(R[3], R[1], R[2]);
        a.add(R[4], R[4], R[3]);
    }
    a.jnz(R[4], check_self);
    a.jmp(ok_label);

    // Check equality with self_prog.
    a.bind(check_self);
    a.li(R[4], 0);
    for i in 0..LIMBS as u64 {
        a.load_abs(R[1], prog_cell + i);
        a.load_abs(R[2], self_cell + i);
        a.neq(R[3], R[1], R[2]);
        a.add(R[4], R[4], R[3]);
    }
    // R[5] = (R[4] == 0); Assert(R[5]) aborts if neither hash matched.
    a.li(R[6], 0);
    a.eq(R[5], R[4], R[6]);
    a.assert(R[5]);

    a.bind(ok_label);
}

/// Emits `SWrite` calls publishing the 8 limbs stored at `base_cell` to
/// consecutive state slots starting at `start_slot`.
fn emit_publish_digest(a: &mut Asm, base_cell: u64, start_slot: u32) {
    for i in 0..u32::try_from(LIMBS).unwrap_or(8) {
        a.load_abs(R[1], base_cell + u64::from(i));
        a.swrite(start_slot + i, R[1]);
    }
}

/// Compiles the canonical `AggMerge` `BudVM` guest program bound to
/// `tick_program_hash`.
///
/// # Errors
///
/// Returns [`AggMergeError::Assemble`] if guest bytecode assembly fails.
pub fn agg_merge(tick_program_hash: &Hash32) -> Result<AggMergeProgram, AggMergeError> {
    let mut a = Asm::new();
    let cells = MergeCells {
        left_prog: a.alloc(LIMBS as u64),
        left_pi: a.alloc(LIMBS as u64),
        right_prog: a.alloc(LIMBS as u64),
        right_pi: a.alloc(LIMBS as u64),
        merge_pi: a.alloc(LIMBS as u64),
        tick_prog: a.alloc(LIMBS as u64),
        self_prog: a.alloc(LIMBS as u64),
    };

    emit_check_allowlisted(&mut a, cells.left_prog, cells.tick_prog, cells.self_prog);
    emit_check_allowlisted(&mut a, cells.right_prog, cells.tick_prog, cells.self_prog);

    let limb_step = u32::try_from(LIMBS).unwrap_or(8);
    emit_publish_digest(&mut a, cells.left_pi, 0);
    emit_publish_digest(&mut a, cells.right_pi, limb_step);
    emit_publish_digest(&mut a, cells.merge_pi, limb_step.saturating_mul(2));
    a.halt();

    let program = a.finish().map_err(AggMergeError::Assemble)?;
    let self_program_hash = program_hash_of(&program.code);
    Ok(AggMergeProgram {
        program,
        self_program_hash,
        tick_program_hash: *tick_program_hash,
        cells,
    })
}
