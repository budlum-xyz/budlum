//! Hidden m-of-n multisig authorization program for Phase 4 (`Claim::Prog`).
//!
//! Neither the threshold `m`, nor the committee size `n`, nor any member key,
//! nor which `m` members signed appears on chain. The account stores only
//! `Account.auth_program_hash = Some(program_hash)`, and each authorized
//! transaction carries only:
//!
//! ```text
//! Claim::Prog {
//!     program_hash: account.auth_program_hash,
//!     input_hash: tx.signing_hash(),
//!     output_hash: AUTH_OK,
//! }
//! ```
//!
//! Inside `BudVM` (`BudAir`), the compiled bytecode bakes in a salted 128-bit
//! Poseidon commitment `(commit_lo, commit_hi)` to `(m, n, policy_salt, pk_0..pk_{n-1})`.
//! At proving time the private witness provides the hidden keyset, salt, and `m`
//! strictly-ordered distinct member witnesses `(idx_j, sk_j, sig_j)` where:
//! - `0 <= idx_0 < idx_1 < ... < idx_{m-1} < n` (forbids reusing a signer)
//! - `poseidon(sk_j, KEY_DERIVE_TAG) == pk[idx_j]`
//! - `poseidon(poseidon(sk_j, msg_lo), msg_hi) == sig_j`
//! - `SWrite[0..8] = msg_hash`, `SWrite[8..16] = AUTH_OK`.
//!
//! WIRING: unwired - wallet provers construct a `HiddenMultisigPolicy`, commit its
//! `program_hash` into `Account.auth_program_hash`, and submit the resulting
//! `StarkProofObject` via `claim_program_auth` onto `agg/object`.

use bud_vm::{poseidon4_hash, Vm};

use super::agg_merge::program_hash_of;
use super::asm::{Asm, Program, R};
use super::prog_claim::{
    emit_swrite_const_digest, emit_swrite_digest_cells, prove_vm_program, write_cell,
    write_digest_cells, ProgClaimError, StarkProofObject, DIGEST_LIMBS, DIGEST_LIMBS_U32,
};
use crate::aggregation::claim::GOLDILOCKS_MODULUS;
use crate::aggregation::hash::auth_ok;
use crate::domain::types::{DomainId, Hash32};

/// Maximum hidden committee size supported by the compiled circuit.
const MAX_MULTISIG_N: usize = 8;

/// Domain tag constant for `pk_i = poseidon(sk_i, KEY_DERIVE_TAG)`.
const KEY_DERIVE_TAG: u64 = 0x4244_4C4D_4B45_5931;
/// Domain tag constant for the low 64-bit policy commitment limb.
const POLICY_TAG_LO: u64 = 0x4244_4C4D_4D53_4731;
/// Domain tag constant for the high 64-bit policy commitment limb.
const POLICY_TAG_HI: u64 = 0x4244_4C4D_4D53_4732;
/// Domain tag constant for folding the 8-limb message hash inside `BudVM`.
const MSG_FOLD_TAG_LO: u64 = 0x4244_4C4D_4D53_4741;
/// Domain tag constant for the second fold of the 8-limb message hash.
const MSG_FOLD_TAG_HI: u64 = 0x4244_4C4D_4D53_4742;

/// Memory layout of a compiled hidden m-of-n multisig `BudVM` program.
#[derive(Debug, Clone, Copy)]
struct MultisigCells {
    msg_limbs: u64,
    policy_salt: u64,
    pks: u64,
    witnesses: u64,
}

/// Compiled hidden m-of-n multisig program bound to one off-chain policy.
#[derive(Debug, Clone)]
pub struct HiddenMultisigProgram {
    /// Compiled `BudVM` bytecode.
    pub program: Program,
    /// `Keccak-256` hash of `program.code` (stored on-chain in `Account.auth_program_hash`).
    pub program_hash: Hash32,
    /// Threshold `m` baked into the bytecode.
    pub threshold_m: usize,
    /// Committee size `n` baked into the bytecode.
    pub total_n: usize,
    cells: MultisigCells,
}

/// Off-chain secret policy of a hidden m-of-n multisig account.
#[derive(Debug, Clone)]
pub struct HiddenMultisigPolicy {
    /// Required distinct signers (`1 <= threshold_m <= member_secrets.len()`).
    pub threshold_m: usize,
    /// Secret Goldilocks scalars of all `n` hidden committee members.
    pub member_secrets: Vec<u64>,
    /// Derived Goldilocks public commitments `pk_i = poseidon(sk_i, KEY_DERIVE_TAG)`.
    pub member_pks: Vec<u64>,
    /// Blinding salt committed into the bytecode so two committees with
    /// overlapping keys never share a policy commitment.
    pub policy_salt: u64,
    /// Low 64-bit limb of the salted Poseidon policy commitment.
    pub commit_lo: u64,
    /// High 64-bit limb of the salted Poseidon policy commitment.
    pub commit_hi: u64,
}

/// One member's private witness entry supplied to the prover (never revealed on chain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberSignatureWitness {
    /// Member index in `0..n`.
    pub index: usize,
    /// Member secret scalar (`< GOLDILOCKS_MODULUS`).
    pub secret: u64,
    /// Signature scalar `poseidon(poseidon(secret, msg_lo), msg_hi)`.
    pub signature: u64,
}

/// Derives a member's hidden Goldilocks public key from their secret scalar.
#[must_use]
fn derive_member_pk(secret: u64) -> u64 {
    poseidon4_hash(secret % GOLDILOCKS_MODULUS, KEY_DERIVE_TAG)
}

/// Collapses a 32-byte message hash into two canonical Goldilocks field elements
/// using the exact Poseidon fold executed inside the `BudVM` guest.
#[must_use]
fn fold_message_hash(msg_hash: &Hash32) -> (u64, u64) {
    let mut lo = MSG_FOLD_TAG_LO;
    let mut hi = MSG_FOLD_TAG_HI;
    for chunk in msg_hash.as_chunks::<4>().0 {
        let limb = u64::from(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        lo = poseidon4_hash(lo, limb);
    }
    for chunk in msg_hash.as_chunks::<4>().0.iter().rev() {
        let limb = u64::from(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        hi = poseidon4_hash(hi, limb);
    }
    (lo, hi)
}

/// Signs `msg_hash` with one hidden member's secret scalar.
#[must_use]
fn sign_member(secret: u64, msg_hash: &Hash32) -> u64 {
    let (msg_lo, msg_hi) = fold_message_hash(msg_hash);
    let inner = poseidon4_hash(secret % GOLDILOCKS_MODULUS, msg_lo);
    poseidon4_hash(inner, msg_hi)
}

/// Computes the salted 128-bit Poseidon commitment `(commit_lo, commit_hi)` to
/// `(threshold_m, pks, policy_salt)`.
#[must_use]
fn compute_policy_commitment(threshold_m: usize, pks: &[u64], policy_salt: u64) -> (u64, u64) {
    let m = threshold_m as u64;
    let n = pks.len() as u64;
    let salt = policy_salt % GOLDILOCKS_MODULUS;

    let mut lo = poseidon4_hash(POLICY_TAG_LO, m);
    lo = poseidon4_hash(lo, n);
    lo = poseidon4_hash(lo, salt);
    for &pk in pks {
        lo = poseidon4_hash(lo, pk);
    }

    let mut hi = poseidon4_hash(POLICY_TAG_HI, salt);
    hi = poseidon4_hash(hi, n);
    hi = poseidon4_hash(hi, m);
    for &pk in pks.iter().rev() {
        hi = poseidon4_hash(hi, pk);
    }
    (lo, hi)
}

impl HiddenMultisigPolicy {
    /// Builds a new off-chain hidden m-of-n multisig policy.
    ///
    /// # Errors
    ///
    /// Returns [`ProgClaimError::InvalidInput`] if `threshold_m == 0`,
    /// `member_secrets.is_empty()`, `threshold_m > member_secrets.len()`,
    /// `member_secrets.len() > MAX_MULTISIG_N`, or any scalar is out of field.
    pub fn new(
        threshold_m: usize,
        member_secrets: Vec<u64>,
        policy_salt: u64,
    ) -> Result<Self, ProgClaimError> {
        let n = member_secrets.len();
        if threshold_m == 0 || n == 0 || threshold_m > n || n > MAX_MULTISIG_N {
            return Err(ProgClaimError::InvalidInput(
                "threshold_m and committee size n must satisfy 1 <= m <= n <= 8",
            ));
        }
        if policy_salt >= GOLDILOCKS_MODULUS
            || member_secrets.iter().any(|&sk| sk >= GOLDILOCKS_MODULUS)
        {
            return Err(ProgClaimError::InvalidInput(
                "secret or policy_salt exceeds Goldilocks modulus",
            ));
        }
        let member_pks: Vec<u64> = member_secrets
            .iter()
            .map(|&sk| derive_member_pk(sk))
            .collect();
        let (commit_lo, commit_hi) =
            compute_policy_commitment(threshold_m, &member_pks, policy_salt);
        Ok(Self {
            threshold_m,
            member_secrets,
            member_pks,
            policy_salt,
            commit_lo,
            commit_hi,
        })
    }

    /// Compiles the `BudVM` authorization program bound to this hidden policy.
    ///
    /// # Errors
    ///
    /// Propagates compilation errors from [`compile_hidden_multisig`].
    pub fn compile(&self) -> Result<HiddenMultisigProgram, ProgClaimError> {
        compile_hidden_multisig(
            self.threshold_m,
            self.member_pks.len(),
            self.commit_lo,
            self.commit_hi,
        )
    }

    /// Produces a valid witness entry for committee member `index` signing `msg_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`ProgClaimError::InvalidInput`] if `index >= n`.
    pub fn sign_as(
        &self,
        index: usize,
        msg_hash: &Hash32,
    ) -> Result<MemberSignatureWitness, ProgClaimError> {
        let &secret = self
            .member_secrets
            .get(index)
            .ok_or(ProgClaimError::InvalidInput("signer index out of range"))?;
        Ok(MemberSignatureWitness {
            index,
            secret,
            signature: sign_member(secret, msg_hash),
        })
    }
}

/// Compiles a hidden m-of-n multisig `BudVM` program whose bytecode commits to
/// `(threshold_m, total_n, commit_lo, commit_hi)` and publishes `(msg_hash, AUTH_OK)`.
///
/// # Errors
///
/// Returns [`ProgClaimError`] if parameters are invalid or assembly fails.
pub fn compile_hidden_multisig(
    threshold_m: usize,
    total_n: usize,
    commit_lo: u64,
    commit_hi: u64,
) -> Result<HiddenMultisigProgram, ProgClaimError> {
    if threshold_m == 0 || total_n == 0 || threshold_m > total_n || total_n > MAX_MULTISIG_N {
        return Err(ProgClaimError::InvalidInput(
            "threshold_m and committee size n must satisfy 1 <= m <= n <= 8",
        ));
    }

    let mut a = Asm::new();
    let cells = MultisigCells {
        msg_limbs: a.alloc(DIGEST_LIMBS as u64),
        policy_salt: a.alloc(1),
        pks: a.alloc(total_n as u64),
        witnesses: a.alloc((threshold_m as u64) * 3),
    };

    // 1. Fold the 8-limb msg_hash into (R[10] = msg_lo, R[11] = msg_hi).
    a.region("fold_message");
    a.li(R[10], MSG_FOLD_TAG_LO);
    for i in 0..DIGEST_LIMBS as u64 {
        a.load_abs(R[1], cells.msg_limbs + i);
        a.poseidon(R[10], R[10], R[1]);
    }
    a.li(R[11], MSG_FOLD_TAG_HI);
    for i in (0..DIGEST_LIMBS as u64).rev() {
        a.load_abs(R[1], cells.msg_limbs + i);
        a.poseidon(R[11], R[11], R[1]);
    }

    // 2. Recompute salted policy commitment over private (salt, pk_0..pk_{n-1})
    //    and Assert equality with the baked-in (commit_lo, commit_hi).
    a.region("verify_policy_commitment");
    a.load_abs(R[2], cells.policy_salt);
    a.li(R[3], threshold_m as u64);
    a.li(R[4], total_n as u64);

    a.li(R[5], POLICY_TAG_LO);
    a.poseidon(R[5], R[5], R[3]);
    a.poseidon(R[5], R[5], R[4]);
    a.poseidon(R[5], R[5], R[2]);
    for k in 0..total_n as u64 {
        a.load_abs(R[1], cells.pks + k);
        a.poseidon(R[5], R[5], R[1]);
    }
    a.li(R[6], commit_lo);
    a.eq(R[7], R[5], R[6]);
    a.assert(R[7]);

    a.li(R[5], POLICY_TAG_HI);
    a.poseidon(R[5], R[5], R[2]);
    a.poseidon(R[5], R[5], R[4]);
    a.poseidon(R[5], R[5], R[3]);
    for k in (0..total_n as u64).rev() {
        a.load_abs(R[1], cells.pks + k);
        a.poseidon(R[5], R[5], R[1]);
    }
    a.li(R[6], commit_hi);
    a.eq(R[7], R[5], R[6]);
    a.assert(R[7]);

    // 3. Verify m distinct member signatures with strictly increasing indices
    //    0 <= idx_0 < idx_1 < ... < idx_{m-1} < n.
    a.region("verify_member_signatures");
    a.li(R[18], KEY_DERIVE_TAG);
    a.li(R[19], total_n as u64);
    for j in 0..threshold_m as u64 {
        let base = cells.witnesses + j * 3;
        a.load_abs(R[20], base); // idx_j
        a.load_abs(R[21], base + 1); // sk_j
        a.load_abs(R[22], base + 2); // sig_j

        // Bounds check: idx_j < n
        a.lt(R[1], R[20], R[19]);
        a.assert(R[1]);

        // Strict ordering check against previous index (prevents duplicate signers).
        if j > 0 {
            a.lt(R[1], R[23], R[20]);
            a.assert(R[1]);
        }
        a.mov(R[23], R[20]);

        // Branchless mux: R[12] = pks[idx_j].
        a.li(R[12], 0);
        for k in 0..total_n as u64 {
            a.li(R[13], k);
            a.eq(R[14], R[20], R[13]);
            a.load_abs(R[15], cells.pks + k);
            a.mul(R[16], R[14], R[15]);
            a.add(R[12], R[12], R[16]);
        }

        // Assert derived public key matches committed pk[idx_j].
        a.poseidon(R[17], R[21], R[18]);
        a.eq(R[1], R[17], R[12]);
        a.assert(R[1]);

        // Assert member signature over (msg_lo, msg_hi) matches sig_j.
        a.poseidon(R[17], R[21], R[10]);
        a.poseidon(R[17], R[17], R[11]);
        a.eq(R[1], R[17], R[22]);
        a.assert(R[1]);
    }

    // 4. Publish (input_hash = msg_hash, output_hash = AUTH_OK) via SWrite[0..16].
    a.region("publish_claim_io");
    emit_swrite_digest_cells(&mut a, cells.msg_limbs, 0);
    let auth_ok_digest = auth_ok();
    emit_swrite_const_digest(&mut a, &auth_ok_digest, DIGEST_LIMBS_U32);
    a.halt();

    let program = a.finish()?;
    let program_hash = program_hash_of(&program.code);
    Ok(HiddenMultisigProgram {
        program,
        program_hash,
        threshold_m,
        total_n,
        cells,
    })
}

/// Proves a hidden m-of-n multisig authorization over `msg_hash`.
///
/// Uses the supplied member signature witnesses to produce a 128-bit `BudAir`
/// [`StarkProofObject`] whose derived claim is
/// `Claim::Prog { program_hash, input_hash: msg_hash, output_hash: AUTH_OK }`.
///
/// # Errors
///
/// Returns [`ProgClaimError::AssertionFailed`] if any signature, secret,
/// signer ordering, or keyset witness fails the guest `Assert` checks.
pub fn prove_hidden_multisig_with_witnesses(
    compiled: &HiddenMultisigProgram,
    policy_salt: u64,
    member_pks: &[u64],
    witnesses: &[MemberSignatureWitness],
    msg_hash: Hash32,
    domain: DomainId,
) -> Result<StarkProofObject, ProgClaimError> {
    if member_pks.len() != compiled.total_n {
        return Err(ProgClaimError::InvalidInput(
            "member_pks length must match compiled committee size",
        ));
    }
    if witnesses.len() != compiled.threshold_m {
        return Err(ProgClaimError::InvalidInput(
            "witnesses length must match compiled threshold m",
        ));
    }
    let mem_bytes = usize::try_from(compiled.program.memory_cells)
        .unwrap_or(0)
        .saturating_add(16)
        .saturating_mul(8);
    let mut vm = Vm::new(mem_bytes.max(4096));
    write_digest_cells(&mut vm, compiled.cells.msg_limbs, &msg_hash);
    write_cell(&mut vm, compiled.cells.policy_salt, policy_salt);
    for (k, &pk) in member_pks.iter().enumerate() {
        write_cell(&mut vm, compiled.cells.pks + k as u64, pk);
    }
    for (j, w) in witnesses.iter().enumerate() {
        let base = compiled.cells.witnesses + (j as u64) * 3;
        write_cell(&mut vm, base, w.index as u64);
        write_cell(&mut vm, base + 1, w.secret);
        write_cell(&mut vm, base + 2, w.signature);
    }

    prove_vm_program(&compiled.program.code, &mut vm, msg_hash, auth_ok(), domain)
}

/// Convenience helper that compiles `policy`, signs `msg_hash` with the chosen
/// `signer_indices`, and produces the `BudAir` [`StarkProofObject`].
///
/// # Errors
///
/// Propagates errors from policy compilation, signing, or proving.
pub fn prove_hidden_multisig_auth(
    policy: &HiddenMultisigPolicy,
    signer_indices: &[usize],
    msg_hash: Hash32,
    domain: DomainId,
) -> Result<(HiddenMultisigProgram, StarkProofObject), ProgClaimError> {
    let compiled = policy.compile()?;
    let mut witnesses = Vec::with_capacity(signer_indices.len());
    for &idx in signer_indices {
        witnesses.push(policy.sign_as(idx, &msg_hash)?);
    }
    let obj = prove_hidden_multisig_with_witnesses(
        &compiled,
        policy.policy_salt,
        &policy.member_pks,
        &witnesses,
        msg_hash,
        domain,
    )?;
    Ok((compiled, obj))
}
