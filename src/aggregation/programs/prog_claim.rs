//! Phase 4 program claims: `ObjectKind::StarkProof` -> `Claim::Prog`.
//!
//! Every `BudZKVM` program claim follows one canonical guest ABI:
//! 1. The guest program executes on `BudVM` under `MainnetActivation::default()`
//!    (so `VerifyMerkle` stays off in production).
//! 2. The guest checks its private or public predicate with `Assert` and halts
//!    with `exit_code == 0`.
//! 3. The guest publishes `input_hash` (8 little-endian `u32` limbs in storage
//!    slots `0..8`) and `output_hash` (8 little-endian `u32` limbs in storage
//!    slots `8..16`) via `SWrite`.
//!
//! [`verify_vm_proof`] checks `program_hash == keccak256(program)`,
//! `chain_id == domain`, `exit_code == 0`,
//! `state_writes_digest == published_writes_digest_many(&[&input_hash, &output_hash])`,
//! and verifies the 128-bit `BudAir` proof with [`Plonky3Adapter::verify`].

use std::io::{Read, Write};

use bincode::Options;
use bud_proof::adapter::{
    initial_state_root_of, memory_image_commitment_of_reads, register_image_commitment_of_reads,
    ExecutionPublicInputs, ProofEnvelope, ProverAdapter,
};
use bud_proof::plonky3_prover::{initial_memory_reads, initial_register_reads, Plonky3Adapter};
use bud_vm::{Vm, VmError};
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

use super::agg_merge::{program_hash_of, published_writes_digest_many};
use super::asm::{Asm, AsmError, R};
use crate::aggregation::claim::Claim;
use crate::aggregation::envelope::{Envelope, ObjectKind};
use crate::aggregation::object::ObjectError;
use crate::crypto::scheme::SchemeId;
use crate::domain::types::{DomainId, Hash32};

/// Magic prefix of an encoded [`StarkProofObject`].
const MAGIC: [u8; 4] = *b"BDP4";
/// Current wire format version.
const VERSION: u8 = 1;
/// Payload compression flag: uncompressed bincode body.
const ENCODING_RAW: u8 = 0;
/// Payload compression flag: raw deflate-compressed bincode body.
const ENCODING_DEFLATE: u8 = 1;

/// Maximum instruction words in a `StarkProofObject` guest program.
const MAX_PROG_WORDS: usize = 4_096;
/// Hard cap on decompressed bytes inside a `StarkProofObject` (prevents zip-bomb `DoS`).
const MAX_DECOMPRESSED_STARK_BYTES: usize = 4 * 1024 * 1024;
/// Number of 32-bit little-endian limbs per 32-byte digest.
pub(crate) const DIGEST_LIMBS: usize = 8;
/// Number of 32-bit limbs per digest as `u32`.
pub(crate) const DIGEST_LIMBS_U32: u32 = 8;

/// Errors returned when building or proving a Phase 4 program claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgClaimError {
    /// Guest assembly failed.
    Assemble(AsmError),
    /// Invalid policy or transition parameter.
    InvalidInput(&'static str),
    /// Guest execution aborted on an `Assert` instruction.
    AssertionFailed,
    /// `BudVM` halted with another error.
    VmFailed(String),
    /// `BudAir` STARK proving failed.
    ProveFailed(String),
    /// Canonical object encoding failed.
    EncodeFailed(String),
}

impl std::fmt::Display for ProgClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Assemble(e) => write!(f, "assemble program: {e}"),
            Self::InvalidInput(msg) => write!(f, "invalid program input: {msg}"),
            Self::AssertionFailed => write!(f, "guest program assertion failed"),
            Self::VmFailed(msg) => write!(f, "BudVM execution failed: {msg}"),
            Self::ProveFailed(msg) => write!(f, "BudAir proving failed: {msg}"),
            Self::EncodeFailed(msg) => write!(f, "stark object encoding failed: {msg}"),
        }
    }
}

impl std::error::Error for ProgClaimError {}

impl From<AsmError> for ProgClaimError {
    fn from(value: AsmError) -> Self {
        Self::Assemble(value)
    }
}

/// Canonical payload carried inside `Envelope { kind: ObjectKind::StarkProof }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkProofObject {
    /// Compiled `BudVM` program words.
    pub program: Vec<u64>,
    /// Program input commitment bound into `SWrite` slots `0..8`.
    pub input_hash: Hash32,
    /// Program output commitment bound into `SWrite` slots `8..16`.
    pub output_hash: Hash32,
    /// Public inputs verified against the `BudAir` STARK proof.
    pub public_inputs: ExecutionPublicInputs,
    /// 128-bit `BudAir` Plonky3 STARK proof envelope.
    pub proof_envelope: ProofEnvelope,
}

impl StarkProofObject {
    /// Serializes this proof object canonically, using bounded deflate
    /// compression whenever it reduces wire size.
    ///
    /// # Errors
    ///
    /// Returns [`ProgClaimError::EncodeFailed`] if serialization exceeds bounds.
    pub fn encode(&self) -> Result<Vec<u8>, ProgClaimError> {
        let raw = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_DECOMPRESSED_STARK_BYTES as u64)
            .serialize(self)
            .map_err(|e| ProgClaimError::EncodeFailed(e.to_string()))?;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&raw)
            .map_err(|e| ProgClaimError::EncodeFailed(e.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|e| ProgClaimError::EncodeFailed(e.to_string()))?;

        let (flag, body) = if compressed.len() < raw.len() {
            (ENCODING_DEFLATE, compressed)
        } else {
            (ENCODING_RAW, raw)
        };

        let mut out = Vec::with_capacity(6 + body.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(flag);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decodes a [`StarkProofObject`] with strict parse-time and
    /// decompression-time byte caps.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectError::Invalid`] if the header, compression stream,
    /// bounds, or inner bincode payload are malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, ObjectError> {
        let Some((header, body)) = bytes.split_at_checked(6) else {
            return Err(ObjectError::Invalid);
        };
        let [m0, m1, m2, m3, ver, flag] = *header else {
            return Err(ObjectError::Invalid);
        };
        if [m0, m1, m2, m3] != MAGIC || ver != VERSION {
            return Err(ObjectError::Invalid);
        }
        let raw = match flag {
            ENCODING_RAW => {
                if body.len() > MAX_DECOMPRESSED_STARK_BYTES {
                    return Err(ObjectError::Invalid);
                }
                body.to_vec()
            }
            ENCODING_DEFLATE => {
                let mut decoder = DeflateDecoder::new(body)
                    .take((MAX_DECOMPRESSED_STARK_BYTES as u64).saturating_add(1));
                let mut buf = Vec::new();
                decoder
                    .read_to_end(&mut buf)
                    .map_err(|_| ObjectError::Invalid)?;
                if buf.len() > MAX_DECOMPRESSED_STARK_BYTES {
                    return Err(ObjectError::Invalid);
                }
                buf
            }
            _ => return Err(ObjectError::Invalid),
        };
        let obj: Self = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_DECOMPRESSED_STARK_BYTES as u64)
            .deserialize(&raw)
            .map_err(|_| ObjectError::Invalid)?;
        if obj.program.is_empty() || obj.program.len() > MAX_PROG_WORDS {
            return Err(ObjectError::Invalid);
        }
        Ok(obj)
    }

    /// Wraps this proof object in an aggregation [`Envelope`] for `domain` and `tx_hash`.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::encode`] errors.
    pub fn to_envelope(
        &self,
        domain: DomainId,
        tx_hash: Hash32,
    ) -> Result<Envelope, ProgClaimError> {
        Ok(Envelope {
            kind: ObjectKind::StarkProof,
            scheme: SchemeId(0),
            payload: self.encode()?,
            tx_hash,
            domain,
        })
    }
}

/// Writes a 32-byte digest into `vm.memory` at `base_cell` as 8 little-endian
/// `u32` values (one per 64-bit VM cell).
pub(crate) fn write_digest_cells(vm: &mut Vm, base_cell: u64, digest: &Hash32) {
    for (i, chunk) in digest.chunks_exact(4).enumerate() {
        let [b0, b1, b2, b3] = *chunk else {
            continue;
        };
        let limb = u64::from(u32::from_le_bytes([b0, b1, b2, b3]));
        write_cell(vm, base_cell + i as u64, limb);
    }
}

/// Writes one 64-bit Goldilocks word into `vm.memory` at `cell`.
pub(crate) fn write_cell(vm: &mut Vm, cell: u64, value: u64) {
    let off = usize::try_from(cell).unwrap_or(0).saturating_mul(8);
    if let Some(slot) = vm.memory.get_mut(off..off + 8) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

/// Emits 8 `SWrite` instructions publishing the 8 limbs at `base_cell` into
/// consecutive storage slots starting at `start_slot`.
pub(crate) fn emit_swrite_digest_cells(a: &mut Asm, base_cell: u64, start_slot: u32) {
    for i in 0..DIGEST_LIMBS_U32 {
        a.load_abs(R[1], base_cell + u64::from(i));
        a.swrite(start_slot + i, R[1]);
    }
}

/// Emits 8 `SWrite` instructions publishing a constant 32-byte digest into
/// consecutive storage slots starting at `start_slot`.
pub(crate) fn emit_swrite_const_digest(a: &mut Asm, digest: &Hash32, start_slot: u32) {
    for (i, chunk) in (0u32..).zip(digest.chunks_exact(4)) {
        let [b0, b1, b2, b3] = *chunk else {
            continue;
        };
        let limb = u64::from(u32::from_le_bytes([b0, b1, b2, b3]));
        a.li(R[1], limb);
        a.swrite(start_slot + i, R[1]);
    }
}

/// Executes and proves a `BudVM` guest program into a [`StarkProofObject`].
///
/// Checks that the guest halts with `exit_code == 0` and commits
/// `(input_hash, output_hash)` via `SWrite[0..16]`, then generates a real
/// 128-bit `BudAir` proof bound to `domain`.
///
/// # Errors
///
/// Returns [`ProgClaimError`] if execution asserts, fails, mismatches the
/// canonical I/O commitment, or STARK proving fails.
pub fn prove_vm_program(
    program: &[u64],
    vm: &mut Vm,
    input_hash: Hash32,
    output_hash: Hash32,
    domain: DomainId,
) -> Result<StarkProofObject, ProgClaimError> {
    if program.is_empty() || program.len() > MAX_PROG_WORDS {
        return Err(ProgClaimError::InvalidInput("program length out of bounds"));
    }
    let receipt = vm.run(program).map_err(|err| {
        if matches!(err, VmError::AssertionFailed) {
            ProgClaimError::AssertionFailed
        } else {
            ProgClaimError::VmFailed(format!("{err:?}"))
        }
    })?;
    if receipt.exit_code != 0 {
        return Err(ProgClaimError::VmFailed(format!(
            "non-zero exit code {}",
            receipt.exit_code
        )));
    }
    let expected_writes = published_writes_digest_many(&[&input_hash, &output_hash]);
    if receipt.state_writes_digest != expected_writes {
        return Err(ProgClaimError::VmFailed(
            "guest SWrite digest does not match (input_hash, output_hash)".into(),
        ));
    }

    let steps = vm.trace.len();
    let init_mem = memory_image_commitment_of_reads(&initial_memory_reads(&vm.trace));
    let init_reg = register_image_commitment_of_reads(&initial_register_reads(&vm.trace));
    let initial_state_root = initial_state_root_of(init_mem, init_reg);

    let public_inputs = ExecutionPublicInputs {
        chain_id: u64::from(domain),
        program_hash: program_hash_of(program),
        initial_state_root,
        final_state_root: receipt.state_writes_digest,
        sender: 0,
        nonce: 0,
        block_height: 0,
        gas_limit: vm.gas_limit,
        gas_used: receipt.gas_used,
        exit_code: receipt.exit_code,
        trace_len: steps as u64,
        event_digest: [0u8; 32],
        state_writes_digest: receipt.state_writes_digest,
    };

    let proof_envelope = Plonky3Adapter::prove(&vm.trace, &public_inputs, program)
        .map_err(|e| ProgClaimError::ProveFailed(format!("{e:?}")))?;

    Ok(StarkProofObject {
        program: program.to_vec(),
        input_hash,
        output_hash,
        public_inputs,
        proof_envelope,
    })
}

/// Verifies a [`StarkProofObject`] via `Plonky3Adapter::verify` (`BudAir`) and
/// derives its canonical [`Claim::Prog`].
///
/// Enforces:
/// 1. `program` is non-empty and bounded (`<= MAX_PROG_WORDS`).
/// 2. `public_inputs.program_hash == keccak256(program)`.
/// 3. `public_inputs.chain_id == u64::from(domain)` (prevents cross-domain replay).
/// 4. `public_inputs.exit_code == 0` (guest completed without error).
/// 5. `public_inputs.state_writes_digest == published_writes_digest_many(&[&input_hash, &output_hash])`
///    and `public_inputs.final_state_root == public_inputs.state_writes_digest`.
/// 6. Full 128-bit Plonky3 FRI-STARK verification via [`Plonky3Adapter::verify`].
///
/// # Errors
///
/// Returns [`ObjectError::Invalid`] if any check or STARK verification fails.
pub fn verify_vm_proof(domain: DomainId, obj: &StarkProofObject) -> Result<Claim, ObjectError> {
    if obj.program.is_empty() || obj.program.len() > MAX_PROG_WORDS {
        return Err(ObjectError::Invalid);
    }
    let program_hash = program_hash_of(&obj.program);
    if obj.public_inputs.program_hash != program_hash {
        return Err(ObjectError::Invalid);
    }
    if obj.public_inputs.chain_id != u64::from(domain) {
        return Err(ObjectError::Invalid);
    }
    if obj.public_inputs.exit_code != 0 {
        return Err(ObjectError::Invalid);
    }
    let expected_writes = published_writes_digest_many(&[&obj.input_hash, &obj.output_hash]);
    if obj.public_inputs.state_writes_digest != expected_writes
        || obj.public_inputs.final_state_root != expected_writes
    {
        return Err(ObjectError::Invalid);
    }
    obj.public_inputs
        .validate_shape()
        .map_err(|_| ObjectError::Invalid)?;
    obj.proof_envelope
        .validate_shape()
        .map_err(|_| ObjectError::Invalid)?;

    Plonky3Adapter::verify(&obj.proof_envelope, &obj.public_inputs, &obj.program)
        .map_err(|_| ObjectError::Invalid)?;

    Ok(Claim::Prog {
        program_hash,
        input_hash: obj.input_hash,
        output_hash: obj.output_hash,
    })
}
