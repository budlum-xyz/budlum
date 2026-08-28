use bud_vm::Step;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

/// The current proof format version.
///
/// Every `ProofEnvelope` carries it; the verifier rejects anything else
/// (older bytes are not migrated, newer bytes are not understood). Bump this
/// constant together with any change to the serialized proof shape,
/// transcript, public inputs, or envelope fields — never edit the literals
/// scattered across the codebase, or a bump is silently half-applied.
pub const PROOF_FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPublicInputs {
    pub chain_id: u64,
    pub program_hash: [u8; 32],
    pub initial_state_root: [u8; 32],
    pub final_state_root: [u8; 32],
    pub sender: u64,
    pub nonce: u64,
    pub block_height: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub exit_code: u64,
    pub trace_len: u64,
    /// Event accumulator bound by the AIR, **not** a hash.
    ///
    /// The STARK trace carries eight little-endian `u32` limbs
    /// (`COL_EVENT_DIGEST_0..8`). Every `Log` row adds the low 32 bits of its
    /// `rs1` operand into limb 0; limbs 1..8 are reserved and stay zero. The
    /// AIR binds the last real row of that accumulator to
    /// `public_inputs[40..48]`, so a caller that puts anything else here (for
    /// example `keccak256(events)`) produces a proof that fails verification
    /// with `OodEvaluationMismatch`.
    ///
    /// Build this field with [`event_digest_from_events`] rather than hashing
    /// the event list.
    pub event_digest: [u8; 32],
    /// Post-execution storage-write digest, bound by the AIR at
    /// `public_inputs[48..56]` (Strix HIGH CWE-345, 2026-08-17). The VM
    /// computes this from every `SWrite` (slot, value) pair; the proof now
    /// commits to it, so a storage-mutating program cannot verify while its
    /// actual state transition is unbound.
    pub state_writes_digest: [u8; 32],
}

/// Build the AIR-compatible event accumulator from a receipt's event list.
///
/// Mirrors the witness generator in `plonky3_prover::trace_matrix`: limb 0 is
/// the wrapping `u32` sum of the low 32 bits of every logged value, the
/// remaining limbs stay zero.
pub fn event_digest_from_events(events: &[u64]) -> [u8; 32] {
    // Sum in the field, then pack the canonical representative as eight u32
    // limbs. The AIR adds each `Log` row's full `rs1` into limb 0, so anything
    // narrower here disagrees with it as soon as a logged value reaches 2^32 -
    // and a Poseidon output always does.
    const P: u128 = 18_446_744_069_414_584_321;
    let mut acc: u128 = 0;
    for &e in events {
        acc = (acc + e as u128) % P;
    }
    // Limb 0 carries the whole field element. The AIR compares
    // `COL_EVENT_DIGEST_0` against `public_inputs[40]` directly, and that
    // column holds a full Goldilocks value, so splitting the sum across two
    // u32 limbs here would compare a truncated number against an untruncated
    // one. Limbs 1..8 stay zero and are asserted so by the AIR.
    let mut digest = [0u8; 32];
    digest[0..8].copy_from_slice(&(acc as u64).to_le_bytes());
    digest
}

/// Commitment to the parts of the initial memory image a program actually
/// reads.
///
/// Folds `(addr, value)` for each seeded word the trace reads before anything
/// writes it, in ascending address order, matching `COL_MEM_INIT_ACC` in the
/// AIR. An image nothing reads folds to zero, so programs that seed nothing
/// keep an all-zero `initial_state_root` and are unaffected.
///
/// **It commits to what was read, not to the whole image.** Bytes the host
/// wrote and the program never touched are outside it, they cannot influence
/// the execution, so binding them would only make the commitment depend on
/// padding. What it does bind is every value the program consumed: change a
/// weight the guest reads and the commitment moves, so a proof produced for
/// one set of weights cannot be presented as a proof for another.
///
/// Callers hand it the addresses the trace read; see
/// [`ProverAdapter::initial_memory_commitment`].
pub fn memory_image_commitment_of_reads(reads: &[(u64, u64)]) -> [u8; 32] {
    const P: u128 = 18_446_744_069_414_584_321;
    const BETA: u128 = 0x9E37_79B9_7F4A_7C15;
    const GAMMA: u128 = 0xC2B2_AE3D_27D4_EB4F;

    let mut acc: u128 = 0;
    for (i, (addr, val)) in reads.iter().enumerate() {
        let term = ((*addr as u128) * GAMMA + *val as u128) % P;
        acc = if i == 0 {
            term
        } else {
            (acc * BETA + term) % P
        };
    }

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&(acc as u64).to_le_bytes());
    out
}

/// The starting register file a trace read, folded into bytes 8..16 of
/// `initial_state_root`.
///
/// The register companion to [`memory_image_commitment_of_reads`]. Both halves
/// live in the same public input because widening it would mean changing
/// `ExecutionPublicInputs`, which is declared twice and constructed in 62
/// places across the L1, the CLI, the benchmarks and the fuzz targets, for a
/// commitment that fits in bytes the struct already carries and the AIR
/// already compares.
///
/// Different fold constants from the memory side, deliberately. Sharing them
/// would let a seeded value move between the two images without either
/// accumulator changing, and "the register file is whatever memory says" is
/// not a property worth shipping.
///
/// Like the memory commitment, this covers **what was read**, not the whole
/// register file. A register the program never touches cannot influence the
/// execution, so binding it would only make the commitment depend on padding.
pub fn register_image_commitment_of_reads(reads: &[(u64, u64)]) -> [u8; 32] {
    const P: u128 = 18_446_744_069_414_584_321;
    const BETA: u128 = 0xD1B5_4A32_D192_ED03;
    const GAMMA: u128 = 0xA24B_AED4_963E_E407;

    let mut acc: u128 = 0;
    for (i, (idx, val)) in reads.iter().enumerate() {
        let term = ((*idx as u128) * GAMMA + *val as u128) % P;
        acc = if i == 0 {
            term
        } else {
            (acc * BETA + term) % P
        };
    }

    let mut out = [0u8; 32];
    out[8..16].copy_from_slice(&(acc as u64).to_le_bytes());
    out
}

/// Combine the memory and register halves into one `initial_state_root`.
///
/// The two commitments occupy disjoint byte ranges, so this is a byte-wise
/// merge rather than a hash. Callers that seed neither can keep passing
/// `[0u8; 32]`: both folds are empty and both halves are zero.
pub fn initial_state_root_of(memory: [u8; 32], registers: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&memory[0..8]);
    out[8..16].copy_from_slice(&registers[8..16]);
    out
}

impl ExecutionPublicInputs {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(208);
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.program_hash);
        bytes.extend_from_slice(&self.initial_state_root);
        bytes.extend_from_slice(&self.final_state_root);
        bytes.extend_from_slice(&self.sender.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.gas_limit.to_le_bytes());
        bytes.extend_from_slice(&self.gas_used.to_le_bytes());
        bytes.extend_from_slice(&self.exit_code.to_le_bytes());
        bytes.extend_from_slice(&self.trace_len.to_le_bytes());
        bytes.extend_from_slice(&self.event_digest);
        bytes.extend_from_slice(&self.state_writes_digest);
        bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.to_canonical_bytes();
        let mut hasher = Keccak::v256();
        hasher.update(&bytes);
        let mut res = [0u8; 32];
        hasher.finalize(&mut res);
        res
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProofEnvelope {
    pub proof_format_version: u32,
    pub backend: String,
    pub p3_version: String,
    pub fri_params_id: String,
    pub public_inputs_hash: [u8; 32],
    pub proof_bytes: Vec<u8>,
    pub degree_bits: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProverError {
    TraceGenerationError(String),
    ProverInternalError(String),
    SerializationError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerifyError {
    DeserializationError(String),
    InvalidEnvelope(String),
    PublicInputsMismatch,
    /// The proof's program hash is not part of the canonical program set
    /// (see `canonical_set`). Raised by `verify_canonical_program`; the
    /// ordinary `verify` path still accepts any well-formed program.
    NonCanonicalProgram([u8; 32]),
    InvalidProof,
}

pub trait ProverAdapter {
    fn prove(
        trace: &[Step],
        public_inputs: &ExecutionPublicInputs,
        program: &[u64],
    ) -> Result<ProofEnvelope, ProverError>;

    fn verify(
        envelope: &ProofEnvelope,
        expected_inputs: &ExecutionPublicInputs,
        program: &[u64],
    ) -> Result<(), VerifyError>;
}

#[cfg(test)]
mod event_digest_tests {
    use super::*;

    #[test]
    fn empty_event_list_yields_all_zero_accumulator() {
        // keccak256("") starts 0xc5d24601 - if that ever comes back, a caller
        // is hashing instead of accumulating.
        assert_eq!(event_digest_from_events(&[]), [0u8; 32]);
    }

    #[test]
    fn single_event_lands_in_limb_zero_little_endian() {
        let d = event_digest_from_events(&[7]);
        assert_eq!(&d[0..8], &7u64.to_le_bytes());
        assert!(d[8..].iter().all(|&b| b == 0), "limbs 1..8 must stay zero");
    }

    /// The accumulator carries the whole logged value, not its low 32 bits.
    ///
    /// The AIR constrains `nxt_event_0 - cur_event_0 - is_log * nxt_rs1 == 0`
    /// and `nxt_rs1` is the full register. Masking here agreed with that only
    /// while every logged value stayed under 2^32.
    #[test]
    fn events_accumulate_over_the_whole_value() {
        let d = event_digest_from_events(&[1, 2, (1u64 << 32) | 3]);
        let expected = 1u64 + 2 + ((1u64 << 32) | 3);
        assert_eq!(&d[0..8], &expected.to_le_bytes());
        assert!(d[8..].iter().all(|&b| b == 0));
    }

    /// A Poseidon output is the case that exposed the mismatch: always above
    /// 2^32, so truncation and the AIR disagree on every one of them.
    #[test]
    fn a_large_event_is_not_truncated() {
        let big = 13_669_935_575_198_700_787u64;
        assert!(big > u32::MAX as u64);
        let d = event_digest_from_events(&[big]);
        assert_eq!(&d[0..8], &big.to_le_bytes());
        // The old implementation kept only the low 32 bits, so bytes 4..8
        // were zero. They are not any more, and that is the whole difference.
        assert_ne!(
            &d[4..8],
            &[0u8; 4],
            "the high half must survive; zeroing it is what the AIR rejected"
        );
    }

    /// Summation is modulo the field, not modulo 2^32 and not saturating.
    #[test]
    fn accumulator_reduces_in_the_field() {
        const P: u64 = 18_446_744_069_414_584_321;
        let d = event_digest_from_events(&[P - 1, 2]);
        assert_eq!(&d[0..8], &1u64.to_le_bytes(), "(P-1) + 2 == 1 mod P");
    }

    /// Every value the accumulator produces has to be a canonical field
    /// element, otherwise the public input cannot equal the trace column.
    #[test]
    fn accumulator_stays_canonical() {
        const P: u64 = 18_446_744_069_414_584_321;
        let d = event_digest_from_events(&[u64::MAX, u64::MAX, u64::MAX]);
        let acc = u64::from_le_bytes(d[0..8].try_into().unwrap());
        assert!(
            acc < P,
            "accumulator {acc} is not a canonical field element"
        );
    }
}
