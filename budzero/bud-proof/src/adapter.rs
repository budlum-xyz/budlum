use bud_vm::Step;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

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
}

/// Build the AIR-compatible event accumulator from a receipt's event list.
///
/// Mirrors the witness generator in `plonky3_prover::trace_matrix`: limb 0 is
/// the wrapping `u32` sum of the low 32 bits of every logged value, the
/// remaining limbs stay zero.
pub fn event_digest_from_events(events: &[u64]) -> [u8; 32] {
    let mut limb0: u32 = 0;
    for &e in events {
        limb0 = limb0.wrapping_add((e & 0xFFFF_FFFF) as u32);
    }
    let mut digest = [0u8; 32];
    digest[0..4].copy_from_slice(&limb0.to_le_bytes());
    digest
}

impl ExecutionPublicInputs {
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(176);
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
        // keccak256("") starts 0xc5d24601 — if that ever comes back, a caller
        // is hashing instead of accumulating.
        assert_eq!(event_digest_from_events(&[]), [0u8; 32]);
    }

    #[test]
    fn single_event_lands_in_limb_zero_little_endian() {
        let d = event_digest_from_events(&[7]);
        assert_eq!(&d[0..4], &7u32.to_le_bytes());
        assert!(d[4..].iter().all(|&b| b == 0), "limbs 1..8 must stay zero");
    }

    #[test]
    fn events_accumulate_additively_over_low_32_bits() {
        let d = event_digest_from_events(&[1, 2, (1u64 << 32) | 3]);
        assert_eq!(&d[0..4], &6u32.to_le_bytes());
        assert!(d[4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn accumulator_wraps_instead_of_overflowing() {
        let d = event_digest_from_events(&[u32::MAX as u64, 1]);
        assert_eq!(&d[0..4], &0u32.to_le_bytes());
    }
}
