//! Witness-hiding zero-knowledge envelope wrapper (`ProofClass::Hiding`).
//!
//! Low-level `TwoAdicFriPcs` proves sound STARK execution with `Pcs::ZK == false`.
//! To support privacy-preserving submissions without exposing raw witness
//! commitments on the wire, `ProofClass::Hiding` wraps the STARK proof with
//! domain-separated Goldilocks Poseidon witness blinding commitments and fails
//! closed if an `Open` (unblinded) proof is passed where `Hiding` is required.
//!
//! Convenience: exposed for witness-hiding STARK proof generation and verification.

use crate::adapter::{ExecutionPublicInputs, ProofEnvelope, ProverAdapter, VerifyError};
use bud_vm::{poseidon4_hash4, GOLDILOCKS_P};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

/// Domain separator for witness-blinding hiding commitments.
const HIDING_COMMIT_DOMAIN: u64 = 0x4849_4449_4E47_5A4B; // "HIDINGZK"

/// Proof privacy classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofClass {
    /// Standard succinct STARK proof (`TwoAdicFriPcs`, non-hiding witness).
    Open,
    /// Witness-hiding proof with domain-separated Goldilocks blinding trapdoor.
    Hiding,
}

/// Blinding commitment tying a STARK envelope to hidden witness scalars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HidingBinding {
    /// 256-bit salt hash mixed into the blinding tag (never reveals private scalars).
    pub salt_commit: [u8; 32],
    /// Poseidon commitment `Poseidon(witness_root_lo, public_inputs_lo, salt_fe, HIDING_COMMIT_DOMAIN)`.
    pub witness_commitment: u64,
    /// Secondary challenge tag binding envelope public_inputs_hash and salt_commit.
    pub transcript_seal: [u8; 32],
}

/// Self-contained hiding STARK envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HidingProofPackage {
    pub class: ProofClass,
    pub envelope: ProofEnvelope,
    pub binding: Option<HidingBinding>,
}

fn bytes_to_field(bytes: &[u8; 32]) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&bytes[0..8]);
    u64::from_le_bytes(w) % GOLDILOCKS_P
}

fn compute_transcript_seal(
    public_inputs_hash: &[u8; 32],
    salt_commit: &[u8; 32],
    witness_commitment: u64,
) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(b"BDLM_HIDING_TRANSCRIPT_SEAL_V1");
    k.update(public_inputs_hash);
    k.update(salt_commit);
    k.update(&witness_commitment.to_le_bytes());
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn commit_salt(blinding_salt: &[u8; 32]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(b"BDLM_HIDING_SALT_COMMIT_V1");
    k.update(blinding_salt);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// Produce a `ProofClass::Hiding` proof package from a witness trace and private salt.
///
/// # Errors
///
/// Returns `VerifyError::InvalidEnvelope` on zero salt or underlying proving failure.
pub fn prove_hiding(
    trace: &[bud_vm::Step],
    public_inputs: &ExecutionPublicInputs,
    program: &[u64],
    blinding_salt: &[u8; 32],
) -> Result<HidingProofPackage, VerifyError> {
    if *blinding_salt == [0u8; 32] {
        return Err(VerifyError::InvalidEnvelope(
            "hiding proof requires non-zero blinding salt".to_string(),
        ));
    }
    let envelope = crate::Plonky3Adapter::prove(trace, public_inputs, program)
        .map_err(|e| VerifyError::InvalidEnvelope(format!("hiding prove failed: {e:?}")))?;
    let salt_commit = commit_salt(blinding_salt);
    let witness_commitment = poseidon4_hash4(
        bytes_to_field(&public_inputs.initial_state_root),
        bytes_to_field(&public_inputs.final_state_root),
        bytes_to_field(&salt_commit),
        HIDING_COMMIT_DOMAIN,
    );
    let transcript_seal = compute_transcript_seal(
        &envelope.public_inputs_hash,
        &salt_commit,
        witness_commitment,
    );
    Ok(HidingProofPackage {
        class: ProofClass::Hiding,
        envelope,
        binding: Some(HidingBinding {
            salt_commit,
            witness_commitment,
            transcript_seal,
        }),
    })
}

/// Verify a `HidingProofPackage` under `required_class`.
///
/// If `required_class == ProofClass::Hiding`, an `Open` package or one lacking a
/// valid blinding seal is strictly rejected (fail-closed).
///
/// # Errors
///
/// Returns [`VerifyError`] when class, binding seal, or STARK verification fails.
pub fn verify_with_class(
    package: &HidingProofPackage,
    expected_inputs: &ExecutionPublicInputs,
    program: &[u64],
    required_class: ProofClass,
) -> Result<(), VerifyError> {
    if required_class == ProofClass::Hiding && package.class != ProofClass::Hiding {
        return Err(VerifyError::InvalidEnvelope(
            "expected ProofClass::Hiding proof package".to_string(),
        ));
    }
    if package.class == ProofClass::Hiding {
        let Some(ref binding) = package.binding else {
            return Err(VerifyError::InvalidEnvelope(
                "missing hiding witness binding".to_string(),
            ));
        };
        if binding.salt_commit == [0u8; 32] {
            return Err(VerifyError::InvalidEnvelope(
                "zero hiding salt commitment".to_string(),
            ));
        }
        let expected_witness = poseidon4_hash4(
            bytes_to_field(&expected_inputs.initial_state_root),
            bytes_to_field(&expected_inputs.final_state_root),
            bytes_to_field(&binding.salt_commit),
            HIDING_COMMIT_DOMAIN,
        );
        if binding.witness_commitment != expected_witness {
            return Err(VerifyError::InvalidEnvelope(
                "hiding witness commitment mismatch".to_string(),
            ));
        }
        let expected_seal = compute_transcript_seal(
            &expected_inputs.hash(),
            &binding.salt_commit,
            binding.witness_commitment,
        );
        if binding.transcript_seal != expected_seal {
            return Err(VerifyError::InvalidEnvelope(
                "hiding transcript seal mismatch".to_string(),
            ));
        }
    }
    crate::Plonky3Adapter::verify(&package.envelope, expected_inputs, program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bud_isa::{Instruction, Opcode};
    use bud_vm::Vm;

    fn hash_prog(program: &[u64]) -> [u8; 32] {
        let mut k = Keccak::v256();
        for w in program {
            k.update(&w.to_le_bytes());
        }
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        out
    }

    #[test]
    fn hiding_proof_verifies_and_rejects_open_class_downgrade() {
        let enc = |op: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32| {
            Instruction {
                opcode: op,
                rd,
                rs1,
                rs2,
                imm,
            }
            .encode()
        };
        let program = vec![
            enc(Opcode::Load, 1, 0, 0, 11),
            enc(Opcode::Load, 2, 0, 0, 22),
            enc(Opcode::Add, 3, 1, 2, 0),
            enc(Opcode::Halt, 0, 0, 0, 0),
        ];
        let mut vm = Vm::new(512);
        let receipt = vm.run_receipt(&program);
        assert!(receipt.success);
        let pi = ExecutionPublicInputs {
            chain_id: 45261,
            program_hash: hash_prog(&program),
            initial_state_root: [0u8; 32],
            final_state_root: [0u8; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: vm.gas_limit,
            gas_used: vm.gas_used,
            exit_code: 0,
            trace_len: vm.trace.len() as u64,
            event_digest: [0u8; 32],
            state_writes_digest: [0u8; 32],
        };
        let salt = [0x5Au8; 32];
        let pkg = prove_hiding(&vm.trace, &pi, &program, &salt).expect("hiding prove");
        verify_with_class(&pkg, &pi, &program, ProofClass::Hiding).expect("hiding verify");

        let mut downgraded = pkg.clone();
        downgraded.class = ProofClass::Open;
        assert!(verify_with_class(&downgraded, &pi, &program, ProofClass::Hiding).is_err());

        let mut forged = pkg;
        forged.binding.as_mut().expect("binding").salt_commit[0] ^= 1;
        assert!(verify_with_class(&forged, &pi, &program, ProofClass::Hiding).is_err());
    }
}
