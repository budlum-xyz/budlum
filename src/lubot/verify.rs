//! Faz A — gerçek STARK doğrulama + proof üretimi (bud-proof `DefaultAdapter`).
//!
//! Lubot çıkarım kanıtı, gerçek plonky3 STARK ile doğrulanır VE üretilir.
//! Bu, düny-ilk "doğrulanabilir çıkarım" iddiasının kriptografik çekirdeğidir.
//! Hem prove hem verify çalışır — tam round-trip.

use bud_proof::{DefaultAdapter, ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use bud_vm::Vm;
use sha3::{Digest, Keccak256};

/// Lubot çıkarım kanıtını gerçek plonky3 STARK ile doğrula (verify-only).
pub fn verify_inference_stark(
    proof_bytes: &[u8],
    expected_inputs: &ExecutionPublicInputs,
    program: &[u64],
) -> Result<(), String> {
    let envelope: ProofEnvelope = bincode::deserialize(proof_bytes)
        .map_err(|e| format!("Lubot STARK: ProofEnvelope deserialize failed: {e}"))?;
    DefaultAdapter::verify(&envelope, expected_inputs, program)
        .map_err(|e| format!("Lubot STARK: verification failed: {e:?}"))
}

/// ExecutionPublicInputs'i Vm + program'dan inşa et (Keccak256 program_hash).
fn build_public_inputs(vm: &Vm, program: &[u64]) -> ExecutionPublicInputs {
    let program_bytes: Vec<u8> = program.iter().flat_map(|&i| i.to_le_bytes()).collect();
    let mut hasher = Keccak256::new();
    hasher.update(&program_bytes);
    let program_hash: [u8; 32] = hasher.finalize().into();
    ExecutionPublicInputs {
        chain_id: 1,
        program_hash,
        initial_state_root: [0u8; 32],
        final_state_root: [0u8; 32],
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: [0u8; 32],
    }
}

/// Lubot çıkarım proof'u üret + doğrula (gerçek plonky3 STARK prove→verify round-trip).
///
/// `vm` üzerinde `program`'ı çalıştırır, trace'den STARK proof üretir,
/// sonra proof'u doğrular. ProofEnvelope döner.
pub fn generate_and_verify_proof(vm: &mut Vm, program: &[u64]) -> Result<ProofEnvelope, String> {
    let receipt = vm.run_receipt(program);
    if !receipt.success {
        return Err("Lubot STARK: program execution failed".into());
    }
    let pi = build_public_inputs(vm, program);
    let envelope = DefaultAdapter::prove(&vm.trace, &pi, program)
        .map_err(|e| format!("Lubot STARK: prove failed: {e:?}"))?;
    DefaultAdapter::verify(&envelope, &pi, program)
        .map_err(|e| format!("Lubot STARK: verify failed: {e:?}"))?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bud_proof::ExecutionPublicInputs;

    fn inputs() -> ExecutionPublicInputs {
        ExecutionPublicInputs {
            chain_id: 0,
            program_hash: [0; 32],
            initial_state_root: [0; 32],
            final_state_root: [0; 32],
            sender: 0,
            nonce: 0,
            block_height: 0,
            gas_limit: 0,
            gas_used: 0,
            exit_code: 0,
            trace_len: 0,
            event_digest: [0u8; 32],
        }
    }

    /// Gerçek STARK verifier çağrılır; geçersiz proof reddedilir.
    #[test]
    fn stark_verify_rejects_invalid_proof() {
        let envelope = ProofEnvelope {
            proof_format_version: 1,
            backend: "plonky3".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "default".to_string(),
            public_inputs_hash: inputs().hash(),
            proof_bytes: vec![0u8; 8],
            degree_bits: 4,
        };
        let bytes = bincode::serialize(&envelope).expect("serialize envelope");
        let res = verify_inference_stark(&bytes, &inputs(), &[]);
        assert!(res.is_err(), "invalid proof must be rejected");
    }

    /// Çöp baytlar deserialize'ta reddedilir.
    #[test]
    fn stark_verify_rejects_garbage_bytes() {
        let res = verify_inference_stark(&[0xFF; 10], &inputs(), &[]);
        assert!(res.is_err(), "garbage bytes must fail");
    }

    /// C5: Gerçek plonky3 STARK prove→verify round-trip (Halt programı).
    #[test]
    fn lubot_stark_prove_and_verify_roundtrip() {
        let mut vm = Vm::new(64);
        // Halt = opcode 0x00 → minimal program, tek instruction.
        let envelope = generate_and_verify_proof(&mut vm, &[0u64]).expect("prove+verify");
        assert!(
            !envelope.proof_bytes.is_empty(),
            "proof bytes must be non-empty after real STARK prove"
        );
    }
}
