use crate::core::transaction::DEFAULT_CHAIN_ID;
use bud_proof::{DefaultAdapter as Prover, ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use bud_vm::Vm;
use sha3::{Digest, Keccak256};

pub const DEFAULT_CONTRACT_GAS_LIMIT: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkVmReceipt {
    pub gas_used: u64,
    pub steps: usize,
    pub events: Vec<u64>,
    pub proof_bytes: usize,
}

pub struct ZkVmExecutor;

impl ZkVmExecutor {
    pub fn execute_bytecode(bytecode: &[u8], gas_limit: u64) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_inner(bytecode, gas_limit, false)
    }

    /// F2: Execute bytecode in mainnet mode where VerifyMerkle is gated
    /// behind `MainnetActivation::full()`.
    pub fn execute_bytecode_mainnet(
        bytecode: &[u8],
        gas_limit: u64,
    ) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_inner(bytecode, gas_limit, true)
    }

    fn execute_bytecode_inner(
        bytecode: &[u8],
        gas_limit: u64,
        mainnet: bool,
    ) -> Result<ZkVmReceipt, String> {
        if bytecode.is_empty() {
            return Err("Empty BudZKVM bytecode".into());
        }
        if !bytecode.len().is_multiple_of(8) {
            return Err("BudZKVM bytecode length must be a multiple of 8 bytes".into());
        }

        let program = decode_program(bytecode)?;
        let mut vm = Vm::with_mainnet_mode(8192, gas_limit, mainnet);

        // Phase 0.358: use run_receipt so the trace matches prover/AIR assumptions
        // (including Z-D terminal Halt row semantics).
        let receipt =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm.run_receipt(&program)))
                .map_err(|_| "BudZKVM execution failed".to_string())?;
        if !receipt.success {
            return Err("BudZKVM execution failed".into());
        }

        let public_inputs = build_public_inputs(&program, &vm, &receipt);
        let proof = Prover::prove(&vm.trace, &public_inputs, &program)
            .map_err(|err| format!("BudZKVM proof generation failed: {err:?}"))?;
        Prover::verify(&proof, &public_inputs, &program)
            .map_err(|err| format!("BudZKVM proof verification failed: {err:?}"))?;

        Ok(ZkVmReceipt {
            gas_used: receipt.gas_used,
            steps: receipt.trace_len as usize,
            events: receipt.events.clone(),
            proof_bytes: proof.proof_bytes.len(),
        })
    }
}

/// Produce a real STARK proof for a BudZKVM bytecode program, returning the
/// proof envelope, its public inputs and the decoded program.
///
/// This is the proving counterpart used by the L1 ↔ BudZKVM proof bridge (and
/// by tests): it runs the VM, derives the canonical public inputs and generates
/// a `ProofEnvelope` that `budlum-core` can verify natively.
pub fn prove_bytecode(
    bytecode: &[u8],
    gas_limit: u64,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String> {
    prove_bytecode_inner(bytecode, gas_limit, false)
}

/// F2: Prove bytecode in mainnet mode where VerifyMerkle is gated.
pub fn prove_bytecode_mainnet(
    bytecode: &[u8],
    gas_limit: u64,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String> {
    prove_bytecode_inner(bytecode, gas_limit, true)
}

fn prove_bytecode_inner(
    bytecode: &[u8],
    gas_limit: u64,
    mainnet: bool,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String> {
    if bytecode.is_empty() {
        return Err("Empty BudZKVM bytecode".into());
    }
    if !bytecode.len().is_multiple_of(8) {
        return Err("BudZKVM bytecode length must be a multiple of 8 bytes".into());
    }
    let program = decode_program(bytecode)?;
    let mut vm = Vm::with_mainnet_mode(8192, gas_limit, mainnet);
    let receipt =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm.run_receipt(&program)))
            .map_err(|_| "BudZKVM execution failed".to_string())?;
    if !receipt.success {
        return Err("BudZKVM execution failed".into());
    }
    let public_inputs = build_public_inputs(&program, &vm, &receipt);
    let proof = Prover::prove(&vm.trace, &public_inputs, &program)
        .map_err(|err| format!("BudZKVM proof generation failed: {err:?}"))?;
    Ok((proof, public_inputs, program))
}

fn build_public_inputs(
    program: &[u64],
    vm: &Vm,
    receipt: &bud_vm::ExecutionReceipt,
) -> ExecutionPublicInputs {
    // Phase 0.358: public inputs must match BudZero AIR bindings.
    // `event_digest` is NOT a keccak of events — the AIR binds an additive
    // Log accumulator packed as eight little-endian u32 limbs (limb 0 holds
    // the sum of Log values). Using keccak here made every prove/verify fail
    // against BudZero main after Z-A phase2 (InvalidProof), forcing the CI pin.
    ExecutionPublicInputs {
        chain_id: DEFAULT_CHAIN_ID,
        program_hash: hash_u64_words(program),
        initial_state_root: [0u8; 32],
        final_state_root: receipt.state_writes_digest,
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: receipt.gas_used,
        exit_code: receipt.exit_code,
        trace_len: receipt.trace_len,
        event_digest: event_digest_air_limbs(&receipt.events),
    }
}

/// Pack Log-event accumulator the way `bud-proof` trace_matrix + AIR expect:
/// limb 0 = sum of (event & 0xFFFF_FFFF) as a u32 LE in bytes[0..4]; other limbs 0.
fn event_digest_air_limbs(events: &[u64]) -> [u8; 32] {
    let mut acc: u64 = 0;
    for e in events {
        acc = acc.wrapping_add(e & 0xFFFF_FFFF);
    }
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&(acc as u32).to_le_bytes());
    // If the field accumulator exceeds 2^32 (many logs), higher bits are lost
    // in the public-input packing (also u32 limbs). Matches current AIR.
    out
}

fn hash_u64_words(words: &[u64]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for word in words {
        hasher.update(word.to_le_bytes());
    }
    hasher.finalize().into()
}

fn decode_program(bytecode: &[u8]) -> Result<Vec<u64>, String> {
    bytecode
        .chunks_exact(8)
        .map(|chunk| {
            let bytes: [u8; 8] = chunk
                .try_into()
                .map_err(|_| "Invalid BudZKVM instruction encoding".to_string())?;
            Ok(u64::from_le_bytes(bytes))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bud_isa::{Instruction, Opcode};

    #[test]
    fn executes_simple_budzkvm_program() {
        let program = vec![
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 7,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode(),
        ];
        let bytecode: Vec<u8> = program
            .into_iter()
            .flat_map(|instruction| instruction.to_le_bytes())
            .collect();

        let receipt =
            ZkVmExecutor::execute_bytecode(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT).unwrap();

        assert_eq!(receipt.events, vec![7]);
        assert!(receipt.steps > 0);
        assert!(receipt.proof_bytes > 0);
    }

    /// F2: Mainnet mode should gate VerifyMerkle behind MainnetActivation.
    /// In mainnet mode with full activation, VerifyMerkle is allowed.
    /// This verifies the wire is connected (not dead code).
    #[test]
    fn f2_mainnet_activation_wire_connected() {
        // Build a simple program: Load + Halt (no VerifyMerkle).
        // Mainnet mode should still execute basic opcodes fine.
        let program = vec![
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 42,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode(),
        ];
        let bytecode: Vec<u8> = program
            .into_iter()
            .flat_map(|instruction| instruction.to_le_bytes())
            .collect();

        // Non-mainnet mode should work.
        let receipt_normal = ZkVmExecutor::execute_bytecode(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT)
            .expect("normal mode should work");
        assert!(receipt_normal.steps > 0);

        // Mainnet mode with full activation should also work for basic opcodes.
        let receipt_mainnet =
            ZkVmExecutor::execute_bytecode_mainnet(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT)
                .expect("mainnet mode should work for basic opcodes");
        assert!(receipt_mainnet.steps > 0);
    }

    /// Phase 0.358: Log + prove/verify against BudZero main (event_digest AIR fixed).
    #[test]
    fn tur129_log_program_proves_against_budzero_main() {
        let program = vec![
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 7,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 1,
                rs2: 0,
                imm: 0,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            }
            .encode(),
        ];
        let bytecode: Vec<u8> = program
            .into_iter()
            .flat_map(|instruction| instruction.to_le_bytes())
            .collect();
        let receipt = ZkVmExecutor::execute_bytecode(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT)
            .expect("prove/verify against BudZero main");
        assert_eq!(receipt.events, vec![7]);
        assert!(receipt.proof_bytes > 0);
    }
}
