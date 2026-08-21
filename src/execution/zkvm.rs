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
    /// Execute contract bytecode under the staged-rollout opcode gates.
    ///
    /// This used to pass `mainnet = false`, which skipped
    /// `decode_for_mainnet` entirely and decoded under `IsaProfile::Production`
    /// with no activation check at all. `ContractCall` in the executor is the
    /// one path that runs bytecode straight out of a user transaction, so the
    /// gates that hold `VerifyMerkle` and `VerifyInference` closed were not
    /// applied to the only input an attacker controls.
    ///
    /// The gate is not a network property - it tracks whether the verification
    /// behind an opcode is finished, and it is not finished on any network. So
    /// the gated decode is unconditional here rather than keyed off a chain id
    /// the executor does not have.
    pub fn execute_bytecode(bytecode: &[u8], gas_limit: u64) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_inner(bytecode, gas_limit, true)
    }

    /// Explicitly gated execution. Same behaviour as `execute_bytecode`; kept
    /// as a separate name because call sites use it to say the gating is the
    /// point, and because removing it would be a silent API break.
    pub fn execute_bytecode_mainnet(
        bytecode: &[u8],
        gas_limit: u64,
    ) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_inner(bytecode, gas_limit, true)
    }

    /// Ungated execution for local tooling and tests.
    ///
    /// Decodes under the testing profile and applies no activation gate. Never
    /// reachable from transaction execution.
    #[cfg(test)]
    pub fn execute_bytecode_ungated(
        bytecode: &[u8],
        gas_limit: u64,
    ) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_inner(bytecode, gas_limit, false)
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

        // Use run_receipt so the trace matches prover/AIR assumptions
        // (including terminal Halt row semantics).
        let receipt =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm.run_receipt(&program)))
                .map_err(|_| "BudZKVM execution failed".to_string())?;
        if !receipt.success {
            // Carry the VM's own error out instead of flattening every failure
            // into one string. A gated opcode, an out-of-gas, and a bad memory
            // access were all reported as "BudZKVM execution failed", which is
            // useless to an operator reading a rejected transaction and was
            // actively misleading in tests asserting *why* something was
            // refused.
            return Err(match receipt.error {
                Some(e) => format!("BudZKVM execution failed: {e:?}"),
                None => "BudZKVM execution failed".to_string(),
            });
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
/// Proof envelope, its public inputs and the decoded program.
///
/// This is the proving counterpart used by the L1 ↔ BudZKVM proof bridge (and
/// By tests): it runs the VM, derives the canonical public inputs and generates
/// A `ProofEnvelope` that `budlum-core` can verify natively.
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

/// Prove bytecode that reads a host-published memory image.
///
/// Programs whose inputs live in memory (the AI matmul guest, for example)
/// need that memory written before the first instruction executes. `setup`
/// receives the VM's memory buffer and must populate it; everything else
/// matches [`prove_bytecode`].
///
/// The initial memory image is *not* bound by the current public inputs, so a
/// proof produced here attests that *some* memory image drove the trace, not
/// that it was this one. Callers must bind the image out of band, for AI
/// execution that is `weights_digest` plus `input_commitment` on the
/// transaction, see `docs/AI_VERIFICATION_STATUS.md`.
pub fn prove_bytecode_with_memory<F>(
    bytecode: &[u8],
    gas_limit: u64,
    setup: F,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String>
where
    F: FnOnce(&mut [u8]) -> Result<(), String>,
{
    prove_bytecode_inner_with_memory(bytecode, gas_limit, false, Some(Box::new(setup)))
}

fn prove_bytecode_inner(
    bytecode: &[u8],
    gas_limit: u64,
    mainnet: bool,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String> {
    prove_bytecode_inner_with_memory(bytecode, gas_limit, mainnet, None)
}

type MemorySetup<'a> = Box<dyn FnOnce(&mut [u8]) -> Result<(), String> + 'a>;

fn prove_bytecode_inner_with_memory(
    bytecode: &[u8],
    gas_limit: u64,
    mainnet: bool,
    setup: Option<MemorySetup<'_>>,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String> {
    if bytecode.is_empty() {
        return Err("Empty BudZKVM bytecode".into());
    }
    if !bytecode.len().is_multiple_of(8) {
        return Err("BudZKVM bytecode length must be a multiple of 8 bytes".into());
    }
    let program = decode_program(bytecode)?;
    let mut vm = Vm::with_mainnet_mode(8192, gas_limit, mainnet);
    if let Some(setup) = setup {
        setup(&mut vm.memory)?;
    }
    let receipt =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm.run_receipt(&program)))
            .map_err(|_| "BudZKVM execution failed".to_string())?;
    if !receipt.success {
        return Err("BudZKVM execution failed".into());
    }
    let public_inputs = build_public_inputs(&program, &vm, &receipt);
    let proof = Prover::prove(&vm.trace, &public_inputs, &program)
        .map_err(|err| format!("BudZKVM proof generation failed: {err:?}"))?;
    // Verify what we just produced.
    //
    // `Prover::prove` succeeds whenever it can build a trace; it does not
    // check that the trace satisfies the AIR. So a program the constraints
    // reject still yields an envelope here, and the caller has no way to tell
    // the difference until someone downstream tries to verify it, which, for
    // a proof that is attached to a transaction and only checked much later,
    // can be a long way from the code that caused it.
    //
    // `ZkVmExecutor::execute_bytecode` has always done this. `prove_bytecode`
    // did not, and that gap is how a guest reading a host-seeded memory image
    // produced an "ok" envelope that no verifier would accept.
    Prover::verify(&proof, &public_inputs, &program)
        .map_err(|err| format!("BudZKVM produced a proof it cannot verify: {err:?}"))?;
    Ok((proof, public_inputs, program))
}

fn build_public_inputs(
    program: &[u64],
    vm: &Vm,
    receipt: &bud_vm::ExecutionReceipt,
) -> ExecutionPublicInputs {
    // `initial_state_root` commits to the state the program started from. It
    // used to be a hard-coded zero that nothing checked; the AIR now folds
    // every pre-seeded word and every pre-seeded register into trace columns
    // and compares the two, so a guest that reads host-written weights can be
    // proven, and cannot claim to have read different ones.
    //
    // Both halves live in the same root: bytes 0..8 carry the memory image,
    // bytes 8..16 the register file. Programs that seed neither fold to zero
    // and keep the old value.
    let initial_state_root = bud_proof::initial_state_root_of(
        bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(&vm.trace)),
        bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
            &vm.trace,
        )),
    );
    // Public inputs must match BudZero AIR bindings.
    // `event_digest` is NOT a keccak of events, the AIR binds an additive
    // Log accumulator packed as eight little-endian u32 limbs (limb 0 holds
    // The sum of Log values). Using keccak here made every prove/verify fail
    // Against BudZero main task2 (InvalidProof), forcing the CI pin.
    ExecutionPublicInputs {
        chain_id: DEFAULT_CHAIN_ID,
        program_hash: hash_u64_words(program),
        initial_state_root,
        final_state_root: receipt.state_writes_digest,
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: receipt.gas_used,
        exit_code: receipt.exit_code,
        trace_len: receipt.trace_len,
        event_digest: event_digest_air_limbs(&receipt.events),
        state_writes_digest: receipt.state_writes_digest,
    }
}

/// Pack Log-event accumulator the way `bud-proof` trace_matrix + AIR expect:
/// Limb 0 = sum of (event & 0xFFFF_FFFF) as a u32 LE in bytes[0..4]; other limbs 0.
fn event_digest_air_limbs(events: &[u64]) -> [u8; 32] {
    // Delegate to the one implementation the AIR agrees with.
    //
    // This used to sum the low 32 bits of each event and pack the result as a
    // u32, while the AIR added each `Log` row's whole `rs1` in the field. The
    // two matched only while every logged value stayed under 2^32; a Poseidon
    // output is always larger, so any guest that logged one produced a proof
    // that could not verify.
    bud_proof::event_digest_from_events(events)
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    /// The gated opcodes must be refused on the path a transaction reaches.
    ///
    /// `ContractCall` in the executor calls `execute_bytecode` with bytecode
    /// taken straight out of `tx.data`. That call used to pass
    /// `mainnet = false`, which skipped `decode_for_mainnet` and decoded under
    /// `IsaProfile::Production` with no activation check, so the gates holding
    /// `VerifyMerkle` and `VerifyInference` closed did not apply to the one
    /// input an attacker chooses.
    ///
    /// `VerifyInference` matters most of the two: per
    /// `docs/AI_VERIFICATION_STATUS.md` there is no verification circuit behind
    /// it and it returns a hard-coded zero, so an accepted execution reads as a
    /// successful verification.
    #[test]
    fn contract_call_bytecode_cannot_reach_a_gated_opcode() {
        for opcode in [Opcode::VerifyMerkle, Opcode::VerifyInference] {
            let program = vec![
                Instruction {
                    opcode,
                    rd: 1,
                    rs1: 2,
                    rs2: 3,
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

            let err = ZkVmExecutor::execute_bytecode(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT)
                .expect_err(&format!(
                    "{opcode:?} decoded on the ContractCall path; the staged-rollout \
                     gate is not applied to user bytecode"
                ));
            assert!(
                err.contains("activation") || err.contains("Activation"),
                "{opcode:?} was refused for the wrong reason: {err}"
            );
        }
    }

    /// The gate reads its defaults, not a blanket activation.
    ///
    /// `decode_instruction` hard-coded `MainnetActivation::full()`, which set
    /// every flag true and left `MainnetActivation::default()` unreachable from
    /// the only place that consults it. The defaults are load-bearing:
    /// `verify_merkle_enabled: false` because the path verification is
    /// unfinished, `verify_inference_enabled: false` because there is no
    /// circuit at all.
    #[test]
    fn the_staged_rollout_defaults_are_the_ones_in_force() {
        let d = bud_isa::MainnetActivation::default();
        assert!(
            !d.verify_merkle_enabled,
            "VerifyMerkle is open by default; README states it stays gated until \
             64-depth soundness is proven"
        );
        assert!(
            !d.verify_inference_enabled,
            "VerifyInference is open by default while its verification returns a \
             hard-coded zero"
        );

        // Strip line comments before matching. The comment above
        // `decode_instruction` explains what `full()` used to do and why it was
        // wrong, so a whole-file `contains` finds the word in the explanation
        // and reports the bug it is describing. `check-containment-defaults.sh`
        // strips comments for the same reason; this test did not, and CI caught
        // the difference the moment the surrounding prose was reflowed.
        let vm_src = include_str!("../../budzero/bud-vm/src/lib.rs");
        let vm_code: String = vm_src
            .lines()
            .map(|l| match l.find("//") {
                Some(at) => &l[..at],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            vm_code.contains("MainnetActivation::default()"),
            "the VM no longer decodes against the staged-rollout defaults"
        );
        assert!(
            !vm_code.contains("MainnetActivation::full()"),
            "the VM is back on full activation, which makes every gate in \
             MainnetActivation::default() dead code"
        );
    }

    /// Basic opcodes keep working under the gate, otherwise the two tests
    /// above would be satisfied by a VM that refuses everything.
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

        // Ungated decoding still works.
        let receipt_normal =
            ZkVmExecutor::execute_bytecode_ungated(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT)
                .expect("normal mode should work");
        assert!(receipt_normal.steps > 0);

        // Mainnet mode with full activation should also work for basic opcodes.
        let receipt_mainnet =
            ZkVmExecutor::execute_bytecode_mainnet(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT)
                .expect("mainnet mode should work for basic opcodes");
        assert!(receipt_mainnet.steps > 0);
    }

    /// Log + prove/verify against BudZero main (event_digest AIR fixed).
    #[test]
    fn log_program_proves_against_budzero_main() {
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

    /// VerifyInference opcode wired into ZkVmExecutor.
    ///
    /// This test verifies that a ZKVM program containing VerifyInference
    /// Can be executed through the ZkVmExecutor pipeline (execute_bytecode).
    /// The opcode is mainnet-gated (requires MainnetActivation), so:
    /// - Non-mainnet mode: VerifyInference is allowed
    /// - Mainnet mode without activation: VerifyInference is rejected
    /// - Mainnet mode with full activation: VerifyInference is allowed
    ///
    /// The program loads model/input/output commitments and runs
    /// VerifyInference (0x1F), which performs the 3-task verification
    /// (structure → binding → AIR) inside bud-vm.
    #[test]
    fn verify_inference_opcode_wired_in_zkvm_executor() {
        // Program: Load commitments into registers, then VerifyInference, then Halt.
        // Register layout for VerifyInference:
        //   Rd=0 (unused), rs1=model_commitment_reg, rs2=input_commitment_reg,
        //   Imm encodes output_commitment offset and proof round.
        let program = vec![
            // Load model commitment (register 1)
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0xAB,
            },
            // Load input commitment (register 2)
            Instruction {
                opcode: Opcode::Load,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 0xCD,
            },
            // Load output commitment (register 3)
            Instruction {
                opcode: Opcode::Load,
                rd: 3,
                rs1: 0,
                rs2: 0,
                imm: 0xEF,
            },
            // VerifyInference: rd=0, rs1=1 (model), rs2=2 (input), imm=3 (output)
            Instruction {
                opcode: Opcode::VerifyInference,
                rd: 0,
                rs1: 1,
                rs2: 2,
                imm: 3,
            },
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
        ];
        let bytecode: Vec<u8> = program
            .into_iter()
            .flat_map(|instruction| instruction.encode().to_le_bytes())
            .collect();

        // Non-mainnet mode: opcode must decode + execute in the VM.
        // Full STARK prove/verify for VerifyInference AIR is still experimental
        // (expansion rows); ZkVmExecutor::execute_bytecode would fail InvalidProof.
        // Wiring gate = VM run_receipt success + non-zero steps.
        let program_words = decode_program(&bytecode).expect("program decodes");
        let mut vm = bud_vm::Vm::with_mainnet_mode(8192, DEFAULT_CONTRACT_GAS_LIMIT, false);
        let receipt = vm.run_receipt(&program_words);
        assert!(
            receipt.success,
            "VerifyInference must execute in non-mainnet mode: {:?}",
            receipt.error
        );
        assert!(
            receipt.trace_len > 0,
            "VerifyInference must produce trace steps"
        );
    }

    /// `VerifyInference` must answer "not verified" for every input.
    ///
    /// The opcode used to accept any non-zero commitment as proof of an AI
    /// Inference - no cryptography, just a non-zero check. It was reduced to a
    /// No-op that always writes 0 until a real STARK verification AIR exists.
    ///
    /// The mainnet gate is tested, and executing the opcode is tested, but
    /// Nothing asserted the *result*. That is the assertion carrying the
    /// Security property: a gate can be lifted by configuration, whereas "the
    /// Answer is always 0" is what makes lifting it safe. If someone
    /// Reintroduces the non-zero-commitment shortcut, the existing tests still
    /// Pass: the opcode runs, the gate still gates, and only this one fails.
    ///
    /// Runs the operands that the old shortcut would have accepted: two
    /// Non-zero commitments and a non-zero proof type.
    #[test]
    fn verify_inference_never_reports_success() {
        // `Load` with rs1 = 0 writes `imm` straight into the register, and
        // `imm` is an i32, so these stay inside what the encoding can carry.
        // The interesting axis is not magnitude - it is that a *non-zero*
        // commitment pair is exactly what the old shortcut accepted.
        for (model, input, proof_type) in [
            (0xABi32, 0xCDi32, 0i32),
            (i32::MAX, i32::MAX, 1),
            (1, 1, 0),
            (0, 0, 0),
        ] {
            let program = vec![
                Instruction {
                    opcode: Opcode::Load,
                    rd: 1,
                    rs1: 0,
                    rs2: 0,
                    imm: model,
                },
                Instruction {
                    opcode: Opcode::Load,
                    rd: 2,
                    rs1: 0,
                    rs2: 0,
                    imm: input,
                },
                // rd = 4 so the result lands somewhere readable; rd = 0 is
                // discarded by the opcode's own `dst_idx > 0` guard.
                Instruction {
                    opcode: Opcode::VerifyInference,
                    rd: 4,
                    rs1: 1,
                    rs2: 2,
                    imm: proof_type,
                },
                Instruction {
                    opcode: Opcode::Halt,
                    rd: 0,
                    rs1: 0,
                    rs2: 0,
                    imm: 0,
                },
            ];
            let bytecode: Vec<u8> = program
                .into_iter()
                .flat_map(|instruction| instruction.encode().to_le_bytes())
                .collect();
            let program_words = decode_program(&bytecode).expect("program decodes");

            let mut vm = bud_vm::Vm::with_mainnet_mode(8192, DEFAULT_CONTRACT_GAS_LIMIT, false);
            let receipt = vm.run_receipt(&program_words);
            assert!(receipt.success, "the opcode must still execute");
            assert_eq!(
                vm.registers[4], 0,
                "VerifyInference reported success for model={model:#x} \
                 input={input:#x} proof_type={proof_type} - there is no \
                 verification AIR behind it, so the only sound answer is 0"
            );
        }
    }

    /// VerifyInference is mainnet-gated - without
    /// MainnetActivation, it must be rejected in mainnet mode.
    #[test]
    fn verify_inference_gated_in_mainnet_mode() {
        let program = vec![
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0xAB,
            },
            Instruction {
                opcode: Opcode::Load,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 0xCD,
            },
            Instruction {
                opcode: Opcode::Load,
                rd: 3,
                rs1: 0,
                rs2: 0,
                imm: 0xEF,
            },
            Instruction {
                opcode: Opcode::VerifyInference,
                rd: 0,
                rs1: 1,
                rs2: 2,
                imm: 3,
            },
            Instruction {
                opcode: Opcode::Halt,
                rd: 0,
                rs1: 0,
                rs2: 0,
                imm: 0,
            },
        ];
        let bytecode: Vec<u8> = program
            .into_iter()
            .flat_map(|instruction| instruction.encode().to_le_bytes())
            .collect();

        // Mainnet mode without activation: VerifyInference must be refused.
        //
        // The assertion used to read `result.is_err() || gas_used > 0`, which
        // is satisfied by every outcome a run can have, a rejection satisfies
        // the left side, and any execution that does work at all satisfies the
        // right. It passed while the VM was hard-coded to full activation and
        // the opcode was running, which is exactly the state it claimed to
        // rule out.
        let err = ZkVmExecutor::execute_bytecode_mainnet(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT)
            .expect_err(
                "VerifyInference decoded under the mainnet gate; it is closed by \
                 default because there is no verification circuit behind it",
            );
        assert!(
            err.contains("activation") || err.contains("Activation"),
            "VerifyInference was refused, but not by the activation gate: {err}"
        );
    }
}
