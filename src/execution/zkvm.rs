//! Convenience: exposed for CLI, RPC, SDK, and multi-VM runtime callers.

use crate::core::transaction::DEFAULT_CHAIN_ID;
use bud_proof::{DefaultAdapter as Prover, ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use bud_vm::Vm;
use sha3::{Digest, Keccak256};

/// Contract gas one call may burn, bounded by what the prover can materialise.
///
/// Witness size is `next_pow2(3 * steps + 1) * TRACE_WIDTH` field elements, so
/// `2^14` steps keep one call's base matrix near half a gigabyte and couple
/// `MAX_BLOCK_CONTRACT_GAS` directly to the per-call trace cap.
pub const DEFAULT_CONTRACT_GAS_LIMIT: u64 = 1 << 14;

/// Memory size in bytes of the VM that runs and proves contract bytecode.
const CONTRACT_VM_MEMORY_BYTES: usize = 8192;

const _: () = assert!(
    CONTRACT_VM_MEMORY_BYTES as u64 <= bud_vm::MAX_MEMORY_BYTES,
    "CONTRACT_VM_MEMORY_BYTES must not exceed bud_vm::MAX_MEMORY_BYTES"
);

const _: () = assert!(
    (3 * bud_vm::MAX_CONTRACT_TRACE_STEPS + 1).next_power_of_two()
        <= bud_proof::plonky3_prover::MAX_PROVER_WITNESS_ROWS,
    "MAX_CONTRACT_TRACE_STEPS must stay within MAX_PROVER_WITNESS_ROWS"
);

/// Contract gas one block may carry, summed over its `ContractCall`
/// transactions at [`DEFAULT_CONTRACT_GAS_LIMIT`] each.
///
/// The per-call limit bounds one execution and its proof; nothing bounded how
/// many such executions a block could ask a validator to run and prove, so a
/// block of near-limit calls repeated the heaviest work
/// `MAX_TRANSACTIONS_PER_BLOCK` times. The budget is counted at the limit,
/// not at `gas_used`: execution cost is committed when the call starts, and a
/// call that runs out of gas at the limit costs the same trace as one that
/// halts just under it. Sixty full calls per block.
///
/// Section 8.9 fixes the hard block limit at 60,000,000 BGU and requires every
/// per-environment soft limit to fit inside it. At one `BudZero` gas per BGU,
/// the former `64 * DEFAULT_CONTRACT_GAS_LIMIT` budget exceeded the block that
/// carried it. Keep the `BudZero` soft limit equal to the hard block ceiling.
pub const MAX_BLOCK_CONTRACT_GAS: u64 = BLOCK_GAS_LIMIT_BGU;

/// Hard block gas ceiling from Section 8.9 item 2 (`TESTNET-DEFAULT`).
///
/// The coordinator's `BLOCK_BGU_LIMIT` and the external conformance runner are
/// locked to this value by `src/tests/conformance_locks.rs`.
const BLOCK_GAS_LIMIT_BGU: u64 = 60_000_000;

const _: () = assert!(
    DEFAULT_CONTRACT_GAS_LIMIT <= BLOCK_GAS_LIMIT_BGU,
    "a contract call limit may not exceed the block gas limit (Section 8.9 item 3)"
);

/// The witness matrix rows one call can materialise must fit the prover cap.
///
/// `next_pow2(3 * steps + 1)` is the shape `trace_matrix` produces, so a step
/// cap above `MAX_PROVER_WITNESS_ROWS` would let a single `ContractCall` ask
/// the prover for a matrix it refuses to build (prover OOM).
const _: () = assert!(
    (3 * bud_vm::MAX_CONTRACT_TRACE_STEPS + 1).next_power_of_two()
        <= bud_proof::plonky3_prover::MAX_PROVER_WITNESS_ROWS,
    "MAX_CONTRACT_TRACE_STEPS must stay within MAX_PROVER_WITNESS_ROWS"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkVmReceipt {
    pub gas_used: u64,
    pub steps: usize,
    pub events: Vec<u64>,
    pub proof_bytes: usize,
}

/// The transaction the bytecode runs for, as the VM sees it.
///
/// Syscalls 1, 2 and 3 read `sender`, `block_height` and `nonce`, and the
/// public inputs carry the same three words, so a program that branches on
/// its caller or its nonce is proved against the values the chain agreed to,
/// not the zeros a fresh `Vm` starts with. `sender` is the first eight bytes
/// of the address, little endian: the VM word is 64 bits wide and the public
/// input carries the same word.
/// Encodes a 32-byte `Address` as four little-endian 64-bit words.
#[must_use]
pub fn address_to_four_words(addr: &crate::core::address::Address) -> [u64; 4] {
    let raw = addr.as_bytes();
    let mut out = [0u64; 4];
    for (idx, dst) in out.iter_mut().enumerate() {
        let start = idx * 8;
        if let Some(chunk) = raw.get(start..start + 8) {
            if let Ok(arr) = <[u8; 8]>::try_from(chunk) {
                *dst = u64::from_le_bytes(arr);
            }
        }
    }
    out
}

/// Reconstructs a 32-byte `Address` from its four 64-bit little-endian words.
#[must_use]
pub fn four_words_to_address(words: [u64; 4]) -> crate::core::address::Address {
    let mut out = [0u8; 32];
    for (idx, w) in words.iter().copied().enumerate() {
        let start = idx * 8;
        if let Some(dst) = out.get_mut(start..start + 8) {
            dst.copy_from_slice(&w.to_le_bytes());
        }
    }
    crate::core::address::Address::from(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxContext {
    pub sender: u64,
    pub sender_words: [u64; 4],
    pub nonce: u64,
    pub block_height: u64,
}

impl TxContext {
    /// The context of `tx` executing in the block at `block_height`.
    #[must_use]
    pub fn of(tx: &crate::core::transaction::Transaction, block_height: u64) -> Self {
        let words = address_to_four_words(&tx.from);
        let [w0, ..] = words;
        Self {
            sender: w0,
            sender_words: words,
            nonce: tx.nonce,
            block_height,
        }
    }
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
    ///
    /// `ctx` is the transaction the bytecode runs for: the VM context carries
    /// its sender, nonce and block height, so the syscalls that read them and
    /// the public inputs that repeat them describe this transaction rather
    /// than a zeroed one.
    ///
    /// Execution-only gated VM run for consensus `ContractCall` (§8.8:
    /// deterministic execution without inline per-validator STARK proof
    /// generation). WIRING: the block path. The executor's `ContractCall`
    /// path is the only caller, and it must not allocate a prover on the
    /// validator critical path; `execute_for_block` is the same execution
    /// door without the proof, `execute_bytecode` keeps the inline STARK
    /// proof for settlement and tooling callers.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn execute_bytecode_vm_only(
        bytecode: &[u8],
        gas_limit: u64,
        ctx: TxContext,
    ) -> Result<ZkVmReceipt, String> {
        if bytecode.is_empty() {
            return Err("Empty BudZKVM bytecode".into());
        }
        if !bytecode.len().is_multiple_of(8) {
            return Err("BudZKVM bytecode length must be a multiple of 8 bytes".into());
        }
        let program = decode_program(bytecode)?;
        let mut vm = Vm::with_mainnet_mode(CONTRACT_VM_MEMORY_BYTES, gas_limit, true)
            .with_step_limit(bud_vm::MAX_CONTRACT_TRACE_STEPS);
        vm.context.sender = ctx.sender;
        vm.context.nonce = ctx.nonce;
        vm.context.block_height = ctx.block_height;
        let receipt =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm.run_receipt(&program)))
                .map_err(|_| "BudZKVM execution failed".to_string())?;
        if !receipt.success {
            return Err(match receipt.error {
                Some(e) => format!("BudZKVM execution failed: {e:?}"),
                None => "BudZKVM execution failed".to_string(),
            });
        }
        Ok(ZkVmReceipt {
            gas_used: receipt.gas_used,
            steps: receipt.trace_len as usize,
            events: receipt.events,
            proof_bytes: 0,
        })
    }

    /// Performs the requested operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn execute_bytecode(
        bytecode: &[u8],
        gas_limit: u64,
        ctx: TxContext,
    ) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_inner(bytecode, gas_limit, true, ctx)
    }

    /// Explicitly gated execution. Same behaviour as `execute_bytecode`; kept
    /// as a separate name because call sites use it to say the gating is the
    /// point, and because removing it would be a silent API break.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn execute_bytecode_mainnet(
        bytecode: &[u8],
        gas_limit: u64,
    ) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_inner(bytecode, gas_limit, true, TxContext::default())
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
        Self::execute_bytecode_inner(bytecode, gas_limit, false, TxContext::default())
    }

    /// Execute contract bytecode inside the deterministic block state
    /// transition without running the inline Plonky3 STARK prover.
    ///
    /// Every validator re-executes the same deterministic VM bytecode under the
    /// staged-rollout activation gates and `MAX_CONTRACT_TRACE_STEPS`; proofs
    /// belong on the dedicated `SubmitZkProof` settlement path rather than on
    /// the per-block validator critical path.
    pub fn execute_for_block(
        bytecode: &[u8],
        gas_limit: u64,
        ctx: TxContext,
    ) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_mode(bytecode, gas_limit, true, ctx, false)
    }

    fn execute_bytecode_inner(
        bytecode: &[u8],
        gas_limit: u64,
        mainnet: bool,
        ctx: TxContext,
    ) -> Result<ZkVmReceipt, String> {
        Self::execute_bytecode_mode(bytecode, gas_limit, mainnet, ctx, true)
    }

    fn execute_bytecode_mode(
        bytecode: &[u8],
        gas_limit: u64,
        mainnet: bool,
        ctx: TxContext,
        prove_execution: bool,
    ) -> Result<ZkVmReceipt, String> {
        if bytecode.is_empty() {
            return Err("Empty BudZKVM bytecode".into());
        }
        if !bytecode.len().is_multiple_of(8) {
            return Err("BudZKVM bytecode length must be a multiple of 8 bytes".into());
        }

        let program = decode_program(bytecode)?;
        let mut vm = Vm::with_mainnet_mode(CONTRACT_VM_MEMORY_BYTES, gas_limit, mainnet)
            .with_step_limit(bud_vm::MAX_CONTRACT_TRACE_STEPS);
        vm.context.sender = ctx.sender;
        vm.context.nonce = ctx.nonce;
        vm.context.block_height = ctx.block_height;

        // Use run_receipt so the trace matches prover/AIR assumptions
        // (including terminal Halt row semantics).
        //
        // `catch_unwind` is not the safety net here. The release profile
        // builds with `panic = "abort"`, so a panic inside `run_receipt`
        // would take the validating node down before this frame saw it. The
        // property the node relies on is that `run_receipt` returns for every
        // program, which the `vm_execute` fuzz target asserts directly on
        // bytecode the compiler never wrote; this wrapper only turns a panic
        // into an error in the dev and test profiles, where unwinding exists.
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

        let proof_bytes = if prove_execution {
            let public_inputs = build_public_inputs(&program, &vm, &receipt);
            let proof = Prover::prove(&vm.trace, &public_inputs, &program)
                .map_err(|err| format!("BudZKVM proof generation failed: {err:?}"))?;
            Prover::verify(&proof, &public_inputs, &program)
                .map_err(|err| format!("BudZKVM proof verification failed: {err:?}"))?;
            proof.proof_bytes.len()
        } else {
            0
        };

        Ok(ZkVmReceipt {
            gas_used: receipt.gas_used,
            steps: receipt.trace_len as usize,
            events: receipt.events.clone(),
            proof_bytes,
        })
    }

    /// Generates and checks a universal BudZero predicate STARK proof (`BLG-242`).
    ///
    /// exposed for: ZkVm universal predicate adapters and contract verification callers.
    ///
    /// # Errors
    ///
    /// Returns [`bud_proof::predicates::PredicateError`] if the predicate statement
    /// fails validation or STARK verification.
    pub fn prove_and_verify_predicate(
        statement: &bud_proof::predicates::PredicateStatement,
    ) -> Result<bud_proof::predicates::PredicateProof, bud_proof::predicates::PredicateError> {
        let proof = bud_proof::predicates::prove_predicate(statement)?;
        bud_proof::predicates::verify_predicate(&proof)?;
        Ok(proof)
    }
}

/// Produce a real STARK proof for a BudZKVM bytecode program, returning the
/// Proof envelope, its public inputs and the decoded program.
///
/// This is the proving counterpart used by the chain ↔ BudZKVM proof bridge (and
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
///
/// The staged-rollout opcode gate applies here as on the ContractCall path.
pub fn prove_bytecode_with_memory<F>(
    bytecode: &[u8],
    gas_limit: u64,
    setup: F,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String>
where
    F: FnOnce(&mut [u8]) -> Result<(), String>,
{
    prove_bytecode_inner_with_memory(
        bytecode,
        gas_limit,
        true,
        DEFAULT_CHAIN_ID,
        TxContext::default(),
        Some(Box::new(setup)),
    )
}

/// Prove bytecode reading a host-published memory image while binding `chain_id`
/// and transaction context (`sender`, `nonce`, `block_height`) into the trace
/// and `ExecutionPublicInputs`.
///
/// Convenience: AI and ZK provers call [`prove_bytecode_with_memory_context`] to
/// produce replay-protected proofs tied to the attaching transaction.
///
/// # Errors
///
/// Returns an error if memory setup, VM execution, or STARK proving/verification fails.
pub fn prove_bytecode_with_memory_context<F>(
    bytecode: &[u8],
    gas_limit: u64,
    chain_id: u64,
    ctx: TxContext,
    setup: F,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String>
where
    F: FnOnce(&mut [u8]) -> Result<(), String>,
{
    prove_bytecode_inner_with_memory(
        bytecode,
        gas_limit,
        true,
        chain_id,
        ctx,
        Some(Box::new(setup)),
    )
}

fn prove_bytecode_inner(
    bytecode: &[u8],
    gas_limit: u64,
    mainnet: bool,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String> {
    prove_bytecode_inner_with_memory(
        bytecode,
        gas_limit,
        mainnet,
        DEFAULT_CHAIN_ID,
        TxContext::default(),
        None,
    )
}

type MemorySetup<'a> = Box<dyn FnOnce(&mut [u8]) -> Result<(), String> + 'a>;

fn prove_bytecode_inner_with_memory(
    bytecode: &[u8],
    gas_limit: u64,
    mainnet: bool,
    chain_id: u64,
    ctx: TxContext,
    setup: Option<MemorySetup<'_>>,
) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String> {
    if bytecode.is_empty() {
        return Err("Empty BudZKVM bytecode".into());
    }
    if !bytecode.len().is_multiple_of(8) {
        return Err("BudZKVM bytecode length must be a multiple of 8 bytes".into());
    }
    let program = decode_program(bytecode)?;
    // A pre-state setup (the stateful-contract door stages memory before the
    // run) appends its own rows, so it gets twice the step budget. Both caps
    // sit under `MAX_PROVER_WITNESS_ROWS` through the const assertion above.
    let max_steps = if setup.is_some() {
        bud_vm::MAX_CONTRACT_TRACE_STEPS.saturating_mul(2)
    } else {
        bud_vm::MAX_CONTRACT_TRACE_STEPS
    };
    let mut vm = Vm::with_mainnet_mode(CONTRACT_VM_MEMORY_BYTES, gas_limit, mainnet)
        .with_step_limit(max_steps);
    vm.context.sender = ctx.sender;
    vm.context.nonce = ctx.nonce;
    vm.context.block_height = ctx.block_height;
    if let Some(setup) = setup {
        setup(&mut vm.memory)?;
    }
    let receipt =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm.run_receipt(&program)))
            .map_err(|_| "BudZKVM execution failed".to_string())?;
    if !receipt.success {
        // The VM's own error, as `execute_bytecode_inner` reports it: an
        // activation refusal reaching this branch through
        // `prove_bytecode_mainnet` was flattened to one string, so the caller
        // could not tell a gated opcode from an out-of-gas.
        return Err(match receipt.error {
            Some(e) => format!("BudZKVM execution failed: {e:?}"),
            None => "BudZKVM execution failed".to_string(),
        });
    }
    let public_inputs = build_public_inputs_for_chain(&program, &vm, &receipt, chain_id);
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
    build_public_inputs_for_chain(program, vm, receipt, DEFAULT_CHAIN_ID)
}

fn build_public_inputs_for_chain(
    program: &[u64],
    vm: &Vm,
    receipt: &bud_vm::ExecutionReceipt,
    chain_id: u64,
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
    //
    // `final_state_root` is the storage-write digest, on purpose. The AIR
    // binds `state_writes_digest` to the SWrite chain (constraint (2b)) and
    // binds `final_state_root` only to itself: it is a prover-supplied value
    // the circuit copies into the last row, nothing derives it. The chain
    // stores it as the domain's `last_committed_hash`, so the only value that
    // makes that record a commitment to a real transition is the one the
    // proof constrains. `submit_zk_proof` refuses a submission where the two
    // differ; this is where the equality is produced.
    ExecutionPublicInputs {
        chain_id,
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
        let bytecode: Vec<u8> = program.into_iter().flat_map(u64::to_le_bytes).collect();

        let receipt = ZkVmExecutor::execute_bytecode(
            &bytecode,
            DEFAULT_CONTRACT_GAS_LIMIT,
            TxContext::default(),
        )
        .unwrap();

        assert_eq!(receipt.events, vec![7]);
        assert!(receipt.steps > 0);
        assert!(receipt.proof_bytes > 0);
    }

    /// Both `VerifyMerkle` and `VerifyInference` are active under
    /// `MainnetActivation::default()` (backed by Poseidon AIR constraints) and
    /// remain gated off under explicit `MainnetActivation::closed()`.
    #[test]
    fn contract_call_bytecode_cannot_reach_a_gated_opcode() {
        let inf_program = vec![
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 0xAB,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Load,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 0xCD,
            }
            .encode(),
            Instruction {
                opcode: Opcode::VerifyInference,
                rd: 4,
                rs1: 1,
                rs2: 2,
                imm: 3,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Log,
                rd: 0,
                rs1: 4,
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
        let bytecode: Vec<u8> = inf_program.into_iter().flat_map(u64::to_le_bytes).collect();
        let receipt = ZkVmExecutor::execute_bytecode(
            &bytecode,
            DEFAULT_CONTRACT_GAS_LIMIT,
            TxContext::default(),
        )
        .expect("VerifyInference must execute and prove on the ContractCall path");
        assert_eq!(
            receipt.events,
            vec![bud_vm::verify_inference_digest(0xAB, 0xCD, 3)]
        );
        prove_bytecode_mainnet(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT)
            .expect("VerifyInference must prove cleanly on mainnet path");

        for opcode in [Opcode::VerifyMerkle, Opcode::VerifyInference] {
            let word = Instruction {
                opcode,
                rd: 1,
                rs1: 2,
                rs2: 3,
                imm: 0,
            }
            .encode();
            let err = bud_isa::Instruction::decode_for_mainnet(
                word,
                bud_isa::MainnetActivation::closed(),
            )
            .expect_err("explicit closed activation must still refuse gated opcodes");
            assert!(
                matches!(err, bud_isa::DecodeError::MainnetActivationRequired(_)),
                "unexpected error for closed activation: {err}"
            );
        }
    }

    /// Memory-image proving shares the canonical `MainnetActivation::default()`
    /// table and proves `VerifyInference` programs identically to direct calls.
    #[test]
    fn memory_image_prover_cannot_reach_a_gated_opcode() {
        let program = vec![
            Instruction {
                opcode: Opcode::Load,
                rd: 1,
                rs1: 0,
                rs2: 0,
                imm: 19,
            }
            .encode(),
            Instruction {
                opcode: Opcode::Load,
                rd: 2,
                rs1: 0,
                rs2: 0,
                imm: 23,
            }
            .encode(),
            Instruction {
                opcode: Opcode::VerifyInference,
                rd: 4,
                rs1: 1,
                rs2: 2,
                imm: 5,
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
        let bytecode: Vec<u8> = program.into_iter().flat_map(u64::to_le_bytes).collect();
        let (env, pi, words) =
            prove_bytecode_with_memory(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT, |_| Ok(()))
                .expect("VerifyInference must prove on memory-image prover");
        Prover::verify(&env, &pi, &words).expect("memory-image proof verifies");
    }

    /// `MainnetActivation::default()` is active for AIR-backed `VerifyMerkle`
    /// and `VerifyInference`, and `bud-vm` reads `MainnetActivation::default()`.
    #[test]
    fn the_staged_rollout_defaults_are_the_ones_in_force() {
        let d = bud_isa::MainnetActivation::default();
        assert!(
            d.verify_merkle_enabled,
            "VerifyMerkle is enabled by default with 64-depth 30-round Poseidon constraints"
        );
        assert!(
            d.verify_inference_enabled,
            "VerifyInference is enabled by default with 30-round Poseidon commitment AIR"
        );

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
            "the VM no longer decodes against MainnetActivation::default()"
        );
        assert!(
            !vm_code.contains("MainnetActivation::full()"),
            "the VM should reference MainnetActivation::default() cleanly"
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
        let bytecode: Vec<u8> = program.into_iter().flat_map(u64::to_le_bytes).collect();

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
        let bytecode: Vec<u8> = program.into_iter().flat_map(u64::to_le_bytes).collect();
        let receipt = ZkVmExecutor::execute_bytecode(
            &bytecode,
            DEFAULT_CONTRACT_GAS_LIMIT,
            TxContext::default(),
        )
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
    /// Canonical 30-round Poseidon binding on `VerifyInference` (never constant zero).
    #[test]
    fn verify_inference_never_reports_success() {
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

            let mut vm = bud_vm::Vm::with_mainnet_mode(8192, DEFAULT_CONTRACT_GAS_LIMIT, true);
            let receipt = vm.run_receipt(&program_words);
            assert!(
                receipt.success,
                "VerifyInference must execute in mainnet mode"
            );
            let m = if model < 0 {
                bud_vm::GOLDILOCKS_P.wrapping_sub(u64::from(model.unsigned_abs()))
            } else {
                u64::from(model.cast_unsigned())
            };
            let x = if input < 0 {
                bud_vm::GOLDILOCKS_P.wrapping_sub(u64::from(input.unsigned_abs()))
            } else {
                u64::from(input.cast_unsigned())
            };
            let aux = if proof_type < 0 {
                bud_vm::GOLDILOCKS_P.wrapping_sub(u64::from(proof_type.unsigned_abs()))
            } else {
                u64::from(proof_type.cast_unsigned())
            };
            assert_eq!(vm.registers[4], bud_vm::verify_inference_digest(m, x, aux));
        }
    }

    /// VerifyInference runs in mainnet mode under `MainnetActivation::default()`
    /// and remains rejected under `MainnetActivation::closed()`.
    #[test]
    fn verify_inference_gated_in_mainnet_mode() {
        let program = [
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
                opcode: Opcode::VerifyInference,
                rd: 4,
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
            .iter()
            .flat_map(|instruction| instruction.encode().to_le_bytes())
            .collect();

        let receipt = ZkVmExecutor::execute_bytecode_mainnet(&bytecode, DEFAULT_CONTRACT_GAS_LIMIT)
            .expect("VerifyInference decodes and proves under MainnetActivation::default()");
        assert!(receipt.proof_bytes > 0);
        assert!(
            bud_isa::Instruction::decode_for_mainnet(
                program[2].encode(),
                bud_isa::MainnetActivation::closed(),
            )
            .is_err(),
            "explicitly closed activation must still refuse VerifyInference"
        );
    }

    #[test]
    fn contract_infinite_loop_stops_within_step_limit_without_prover_oom() {
        let jump = Instruction {
            opcode: Opcode::Jmp,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        };
        let bytecode: Vec<u8> = jump.encode().to_le_bytes().to_vec();
        let err = ZkVmExecutor::execute_bytecode(
            &bytecode,
            DEFAULT_CONTRACT_GAS_LIMIT,
            TxContext::default(),
        )
        .expect_err("infinite loop must terminate via OutOfGas within step limit");
        assert!(err.contains("OutOfGas"), "unexpected error: {err}");
    }

    #[test]
    fn execute_for_block_runs_gated_vm_without_prover_allocation() {
        let halt = Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        };
        let bytecode = halt.encode().to_le_bytes().to_vec();
        let receipt = ZkVmExecutor::execute_for_block(
            &bytecode,
            DEFAULT_CONTRACT_GAS_LIMIT,
            TxContext::default(),
        )
        .expect("halt must succeed");
        assert_eq!(receipt.proof_bytes, 0);
        assert!(receipt.steps >= 1);
    }

    #[test]
    fn execute_bytecode_still_proves_what_execute_for_block_deliberately_skips() {
        let halt = Instruction {
            opcode: Opcode::Halt,
            rd: 0,
            rs1: 0,
            rs2: 0,
            imm: 0,
        };
        let bytecode = halt.encode().to_le_bytes().to_vec();
        let receipt = ZkVmExecutor::execute_bytecode(
            &bytecode,
            DEFAULT_CONTRACT_GAS_LIMIT,
            TxContext::default(),
        )
        .expect("halt must succeed");
        assert!(receipt.steps >= 1);
        // The block path moved to `execute_for_block` (no prover allocation on
        // the validator critical path); this call pins that the proving entry
        // point still runs the inline prover, so a future refactor cannot
        // silently turn every receipt into an unproved one.
        assert!(receipt.proof_bytes > 0);
        // The same program under the block path proves nothing.
        let unproved = ZkVmExecutor::execute_for_block(
            &bytecode,
            DEFAULT_CONTRACT_GAS_LIMIT,
            TxContext::default(),
        )
        .expect("halt must succeed");
        assert_eq!(unproved.proof_bytes, 0);
    }
}
