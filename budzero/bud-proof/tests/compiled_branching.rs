// Integration test: an unwrap here is how the test reports a broken
// invariant, so the workspace-wide panic gate does not apply.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! FINDING: the conditional branching the compiler emits could not be proven.
//!
//! Measured with a live `bud-cli run`: EVERY program containing a branch gave
//! "Verification of generated proof failed!", while straight-line programs
//! passed.
//!
//!   example.bud      (no Jmp/Jnz, 22 steps) -> VALID
//!   example2.bud     (no Jmp/Jnz, 16 steps) -> VALID
//!   long.bud         (no Jmp/Jnz, 19 steps) -> VALID
//!   if_only.bud      (Jnz + Jmp)            -> FAILED
//!   short_loop.bud   (Jnz + Jmp)            -> FAILED
//!   control_flow.bud (Jnz + Jmp)            -> FAILED
//!   example_loop.bud (Jnz + Jmp)            -> FAILED
//!
//! (`long.bud`, `if_only.bud` and `short_loop.bud` were written by hand for
//! that measurement and are not kept in the tree; the other four are.)
//!
//! Comparing the bytecode settled the distinction: the opcode set of the
//! failing programs contains `Jnz` and `Jmp`, and the passing ones contain
//! neither. So the problem is not the trace length but branching itself -- a
//! straight 19 step program passes while a two-iteration loop fails.
//!
//! The existing 106 prover tests had fallen into this gap: they all prove
//! HAND-BUILT instruction sequences (`inst(Opcode::Jnz, ...)`), and none of
//! them proves the compiler's actual output. When a hand-built Jnz passes but a
//! compiled Jnz fails, the difference is not in the instruction itself but in
//! what surrounds it: the pc target, the call frame, the register allocation.
//!
//! This test closes that gap: it starts from source code, runs the compiler,
//! executes the result on the VM and verifies the proof that was PRODUCED.

use bud_compiler::compile;
use bud_isa::IsaProfile;
use bud_proof::adapter::{ExecutionPublicInputs, ProofEnvelope, ProverAdapter};
use bud_proof::DefaultAdapter as Prover;
use bud_vm::Vm;
use tiny_keccak::{Hasher, Keccak};

/// Compiles, executes, proves and verifies the source. `Ok(())` = the proof is valid.
///
/// Public inputs are built the SAME way as on `bud-cli`'s `run` path:
/// `initial_state_root` is not the root of the state tree but the memory+register
/// image the AIR folds; giving a hand-written constant produces
/// `PublicInputsMismatch`.
fn compile_run_prove(source: &str) -> Result<(), String> {
    let (envelope, pi, bytecode) = prove_source(source)?;
    Prover::verify(&envelope, &pi, &bytecode).map_err(|e| format!("the proof is invalid: {e:?}"))
}

/// Compiles, executes and proves the source. The run must succeed: a proof of
/// a failed run would pass the checks below and say nothing about branching.
fn prove_source(source: &str) -> Result<(ProofEnvelope, ExecutionPublicInputs, Vec<u64>), String> {
    let bytecode =
        compile(source, IsaProfile::Experimental).map_err(|e| format!("compile error: {e:?}"))?;

    let mut vm = Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
    let receipt = vm.run_receipt(&bytecode);
    if !receipt.success {
        return Err("the compiled program did not run to success".to_string());
    }

    let mut bytecode_bytes = Vec::with_capacity(bytecode.len() * 8);
    for w in &bytecode {
        bytecode_bytes.extend_from_slice(&w.to_le_bytes());
    }
    let mut program_hash = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(&bytecode_bytes);
    k.finalize(&mut program_hash);

    let initial_state_root = bud_proof::initial_state_root_of(
        bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(&vm.trace)),
        bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
            &vm.trace,
        )),
    );

    let pi = ExecutionPublicInputs {
        chain_id: 1,
        program_hash,
        initial_state_root,
        final_state_root: [0u8; 32],
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: bud_proof::event_digest_from_events(&receipt.events),
        state_writes_digest: [0u8; 32],
    };

    let envelope = Prover::prove(&vm.trace, &pi, &bytecode)
        .map_err(|e| format!("the proof could not be produced: {e:?}"))?;
    Ok((envelope, pi, bytecode))
}

/// Control: a branchless program can be proven. This test must be GREEN;
/// if it turns red the problem is not branching but the whole pipeline
/// and the diagnosis of the test below would be misleading.
#[test]
fn a_branchless_program_is_proven() {
    let source = r#"
contract Straight {
    pub fn main() {
        let a = 1;
        let b = 2;
        let c = a + b;
        emit R(c);
    }
}
"#;
    compile_run_prove(source).expect("a branchless program has to be provable");
}

/// FINDING: a program containing a single `if` could not be proven.
#[test]
fn a_compiled_if_is_proven() {
    let source = r#"
contract IfOnly {
    pub fn main() {
        let a = 5;
        if (a > 3) {
            emit Greater(a);
        } else {
            emit Smaller(a);
        }
    }
}
"#;
    compile_run_prove(source)
        .expect("the conditional branching the compiler emits has to be provable");
}

/// FINDING: a program containing a `while` loop could not be proven.
#[test]
fn a_compiled_while_loop_is_proven() {
    let source = r#"
contract ShortLoop {
    pub fn main() {
        let i = 0;
        while (i < 2) {
            i = i + 1;
        }
        emit R(i);
    }
}
"#;
    compile_run_prove(source).expect("the loop the compiler emits has to be provable");
}

/// A loop that contains a branch: the pc targets of the inner `if` and of the
/// loop back edge both have to hold in one proof.
#[test]
fn a_compiled_loop_with_a_branch_inside_is_proven() {
    let source = r#"
contract LoopWithBranch {
    pub fn main() {
        let i = 0;
        while (i < 3) {
            if (i > 1) {
                emit Big(i);
            } else {
                emit Small(i);
            }
            i = i + 1;
        }
    }
}
"#;
    compile_run_prove(source).expect("a branch inside a loop has to be provable");
}

const IF_SOURCE: &str = r#"
contract IfOnly {
    pub fn main() {
        let a = 5;
        if (a > 3) {
            emit Greater(a);
        } else {
            emit Smaller(a);
        }
    }
    }
"#;

const LOOP_SOURCE: &str = r#"
contract ShortLoop {
    pub fn main() {
        let i = 0;
        while (i < 2) {
            i = i + 1;
        }
        emit R(i);
    }
    }
"#;

/// A proof of one compiled program must not verify against the bytecode of
/// another compiled program.
#[test]
fn a_compiled_proof_is_refused_for_other_bytecode() {
    let (envelope, pi, bytecode) = prove_source(IF_SOURCE).expect("the control proof must exist");
    assert!(
        Prover::verify(&envelope, &pi, &bytecode).is_ok(),
        "the control proof must verify, or the refusal below proves nothing"
    );
    let other = compile(LOOP_SOURCE, IsaProfile::Experimental).expect("the loop must compile");
    assert_ne!(other, bytecode, "the two programs must differ");
    assert!(
        Prover::verify(&envelope, &pi, &other).is_err(),
        "a proof of one compiled program verified against another program"
    );
}
