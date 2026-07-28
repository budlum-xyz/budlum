//! End-to-end coverage for the BudL toolchain: every checked-in `.bud` program
//! must compile, execute, prove and verify.
//!
//! Nothing exercised the compiler output through the prover before this file.
//! The unit tests inside `bud-proof` build their public inputs by hand, and the
//! shared helper hard-codes `event_digest: [0u8; 32]` — correct only for
//! programs that emit nothing. `bud-cli` filled that field with
//! `keccak256(events)`, so every proof it produced failed verification with
//! `OodEvaluationMismatch` and `bud-cli prove`/`run` were unusable.

use bud_isa::IsaProfile;
use bud_proof::{event_digest_from_events, ExecutionPublicInputs, ProverAdapter};
use bud_vm::Vm;
use tiny_keccak::{Hasher, Keccak};

/// Straight-line programs: these must survive the whole pipeline.
const PROVABLE_PROGRAMS: &[&str] = &["example.bud", "example2.bud", "test_prover.bud"];

/// Programs whose control flow skips an instruction.
///
/// The Program CTL LogUp in `plonky3_air` pairs every CPU row with exactly one
/// preprocessed program row, so an instruction that is never executed leaves an
/// unmatched row and verification fails. They must still compile and execute.
const BRANCHING_PROGRAMS: &[&str] = &["example_loop.bud", "control_flow.bud"];

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("bud-cli lives inside the budzero workspace")
        .to_path_buf()
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

fn public_inputs_for(vm: &Vm, bytecode: &[u64], events: &[u64]) -> ExecutionPublicInputs {
    let bytecode_bytes: Vec<u8> = bytecode
        .iter()
        .flat_map(|&word| word.to_le_bytes().to_vec())
        .collect();
    ExecutionPublicInputs {
        chain_id: 1,
        program_hash: keccak256(&bytecode_bytes),
        initial_state_root: [0u8; 32],
        final_state_root: [0u8; 32],
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: event_digest_from_events(events),
    }
}

#[test]
fn every_straight_line_program_compiles_executes_proves_and_verifies() {
    let root = workspace_root();
    for name in PROVABLE_PROGRAMS {
        let path = root.join(name);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{name}: cannot read {}: {e}", path.display()));

        let bytecode = bud_compiler::compile(&source, IsaProfile::Production)
            .unwrap_or_else(|e| panic!("{name}: compile failed: {e:?}"));

        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&bytecode);
        assert!(
            receipt.success,
            "{name}: execution failed: {:?}",
            receipt.error
        );

        let pi = public_inputs_for(&vm, &bytecode, &receipt.events);
        let envelope = bud_proof::Plonky3Adapter::prove(&vm.trace, &pi, &bytecode)
            .unwrap_or_else(|e| panic!("{name}: prove failed: {e:?}"));

        bud_proof::Plonky3Adapter::verify(&envelope, &pi, &bytecode)
            .unwrap_or_else(|e| panic!("{name}: verify rejected a self-generated proof: {e:?}"));
    }
}

/// Canary: if a caller goes back to hashing the event list, a program that
/// actually emits events must fail verification.
#[test]
fn hashing_the_event_list_breaks_verification_of_an_emitting_program() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("example.bud")).expect("read example.bud");
    let bytecode = bud_compiler::compile(&source, IsaProfile::Production).expect("compile");

    let mut vm = Vm::new(1024);
    let receipt = vm.run_receipt(&bytecode);
    assert!(receipt.success, "example.bud must execute cleanly");
    assert!(
        !receipt.events.is_empty(),
        "this canary needs emitted events"
    );

    let mut pi = public_inputs_for(&vm, &bytecode, &receipt.events);
    let good = bud_proof::Plonky3Adapter::prove(&vm.trace, &pi, &bytecode).expect("prove");
    assert!(
        bud_proof::Plonky3Adapter::verify(&good, &pi, &bytecode).is_ok(),
        "accumulator-built digest must verify"
    );

    let event_bytes: Vec<u8> = receipt
        .events
        .iter()
        .flat_map(|&e| e.to_le_bytes().to_vec())
        .collect();
    pi.event_digest = keccak256(&event_bytes);
    let bad = bud_proof::Plonky3Adapter::prove(&vm.trace, &pi, &bytecode).expect("prove");
    assert!(
        bud_proof::Plonky3Adapter::verify(&bad, &pi, &bytecode).is_err(),
        "a hashed event digest must not satisfy the AIR binding"
    );
}

/// Branching programs must still compile and execute; only proving is blocked.
#[test]
fn branching_programs_execute_but_cannot_be_proved_yet() {
    let root = workspace_root();
    for name in BRANCHING_PROGRAMS {
        let source = std::fs::read_to_string(root.join(name))
            .unwrap_or_else(|e| panic!("{name}: cannot read: {e}"));
        let bytecode = bud_compiler::compile(&source, IsaProfile::Production)
            .unwrap_or_else(|e| panic!("{name}: compile failed: {e:?}"));

        let mut vm = Vm::new(1024);
        let receipt = vm.run_receipt(&bytecode);
        assert!(
            receipt.success,
            "{name}: execution must still succeed: {:?}",
            receipt.error
        );

        let visited: std::collections::HashSet<usize> =
            vm.trace.iter().map(|step| step.pc).collect();
        assert!(
            visited.len() < bytecode.len(),
            "{name}: this list is for programs that leave an instruction unexecuted \
             ({} of {} program counters visited)",
            visited.len(),
            bytecode.len()
        );

        let pi = public_inputs_for(&vm, &bytecode, &receipt.events);
        let envelope = bud_proof::Plonky3Adapter::prove(&vm.trace, &pi, &bytecode)
            .unwrap_or_else(|e| panic!("{name}: prove failed: {e:?}"));
        assert!(
            bud_proof::Plonky3Adapter::verify(&envelope, &pi, &bytecode).is_err(),
            "{name}: verified unexpectedly — the Program CTL branch gap looks fixed, \
             update BudL_SPEC.md and move this program to PROVABLE_PROGRAMS"
        );
    }
}

/// The checked-in `state.json` is the default state file for `bud-cli`, so it
/// must deserialise into the current `bud_state::Account` shape. It carried
/// only `nonce`/`balance` and made every default-path invocation fail with
/// "missing field `code_hash`".
#[test]
fn checked_in_state_file_matches_the_account_schema() {
    let path = workspace_root().join("state.json");
    let raw = std::fs::read_to_string(&path).expect("read state.json");
    let parsed: std::collections::HashMap<String, bud_state::Account> =
        serde_json::from_str(&raw).expect("state.json must match bud_state::Account");
    assert!(
        !parsed.is_empty(),
        "state.json should carry at least one account"
    );
}
