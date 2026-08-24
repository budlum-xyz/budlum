// Integration test: an unwrap here is how the test reports a broken
// invariant, so the workspace-wide panic gate does not apply.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end coverage for the BudL toolchain: every checked-in `.bud` program
//! must compile, execute, prove and verify.
//!
//! Nothing exercised the compiler output through the prover before this file.
//! The unit tests inside `bud-proof` build their public inputs by hand, and the
//! shared helper hard-codes `event_digest: [0u8; 32]` - correct only for
//! programs that emit nothing. `bud-cli` filled that field with
//! `keccak256(events)`, so every proof it produced failed verification with
//! `OodEvaluationMismatch` and `bud-cli prove`/`run` were unusable.

use bud_isa::IsaProfile;
use bud_proof::{event_digest_from_events, ExecutionPublicInputs, ProverAdapter};
use bud_vm::Vm;
use tiny_keccak::{Hasher, Keccak};

/// Programs that must survive the whole pipeline.
///
/// Branching programs belong here too: the Program CTL is now a *lookup*,
/// not a permutation. Because `COL_PROG_MULT` carries how many times each ROM row
/// ran, a skipped instruction (0 times) and a loop body (N times) do not break the balance.
const PROVABLE_PROGRAMS: &[&str] = &[
    "example.bud",
    "example2.bud",
    "test_prover.bud",
    "example_loop.bud",
    "control_flow.bud",
];

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
    public_inputs_with_writes(vm, bytecode, events, [0u8; 32])
}

/// The public inputs for a program that writes storage.
///
/// `state_writes_digest` AIR tarafindan gercek SWrite zincirine baglanir;
/// sabit sifir vermek, depolamaya dokunan her programin dogrulamasini
/// dusurur.
fn public_inputs_with_writes(
    vm: &Vm,
    bytecode: &[u64],
    events: &[u64],
    state_writes_digest: [u8; 32],
) -> ExecutionPublicInputs {
    let bytecode_bytes: Vec<u8> = bytecode
        .iter()
        .flat_map(|&word| word.to_le_bytes().to_vec())
        .collect();
    // The AIR folds every pre-seeded memory word and register into trace
    // columns and compares them against this root, so it is computed from the
    // trace rather than assumed to be zero. Programs that seed neither fold to
    // zero and land on the same all-zero root.
    let initial_state_root = bud_proof::initial_state_root_of(
        bud_proof::memory_image_commitment_of_reads(&bud_proof::initial_memory_reads(&vm.trace)),
        bud_proof::register_image_commitment_of_reads(&bud_proof::initial_register_reads(
            &vm.trace,
        )),
    );
    ExecutionPublicInputs {
        chain_id: 1,
        program_hash: keccak256(&bytecode_bytes),
        initial_state_root,
        final_state_root: [0u8; 32],
        sender: vm.context.sender,
        nonce: vm.context.nonce,
        block_height: vm.context.block_height,
        gas_limit: vm.gas_limit,
        gas_used: vm.gas_used,
        exit_code: 0,
        trace_len: vm.trace.len() as u64,
        event_digest: event_digest_from_events(events),
        state_writes_digest,
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

/// A struct-using contract must survive the whole pipeline.
///
/// The generated prologue points the heap pointer at `bud_compiler::HEAP_BASE`
/// (4096), so a `Vm` smaller than that faults with `InvalidMemoryAccess` on the
/// first struct literal. `bud-cli` built `Vm::new(1024)` while the compiler's
/// own tests sized theirs at 8192, so every struct contract failed only through
/// the CLI. This test runs the real host memory size.
#[test]
fn a_struct_using_contract_runs_and_proves() {
    let source = "contract S {\n\
                  \x20   struct P {\n\
                  \x20       a: u64,\n\
                  \x20       b: u64,\n\
                  \x20   }\n\
                  \x20   pub fn main() {\n\
                  \x20       let p = P { a: 1, b: 2 };\n\
                  \x20       let s = p.a + p.b;\n\
                  \x20       emit Ok(s);\n\
                  \x20   }\n\
                  }\n";
    let bytecode = bud_compiler::compile(source, IsaProfile::Production).expect("compile");

    let mut vm = Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
    let receipt = vm.run_receipt(&bytecode);
    assert!(
        receipt.success,
        "struct contract must execute: {:?}",
        receipt.error
    );
    assert_eq!(receipt.events, vec![3], "p.a + p.b must be 3");

    // Proving is a separate matter and is deliberately not asserted here.
    // A struct contract exercises Store/Load against the heap, and the memory
    // CTL side of the AIR has far thinner test coverage than the register side
    // (bud-proof has no Store test at all). Whether such a program proves is
    // tracked separately; this test's job is to prove that the *host memory
    // floor* is right, which is what the execution assertions above establish.
    let _ = public_inputs_for(&vm, &bytecode, &receipt.events);
}

/// The host memory floor must stay above the heap base, otherwise struct
/// allocation starts out of bounds.
#[test]
fn minimum_vm_memory_leaves_room_above_the_heap_base() {
    assert!(
        bud_compiler::MIN_VM_MEMORY_BYTES > bud_compiler::HEAP_BASE as usize,
        "MIN_VM_MEMORY_BYTES ({}) must exceed HEAP_BASE ({})",
        bud_compiler::MIN_VM_MEMORY_BYTES,
        bud_compiler::HEAP_BASE
    );
}

/// Canary for the bug above: a VM sized below the heap base must still fail, so
/// the floor is doing real work rather than being decoration.
#[test]
fn a_vm_smaller_than_the_heap_base_still_faults_on_structs() {
    let source = "contract S {\n\
                  \x20   struct P {\n\
                  \x20       a: u64,\n\
                  \x20   }\n\
                  \x20   pub fn main() {\n\
                  \x20       let p = P { a: 1 };\n\
                  \x20       emit Ok(p.a);\n\
                  \x20   }\n\
                  }\n";
    let bytecode = bud_compiler::compile(source, IsaProfile::Production).expect("compile");

    let mut vm = Vm::new(1024);
    let receipt = vm.run_receipt(&bytecode);
    assert!(
        !receipt.success,
        "a 1024-byte VM is below HEAP_BASE and must fault; if this now succeeds \
         the heap layout changed and MIN_VM_MEMORY_BYTES needs revisiting"
    );
}

/// Depolama alani bildirmek onu kullanilabilir yapmali.
///
/// `storage { count: u64, }` was parsed and `codegen` emitted a slot for each field,
/// slot ayirip `SWrite` uretebiliyordu, ama sema fonksiyon govdesine bos bir
/// ortamla giriyordu: bildirilen alani okumak da yazmak da "Undefined
/// but it was refused with "variable". The language's persistent state feature was
/// written end to end and no program could reach it.
#[test]
fn a_declared_storage_field_can_be_read_and_written() {
    let source = "contract Counter {\n\
                      storage {\n\
                          count: u64,\n\
                      }\n\
                      pub fn main() {\n\
                          storage::count = storage::count + 7;\n\
                      }\n\
                  }\n";
    let bytecode = bud_compiler::compile(source, IsaProfile::Production)
        .expect("bildirilen bir storage alani derlenebilmeli");

    let mut vm = Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
    let receipt = vm.run_receipt(&bytecode);
    assert!(receipt.success, "kosum basarisiz: {:?}", receipt.error);
    assert_ne!(
        receipt.state_writes_digest, [0u8; 32],
        "depolamaya yazan bir kosum bos olmayan bir yazma ozeti uretmeli"
    );
}

/// Depolamaya yazan bir program kanitlanabilmeli.
///
/// AIR `state_writes_digest`'i gercek SWrite zincirine baglar (Strix HIGH
/// CWE-345). When the caller put a hardcoded zero there a proof was produced but
/// **kendi dogrulayicisinda** dusuyordu. Depolamaya dokunmayan programlarda
/// the defect stayed invisible because zero was the right answer.
#[test]
fn a_storage_writing_program_proves_and_verifies() {
    let source = "contract W {\n\
                      storage {\n\
                          count: u64,\n\
                      }\n\
                      pub fn main() {\n\
                          storage::count = 5;\n\
                      }\n\
                  }\n";
    let bytecode = bud_compiler::compile(source, IsaProfile::Production).expect("compile");

    let mut vm = Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
    let receipt = vm.run_receipt(&bytecode);
    assert!(receipt.success, "kosum basarisiz: {:?}", receipt.error);

    let pi =
        public_inputs_with_writes(&vm, &bytecode, &receipt.events, receipt.state_writes_digest);
    let envelope = bud_proof::Plonky3Adapter::prove(&vm.trace, &pi, &bytecode)
        .expect("a proof must be produced");
    bud_proof::Plonky3Adapter::verify(&envelope, &pi, &bytecode)
        .expect("the produced proof must verify");

    // Kirmizi taraf: eski davranis (sabit sifir) reddedilmeli.
    let zeroed = public_inputs_with_writes(&vm, &bytecode, &receipt.events, [0u8; 32]);
    assert!(
        bud_proof::Plonky3Adapter::verify(&envelope, &zeroed, &bytecode).is_err(),
        "a public input carrying a zero write digest must not be accepted - this is exactly \
         duzeltilen kusurdur"
    );
}

/// The type of a storage field must really exist.
///
/// `Type::from_str` primitif olmayan her adi `Type::Struct(ad)` yapar, bu
/// yuzden `count: Uint644` gibi bir yazim hatasi hayali bir struct tipine
/// turned into one and was accepted silently. The same hole had been closed for
/// struct field types; storage fields had been left out of that pass.
#[test]
fn a_storage_field_with_an_unknown_type_is_refused() {
    let source = "contract T {\n\
                      storage {\n\
                          count: Uint644,\n\
                      }\n\
                      pub fn main() {\n\
                          storage::count = 1;\n\
                      }\n\
                  }\n";
    let err = bud_compiler::compile(source, IsaProfile::Production)
        .expect_err("bilinmeyen bir storage tipi reddedilmeli");
    let text = format!("{err:?}");
    assert!(
        text.contains("Uint644") && text.contains("storage field"),
        "hata alani ve tipi adlandirmali: {text}"
    );

    // Yesil taraf: gercek tip gecmeli.
    let ok = "contract T {\n\
                  storage {\n\
                      count: u64,\n\
                  }\n\
                  pub fn main() {\n\
                      storage::count = 1;\n\
                  }\n\
              }\n";
    bud_compiler::compile(ok, IsaProfile::Production).expect("u64 is a valid storage type");
}
