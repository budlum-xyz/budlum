#![no_main]

//! Whatever the compiler emits, the VM must survive.
//!
//! `budl_compile` asks whether the front end can be made to panic. This asks
//! the next question: when it succeeds, is the bytecode it produced something
//! the VM can execute without aborting the process?
//!
//! That is a real gap and not a hypothetical one. The compiler and the VM are
//! separate crates with separate tests, and the compiler's own suite runs its
//! output through a `Vm` only in the handful of cases where a test author
//! chose to. Codegen owns register allocation, jump offsets and the heap
//! pointer convention; a bug in any of those produces bytecode that is
//! perfectly well formed as a `Vec<u64>` and wrong the moment it runs.
//!
//! What this asserts: a successful `compile` is followed by a `run_receipt`
//! that returns. An `ExecutionReceipt` with `success == false` is a correct
//! outcome, out of gas is a correct outcome, an invalid memory access reported
//! as an error is a correct outcome. A panic is not.
//!
//! The VM is sized at `MIN_VM_MEMORY_BYTES` rather than something generous on
//! purpose. That constant exists because `bud-cli` used 1024 and every
//! struct-using contract faulted on its first allocation while the compiler's
//! own tests passed at 8192. Fuzzing at exactly the documented minimum is what
//! keeps the constant honest.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    if source.len() > 64 * 1024 {
        return;
    }

    // Only the production profile here. The point of this target is the
    // compiler-to-VM handoff, and running both profiles would double the cost
    // of every iteration to re-test the front end that `budl_compile` already
    // covers.
    let Ok(bytecode) = bud_compiler::compile(source, bud_isa::IsaProfile::Production) else {
        return;
    };

    // Bytecode a fuzzer reached is not bytecode anyone reviewed, so a loop in
    // it can run until the gas limit rather than forever. `run_receipt` is the
    // non-panicking entry point and returns the receipt either way.
    let mut vm = bud_vm::Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
    let _ = vm.run_receipt(&bytecode);
});
