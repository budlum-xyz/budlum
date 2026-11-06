#![no_main]

//! Bytecode the compiler did not write, executed by the VM.
//!
//! # The gap this closes
//!
//! `budl_compile_then_run` reaches the VM through the compiler, so every
//! program it executes is one the front end agreed to emit. That covers the
//! handoff and nothing past it: codegen will not emit a jump past the end of
//! the program, a register index above the file, an immediate that overflows
//! when sign extended, or a `Ret` with an empty call stack. The VM still has
//! to survive all of them, because the compiler is not the only thing that
//! can hand it a program.
//!
//! The seeds for this target were written before the target was. They sat in
//! `fuzz/corpus/zkvm/` for two years under a `.bud` extension while holding
//! raw instruction words, and no fuzz target named `zkvm` ever existed, so
//! nothing ever read them. Their filenames name the opcodes they exercise and
//! the bytes agree with the opcode table: `03_verify_merkle_0x1E` really does
//! start with `VerifyMerkle = 0x1E`, `05_memory_ops` really is `Jmp` followed
//! by `Jnz`. Somebody built the input set for exactly this target and stopped
//! before writing it.
//!
//! # What this asserts
//!
//! `run_receipt` returns, for every input. A receipt with `success == false`
//! is a correct outcome. Out of gas is a correct outcome. `VmError` in the
//! receipt is a correct outcome; that is what the type is for. A panic, an
//! abort, an arithmetic overflow under `overflow-checks`, or an out-of-bounds
//! access reported by the sanitiser is not.
//!
//! # Why the input is bytes and the program is words
//!
//! The VM executes `&[u64]`. Handing the fuzzer eight bytes per instruction
//! and packing them little-endian keeps every byte it mutates meaningful:
//! flipping one bit changes an opcode, a register index or an immediate,
//! rather than shifting the whole program by one byte and turning the rest
//! into noise. It also means the committed seeds, which are instruction words
//! written as bytes, are read back as the instructions they were written to
//! be.
//!
//! # Gas and memory
//!
//! `MIN_VM_MEMORY_BYTES` for the same reason `budl_compile_then_run` uses it:
//! that constant exists because `bud-cli` shipped 1024 and every
//! struct-using contract faulted on its first allocation while the compiler's
//! tests passed at 8192, so fuzzing at exactly the documented minimum is what
//! keeps it honest.
//!
//! The gas limit is lowered from the default. A fuzzer will find an infinite
//! loop within seconds, and at a million gas each of those inputs costs the
//! full budget before halting. The limit is a throughput decision, not a
//! safety one: the property under test is that the VM returns, and it has to
//! return at any limit.

use libfuzzer_sys::fuzz_target;

/// Instructions in a fuzzed program.
///
/// A program long enough to reach every branch in `step` is far shorter than
/// this; the cap is here so that one input cannot spend the iteration budget
/// on decode alone.
const MAX_INSTRUCTIONS: usize = 4096;

/// Gas for one program.
///
/// Low enough that a tight loop terminates quickly, high enough that a
/// straight-line program of `MAX_INSTRUCTIONS` finishes.
const GAS_LIMIT: u64 = 50_000;

fuzz_target!(|data: &[u8]| {
    // Eight bytes per instruction word, little-endian. A trailing partial
    // word is zero-padded rather than dropped: zero is `Halt`, which is a
    // legitimate instruction and keeps short inputs meaningful.
    if data.len() > MAX_INSTRUCTIONS * 8 {
        return;
    }
    let mut program: Vec<u64> = Vec::with_capacity(data.len().div_ceil(8));
    for chunk in data.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        program.push(u64::from_le_bytes(word));
    }
    if program.is_empty() {
        return;
    }

    let mut vm = bud_vm::Vm::with_gas_limit(bud_compiler::MIN_VM_MEMORY_BYTES, GAS_LIMIT);
    let _ = vm.run_receipt(&program);
});
