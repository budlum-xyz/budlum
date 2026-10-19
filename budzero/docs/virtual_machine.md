# Building the virtual machine (bud-vm)

We have defined our instruction set (the ISA). Now we build the "heart" that will actually take those instructions and run them: the virtual machine. This module is called `bud-vm`.

To an ordinary software developer, writing a VM is a complicated `switch-case` loop. But you must never forget you are writing a **ZKVM**. Every step of the VM must be recorded in such a way that the ZK prover can later take those steps and turn them into mathematical equations.

## The VM state

What makes up the momentary state of a VM?

1. **Program counter (PC):** which instruction line are we running right now?
2. **Registers:** the current values of the registers R0 through R31.
3. **Stack:** the small execution stack used by `Call`, `Ret`, `Push`, `Pop`.
4. **Memory/storage:** the application's transient memory and key-value storage area.
5. **Gas counters:** `gas_used` and `gas_limit`. Every instruction has a cost, to cut off infinite loops and DoS risks.
6. **Execution trace:** the "log" records of everything done so far (critical for ZKVMs).

## The execution loop (fetch-decode-execute)

The classic processor loop:

1. **Fetch:** take the next instruction from the address the `PC` points at.
2. **Decode:** split out the opcode, src1, src2, dst and imm inside the instruction.
3. **Execute:** perform the operation the opcode requires, write the result into the `dst` register, and move `PC` to the next instruction.

The `step(program)` function in `bud-vm/src/lib.rs` does exactly this. In the current VM the first rule is: if the VM has already halted or `pc` has run past the program, no new trace row is produced.

```rust
pub fn step(&mut self, program: &[u64]) {
    if self.halted || self.pc >= program.len() {
        self.halted = true;
        return;
    }

    // 1. Fetch
    let raw_inst = program[self.pc];
    let inst = Instruction::decode(raw_inst);
    let cur_pc = self.pc;

    // Every instruction consumes gas.
    self.consume_gas(Self::gas_cost(inst.opcode));

    // 2. Decode
    let src1_val = self.registers[inst.rs1 as usize];
    let src2_val = self.registers[inst.rs2 as usize];

    // 3. Execute
    let (dst_val, next_pc) = match inst.opcode {
        Opcode::Add => {
            let result = src1_val.wrapping_add(src2_val);
            self.registers[inst.rd as usize] = result;
            self.pc += 1;
            (result, cur_pc + 1)
        }
        Opcode::Call => {
            let target = (cur_pc as i64 + inst.imm as i64) as usize;
            self.stack.push((cur_pc + 1) as u64);
            self.pc = target;
            ((cur_pc + 1) as u64, target)
        }
        Opcode::Ret => {
            let target = self.stack.pop().expect("Return stack underflow") as usize;
            self.pc = target;
            (target as u64, target)
        }
        Opcode::Halt => {
            self.halted = true;
            (0, cur_pc)
        }
        // Other opcodes...
    };

    // Record the execution trace!
    self.trace.push(Step {
        pc: cur_pc,
        instruction: inst,
        src1_idx: inst.rs1,
        src2_idx: inst.rs2,
        dst_idx: inst.rd,
        src1_val,
        src2_val,
        dst_val,
        next_pc,
        registers: self.registers,
    });

}
```

That small guard matters a lot to the prover. We do not produce a fake instruction row for a branch or jump that leaves the program; the VM halts deterministically. The trace length and the trace content are therefore always the same for the same bytecode.

## Gas metering

`Vm::new(memory_size)` comes with a default gas limit of `1_000_000`. For tests and L1 integrations `Vm::with_gas_limit(memory_size, gas_limit)` can be used.

Gas costs are deliberately kept simple:

* simple ALU and branch instructions are mostly `1` gas,
* memory/storage operations such as `Load`, `Store`, `SRead`, `SWrite` are `3` gas,
* `Call`, `Ret`, `Push`, `Pop` are `2` gas,
* `Syscall` is `5` gas,
* `Poseidon` and `VerifyMerkle` are `10` gas.

If the limit is exceeded the VM stops with an `Out of gas` error. In the Budlum L1 integration that error becomes a transaction failure and the sender state stays atomically unchanged.

Gas behaviour is pinned by tests. On small programs like `Load + Push + Syscall + Halt`, `gas_used` gives exactly the expected total cost. The infinite-loop example `Jmp 0` is cut off with `Out of gas` when the limit is crossed.

## Deterministic error and edge case semantics

In a ZKVM it is dangerous for behaviour like "did it panic or not" to be incidental or dependent on the Rust build mode. So BudVM defines some edge cases explicitly.

### PC past the program

If `pc >= program.len()`:

* `halted = true`,
* no new `Step` row is added,
* registers and memory do not change.

This matters especially for `Jmp` and `Jnz` instructions that jump outside the program. Control flow ends deterministically on the next `step` call.

### A step after halt

After the `Halt` instruction has executed:

* `pc` stays the same,
* one `Halt` row is added to the trace,
* subsequent `step` calls add no new rows to the trace,
* registers and memory do not change.

This behaviour is our base assumption for strengthening the `COL_IS_HALT` constraints on the prover side.

### Memory access

`Load` works in two modes:

* if `rs1 == 0`, `imm` is written into the `rd` register as an immediate value,
* if `rs1 != 0`, an 8-byte little-endian word is read from address `register[rs1] + imm`.

An invalid memory read returns `0`. An invalid memory write is a no-op. The cases considered invalid:

* a negative address,
* an address that does not fit in `usize`,
* an `addr + 8` overflow,
* `addr + 8 > memory.len()`.

This behaviour is centralized for `Load` and `Store` in the `memory_word_addr` helper.

### Register access

The normal `rd`, `rs1` and `rs2` fields are masked to 5 bits during ISA decoding, so they lie in `0..32`. But `VerifyMerkle` selects its path register through `imm`. If `imm` is negative or out of register range the path value is taken as `0`, so bad bytecode does not directly produce an index panic.

### Arithmetic semantics

BudVM arithmetic runs over the Goldilocks prime field (P = 2^64 - 2^32 + 1):

* `Add`, `Sub`, `Mul`: wrapping u64 arithmetic. No debug/release difference.
* `Div`: Goldilocks field-native modular division, `rd = rs1 * rs2^{-1} mod P`. If the denominator is zero the result is 0.
* `Inv`: modular inverse, `rd = rs1^{-1} mod P`. If the input is zero the result is 0.
* **`Poseidon`**: a 4-round Poseidon hash (alpha=7, width=8). It takes two register values and applies the Poseidon permutation over the Goldilocks field.
* **`VerifyMerkle`**: 64-depth Merkle proof verification. `rs1` = root, `rs2` = leaf, `imm` = the memory address. Memory layout: `[key: u64, 64x sibling: u64]` (520 bytes). At each level the hash direction is chosen by the key's bit, using `poseidon4_hash`.
* **`Not`**: logical NOT, returns 1 if `rs1 == 0`, otherwise 0.
* **`Eq/Neq`**: comparisons. `Lt/Gt/Lte/Gte`: 64-bit comparisons.
* **`And/Or/Xor`**: bitwise operations. `And`: bitwise AND, `Or`: bitwise OR, `Xor`: bitwise XOR.
* **`SRead/SWrite`**: storage read/write. It accesses the slot named by `imm`. It is stored in memory at address `STORAGE_BASE + slot` (for the LogUp CTL).

## The call stack and stack opcodes

BudZKVM's main data model is register based, but for `Call`, `Ret`, `Push`, `Pop` there is a `Vec<u64>`-based stack inside the VM.

* `Call`: pushes the return address onto the stack.
* `Ret`: pops the return address from the stack.
* `Push`: pushes the `rs1` register value onto the stack.
* `Pop`: writes the value popped from the stack into the `rd` register.

Stack underflow is caught by a panic. That behaviour is handled as a failed execution in the proof/backend layer.

## Why do we record an execution trace?

In a classic VM we do a `step` and forget the old state. But in the ZK world the prover **must know what happened on every clock cycle.** The prover's job is to prove, over a STARK circuit, the question *"did the VM really compute these steps correctly?"*

So while the VM runs we append each `Step` object to a list. That is the **execution trace**. This list will later be sent to the ZK prover and turned, row by row and column by column, into an enormous matrix.

`Step` rows no longer carry only "which opcode ran". Every row holds:

* `pc` and `next_pc`,
* the decoded instruction,
* `src1_idx`, `src2_idx`, `dst_idx`,
* `src1_val`, `src2_val` before execution,
* `dst_val`, the instruction's result,
* a 32-register snapshot after execution.

For the detailed trace contract see the [BudVM trace schema](vm_trace_schema.md).

## Trace fixture tests

VM trace behaviour is pinned by fixture tests. They live in `bud-vm/tests/trace_fixtures.rs` and cover three main flows:

1. arithmetic: `Load`, `Add`, `Sub`, `Mul`, `Halt`,
2. control flow: `Jnz`, `Jmp`, and a deterministic halt on leaving the program,
3. memory/storage/event: `Store`, memory `Load`, `SWrite`, `SRead`, `Log`.

These tests do not check only the final register result. On every `Step` row they compare `pc`, `next_pc`, the opcode, the operand values and selected register snapshots. When the VM is refactored, the trace format the prover is fed therefore cannot change silently.

## Storage and the state root

In real applications (contracts, for example) registers alone are not enough; we need key-value storage.

Inside `bud-vm`, rather than a plain `HashMap`, we need a data structure provable in ZK. That is usually a **Merkle tree** or a **sparse Merkle tree (SMT)**.

When the VM executes an `SWrite` (storage write), the value of a leaf in the tree is updated and the tree's **root** changes. By publishing only the latest root as a public input, the prover proves the integrity of a database of billions of records with a few bytes.

Our virtual machine can now run code and produce an execution trace. But seating that trace on ZK mathematics (polynomials) is far from easy. The next chapter examines how we solve that architectural problem and what a **ZK-friendly architecture** looks like.
