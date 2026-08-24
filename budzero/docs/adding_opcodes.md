# Adding an Opcode

This guide presents, as a checklist, the steps to follow when adding a new opcode to BudZKVM. The aim is to add an opcode deterministically and soundly without breaking the ISA, VM, trace, AIR and proof-stack contract.

## Current status

BudZKVM defines **31 opcodes**. **30 are production** (their AIR constraints are complete) and **1 is experimental** (`VerifyMerkle`). Production opcodes are usable when built with the `default` feature; experimental opcodes require `cfg(feature = "experimental")`.

## 1. Define the ISA surface

Update `bud-isa/src/lib.rs`:

- add a new variant to the `Opcode` enum,
- assign a stable discriminant (starting from 0x1F),
- add the raw byte -> new variant mapping in `Instruction::decode_any()`,
- if the opcode is to be experimental, add it to the `Opcode::is_experimental()` list,
- write an encoding/decoding test.

**Rule:** keep the discriminant stable, because bytecode artifacts may depend on it. If the value is experimental, document that in `docs/isa_and_bytecode.md`.

## 2. Implement the VM semantics

Update `bud-vm/src/lib.rs`:

- add an arm for the new opcode in `Vm::step()`,
- define the register reads, the register writes, `dst_val` and `next_pc`,
- decide how the opcode interacts with memory, storage, stack, gas and halt behaviour,
- set the gas cost in `Vm::gas_cost()`,
- add VM tests for normal behaviour and edge cases.

The VM trace must carry enough information for the AIR to verify this step. If the AIR needs a new witness value, add it deliberately to the `Step` struct and to the trace matrix.

## 3. Expose it from the compiler or the CLI

If the opcode is user facing, update the compiler pipeline:

- `bud-compiler/src/ast.rs` and `parser.rs`: AST/payload changes.
- `bud-compiler/src/sema.rs`: semantic validation.
- `bud-compiler/src/codegen.rs`: bytecode generation.
- CLI examples or fixtures if needed.

Opcodes may exist in the VM before the language exposes them, but the documentation must state whether an opcode is internal, experimental or stable.

## 4. Add trace columns or selectors

Update `bud-proof/src/plonky3_air.rs` and `bud-proof/src/plonky3_prover.rs`:

- add a new selector column only if the existing selectors cannot represent the opcode,
- fill the selector in the `trace_matrix()` function,
- fill any new witness columns,
- keep the trace padding and halt rows consistent,
- if the opcode brings new reads/writes, update the register, memory or lookup events.

**Current trace width: 354 columns.** Add new columns after these groups:
- 0-64: base + selectors + register + memory + soundness
- 65-257: comparison + bitwise witnesses
- 258-353: Poseidon witnesses

Every new column must have a clear meaning in the trace schema document (`docs/vm_trace_schema.md`) before it becomes stable.

## 5. Add the AIR constraints

Inside `BudAir::eval()`:

- gate the opcode-specific equations with the opcode selector (`builder.when(is_my_opcode)`),
- constrain the `next_pc` behaviour,
- constrain the destination values and side effects,
- add boolean/range constraints if a value is meant to be small or binary,
- update the permutation/lookup constraints if the opcode reads or writes shared tables.

**Critical rule:** a constraint must not merely accept an honest trace, it must **refuse** a tampered one. Write a negative test for every constraint.

## 6. Add tests

At minimum:

- `bud-isa`: encoding/decoding coverage for the opcode.
- `bud-vm`: execution coverage (normal + edge cases).
- `bud-proof`: a positive prover test (prove + verify).
- a negative prover/verifier test if the AIR must refuse a tampered witness.
- a compiler snapshot or integration test if BudL emits the opcode.

The test pattern (bud-proof):
```rust
#[test]
fn proves_my_new_opcode() {
    let program = vec![
        inst(Opcode::MyNewOpcode, 1, 2, 3, 0),
        inst(Opcode::Halt, 0, 0, 0, 0),
    ];
    prove_and_verify(program, |vm| {
        vm.registers[2] = input_a;
        vm.registers[3] = input_b;
    });
}
```

## 7. Update the documentation

Files that must be updated:

- `docs/isa_and_bytecode.md`: the opcode format, discriminant and stability status.
- `docs/vm_trace_schema.md`: if new trace columns were added.
- `docs/virtual_machine.md`: if the VM semantics changed.
- `docs/STABILIZATION.md`: if a new production opcode was added.
- `README.md`: roadmap status.

Before sending the change, run the local CI equivalent from `docs/development.md`:

```bash
nix develop --command cargo fmt --all -- --check
nix develop --command cargo check --workspace --all-targets
nix develop --command cargo clippy --workspace --all-targets -- -D warnings
nix develop --command cargo test --workspace
```
