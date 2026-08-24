# Instruction set architecture and bytecode (bud-isa)

The first step in building a virtual machine is designing the language the machine will understand. That language is called the **instruction set architecture (ISA)**. The ISA is the contract between the VM's hardware (or its software emulation) and the outside world.

For BudZKVM we created a separate crate called `bud-isa`. Why separate? Because this language definition is shared by the VM (to run), the compiler (to compile) and the prover (to prove).

## Register based vs stack based

Virtual machines usually fall into two groups:

1. **Stack based (the EVM, the JVM):** operations go through a stack - `PUSH 5`, `PUSH 3`, `ADD`. It is easy to implement and the compiler is relatively easy to write, but the same work takes many more instructions. Tracking "stack depth" in STARK provers can be complicated (and expensive) in ZK terms.
2. **Register based (LuaVM, ARM, RISC-V, BudZKVM):** data is held in a limited number of registers inside the CPU - `ADD R1, R2, R3` (add R2 and R3, write to R1). Instructions are longer but more work is done in fewer steps. It seats far more easily into the table (trace) structure ZKVMs need.

**Decision:** BudZKVM uses a **register-based** architecture. We have 32 general-purpose registers (R0 through R31). **R0 is special: it is hardwired to always hold 0.** That property is critical both for the VM's determinism and for STARK soundness.

## The structure of an instruction

A CPU instruction is not a magic word floating in the air; it is a simple number (bytecode). In BudZKVM every instruction is encoded as a `u64`:

```rust
pub struct Instruction {
    pub opcode: Opcode,  // Which operation? (ADD, LOAD, JMP and so on)
    pub rd: u8,          // Which register receives the result? (destination)
    pub rs1: u8,         // Which register is the first argument read from? (source 1)
    pub rs2: u8,         // Which register is the second argument read from? (source 2)
    pub imm: i32,        // Is there an immediate value?
}
```

### The encoding format

`Instruction::encode()` packs each instruction into a single `u64`:

| Bit range | Field | Description |
|-------------|------|----------|
| 0-7 | `opcode` | The operation code (0x00-0x1E) |
| 8-12 | `rd` | Destination register (0-31) |
| 13-17 | `rs1` | First source register (0-31) |
| 18-22 | `rs2` | Second source register (0-31) |
| 23-54 | `imm` | A 32-bit signed immediate value |

Every instruction is therefore a fixed-size 8-byte word, which is a critical advantage for the bytecode alignment check in the L1 integration.

## Opcodes and their production status

The BudZKVM ISA is split into two profiles, **production** and **experimental**. In the production profile only opcodes whose AIR constraints are complete and mathematically sound may be used. Experimental opcodes are still in development and are refused at build or run time without `cfg(feature = "experimental")`.

### Production opcodes

| Opcode | Hex | Description |
|--------|-----|----------|
| `Halt` | 0x00 | Stop the program |
| `Add` | 0x01 | `rd = rs1 + rs2` (wrapping) |
| `Sub` | 0x02 | `rd = rs1 - rs2` (wrapping) |
| `Mul` | 0x03 | `rd = rs1 * rs2` (wrapping) |
| `Div` | 0x04 | `rd = rs1 * rs2^{-1} mod P` (Goldilocks division) |
| `Inv` | 0x05 | `rd = rs1^{-1} mod P` (modular inverse) |
| `And` | 0x06 | `rd = rs1 & rs2` (bitwise AND) |
| `Or` | 0x07 | `rd = rs1 \| rs2` (bitwise OR) |
| `Xor` | 0x08 | `rd = rs1 ^ rs2` (bitwise XOR) |
| `Not` | 0x09 | `rd = (rs1 == 0) ? 1 : 0` (logical NOT) |
| `Eq` | 0x0A | `rd = (rs1 == rs2) ? 1 : 0` |
| `Neq` | 0x0B | `rd = (rs1 != rs2) ? 1 : 0` |
| `Lt` | 0x0C | `rd = (rs1 < rs2) ? 1 : 0` (64-bit comparison) |
| `Gt` | 0x0D | `rd = (rs1 > rs2) ? 1 : 0` |
| `Lte` | 0x0E | `rd = (rs1 <= rs2) ? 1 : 0` |
| `Gte` | 0x0F | `rd = (rs1 >= rs2) ? 1 : 0` |
| `Jmp` | 0x10 | `pc += imm` (unconditional jump) |
| `Jnz` | 0x11 | `pc += imm` if `rs1 != 0`, otherwise `pc += 1` |
| `Call` | 0x12 | Push the return address onto the stack, `pc += imm` |
| `Ret` | 0x13 | Pop the return address from the stack and update `pc` |
| `Load` | 0x14 | `rd = memory[rs1 + imm]`, or `rd = imm` when rs1=0 |
| `Store` | 0x15 | `memory[rs1 + imm] = rs2` |
| `Push` | 0x16 | Push the `rs1` value onto the stack |
| `Pop` | 0x17 | Pop a value from the stack into `rd` |
| `Assert` | 0x18 | Stop the program unless `rs1 != 0` |
| `Poseidon` | 0x19 | `rd = Poseidon4(rs1, rs2)` (4 rounds, alpha=7) |
| `Log` | 0x1A | Append the `rs1` value to the event log |
| `SRead` | 0x1B | `rd = storage[imm]` (storage read) |
| `SWrite` | 0x1C | `storage[imm] = rs1` (storage write) |
| `Syscall` | 0x1D | `rd = syscall(imm)` |
| `VerifyMerkle` | 0x1E | `rd = verify_merkle(root, leaf, path)`, poseidon4-based, 64 deep |

> All 31 opcodes are at production level. No experimental opcode remains. Every opcode's VM implementation and AIR constraint is complete.

## The bytecode format and the L1 integration

`Instruction::encode()` packs each instruction into a single `u64`. In the CLI and the L1 integration these values are turned into a little-endian byte string:

```rust
let bytes: Vec<u8> = bytecode
    .iter()
    .flat_map(|instruction| instruction.to_le_bytes())
    .collect();
```

`TransactionType::ContractCall` in the Budlum L1 `infra` repository uses this format. The `tx.data` field cannot be empty and its length must be a multiple of 8; every 8 bytes is one BudZKVM instruction.

## ZK-friendly encoding

In traditional VMs this `Instruction` struct is squeezed into a single 32-bit integer with bit shifting (for example `0b00000001_00000001_00000000_00001010`). But in ZKVMs bit shifting is a very expensive operation in the world of polynomials. Because we work over primes, bit-level operations need complicated tables.

So in STARK-based VMs we avoid making the ZKVM do instruction decoding wherever possible.

**The trick:** in BudZKVM the `Instruction` components (`opcode`, `rd`, `rs1`, `rs2`, `imm`) are placed in separate columns of the execution trace matrix. The prover therefore never has to split bits; it takes the column values directly and puts them into the mathematical equation.
