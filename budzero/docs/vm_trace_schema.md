# BudVM Trace Schema v2

This document pins how the `Step` records produced by `bud-vm` are transferred into the AIR trace matrix, and what the trace columns look like. The prover-side AIR constraints are written against exactly this schema.

## Basic rule

`Vm::step(program)` produces exactly one `Step` whenever it really fetches and executes an instruction. No new trace row is produced when:

* the VM is already in `halted == true`, or
* `pc >= program.len()`.

## Step fields

| Field | Meaning |
| --- | --- |
| `pc` | The program counter before the instruction is fetched |
| `next_pc` | The expected next program counter after the instruction executes |
| `instruction` | The decoded `bud_isa::Instruction` |
| `src1_idx` | The `rs1` register index |
| `src2_idx` | The `rs2` register index |
| `dst_idx` | The `rd` register index |
| `src1_val` | The `rs1` value read before the instruction executes |
| `src2_val` | The `rs2` value read before the instruction executes |
| `dst_val` | The result value the instruction computes |
| `registers` | A 32-register snapshot after the instruction executes |
| `memory_addr` | The memory access address (for Load/Store) |
| `memory_val` | The value read from or written to memory |
| `is_memory_write` | Is this a write? |
| `stack_pointer` | The current value of the stack pointer |

## Prover trace columns (main trace)

The main matrix built on the prover side is **354 columns** wide. The columns fall into these groups.

### Base columns (0-10)
| Index | Column | Description |
|--------|-------|----------|
| 0 | `CLK` | Row counter (clock) |
| 1 | `PC` | Program counter |
| 2 | `OPCODE` | Operation code (0x00-0x1E) |
| 3 | `RD_IDX` | Destination register index |
| 4 | `RS1_IDX` | First source register index |
| 5 | `RS2_IDX` | Second source register index |
| 6 | `RS1_VAL` | First source register value |
| 7 | `RS2_VAL` | Second source register value |
| 8 | `RD_VAL_NEW` | The computed result value |
| 9 | `NEXT_PC` | The expected next PC |
| 10 | `IMM` | Immediate value (as i32) |

### CPU selector columns (11-22)
| Index | Column | Description |
|--------|-------|----------|
| 11 | `IS_ADD` | Add opcode selector |
| 12 | `IS_SUB` | Sub selector |
| 13 | `IS_MUL` | Mul selector |
| 14 | `IS_EQ` | Eq selector |
| 15 | `IS_LT` | Lt selector |
| 16 | `IS_JMP` | Jmp selector |
| 17 | `IS_JNZ` | Jnz selector |
| 18 | `IS_LOAD` | Load selector |
| 19 | `IS_HALT` | Halt selector |
| 20 | `IS_ASSERT` | Assert selector |
| 21 | `IS_LOG` | Log selector |
| 22 | `JNZ_COND` | Jnz condition value (1 = take the jump, 0 = fall through) |

### Register table columns (23-28)
| Index | Column | Description |
|--------|-------|----------|
| 23 | `REG_CLK` | Register event clock |
| 24 | `REG_IDX` | Register index |
| 25 | `REG_VAL` | Register value |
| 26 | `REG_IS_WRITE` | Is this a write event? |
| 27 | `REG_ACTIVE` | Is the event active? |
| 28 | `REG_SAME` | Is the next event for the same register? |

### Extended selector columns (29-48)
| Index | Column | Description |
|--------|-------|----------|
| 29 | `IS_DIV` | Div selector |
| 30 | `IS_INV` | Inv selector |
| 31 | `IS_AND` | And selector |
| 32 | `IS_OR` | Or selector |
| 33 | `IS_XOR` | Xor selector |
| 34 | `IS_NOT` | Not selector |
| 35 | `IS_NEQ` | Neq selector |
| 36 | `IS_GT` | Gt selector |
| 37 | `IS_LTE` | Lte selector |
| 38 | `IS_GTE` | Gte selector |
| 39 | `IS_STORE` | Store selector |
| 40 | `IS_PUSH` | Push selector |
| 41 | `IS_POP` | Pop selector |
| 42 | `IS_CALL` | Call selector |
| 43 | `IS_RET` | Ret selector |
| 44 | `IS_SREAD` | SRead selector |
| 45 | `IS_SWRITE` | SWrite selector |
| 46 | `IS_POSEIDON` | Poseidon selector |
| 47 | `IS_SYSCALL` | Syscall selector |
| 48 | `IS_VERIFY_MERKLE` | VerifyMerkle selector |

### Memory table columns (49-54)
| Index | Column | Description |
|--------|-------|----------|
| 49 | `MEM_CLK` | Memory event clock |
| 50 | `MEM_ADDR` | Memory address |
| 51 | `MEM_VAL` | Memory value |
| 52 | `MEM_IS_WRITE` | Is this a write event? |
| 53 | `MEM_ACTIVE` | Is the event active? |
| 54 | `MEM_SAME` | Is the next event for the same address? |

The memory table covers `Load`, `Store`, `Push`, `Pop`, `Call`, `Ret` and **also `SRead` and `SWrite`.** Storage operations are placed into the memory address space behind the `STORAGE_BASE = 2 << 60` address prefix. Storage consistency is therefore verified through the existing memory LogUp infrastructure, without a separate LogUp table.

### Soundness and public input columns (55-64)
| Index | Column | Description |
|--------|-------|----------|
| 55 | `STACK_PTR` | Stack pointer |
| 56 | `REG_SUB_CLK` | Register sub-clock (LogUp ordering) |
| 57 | `GAS_USED` | Cumulative gas consumption |
| 58 | `DIV_INV` | Div inverse witness |
| 59 | `DIV_ZERO` | Div zero flag |
| 60 | `INV_ZERO` | Inv/Not zero flag (shared) |
| 61 | `EQ_DIFF_INV` | Eq/Neq difference inverse witness |
| 62 | `JNZ_COND_INV` | Jnz condition inverse witness |
| 63 | `RAW_INST` | Raw instruction (encoded u64) |
| 64 | `CPU_ACTIVE` | CPU activity flag (padding isolation) |

### Comparison witness columns (65-257)
| Range | Group | Description |
|--------|------|----------|
| 65-128 | `CMP_RS1_BASE` | The 64-bit decomposition of rs1 (shared by Lt/Gt/Lte/Gte and And/Or/Xor) |
| 129-192 | `CMP_RS2_BASE` | The 64-bit decomposition of rs2 |
| 193-256 | `CMP_EQ_BASE` | Equality prefix flags (eq_0..eq_63, comparison only) |
| 257 | `CMP_LT_RAW` | The raw less-than result (computed from the bit decomposition) |

**Comparison constraints:** the 64-bit decomposition checks that every bit is boolean. The equality prefix flags (eq_i) are computed recursively from MSB to LSB: `eq_i = eq_{i+1} * (a_i == b_i)`. Results: `Lt: rd = cmp_lt_raw`, `Gt: rd = 1 - eq_0 - cmp_lt_raw`, `Lte: rd = eq_0 + cmp_lt_raw`, `Gte: rd = 1 - cmp_lt_raw`.

**Bitwise constraints:** And/Or/Xor use the same bit decomposition columns. `And: rd = Sum(a_i*b_i*2^i)`, `Or: rd = rs1 + rs2 - and_result`, `Xor: rd = rs1 + rs2 - 2*and_result`. `Not` uses an inverse witness instead: `rd = 1 - rs1*inv` (`COL_INV_ZERO` shared).

### Poseidon witness columns (258-353)
| Range | Group | Description |
|--------|------|----------|
| 258-289 | `POSEIDON_STATE_BASE` | 4 rounds x 8 state elements (round input state) |
| 290-321 | `POSEIDON_X2_BASE` | S-box intermediates: x^2 |
| 322-353 | `POSEIDON_X4_BASE` | S-box intermediates: x^4 |

**Poseidon4 parameters:** alpha=7, width=8, 4 full rounds. The MDS circulant matrix is `[7,1,3,8,8,3,4,9]`. The round constants are taken from Plonky3's Poseidon1 Goldilocks. The AIR verifies only the round 0 S-box constraint; the VM computes all 4 rounds.

## Auxiliary trace schema

BudZKVM uses LogUp fractional sums to verify cross-table lookups (CTL). The auxiliary trace is **3 columns** wide:

| Column | Name | Definition |
| --- | --- | --- |
| 0 | `S_REG` | Register consistency LogUp accumulator |
| 1 | `S_MEM` | Memory + storage consistency LogUp accumulator |
| 2 | `S_PROG` | Program CTL LogUp accumulator |

> **Note:** storage operations (`SRead`, `SWrite`) need no separate LogUp table. They are folded into the memory table behind the `STORAGE_BASE = 2 << 60` address prefix, so storage consistency is verified through the existing memory LogUp (column 1).

These columns depend on the alpha, beta (tuple packing) and gamma (fractional denominator) values drawn from the Fiat-Shamir transcript. Each row applies the rule S_{i+1} = S_i + Sum w_j/(gamma - C_j). At the end of the program every column must be 0.

## Arithmetic semantics

BudVM arithmetic runs over the Goldilocks prime field (P = 2^64 - 2^32 + 1):

* `Add`, `Sub`, `Mul`: wrapping u64 arithmetic
* `Div`: Goldilocks field-native modular division, `rd = rs1 * rs2^{-1} mod P`. If the denominator is zero the result is 0.
* `Inv`: modular inverse, `rd = rs1^{-1} mod P`. If the input is zero the result is 0.
* `Poseidon4`: a 4-round Poseidon hash (alpha=7, width=8 Goldilocks). Input `(rs1, rs2)`, state `[a, b, 0, 0, 0, 0, 0, 0]`, output `state[0]`.

## Gas semantics

| Opcode group | Gas |
| --- | ---: |
| `Halt` | 0 |
| Simple ALU, branch, comparison | 1 |
| `Call`, `Ret`, `Push`, `Pop` | 2 |
| `Load`, `Store`, `SRead`, `SWrite` | 3 |
| `Syscall` | 5 |
| `Poseidon`, `VerifyMerkle` | 10 |

## Fixture tests

`bud-vm/tests/trace_fixtures.rs` pins the trace schema through sample programs:

* Arithmetic trace: `Load`, `Add`, `Sub`, `Mul`, `Halt`
* Control-flow trace: `Jnz`, `Jmp`, and a deterministic halt on running past the end of the program
* Memory/storage/event trace: `Store`, memory `Load`, `SWrite`, `SRead`, `Log`

If the trace schema changes, the VM tests and the prover tests must be updated together.
