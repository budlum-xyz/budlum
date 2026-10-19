# STARK, AIR and Plonky3 (bud-proof)

Now for the place where the magic becomes real. We have a wide, detailed execution trace from the VM. Our aim is to take that matrix and prove it cryptographically with a ZK-STARK. For that we use **Plonky3**, a library that is becoming an industry standard. The `bud-proof` module is dedicated entirely to this job.

## Why does Plonky3 matter?

In the past (using Winterfell, for example) constraint degrees, domain sizes and blowup factors had to be tuned very carefully by hand. Plonky3 seats the mathematics of STARK proofs on a more modular, flexible architecture. It has particularly good native support for hardware-friendly small primes such as the **Goldilocks** field, which shortens proving time considerably.

## AIR (algebraic intermediate representation)

The heart of a ZKVM is its AIR. An AIR is the **set of mathematical rules** that check the correctness of the execution trace.

* In traditional programming we check correctness with `if (A + B == C)`.
* In the AIR world we must set that equation to zero: `(A + B) - C = 0`.

If every equation evaluates to zero on every row, the STARK proof succeeds. If a single constraint on a single row gives a non-zero result (the VM did a wrong computation, say), the system reports "constraint failed" and no proof can be produced.

### Transition constraints

If you look at `plonky3_air.rs` you will see the `eval` function in the `BudAir` implementation. That function checks relations between "the current row (`cur`)" and "the next row (`nxt`)" of the trace.

Take the PC (program counter) rule:
*"If the program has not ended, the next row's PC must equal the current row's next_pc."*

```rust
builder.when_transition().assert_zero(
    is_cpu.clone() * (nxt_pc.clone() - next_pc.clone())
);
```

In this equation, if the CPU is active and `nxt_pc` differs from `next_pc`, the result is not zero and the proof blows up.

### The power of selector columns

We said earlier that opcodes (0x01 = Add and so on) are added to the trace. But in polynomial mathematics you cannot write `if (opcode == 0x01)`. Instead, **selector columns** were added to the BudZKVM trace: `COL_IS_ADD`, `COL_IS_SUB`, `COL_IS_JMP` and so on.

If the operation is an ADD, the trace is built with `1` in the `COL_IS_ADD` column and `0` in the others. Our AIR rule then looks like this:

```rust
builder.when(cur[COL_IS_ADD].clone())
    .assert_eq(rd_val_new.clone(), rs1_val.clone() + rs2_val.clone());
```

Each mathematical equation therefore runs only when its own opcode is active. BudZKVM has **32 selector columns**, one per opcode.

### The trace matrix structure

The current BudZKVM main trace matrix is **354 columns** wide. The column groups:

| Range | Group | Description |
|--------|------|----------|
| 0-10 | Base | PC, next PC, opcode, register indices/values, immediate |
| 11-22 | CPU selectors | 12 selectors (ADD, SUB, JMP, JNZ, HALT and so on) |
| 23-28 | Register table | Register event ordering (for LogUp) |
| 29-48 | Extended selectors | 20 more selectors (DIV, AND, STORE, CALL, POSEIDON and so on) |
| 49-54 | Memory table | Memory event ordering (Load, Store, Push, Pop, SRead, SWrite) |
| 55-64 | Soundness | Gas, inverse witnesses, the CPU activity flag |
| 65-257 | Comparison/bitwise | 64-bit decomposition + equality prefix flags |
| 258-353 | Poseidon | 4-round state + S-box intermediates |

## Register table constraints

Here is how the "register consistency" check from the previous chapter is written in Plonky3:

*"If we stay on the same register on the next row (`r_same = 1`) AND this is a read (`nr_write = 0`), the value inside the register MUST NOT change."*

In the language of polynomials:

```rust
builder.when_transition().assert_zero(
    r_active.clone() * nr_active.clone() * r_same.clone() *
    (one.clone() - nr_write) * (nr_val - r_val)
);
```

These mathematical formulas are exactly the firewall that preserves a ZKVM's memory integrity and prevents hacking or data leakage.

## LogUp CTL: a three-table cross-table lookup

BudZKVM verifies consistency between the register, memory and program tables using **LogUp fractional sums**. Three Fiat-Shamir challenges (alpha, beta, gamma) are used:

1. **Register LogUp** (accumulator 0): the CPU's `rs1`, `rs2` reads and `rd` write are matched against the register event table. `R0` is hardwired to zero.

2. **Memory LogUp** (accumulator 1): it covers the CPU's `Load`, `Store`, `Push`, `Pop`, `Call`, `Ret` operations and **also `SRead` and `SWrite`.** Storage operations are placed into the memory address space behind the `STORAGE_BASE = 2 << 60` address prefix. Stack operations use `STACK_BASE = 1 << 60`. No separate storage LogUp table is therefore needed.

3. **Program CTL** (accumulator 2): the CPU's `(pc, instruction)` pairs are matched against the preprocessed program table. Only rows with `CPU_ACTIVE = 1` join the LogUp.

## The comparison and bitwise constraint strategy

### Comparison (Lt, Gt, Lte, Gte)

To compare two u64 numbers over the Goldilocks field (P = 2^64 - 2^32 + 1), a **64-bit decomposition + equality prefix flags** scheme is used. Both operands are split into 64 bits and compared from MSB to LSB:

```
Lt:  rd = cmp_lt_raw
Gt:  rd = 1 - eq_0 - cmp_lt_raw
Lte: rd = eq_0 + cmp_lt_raw
Gte: rd = 1 - cmp_lt_raw
```

This approach needs 193 extra columns (64+64 bits + 64 eq flags + 1 result).

### Bitwise (And, Or, Xor, Not)

The bit decomposition columns added for comparison are **reused** for the bitwise operations, through algebraic equivalences:

```
And: rd = Sum(a_i * b_i * 2^i)
Or:  rd = rs1 + rs2 - and_result
Xor: rd = rs1 + rs2 - 2*and_result
Not: rd = 1 - rs1*inv  (inverse witness, logical NOT)
```

## The Poseidon hash (alpha=7, 4 rounds)

The VM computes a 4-round Poseidon hash (alpha=7, width=8, Goldilocks field). The AIR verifies the round 0 S-box:

```rust
// X2 = (state + RC)^2
builder.assert_eq(x2, (state + RC) * (state + RC));
// X4 = x2^2
builder.assert_eq(x4, x2 * x2);
```

The S-box intermediates take 96 columns in the trace (4 rounds x 8 elements x 3 values). Full multi-round verification is left to future work because of Plonky3 constraint limits.

## The current prover flow in BudZKVM

1. The VM runs the program and produces one trace row per cycle.
2. The adapter converts those rows into a **354-column** `Goldilocks` main trace matrix (including the bit decomposition, the S-box intermediates and the storage events).
3. The main trace is committed and written to the transcript.
4. Fiat-Shamir randomness is drawn.
5. With that randomness a **3-column** auxiliary trace is produced (register, memory+storage, program CTL LogUp).
6. The AIR constraints are evaluated reading the main and auxiliary windows together.
7. The proof is serialized with `postcard` (bounded, DoS protected) and carried to the CLI, the tests or the L1 integration layer.

On the current Plonky3 path the auxiliary trace uses **LogUp fractional sums**. Three random challenges (alpha, beta, gamma) are drawn from the Fiat-Shamir transcript; gamma is used to build the fractional sums in the denominator.

The next chapter examines the compiler and the CLI layer.
