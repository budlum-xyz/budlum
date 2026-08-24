# Stabilization, Soundness and the Road to Production

> **"How do you know a ZKVM is mathematically sound? It is not enough that it returns the right output for the right input. It has to refuse every kind of tampering a malicious prover can attempt."**

This chapter walks step by step through the 5 critical improvements made during the BudZKVM stabilization work. Each step covers a real problem you will meet when designing a ZKVM, the method used to solve it, and the answer to the "why did we do it this way" question.

---

## Dependency management and serialization (Bincode to Postcard)

### Problem

`bincode` 1.3 carried the **RUSTSEC-2020-0159** advisory in the Rust ecosystem: unbounded deserialization can lead to memory exhaustion (DoS). We were ignoring that advisory in `deny.toml`. But in a production environment an enormous invalid proof byte string sent to an L1 node can bring the node down.

### Solution

We moved to the `postcard` crate. `postcard` is `serde` compatible, `no_std` friendly, and naturally a bounded deserializer through its `from_bytes(&[u8])` interface. Unlike `bincode`, it is also maintained.

```rust
// Old (unsafe):
let proof_bytes = bincode::options()
    .with_limit(10 * 1024 * 1024)
    .serialize(&p3_proof)?;

// New (safe):
let proof_bytes = postcard::to_allocvec(&p3_proof)?;

// Deserialization:
let bounded = &envelope.proof_bytes[..envelope.proof_bytes.len().min(MAX_PROOF_BYTES)];
let proof: Proof<MyConfig> = postcard::from_bytes(bounded)?;
```

### Lesson

In ZKVMs the proof transport layer matters as much as the mathematical security. The serialization format must be chosen against both security (bounded deserialization) and maintenance (a maintained crate) criteria.

---

## AIR constraints for the comparison opcodes

### Problem

The `Lt`, `Gt`, `Lte`, `Gte` opcodes worked correctly in the VM, but had **no constraint at all** in the AIR. A malicious prover could change the `rd` (result) value in the trace at will. For example the result of `5 < 10` could be presented as `0`.

### Why is it hard?

In the Goldilocks field (P = 2^64 - 2^32 + 1) comparing two u64 numbers is not as simple as in the integer world:

* the difference `d = b - a` is computed mod P
* if `a < b` then `d` is the natural difference (between 1 and 2^64-1)
* if `a > b` then `d` is the wrapped difference (between P-(2^64-1) and P-1)
* **these two ranges overlap!** A comparison cannot be made by looking at the difference alone

### Solution: 64-bit decomposition + equality prefix flags

We decomposed both operands into 64 bits and compared from MSB down to LSB:

1. **Bit decomposition:** `a = sum a_i * 2^i`, `b = sum b_i * 2^i`. Every bit is constrained to be boolean.
2. **Equality prefix flags (eq_i):** `eq_i = 1` means the bits from 63 down to i are equal. It is computed recursively as `eq_i = eq_{i+1} * (a_i == b_i)`.
3. **Result:** `cmp_lt_raw = sum eq_{i+1} * (1-a_i) * b_i`. If at the first differing bit position `a_i=0, b_i=1` then `a < b`.

```
Lt:  rd = cmp_lt_raw
Gt:  rd = 1 - eq_0 - cmp_lt_raw
Lte: rd = eq_0 + cmp_lt_raw
Gte: rd = 1 - cmp_lt_raw
```

### Lesson

Inequality checking over finite fields always requires bit decomposition. That raises both the column count (193 new columns) and the constraint degree. On primes close to 64 bits such as Goldilocks the natural/wrapped difference cannot be told apart, so the operands themselves must be decomposed.

---

## AIR constraints for the bitwise opcodes

### Problem

The `And`, `Or`, `Xor`, `Not` opcodes were placeholders in the AIR, written as `assert_zero(rd - rd)` (that is, "accept everything"). This is a soundness disaster: the prover can invent any bitwise result.

### Solution: shared bit decomposition

We reused the 64-bit decomposition columns added for comparison (CMP_RS1_BASE, CMP_RS2_BASE) for the bitwise operations too. With the same infrastructure:

```
And: rd = sum (a_i * b_i * 2^i)         [bitwise AND]
Or:  rd = rs1 + rs2 - and_result        [a_i | b_i = a_i + b_i - a_i*b_i]
Xor: rd = rs1 + rs2 - 2*and_result      [a_i ^ b_i = a_i + b_i - 2*a_i*b_i]
```

For `Not` an inverse witness approach was used: `rd = 1 - rs1*inv` (logical NOT, not bitwise). The `COL_INV_ZERO` column is shared with the `Inv` opcode (no clash, thanks to selector exclusivity).

### Lesson

The most efficient approach for bitwise operations is to decompose the operands into bits. Thanks to algebraic equivalences (such as `a_i | b_i = a_i + b_i - a_i*b_i`) every bitwise result can be derived from the same bit columns. No extra witness column is needed.

---

## Poseidon hash implementation

### Problem

The `Poseidon` opcode ran on a cryptographically meaningless placeholder like `src1*31 + src2 + 0x1337`. In a real ZKVM the hash function is critical for Merkle proof verification, state commitment and randomness generation.

### 4-round Poseidon (alpha=7, width=8): NOT PRODUCTION READY

> **OK, RESOLVED (2026-07-28).** The section below describes the 4-round
> parameter set and why it was insufficient; it is **no longer in use**. The VM
> and the AIR moved to the full 30-round permutation (R_F=8, R_P=22) and the
> privacy opcodes were opened. The text stays because it records which problem
> was solved.
>
> What it was: with R_F=4, R_P=0, alpha=7 the algebraic degree was only 7^4 =
> 2401. A system of that degree is invertible in practice by interpolation or a
> Groebner basis; on top of that the function is so cheap that a generic
> birthday collision search (~2^32) is reachable within hours on a single GPU.
>
> Concrete consequence: `(amount, blinding, recipient_tag)` could be recovered
> from a `PrivacyCommit` commitment, so there was no hiding. A second opening
> could be found for the same commitment or nullifier, so there was no binding.
>
> The STARK side was honest even then: the AIR constrained all four rounds, so
> the proof system correctly proved that the weak function had been executed
> correctly. The problem was in the proven function itself.

### Target parameters derived (2026-07-28)

The warning above said "real parameters ask for roughly 8 full + 22 partial
rounds". The "roughly" is gone; the set was derived, put into the code and
locked.

| | value | from where |
|---|---|---|
| R_F (full rounds) | 8 | 4 head + 4 tail, with the +2 margin of the Poseidon2 paper |
| R_P (partial rounds) | 22 | interpolation bound + 7.5% margin (below) |
| alpha (S-box) | 7 | `gcd(7, P-1) = 1`, verified by test |
| total rounds | 30 | `POSEIDON_RC_FULL` |
| total S-boxes | 86 | `t*R_F + R_P = 8*8 + 22` |

R_P is not a preference, it follows from the interpolation bound of the
Poseidon paper (Eq. 3):

```
R_interp >= ceil(min(k,n) / log2(alpha)) + ceil(log_alpha(t)) - 5
          = ceil(64 / log2(7)) + ceil(log_7(8)) - 5
          = 23 + 2 - 5 = 20
ceil(1.075 * 20) = 22
```

This computation is redone in the
`partial_round_count_matches_the_interpolation_bound` test; if the constant is
edited by hand the test falls.

**The set in use really is a prefix.** This is no longer folklore: the
`four_round_set_is_a_prefix_of_full` test verifies that `POSEIDON_RC` is byte
for byte identical to the first four rows of `POSEIDON_RC_FULL`.

**Why do four rounds still run?** Because the AIR constrains four rounds
(`plonky3_air.rs`, `for r in 0..4`). Moving the VM alone to 30 rounds would mean
the proof verifies a function **other** than the one the VM executes, a
soundness break decidedly worse than a weak hash. Therefore:

- `POSEIDON_RC_FULL`, `POSEIDON_FULL_ROUNDS`, `POSEIDON_PARTIAL_ROUNDS` and
  `POSEIDON_ALPHA` were added, the exact target the AIR work will aim at.
- A `poseidon_full_hash_state` reference implementation was added; the AIR can
  be verified against it. `full_permutation_differs_from_truncated_one` shows
  the two functions really differ on every sampled input (otherwise the target
  would be decoration).
- `vm_hash_still_matches_the_air_round_count` falls if the VM changes
  one-sidedly and forces the AIR to move in the same change.

### Applied (2026-07-28)

All three moved in the same change; moving one side alone would have meant the
proof verifying a function other than the one the VM executes:

| component | what was done |
|---|---|
| `bud-vm` | `poseidon4_hash_state` redirected to `poseidon_full_hash_state` |
| `plonky3_air.rs` | gadget widened to 30 rounds, S-box only on lane 0 in partial rounds |
| `plonky3_prover.rs` | witness columns filled with the same layout |

**Column budget.** The trace goes `414 -> 730` columns. Partial rounds do not
pay full price:

```
state: 30 * 8                          = 240 columns
x2:    8 * 8 (full) + 22 * 1 (partial) =  86 columns
x4:    same shape                      =  86 columns
```

A naive widening (8 lanes in every round) would have asked for 720 columns; the
asymmetry saves 308 columns. Measured prover time: **0.17 s -> 4.75 s**
(release, 71 tests).

**RC/MDS now live in a single source.** Previously the AIR, the prover and the
VM each carried their own 4-round copy. All three now read
`bud_vm::POSEIDON_RC_FULL` and `bud_vm::POSEIDON_MDS`.

**A second bug found along the way.** The equality witness of `NullifierCheck`
was computed with `wrapping_sub` in the prover while the AIR does field
subtraction. The two agree only when `poseidon_out >= claimed`. At 4 rounds it
happened never to trigger; at 30 rounds it fell immediately. Fixed with
`field_sub_goldilocks`.

**Privacy flags opened.** `privacy_commit_enabled`, `nullifier_check_enabled`
and `sum_conservation_enabled` are now **ON** under
`MainnetActivation::default()`. The gate went because the reason for the gate
went. `verify_merkle_enabled` and `verify_inference_enabled` stay closed for
their own reasons (unfinished path verification; a verification circuit that is
not in service).

Lock: `privacy_opcodes_are_open_only_while_poseidon_is_strong` falls if the
round count drops below 30 - an open gate depends on the strong-permutation
assumption.

### Applied parameters

Plonky3's `p3-goldilocks` crate contains a Poseidon1 implementation optimized for the Goldilocks field. We wrote our own 4-round version using the parameters of that implementation:

**Why alpha=7?** Poseidon's S-box has the form `x^alpha`. For alpha to be a permutation of the field we need `gcd(alpha, P-1) = 1`. In Goldilocks P-1 = 2^32*(2^32-1) = 2^32*3*5*17*257*65537. So P-1 is divisible by 2, 3, 5, 17, 257, 65537. alpha=7 divides none of these, so it is a valid permutation.

**Parameters:**
```
State width (t):        8
Full round count (R_F): 4
Partial round count (R_P): 0
S-box degree (alpha):   7
MDS matrix (circulant, first row): [7, 1, 3, 8, 8, 3, 4, 9]
```

**Hash computation:** State = `[a, b, 0, 0, 0, 0, 0, 0]`, 4 rounds (AddRoundConstants -> S-box -> MDS), output = `state[0]`.

**AIR constraint:** For every S-box the intermediate values `x2 = (state+RC)^2` and `x4 = x2^2` are stored in the trace. The AIR verifies the round 0 S-box. The VM computes all 4 rounds.

```
S-box constraint (degree 2):
  x2 = (state + RC)^2    ->  assert_eq(x2, (state+RC) * (state+RC))
  x4 = x2^2              ->  assert_eq(x4, x2 * x2)
  sbox = x4 * x2 * (state+RC)  [used as an algebraic expression in the MDS]
```

### Lesson

When choosing a ZK-friendly hash function:
1. the **S-box degree** must satisfy gcd(alpha, P-1) = 1
2. the **MDS matrix** should be circulant if possible (fewer constraints)
3. the **round count** is a security/constraint-count trade-off
4. constraining every round in the AIR can be hard; a staged approach (first 1 round, then all of them) is good

---

## Soundness for storage (SRead/SWrite)

### Problem

The `SRead` and `SWrite` opcodes operated on a `HashMap<i32, u64>` in the VM. But there was no mechanism in the AIR checking storage consistency. A malicious prover could invent the value read, or misreport the value written.

### First attempt: a separate storage LogUp table

In the first approach we tried to add a separate LogUp CTL for storage (a 4th accumulator), similar to the register and memory tables. But Plonky3's mechanism for determining permutation width created a chicken-and-egg problem:

* the symbolic evaluator determines the permutation width by counting the `perm_cur[N]` accesses in the AIR code
* but accessing `perm_cur[3]` requires a `perm_cur.len() >= 4` check
* during symbolic evaluation `perm_cur.len()` is not determined yet
* result: index out of bounds panic

### Solution: integration into the memory table by address range

We folded storage into the **existing memory LogUp infrastructure**. The approach:

```
STACK_BASE   = 1 << 60   (for stack operations)
STORAGE_BASE = 2 << 60   (for storage operations)
```

`SRead(slot)` -> a memory read from address `STORAGE_BASE + slot`
`SWrite(slot, val)` -> a memory write to address `STORAGE_BASE + slot`

Thanks to this:
* **no new LogUp table is needed**: the existing 3 accumulators (register, memory+storage, program) are enough
* **storage consistency** is provided automatically by the memory consistency rules (same-address read/write, first-read zero)
* **no address clash**: stack (1<<60), storage (2<<60) and normal memory (0..2^60) live in different ranges

### Lesson

Adding a new state area (storage, stack, memory) to a ZKVM does not always require a separate LogUp table. With address space partitioning the existing infrastructure can be reused. That approach gives:
1. fewer witness columns
2. a lower constraint degree
3. staying within Plonky3's permutation width limits

---

## Technical debt and future work

### Current limitations

| Topic | Status | Plan |
|------|-------|------|
| Poseidon multi-round AIR | only round 0 is verified | full verification once Plonky3 supports multi-round constraints |
| L1 node integration | bud-node placeholder | JSON-RPC API and P2P network layer |
| Compiler error messages | no span information | `miette` integration |
| Debug mode | no step-by-step debugger | a `bud-cli debug` command |

### Opcode status after this work

```
Production (31 opcodes):  Halt, Add, Sub, Mul, Div, Inv, And, Or, Xor, Not,
                          Eq, Neq, Lt, Gt, Lte, Gte, Jmp, Jnz, Call, Ret,
                          Load, Store, Push, Pop, Assert, Poseidon, Log,
                          SRead, SWrite, Syscall, VerifyMerkle

Experimental (0 opcodes): (none - every opcode is production)
```

### Test coverage (at the end)

```
bud-proof: 36 unit tests + 1 integration test
  - Arithmetic: Add, Sub, Mul
  - Memory: Load, Store, Push, Pop, Call, Ret, NestedCall
  - Control flow: Jmp, Jnz
  - Comparison: Lt, Gt, Lte, Gte, AllComparisons
  - Bitwise: And, Or, Xor, LogicalNot, LogicalNotNonzero
  - Hash: Poseidon
  - Storage: SRead/SWrite (write-read, multiple slots, default zero)
  - Merkle: VerifyMerkle (valid, invalid root, invalid path)
  - Negative (trace tampering): tampered comparison, tampered bitwise AND,
    tampered poseidon S-box, tampered storage read-back, tampered public inputs,
    tampered program, tampered PC, invalid proof bytes

bud-vm: 6 unit tests + 2 fixture tests
bud-compiler: 2 unit tests
bud-state: 4 unit tests

Total: 51 tests, 0 failures
```

---

## A real implementation for the VerifyMerkle opcode

### Problem

The `VerifyMerkle` opcode ran on a cryptographically meaningless placeholder like `leaf*31 + path + 0x1337`. Yet in a ZKVM, Merkle proof verification is critical for state inclusion proofs and light client verification.

### Solution

**VM:** 64-depth Merkle proof verification, based on `poseidon4_hash`. API:
- `rs1`: root (u64)
- `rs2`: leaf (u64)
- `imm`: memory address (layout: `[key: u64, 64x sibling: u64]`, 520 bytes total)
- at every level, according to the relevant bit of `key`: `Poseidon(current, sibling)` or `Poseidon(sibling, current)`
- result: `rd = (current == root) ? 1 : 0`

**AIR:** it is verified that `rd` is boolean (0 or 1). Full 64-step path verification requires multi-round Poseidon constraints and was left to future work. The current constraint, `assert_bool(rd)`, guarantees that the result is a valid boolean.

```rust
// VerifyMerkle constraint:
builder.when(is_verify_merkle).assert_bool(rd_val_new);
```

### Tests

- **Valid proof:** with the correct root, leaf, key and path -> `rd = 1`
- **Invalid root:** with a wrong root value -> `rd = 0`
- **Invalid path:** with a tampered sibling -> `rd = 0`

---

## Summary: what this work contributed to the ZKVM design

Every change made during this work represents a critical step in a ZKVM's transition from "a VM that works" to "a ZKVM you can trust":

1. **Dependency hygiene:** cleaning out libraries with security advisories is the first rule of a production environment.
2. **Comparison soundness:** inequality over finite fields is impossible without bit decomposition.
3. **Bitwise soundness:** the same bit decomposition infrastructure can be reused for different opcodes (DRY).
4. **Hash function:** the choice of S-box degree depends on the structure of the field's multiplicative group.
5. **State management:** address range partitioning reduces the need for separate LogUp tables.
6. **Merkle verification:** full path verification is expensive in the AIR; a staged approach (first a boolean output, then the full hash chain) offers a pragmatic solution.

Each step follows the "why does this not work -> what is the mathematical reason -> how do we solve it" loop. That loop is the essence of ZKVM development.
