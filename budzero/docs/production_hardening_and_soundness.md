# Production hardening and soundness

A virtual machine running the right bytecode and giving green tests in a local test environment does not mean it is a cryptographically sound ZKVM. In classical software a "correct input -> correct output" test is enough; in the ZKVM world we face a far larger threat model: the **malicious prover**.

A malicious prover can, without ever running the virtual machine locally, prove an invalid state or a fake transaction to the verifier by falsifying numbers in the execution trace matrix or by exploiting gaps in the algebraic (AIR) constraints.

> [!IMPORTANT]
> **Soundness:** the guarantee that no dishonest prover can produce a proof that the verifier accepts for a false claim - for example minting tokens from nothing, stealing someone else's balance, or executing invalid bytecode.

This chapter examines in detail, with the mathematical formulas and code structures, the hardening and soundness steps applied while preparing BudZKVM for production and for a security audit.

---

## 1. Virtual machine and ISA security (determinism and semantics)

A ZKVM's mathematical constraints are built on the virtual machine's deterministic semantics. If the VM has silently swallowed errors or undefined behaviour, the AIR rules cannot catch those situations.

### Preventing silent `Vm::run` failures

In the first designs `Vm::run` silently swallowed errors that occurred during execution (out of gas, an invalid opcode, a stack overflow) or panicked. In production, when an error occurs while running a contract, the state must roll back deterministically and that failure must be reflected in the cryptographic proof receipt.

To achieve this the VM core was updated:

* `Vm::run` now returns `Result<ExecutionReceipt, VmError>`.
* The `ExecutionReceipt` structure clearly carries the success of the execution (`success`), the gas spent (`gas_used`), the final PC (`final_pc`), the events raised (`events`) and the state write digest (`state_writes_digest`).
* When an error occurs (for example `VmError::OutOfGas` or `VmError::AssertionFailed`), state writes are rolled back, but the gas spent and the failure status are written into the receipt, so determinism is preserved.

### `IsaProfile` (production vs experimental opcode policy)

New features are added to virtual machines during development - experimental cryptographic primitives, storage opcodes and so on. But those experimental instructions may not be mature yet, or their AIR constraints may not be fully written. A malicious prover could deceive the verifier by using an experimental instruction that has no AIR constraint.

To close this weakness BudZKVM introduces **`IsaProfile`**:

```rust
pub enum IsaProfile {
    Production,
    Experimental,
    Testing,
}
```

* `Instruction::decode` decodes according to the active profile. If the profile is `Production` and the bytecode contains an experimental instruction (for example `SWrite` or `SRead` while they are experimental), the VM errors during decoding.
* The compiler (`bud-compiler`) checks the target profile while generating code. If the production profile is active and the source contains an experimental expression or instruction, compilation is blocked statically.

### Goldilocks field-native modular division

On classical computers division is integer division (`src1 / src2 = quotient`, remainder discarded). In ZK-STARK systems working over finite fields, writing integer division as an AIR constraint is extremely expensive (it needs bit decomposition and range checks).

Because BudZKVM works natively over the Goldilocks field ($p = 2^{64} - 2^{32} + 1$), the division instruction (`Div`) was made a field-native modular division:

$$\text{dst} = \text{src1} \cdot \text{src2}^{-1} \pmod p$$

If $\text{src2} = 0$ the operation is mathematically undefined. During execution the VM stops with `VmError::DivisionByZero` when $\text{src2} = 0$. On the AIR side this case is enforced with a modular inverse constraint (see the arithmetic inverse witness below).

---

## 2. Closing the AIR soundness gaps (mathematical security)

Mathematical soundness requires that the relations between every row and column of the trace matrix be locked down by AIR (algebraic intermediate representation) equations leaving no open door.

### The R0 register soundness gap and its fix

In BudZKVM the `R0` register is hardwired to zero. But in the first trace generation code, stack operations (`Push`, `Call`, `Ret`) took `dst_idx = 0` in the background, and non-zero values could be written into the `dst_val` cell (and hence `COL_RD_VAL_NEW`) on those rows.

A malicious prover could exploit this to inject fake intermediate values into the `R0` cell on stack steps and, by corrupting the LogUp CTL (cross-table lookup) bus, make the register table and the CPU table inconsistent.

This soundness gap was closed in two phases:

1. **VM trace level:** while building `trace_matrix`, if the destination register of a step is `0` (`dst_idx == 0`), the `COL_RD_VAL_NEW` value in the trace cell is forced to `0`:
   ```rust
   let dst_val = if dst_idx == 0 { 0 } else { step.dst_val };
   ```
2. **AIR level:** in the register LogUp CTL and the AIR constraints, whenever the destination register is `0` the written value is algebraically constrained to be `0`:
   ```rust
   // The constraint that R0 is always zero
   builder.when(cur[COL_DST_IDX_IS_ZERO].clone()).assert_zero(rd_val_new.clone());
   ```

### Preprocessed trace and padding soundness (padding-row leakage)

In ZK-STARK systems the trace matrix size must be $2^N$. But a real program may finish in 5 steps, in which case the remaining 11 rows of the matrix are filled with **padding** rows.

If the padding rows are not properly isolated from the AIR and CTL lookup equations, a malicious prover could execute imaginary program instructions on the padding rows and deceive the verifier.

> [!CAUTION]
> **The padding soundness gap:** the prover being able to add fake program read/write (lookup) requests to the LogUp bus using the padding rows after the program has halted, without the verifier noticing.

The following architecture was integrated to close this gap:

1. **CPU activity separation (`COL_CPU_ACTIVE`):** an activity column was added to the trace matrix, taking `1` only on the program's real steps and `0` on padding steps.
2. **Preprocessed active column:** while the program bytecode's lookup verification (program CTL) runs, only rows with `COL_CPU_ACTIVE = 1` join the LogUp set:
   ```rust
   // Preprocessed activity column and memory lookup
   let term = alpha + memory_addr + memory_val;
   s_mem_next = s_mem + is_active * inv(term);
   ```
3. **Degree alignment:** so that the prover and the verifier compute padding decisions with the same generosity, the trace degree formula was synchronized:
   $$\text{degree} = (3 \cdot n_{\text{cpu}} + 1).\text{next\_power\_of\_two}().\text{max}(16)$$

### Arithmetic inverse witness

Writing an `if (x != 0)` condition directly in an AIR equation is impossible. Because polynomials are continuous functions, the **arithmetic inverse witness** method is used to prove non-zeroness.

The algebraic rule: to prove an element $x$ is not zero, the prover places an auxiliary $v$ (inverse) column in the trace. The AIR verifies that this $v$ really is the inverse of $x$, and hence $x \neq 0$, with these equations:

1. $$x \cdot (1 - x \cdot v) = 0$$
2. If $x \neq 0$ then $x \cdot v = 1$ must hold.

In BudZKVM this mechanism is fully implemented for:

* **`Div`:** the denominator is proved non-zero and the product with its inverse is verified.
* **`Eq` / `Neq`:** the difference of the two values $d = A - B$ is computed. Its inverse $v = d^{-1}$ is added to the trace as a witness, and equality is verified through that inverse.
* **`Jnz`:** whether the condition register is non-zero is checked with this inverse witness, locking branch correctness.

```rust
// The JNZ arithmetic inverse constraint (plonky3_air.rs)
// cond * (1 - cond * cond_inv) = 0
builder.when(cur[COL_IS_JNZ].clone()).assert_zero(
    cond.clone() * (one.clone() - cond.clone() * cond_inv.clone())
);
```

### Halt and padding transition constraints

Once the program reaches the `HALT` opcode the virtual machine's state must freeze. Otherwise a dishonest prover could change the PC or the registers after the program has ended.

The transition constraints written say:

* when `is_halt` is active, the `PC` on the next row must equal the current `PC`:
  $$\text{is\_halt} \cdot (\text{PC}_{\text{next}} - \text{PC}_{\text{current}}) = 0$$
* all state updates over registers and memory stop and stay locked through the padding steps.

### Gas consumption bounds and overflow checks

It is not enough for the VM to stop when the gas limit is exceeded; it must be verified at the AIR level that the prover did not produce a trace exceeding the gas limit.

* Gas consumption on each row increases cumulatively over the previous row:
  $$\text{gas\_used}_{\text{next}} - (\text{gas\_used}_{\text{current}} + \text{gas\_cost}_{\text{current}}) = 0$$
* On the last row (or at every step throughout the program) the total gas spent is enforced not to exceed the set limit, via an inequality range check or public input bounds:
  $$\text{gas\_used} \le \text{gas\_limit}$$

---

## 3. Serialization and public input security (the public inputs envelope)

Once ZK-STARK proofs are produced they travel between networks (L1/L2 nodes). Weaknesses in this transport and verification layer can bring the whole system down.

### `ExecutionPublicInputs` and the Keccak256 binding

The verifier needs the public input values to verify a proof. If those inputs travel loosely and unprotected between prover and verifier, the prover can change the public input parameters it sends in flight.

To block this weakness a **Keccak256 hash binding** was set up:

1. The `ExecutionPublicInputs` structure packs every parameter critical to the execution with canonical byte serialization:
   ```rust
   pub struct ExecutionPublicInputs {
       pub program_hash: [u8; 32],
       pub pre_state_root: [u8; 32],
       pub post_state_root: [u8; 32],
       pub gas_used: u64,
       pub gas_limit: u64,
       pub exit_code: u32,
       pub chain_id: u64,
   }
   ```
2. This byte string is hashed with Keccak256 and the single resulting `public_input_hash` is added to the STARK proof's transcript (the Fiat-Shamir seed).
3. Before verifying, the verifier recomputes this hash from the data it holds and checks it at the STARK opening. The smallest parameter change (falsifying `chain_id` or `gas_used`, say) therefore invalidates the proof.

### A safe `ProofEnvelope` and bounded bincode decoding

Version `bincode 1.3` in the Rust ecosystem has memory consumption weaknesses (a RustSec advisory) on unbounded decoding. A malicious attacker could crash a verifier RPC node by sending it an enormous invalid proof byte string (denial of service).

To block this the proof transport layer was wrapped in a **`ProofEnvelope`**:

* `ProofEnvelope` carries version information (`version: u32`), the backend used (`backend: String`) and the actual proof byte string.
* Deserialization on the verifier side strictly runs with bounded bincode settings:
  ```rust
  let reader = bincode::options()
      .with_limit(10 * 1024 * 1024) // a maximum of 10 MB
      .with_fixint_encoding();
  let envelope: ProofEnvelope = reader.deserialize(bytes)?;
  ```

This simple but critical measure protects production L1 verification nodes against DoS attacks.

---

## 4. Operational security, the state model and the CLI

Code security does not end with mathematics. The CLI surface and state management on the local filesystem must be operationally safe too.

### `StateBackend` commit and rollback

BudZKVM now carries contract state. If storage updates were written to disk immediately during execution and an `OutOfGas` error or a prover verification failure happened midway, the state would be left corrupted.

To prevent that a transactional **`StateBackend`** design was applied:

* `StateBackend` accumulates its updates in a temporary journal/backup.
* If the execution succeeds completely and the produced STARK proof verifies, `commit()` is called and the updates are applied to the persistent state.
* If an error occurs during execution, or the produced proof does not verify, `rollback()` is triggered and the state returns immediately to its previous consistent form.

#### Strict encapsulation and CLI integration

To maximize operational security, the `accounts` HashMap inside the `State` structure was made strictly **private**. The CLI (`bud-cli`) or any external module can no longer read or write that map directly.

Instead, the execution pipeline (`run_pipeline`) performs all state access through the safe methods the `StateBackend` trait offers (`get_account`, `set_account`, `begin_transaction`, `commit`, `rollback`). As a result:

1. a transaction journal (`begin_transaction`) is opened at the start of execution,
2. depending on the outcome, either an atomic disk write is triggered (`commit`) or all changes are undone (`rollback`),
3. state serialization is also managed from inside the `State` structure with atomic operating-system calls, through the `save_to` method.

### A 64-depth sparse Merkle tree (SMT) state root

In early versions the state root was a flat Keccak256 hash of all accounts. Flat hash models do not suit ZK systems, because they do not let L1/L2 nodes verify partial state (inclusion) proofs.

The BudZKVM state root infrastructure was rebuilt on a **64-depth sparse Merkle tree (SMT)** architecture:

* **Keys:** account IDs (u64) are converted to a 256-bit string that determines the leaf coordinates in the tree.
* **Leaves:** each active account's `nonce`, `balance`, `code_hash` and `storage_root` fields are concatenated and hashed (`hash_account`).
* **Sparse subtrees:** because most of the tree consists of empty accounts, a precomputed `EMPTY_HASHES` cache avoids the $O(2^{64})$ cost.
* **SMT proofs:** the `get_account_proof` method produces $O(\log n)$ (64 hashes) Merkle proofs showing that an account exists in the state (inclusion proof) or does not (non-membership proof). `verify_account_proof` verifies those proofs in seconds.

### State root domain separation

To prevent collisions between different state or network versions, a **domain separation** prefix is added when computing the Keccak256 state root:

```rust
let domain_prefix = b"BUDZKVM_STATE_ROOT_V1";
let mut hasher = Keccak::v256();
hasher.update(domain_prefix);
hasher.update(&bytes);
```

This prefix cryptographically isolates BudZKVM state roots from other systems using Keccak256 and prevents collision attacks.

### Atomic CLI state writes and alignment checks

* **Atomic rename:** the state file (`state.json`) is not overwritten in place. It is first written to a temporary file (`state.json.tmp`), synchronized to disk (`fsync`), then atomically moved over the real file at the operating-system level (`rename`). The state file is therefore never corrupted by a power cut or a sudden crash.
* **8-byte bytecode alignment:** when bytecode is read through the CLI, it is strictly checked whether the data is 8-byte aligned and whether any leftover bytes remain. Misaligned bytecode is refused outright rather than executed.

---

## 5. The security test matrix and negative verification

The only way to test whether a soundness constraint really works is to hand the system an **invalid trace** and see the verifier refuse it. That is **negative testing**.

For this purpose BudZKVM has the `bud-proof/tests/soundness_negatives.rs` integration test suite.

### The PC tampering negative test

This test takes the normal VM trace of a valid program (`ADD + HALT`), then changes the values in the `PC` column of that trace matrix, injecting a fake PC (`999`).

```rust
// soundness_negatives.rs
let mut values = vec![Goldilocks::new(0); 16 * TRACE_WIDTH];
for (i, step) in vm.trace.iter().enumerate() {
    let row_start = i * TRACE_WIDTH;
    values[row_start] = Goldilocks::new(i as u64); // clk
    values[row_start + 1] = Goldilocks::new(999); // TAMPERED PC!
    ...
}
```

When this tampered matrix goes through the Plonky3 prover and verifier:

* at the out-of-domain (OOD) evaluation step the verifier notices that the transition polynomial is not zero (`nxt_pc - cur_next_pc != 0`),
* the proof is immediately refused during cryptographic verification with an **`OodEvaluationMismatch`** error.

These negative tests passing (that is, the proof failing) is the strongest evidence that our AIR constraints and soundness protections work in production.

---

## Summary and post-audit checklist

These steps, applied while building BudZKVM from scratch and preparing it for production, turned it from merely a working VM into a ZKVM offering financial-grade security. When designing or reviewing a ZKVM this checklist should always be at hand:

1. **[x] R0 protection:** make sure every write to the `R0` register is algebraically forced to `0`.
2. **[x] Padding isolation:** verify with activity selectors that padding rows after HALT do not pollute the LogUp CTL/lookup terms.
3. **[x] Arithmetic inverses:** make sure the inverse witness ($v$) is locked by algebraic equations on branch and division rules that require non-zeroness.
4. **[x] Public input binding:** verify that the Keccak256 hash of the inputs is fed to the transcript as a seed.
5. **[x] Deserialization safety:** apply size bounds (bounded decoders) to prevent DoS attacks during byte decoding (postcard + MAX_PROOF_BYTES).
6. **[x] Negative tests:** prove at code level that the verifier refuses tampering, by writing negative tests against the critical AIR rules (8 negative tests).
7. **[x] Comparison soundness:** Lt/Gt/Lte/Gte constraints via 64-bit decomposition + equality prefix flags.
8. **[x] Bitwise soundness:** And/Or/Xor/Not constraints via bit decomposition + algebraic equivalence.
9. **[x] Hash soundness:** deterministic hashing with Poseidon4 (alpha=7, Goldilocks), round 0 S-box AIR verification.
10. **[x] Storage soundness:** storage consistency folded into the memory LogUp through STORAGE_BASE addressing.
11. **[x] Merkle soundness:** 64-depth Merkle verification on poseidon4_hash, with a boolean output constraint.

> **Completed (2026):** every checklist item is met. 31 opcodes are production-ready with 51 tests (8 of them negative). For detailed documentation see [Chapter 9: Stabilization](STABILIZATION.md).
