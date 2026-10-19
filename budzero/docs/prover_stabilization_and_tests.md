# Prover stabilization and tests

This chapter is not a generic "let us write a ZKVM from scratch" text. It describes making the real prover code in the BudZKVM repository compatible with Plonky3 0.5.2, testable, and improvable step by step. The aim is that a reader looking at the `bud-proof` module can see which file carries which mathematical responsibility, and knows where to start when a new failure appears.

Three things are held together here:

1. The Plonky3 0.5.2 type system and configuration boundaries.
2. The two-phase trace structure: main trace and auxiliary trace.
3. The prover adapter, serde, and the test strategy.

## Why is there a stabilization phase?

In a ZKVM it is not enough for the VM to run. Even when the VM produces the right result, the prover must additionally prove that:

* every row executes a valid opcode,
* the program counter advances correctly,
* register values stay consistent,
* read and write events are bound to the same logical memory,
* the trace does not wrongly continue after a halt,
* the proof can be turned into a byte string and read back.

In BudZKVM most of these responsibilities live inside the `bud-proof` crate. The stabilization phase makes that crate speak the current Plonky3 API and sets up a skeleton that will not break when real lookup/permutation rules are added later.

## File map

When reading the prover side these files must be considered together:

* `bud-proof/src/plonky3_air.rs`: the main AIR, where the opcode, PC, register and halt constraints over the VM trace are written.
* `bud-proof/src/plonky3_prover.rs`: the adapter binding the BudZKVM `ProofSystem` trait to the Plonky3-based prover.
* `bud-proof/src/bud_stark/config.rs`: the central place where the Plonky3 PCS, challenger, domain and field types are defined.
* `bud-proof/src/bud_stark/proof.rs`: the transportable shape of commitments, opened values and the proof object.
* `bud-proof/src/bud_stark/prover.rs`: the core prover, where the main trace, auxiliary trace, challenge generation, commitment and opening flow are set up.
* `bud-proof/src/bud_stark/verifier.rs`: the side that verifies the proof contents through the same transcript flow.
* `bud-proof/src/bud_stark/folder.rs`: the constraint folder that folds AIR constraints with the same logic on the prover and verifier sides.
* `bud-proof/src/bud_stark/sub_builder.rs`: the helper builder that lets the AIR operate over sub-windows.

This split matters. `plonky3_air.rs` says what the VM proves. The files under `bud_stark` manage how those rules are turned into a STARK proof.

## Type system and configuration

When working with Plonky3 0.5.2 the most critical concern is defining the generic types in one place and consistently. If the `Val<SC>`, `Challenge`, `Domain`, `Pcs` and `Challenger` bounds are set up differently in different files, the Rust compiler produces very long type inference errors.

That is why `bud_stark/config.rs` is made the central file in BudZKVM. Its goals are:

* the main field type is read through `SC::Val`,
* packed values are defined without entering a recursive type alias cycle,
* PCS proof and commitment types are carried by shared aliases,
* the challenger and domain types stay byte-identical between prover and verifier.

The output of this phase: the prover and the verifier never have to answer "which PCS am I using?" separately. Both speak through the same `StarkGenericConfig`.

## Proof and serde bounds

The `Proof<SC>` structure is not made of simple fields alone. It contains commitments, opened values and a PCS proof, each bound to the `SC` generic parameter. That makes it hard for the compiler to derive serde bounds automatically.

The solution in BudZKVM is to write the serde bounds explicitly. The proof is treated with this logic:

* if the commitment type is serializable, the proof is serializable,
* if the challenge type is serializable, the opened values are serializable,
* if the PCS proof type is serializable, the whole proof can be turned into a byte string.

This approach brings `postcard` support and simplifies the proof transport layer needed for CLI/L1 integration. If the proof format should later become a stable wire format, this file is the natural boundary.

## Main trace and auxiliary trace

The BudZKVM prover architecture is two-phase:

1. the main trace is committed,
2. a challenge is drawn over the transcript,
3. the auxiliary trace is produced using that challenge,
4. the main and auxiliary openings are verified together.

This structure is required for cross-table lookup and permutation rules. For instance, when a register read in the CPU table needs to be bound to the earlier write in the register event table, the main trace alone is not enough. The lookup accumulator values depend on the challenge and are carried inside the auxiliary trace.

In the current stabilization phase the auxiliary trace has moved to a **LogUp (fractional sums)** architecture. The `generate_aux_trace` function on the adapter side takes the Fiat-Shamir randomness values (alpha, beta, gamma) and produces **three main columns** holding the fractional sums:

* **Register accumulator (S_REG):** it adds the `rs1`, `rs2` reads and the `rd` write of each CPU row as fractional terms, and subtracts their counterparts in the register event table. `R0` is hardwired to zero; on rows where `dst_idx == 0` the trace forces `dst_val` to `0`.
* **Memory accumulator (S_MEM):** it enforces consistency between CPU memory accesses (`Load`, `Store`, `Push`, `Pop`, `Call`, `Ret`) and the memory table. It **also covers storage operations** (`SRead`, `SWrite`). Storage is placed into the memory address space behind the `STORAGE_BASE = 2 << 60` address prefix, so no separate LogUp table is needed.
* **Program accumulator (S_PROG):** it matches the CPU's `(pc, instruction)` pairs with the `(pc, instruction)` pairs in the preprocessed program table. Only rows with `CPU_ACTIVE = 1` join the LogUp set; padding rows are excluded.

This transition lowered the constraint degree, optimizing proving time, and completed the infrastructure needed for memory integrity. The auxiliary trace now carries real witness data bound to the transcript challenges, and the AIR fully verifies these transitions with `when_transition`, `when_first_row` and `when_last_row` constraints.

## What does the constraint folder do?

AIR constraints run in two different contexts:

* on the prover side the trace rows are packed field elements,
* on the verifier side the opening values are challenge field elements.

`folder.rs` binds these two worlds to the same AIR code. The `PermutationAirBuilder` implementation matters especially, because that is where the auxiliary trace window is exposed to the AIR. If `permutation()` returns an empty window, lookup constraints can be written yet never bind to the real auxiliary columns.

So `AuxWindow` must carry these two windows:

* `current_slice`: the auxiliary values on the current row,
* `next_slice`: the auxiliary values on the next row.

On the prover side these values are packed from packed base trace rows into challenge elements. On the verifier side the opening values are reassembled into a challenge element from their base coefficient parts.

## Sub builder and the window API

`sub_builder.rs` lets the AIR operate over a specific range of the trace. This mechanism is needed for the register table, the CPU table, and any sub-tables added later. In the new WindowAccess API, using `current_slice()` and `next_slice()` directly gives a clearer model.

What the sub builder must watch out for: whatever context the main builder supports, the sub builder must forward correctly. That is, not only `AirBuilder` but, as needed, these capabilities too:

* `AirBuilderWithContext`
* `PeriodicAirBuilder`
* `ExtensionBuilder`
* `PermutationAirBuilder`

When that forwarding is missing the error usually surfaces in the AIR file, but the root cause is in the builder trait chain.

## Adapter flow

`plonky3_prover.rs` is the proof API BudZKVM shows to the outside world. The job here is to separate Plonky3 details from the VM.

Proof generation flows in this order:

1. the VM runs the program and produces a `Step` trace,
2. the adapter converts the trace rows into `RowMajorMatrix<Goldilocks>` form,
3. `BudAir` is set up with the program and the initial register state,
4. a `StarkConfig` is built,
5. `prove` is called with the main trace, the auxiliary generator and the public input,
6. the returned proof is turned into a byte string with `postcard` (bounded deserialization, DoS protected).

On the verification side the flow reverses:

1. the proof byte string is deserialized,
2. the same AIR and config are rebuilt,
3. `verify` runs over the proof and the public input,
4. it returns `false` on error and `true` on success.

The purpose of this adapter is to keep the CLI, the L1 integration and the tests from having to know Plonky3's internal types.

Auxiliary trace generation is also kept at the adapter boundary. `plonky3_prover.rs` first builds the main trace matrix, then hands the prover a closure that computes the register accumulators from that same matrix. The `bud_stark` core therefore only knows the two-phase protocol; the BudVM-specific register packet details stay in the adapter/AIR layer.

## Test strategy

Stabilization tests should be thought of in two classes.

The first class tests VM behaviour together with the prover:

* a simple `ADD + HALT` program must be proved and verified,
* arithmetic opcodes such as `ADD`, `SUB`, `MUL` must work in the same trace,
* the immediate-load flow must be provable,
* the post-halt trace logic must not break.

The second class tests the proof transport layer:

* a produced proof byte string must deserialize and verify again,
* a random or corrupted byte string must not pass verification,
* when the serde bounds change, the tests must catch the break in the proof format.

These tests do not prove mathematical security on their own, but they catch breaks in the prover integration early. When updating Plonky3 in particular, these tests must stay green first.

## What is stable today

State after stabilization:

* `cargo check --workspace --all-targets` clean.
* `cargo clippy --workspace --all-targets -- -D warnings` clean.
* `cargo test --workspace` -> 0 failures (the count at the time of writing is not kept here; CI measures the current one).
* The `bud-proof` tests produce and verify proofs over the Goldilocks field with 29 unit tests + 1 integration test.
* The proof byte string is transportable through `postcard` (bounded deserialization, DoS protected).
* The folder skeleton for the main trace and the auxiliary trace binds to the same AIR.
* The auxiliary trace produces 3 columns: register, memory+storage and program LogUp accumulators.
* The memory STARK infrastructure is active; `Load`, `Store`, `SRead`, `SWrite`, `Push`, `Pop`, `Call`, `Ret` are fully verified through CTL.
* The comparison opcodes (Lt, Gt, Lte, Gte) are sound via 64-bit decomposition + equality prefix flags.
* The bitwise opcodes (And, Or, Xor, Not) are sound via bit decomposition + algebraic equivalence.
* The Poseidon hash (4 rounds, alpha=7, Goldilocks) is deterministic and its round 0 S-box is AIR-verified.
* Storage consistency is verified through the memory LogUp with STORAGE_BASE addressing.
* R0 protection, padding isolation, inverse witnesses, public input hash binding and bounded deserialization are done.
* The CI workflow (fmt, check, clippy, test, docs), the opcode contribution guide, the proof-format checklist and the trace schema document exist.

Work to do from this point:

* the full AIR constraint for the `VerifyMerkle` opcode and moving it into production,
* multi-round Poseidon AIR verification,
* recursive proof aggregation,
* WASM/EVM verifier targets,
* struct, mapping and standard library support in the BudL language,
* the `bud-node` network layer and JSON-RPC API.

## Next hardening steps

The next steps after this:

* move the VerifyMerkle opcode into production,
* integrate the tracing/logging infrastructure across the whole pipeline,
* a comprehensive negative test suite and CI expansion,
* AIR verification for all Poseidon rounds,
* clarify the public input context: the program hash, the initial state and the final state must be bound to the proof,
* version the proof format for long-term compatibility.
