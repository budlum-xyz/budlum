# Aggregation directive: phase inventory

Measured against `budlum-stack` (head `462d7d5d`) on 2026-11-17 by reading the
tree. Every row names the file where the phase's code lives, or says plainly
that the code is not there. Nothing in this file is copied from a plan.

## Phase 0: baseline measurement

Done, and better than the phase asks for.

- `benches/agg_baseline.rs` measures the witness cost per scheme (name,
  public key bytes, signature bytes, one verification) and, for blocks of 100
  and of 1000 transfers in the V5 and V7 form, the protobuf size of the block
  with and without witnesses, the witness share and the time to verify every
  transaction. Sizes come from `ProtoBlock::encoded_len`, not from the scheme
  table, and the harness exits 2 rather than print a number it cannot trust.
- `benches/agg_tick_steps.rs` is the phase 2 measurement: where one signature
  verification spends its steps, and per tick size the steps, the VM time and
  how many prover rows that many steps need. It self-checks `tick_pi`.
- Both are registered in `Cargo.toml` with `required-features = ["wallet-ml-dsa"]`.
- Status: done.

## Phase 1: claim layer

Done, and it is the part the whole module rests on.

- `src/aggregation/claim.rs` holds `Claim::{Sig, Prog, Poly}` and the digest
  rules, with a tag test per tag in `src/aggregation/tests/claims.rs`.
- `src/aggregation/schemes.rs` is the scheme registry: name, native verifier
  and `max_object_bytes` per `SchemeId`.
- `src/aggregation/backend.rs` holds the `AggBackend` trait exactly as the
  directive writes it.
- `src/aggregation/native.rs` is `NativeBackend`. Its proof is the list of
  encoded objects, its `verify` re-verifies each object. It is compiled for
  tests and for `feature = "agg-native-backend"` only; the gate
  `agg-native-backend-is-devnet-only` keeps it out of a production build.
- `src/aggregation/pool.rs` is the object pool with the 6.1 admission rules,
  `src/aggregation/aggregator.rs` is the tick loop and the merge.
- `src/network` carries `agg/object` and `agg/frame`.
- `src/aggregation/envelope.rs` and `src/aggregation/object.rs` define the
  object form; `src/core/transaction.rs` carries `TxAuth` and `claim_refs`;
  `src/core/block.rs` carries `claim_frame` and `frame_hash`.
- `src/aggregation/block.rs` is the block rule set; `src/aggregation/fees.rs`
  is the fee rule; pruning is in `src/aggregation/pool.rs` and
  `src/aggregation/aggregator.rs`.
- `src/aggregation/params.rs` holds `AggMode` and `AggParams`.
- Status: done.

## Phase 2: signature claims, the tick proof

The programs exist as BudZKVM bytecode and are exercised by a real VM.

- `src/aggregation/programs/verify_sig.rs` is the reference signature program.
- `src/aggregation/programs/agg_tick.rs` is `AggTick`: it verifies each
  object, checks that the signer is the address of the key, computes the claim
  digest, the claim Merkle root and `tick_pi`, and writes `tick_pi` as eight
  storage writes.
- `src/aggregation/tests/programs.rs` runs those programs on `bud_vm::Vm` and
  covers the differential and the negative cases (a forged signature stops the
  run with `VmError::AssertionFailed`).
- What is missing: a **prover** that turns an `AggTick` run into a Plonky3
  proof inside the aggregator. The programs are proved nowhere in
  `src/aggregation`; only `bud-vm` executes them.
- Status: programs done, circuit wiring not done.

## Phase 3: recursion, master proof, `StarkBackend`, `Shadow`

- `src/aggregation/frame.rs` already carries the merge shape, `merge_pi`,
  `AggProgram` and the frame hash rule, and `src/aggregation/programs`
  describes the tick program a merge would recurse over.
- `StarkBackend` is **missing**: `grep -r StarkBackend src/aggregation` finds
  nothing. `prove_merge` today is `NativeBackend`'s, which concatenates rather
  than recurses.
- `AggMode::Shadow` exists in `src/aggregation/params.rs` and is covered in
  `src/aggregation/tests/flow.rs`, but there is no 10 000-block shadow run
  against a circuit, because there is no circuit to compare with.
- Status: not done.

## Phase 4: program claims, hidden multisig

- `Claim::Prog` and the `auth_program_hash` slot exist in the claim and
  account shapes.
- The hidden-multisig example program is **missing**.
- Status: types only.

## Phase 5: PCS claims, `VerifyStark`, `AirRegistry`

- `Claim::Poly` exists with canonical field elements.
- `VerifyStark`, `verify_pcs_openings` / `verify_algebra` split `AirRegistry`
  are **missing**.
- Status: `Claim::Poly` only.

## Why phases 2 and 3 cannot be finished here

Measured, not assumed:

- `src/aggregation/tests/programs.rs` runs the reference programs on
  `bud_vm::Vm` and throws the trace away as it goes
  (`if vm.trace.len() >= 1 << 12 { vm.trace.clear(); }`), with the comment
  that a run of millions of steps "does not fit in memory with it". A tick
  over one ML-DSA-87 object is such a run.
- `ProverAdapter::prove` takes the whole `&[Step]` trace, so a tick proof first
  needs the hot spots moved to chips (phase 2, item 6), the way
  `src/domain/storage_deal.rs` does for `VerifyMerkle`: there the program is
  small enough that `DefaultAdapter::prove(&vm.trace, ...)` is affordable.
- This host is two cores and about 2 GiB. Writing a `StarkBackend` whose
  `prove_tick` no machine here can run would produce code no test could
  exercise, which is worse than the honest gap.

So the order the next phase has to take is: chip the tick program (hash,
Merkle path, signature verify) until one tick's trace fits, then write
`StarkBackend` against `DefaultAdapter`, then turn `Shadow` on for the 10 000
block run. Writing the backend first would put the cart before the horse.

## What the tree already gives the next phase

`budzero/bud-vm` is a real VM and `budzero/bud-proof` is a real Plonky3
prover and verifier for it: `plonky3_prover::prove_chip`, `verify_chip`,
`Plonky3Adapter::verify_canonical_program` (which also refuses a program
outside `canonical_set`), and `bud_stark::{prover,verifier}`. The canonical set
holds a program that uses `VerifyMerkle`, so a verifier that has not activated
that opcode refuses it rather than accepting it by way of the set.

That is the material `StarkBackend` should be built on. A hand-written backend
that "looks like" a STARK would be worse than none: it would carry the frame
rules and none of the soundness.

## Constraint that stays in force

`VerifyMerkle` (64-depth) stays disabled in production. While the aggregation
circuit depends on it, mainnet keeps `AggMode::Off` and testnet may run `On`.
