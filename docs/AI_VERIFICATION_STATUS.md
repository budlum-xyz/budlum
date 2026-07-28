# AI Inference Verification — What Is and Is Not Verified

Status document for the Lubot AI layer. It exists because the README and
several module headers described on-chain inference verification as a working
feature, while the code deliberately refuses to perform it.

## Summary

| Capability | State | Where |
|---|---|---|
| Model registry, operator compute-bond, Pollen-gated data access | working | `src/lubot/`, `src/ai/registry.rs` |
| Structural checks on an execution proof (commitments, model binding, program-hash match) | working | `verify_execution_proof_structural_with_model` |
| Guest program computes the MLP forward pass in-VM and matches the host evaluator bit-for-bit | working | `build_matmul_guest_program`, `run_matmul_guest` |
| Initial guest memory (weights, biases, input) bound by the AIR | **not bound** | `prove_bytecode_with_memory` |
| STARK verification of an inference proof on the transaction path | **not wired** | `src/execution/executor.rs` |
| `VerifyInference` opcode (0x1F) inside the zkVM | **always returns 0** | `budzero/bud-vm/src/lib.rs` |

## What the guest actually computes

`build_matmul_guest_program` emits a straight-line program that loads the
weights, biases and activations from memory, accumulates each neuron in the
Goldilocks field, applies a branchless ReLU on hidden layers and stores the
outputs. `run_matmul_guest` executes it and `prove_mlp_inference` refuses to
package a proof whose guest output differs from `eval_fixed_point_mlp`.

Three things were wrong before and are fixed:

- **The forward pass was never executed.** `prove_mlp_inference` proved a
  five-instruction commitment stub; the matmul builder existed but only its
  program hash was ever taken. Nothing ran it in the VM, so nothing noticed
  the two items below.
- **ReLU never fired.** The guest tested `Lt(acc, 0)`, and `Lt` is unsigned —
  no `u64` is below zero. Negative activations passed through unclamped. The
  sign test is now `Gt(acc, (P-1)/2)`, the signed embedding for a prime field,
  and the threshold is materialised arithmetically because it does not fit in
  a 32-bit immediate.
- **Host memory was never populated.** The layout was documented in a comment
  and written by nobody, so the guest read zeroes.
  `guest_without_host_memory_setup_computes_zero` pins that failure mode.

`prove_mlp_inference` still packages the *host* output commitment. The guest's
own outputs are folded into a Poseidon chain that is logged, but the AIR binds
the event accumulator as a sum of low 32-bit limbs, so that log is a
consistency signal, not a binding commitment.

## What the STARK does not cover

The initial memory image is witness data. The AIR binds the program, the gas
counters, the exit code, the trace length and the event accumulator — it does
not bind the memory a program starts from. A prover can therefore run the same
program words over a different weight matrix and produce an equally valid
proof.

For AI execution the binding has to come from outside the STARK:
`weights_digest(spec)` must be registered in `AiModelSpec` and re-derived by
the verifier, exactly the way `execution_program_hash` already is. Until that
is wired, `matmul_program_hash` binds the model *architecture* only — two
models with the same shape and different weights share a program hash, which
`matmul_program_hash_does_not_bind_weights` records deliberately.

## Why the transaction path fails closed

`src/execution/executor.rs` rejects any model that sets
`require_execution_proof` with `ai_exec_verifier_unavailable`. This is
intentional: full STARK verification needs the registered guest program words
plus the canonical `ExecutionPublicInputs`, and the transaction carries
neither. Accepting a proof envelope as evidence without checking it would be
worse than refusing, so the path refuses.

Structural checks still run for models that do not require an execution proof.
They bind commitments and the model id; they do **not** prove that the claimed
computation happened.

## Code that is present but unreachable

These functions compile and are unit-tested, but nothing in a production path
calls them. They are the scaffolding for the feature, not the feature:

- `src/ai/execution/verify.rs::verify_execution_proof_stark` — only reached
  through `verify_execution_proof_full`
- `src/ai/execution/verify.rs::verify_execution_proof_full` — no callers
- `src/lubot/verify.rs::verify_inference_stark` — only its own tests
- `src/lubot/verify.rs::generate_and_verify_proof` — only its own tests

`src/tests/ai_verification_status_locks.rs` pins this: if any of them gains a
production caller, or if the executor stops failing closed, those tests break
and this document has to be updated with the change.

## The zkVM opcode

`VerifyInference` (0x1F) is constrained in the AIR, but the constraint says the
result is always zero (fail-closed) — the AIR binds the selector to the opcode
and forces `rd_val_new = 0`. There is no STARK-verification circuit behind it
yet. The opcode is additionally gated by `MainnetActivation`, which is off by
default.

## What closing the gap requires

1. Store the guest program words (or a commitment plus a retrievable blob) in
   `AiModelSpec` at registration time.
2. Bind the initial memory image. Either extend the AIR with an initial-memory
   commitment column, or register `weights_digest` in `AiModelSpec` and have
   the verifier rebuild the memory image itself before checking the proof.
   Without this a valid proof says nothing about *which* weights ran.
3. Re-derive `ExecutionPublicInputs` on the transaction path from the request,
   the result and the registered program.
4. Call `verify_execution_proof_full` with that bundle and treat
   `stark_ok == Some(true)` as the acceptance condition.
5. Replace the fail-closed branch, and update this document together with the
   locking tests.

Until all five are done, the honest claim is "AI layer with data-sovereign
access control, a guest that really computes the forward pass, and structural
proof checks", not "verifiable inference".
