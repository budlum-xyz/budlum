# AI Inference Verification — What Is and Is Not Verified

Status document for the Lubot AI layer. It exists because the README and
several module headers described on-chain inference verification as a working
feature, while the code deliberately refuses to perform it.

## Summary

| Capability | State | Where |
|---|---|---|
| Model registry, operator compute-bond, Pollen-gated data access | working | `src/lubot/`, `src/ai/registry.rs` |
| Structural checks on an execution proof (commitments, model binding, program-hash match) | working | `verify_execution_proof_structural_with_model` |
| STARK verification of an inference proof on the transaction path | **not wired** | `src/execution/executor.rs` |
| `VerifyInference` opcode (0x1F) inside the zkVM | **always returns 0** | `budzero/bud-vm/src/lib.rs` |

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
2. Re-derive `ExecutionPublicInputs` on the transaction path from the request,
   the result and the registered program.
3. Call `verify_execution_proof_full` with that bundle and treat
   `stark_ok == Some(true)` as the acceptance condition.
4. Replace the fail-closed branch, and update this document together with the
   locking tests.

Until all four are done, the honest claim is "AI layer with data-sovereign
access control and structural proof checks", not "verifiable inference".
