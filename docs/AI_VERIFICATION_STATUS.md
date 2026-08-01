# AI Inference Verification - What Is and Is Not Verified

Status document for the Lubot AI layer. It exists because the README and
several module headers described on-chain inference verification as a working
feature, while the code deliberately refuses to perform it.

## Summary

| Capability | State | Where |
|---|---|---|
| Model registry, operator compute-bond, Pollen-gated data access | working | `src/lubot/`, `src/ai/registry.rs` |
| Structural checks on an execution proof (commitments, model binding, program-hash match) | working | `verify_execution_proof_structural_with_model` |
| Guest program computes the MLP forward pass in-VM and matches the host evaluator bit-for-bit | working | `build_matmul_guest_program`, `run_matmul_guest` |
| Initial guest memory (weights, biases, input) bound by the AIR | working | `COL_MEM_INIT_ACC`, `initial_state_root` |
| Weights bound outside the proof, by registry comparison | working | `AiModelSpec::execution_weights_digest` |
| STARK verification of an inference proof on the transaction path | working | `src/execution/executor.rs` |
| `VerifyInference` opcode (0x1F) inside the zkVM | **always returns 0** | `budzero/bud-vm/src/lib.rs` |

## STARK verification on the transaction path

The executor verifies the STARK for any model with
`require_execution_proof`. It used to refuse them outright, with the comment
"the transaction path currently has no program/public-input bundle to pass to
the verifier". Three things were missing, and each was a different kind of
gap.

**The program hash came from two schemes.** `AiExecutionProof::program_hash`
carried `program_hash_from_words` - SHA3-256 over a domain tag, the guest
version and the words - while `ExecutionPublicInputs::program_hash` carried an
unlabelled Keccak-256 over the same words. `verify_execution_proof_stark`
compares the two, so it could never succeed. Measured, with everything else
already lining up:

```
program_hash esit mi -> true      (verifier rebuilt the program)
pi hash esit mi      -> true      (public inputs matched byte for byte)
pi.initial_state_root == turetilen -> true
SONUC: Err("execution proof program_hash != public_inputs.program_hash")
```

`stark_program_hash_from_words` is now the one the proof and the registration
both use, because the AIR fixes that end.

**The verifier had no program.** A fixed-point MLP guest depends on the layer
shape alone - weights are read from memory, not baked into immediates - so
`AiModelSpec::execution_dims` is enough to rebuild the exact instruction words
a proof was produced against. `guest_program_for_model` does that.
`guest_program_for_model_ignores_weight_values` pins that weights never reach
the program, which is why registering the architecture is enough and the
owner's weights stay off-chain.

**The verifier had no public inputs.** `AiInferenceRequest` carries an input
*commitment*, not the raw input, so a node cannot replay the guest to derive
`initial_state_root` or the gas counters.
`AiExecutionProof::public_inputs` carries them. That is a claim, not an
axiom: the envelope commits to `public_inputs_hash`, so a prover shipping
inputs it did not prove against gets a mismatch, and the AIR binds every
field in the bundle to the trace.
`tampering_with_the_carried_public_inputs_is_refused` pins it.

The executor checks, in order: the proof carries public inputs; the model
registered a program hash; the claimed `program_hash` equals the registered
one; `exit_code` is zero; and then the STARK itself against the rebuilt
program. Each failure has its own error
(`ai_exec_no_public_inputs`, `ai_exec_no_program_hash`,
`ai_exec_program_hash`, `ai_exec_exit_code`, `ai_exec_stark`), so a rejection
says which part disagreed.

`a_real_inference_proof_verifies_against_the_registered_model` runs the whole
thing: a 2 -> 2 -> 1 network with a negative weight so ReLU fires, proved and
then verified against a model that holds only the architecture and the
digests.

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
- **ReLU never fired.** The guest tested `Lt(acc, 0)`, and `Lt` is unsigned -
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

## The initial memory image is committed

The AIR used to require that the first access to any address read zero. That
was correct while nothing committed to the starting memory: a prover free to
claim arbitrary initial memory is a prover free to claim arbitrary weights. It
also made the matmul guest unprovable, because it reads weights the host wrote
before the first instruction.

Both are now handled. A memory row can be flagged `COL_MEM_IS_INIT`, which
exempts it from the zero rule, and every flagged row is folded into
`COL_MEM_INIT_ACC`. The AIR checks that accumulator against
`public_inputs.initial_state_root` on the halt row, so the exemption costs the
prover a commitment it cannot fake by flagging rows it did not seed -
flagging changes the fold, and the fold has to equal a public input the
verifier already holds.

`initial_state_root` was previously a hard-coded zero that nothing constrained.
It now carries that commitment.

**What it covers.** Exactly the pre-written words the program reads. Bytes the
host seeded and the guest never touched are outside it, deliberately: they
cannot influence execution, so binding them would make the commitment depend on
padding. Every value the program consumed is bound - change a weight the guest
reads and the commitment moves.

**The fold on its own is collidable, and the verifier does not rely on it.**
`acc' = acc * BETA + addr * GAMMA + val` with fixed constants is a polynomial
evaluated at a known point. Given an honest accumulator a prover can pick the
first reads freely and solve the last one to land on the same value - one
modular multiplication, no search. `the_constant_fold_can_be_collided` performs
that collision in code so the property is a measured fact rather than a worry.

Making the fold collision-resistant would mean hashing inside the AIR, and the
trace cannot afford one: the Poseidon gadget is per-row and already shares
rows with the CPU, so a second instance for memory rows costs roughly 400 more
columns. Moving the base to a Fiat-Shamir challenge does not work either - the
accumulator lives in the main trace, which is committed before any challenge is
sampled, and moving it to the aux trace leaves it with nothing to be compared
against, because a challenge-dependent value cannot be a public input.

So the defence is to stop trusting the prover's value.
`expected_initial_state_root` rebuilds the memory image from the registered
model, replays the guest, and derives the commitment independently. A proof
whose `initial_state_root` disagrees is rejected before the STARK is checked.
The AIR still proves the trace folds to what the public input claims; the
verifier decides what that claim has to be.

## What the STARK does not cover

The initial memory image is witness data. The AIR binds the program, the gas
counters, the exit code, the trace length and the event accumulator - it does
not bind the memory a program starts from. A prover can therefore run the same
program words over a different weight matrix and produce an equally valid
proof.

For AI execution the binding therefore comes from outside the STARK, and it is
now wired: `AiModelSpec::execution_weights_digest` holds
`weights_digest(spec)`, `AiExecutionProof::weights_digest` carries what the
prover claims to have run, and
`verify_execution_proof_structural_with_model` refuses a proof whose digest is
absent or different. Both fields travel over the wire
(`ProtoAiModelRegister.execution_weights_digest` field 12,
`ProtoAiAttachExecutionProof.weights_digest` field 9) and
`weights_digest_survives_proto_round_trip` pins that, because a digest lost in
encoding would silently turn the check into a no-op on every relayed
transaction.

`matmul_program_hash` still binds the model *architecture* only - two models
with the same shape share a program hash, which
`program_hash_alone_does_not_separate_two_models_of_the_same_shape` records
deliberately. That is exactly why the digest exists.

**What this is and is not.** The digest is a *claim* checked against a
*registration*: it tells the verifier which weights the prover says it used,
and the registry says which ones it was allowed to use. A prover that lies
about the digest is caught; a prover that reports the registered digest while
running different weights in memory is not, because the AIR still does not
constrain the initial image. Closing that last step means an initial-memory
commitment column in the AIR, or having the verifier rebuild the image and
re-derive the trace itself. Until then the digest narrows the gap from "any
weights" to "the registered weights, on the prover's word".

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

- `src/ai/execution/verify.rs::verify_execution_proof_stark` - only reached
  through `verify_execution_proof_full`
- `src/ai/execution/verify.rs::verify_execution_proof_full` - no callers
- `src/lubot/verify.rs::verify_inference_stark` - only its own tests
- `src/lubot/verify.rs::generate_and_verify_proof` - only its own tests

`src/tests/ai_verification_status_locks.rs` pins this: if any of them gains a
production caller, or if the executor stops failing closed, those tests break
and this document has to be updated with the change.

## The zkVM opcode

`VerifyInference` (0x1F) is constrained in the AIR, but the constraint says the
result is always zero (fail-closed) - the AIR binds the selector to the opcode
and forces `rd_val_new = 0`. There is no STARK-verification circuit behind it
yet. The opcode is additionally gated by `MainnetActivation`, which is off by
default.

## What closing the gap requires

1. Store the guest program words (or a commitment plus a retrievable blob) in
   `AiModelSpec` at registration time.
2. Derive the fold constants from the Fiat-Shamir transcript instead of fixing
   them. The initial-memory commitment is in the AIR now
   (`COL_MEM_INIT_ACC` against `initial_state_root`), but with constant
   `BETA`/`GAMMA` it is solvable rather than collision-resistant.
3. Re-derive `ExecutionPublicInputs` on the transaction path from the request,
   the result and the registered program.
4. Call `verify_execution_proof_full` with that bundle and treat
   `stark_ok == Some(true)` as the acceptance condition.
5. Replace the fail-closed branch, and update this document together with the
   locking tests.

Until all five are done, the honest claim is "AI layer with data-sovereign
access control, a guest that really computes the forward pass, and structural
proof checks", not "verifiable inference".
