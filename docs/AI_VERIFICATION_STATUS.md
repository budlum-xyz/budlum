# AI Inference Verification: What Is and Is Not Verified

Status document for the AI inference layer. It exists because the README and
several module headers described on-chain inference verification as a working
feature, while the code deliberately refuses to perform it.

## Summary

| Capability | State | Where |
|---|---|---|
| Model registry, operator compute-bond, Pollen-gated data access | working | `src/ai_inference/`, `src/ai/registry.rs` |
| Structural checks on an execution proof (commitments, model binding, program-hash match) | working | `verify_execution_proof_structural_with_model` |
| Guest program computes the MLP forward pass in-VM and matches the host evaluator bit-for-bit | working | `build_matmul_guest_program`, `run_matmul_guest` |
| Initial guest memory (weights, biases, input) bound by the AIR | working | `COL_MEM_INIT_ACC`, `initial_state_root` |
| Weights bound outside the proof, by registry comparison | working | `AiModelSpec::execution_weights_digest` |
| STARK verification of an inference proof on the transaction path | working | `src/execution/executor.rs` |
| Perception declaration (what is read, in which modality, how much) enforced fail-closed at admission | working | `ai_inference::admit_inference_request`, `AiInferenceRequest::perception` (request-id V3) |
| Model modality declaration checked against the read it is asked to serve | working | `AiModelSpec::modalities`, `ModalitySet` |
| SocialFi bridge: finalized AI inference layer output minted as requester-owned NFT | working (best-effort) | `src/execution/executor.rs` → `ai_inference::social::ai_output_to_nft` |
| `VerifyInference` opcode (0x1F) inside the zkVM | **fail-closed Poseidon binding**: `rd = 1` iff `output_c == poseidon4_hash(model_c, input_c)` for a proof window that fits memory, else 0; mainnet decoding is gated off | `budzero/bud-vm/src/lib.rs` |

## Perception declaration (V3)

An inference request now carries what it intends to read: the Pollen asset,
the B.U.D. content id, the modality (text/image/audio/video) and the declared
size in that modality's unit (`src/ai_inference/perception.rs`). The declaration is
inside the request id (`BDLM_AI_REQUEST_ID_V3`), so an operator cannot answer
a different read than the one paid for. The executor admits a request only if
all of the following hold (`admit_inference_request`):

- the request carries a declaration (requests built before V3 are refused
  fail-closed, including the contract-call path - deliberate behavior change);
- the model declared the modality at registration (`AiModelSpec::modalities`; a
  missing registration reads as `ModalitySet::none`, which refuses everything);
- the declaration respects the per-modality ceilings;
- when the `input_ref` is a Pollen data reference, it names the same asset as
  the declaration (permission for A does not authorize reading B).

## SocialFi bridge

When an inference outcome finalizes, the executor mints the output bytes as a
`ai-inference` NFT owned by the requester (best-effort: a mint refusal - e.g. a
duplicate content id - is logged, never a block rejection, because the outcome
has already settled and the bridge is a product surface, not a consensus
condition).

The reverse direction runs through Pollen rather than a new read path: the
same output is registered as a `DataAsset` (manifest = the NFT's content id,
metadata commitment = the finalized output commitment). The owner can then
grant and read their own output through the existing
`AiDataInputRef` / `validate_ai_read_ref` path - closed-circuit without a new
transaction type.


## STARK verification on the transaction path

The executor verifies the STARK for any model with
`require_execution_proof`. It used to refuse them outright, with the comment
"the transaction path currently has no program/public-input bundle to pass to
the verifier". Three things were missing, and each was a different kind of
gap.

**The program hash came from two schemes.** `AiExecutionProof::program_hash`
carried `program_hash_from_words`: SHA3-256 over a domain tag, the guest
version and the words, while `ExecutionPublicInputs::program_hash` carried an
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
shape alone, weights are read from memory, not baked into immediates, so
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
- **ReLU never fired.** The guest tested `Lt(acc, 0)`, and `Lt` is unsigned,
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
prover a commitment it cannot fake by flagging rows it did not seed,
flagging changes the fold, and the fold has to equal a public input the
verifier already holds.

`initial_state_root` was previously a hard-coded zero that nothing constrained.
It now carries that commitment.

**What it covers.** Exactly the pre-written words the program reads. Bytes the
host seeded and the guest never touched are outside it, deliberately: they
cannot influence execution, so binding them would make the commitment depend on
padding. Every value the program consumed is bound, change a weight the guest
reads and the commitment moves.

**The fold on its own is collidable, and the verifier does not rely on it.**
`acc' = acc * BETA + addr * GAMMA + val` with fixed constants is a polynomial
evaluated at a known point. Given an honest accumulator a prover can pick the
first reads freely and solve the last one to land on the same value, one
modular multiplication, no search. `the_constant_fold_can_be_collided` performs
that collision in code so the property is a measured fact rather than a worry.

Making the fold collision-resistant would mean hashing inside the AIR, and the
trace cannot afford one: the Poseidon gadget is per-row and already shares
rows with the CPU, so a second instance for memory rows costs roughly 400 more
columns. Moving the base to a Fiat-Shamir challenge does not work either, the
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
counters, the exit code, the trace length and the event accumulator, it does
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

`matmul_program_hash` still binds the model *architecture* only, two models
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

## Why the transaction path refuses a proof it cannot check

`src/execution/executor.rs` calls `verify_execution_proof_full` for every model
that sets `require_execution_proof`, and refuses when the bundle says the proof
does not hold. The refusal is per missing input rather than blanket: a proof
without `public_inputs` is rejected with `ai_exec_no_public_inputs`, a model
without a registered `execution_program_hash` with `ai_exec_no_program_hash`, a
proof that names another chain with `ai_exec_chain_id`, and a program that
cannot be rebuilt from the registration with `ai_exec_program_rebuild`. The
older blanket refusal `ai_exec_verifier_unavailable` is gone: the two inputs it
complained about (the guest program words, rebuilt from the registered model,
and the canonical `ExecutionPublicInputs`, carried by the proof) both exist.

- `AiModelSpec::execution_dims` lets the node rebuild the exact guest program
  words a proof was produced against (`guest_program_for_model`).
- `AiExecutionProof::public_inputs` carries the public inputs the envelope was
  produced against, and the envelope commits to them
  (`public_inputs_hash`), so a prover cannot ship a bundle it did not prove
  against.

For a proof-required model the executor now fails closed on named conditions
rather than on the whole feature: missing public inputs
(`ai_exec_no_public_inputs`), missing registered program hash
(`ai_exec_no_program_hash`), a public-inputs program hash that disagrees with
the registration (`ai_exec_program_hash`), a non-zero exit code
(`ai_exec_exit_code`), a `chain_id` that does not match the transaction
(`ai_exec_chain_id`), and finally the STARK itself against the rebuilt program
(`ai_exec_stark`). Structural checks (commitments, model id, weights digest)
still run for every model; they bind the claim but do **not** prove that the
claimed computation happened - the STARK is what does that, and only for
proof-required models.

## Code that is present but unreachable

These functions compile and are unit-tested, but nothing in a production path
calls them. They are the scaffolding for the feature, not the feature:

- `src/ai_inference/verify.rs::verify_inference_stark`: only its own tests
- `src/ai_inference/verify.rs::generate_and_verify_proof`: only its own tests

`src/ai/execution/stark.rs::verify_execution_proof_stark` and
`src/ai/execution/verify.rs::verify_execution_proof_full` are absent from the
list because the transaction path reaches the STARK through the bundle. The two
are deliberately one call rather than two: a caller that asks only for the
structural checks accepts a proof it never checked cryptographically, and a
caller that asks only for the STARK accepts a proof whose commitments belong to
a different request.

`src/tests/ai_verification_status_locks.rs` pins this: if any of them gains a
production caller, or if the executor stops calling
`verify_execution_proof_stark` on the transaction path, those tests break and
this document has to be updated with the change.

## The zkVM opcode

`VerifyInference` (0x1F) is no longer a hard-coded zero. The VM reads a
32-byte proof window (model, input and output commitments) and sets `rd = 1`
exactly when `output_c == poseidon4_hash(model_c, input_c)`; a window that
does not fit in memory, and any binding mismatch, answer 0. The AIR carries
the matching witnesses: `COL_IS_VERIFY_INFERENCE` is bound to opcode 0x1F and
`inference_is_expand` rows feed the commitment chain into the trace.

What is still open is the circuit half: nothing re-derives `output_c` from
model weights yet, so no proof demonstrates the forward pass of an inference.
Until that exists, mainnet keeps the opcode undecodable
(`MainnetActivation::default()` sets `verify_inference_enabled = false`), and
no production settlement can depend on an inference verification.

## What closing the gap requires (status)

The original five-step plan, with what has since landed:

1. ~~Store the guest program words in `AiModelSpec` at registration~~ -
   **done**: `execution_dims` + `execution_program_hash` +
   `execution_weights_digest`; the node rebuilds the words with
   `guest_program_for_model`.
2. Derive the fold constants from the Fiat-Shamir transcript instead of fixing
   them. The initial-memory commitment is in the AIR now
   (`COL_MEM_INIT_ACC` against `initial_state_root`), but with constant
   `BETA`/`GAMMA` it is solvable rather than collision-resistant.
3. Done. The transaction path derives `ExecutionPublicInputs` from the proof's
   own claim (`AiExecutionProof::public_inputs`), binds it to the registration
   (program hash, `chain_id`, `exit_code`) and rebuilds the guest program from
   the registered model.
4. Done. The executor calls `verify_execution_proof_full` and accepts only with
   `stark_ok == Some(true)` plus a structurally valid report; `stark_error`
   carries the verifier's own reason into the rejection.
5. Done. The blanket refusal is replaced by the per-input refusals above, and
   `src/tests/ai_verification_status_locks.rs` pins the chain end to end.

The honest claim is now "AI layer with data-sovereign access control, a guest
that really computes the forward pass, and a transaction path that STARK-
verifies proof-required executions against the registered program". The gap argued above stays open: the Fiat-Shamir fold (step 2). Behind the
`VerifyInference` opcode the commitment binding is real in VM and AIR, while
the circuit that re-derives the output from the weights (step 3b) is not
written, and mainnet keeps the opcode undecodable until it is.

## RPC / economics audit (2026-08-14, skill §10.5 pass)

Every AI inference layer surface was checked against live code with call-site evidence:

| Surface | Result | Evidence |
|---|---|---|
| Per-IP RPC rate limit | working | `rpc/server.rs` rate_limit_per_minute (default 120); rotating-source-aware |
| Request input bound | working | `submit_request` enforces `spec.max_input_ref_bytes` |
| Result output bound | working | `submit_result` enforces `spec.max_output_ref_bytes` |
| Result deadline (dual) | working | `deadline_block` AND `result_deadline_blocks` both checked |
| Zero-fee request spam | working | `max_fee >= 1` required |
| Model registration spam | working | `ai_model_register_fee` (governance-tunable, exact-cost, atomic) |
| Equivocation slash | working | executor → `slash_equivocator` (call site: executor.rs) |
| Callback queue bound | working | `MAX_CALLBACK_EVENTS_PER_ADDRESS`, oldest-first eviction |
| State growth | working | `run_ai_maintenance` wired at both block paths (prune_expired + expire_dispute_window, retention = DISPUTE_WINDOW_BLOCKS) |
| Request cancel | working | `AiRequestCancel` executor branch; double-cancel prevented |
| Agent payments | working | `AiAgentPayment`/`Release`/`Reclaim` executor branches |
| Canonical input commitment | working | `admit_inference_request` (V3) |
| Execution dims sanity | working | `AiModelSpec::validate` (2-32 layers, non-zero) |

Open items (recorded, not silently closed): callback `consume_callback_events`
drain has no production caller (queue is bounded; drain is an off-chain
optimization - documented in `src/ai/registry.rs`).
