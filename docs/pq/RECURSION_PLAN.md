# BudZero recursion plan

Status: plan only. BudZero does not support recursion today. This file lists
the coding steps that would add it, in dependency order, and the acceptance
test of each step. No claim in `docs/pq/CLAIMS.md` depends on it.

## Why recursion

PUL-Full (section 6.1 of) proves the post-quantum half of every
signature in a finality window. One proof per window is already smaller than
the raw witnesses for large windows, but the saving that matters is one proof
per many windows (a handoff period of 86,400 blocks is 8,640 windows). That
needs a proof that verifies other proofs.

## Fixed inputs

- Prover: the Budlum fork of the Plonky3 univariate STARK
  (`budzero/bud-proof/src/bud_stark`), Goldilocks base field, a cubic
  extension for challenges, Keccak-256 Merkle commitments, FRI.
- Hash for commitments and the Fiat-Shamir transcript: Keccak-f[1600]
. No Poseidon on a long-lived path.
- Soundness target: at least 128 provable bits at every level
  (`cargo run --manifest-path xtask/tools/Cargo.toml -- stark-soundness`).

## Steps

### R-1 Transcript chip

Implement the verifier's Fiat-Shamir duplex over the Keccak chip: absorb
field elements and digests, squeeze challenges in the cubic extension, grind
check.

Accept: the in-circuit transcript produces the same challenges as the native
verifier transcript on 1,000 random proof transcripts, byte for byte.

### R-2 Extension field arithmetic rows

Add multiplication and inversion of the cubic extension as constrained rows
(a few base multiplications each, with the inverse as a witnessed value and a
product check).

Accept: random operand pairs agree with the native `p3-field` results, and a
row with a wrong inverse is rejected by the AIR.

### R-3 Merkle path verification rows

Verify a Keccak Merkle path of a given depth against a root: one Keccak-f
call per level, left and right selected by the index bit.

Accept: valid paths of depth 1 to 24 verify in the circuit; a flipped sibling,
a flipped index bit or a wrong root is rejected.

### R-4 FRI query rows

For each query: open the committed layers, check the folding relation
`f_{i+1}(x^2) = fold(f_i(x), f_i(-x), beta_i)`, and check the final
polynomial. The number of queries and the folding arity come from the child
proof's `build_config`, as public inputs of the parent.

Accept: the circuit accepts every proof the native verifier accepts in the
test corpus and rejects a proof with one tampered FRI opening at each layer.

### R-5 Constraint evaluation at the out-of-domain point

Evaluate the child AIR's constraint polynomial at the sampled point from the
opened trace values and compare with the quotient opening. The child AIR is
fixed per recursion level, so its constraint evaluator is compiled into the
parent AIR (no interpreter in the circuit).

Accept: for the PulAir child, the parent accepts a valid child proof and
rejects a child proof whose trace opening is changed by one field element.

### R-6 Single-child recursion

Compose R-1 to R-5 into a parent circuit that verifies exactly one child
proof and exposes the child's public inputs (the statement root of PUL-Full)
as its own.

Accept: end to end, `verify(parent)` implies the child statement; the parent
proof size and prover time are measured and written to
`docs/pq/MEASUREMENTS.md`; the parent reaches 128 provable bits on its own
parameters.

### R-7 Aggregation of k children

Verify k child proofs in one parent (k from a fixed set, for example 8) and
expose a Merkle root over the k statements. Build a tree: windows to epochs to
handoff periods.

Accept: a tree over 64 windows verifies; swapping, dropping or duplicating a
child changes the root or fails the parent; one invalid child fails the tree.

### R-8 Wire format and versioning

Version the proof envelope (`PROOF_FORMAT_VERSION`), bind the recursion level
and the child verification key digest into the statement, and refuse a proof
whose level or key digest is not the expected one.

Accept: a level-1 proof presented as level 0, and a proof under another
child key digest, are rejected.

### R-9 Archive wiring

Let the archive compaction path replace a span of raw window proofs by
one aggregate when `pul_full_bytes < 0.5 * witness_bytes_in_archive` holds for
the span, and keep the raw proofs until the aggregate is confirmed.

Accept: below the threshold nothing is produced; above it the aggregate
verifies and the raw proofs may be deleted; an aggregate that does not verify
never allows deletion.

## Order and parallelism

R-1, R-2 and R-3 are independent. R-4 needs R-1, R-2 and R-3. R-5 needs R-2.
R-6 needs R-4 and R-5. R-7 needs R-6. R-8 and R-9 need R-7.

## Risks recorded

- The Keccak chip dominates the cost: each Merkle level and each transcript
  squeeze is a Keccak-f call. The measured count per recursion step decides
  whether R-7 is practical; if it is not, the fallback is to stop at R-6 and
  aggregate by list, which is claimed nowhere.
- An independent review of the recursion circuit is required before any claim
  rests on it (audit package A5).
