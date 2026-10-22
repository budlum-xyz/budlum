# BPQS Verify Chain: VerifyMerkle Audit Expressibility (promotion bar item 4)

Status: analysis, written 2026-09-22 against the tree at `eafbe01`
(bud-isa, bud-vm, bud-proof as committed). Bar item 4 stays OPEN; this
document is its pre-work and its routing manifest. Read it beside
SECURITY-ARGUMENT.md: that file owns the cryptography, this one owns the
verifier-side audit surface. Writing rules as there: PROVEN =
code-verifiable on this tree today, ASSUMED = tagged, OPEN = routed.

## 1. What bar 4 actually requires

Promotion bar item 4 (`docs/PQ_ANCHOR_RESEARCH.md` section 3): "the verify
chain must be expressible within the VerifyMerkle opcode audit scope so
the anchor verification stays auditable." The 2026-09-19 pre-registration
(section 5) pre-answered this as: the verify chain is Poseidon
permutations + SELECT/compare, so no new opcode class is needed and the
third-party audit scope does not widen. This analysis checks that claim
against the code. It does not survive the check as written; sections 3
and 4 give the measured state and the route that restores the intent.

## 2. Measured baseline (PROVEN, on this tree)

The BudZKVM primitive inventory the claim points at:

- `Opcode::Poseidon = 0x19` (bud-isa): executes as
  `poseidon4_hash(src1, src2) -> u64` in bud-vm - a width-8 Goldilocks
  Poseidon compression over register lanes, single u64 in/out per call.
- `Opcode::VerifyMerkle = 0x1E`: operands (root, leaf, path_addr) over a
  memory layout of 64 x u64 siblings + key; pushes 64 immediate
  "expansion" rows (one per Poseidon round) that the STARK AIR
  (`bud-proof/plonky3_air.rs`) constrains row by row. Gas/price: priced
  in the gas table among the 17 priced opcodes.
- Program budget: the VM iteration contract caps programs at 4096
  instructions and 50,000 gas (the `vm_execute` fuzz harness documents
  the cap; the gas-calibration gate pins the price floor).
- The Poseidon permutation inside the AIR is the Goldilocks **width-8**
  instance, R_F = 8 + R_P = 22, 30 rounds, every round constrained
  (bud-isa's own privacy-opcode comment block). The earlier 4-round
  truncation was found inversionable and is gone.
- `VerifyMerkle` is **gated OFF on mainnet** today
  (`MainnetActivation::default().verify_merkle_enabled = false`), and the
  activation condition recorded in bud-isa is an **external review**, not
  a missing constraint. The file documents the binding gap that was
  already found once (round-64 output not bound to `merkle_current`;
  measured exploitable, fixed since, `rejects_verify_merkle_root_not_produced_by_the_path`)
  and an address-wrap panic the fuzzer hit in about a second. Anchor
  production mode itself is fail-closed pending the same audit
  (`src/settlement/pq_anchor.rs`: "fails by construction until the
  VerifyMerkle third-party opcode audit").

BPQS verify chain weight (PROVEN by construction in `crates/bpqs`):
epoch derivation (one u64 divide), LEN x (w-1-d) chain steps (<= 67 x 15
at L5), one vk_compress, one leaf hash, T_LOG2 = 16 node hashes, plus
compares. In hash calls: ~10^3 digests per verify; each digest =
BPQS-POSEIDON2-SPONGE-v0 = 1-2 width-16 permutations over 4-byte LE
chunks. Total: approximately 2 x 10^3 width-16 permutations per verify,
plus ~10^3 u64 compares.

## 3. The mismatch, stated plainly

Three facts collide with the pre-registration's sentence:

1. The permutations are not the same permutation. The AIR constrains a
   width-8 Poseidon2; the BPQS canonical backend (user decision
   2026-09-19, "p3 parameters") is width-16 with a 512-bit capacity
   sponge - the width is exactly where the L5 budget lives (SECURITY-
   ARGUMENT.md section 5/A3). A width-8 sponge at the same rate split
   offers a 256-bit capacity, which prices the one-way claim at ~128
   bits and collision at ~64 bits: the canonical row cannot be re-bound
   onto width-8 without cutting its assumed budgets below label (this
   kills the naive variant of "re-bind BPQS to the VM permutation").
2. VerifyMerkle as an opcode speaks a different Merkle: 64-deep path of
   u64 nodes hashed with poseidon4 over register lanes; BPQS paths are
   16-deep over 32-byte node values from a domain-separated byte sponge.
   They are structurally cousins, not the same construction; nothing in
   the current opcode verifies a BPQS path.
3. The "no new opcode class" escape (express it in plain VM instructions)
   is budget-dead on arrival: a width-16 Goldilocks permutation in raw
   u64 arithmetic costs roughly 10^2-10^3 instructions even before the
   sponge logic (field width exceeds the machine word; every multiply
   is multi-limb), so one BPQS verify (~2 x 10^3 permutations) is
   ~10^6 instructions against a 4096-instruction program cap and a
   50,000-gas ceiling. Expressibility that cannot execute inside the
   contract's own budget is not expressibility.

So: as of this tree, the BPQS verify chain is NOT expressible within the
audited VerifyMerkle scope. The intent behind the bar (the anchor
verification must not widen the third-party audit surface beyond one
named scope) is salvageable - section 4 - but the pre-registration's
sentence "no new opcode class is needed" is hereby corrected in the
record.

## 4. Route options (costed; decision routed, not taken here)

E1 - Poseidon16 chip inside the existing audit scope. Add a width-16
Poseidon2 lane to the same plonky3 AIR package the VerifyMerkle audit
will already read (same 30-round schedule, initial/terminal round
splits, same Grain-LFSR constants set - byte-identical constants to
`crates/bpqs/src/poseidon2.rs`, enabling a cross-KAT: the pinned p3
width-16 vector holds in the Rust reference and in the AIR row
generator). BPQS verify then projects to: one u64-divide + ~2 x 10^3
chip rows (permutation calls) + compare rows, all inside ONE audit
package. Cost: one new chip in the AIR (trace widens, round count
unchanged); the VerifyMerkle external-review already on the critical
path absorbs the poseidon16 chip in the same engagement if it is in the
queue manifest (section 5). This is the route that keeps bar 4's
sentence true with one honest amendment: the needed class is a chip,
not an opcode; the audit scope widens by one chip inside one package.

E2 - Generalize VerifyMerkle to parameterized width/depth. Fold the
64-deep u64 path verifier and a 16-deep 32-byte path verifier into one
parameterized AIR. Cost: higher chip complexity, longer review;
benefit over E1: one chip instead of two (path walk + sponge). Carried
as an option, not recommended for the first audit round: it multiplies
the reviewer-facing surface exactly where history says bindings get
forgotten (the `merkle_current` lesson).

E3 - Defer: keep BPQS verification off-VM entirely (native settlement
code), with the production slot fail-closed forever unless bar 2/3 say
otherwise. Cost: bar 4 never closes, BPQS never promotes beyond
research; the anchor flow keeps its current PQ family. Honest and
available; recorded so the cost of E1 is visible against it.

Registered recommendation (this document's own weighing, pending the
user's decision on item 7 and the review-call issue): E1, queued as
manifest items M-3/M-4 below so the review assesses the widened chip
set in the same engagement as the VerifyMerkle binding re-review.

## 5. Audit queue manifest (routing for the bar-3/bar-4 joint engagement)

The single named audit package this document and `src/settlement/
pq_anchor.rs` both wait on; each item names its evidence owner:

- M-1: VerifyMerkle opcode 0x1E re-review after the binding fix -
  includes `rejects_verify_merkle_root_not_produced_by_the_path` and
  the address-wrap panic history (fix + regression pins in place).
  Owner of evidence: bud-proof / bud-isa trees as pinned at the
  engagement start commit.
- M-2: plonky3 AIR main package covering execution + Poseidon width-8
  privacy lane (the 30-round constraint set; the privacy opcodes'
  reopening rationale in bud-isa is part of the record the reviewer
  reads).
- M-3 (queued by this document): Poseidon16 chip (E1) with the
  cross-KAT obligation against `crates/bpqs/src/poseidon2.rs`
  constants and the pinned upstream vector; opens once decision item 7
  lands E1-side.
- M-4 (queued by this document): BPQS verify-chain trace projection
  (the ~2 x 10^3-permutation schedule of section 2) expressed over
  M-3's chip, so the anchor verification's row count is part of the
  audited package, not an estimate in a markdown file.
- M-5: gas table impact of any new chip (17-priced-opcode calibration
  gate currently pins floors; new priced entries need new evidence).

## 6. What blocks where (dependency graph, one line each)

- Bars 1/2/3 -> KARAR-7 (user decision: residual-risk posture of the
  few-time term; SECURITY-ARGUMENT.md section 6).
- Bar 3 (review call) can issue in parallel with KARAR-7; the call's
  question 2 already subsumes it (`docs/BPQS_INDEPENDENT_REVIEW_CALL.md`).
- Bar 4 (this document) -> E1/E2/E3 posture (user decision; E1
  recommended) -> M-3/M-4 implementation (a later milestone; chip work
  belongs to the BudZero tree, not crates/bpqs) -> VerifyMerkle
  external review (shared blocker with anchor production mode).
