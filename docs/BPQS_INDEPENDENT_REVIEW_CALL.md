# BPQS Independent Review Call (DRAFT - not yet issued)

Status: draft artifact for promotion-bar item 3 of research line F2. This
document is the call itself; issuing it (posting where, naming whom,
timeline) is a user action. It is committed in-tree so the reviewer can be
pointed at a single permalink that names every artifact under review.

Review target: the Budlum-BPQS research implementation, in-tree crate
`crates/bpqs`, at commit `c3fbc75` (branch `bug-fix`, PR #67), together
with:

- `crates/bpqs/SECURITY-ARGUMENT.md` (bar item 1, written 2026-09-22;
  contains the claim labels PROVEN / ASSUMED A1..A4 / OPEN that this
  review is asked to challenge),
- the design decision record: the 2026-09-19 BPQS F2 pre-registration in
  the companion workspace repository (section 9 lists the six pinned
  decisions; section 12 records the M2 landing and its CI evidence),
- the 69-test library battery (three hash backends x two parameter rows
  x four behaviors differential battery included),
- `crates/bpqs/kat/bpqs-kat-v1.txt` (frozen known-answer vectors),
- `crates/bpqs/examples/bench_differential.rs` (reproduces the M2
  measurement table via `cargo run --release --example bench_differential`
  inside `crates/bpqs`),
- the `bpqs_wots_reject` fuzz harness (wired into the quick 60s CI sweep
  and the 4-hour nightly schedule).

To reproduce the evidence locally: check out `c3fbc75`, then inside
`crates/bpqs` run `cargo test` (69 passed, 2 ignored: the full-scale L5
ceremony lane and the KAT writer). Rust toolchain is pinned at 1.97.1.

## Questions the review is asked to answer

1. Few-time bound (the open core): SECURITY-ARGUMENT.md section 6 prices
   the domination hunt first-order (message digits independent across
   chains) and, since 2026-09-22, carries an EXACT checksum-side
   enumeration pinned to a stdlib-only script
   (tools/bpqs_checksum_domination_exact.py: exact digit marginals,
   exact joint domination over the three checksum ranks with pool
   minima, pool saturation at q ~ 4-8). Tighten or refute what remains:
   (a) the message-into-checksum cross-correlation, stated at the end
   of the section-6 refinement - bound it tightly or break it with a
   counter-example; (b) re-derive the per-q work factors under an
   OFFLINE hunter vs an ADAPTIVE hunter (who may feed honest members
   protocol-weight payloads); (c) check the section's arithmetic itself
   against the code (params, checksum gadget, quota).
2. Family question: for the cold-committee anchor flow (window-paced,
   at most one mint per epoch per member, offline ceremony), is the
   LANDED in-family posture (PRF-derived per-call randomizer + Q_MAX=1,
   decision item 7 of 2026-09-22, in the crate since that date)
   defensible at the aimed security label, or should the recommendation
   be a family change toward a FORS/hyperstructure core (R-4), or a
   fallback to FIPS-205 tree class for the anchor slot? The review's
   answer to this question supersedes the landed interim posture.
3. Poseidon load (A3): the canonical backend is Poseidon2-Goldilocks-16
   under an overwrite sponge with 512-bit capacity and an injective
   u32-element byte binding. Assess the assumption "the sponge binding
   keeps at least its capacity budgets as a one-way function" for the
   BPQS call pattern, including any algebraic-hunt analog of the
   domination hunt above that would beat its FIPS-202 equivalent. The
   construction's insurance is the exercised SHAKE-256 cross-backend;
   the review should say whether that insurance is adequate as stated
   or needs to become the canonical label.
4. Truncation labels (N=24 row): confirm or dispute the 192-bit
   one-way / 96-bit collision labeling of the L3 row, including the
   chain-step prefix interaction (a truncated output of one step is
   the next step's input).
5. Framing injectivity (A4): check the packaging proof sketch (length
   prefixes at every nesting level; the partial-chunk ambiguity class
   killed by frame lengths) against `hash.rs`/`poseidon2.rs` as
   implemented, not as described.
6. Constant-time statement: section 1 scopes side channels out. If the
   reviewer can issue a confined statement on secret-dependent control
   flow / memory access in the signing path with bounded effort, it is
   welcome; it is not a precondition for items 1-3.

## Deliverable

A written note, severity-labeled, addressing the six questions and any
additional findings (outside the named list is explicitly in scope).
Public disclosure preferred: the research line's value to Budlum is an
auditable primitive, and an unshareable review is half the value.
Timeline suggestion: three to four weeks from artifact handoff. The
reviewer has no code-change authority; findings are triaged through the
four-item promotion bar in `docs/PQ_ANCHOR_RESEARCH.md` section 3, and
each material finding becomes its own tracked follow-up.

## Reviewer profile and process

Profile sought: published work in hash-based signatures (WOTS/FORS/class
analyses) or algebraic-hash cryptanalysis (Poseidon-family diet
analyses); conflict declaration requested before handoff (commercial
stake in competing anchor/signature products).
Logistics: the artifact set is public in this repository at the pinned
commit; a reviewer onboarding walkthrough (call, 60-90 min) can be
booked through the maintainers; compensation, if any, is outside this
document.
