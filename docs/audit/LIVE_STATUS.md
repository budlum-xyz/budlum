# Live status of the findings register

The findings register of the directive carries 267 records (BLG-001 to
BLG-267) written against an earlier snapshot. This file is where their live
status is recorded. A record is live-verified only when the tree at a named
commit is read and the condition is either reproduced (open) or shown absent
(closed, with the test or the removed path as evidence).

## Method

1. Read the record, its location and its evidence field.
2. Read the live tree at the commit named in the row.
3. Reproduce the condition with a test, or show the code is gone.
4. Write the status, the commit and the evidence path. A status without those
   three is not a live status.

The directive requires a reproduction test per record. Reading a file and
concluding "this looks fixed" is not a live verification, so no row below is
marked closed on that basis.

## Environment limit of this pass

This pass ran without a Rust toolchain and without access to the CI job logs.
No test could therefore be executed and no run number exists. The honest result
is the one recorded here: the records below are not live-verified in this pass,
and the pass says so instead of guessing.

| Range | Source | Records | Live status in this pass |
| --- | --- | --- | --- |
| BLG-001 to BLG-207 | Findings ledger | 207 | Not live-verified. One record, BLG-005, was already closed in the ledger. |
| BLG-208 to BLG-222 | B.U.D. 3.0 specification, code faults H1 to H15 | 15 | Not live-verified. |
| BLG-223 to BLG-245 | BudZero specification findings E1 to E23 | 23 | Not live-verified. |
| BLG-246 to BLG-267 | Directive review of 2026-11-04 | 22 | Not live-verified. |
| BLG-268 to BLG-275 | New findings, `docs/audit/FINDINGS.md` | 8 | Open. See the register table below. |

## New findings, state at this pass

| Identity | Severity | State | Note |
| --- | --- | --- | --- |
| BLG-268 | High | Open | The `no_out_of_block_consensus_writes` gate refuses an unmodified tree around `chain_actor.rs`. Reconciling the gate and the call is WP-17 work. |
| BLG-269 | Medium | Open | Two files sit outside the recorded index of the `indexing_is_not_new` gate. |
| BLG-270 | Medium | Open | Dead public API count is above its baseline. |
| BLG-271 | Medium | Open | Five guards are unwired against a baseline of three. |
| BLG-272 | High | Open | Three formatting diffs. |
| BLG-273 | Critical | Open | The feature matrix build and the library test step fail. |
| BLG-274 | Medium | Open | The network hardening test step fails. |
| BLG-275 | Low | Open | Both cargo deny jobs fail. |

## What this pass adds

One new record, BLG-276, written in `docs/audit/FINDINGS.md`: the concept name
counts of the integrated tree are above their baseline for five concepts, so
the `concept_names` gate cannot be green on this tree. The finding names the
five concepts and the files that carry the new names.

## What closes the register

The register is live-verified when every row above carries a commit, an
evidence path and a run number. Until then the launch gate row TLG-01 stays
red, which is what `docs/audit/TLG_REPORT.md` records.
