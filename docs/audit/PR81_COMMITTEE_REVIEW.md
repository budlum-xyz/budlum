# PR #81 committee/finality integration review

| Field | Value |
|---|---|
| Reviewed source | PR #81, `e8f7365bf48ba06d9e35cb47bd09fe6f2a7a7b19` |
| Integration target | PR #140 / `arena/8f90e12c-budlum` |
| Source checks | 44 failed, 55 pending and 3 skipped in the captured inventory. These checks are not represented as green or diagnosed wholesale. |
| Local execution boundary | Tree-sitter/source invariant checks and the Python integration audit. No Rust compiler, rustfmt, Clippy, Cargo test or live finality network is available. |

## Integrated protocol surface

The source's 26-file WP-12 slice is merged into the current tree rather than
checked out over newer work:

- `CommitteeTable`, deterministic largest-remainder/capped seat allocation,
  standby ranking, seat bitmaps and two-record Instant Seat Handover;
- seat-weighted prevote/precommit aggregation, certificates and QC production;
- checkpoint participation records in block hashes and protobuf/network
  conversion, plus `seat_table_version` on finality certificates;
- sequential-finality signing guards and epoch/checkpoint bindings;
- the `BDLM_HCLE_LINK_V1` rename and three seat domain tags.

Three textual conflicts were resolved by retaining the current shared canonical
hash helper and bounded conversion constants while adding the seat code. The
validator module exports both `committee` and `handover` exactly once. A later
bridge-settlement certificate literal and later current-tree call sites were
included in the field/argument audit.

## Corrections made during integration

### BLG-310: exact table identity

The source allowed version zero to bypass a table-version mismatch. It also used
the checkpoint height as the base version, making the meaning of zero dependent
on the caller. All base tables now use version zero. A handover alone advances
the version, and verification requires both the certificate epoch and the exact
table version. The PQ-alarm path applies the same identity check.

The quorum tests no longer assert the removed hybrid stake/count rule. They
exhaust every four-validator bitmap against committee coverage, prove that a
stake-majority holder still has only its capped seats, and prove that three
low-stake validators can finalize when their seats meet the threshold.

### BLG-311: pure, archive-complete replay

The source capped replay with `finalized_height`, making the output of
certificate verification an input to the table used to verify that certificate.
Simply deleting the cap is also unsafe: a node could start a future round with
no corresponding archive and silently obtain the base table.

The integrated function therefore:

1. validates the nonzero checkpoint height, height-derived epoch and snapshot
   epoch;
2. requires the checkpoint block in the canonical chain, or in the candidate
   pruned segment being verified;
3. reads only records below that checkpoint and never reads `finalized_height`;
4. separates that pure replay from the live round-start wrapper, which requires
   exactly the lowest unfinalized checkpoint even if a future block is present;
5. returns `Result`, so startup refuses missing history instead of constructing
   an aggregator with a fallback table;
6. checks integer height increments rather than allowing a saturating loop.

Pruned-segment verification uses a borrowed chain-plus-segment view. It clones
or installs nothing before the existing segment validation completes. Thus the
new archive requirement does not reject every pruned import merely because its
certified block is not installed yet.

A regression creates a real handover, derives the identical table with different
local finalized markers, refuses the following checkpoint when its block is
absent, and refuses that future round even after its block arrives if the
predecessor is not final. Certificate verification/pruned sync deliberately uses
the pure function, not that round-start gate.

### BLG-312 and BLG-313

The quantum-alarm PQ path now counts verified signers under the same replayed
seat table as BLS. The snapshot-only light client remains an explicitly legacy
stake/count fallback because it has no finalized participation history.

Integration-only defects were also repaired: duplicate module declaration,
reserved `raw` identifiers, a missing later certificate field, stale test
assertions and an unbudgeted test-wide suppression. No suppression budget was
added for `committee.rs`; ordinary unit-test lint policy applies.

## Executed static evidence

- 26 changed Rust files parsed without tree-sitter errors after the adaptations.
- 30 `FinalityCert`, all block/header, aggregator and generated-protobuf struct
  literal surfaces were scanned for the new fields; no required field is absent.
- 26 `FinalityAggregator::new`, one `with_committee`, five `for_snapshot`, and
  all nine pure/guarded seat-table call sites were checked for their required arity.
- Domain tags are sorted and unique (437 entries), with the old link tag absent
  and all four replacement/seat tags present.
- The Python integration audit passed 14/14 current-tree checks, and all 14
  injected canaries refused their intended violation. `git diff --check` passed.

These checks do not prove Rust type checking, formatting, Clippy, test passage,
BLS/PQ interoperability or deterministic finality under a live network.

## Explicitly unfinished WP-12 scope

The source is **1/N**, not a completed testnet package. In particular this merge
does not claim vote-message V3 with seat-list/version in every signed preimage,
signed `HandoffCertificate`, participation-omission proofs/reward deletion,
light-client PQ seat migration, full quantum-alarm renaming, HCLE primary-mode
wiring or the 10,000-block measurement. Proposer-reported participation and the
current V2 vote preimage must not be described as those missing proofs.

BLG-246 and BLG-310 through BLG-313 remain open pending pinned execution evidence
and the remaining scoped work. The source's 44 failed checks, pending/cancelled
checks and any newer integration-head checks require their own triage.
