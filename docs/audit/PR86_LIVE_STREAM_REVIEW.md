# PR #86 live-stream integration review

## Decision and scope

PR #86 source head `b2ba0fdb4bd7206b73406ffd57f0cad59196d273` carries a real
WP-55 live-stream core that was absent from integration base
`c2166a886be1787dfe9260bd94252661194741d9`. It is integrated as a closed,
unwired T-Expansion state machine. This is not WP-55 package completion, an
activation decision, or a testnet-readiness claim.

| Source path | Disposition |
|---|---|
| `src/storage/bud3/live.rs` | Retained and adapted. The two-second P0 BOF-1 segment chain, ratioless frame plan, bounded viewer join and deterministic final NFT-binding record are now present. Timestamp and empty-chain boundary corrections are recorded as BLG-315. |
| `src/storage/bud3/mod.rs` | The module row, declaration and re-exports were added without dropping the current optical profile, frame, grant, key, maintenance, upload or other later B.U.D.3 exports. |
| `THE_BUDLUM_DIREKTIF.md` | The source deletion needed no new change: the current tree already excludes the binding directive, and the integration audit enforces that property. |
| `docs/audit/LIVE_PR_STACK_AUDIT_2026-11-06.md` | Not restored as current evidence. Its stack counts, base commit and canonical finding ids are historical; the source findings are dispositioned below under PR86-qualified names so they cannot collide with the current BLG-298/299 records. |

Two integration adaptations are outside the source's four-path list:

- `src/crypto/domain_tags.rs` registers both new separation tags (BLG-314).
- `docs/audit/FINDINGS.md` reserves BLG-314 and BLG-315 for the corrected
  integration findings; the old audit's identifiers are not reallocated.

## Retained protocol behavior

- `ACTIVATION.height` is `None`. `begin`, `push_segment` and `finish` all
  refuse a closed context. The open path exists only under an explicitly
  supplied post-activation test context; no chain height was activated.
- A segment is a nonempty P0/raw BOF-1 object with only the live bit set by
  the producer. The first `prev_object` is the stream id and every later link
  is the preceding object commitment. The default 2,000 ms segment is a
  starting parameter, not a performance measurement.
- The producer treats a pushed segment as complete. Viewer join therefore
  retains the source's explicit ability to join inside the newest produced
  segment window; it was not changed into a wall-clock/end-of-window rule.
  A produced head more than 4,000 ms behind the requested time is refused.
  This is a state-machine budget, not a measured network-latency guarantee.
- `RatiolessPlan` emits source symbols in segment/ESI order and then repair
  symbols round-robin with increasing ESIs. It terminates at the RFC 6330
  `MAX_ESI` bound; "continuous" does not mean an unbounded integer or an
  actually connected transport.
- `finish` binds the final object commitment, segment count and NFT id into a
  deterministic `StreamEnd::bind_tag`. It does not itself mutate the NFT
  registry. The documented future door is `StorageTxV3::BindNft`.

The source comments correctly leave executor, live transaction, transport and
final registry wiring for their later activation/package work. This review did
not invent those doors or route testnet traffic into the new module.

## New findings and corrections

### BLG-314 - domain-tag inventory omission (Medium)

The source declared `BDLM_BUD3_LIVE_STREAM_V1` and
`BDLM_BUD3_LIVE_END_V1`, but did not add either to the central inventory.
Both are now registered. The primary `DOMAIN_TAGS` table is sorted and unique
with 439 entries.

A source-wide comparison still reports the pre-existing missing
`BDLM_LIVENESS_TRACKER_V4`, `BUDLUM_BUD3_ACCEPTANCE_TRIALS` and
`BUDLUM_GIT_HASH`, plus stale `BDLM_LIVENESS_TRACKER_V3`. Replaying the same
comparison without the two live additions produces exactly the same four
differences. Thus #86 adds no inventory drift, but the global domain-tag gate
is not represented as passing.

### BLG-315 - timestamp saturation and empty-chain success (Medium)

The source used `start_ms.saturating_add(LIVE_SEGMENT_MS)`, allowing an upper
boundary timestamp to collapse the fixed window instead of continuing the
timeline. It also returned `Ok(vec![])` from `verify_chain` when given no
objects, despite an empty broadcast being invalid everywhere else.

The integration uses checked addition with `LiveError::TimestampOverflow` and
refuses an empty object chain with `LiveError::EmptyStream`.
`bud3_live_stream_refuses_timestamp_overflow_and_empty_chain` pins both cases.
That regression was added as source evidence only; no Rust runner executed it.

## Disposition of the source's historical stack findings

These rows preserve review coverage without presenting the 2026-11-06 stack
snapshot as a live query or importing duplicate canonical identities.

| Source-qualified id | Current integration disposition |
|---|---|
| PR86-BLG-288 | The directive is absent and the current integration audit has a dedicated refusal canary. No second deletion or historical copy is needed. |
| PR86-BLG-289/290 | `docs/work/PACKAGES.md` and `docs/audit/FINDINGS.md` now exist. Their historical snapshot language is retained; integration ordering and current dispositions are recorded in PR #140 and the review documents rather than by rewriting that snapshot as current fact. |
| PR86-BLG-291 | A historical shared-file/coordination concern, not a live-core code defect. The ordered integration ledger and path-by-path reviews are the current control; no directive text is restored. |
| PR86-BLG-292 | PRs #77 and #80 are both in the current ancestry, with their worker transport review and integration corrections recorded separately. The old duplicate-checkpoint warning is not reapplied as a new code change. |
| PR86-BLG-293 | The evidence warning remains material: this integration has no Rust build/test success and does not repair the source PR's failed checks. |
| PR86-BLG-294 | Only the WP-55 core slice is integrated. No ownership or completion claim is made for the other T-Expansion packages. |
| PR86-BLG-295 | The old Universal Object Layer inventory was not revalidated by this live-stream review and is not imported as current evidence. |
| PR86-BLG-296 | The adapted live implementation and its review remain below the source's 1,500-line package cap; no claim is made that every other PR now satisfies that cap. |
| PR86-BLG-297 | Open-PR counts in the old document are stale by construction and are not carried into the current tree. |
| PR86-BLG-298 | Old PR #8/#9 blobs are not evidence about this integrated tree. The committee line was reviewed and adapted through #81. The whole-tree parser still finds 61 baseline error files, so no repository-wide syntax-green claim is made. |
| PR86-BLG-299 | Local tree-sitter parsing and integration canaries were used here, but they are not a pinned CI syntax gate and do not close the historical control gap. |

## Verification actually performed

- Tree-sitter-rust parsed `live.rs`, `bud3/mod.rs` and `domain_tags.rs` with
  zero `ERROR`/missing nodes.
- The same parser scanned 1,107 Rust files: 61 files retain baseline syntax
  errors, none in the three affected Rust files. Because all other Rust files
  are unchanged, this slice introduces no new parser-error file.
- The referenced current APIs were inspected: BOF-1 flags/header/encoding,
  `ContentId`, P0, `commit_object`, `MAX_ESI`, `NftId`, `Meter::for_object`,
  `hash_fields_bytes` and `StorageTxV3::BindNft` all have the source-assumed
  shapes. This is an API/source audit, not type checking or borrow checking.
- The new domain tags are both listed and used; their addition leaves the
  baseline inventory differences unchanged. The primary table's sort and
  uniqueness checks pass.
- `python3 ops/scripts/integration_audit.py` passed all 14 checks.
- `python3 ops/scripts/integration_audit.py --self-test` passed all 14 real
  violation canaries.
- Conflict-marker and whitespace/diff checks are clean on the final reviewed
  source changes.
- The #86 check snapshot had **8 passed, 38 failed, 55 pending and 3 skipped**
  checks. Those results were observed, not repaired or relabeled.

No `cargo`, `rustc`, `rustfmt` or Clippy executable is available. Accordingly,
this review does **not** claim formatting, compilation, lint passage, Rust unit
test passage, fountain/transport interoperability, deterministic execution,
NFT registry integration, measurements or testnet readiness. Closing BLG-314
and BLG-315 still requires the pinned gate/Rust CI evidence required by the
repository's finding protocol.
