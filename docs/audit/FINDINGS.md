# The finding ledger

The single ledger of the repository's findings. A finding is a defect, a gap
or a security weakness with a stable identifier; the identifier is never
reused and never renumbered. The ledger is the record of *closures*: it names
the commit and the CI run that closed a finding, and nothing else counts.

Section 14.1 of the binding directive defines the rules. They are repeated
here in English because the directive does not enter the repository.

## Rules

1. **Identity.** Every finding carries a `BLG-NNN` identifier. Identifiers are
   stable and are never given to another finding.
2. **Severity.** Critical, High, Medium, Low.
3. **Status.**
   - `Open` - the defect is in the tree and nothing has been done about it.
   - `Confirmed` - the defect is open and has been reproduced.
   - `Closed` - the fix is merged. The row carries the commit SHA and the CI
     run number.
   - `Closed by removal` - the code that carried the defect is gone. The
     evidence is the file list plus the green `no_legacy_storage` gate.
   - `Invalid` - the condition no longer exists, with the evidence that shows
     it.
   - `Fix in review` - a fix is written and pushed but no CI run has proved it
     yet. This is not a closure.
4. **Live status.** The live status of every finding is produced by the lane
   audits (WP-01 to WP-04) into `docs/audit/LIVE_STATUS.md`. That file does not
   exist yet; until it does, a finding is only described here when a package
   closes it or when a new one is found.
5. **Closing protocol.** Write the test named in the finding's *required test*
   field. The test is red before the fix, and the pull request description
   carries the red output. Then write the fix. Then merge. Only then does the
   status become `Closed`, with the SHA and the CI run number.
6. **Invalid findings.** A finding already fixed in the analysis base is
   proved with a regression test that stays in the tree. The status is
   `Closed` and the note reads "already fixed".
7. **New findings.** Every new problem found while working gets the next free
   identifier from `BLG-268` upwards and is written here. Do not skip a number
   and do not reuse one; the ledger is append-only in that range.
8. **Archive families.** The archived records `BULGU-001` to `BULGU-027`,
   `TEST-GAP-01` to `TEST-GAP-08` and `DOC-GAP-01` to `DOC-GAP-09` keep their
   identifiers. A package that closes one writes it in its own row.

## Closed findings

No finding was closed by a merged pull request at this commit. The lane audits
fill the rows as packages merge. A row is only added here with its SHA and CI
run number.

| Finding | Severity | Area | Title | Closed by | Commit | CI run |
|---|---|---|---|---|---|---|

## Findings opened here

| Finding | Severity | Area | Title | Status | Evidence | Closing package |
|---|---|---|---|---|---|---|
| BLG-268 | Medium | CI gates | The `indexing-is-not-new` ratchet is red on `main`: `src/bin/support/http.rs` indexes a slice at runtime and is not in the frozen baseline | Fix in review (PR #135) | The gate scans `src/` for `slice[i]` and `slice[a..b]` with non-literal bounds outside test modules, and fails on any file that is not in its baseline. A faithful port of the gate's own `indexes_at_runtime` and `strip_test_mods` over the tree at `20140e8` reports 293 files scanned, 80 baseline entries, 0 stale entries and one offender: `src/bin/support/http.rs:37: octets[8..].fill(0);`. The line zeroes the low 64 bits of an IPv6 bucket; PR #135 replaces it with `octets.iter_mut().skip(8)`, which preserves the bucket without adding a runtime index. It remains open pending merge and CI evidence. | WP-42 |

## Notes on the evidence

The environment this row was written in has no Rust toolchain: `cargo`,
`rustc` and `rustfmt` are absent, and a network fetch of a toolchain is not
available. The gate was therefore reproduced from its source rather than
executed, and the row says `Fix in review` rather than `Closed`. The first CI
run on this branch supplies the number the row is waiting for.

A gate that cannot run is not a protection, so the CI wiring of the gate suite
is recorded as a gap in `docs/work/PACKAGES.md` (WP-42, gap 4) rather than
claimed as done here.
