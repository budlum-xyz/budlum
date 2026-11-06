# Work package board

Directive section 15.7 lists 64 packages. This file is the status record that
section 15.5 item 7 asks each package's last pull request to update: package,
lane, state, dependency, pull request list, last commit SHA, CI run numbers and
closed findings. It is a shared append-only file (section 15.3 item 4), so every
package appends to it and no package locks it.

The state vocabulary is the directive's: `Open`, `In progress`, `Blocked`,
`Merged`. A package is `Merged` only after its pull request is in `main`; a
branch that carries the work is `In progress`.

## Board (live at 2026-11-06)

| Package | Lane | State | Dependency | Pull request | Last commit | CI runs | Closed findings |
|---|---|---|---|---|---|---|---|
| WP-01 | A | In progress | none | #12 (`arena/b0362659-budlum`) | `442d477` | see PR #12 | none (verification only) |
| WP-02 | B | In progress | none | #12 (`arena/b0362659-budlum`) | `b7083e0` | see PR #12 | none (verification only) |
| WP-03 | C | In progress | none | this branch | see below | see below | none (verification only) |
| WP-06 | B | In progress | WP-02 | #11 (`arena/792d7fb2-budlum`) | see PR #11 | see PR #11 | see PR #11 |
| WP-12 | A | In progress | WP-08 (on `main`) | #9 (`arena/5b54fce9-budlum`) | `d6a96eb9` base | see PR #9 | see PR #9 |
| WP-20 | B | In progress | WP-08, WP-18 | #13 (`arena/df5c50ec-budlum`) | see PR #13 | see PR #13 | see PR #13 |
| WP-24 | B | In progress | WP-10 | #8 (`arena/b7784c85-budlum`) | see PR #8 | see PR #8 | see PR #8 |
| WP-04 | D | In progress | none | #35 (`arena/3ef3b577-budlum`) | see PR #35 | see PR #35 | none (verification only) |

## WP-03: live verification, lane C (execution, BudZero, domains, privacy, AI)

- **Lane / layer:** C, T-Açılış, TLG yes.
- **Dependency:** none. Started on `cccf1da` (`main`).
- **Deliverables:**
  - `docs/audit/live/lane-c.md`: 74 records, one row each. 4 closed
    (`Kapalı (önceden düzeltilmiş)`), 19 reproduced (`Doğrulandı`), 51 open
    (`Açık`). Every row carries the English title `docs/audit/FINDINGS.md` needs,
    the live status, the test or lock, identifier-level evidence and the closing
    package.
  - `docs/audit/live/engine-inventory.md`: the section 8.2 engine table. Measured
    result: no catalog engine is a dependency of any workspace, so the inventory
    is a policy pre-check, not a scan.
  - `src/tests/audit_lane_c.rs`: source locks for the closed record and the
    closed feet on the `src/` side. Wired into `src/tests/mod.rs`.
  - `budzero/tests/audit_lane_c.rs`: source locks for the closed records and the
    closed feet on the BudZero side, compiled as `bud-proof`'s `audit_lane_c`
    target through `budzero/bud-proof/tests/audit_lane_c.rs`.
- **Done criterion status:** every record in scope has a row; the four closed
  records carry a permanent test; the `engine-inventory.md` extra file exists.
  The remaining done-criterion item is the pull request merge. Red reproduction
  tests for the 51 open and 19 reproduced records are owed on `audit/repro-c`
  (a branch that never merges) and move into each closing package's pull request
  (section 14.1, S-3).
- **Closed findings:** none. WP-03 verifies; the closing packages fix.
- **Findings moved to `Kapalı (önceden düzeltilmiş)`:** BLG-039, BLG-114,
  BLG-136, BLG-162. Their permanent tests are named in the ledger and held by the
  locks above.

## WP-04: live verification, lane D (clients, operations, CI, documentation, combined state)

- **Lane / layer:** D, T-Acilis, TLG yes.
- **Dependency:** none. Started on `cccf1da` (`main`), pull request #35.
- **Scope:** the section 14 rows whose closing package is WP-05, WP-11, WP-36, WP-40, WP-41,
  WP-42, WP-43, or WP-46, plus WP-61. That is 70 records, all of them listed verbatim in
  `lane-d.md` section 8.
- **Deliverables:**
  - `docs/audit/live/lane-d.md`: the 70 records, with the lane's scope derivation, the per-package
    counts, what was read and what was not, and the lane's own corrections to its earlier readings.
  - `docs/audit/LIVE_STATUS.md`: the ledger index, the section 14 row arithmetic, the per-package
    distribution, the CI baseline (card item 2), and the proposed replacement for section 14.2
    (card item 7).
  - `docs/audit/FINDINGS.md`: the 70 rows in English, one per record, with the five state words of
    section 14.1 rule 3 and the WP-04 vocabulary mapped to them.
  - `src/tests/audit_lane_d.rs`: the lane's permanent tests, wired into `src/tests/mod.rs`.
- **State of the readings:** 10 records are `Previously fixed` (BLG-012, BLG-013, BLG-014, BLG-022,
  BLG-099, BLG-192, BULGU-011, BULGU-012, DOC-GAP-03, DOC-GAP-07) and 1 is `Will close by removal`
  (BLG-254).
  Four of those carry a record-named test in `src/tests/audit_lane_d.rs`
  (`blg_099_`, `blg_022_`, `blg_192_`, `bulgu_012_`). Six records are narrowed rather than decided
  (BLG-015, BLG-016, BLG-081, BLG-085, BLG-095, BLG-097): each names the clause that is still open.
  The remaining records stay `Open` because section 15.8 places the old ledger outside this
  repository and it is not in this checkout.
- **Findings moved by this package:** BLG-012, BLG-013, BLG-014, BLG-022, BLG-099, BLG-192,
  BULGU-011, BULGU-012, DOC-GAP-03, DOC-GAP-07 to `Previously fixed`; DOC-GAP-03 fixed in this pull request (both READMEs
  named a script that `ops/scripts/` no longer holds, and `fuzz/README.md` named two more).
- **Not delivered, with the reason:**
  - Card item 5 (one GitHub record per package) is impossible on this repository: the API reports
    `has_issues: false`, so no issue can be opened. Section 15.3 item 1's flow cannot run until
    issues are enabled on the repository, which is a settings change, not a code change.
  - The 64 package records of the done criterion cannot be created for the same reason, so
    "M0 complete" is not claimed.
- **Done criterion status:** all four lane files are on the branch (`lane-d.md`, `LIVE_STATUS.md`,
  `FINDINGS.md`, and this section of `PACKAGES.md`); the lane test file exists and is wired. The
  pull request is open and not merged.

<!-- carried rows from pr-68 -->
| Package | Lane | Status | Dependency | PR List |
| İP-01 | A | Open | None | PR #64 (proposed) |
| İP-02 | B | Open | None | PR #65 (proposed) |
| İP-03 | C | Open | None | PR #66 (proposed) |
| İP-04 | D | Open | İP-01, İP-02, İP-03 | PR #67 (proposed) |
| İP-05 | D | Open (WP-05) | İP-04 | PR #50 (WP-05) |
| İP-06 | B | Open (WP-06) | İP-02 | PR #60 (WP-06 continuation) |
| İP-07 | B | Open | İP-06 | PR #68 (proposed) |
| İP-08 | A | Open | İP-01 | PR #69 (proposed) |
| İP-09 | C | Open | İP-03 | PR #70 (proposed) |
| ... (remaining İP-10 to İP-64) ... | | | | |

## WP-05 status carried from pr-20

One row per work package of the directive (section 15.7). A row is written
only from evidence: a merged path in the tree, an open pull request, or a
command output quoted in the row. The record protocol is directive
section 15.5 item 7: package, status, pull requests, last commit, CI run,
closed findings.

Status vocabulary: `not started`, `in progress`, `in review`, `merged`,
`blocked`.

## Packages

| Package | Title | Lane | Layer | Status | Pull requests | Last commit | CI run | Closed findings |
|---|---|---|---|---|---|---|---|---|
| WP-05 | Concept name map and counter gate | D | T-Launch | in review | #20 | `cc772c9` | `42168200804` (Gates queued) | BLG-255 (owner field and owner test; the counter is unchanged) |

## WP-05 evidence

- `config/naming/concept_map.toml`: 27/27 entries carry an `owner` in
  `WP-01..WP-64`.
- `docs/NAMING.md`: the owner column is present for all 27 rows.
- `xtask/gates/src/gates/concept_names.rs`: `parse_map` requires `owner`
  and calls `parse_owner`; the canary rejects `WP-99` and `WP-5`.
- `concept_map_owner_is_a_known_package` pins the real map.
- The legacy-name counts are unchanged, so the baseline is unchanged.
