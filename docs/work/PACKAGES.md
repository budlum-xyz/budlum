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
