# Work packages

The work packages are defined in directive section 15.7 and section 15.8. This
file records what the tree and GitHub show for them: status, pull requests, the
last commit and the findings a package closes. The tree keeps this ledger so
package status has one written home in English. Where the directive and GitHub
disagree, the disagreement is written down here rather than resolved silently.

## How to read a row

| Field | Meaning |
|---|---|
| Package | `WP-NN`, the same package as the directive number with the `IP` prefix |
| Lane | A, B, C or D (section 15.2) |
| State | `unstarted`, `in review`, `blocked`, `merged` |
| Evidence | What exists for it on the live branch: a pull request number, a merged commit, or a named blocker |

## Live snapshot

- `main`: `cccf1da1f4bcfe97503a3a00cfba24b172b49b31`.
- `main` is red. The failing jobs at `cccf1da` are `Gates`, `Budlum Core PQ
  build`, `Budlum Core library test`, `Budlum Core quality`, `Network Hardening`
  and `Cargo Deny (root)`/`Cargo Deny (fuzz)` in the `CI` workflow, plus
  `Audit Guard`, `Cargo Vet`, `Dependency Review`, `OSV Scanner`, `Semgrep`,
  `Typos`, `Semver Check`, `Determinism`, `Security Audit`, `Diverse Double
  Compiling` and `Extra Tooling` as their own workflows, plus `Watchdog`, which
  reports the others. A green run of these is the acceptance bar for every pull
  request in this file.
- GitHub issues are disabled on this repository
  (`hasIssuesEnabled = false`), so the package register of section 15.3, item 1
  cannot be created. Package identity is therefore carried by this file and by
  the pull request titles. This is a deviation from the directive, recorded
  here rather than worked around.
- WP-01 to WP-05 are consumed by open pull requests. WP-06 and WP-07 are consumed
  by another open pull request. Every package whose dependency row names WP-01 to
  WP-07 is therefore not ready under section 15.1, item 5.
- WP-09 and WP-10 have no open row, so their paths are free. No later package
  starts before its own dependency chain is merged into `main`; the row for
  WP-18 below says what that means for its own claim.

## Packages

| Package | Lane | State | Evidence |
|---|---|---|---|
| WP-01 | A | in review | pull request #12 (lane A ledger and tests); duplicate streams in #15 and #16 |
| WP-02 | B | in review | pull request #12 (lane B ledger and tests) |
| WP-03 | C | in review | pull request #12; #15 and #16 carry the same stream, #16 adds the engine inventory |
| WP-04 | D | in review | pull request #18 (lane D ledger and tests); #21 is a duplicate, #14, #17, #19, #22, #23 are stop reports |
| WP-05 | D | in review | pull request #20 (concept names, owner field, owner gate) |
| WP-06 | B | in review | pull request #11 (persistence move, `src/persistence/` exists in the tree) |
| WP-07 | B | in review | pull request #11 removes files under `bud/`; the full removal is not merged. This is the last link of the B chain that blocks WP-10 |
| WP-08 | A | not ready | dependency WP-01 not merged; `src/validators/` exists but `src/validators/committee.rs` (WP-12) and `presence.rs` (WP-13) do not |
| WP-09 | C | not ready | dependency WP-03 not merged. `crates/uel-abi/` exists with its own tests, frames, transport and a mock environment, so the crate is further along than its row says |
| WP-10 | B | not ready | dependency WP-07 not merged. `src/storage/bud3/` exists: `bof1`, `content_id`, `custody`, `dedup_index`, `fountain`, `limits`, `meter`, `pipeline`, `placement`, `registry`, `segment`, `tx`, `varint` |
| WP-12 | A | in review | pull request #9 (committee seat table, seat quorum, seat handover) |
| WP-18 | B | in review | this pull request: RFC 6330 acceptance (T6), the two retired carousel ceilings (BLG-216, BLG-213), the genesis object ceiling applied by the streamer, and `docs/STORAGE.md`. Its dependency WP-10 is not merged, so it claims no completion and closes no finding; see the pull request body |
| WP-20 | B | in review | pull request #13 (placement, custody proof and repair gates) |
| WP-26 | C | in review | pulled into pull request #24 |
| WP-33 | C | in review | pulled into pull request #24 |
| WP-42 | D | in review | pulled into pull request #24 |
| WP-44 | A | in review | pull request #14 (testnet feature closures and the launch decision record) |
| WP-11, WP-13, WP-14, WP-15, WP-16, WP-17, WP-19, WP-21 to WP-25, WP-27 to WP-32, WP-34 to WP-41, WP-43, WP-45 to WP-64 | not stated | unstarted | no row on GitHub and no open pull request path |

## Findings closed by this file's pull requests

None yet. A finding is closed when the directive's closure protocol in section
14.1, item 5 has run: the test is red before the fix, the fix makes it green, the
pull request merges, and the record carries the commit SHA and the CI run number.
The pull requests in the table above are open, so none of them closes a finding.
