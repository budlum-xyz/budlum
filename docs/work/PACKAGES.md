# Work packages

The directive (Section 15) splits all work into 64 packages, `WP-01` to `WP-64`
(the directive writes `WP-NN` as `IP-NN` in Turkish; the repository and GitHub
are English, so the package identifier is `WP-NN`, Section 15.3 item 1). One
agent runs one package at a time, and a package is ready only when every
dependency it names is merged on `main` (Section 15.1 item 5).

This file is the status record Section 15.5 item 7 requires. It is updated by
the last pull request of every package and it names, for each package, its
status, its pull requests, its last commit, and the findings it closes.

## Status of the tree this file was written against

- Branch: `main` at `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` (2026-11-05).
- The branch contains no package output: there is no `docs/audit/live/`, no
  `src/tests/audit_lane_*.rs` and no `docs/audit/FINDINGS.md`. Nothing was
  merged from the agent branches.
- There are no GitHub issues in this repository (issues are disabled), so the
  package record Section 15.3 item 1 asks for cannot be opened as an issue.
  The record is kept here instead: one row per package, with the claim, the
  lock paths and the state. Pull request descriptions carry the same claim.

## Ready packages

| Package | Lane | Layer | Dependencies | Status |
|---|---|---|---|---|
| WP-01 | A | launch | none | claimed, open pull request |
| WP-02 | B | launch | none | claimed, open pull request |
| WP-03 | C | launch | none | claimed, open pull request |
| WP-04 | D | launch | none | claimed, open pull request |
| WP-05 | D | launch | WP-04 | **done in this pull request**, see below |
| WP-06 | B | launch | WP-02 | claimed, open pull request |
| WP-12 | A | launch | WP-08 | claimed, open pull request |
| WP-20 | B | launch | WP-08, WP-18 | claimed, open pull request |
| WP-44 | A | launch | WP-01 | claimed, open pull request |

Every other package has an unmerged dependency, so Section 15.1 item 5 makes it
not ready. The dependency order is Section 15.7.

## WP-05: the concept-name map and the counter gate

Section 15.8, WP-05 card. Lane D, layer T-Launch. Dependency WP-04, whose
output (the lane ledgers) is not on `main`; WP-05 does not read that output, so
the dependency did not hold this package.

What the package required, and what the tree already had:

| Card item | State in the tree | Left to do |
|---|---|---|
| 1. The Appendix C map written to `config/naming/concept_map.toml` | present, and its 27 entries match Appendix C pattern for pattern | nothing |
| 2. The gate searches every root for every entry's patterns, skipping `allow_paths` | present (`xtask/gates/src/gates/concept_names.rs`) | nothing |
| 3. Two modes, `count` and `absolute`, starting in `count` | both modes present, map in `count` | nothing |
| 4. A baseline of files and matches per entry; a rise fails, a fall must be recorded | present, but the shipped numbers were not the numbers the gate measures | **fixed**: four entries were corrected, and a canary now refuses a baseline that disagrees with the measurement |
| 5. Every entry names the owning package; `docs/NAMING.md` lists the table | `owner` was the one Appendix C field missing from every entry | **fixed**: all 27 entries carry `owner`, the gate refuses an entry without one, and `docs/NAMING.md` shows the column |
| 6. The gate's self-test injects a legacy name and requires a red result | present and green | nothing |

Findings closed: `BLG-255` (the concept-name count; the final zeroing is
WP-43's, Section 15.8). Evidence and the pull request are named in
`docs/audit/FINDINGS.md`.

Reproducing the numbers: the baseline in `.github/concept-names-baseline.txt`
is the measurement of this tree; run the gate with
`BUDLUM_CONCEPT_NAMES_WRITE=1 cargo run --release --manifest-path xtask/gates/Cargo.toml -- concept-names`
to re-measure. The writer refuses to raise a number, so any change it makes is
a lowering.
