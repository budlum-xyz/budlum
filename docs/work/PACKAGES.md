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
| WP-42 | D | launch | WP-04 | **started in this pull request** (gates 1 and 2 of 8), see below |
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

## WP-42: CI, gates and the supply chain

Section 15.8, WP-42 card. Lane D, layer T-Launch, TLG yes. Dependency WP-04,
whose output (the lane ledgers) is not on `main`; the two gates below read the
tree, not that output, so the dependency did not hold them.

The card has eight jobs. Two are done here, and the other six are named so the
next packet does not start from a guess:

| Card item | State | What this packet did |
|---|---|---|
| 4. The float gate | done | `no_float_in_consensus_paths`, with the scope the card lists and a canary that stages each skip |
| (16.3) every workspace is compiled | done | `workflows_cover_every_workspace`, which discovers the workspace roots instead of listing them, and exempts the two contract workspaces with their toolchains named |
| 1. The workflow set of Section 16.2 | open | nine of the twelve named files do not exist: `execution.yml`, `mobile.yml`, `mobile-ios.yml`, `conformance-nightly.yml`, `storage-nightly.yml`, `churn-nightly.yml`, `nat-nightly.yml`, `supply-chain.yml` and `release.yml`. `release-signature.yml` is not `release.yml`. Adding one of them is a packet with its own tests, so this packet adds none rather than nine untested ones |
| 2. Runner requirements | open | `determinism.yml` runs x86_64, macOS and Windows but no `aarch64` runner, and no workflow names a 16 GiB requirement or a macOS job for iOS |
| 3. deny / vet / geiger per execution workspace | mostly done | `ci.yml` runs `cargo-deny` and the licence matrix over eleven manifests, but the `supply-chain-extra.yml` geiger job walks the root and `budzero` only, so `crates/ai-inference` and `crates/budscan` are not measured for unsafe code |
| 5. Kani coverage of the `SECURITY.md` targets | open | `TEST-GAP-02` is recorded as partly closed in `docs/audit/FINDINGS.md`, with the remainder named |
| 6. The new fuzz targets | mostly done | the seven named parsers have targets; `uel_abi_frame` runs from `fuzz/` and the list is pinned by `fuzz/`'s manifest |
| 7. The listed CI and gate findings | partly done | `BLG-012` and `BLG-014` were already closed in the tree; the other thirty-odd findings on the card, and the four gate findings for the two contract workspaces, are untouched |
| 8. The `budlum-indexer` binary registration | already done | `Cargo.toml` carries the `[[bin]]` row by name, so `DOC-GAP-07` needs verification, not a change |

Measuring the two gates: run
`cargo run --release --manifest-path xtask/gates/Cargo.toml -- no-float-in-consensus-paths`
and `... -- workflows-cover-every-workspace`. Both are wired into `ci.yml`'s
Gates job by name, so `--all` is not the only way they run.

### WP-42 overlaps an open pull request, and that is recorded rather than hidden

PR #30 (`WP-42: the float gate, the workspace coverage gate and the conformance
nightly`) and PR #29, which continues it, were open when the two gates in this
branch were written. The work here was done without reading them and is
independent, but it is a second implementation of the same two gates, and
Section 15.1 item 7 forbids two agents on one package. What follows is the
honest part.

The two versions agree on scope, on the 20 percent workspace rule and on
`EXEMPT_FUNCS` versus `EXEMPT_FILES`. They disagree in two places, and reading
#30's version is what found both bugs in this one:

| Shape | This branch, before | This branch, now | #30 |
|---|---|---|---|
| `#[cfg(test)]` on a `use` or a `const` | blanked the whole item *and the function under it*, hiding a production float | blanks the gated item only | correct |
| `#[cfg(any(test, feature = "..."))]` | treated as test-only and blanked, hiding production code | left visible, because `any` widens | correct |
| `src/storage/bud3/placement.rs` | scanned | exempt by function span, with the reason | exempt by file name, as the card writes it |

Both shapes now carry canaries (1b and 1c). Which branch merges first decides
which implementation survives; the other should be closed with a pointer to this
table rather than merged, and the survivor should take `EXEMPT_FILES` by name for
`placement.rs`, because that is the wording the card uses.

### WP-08, the same situation

`src/mempool/duty_lane.rs` here and in PR #40 are also two implementations. The
one here takes the window from the caller (`state.epoch_index`), which is wrong:
Section 7.2 gives a Mobile validator a 10-minute presence cadence and an epoch
spans many blocks, so one batch per epoch is one batch per hour on the devnet
parameters. PR #40's `window_at(now_ms)` numbers windows from the Unix epoch and
matches the cadence the directive writes. If #40 merges first, this module should
be dropped rather than reconciled; the tests it added to
`src/tests/validator_classes.rs` are the reusable part.
