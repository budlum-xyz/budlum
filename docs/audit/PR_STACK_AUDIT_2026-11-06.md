# Open pull-request stack audit — 2026-11-06

Audit written on branch `arena/8067bfbc-budlum` against the live repository state
read on 2026-11-06. Method: `gh pr list --state open`, `git fetch` of every branch a
finding depends on, and text-level comparison of the checked-out files. No build was
run: this environment has no Rust toolchain, so every statement about a gate is a
statement about the code the gate runs, not about its output. Where a conclusion
depends on CI that was still queued or red, the record says so.

Findings carry the local identifier `STACK-NN`. They are not `BLG-NNN` records:
`docs/audit/FINDINGS.md` does not exist on `main` (nine open pull requests create it,
in nine different shapes, see STACK-06), and a `BLG` number must be minted by the PR
that owns the closing change. Whoever canonicalises `FINDINGS.md` should adopt the
records below with fresh numbers.

Severity vocabulary is the one `docs/audit/AUDIT_FINDINGS.md` uses: `blocker`, `high`,
`medium`, `low`.

## The state the audit was written against

| Item | Value |
|---|---|
| `main` | `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` ("Add files via upload") |
| Open pull requests | 52 (`gh pr list --state open`) |
| Head of this branch | branched from `cccf1da1` |
| CI on `main` | not green. Open pull requests carry mixed states; see STACK-12. |
| THE_BUDLUM_DIREKTIF.md | tracked in the tree at the repository root (STACK-02) |

---

## STACK-01 (blocker) — PR #8 and stacked PR #9 do not descend from `main`

`gh pr view 8 --json baseRefName` gives `ccr-c224ffbb-cbjvam`. That branch and PR
#8's branch `arena/b7784c85-budlum` share no merge base with `origin/main`:

```
$ git merge-base refs/remotes/pr-8 origin/main ; echo $?
1
$ git rev-list --count b9f27a74 ^cccf1da1
1336
```

Both sit on the pre-`Add files via upload` timeline; the 5200+ line commit
`cccf1da1` re-rooted the repository as a single import. Consequences:

- PR #8's reported diff against its base is 99,341 changed lines across 344 files
  (`gh pr view 8`); almost all of it is the absence of the re-root, not new work.
- Nothing in #8 can reach `main` except through a tree-level (squash) merge whose
  conflict resolution is a rewrite of the 74 files the squash touched, or a manual
  rebuild.
- #8 duplicates the B.U.D. 3.0 codec/dedup slice that `main`-based PR #65
  (`WP-24, 1/3`) carries, and its nine stacked commits (`state recovery move`,
  `persistence move`, `codec registry`, `The concept counter meets its baseline again`)
  duplicate work now carried by `main`-based PRs #11, #60, #65, #69.
- #8's title violates the `WP-NN: <summary>` rule (directive section 15.5 item 3):
  it is the WP-24 slice and carries no package id. Its two named commits do the same
  `regression_ops_crypto.rs` rename that this branch does, against the old layout.
- PR #9 (`WP-12`, the committee seat table) is based on `arena/b7784c85-budlum`, so
  it inherits the same root problem. `src/chain/finality.rs` in #9 is the same file
  that eight `main`-based PRs edit.

Recommended action: do not merge #8 or #9 as-is. Rebuild the WP-24 slice as a
`main`-based PR (PR #65 already is one), and rebuild WP-12's committee work on top of
it. If the unique content of #8 is wanted (the codec register and the dedup index),
cherry-pick it onto `main` in a new branch and let the old line retire. This is an
owner decision: see STACK-10 on who may close or supersede a pull request.

## STACK-02 (high) — the binding directive is tracked in the tree

`git ls-files | grep -i direktif` → `THE_BUDLUM_DIREKTIF.md` (root, 6044 lines).
Directive section 0.1 item 5 forbids this: the tree is English and the directive
must not be in it. This is WP-42's scope and two open PRs attempt it (#42 "keep the
directive outside the tree", #63 "remove the binding directive from the tree"), and
ten more open PRs touch the file anyway (#8, #11, #14, #24, #34, #36, #42, #43, #45,
#63), which guarantees last-writer conflicts on a file that should not exist.

Recommended action: land exactly one of #42/#63 (they overlap; confirm which) and
rebase the rest. Nobody else should edit the directive: corrections belong in the
directive's own revision cycle, not in a package PR.

## STACK-03 (blocker) — `docs/work/PACKAGES.md` does not exist on `main`; 20 open PRs create it in at least three divergent formats

Directive section 15.5 item 7 requires the file (package, status, pull requests,
last commit, CI run numbers, closed findings). It is absent on `main`. The 20 open
PRs that add it do not agree:

- #13 and #50 write evidence-based ledgers (state only what can be verified; no row
  without a source). These are the two usable formats.
- #68 writes a placeholder table (`İP-01 .. PR #64 (proposed)`, `İP-07 .. PR #68`,
  `... (remaining İP-10 to İP-64) ...`) mapping packages to pull requests that do not
  carry them (WP-01 is not PR #64; #64 is `WP-09: do not retry uncertain worker
  request writes`). It is not a record; it is a template with invented numbers.
- The remaining seventeen vary on those three shapes: #14, #16, #20, #29, #30, #31,
  #35, #36, #41, #47, #48, #51, #56, #57, #59, #63, #65.

Recommended action: keep one ledger (this pull request seeds an evidence-based
version; see `docs/work/PACKAGES.md`), rebase the other 19 creators onto it, and
reject #68's variant. GitHub issues are disabled on this repository, so the file is
also the claim record (sections 15.3 items 1-2); its format must stay
machine-checkable or the claim protocol silently dies.

## STACK-04 (blocker) — PR #68 ships an unparseable concept-names baseline

`xtask/gates/src/gates/concept_names.rs::parse_baseline` hard-fails on any line that
is not `name|files|matches` with `usize` fields. PR #68 rewrites
`.github/concept-names-baseline.txt` into prose arrow lines
(`Budscan|33|268 -> 0|0: the crate, ...`), so the gate returns
`Err("expected `name|files|matches`")` and CI cannot go green on that branch for
that gate. The baseline may be lowered (this pull request lowers `Budscan` to
`Budscan|0|0`), never rewritten into prose.

## STACK-05 (high) — three incompatible strategies lower the same ratchet lines

The concept-names gate requires the baseline to equal the measured count exactly, so
concurrent lowerings conflict textually and semantically:

| PR | `Budscan` | `PUL` | `Tarif` | `Regeneration` | Mechanism |
|---|---|---|---|---|---|
| #8 (legacy) | 33\|268 → 33\|267 | — | — | — | edit one match |
| #11 | — | — | — | 43\|316 → 33\|138 | edit |
| #31 | 33\|268 → 34\|272 (**raised**) | 13\|99 → 14\|100 (raised) | 51\|1442 → 52\|1444 (raised) | — | raise, with the reason recorded in a comment |
| #43 | 33\|268 → 32\|268 | — | — | — | edit |
| #50 | 33\|268 → 0\|0 | — | 51\|1442 → 50\|1356 | — | `allow_paths` in the map |
| #60 | — | — | — | 43\|316 → 29\|110 | edit |
| #68 | 0\|0 (unparseable, STACK-04) | — | — | — | prose |
| this PR | 33\|268 → 0\|0 | unchanged | unchanged | unchanged | mechanical rename, measured 0 files / 0 matches |

#31's raise contradicts the file header ("the numbers may only fall") but records why:
the gate's own algorithm measures 34|272 on the inherited tree, so the old baseline
was unreproducible. Raising is the only way to make `measured == baseline` if the map
is not also corrected. Both resolutions are internally consistent; they are mutually
exclusive in one tree. Exactly one line of each strategy can win per entry, so merge
order decides the outcome and the losing PRs go red on rebase.

Recommended action: one canonical concept-names pass (the WP-05/WP-43 owners), the
others rebase and re-measure. This pull request lowers only the `Budscan` line, which
is the line its rename eliminates; it does not touch any other entry.

## STACK-06 (high) — `docs/audit/FINDINGS.md` is created by nine PRs in nine shapes

Same failure mode as STACK-03. `docs/audit/AUDIT_FINDINGS.md` exists and is the
running ledger used by the security rounds; the nine creators of the new file do not
state how the two relate, and none of them is `main`. Until one canonical file wins,
closure claims in package PRs point at a file that does not exist on `main`.

Recommended action: pick one path (either finish the migration of
`AUDIT_FINDINGS.md` into `FINDINGS.md` in one PR, or keep `AUDIT_FINDINGS.md` and
drop the new file from the other eight). Do not accept nine divergent ledgers.

## STACK-07 (blocker) — PR #24 and PR #36 implement the same eleven new execution files, divergently

Both pull requests add these paths and they differ in every one (measured by the
branches fetched 2026-11-06):

| Path | #24 | #36 |
|---|---|---|
| `contracts/uel/BudlumUniversal.sol` | 53 lines | 84 lines |
| `docs/EXECUTION.md` | 112 lines | 149 lines |
| `execution/budzero/Cargo.toml` | — | — |
| `execution/evm/Cargo.toml` | 37 lines | 19 lines |
| `execution/evm/src/main.rs` | 67 lines | 189 lines |
| `execution/budzero/src/main.rs` | 67 lines | 105 lines |
| `src/execution/coordinator/foreign/ethereum.rs` | 701 lines | 704 lines |
| `src/execution/coordinator/gas.rs` | 269 lines | 259 lines |
| `src/execution/coordinator/overlay.rs` | 784 lines | 328 lines |
| `src/mempool/lanes.rs` | 387 lines | 316 lines |
| `src/rpc/compat/mod.rs` | 6 lines | 237 lines |
| `xtask/gates/src/gates/ee_workers_build_with_unwind.rs` | 159 lines | 274 lines |

#24 is a multi-package mega-PR (`WP-05, WP-42, WP-26, WP-33, WP-27, WP-28 (+ WP-29, WP-30)`,
19,482 changed lines). #36 is `WP-26, 1/2` (23,141 changed lines). Both claim the
WP-26 execution coordinator; the implementations of the EVM worker, the BudZero
worker, the foreign-envelope decoder seed, the gas schedule and the overlay do not
agree. Merging both is not possible; the second will conflict on all eleven files.

Recommended action: one of the two wins WP-26 (#36 is titled and scoped as the WP-26
slice and is based on `main`; #24's scope spans five packages). The loser rebases and
defers file ownership to the winner. The same applies to the three claimants of
WP-28's compat surface: #24 (`src/rpc/compat/**`), #56 (`WP-10 + WP-28`) and #72
(`WP-28 (1/2)`), which all add `src/rpc/compat/mod.rs` and `src/rpc/compat/ethereum/mod.rs`.

## STACK-08 (high) — shared files, expected conflicts, one real defect

Shared append-only files are edited by many PRs as designed (section 15.3 item 4):

- `.github/workflows/ci.yml`: #8, #24, #29, #30, #31, #40, #44, #51, #56, #60 (10 PRs)
- `src/chain/blockchain.rs`: #9, #11, #31, #40, #59, #60, #62, #66, #67, #70 (10 PRs)
- `src/execution/executor.rs`: #24, #39, #43, #44, #49, #60, #62, #66, #67, #70 (10 PRs)
- `src/core/account.rs`: #11, #24, #36, #39, #60, #66, #67, #70 (8 PRs)
- `xtask/gates/src/main.rs`: #13, #24, #29, #30, #31, #36, #40, #45, #51, #56, #60, #69 (12 PRs)
- `src/core/transaction.rs`: #45, #60, #66, #70 (4 PRs)
- `Cargo.toml` (workspace members) and `Cargo.lock`: #8, #44, #46 (2 PRs each)

Within that noise this pull request fixes one real defect: in `ci.yml`, the step
`Format / cargo fmt --manifest-path crates/<explorer>/Cargo.toml --all -- --check`
sat at the boundary between the `standalone-crates` job and the `bns-gate` job. At
that indent it parses as a **step of the `standalone-crates` job**, not of the job
that builds the crate (it ran, but in the wrong job, and the comment header
`# ===== / Bolum 4 (BNS gate) =====` split it from both). This pull request moves it
into the `budlum-explorer` job, where every sibling check for that crate lives.

## STACK-09 (medium) — WP-17 is split three ways, and two of the three stack on #60

- #60 (`WP-06 continuation + WP-17/WP-14/WP-44`) is based on #11 (`arena/792d7fb2-budlum`).
- #62 (`WP-17: make checked block application failure-atomic (1/N)`) is based on #60.
- #66 (`WP-17: reject overflowing transaction costs`) is based on #62.
- #67 (`WP-17, 2/N: spendable-balance fee gates and checked supply-path arithmetic`)
  is based directly on `main` and touches `src/chain/blockchain.rs`,
  `src/core/account.rs`, `src/execution/executor.rs` — the same files #62/#66/#60
  rewrite (STACK-10 overlaps). Two divergent WP-17 lines into the same three files.
- #66 also passes through `src/sharding/mod.rs`, which #39 (WP-16) and #60 touch.

Recommended action: merge the #60→#62→#66 chain first (it is one consistent series),
then rebase #67 onto it and drop whatever is already there. If #67 lands first, the
chain loses its fee-gate and supply-path halves and lands red.

## STACK-10 (medium) — WP-16 and WP-41 are each carried by four PRs

- WP-16: #34 (main), #37 (main), #39 (main), #52 (main, "completes the deliveries
  missing from #34 and #39"). #52 explicitly depends on #34 and #39 having merged
  or rebased.
- WP-41: #34 (main), #52, #58 (stacked on #34), #59 (main, "continues #34, #39, #52").

All six are `main`-based (or one hop from it), so the failure mode is not timeline,
it is inconsistent re-implementation of the same faucet/ops/storage-fee surface. See
STACK-07 for the execution-layer twin of this problem.

## STACK-11 (low) — stacked-branch map and non-`WP-NN` titles

Stacked (non-`main`) pull requests, top branch first; all are consistent chains
except #8 → #9 (STACK-01):

- #51 (WP-43) → #24
- #54 (WP-09) → #38 → main; #64 (WP-09) → #54
- #58 (WP-41) → #34
- #60 (WP-06 continuation) → #11
- #61 (WP-34 3/3) → #46
- #62 (WP-17) → #60; #66 → #62
- #71 (WP-07 2/N) → #69

Titles that violate the `WP-NN: <summary>` rule (section 15.5 item 3): #8, #45, #68.
Titles with a package id but no delivery ordinal for a multi-slice package: none
beyond the above; `(1/N)`/`(2/N)` markers are otherwise used consistently.

## STACK-12 (medium) — CI state is red somewhere and this environment cannot read logs

`gh pr checks 11` on 2026-11-06 lists 43 completed checks with conclusion `failure`
(everything from `Budlum Core PQ build` to `Cargo Deny (root)` to `MSRV check`), on a
run whose sibling is still in progress. Other open PRs show queued or pending runs.
This environment's network policy blocks `*.blob.core.windows.net`, so check logs
cannot be retrieved here; the root cause is **unverified**. It was not possible to
reproduce any of it locally (no Rust toolchain in this environment).

What is verified: the failure set is repo-wide (compile, lint, gates, determinism,
supply-chain), not a single crate. A change that breaks everything at once usually
does so through one of: a workspace-wide manifest/lock inconsistency, a gate that
self-test refuses, or a shared workflow edit. Candidates visible from here:

- STACK-04 (a rewrite of the concept-names baseline) — the concept-names gate would
  hard-error on #68's branch, but #11 does not carry that file change, so it is not
  the cause for #11.
- The `THE_BUDLUM_DIREKTIF.md` root file is not the cause either (it is not scanned
  by the gates).

Recommended action: the owner reads the first failing job in run
`42166395238` (and the corresponding run on `main`) before merging anything else.
Every claim of "green" in this audit would be a guess; none is made.

## STACK-13 (low) — process: pull-request size

Directive section 15.5 item 2 caps a PR at 1,500 changed lines (generated files and
test vectors excepted). Measured 2026-11-06 (`additions + deletions`, `gh pr view`):

| PR | Changed lines | Files |
|---|---|---|
| #8 | 99,341 | 344 (legacy timeline, see STACK-01) |
| #36 | 23,141 | 75 |
| #45 | 21,387 | 72 |
| #24 | 19,482 | 72 |
| #43 | 11,183 | 91 |
| #34 | 6,573 | 9 |
| #11 | 6,710 | 60 |
| #63 / #42 / #14 | ~6,100 each | 3–5 |

Every one of these will need splitting or a recorded exception before merge, or the
1500-line rule is decorative.

## What this pull request changes, and what it deliberately does not

Changes (all verified textually; see the pull-request body for the verification
statement):

1. `crates/budscan` → `crates/budlum-explorer` mechanical rename (WP-40, slice 1/N):
   crate/package/lib/bin names, the two gate files (`explorer_parity.rs`,
   `explorer_patchset.rs`), gate CLI names (`explorer-name-rule-parity`,
   `explorer-patchset`), `Cargo.lock` entries, CI job and step wiring, dependabot,
   osv-scanner, typos, the idle-code baseline paths, `tree_is_english` allowed dirs,
   `repository_locks` and `lock_failures` path lists, `suppressions_are_justified`
   budget paths, docs references, the `budscan.example` CORS test origin.
2. `.github/concept-names-baseline.txt`: `Budscan|33|268` → `Budscan|0|0`, measured
   after the rename with the gate's own scan roots (0 files, 0 matches).
3. `.github/workflows/ci.yml`: the misplaced `Format` step moved into the
   `budlum-explorer` job (STACK-08).
4. `docs/work/PACKAGES.md`: seeds the evidence-based work-package ledger
   (STACK-03).
5. This file (STACK-01 … STACK-13).

Deliberately not changed:

- `THE_BUDLUM_DIREKTIF.md` (STACK-02: two PRs own removing it; this PR does not grow
  the conflict set).
- `config/naming/concept_map.toml` and `docs/NAMING.md`: the `Budscan` mapping is
  the record of the old name and stays (it is a `config/naming/` allow-listed path
  and keeps the pattern, which is how the counter proves zero).
- `docs/audit/FINDINGS.md` (STACK-06: a canonicalisation decision is the owner's).
- Every other ratchet line in `.github/concept-names-baseline.txt` (STACK-05).
- Any execution-layer, storage-layer or consensus file (STACK-07, STACK-09, STACK-10:
  resolutions belong to the WP owners of those packages).

## Owner decisions required (not this pull request's to make)

1. STACK-01: retire or rebuild #8/#9.
2. STACK-02: pick #42 or #63 as the directive-removal PR.
3. STACK-03/06: pick the canonical ledger files.
4. STACK-05: pick the concept-names resolution per entry.
5. STACK-07/STACK-09/STACK-10: pick the winning WP-26, WP-17, WP-16 and WP-41 line.
6. STACK-12: read the first failing job of the current run before merging anything.
