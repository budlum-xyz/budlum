# Open pull request coordination report

| Field | Value |
|---|---|
| Date | 2026-11-06 |
| Scope | the 63 open pull requests against `main` at `cccf1da1`, measured after `git fetch origin '+refs/heads/*:refs/remotes/origin/*'` |
| Measured by | `python3 ops/scripts/pr_coordination.py --prs-only --base main --remote origin` |
| Baseline | `main` = `cccf1da1` ("Add files via upload") |
| Kind | measurement, not a decision. Where a decision is needed, this file names it and does not take it (Section 0.3 item 2). |

The first version of this report measured **every remote branch** (84 refs,
including dependabot branches and branches with no pull request) while its
header claimed 52 open pull requests. `--prs-only` now limits the measurement to
the heads reported by `gh pr list --state open`, which is the scope the report
claims. The number of open pull requests grows while this branch is worked on;
re-run the command for current numbers. Section 8 records every correction.

## 1. What the numbers say

| Measure | Value |
|---|---|
| open pull requests | 63 |
| distinct PR head refs present locally | 63 |
| pull requests whose head has **no common ancestor** with `main` | 2 (#8, #9) |
| pull requests whose **base is not `main`** | 16 |
| paths changed by two or more open pull requests | 431 |
| new files implemented **twice or more with different content** | 57 |
| new files added by two or more pull requests with identical content | 35 |

Every one of those 63 pull requests is written as if it were alone. The
directive's queue model (Section 15.1) has four agents and one owner per lock
path (Section 15.3); the queue it is actually being asked to describe has
sixty-three, and 16 of them are stacked on another pull request rather than on
`main`. A stacked pull request cannot be reviewed against `main` alone: its
diff includes its parent stack.

## 2. Two histories in one repository

`main` is rooted at `cccf1da1` ("Add files via upload"). Two open pull requests
are rooted at a different commit, `5b629e15` ("Universal Settlement Layer"),
which shares no ancestor with `main`:

| Pull request | Branch | GitHub's own diff |
|---|---|---|
| #8 | `arena/b7784c85-budlum` | 344 files, +4 724 / **-94 617** |
| #9 | `arena/5b54fce9-budlum` | 25 files, +1 362 / -94 |

A pull request whose branch has no merge base with `main` is not a change to
this tree, it is a competing tree. #8's diff is 344 files and 94 617 deleted
lines: that is not "the codec register and the dedup index", whatever its
title says. Merging it would replace the repository, and every other open pull
request would be rebased onto a tree it was not written against.

### Correction: #71 is not on the other root

The earlier version named #71 (`arena/ea7ae280-budlum`) as a third orphan and
reported "9 files, +72 / -1 345" for it. That is false on the fetched refs:

```
git merge-base main origin/arena/ea7ae280-budlum
cccf1da1f4bcfe97503a3a00cfba24b172b49b31
```

#71 is a descendant of `main`, its base is `arena/8f1fe85d-budlum` (itself a
descendant of `main`), and this integration branch fast-forwarded to its head
before any other merge. The claim in #71's own body and in #72's report is
stale. **It was not merged from a second history.** This is the kind of
incompatibility an integration audit has to catch: a text claim about the tree
is not evidence about the tree.

The directive's own analysis base, the `testnet-quantum` snapshot, and the
`consensus-of-consensuses` branch do live in that second history, so the
two-root problem is real even though #71 is not part of it.

**This is a concrete scope conflict (Section 0.3 item 2), and the report does
not decide it.** What a human must decide, once:

1. which root is the repository of record (`cccf1da1` or `5b629e15`), and
2. what happens to the two pull requests on the other root: rebase their
   change onto the chosen root, or close them with the decision written down.

Deciding it by merging both roots in one direction produces a 344-file
"feature" pull request and a history in which no commit means what its message
says.

## 3. The shared files

431 paths are changed by two or more open pull requests. The directive's rule
(Section 15.3 item 4) exempts ten append-only files from locking because a
conflict there is a text conflict with an obvious resolution. Those are
exactly the top of the list, which is the good news:

| Pull requests | Path | Kind |
|---|---|---|
| 26 | `docs/work/PACKAGES.md` | shared append-only |
| 21 | `THE_BUDLUM_DIREKTIF.md` | **not** on the exempt list |
| 20 | `xtask/gates/src/main.rs` | shared append-only |
| 19 | `.github/workflows/ci.yml` | shared append-only |
| 16 | `src/tests/mod.rs` | **not** on the exempt list |
| 15 | `src/rpc/server.rs` | **not** on the exempt list |
| 14 | `src/core/account.rs` | **not** on the exempt list |
| 14 | `src/execution/executor.rs` | **not** on the exempt list |
| 13 | `config/naming/concept_map.toml` | shared append-only |
| 13 | `src/chain/blockchain.rs` | **not** on the exempt list |
| 12 | `.github/concept-names-baseline.txt` | shared append-only |
| 12 | `src/crypto/domain_tags.rs` | shared append-only |

Two rows deserve a name rather than a count:

* **`THE_BUDLUM_DIREKTIF.md` is changed by 21 pull requests**, and most of them
  delete it (Section 0.1 item 5: the directive does not enter the repository).
  A file that many pull requests delete is a decision already taken,
  implemented many times; the first merge takes it. This integration branch
  has taken it and added the `.gitignore` anchor from PR #63.
* **`src/tests/mod.rs` is changed by 16**: every package that adds a test file
  adds its `mod` line, which is append-only in practice and should be treated
  as such even though the exempt list does not name it.

The rest of the 431 are lock collisions in the directive's sense: two packages
claiming one path. Since most of them are unmerged, they are still rebase work
rather than a lost change, but the order of merges decides who rebases.

## 4. One new file, several implementations

57 new files are added by two or more pull requests **with different content**.
This is the expensive class: only one copy can survive, and the surviving copy
is decided by merge order rather than by review.

The worst cases, with the size of each variant:

| File | Pull requests | Variants |
|---|---|---|
| `docs/work/PACKAGES.md` | 13, 14, 16, 20, 29, 30, 31, 35, 36, 41, 47, 48, 50, 51, 56, 57, 59, 63, 65, 68, 72, 73, 77, 79, 82, 83 | 26 state tables of one repository |
| `docs/audit/FINDINGS.md` | 13, 31, 35, 36, 41, 44, 48, 50, 68 | 9 ledger openings for one ledger |
| `src/chain/state_recovery/mod.rs` | 8, 9, 11, 60, 62, 66 | 6 module skeletons |
| `src/persistence/mod.rs` | 8, 9, 11, 60, 62, 66 | 6 module skeletons |
| `xtask/gates/src/gates/no_float_in_consensus_paths.rs` | 24, 29, 30, 31, 51 | 4 implementations: 646, 657, 311 (twice), 314 lines |
| `xtask/gates/src/gates/workflows_cover_every_workspace.rs` | 24, 29, 30, 31, 51 | 4 implementations: 520, 392, 266 (twice), 413 lines |
| `src/tests/persistence_move.rs` | 11, 60, 62, 66 | 4 test files |
| `src/storage/bud3/volume.rs` | 45, 55, 57 | 3 implementations |
| `src/mempool/lanes.rs` | 24, 36, 51 | 3 implementations |
| `src/execution/coordinator/gas.rs` | 24, 36, 51 | 3 implementations |
| `contracts/uel/BudlumUniversal.sol` | 24, 36 | 2 Solidity libraries |

The two gates are the clearest case. A gate is not a style preference: it is the
thing that stops a regression. Four different `no_float_in_consensus_paths`
implementations of 311 to 657 lines cannot all run, and the merge order decides
which one guards consensus code from floating point. The directive already has
the rule for this (Section 15.3 item 6, the definition-path rule): one owner per
definition path. Applying it here means picking one pull request as the owner
of each row above, and deleting the copy from the others in the same rebase.

### A second Ethereum gateway, on a different stack

`src/rpc/compat/ethereum/filters.rs` is one of the divergent additions. PR #24's
stack implements a full EVM gateway (`types.rs`, log parsing, subscriptions),
PR #76 hardens its filter ownership using `jsonrpsee::ConnectionId`, and PR #72
implements a refusal gateway whose filter methods were pending. This
integration branch merged PR #72 and delivered the bounded filter table on top
of it. The two trees are not interchangeable: PR #76's `filters.rs` imports
`super::types`, which does not exist in the PR #72 gateway, so merging that
branch here would not compile. **Choosing the Ethereum gateway of record is a
human decision (Section 0.3 item 2)**; this report does not take it. The
security finding from #76 was carried over: filter ownership is keyed by the
server-assigned connection id, with the socket address as a fail-closed
fallback.

A further 35 new files are added by two or more pull requests with **identical**
content. Those are cheap: either copy is the same bytes, and the rebase is
mechanical.

## 5. What was verified about `main` itself

Before blaming the queue, `main` was checked for the inconsistencies a reader
would find first. The earlier version reported 218 methods, 142 gate files,
241 required test names and 122 metrics written. Those were pre-integration
numbers from a different measurement. Replayed on the **integrated** tree of
this branch, the classes that can be decided textually are:

| Check | Result | How |
|---|---|---|
| every `#[method]` / `#[subscription]` in `src/rpc/api.rs` has exactly one row in `METHOD_CLASSES`, in declaration order | pass, 198 names | `integration_audit.py`, declaration-order replay |
| the Ethereum gateway table, `api.rs` and `METHOD_CLASSES` agree | pass, 37 gateway rows | `integration_audit.py`, pending and effect mapping |
| every gate file is registered and wired | pass, 143 files | file list against `pub mod` and `run: gates::*` lines |
| every test file is registered | pass, 98 files | `src/tests/*.rs` against `src/tests/mod.rs` |
| every `mod name;` resolves to a file | pass | `integration_audit.py` module-path replay |
| no `assert!(true)` stands in for a test | pass | static scan of source, comments stripped |
| the legacy-storage ratchet has no new or stale line | pass, 89 lines | `integration_audit.py` replay of the gate's rules |

The 241 required test names and 122 metric writes were **not** replayed here;
they are claims from the earlier report, not evidence from this branch. The
audit was not exhaustive: type errors, borrow errors and macro expansion need a
compiler, and this workspace has no `cargo`. Section 7 says so plainly.

## 6. Recommended order, from the dependency table

Section 15.7 gives the order the packages depend on each other; the queue should
follow it, one lock set at a time, with
`python3 ops/scripts/pr_coordination.py --prs-only` re-run after each merge:

1. **M0 first**: the live-verification packages (WP-01, WP-02, WP-03, WP-04).
   They add documents and tests, they claim no runtime path, and every later
   package cites their state. #8 and #9 must be decided before them (see
   Section 2). #71 is not part of that decision.
2. **The two-history decision.** Nothing else should merge while a competing
   root is still open: any merge before the decision can be undone by it.
3. **M1**: WP-05 (concept map and counter), WP-06 (persistence move), WP-07
   (legacy storage removal), WP-08 (validator classes), WP-09 (execution
   interface). WP-07 deletes code that WP-06 moves, so the order inside M1 is
   fixed by the directive and not by the queue.
4. **M2**: WP-10, WP-12, WP-15, WP-17, WP-26, WP-42, WP-61.
5. **Then M3 and M4** in the card order of Section 15.8, with the expansion-layer work
   packages (WP-49 and later) staying on their branches until the freeze lifts
   at M7 (Section 15.5 item 9).

One rule makes the rest safe: merge one pull request, rebase the others, re-run
the script, then merge the next. Two merges without a rebase turn a text
conflict into a silently duplicated implementation, which is the failure mode
Section 4 measures.

## 7. What this report does not claim

* **No semantic comparison.** Two implementations of one file are compared as
  bytes, not as behaviour. Two files with different bytes can mean the same
  thing, and two files that differ in one line can mean opposite things.
* **No green claim.** No CI job produced a verdict for these pull requests
  while this report was written. Nothing here says a branch passes its tests.
  CI was not consulted: the instruction for this work is to check CI only when
  a red result is found, and none was found.
* **No compiler run.** This workspace has no Rust toolchain. Every result in
  Section 5 is a static replay, not a build.
* **No decision.** Sections 2 and 4 name decisions a human must take. An agent
  that took them would be inventing a repository of record, which Section 0.3
  item 2 forbids it to do.

## 8. Which branches are already inside the integration stack

`python3 ops/scripts/integration_audit.py --branches` asks `git merge-base
--is-ancestor` for every `origin/arena/*` ref against `HEAD`. At the last
measurement there were 77 such refs: **12 are ancestors of this branch** and
65 are not. The twelve are the seven merged PR heads (#61, #63, #65, #67, #70,
#71, #72), their stacked bases, and this branch's own remote ref. All seven
merged heads are still ancestors, so none of them has moved since the merge.

This is a *branch ancestry* check, not a pull request status check: a PR can be
open with its head already merged into another branch, which is exactly the
situation here. No PR was closed to produce these numbers.

## 9. Corrections made after integration

| Earlier claim | Corrected fact | Evidence |
|---|---|---|
| 52 open pull requests | 63 at the last measurement | `gh pr list --state open --limit 100` |
| 84 remote branches measured, reported as "open PRs" | `--prs-only` measures PR heads only | `ops/scripts/pr_coordination.py` |
| 3 PRs with no common ancestor (#8, #9, #71) | 2 (#8, #9) | `git merge-base` and the corrected script |
| #71 has no common ancestor with `main` | `main` is its ancestor; this branch fast-forwarded to its head | merge base `cccf1da1` |
| 332 shared paths, 44 divergent files, 18 identical | 431, 57, 35 on the PR-only measurement | `--prs-only` output |
| 218 RPC methods, 142 gate files on the base | 198 methods, 143 gate files on the integrated tree | `integration_audit.py` |
| `arena_claude.py` is an English-neutral helper | it carries 38 Turkish lines and is not in `tree_is_english`'s baseline | static scan; removed from this tree |
| #68 is safe to merge as-is | its audit tests contain `assert!(true)` and Turkish package ids, and it replaces a 456-line gate with 78 lines | PR #68 audit; not merged here |

The last row is the reason PR #68 was **not** merged into this integration
stack. Its work belongs on its own branch (`origin/arena/e40cf955-budlum`) and
must be rewritten there before it can join the queue.
