# Open pull request coordination report

| Field | Value |
|---|---|
| Date | 2026-11-06 |
| Scope | the 52 open pull requests against `main` at `cccf1da1` |
| Measured by | `python3 ops/scripts/pr_coordination.py` (committed with this report) |
| Baseline | `main` = `cccf1da1` ("Add files via upload") |
| Kind | measurement, not a decision. Where a decision is needed, this file names it and does not take it (Section 0.3 item 2). |

## 1. What the numbers say

| Measure | Value |
|---|---|
| open pull requests | 52 |
| pull requests whose branch has **no common ancestor** with `main` | 3 (#8, #9, #71) |
| paths changed by two or more open pull requests | 332 |
| new files implemented **twice or more with different content** | 44 |
| new files added by two or more pull requests with identical content | 18 |

Every one of those 52 pull requests is written as if it were alone. The
directive's queue model (Section 15.1) has four agents and one owner per lock
path (Section 15.3); the queue it is actually being asked to describe has
fifty-two.

## 2. Two histories in one repository

`main` is rooted at `cccf1da1` ("Add files via upload"). Three open pull
requests are rooted at a different commit, `5b629e15` ("Universal Settlement
Layer"), which shares no ancestor with `main`:

| Pull request | Branch | GitHub's own diff |
|---|---|---|
| #8 | `arena/b7784c85-budlum` | 344 files, +4 724 / **-94 617** |
| #9 | `arena/5b54fce9-budlum` | 25 files, +1 362 / -94 |
| #71 | `arena/ea7ae280-budlum` | 9 files, +72 / **-1 345** |

A pull request whose branch has no merge base with `main` is not a change to
this tree, it is a competing tree. #8's diff is 344 files and 94 617 deleted
lines: that is not "the codec register and the dedup index", whatever its
title says. Merging it would replace the repository, and every other open pull
request would be rebased onto a tree it was not written against.

The directive's own analysis base, the `testnet-quantum` snapshot, and the
`consensus-of-consensuses` branch also live in that second history, so this is
not an accident of one branch: there are two candidate repositories of record.

**This is a concrete scope conflict (Section 0.3 item 2), and the report does
not decide it.** What a human must decide, once:

1. which root is the repository of record (`cccf1da1` or `5b629e15`), and
2. what happens to the three pull requests on the other root: rebase their
   change onto the chosen root, or close them with the decision written down.

Deciding it by merging both roots in one direction produces a 344-file
"feature" pull request and a history in which no commit means what its message
says.

## 3. The shared files

332 paths are changed by two or more open pull requests. The directive's rule
(Section 15.3 item 4) exempts nine append-only files from locking because a
conflict there is a text conflict with an obvious resolution. Those are
exactly the top of the list, which is the good news:

| Pull requests | Path | Kind |
|---|---|---|
| 21 | `docs/work/PACKAGES.md` | shared append-only |
| 16 | `xtask/gates/src/main.rs` | shared append-only |
| 16 | `THE_BUDLUM_DIREKTIF.md` | **not** on the exempt list |
| 14 | `src/tests/mod.rs` | **not** on the exempt list |
| 13 | `.github/workflows/ci.yml` | shared append-only |
| 12 | `src/core/account.rs` | **not** on the exempt list |
| 12 | `src/execution/executor.rs` | **not** on the exempt list |
| 12 | `config/naming/concept_map.toml` | shared append-only |
| 11 | `src/rpc/server.rs` | **not** on the exempt list |
| 11 | `src/chain/blockchain.rs` | **not** on the exempt list |
| 10 | `.github/concept-names-baseline.txt` | shared append-only |
| 9 | `src/crypto/domain_tags.rs` | shared append-only |

Two rows deserve a name rather than a count:

* **`THE_BUDLUM_DIREKTIF.md` is changed by 16 pull requests**, and most of them
  delete it (Section 0.1 item 5: the directive does not enter the repository).
  A file that fifteen pull requests delete and one edits is a decision already
  taken, implemented sixteen times; the first merge takes it.
* **`src/tests/mod.rs` is changed by 14**: every package that adds a test file
  adds its `mod` line, which is append-only in practice and should be treated
  as such even though the exempt list does not name it.

The rest of the 332 are lock collisions in the directive's sense: two packages
claiming one path. Since nothing is merged, they are still rebase work rather
than a lost change, but the order of merges decides who rebases.

## 4. One new file, several implementations

44 new files are added by two or more pull requests **with different content**.
This is the expensive class: only one copy can survive, and the surviving copy
is decided by merge order rather than by review.

The worst cases, with the size of each variant:

| File | Pull requests | Variants |
|---|---|---|
| `docs/work/PACKAGES.md` | 13, 14, 16, 20, 29, 30, 31, 35, 36, 41, 47, 48, 50, 51, 56, 57, 59, 63, 65, 68, 72 | 21 state tables of one repository |
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

A further 18 new files are added by two or more pull requests with **identical**
content. Those are cheap: either copy is the same bytes, and the rebase is
mechanical.

## 5. What was verified about `main` itself

Before blaming the queue, `main` was checked for the inconsistencies a reader
would find first. All four checks pass, so the open pull requests are building
on a consistent base:

| Check | Result | How |
|---|---|---|
| every `#[method]` in `src/rpc/api.rs` has exactly one row in `METHOD_CLASSES`, in declaration order | pass, 218 methods | the gate's own scan, replayed |
| the listener column matches the `require_operator` calls in `src/rpc/server.rs` | pass | the gate's own scan, replayed |
| every gate file is registered in `xtask/gates/src/main.rs` | pass, 142 files, 142 registrations | file list against `pub mod` lines |
| every test name the named-test gates require exists | pass, 241 names across 14 gates | name lists against `fn` declarations |
| every declared Prometheus metric is written in production code | pass, 122 metrics | `src/core/metrics.rs` fields against mutator calls |

The audit was not exhaustive: it covers the classes that can be decided
textually (tables, gates, required names, metrics). Type errors and borrow
errors need a compiler, and no compiler ran for this report.

## 6. Recommended order, from the dependency table

Section 15.7 gives the order the packages depend on each other; the queue should
follow it, one lock set at a time, with
`python3 ops/scripts/pr_coordination.py` re-run after each merge:

1. **M0 first**: the live-verification packages (WP-01, WP-02, WP-03, WP-04).
   They add documents and tests, they claim no runtime path, and every later
   package cites their state. #8, #9 and #71 must be decided before them (see
   Section 2).
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
  thing, and two files that differ in one line can mean opposite things. The
  line counts in Section 4 are a proxy for "not the same implementation", not
  a proof of it.
* **No green claim.** No CI job produced a verdict for any of the 52 pull
  requests while this report was written; every run was queued and none
  started. Nothing here says a branch passes its tests.
* **No decision.** Sections 2 and 4 name decisions a human must take. An agent
  that took them would be inventing a repository of record, which Section 0.3
  item 2 forbids it to do.
