# Live PR-stack integration audit (2026-11-06)

| Field | Value |
|---|---|
| Scope | `main` at `cccf1da1f4bcfe97503a3a00cfba24b172b49b31`, all 70 open pull requests, the closed/merged history, and the live CI state |
| Method | `gh pr list`, `gh pr view`, `gh run list`, `gh run view`, `gh api` job annotations and log text, `git diff`, `git merge-base`, tree-sitter Rust grammar 0.26 over every changed `.rs` file |
| Purpose | find the work packages that the recent commits and the live open PRs did not do, find incompatible or broken code, and name which other PR's incomplete work this branch continues |
| Constraint | this session's branch is fixed to `arena/0238388a-budlum`. No other branch was pushed, merged, closed or retargeted. Carrying another PR's work means applying its diff here, on this branch. |

## 1. The live picture (snapshot, counts drift)

- 70 open pull requests, 100 remote branches. `main` holds one squashed commit
  (`Add files via upload`). The earlier merged PRs (#5, #6) are folded into it;
  the closed-unmerged PRs are mostly WP-00 stop reports.
- Every T-Launch package WP-01..WP-48 and WP-61 is claimed by at least one open
  PR. No T-Expansion package except WP-55 (#86) and slices of WP-56/WP-57 is
  claimed. WP-49, WP-50, WP-51, WP-52, WP-53, WP-54, WP-58, WP-59, WP-60,
  WP-62, WP-63 and WP-64 have no owner (BLG-294).
- `docs/work/PACKAGES.md` is created by 25 open PRs and
  `docs/audit/FINDINGS.md` by 11 (BLG-289, BLG-290). This pull request appoints
  one integrator for both.
- PR #86's integration probe merged 14 of 68 open PRs cleanly, 54 conflicted;
  the conflict magnets are the shared ledgers, `.github/workflows/ci.yml`,
  `xtask/gates`, `src/tests/mod.rs`, `src/chain/blockchain.rs`,
  `src/execution/executor.rs` and `src/rpc/server.rs` (BLG-291, BLG-311).

## 2. Why `main` is red, with the actual log text

CI run `42050659038` on `cccf1da` fails seven jobs. The annotations alone say
"exit 101"; the job logs were read through the API log host, and the causes are
these, not guesses:

| Job | Cause | Evidence |
|---|---|---|
| `Budlum Core PQ build`, `Budlum Core library test`, `Budlum Core quality` (Clippy), `Network Hardening` | one denied lint: `manual_div_ceil` at `src/storage/bud3/dedup_index.rs:83`, `let words = ((bits + 63) / 64) as usize;` | "could not compile `budlum-core` (lib) due to 1 previous error", run 42050659038 |
| `Budlum Core quality` (Format) | three rustfmt hunks: `crates/bud-codec/src/lib.rs:304`, `src/storage/bud3/bof1.rs:278`, `src/tests/bud3_door.rs:242` | exact diff hunks in the Format step log |
| `Gates` | four red gates: `no-out-of-block-consensus-writes` (`required_fee`), `indexing-is-not-new` (2 files), `dead-public-api-is-ratcheted` (182 vs 173), `guards-are-reachable` (5 vs 3); `badges-are-current` is a cascade | Tally step, "gate tally: 4 red gate(s)" |
| `Cargo Deny (root)`, `Cargo Deny (fuzz)` | failing step, no downloadable annotation body | step conclusion only |
| Other workflows | `Security Audit`, `Determinism`, `Watchdog`, `OSV Scanner`, `Semgrep`, `Extra Tooling`, `Audit Guard`, `Semver Check`, `Cargo Vet`, `Diverse Double Compiling` fail on `main` | `gh run list --branch main` |

Consequence: no PR in the stack can currently show red-to-green for its own
feature, because the base is red (BLG-293, BLG-312). Fixing the tree-attributable
causes first is the only order that produces attributable evidence.

## 3. What the open PRs left undone (the work this branch starts)

| WP | Open delivery | Owed |
|---|---|---|
| WP-28 | #72 (1/2), #76 (filter owner) | subscriptions; the 2/2 slice has no owner |
| WP-31 | #83 (1/N), #51 | subscriptions and the SVM-state reads; 2/N has no owner |
| WP-32 | #89 (1/N) | the Move worker, pinned framework, BCS, `Foreign::Aptos`, 0xBD alias, SDK conformance; the body names all of them as pending |
| WP-35 | #79 (1/3) | 2/3 and 3/3: measured gas calibration and the five nightly conformance suites |
| WP-24 | #65 (1/3) | 2/3 and 3/3: access tiering and codec acceptance |
| WP-11 | #82, #85, #88, #91 (2/N) | jobs 2-9: signed releases, durable share ids, authenticated placement roots, node transport |
| WP-12 | #81 (1/N) | HCLE shadow mode, the 10,000-block measurement, `WIRING:` marker removal |
| WP-07 | #69 (1/N), #71 (2/N), #75 (3/N, WIP) | finish legacy-storage removal on the integrated stacks |
| WP-40 | #73 (1/N) | explorer pages and indexer events |
| WP-43 | #51, #56, #87 (1/N) | README numbers from CI output, TLG report |
| WP-55 | #86 (1/N) | broadcast driver, gateway door, activation height, measurements |
| WP-42 | #29/#30/#31/#42/#63/#74/#84 (slices) | `main` itself green; the two gate debts named in BLG-309 |
| WP-49..WP-64 | only WP-55, and slices of WP-56/WP-57 | eleven unowned T-Expansion packages |

## 4. Compatibility audit of the open stack

1. **Syntax.** Every changed `.rs` file of every open PR branch was parsed with
   the tree-sitter Rust grammar. 68 of 70 branches parse with zero `ERROR` or
   `MISSING` nodes. Two do not (BLG-298):

   | PR | Files with syntax errors |
   |---|---|
   | #9 (`arena/5b54fce9-budlum`) | `crates/bud-codec/src/container.rs`, `src/tests/integration.rs` |
   | #8 (`arena/b7784c85-budlum`) | `src/chain/blockchain.rs`, `src/persistence/db.rs`, `src/persistence/traits.rs`, `src/rpc/tests.rs`, `src/storage/bud3/content_ref.rs`, `src/tests/priority_findings.rs`, `src/tests/regression_ai_storage.rs`, `src/tests/regression_chain.rs` |

   The visible mangling matches PR #86's hand inspection: lone `f` and `a`
   lines (`src/tests/priority_findings.rs:130`, `src/rpc/tests.rs:445`), a
   deleted method name in `src/persistence/db.rs:2092`, `seat_table_version: 0,`
   inserted mid-expression in `src/tests/integration.rs:507` and `:758`, and
   `Bud3NotReady,` orphaned outside its enum in
   `src/storage/bud3/content_ref.rs:239`. PR #81 re-roots #9's work correctly;
   PR #8 has no successor. Neither PR is closed or edited here. A syntax parse
   is not a type-check: `cargo check` cannot run in this workspace.
2. **Duplicate work.** #77 and #80 carry the same `#38 -> #54 -> #64` ABI
   checkpoint under different SHAs (BLG-292). Four PRs (#42, #63, #77, #78)
   and two more (#86, #87) remove the same directive file. BLG-298..BLG-301 are
   allocated twice (BLG-313).
3. **Cross-PR API drift.** PR #91 reports two different presence-message
   digests for the same window across #45 and #70 (BLG-301), and PR #70's
   `presence.rs` does not type-check (BLG-302). PR #88 records unauthenticated
   placement roots and process-local share ids as open integration blockers.
   These are reasons not to squash the stack into one tree before an owner
   reconciles the wire shapes.
4. **Gate debt.** PR #79's `docs/audit/GATE_DEBT_2026-11-06.md` names ten dead
   public functions and two unwired guards; no open PR wires them (BLG-309).
   The same PR fixes the two runtime indexes but not the `manual_div_ceil` lint,
   so its branch would still be red on Clippy.

## 5. What this branch carries over, and from which PR

Carrying a fix means applying the other PR's diff to this branch, then
continuing it here. No other branch is touched.

| Source | Carried | Continuation here |
|---|---|---|
| #42, #63, #74 | `required_fee` as a state read; the directive-out-of-tree regression test | the narrow #74 version, with its "no widening" test, is used rather than the three overlapping copies |
| #79 | the two `indexing-is-not-new` rewrites and the three rustfmt hunks | the one missing root cause (the clippy lint) is fixed here, so the whole quality job can go green |
| #86 | WP-55, 1/N live stream core and the stack audit | WP-55, 2/N: broadcast driver, gateway door and activation height |
| #89 | WP-32, 1/N Aptos REST route table | WP-32, 2/N: the Move execution refusal surface and the named pending list |
| #83 | WP-31, 1/N Solana namespace | WP-31, 2/N: subscription methods and their refusal semantics |
| #81, #88, #91 | the committee seat table and the mobile core slices | recorded in the register as partial; their wire shapes are not merged here (section 4.3) |

## 6. Decisions and evidence boundary

- `main` is fixed first, in the smallest commits that each name one red gate or
  one lint. Baselines are never raised; the directive forbids softening (0.3.1).
- Work packages are delivered as slices (commits) on this single fixed branch.
  Directive 15.5.2 asks for one PR per slice; the fixed session branch cannot
  host several open PRs, so the slice boundary is the commit boundary and the
  PR body carries the slice table. This deviation is recorded rather than hidden.
- No Rust toolchain, crate registry, `rustfmt`, `clippy` or `cargo` exists in
  this workspace. No test was executed locally. New Rust is syntax-checked with
  tree-sitter; the CI run on this branch is the compiler and test verifier.
- No green CI, completed package or closed finding that needs a run number is
  claimed here. The live base is red; an attributable green run is owed after
  the tree fixes land.
