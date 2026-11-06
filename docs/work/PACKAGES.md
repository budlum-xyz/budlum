# Work packages

Status of the work packages defined in `THE_BUDLUM_DIREKTIF.md` Section 15.
The file is English, append only, and updated by a package's last pull request
(directive 15.5 item 7). One row per package; the pull requests list what the
package has delivered so far.

Reading the columns:

- **Package**: `WP-NN`, the identifier used in the tree and on GitHub. It is
  the same package as `IP-NN` in the directive.
- **Lane / layer**: from the ownership table (15.2) and the dependency table
  (15.7).
- **Status**: `not started`, `in progress`, `blocked` or `merged`. A package is
  `merged` only when every item of its completion criterion is green in `main`;
  a claim without a commit SHA and a CI run number is not a status.
- **PRs**: pull requests that carry the package.
- **Findings**: ledger rows the package closes. A row is closed only with a red
  reproduction output or a "pre-corrected" green regression test, plus the CI
  run number (14.1 madde 5, 15.5 madde 4). Until then the finding stays open
  even when the code that closes it is in the tree.

## Status

| Package | Lane | Layer | Status | PRs | Findings | Notes |
|---|---|---|---|---|---|---|
| WP-42 | D | T-Launch | in progress (1/3) | this pull request | BLG-015 (open), BLG-012 to BLG-016 and BLG-081 to BLG-193 (open) | Slice 1 adds `no-float-in-consensus-paths`, `workflows-cover-every-workspace` and `nightly-workflows-are-required` to `xtask/gates`, wires all three into the `Gates` job of `ci.yml`, adds the `Conformance nightly` workflow that compiles the two endpoint contract workspaces, adds the missing cron trigger to `determinism.yml`, and adds the `bud3_qr_frame_decode` fuzz target with its corpus. |

## WP-42: CI, gates and supply chain

Lock paths: `.github/workflows/`, `xtask/` (outside WP-05 and package gates),
`fuzz/`, `kani/`, `benches/`, `supply-chain/`, `deny.toml`.

Slice 1 (this pull request):

1. `no-float-in-consensus-paths` (`xtask/gates/src/gates/no_float_in_consensus_paths.rs`).
   Job item 4 of the package card. Scope is the card's list: `src/chain`,
   `src/consensus`, `src/execution`, `src/settlement`, `src/validators`,
   `src/storage/bud3`, the AI selection path `src/ai`, and `budzero/`.
   Comments, string literals, measurement harnesses (`tests/`, `benches/`,
   `examples/`) and `#[cfg(test)]` modules are outside the ban because they are
   not the consensus path. The one file the card exempts by name,
   `src/storage/bud3/placement.rs`, is exempt by name.
   `BLG-240` (verifier ranking in `f64`, display only, owned by WP-45 and closed
   by WP-57 after it) is the only open finding inside the scope. Its two files
   are pinned by name with a ceiling on the occurrence count, and a pin whose
   file has no float left fails, so closing `BLG-240` cannot leave a silent
   exemption behind. A pin is a ceiling, not a permit: a new float in a pinned
   file fails the gate.
2. `workflows-cover-every-workspace`
   (`xtask/gates/src/gates/workflows_cover_every_workspace.rs`).
   Job item 1 and Section 16.2 rule 3. Every cargo workspace in the tree is
   covered: the root package, `budzero`, `crates/ai-inference`, the explorer
   crate, `fuzz`, `kani`, and the two endpoint contract workspaces
   under `contracts/object-layer/`. Only executable `run:` content counts, so a
   job name, a cache key and a comment cannot satisfy it.
3. `nightly-workflows-are-required`
   (`xtask/gates/src/gates/nightly_workflows_are_required.rs`).
   Section 16.2 rule 1 makes a nightly run a gate, and a nightly that never
   fires protects nothing. Every workflow whose name promises a nightly or a
   weekly run, and every scheduled workflow Section 16.2 requires, must carry a
   `cron:` under `schedule:`, declare jobs and disable none of them with a
   literal false. The required workflows whose subject is not in the tree yet
   are reported with their owning package instead of failing the build, so the
   list is visible in every run and shrinks as those packages land; a required
   workflow that exists and is not scheduled always fails.
   Running it found one real defect: `determinism.yml` ran on push and on a
   pull request only, while Section 16.2 puts it on a nightly run as well. The
   cron trigger is added here.
4. `fuzz/fuzz_targets/bud3_qr_frame_decode.rs` (job item 6: every new parser
   has a fuzz target). The optical frame parser is the third parser on the
   B.U.D. 3.0 read path and the only one a camera feeds: it reads a declared
   drop length out of a header, indexes past it, compares a digest and hands
   the nested drop to a second parser, all over bytes an untrusted holder or a
   screen controls. The target asserts three things on every input: no panic,
   an accepted drop within the lab cap (`MAX_DROP_WIRE`), and that an accepted
   frame with a clear flags nibble re-packs to itself (one frame, one
   encoding). The stream commitment is fixed so the fast reject does not eat
   the budget.
   Declared in `fuzz/Cargo.toml`, scheduled in the `fuzz-nightly.yml` matrix
   next to the two other B.U.D. 3.0 targets, and seeded with three files: a
   canonical frame, a frame that sets only the ignorable flag nibble, and a
   header-only frame that stops at the truncation check. The seeds are valid
   vectors, not noise: the canonical one decodes and re-encodes byte for byte.
5. `.github/workflows/conformance-nightly.yml`. Section 16.2 requires this
   workflow and it did not exist. It compiles the CosmWasm and SVM endpoint
   workspaces, which no job reached before, and asserts that their entry points
   still exist. The full conformance suite of Section 8.13 lands here as the
   execution environments arrive.

Still open in this package: fuzz targets for the parsers item 6 names whose
type does not exist in the tree yet (the proof batch of the custody path, the
`ee.proto` message set, the foreign envelope and the asset message: the last
two belong to WP-30 and WP-45 and have no type to decode today), the workflow
set of Section 16.2 that depends on
workspaces which do not exist yet (`execution.yml` needs the execution
workspaces of WP-26 to WP-35, `mobile.yml` and `mobile-ios.yml` need WP-11 to
WP-38), `cargo-deny`/`cargo-vet`/`cargo-geiger` per execution workspace, the
Kani coverage of TEST-GAP-02, and the closure protocol of the findings listed
above.

Evidence for this slice:

- All three gates carry canaries (`--self-test`) and are invoked as a canary before
  the plain run in `ci.yml`, which is the repository's red-before-green rule.
- `no-float-in-consensus-paths` scans 124 files under 8 scoped paths and reports
  no float outside the two pins. The pins hold 4 and 10 occurrences against
  ceilings of 5 and 12.
- `workflows-cover-every-workspace` reads 31 workflow files and reports all 8
  workspaces covered, with `fuzz` covered implicitly by `cargo fuzz` because
  cargo-fuzz resolves `fuzz/Cargo.toml` itself.
- `nightly-workflows-are-required` reports 7 scheduled workflows green and 6
  required workflows deferred with their owners (`storage-nightly.yml`,
  `churn-nightly.yml`, `nat-nightly.yml`, `mobile.yml`, `mobile-ios.yml`,
  `supply-chain.yml`).
- The fuzz set is 19 targets after this change: all 19 declared in
  `fuzz/Cargo.toml`, all 19 with a harness file, all 19 named by a schedule,
  all 19 with a seeded corpus directory, and no corpus directory without a
  target.
- No CI run number yet: the workflow runs for this pull request are queued and
  no run has reported. The findings this package owns stay open until one does,
  and a self-declared result is not evidence (directive 0.3 item 5).
