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
| WP-42 | D | T-Launch | in progress (1/3) | this pull request | BLG-015 (open), BLG-012 to BLG-016 and BLG-081 to BLG-193 (open) | Slice 1 adds `no-float-in-consensus-paths` and `workflows-cover-every-workspace` to `xtask/gates`, wires both into the `Gates` job of `ci.yml`, and adds the `Conformance nightly` workflow that compiles the two endpoint contract workspaces. |

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
3. `.github/workflows/conformance-nightly.yml`. Section 16.2 requires this
   workflow and it did not exist. It compiles the CosmWasm and SVM endpoint
   workspaces, which no job reached before, and asserts that their entry points
   still exist. The full conformance suite of Section 8.13 lands here as the
   execution environments arrive.

Still open in this package: the workflow set of Section 16.2 that depends on
workspaces which do not exist yet (`execution.yml` needs the execution
workspaces of WP-26 to WP-35, `mobile.yml` and `mobile-ios.yml` need WP-11),
`cargo-deny`/`cargo-vet`/`cargo-geiger` per execution workspace, the Kani
coverage of TEST-GAP-02, the fuzz targets of item 6, and the closure protocol
of the findings listed above.

Evidence for slice 1:

- Both gates carry canaries (`--self-test`) and are invoked as a canary before
  the plain run in `ci.yml`, which is the repository's red-before-green rule.
- `no-float-in-consensus-paths` scans 124 files under 8 scoped paths and reports
  no float outside the two pins. The pins hold 4 and 10 occurrences against
  ceilings of 5 and 12.
- `workflows-cover-every-workspace` reads 31 workflow files and reports all 8
  workspaces covered, with `fuzz` covered implicitly by `cargo fuzz` because
  cargo-fuzz resolves `fuzz/Cargo.toml` itself.
- No CI run number yet: this pull request has not run. The findings this package
  owns stay open until it does, and a self-declared result is not evidence
  (directive 0.3 item 5).
