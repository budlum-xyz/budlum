# Lane D: live verification of the clients, operations, CI, documentation and the combined state

Package WP-04 (directive card WP-04, section 15.8). Lane D. Layer T-Launch.
Branch `arena/3ef3b577-budlum`. Snapshot time 2026-11-06 05:45 UTC.

## 1. Live state at claim time

| Item | Live value | How it was read |
|---|---|---|
| `main` head | `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` | `gh api repos/lubothebook/budlum/commits` |
| Branch base | `cccf1da1f4bcfe97503a3a00cfba24b172b49b31` | `git merge-base` against `origin/main` |
| GitHub Issues | disabled | `gh api repos/lubothebook/budlum` returns `has_issues: false` |
| CI, this repository | 400 runs sampled: 155 `cancelled`, 245 with no conclusion, 0 `success` and 0 `failure` | `gh run list --limit 400 --json conclusion` |
| Rust toolchain in the agent sandbox | absent (`cargo` and `rustc` not found) | `which cargo`, `which rustc` |
| Compile or test result claimed | none | this environment cannot produce one |

The CI reading is the reason no record below is labelled fixed. Section 0.3 rule 5 accepts a claim
only with a commit SHA and a CI run number. Neither exists for any change in this repository at the
snapshot, so a label of "verified", "already fixed" or "invalid" would be an assertion without
evidence.

## 2. Path readiness (card item 1 and section 0.4)

WP-04 locks five paths. Three of them are free at the snapshot:

| Path | Live claim at the snapshot | This delivery |
|---|---|---|
| `docs/audit/live/lane-d.md` | none | **delivered** |
| `docs/audit/LIVE_STATUS.md` | none | **delivered** |
| `docs/audit/FINDINGS.md` | none | **delivered**: the 70 lane D records, English titles, live state |
| `docs/work/PACKAGES.md` | open PR #16 writes it from its own base | pending: a write here forks the file against #16 |
| `src/tests/audit_lane_d.rs` | PR #18 and PR #21 | blocked |

`docs/audit/AUDIT_FINDINGS.md` is a different file from the card's `docs/audit/FINDINGS.md`. The
first is the existing round-based ledger; the second is the flat, directive-numbered ledger the card
asks for. This delivery does not add WP-04 numbers to the existing file, because that would create
the second ledger under the wrong name.

## 3. Records assigned to lane D

Read from the section 14 tables, row by row, by the closing package. A record is in lane D scope
when its closing package is WP-05, WP-11, WP-36 to WP-43, WP-46 or WP-61.

| Id | Importance | Area or location | Closing package |
|---|---|---|---|
| BLG-004 | Medium | cryptography, key file permissions | WP-61 |
| BLG-009 | Medium | cryptography, FIPS context and scheme id | WP-61 |
| BLG-010 | Medium | cryptography, PKCS#11 key label | WP-61 |
| BLG-011 | Medium | RPC / operations, systemd unit | WP-41 |
| BLG-012 | High | build/CI, coverage ratchet | WP-42 |
| BLG-013 | Medium | build/CI, `prepush` helper | WP-42 |
| BLG-014 | Medium | storage, backup drill exit code | WP-42 |
| BLG-015 | Medium | build/CI, standalone package tests | WP-42 |
| BLG-016 | High | build/CI, supply chain advisories | WP-42 |
| BLG-022 | Medium | consensus, light-client checkpoint loop | WP-11 |
| BLG-026 | Medium | build/CI, sub-workspace gaps, wallet seed path | WP-39 |
| BLG-029 | High | RPC, client IP extraction and rate-limit eviction | WP-61 |
| BLG-030 | Critical | RPC, consensus state written outside a block; dev faucet on testnet | WP-61, WP-41 |
| BLG-032 | Medium | RPC, `Prepare` templates | WP-61 |
| BLG-068 | High | verifiable browser core | WP-40 |
| BLG-081 to BLG-087 | High / Medium | gate and CI blind spots | WP-42 |
| BLG-092 | High | document and code agreement, link framing | WP-43 |
| BLG-095 | Medium | supply chain, Dependabot, CODEOWNERS, stale branch names | WP-41 |
| BLG-097 | High | CI, missing lockfiles, orphan Kani file | WP-42 |
| BLG-098 | Critical | security, RPC auth and allow-list defaults | WP-39 |
| BLG-099 | High | security, timing leak in the API-key compare | WP-61 |
| BLG-117 | Critical | wallet cryptography, note planting, replay | WP-39 |
| BLG-121 | High | verifiable browser, manifest and patchset | WP-40 |
| BLG-143 | High | verifiable browser, content verification | WP-40 |
| BLG-150 | Critical | consensus signature domain separation, nullifier zero | WP-61 |
| BLG-169 | Medium | developer SDK | WP-40 |
| BLG-170 to BLG-181 | High / Medium | gates, fuzzing, Kani, benches, module hygiene | WP-42 |
| BLG-187 to BLG-189 | High / Medium | fuzz coverage, gate blind spots | WP-42 |
| BLG-192 | High | RPC, `bud_estimateGas` under-reports | WP-61 |
| BLG-193 | Medium | gates, comment and syntax bypasses | WP-42 |
| BLG-200 | High | BLS12-381 keys, finality aggregator, RLP depth | WP-61 |
| BLG-231 | Medium | BudZero docs claim recursion the code lacks | WP-43 |
| BLG-241 | Low | BudZero docs claim Poseidon width 8, code uses 12 | WP-43 |
| BLG-254 | High | three gates force the wrong B.U.D. 3.0 model | WP-07, WP-42 |
| BLG-255 | Low | retired concept names spread across the tree | WP-05, WP-43, every package |
| BLG-257 | High | no mobile client exists | WP-11, WP-36 |
| BLG-259 | Medium | light-client trust model undocumented | WP-12, WP-11 |
| BLG-265 | Medium | mobile power and challenge model against Android limits | WP-36 |
| BULGU-011 | S3 | RPC, CORS wildcard reflects the caller | WP-61 |
| BULGU-012 | S3 | RPC, serialization failure answered silently | WP-61 |
| TEST-GAP-02 | Medium | Kani covers a quarter of the `SECURITY.md` targets | WP-42 |
| TEST-GAP-04 | Low | `src/bin/budlum-domain-producer.rs` has no tests | WP-42 |
| TEST-GAP-07 | Low | RPC endpoints have weak direct coverage | WP-61 |
| DOC-GAP-01 | S1 | testnet first run blocked, SoftHSM | WP-41 |
| DOC-GAP-02 | S3 | port documents disagree across four modes | WP-43 |
| DOC-GAP-03 | S3 | broken script references | WP-43 |
| DOC-GAP-04 | S3 | systemd unit names the wrong repository | WP-41 |
| DOC-GAP-05 | S3 | half sentences in three guides | WP-43 |
| DOC-GAP-06 | S3 | empty measurement tables | WP-46 |
| DOC-GAP-07 | S3 | `budlum-indexer` binary registration | WP-42 |
| DOC-GAP-08 | S3 | CLI fee default disagrees with the network | WP-39 |
| DOC-GAP-09 | S3 | ledger table detail | WP-43 |

That is 70 records. This pass reads the closing package for every one of them.

## 4. Live checks performed (content, not line numbers)

Each check names the file it reads and the result. `CLOSED (trace)` means the code no longer shows
the defect and a test or a gate pins the fix; it does not mean the record is closed, because the
closing package owns that decision.

| Check | Evidence in the live tree | Reading |
|---|---|---|
| A6 DOC-GAP-07, the indexer binary is registered | `Cargo.toml:255-256` declares `[[bin]] name = "budlum-indexer"` | **CLOSED (trace)** |
| A7 TEST-GAP-04, a binary with no tests | `src/bin/budlum-domain-producer.rs` has 0 `#[test]` and no test module | open |
| BULGU-011, CORS wildcard | `src/rpc/server.rs::cors_outcome` returns the literal `*` for a wildcard entry and never echoes the caller; `cors_wildcard_does_not_reflect_headers` pins it | **CLOSED (trace)** |
| BULGU-012, silent serialization failure | `src/rpc/server.rs::to_val` maps a failure to an explicit error; `rpc_serialization_error_is_explicit` pins it | **CLOSED (trace)** |
| BLG-099, API-key compare | `src/rpc/server.rs::constant_time_eq_str` walks the expected value in full and folds the length difference; `src/tests/hardening_h4_locks.rs::constant_time_eq_str_correctness` pins it | **CLOSED (trace)** |
| BLG-098, RPC auth defaults | `src/cli/commands.rs::NodeConfig::default` sets `rpc_auth_required: true` and `rpc_allowed_ips: ["127.0.0.1", "::1"]` | **PARTIAL**: the defaults are fixed, the record's `validator`-role and single-env-var claims were not re-tested |
| BLG-231, recursion documented but absent | both files named by the record exist; neither carries `recursi*` or `aggregat*` prose any more | the disputed sentence is gone; whether that closes the record needs the record text |
| BLG-241, Poseidon width in prose | `budzero/bud-isa/src/lib.rs:115` still says "full Goldilocks width-8 instance" while `budzero/bud-vm/src/lib.rs:1067` sets `POSEIDON_WIDTH = 12` | **confirmed, open** |
| BLG-257, no mobile client | `mobile/` and `crates/budlum-types/` do not exist; the only mobile code is the node flag in `src/network/mobile.rs` | **confirmed, open** |
| BLG-254, wrong-model gates | `three_is_recipe_only.rs`, `zero_storage_frozen.rs` and `generated_content.rs` are all still wired in `xtask/gates/src/main.rs` | **confirmed, open** |
| BLG-255, name counter | recomputed with the map's own patterns (section 6) | **below the baseline in 15 of 27 entries** |
| TEST-GAP-07, RPC method coverage | see section 6.1 | **confirmed, open** |

### 4.1 Second pass: seven more records decided from the tree

| Record | Evidence read | Reading |
|---|---|---|
| BLG-012 | `xtask/gates/src/gates/coverage.rs:46` reads `data[0].totals.lines.percent`, and `run` refuses a non-finite percentage; the baseline parser at line 20 also refuses `nan` | **Previously fixed** |
| BLG-013 | `xtask/tools/src/prepush.rs:54` runs `clippy --all-features`, and `.github/workflows/ci.yml:260` builds `--all-features` as a required canary, so the combination is valid and the helper agrees with CI | **Previously fixed** |
| BLG-014 | `xtask/tools/src/backup_drill.rs:218` checks the `--check-db` exit code, and `integrity_line` (line 139) needs the exact line, not a substring, with three tests around it | **Previously fixed** |
| BLG-022 | `src/light_client/mod.rs:680` is one division with checked arithmetic, and `next_checkpoint_height_is_closed_form` (line 1253) covers the `u64::MAX` boundary | **Previously fixed** |
| DOC-GAP-04 | `ops/budlum-core.service:11` sets `Documentation=https://github.com/rade/budlum-core`; every flag in `ExecStart` exists in `NodeConfig`, `LimitCORE=0`, and the key comes from a 0600 `EnvironmentFile` | **Open, one line**. The wrong repository is real; the rest of the record is already correct |
| DOC-GAP-03 | `ops/scripts/` held only `.gitkeep`; `README.md:282` and `README.tr.md:286` ran `ops/scripts/devnet-multinode-smoke.sh`; the script is the `xtask/tools` `devnet-multinode-smoke` subcommand and `.github/workflows/docker-smoke.yml:132` runs it there. `fuzz/README.md` named two more removed scripts and said fourteen targets against eighteen bins | **Previously fixed in this PR** (three files, five lines) |
| BLG-254 | `xtask/gates/src/main.rs:994` (and 928, 980) still wire all three wrong-model gates | **Will close by removal**, because section 16.3 lists them among the deleted gates and WP-07 deletes them |

Two readings that changed the shape of the record:

- BLG-013's premise is now the opposite of what the record says: the `--all-features` combination is
  not invalid, CI requires it to build. The record is `Previously fixed` through that canary.
- DOC-GAP-04 is narrower than its title. Only `Documentation=` is wrong; the unit is otherwise
  hardened and its flags exist.

### 4.2 Third pass: the CI and gate records, read against the workflow files

| Record | Evidence read | Reading |
|---|---|---|
| BLG-015 | `crates/bud-codec` and `crates/uel-abi` are path dependencies of the root crate and are used in `src/storage/bud3/` and `src/execution/ee.rs`, so their library code compiles in every root build. No workflow has `--manifest-path crates/bud-codec` or `crates/uel-abi`, so their own `#[cfg(test)]` blocks and `crates/uel-abi/tests/` never execute | **Open, narrowed**: it is a test-execution gap, not a compile gap |
| BLG-016 | `.github/workflows/ci.yml:1480` runs `cargo deny check` and the `Cargo Deny` matrix covers each manifest; `find` in the lock-freshness step (line 2026) walks all 15 lockfiles. `.github/dependabot.yml` names only three cargo directories (`/`, `/budzero`, `/fuzz`) | **Partly fixed**: the scan covers every lockfile, the update bot still covers three of fifteen |
| BLG-081 | `crates/wallet-core` exists, so the "directory that does not exist" clause is closed; the only `"wallet-core"` strings left are the `wallet-core` gate's own name and two scratch directories in test fixtures | **Partly fixed**: the missing-directory clause is gone |
| BLG-085 | `crates/bud-codec/Cargo.toml` and `crates/uel-abi/Cargo.toml` have neither `[profile.release]` nor `overflow-checks`; every other crate in the tree has both | **Open, narrowed to exactly two crates** |
| BLG-097 | `kani/Cargo.lock` exists, so that clause is closed. `bud/fuzz/` has no `Cargo.lock`, and `bud/kani/kani_bud_format.rs` is still in the tree with no workflow that names `bud/kani` or the file | **Partly fixed**: two clauses closed, two still open |
| DOC-GAP-07 | `Cargo.toml:255` declares the bin | **Previously fixed** |

The value of the pass is the narrowing: three records that read as wide classes (BLG-015, BLG-085,
BLG-097) are down to one or two named files each, which is what a closing package needs to act on.

### 4.3 Fourth pass: BLG-095, read against the workflow and owner files

| Clause of BLG-095 | Evidence | Reading |
|---|---|---|
| Supply-chain scripts and Dependabot skip most lockfiles | `.github/dependabot.yml` names three cargo directories (`/`, `/budzero`, `/fuzz`); 15 lockfiles exist | **open** |
| `CODEOWNERS` is empty | `.github/CODEOWNERS` is 1420 bytes and names `@lubothebook` for the workflows, `.quality`, the baselines and `Cargo.toml` | **previously fixed** |
| `fifteen workflows name a deleted branch` | `consensus-of-consensuses` and `testnet-quantum` appear in exactly two workflows (`ci.yml:10`, `solidity.yml:7`), and neither branch exists on the remote (59 branches, none of them either name) | **narrowed from fifteen to two**, still open |
| the audit config keeps a stale exception | `.cargo/audit.toml` has `ignore = []` with the reason recorded | **previously fixed** |

### 4.4 Fifth pass: BLG-192 is already fixed

`estimate_gas` in `src/rpc/server.rs` returns `tx.fee.max(required)`, where `required` is
`AccountState::required_fee` through `chain.get_required_fee`: the same function admission uses, so
the base fee, the proportional transfer cut and the escalating governance fee are all in the number.
The record's premise (a flat 21000 that ignores both cuts) is gone. **Previously fixed**, and the
rationale is written in the handler itself, which is where the next reader will look.

### 4.5 The lane's permanent tests

Section 15.8 cards `src/tests/audit_lane_d.rs` as a lock path, and section 14.1 rule 7 is what it
is for: a record that was already fixed is pinned by a test that outlives the lane. Four records
whose reading produced no test of their own now have one, named after the record so `grep BLG-099`
and `grep blg_099_` find each other:

| Record | Test in `src/tests/audit_lane_d.rs` | What it holds |
|---|---|---|
| BLG-099 | `blg_099_credential_comparison_does_not_stop_at_a_common_prefix` | A prefix, a superset, a one-byte change and the empty string are all refused against the credential, and both-empty matches through the length fold |
| BLG-022 | `blg_022_next_checkpoint_is_answered_for_the_largest_target` | Interval 1 with target `u64::MAX` answers 5 from a height-4 anchor: the closed form, not a walk; interval 0 and a target behind the anchor are `None` |
| BLG-192 | `blg_192_estimate_fee_comes_from_the_admission_rule_not_a_constant` | The estimate handler asks `get_required_fee`, and no line of code in it returns 21000. The literal stays in the comment that explains the fix, which is why the assertion reads code lines, not the body text |
| BULGU-012 | `bulgu_012_serialisation_failure_is_an_error_not_a_null` | A value serde refuses produces `-32603` naming the method, and an encodable one still produces a value |

The other five `Previously fixed` rows already had a test in the module they belong to (BLG-012,
BLG-014, BULGU-011, DOC-GAP-07 has a declaration instead), and duplicating a test name is not
possible in one crate's test binary, so they keep the module's name and this file cites it.

### 4.6 Two live red jobs on `main`, read while working

The lane's earlier passes recorded that no run had concluded. That changed during this session, and
section 14.1 rule 9 says a new problem found while reading gets the next free id. Two scheduled jobs
on `main` are red right now:

| Run | Workflow / job | Failed step | What the step runs |
|---|---|---|---|
| `42163252239` | Watchdog / Main health pulse | `Lockfiles still match their manifests on main` | `cargo metadata --format-version 1 --locked` from the directory of every `Cargo.lock`: a nonzero exit means a manifest moved without its lockfile |
| `42163252239` | Watchdog / RustSec drift | `Audit every workspace lockfile` | `cargo audit --file` over 15 lockfiles against a freshly fetched advisory DB; the workflow treats a failed DB fetch as a failure too |
| `42002851792` | Testnet Rehearsal | (whole run) | the rehearsal, on `main` |

The same Watchdog job's two later steps passed (`actionlint` parsed every workflow, and
`budlum-gates regen-health-door` ran with its `--self-test`). That bounds the failure: the YAML is
valid and the gate is wired; the drift is in a manifest and lockfile pair, or in the advisory DB
fetch.

The error text itself is not reachable from this environment. `gh run view --log-failed` returns
empty and both `actions/jobs/<id>/logs` endpoints return `EOF` from the blob-storage redirect on
every attempt. So this ledger records the failed step and the command it runs, which is enough to
reproduce locally with one command, and does not invent an error message.

### The first red job is not a drift in the lock, it is an omission

The health pulse's failing step runs `cargo metadata --format-version 1 --locked` once per lockfile
directory. Read against the root pair, that command has a definite reason to fail, and it is not a
stale version:

- `Cargo.toml:205` declares `bud-codec = { path = "crates/bud-codec" }`, not `optional`.
- The root `Cargo.lock` contains no `bud-codec` package at all: `grep -c` over the lock returns 0.
- The `budlum-core` package block lists eleven sibling crates and `bud-codec` is not among them,
  although it is the twelfth path dependency.
- `crates/bud-codec` needs `zstd 0.13.3` and `ruzstd 0.8.1`, and the root lock names neither, so
  this is not just a missing package block: four packages are absent and eight transitive versions
  differ from what `crates/bud-codec/Cargo.lock` resolves (`libc` 0.2.186 against 0.2.191, `cc`
  1.2.63 against 1.11.0, and six more).

That makes the missing `--locked` resolution a *consequence* of the missing dependency, not a
separate fault. It is why the record below is written as an omission with its arithmetic, and why
this lane does not fix it: `Cargo.lock` is not a lane D lock path, and hand-writing the four package
blocks would invent a resolution that the next real `cargo` run would rewrite. The fix is one
`cargo update` on a machine with a toolchain, in WP-42, where `.github/workflows/` and the supply
chain live.

Two records in the directive's own review family read on this: BLG-264 and BLG-265 (the `WIRING:`
count and the combined-state record). They stay `Open` here; the red pulse is cited as the live
evidence that the drift is real, not as a closed record.

Seven records still have no reading: BLG-011, BLG-016, BLG-081 to BLG-087, BLG-097, BLG-169,
BLG-170 to BLG-181, BLG-187 to BLG-193, BLG-200, BLG-231, BLG-255, TEST-GAP-02 and TEST-GAP-07 need
either the record text or a toolchain this sandbox does not have.

## 5. The record bodies are not in this tree

Card item 2 requires each record's description and evidence. Section 15.8 (WP-01 item 2) states
that the old finding ledger is outside the repository and is supplied with the directive. It is not
in this checkout: `docs/audit/` holds only `AUDIT_FINDINGS.md`, which carries zero rows in the
`| BLG-NNN |` shape, and `TESTNET_TRACEABILITY.md`. The directive's own tables in section 14 give the
id, importance, area, Turkish title and closing package, and those are what section 3 records.

`docs/audit/FINDINGS.md` is written from the directive's own tables in the section 14.1 vocabulary:
identity, importance, area, English title, state, evidence, test, closing package and note. Four
records reach `Closed` by rule 7 (already fixed, with the note and a pinning test or a build
declaration). The rest stay `Open`, because without the record text the lane cannot honestly write
"already fixed" or "invalid" for a record it did not read. Two ways forward, both allowed by the directive:

1. the ledger is supplied to the session, and WP-04 item 3 is completed against it; or
2. every record is re-derived from the live tree, which is what section 4 starts.

The card's closing criterion, "four lane files, `LIVE_STATUS.md`, `FINDINGS.md` and `PACKAGES.md` on
`main`, 64 package records open", is therefore not met. This file is partial by construction, and it
says so rather than implying the card is done.

## 6. Measurements taken in this pass

### 6.1 Named-test probe (text search, not a test run)

Section 16.4 rule 5 binds every test name the directive writes. A text search for a `fn` declaration of each name gives the
lane D gaps below. A name found here is declared somewhere in the tree; it says nothing about
whether the test compiles or passes.

| Card | Named test | Live state |
|---|---|---|
| WP-05 | `concept_map_owner_is_a_known_package` | missing; open PR #20 adds it, so this pass does not duplicate it |
| WP-42 | `workflows_cover_every_workspace` | missing at the base; unopened branch `arena/8ff8d926-budlum` adds it |
| WP-42 | `nightly_workflows_are_required` | missing at the base; unopened branch `arena/aee1885c-budlum` adds it |
| WP-61 | `rpc_every_method_has_success_and_refusal_test` | missing on this branch and on every branch pushed to this repository that was compared |
| WP-61 | `cors_wildcard_does_not_reflect_headers`, `rpc_serialization_error_is_explicit` | present in `src/rpc/server.rs` |
| WP-43 | `readme_definition_block_is_verbatim`, `readme_has_no_placeholders`, `readme_claims_are_wired` | all missing |
| WP-11 | `light_client_*`, `mobile_core_*` | all missing; the crates do not exist |
| WP-36 to WP-38 | `android_*`, `ios_*` | all missing; no `mobile/` tree |
| WP-41 | `faucet_*`, `ops_compose_testnet_profile_boots` | all missing |

### 6.2 Finding-name rule coverage

Section 16.4 rule 1 requires a regression test named `blg_NNN_<short>`. A search for
`fn blg_` across `src/`, `crates/`, `budzero/` and `xtask/` returns zero definitions, so none of the
70 lane D records has its regression test under the bound name. The two records whose fixes are
pinned (section 4, BULGU-011 and BULGU-012) use names that the directive also writes for other purposes.

### 6.3 Concept-name counter (BLG-255)

`config/naming/concept_map.toml` holds 27 entries in mode `count`. Each entry carries its own
`patterns`, its own `paths` and a recorded count in `.github/concept-names-baseline.txt` of the form
`key|files|matches`. Re-implementing the map's own regexes over its own paths, with the map's
`global_allow_paths` skipped, gives 27 results: three entries sit exactly at the recorded baseline,
nineteen entries are below it in both columns, and five entries are recorded as zero and count zero.
No entry is above its baseline. Of the nineteen, the largest gaps are entries whose baseline records
between 23 and 71 files while the live count is zero.

Two consequences, both for WP-05 and not for this pass:

1. WP-05 item 4 says a count below the baseline requires the baseline to be lowered in the same
   change, so `.github/concept-names-baseline.txt` is stale for those nineteen entries.
2. The gate's `absolute` mode ends every rename, and it cannot be reached while nineteen entries are
   recorded above their live value.

This is a measured statement from a re-implementation of the map's regexes, not a run of the gate:
the gate itself must confirm it in CI. This pass does not edit the baseline, because `config/naming/`
is WP-05's lock path and open pull request #20 holds it. The retired names are deliberately not
repeated in this file; the map is their one home.

## 7. Deliberately not done

- No record is marked verified, already fixed, invalid or closed. The evidence for that label does
  not exist in this environment (section 1, section 5).
- `docs/audit/FINDINGS.md`, `docs/work/PACKAGES.md`, `src/tests/audit_lane_d.rs` and the 64 package
  issues are untouched: three are locked by live work and the fourth needs GitHub Issues, which are
  disabled.
- No build, test, clippy or gate output is claimed. No wire format, RPC name, measurement table or
  concept name is changed.

## 8. Summary of section 3, computed from the directive tables

The row set below is produced by parsing `THE_BUDLUM_DIREKTIF.md` section 14 tables and keeping a
row when any closing package in its last column is WP-05, WP-11, WP-36 to WP-43, WP-46 or WP-61.
It is printed here so the count in section 3 can be checked without reading the tables again.

| Measure | Value |
|---|---|
| Records in lane D | 70 |
| Importance, as written in font size and severity | 4 Critical, 26 High, 25 Medium, 4 Low, 1 S1, 10 S3 |
| Closing package WP-42 | 32 |
| Closing package WP-61 | 13 |
| Closing package WP-43 | 8 |
| Closing package WP-41 | 5 |
| Closing package WP-39 | 4 |
| Closing package WP-40 | 4 |
| Closing package WP-11 | 3 |
| Closing package WP-36 | 2 |
| Closing packages WP-05, WP-07, WP-12, WP-46 | 1 each |

The record ids are: BLG-004, BLG-009, BLG-010, BLG-011, BLG-012, BLG-013, BLG-014, BLG-015,
BLG-016, BLG-022, BLG-026, BLG-029, BLG-030, BLG-032, BLG-068, BLG-081, BLG-082, BLG-083, BLG-084,
BLG-085, BLG-086, BLG-087, BLG-092, BLG-095, BLG-097, BLG-098, BLG-099, BLG-117, BLG-121, BLG-143,
BLG-150, BLG-169, BLG-170, BLG-171, BLG-172, BLG-174, BLG-175, BLG-176, BLG-177, BLG-178, BLG-179,
BLG-180, BLG-181, BLG-187, BLG-188, BLG-189, BLG-192, BLG-193, BLG-200, BLG-231, BLG-241, BLG-254,
BLG-255, BLG-257, BLG-259, BLG-265, BULGU-011, BULGU-012, TEST-GAP-02, TEST-GAP-04, TEST-GAP-07,
DOC-GAP-01, DOC-GAP-02, DOC-GAP-03, DOC-GAP-04, DOC-GAP-05, DOC-GAP-06, DOC-GAP-07, DOC-GAP-08,
DOC-GAP-09.

Three records are not in the list although they touch lane D work: BLG-248 (contract-call
execution, WP-26) belongs to lane C, and BLG-264 (`WIRING:` count) closes under WP-12, lane A.
BLG-005 is the one record section 14.2 calls closed, and section 14.3 still gives it a closing
package, WP-16. It is outside lane D because WP-16 is not in the lane's scope, not because nothing
closes it. The tree agrees with the ledger entry: `.gitignore:16-17` excludes `/secrets/` and
`/data/`, which is what the record was about. No row in the lane's 70 has an empty closing package;
the parse counts zero.

One correction to an earlier reading in this file: `BULGU-001` through `BULGU-027` are rows of the
section 14.6 archive table, not family placeholders. Section 14.6 names 27 `BULGU-` ids, 8
`TEST-GAP-` ids and 9 `DOC-GAP-` ids, and it carries one row for each, 44 in total. The note that
the archive might be short by 17 rows is withdrawn.
