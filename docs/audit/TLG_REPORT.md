# Testnet Launch Gate Report

The Testnet Launch Gate (TLG) has 27 items, and the sentence "Budlum is ready for
the testnet" may be written only when every one of them is green (directive 18).
This file is the evidence register for that sentence. It is not that sentence.

Two rules decide everything in this file.

1. An item with no evidence is red (R-32). "We believe it passes" is not evidence.
2. The agent that writes this report is not the agent that approves it (18, rule 1).
   No item below is approved. The approval column is empty for that reason, not
   because approval was refused.

Measured on this branch, whose base is `main` at `20140e87`. Every measurement
below names the command that produced it, so a reader can reproduce it instead of
trusting this file.

## Summary

| Status | Items |
|---|---|
| Red: the artifact the item names does not exist | 22 |
| Unverified: the artifact exists, no verdict exists | 3 |
| Green | 0 |
| Approved by a second agent | 0 |

Three of the 27 items name an artifact that is present but whose verdict cannot be
read, because no workflow has produced a verdict for any commit after `20140e87`
(see TLG-25). Those three are marked `unverified` rather than green: an artifact is
not a result.

## The 27 items

| Code | Item, in short | Evidence the directive names | What this tree has | Status |
|---|---|---|---|---|
| TLG-01 | No open Critical or High finding; an open one is closed on the testnet behind a test | `docs/audit/FINDINGS.md` count and closure tests | `docs/audit/FINDINGS.md` does not exist. `docs/audit/AUDIT_FINDINGS.md` is a different register: review-round records `AF-01`..`AF-15`, not the 267 `BLG-` identities. Measured: `grep -c "BLG-" docs/audit/AUDIT_FINDINGS.md` is 0. | Red |
| TLG-02 | Every closed feature has a green `<feature>_is_closed_on_testnet` test | CI | Measured: `grep -rn "fn [a-z0-9_]*_is_closed_on_testnet" --include=*.rs .` matches 0 definitions in the whole tree. | Red |
| TLG-03 | No legacy storage code | `no_legacy_storage` gate | The gate does not exist (see `docs/audit/GATES.md`). The identifiers the gate is specified to ban are still here: `ContentManifest` occurs in 29 source files, `StorageProvider` in 70 lines, `OpenDeal` in 23, `AnswerCodingAudit` in 18. | Red |
| TLG-04 | The B.U.D. 3.0 acceptance tests T1..T12, T14..T26, T34..T41 are green, and the nightly tests T3, T4, T6, T7, T17 have been green for 7 nights | CI | Measured: 0 test definitions match `fn bud3_`. `src/storage/bud3/` does not exist. No nightly storage workflow exists (see TLG-04's own nightly list). | Red |
| TLG-05 | Committee finality and seat-transfer tests are green (7.12) | CI | 113 test definitions carry `finality` in their name and 23 functions carry `committee`, so the area is tested. The directive's committee and seat-transfer tests are not named anywhere, and no verdict exists for the current commit. | Unverified |
| TLG-06 | Instant Duty Transfer tests and the churn simulation are green | CI | `tests/churn/` does not exist. No `churn-nightly.yml` exists. | Red |
| TLG-07 | Rehearsal drill T-1 passed | Rehearsal record | `docs/rehearsal/` does not exist. `ops/rehearsal/` does not exist. | Red |
| TLG-08 | Rehearsal drill T-2 passed | Rehearsal record | As TLG-07. | Red |
| TLG-09 | Rehearsal drills T-3, T-4, T-5, T-7 passed | Rehearsal record | As TLG-07. | Red |
| TLG-10 | At least 20 real Android phones served as validators in the rehearsal | Explorer records and rehearsal record | `mobile/` does not exist. No explorer record of a mobile validator exists. | Red |
| TLG-11 | Device matrix results exist: 24 hour service, battery budget, NAT matrix | `docs/MOBILE_DEVICE_MATRIX.md` | The document does not exist. | Red |
| TLG-12 | EVM, WASM, SVM, Move and BudZero conformance suites pass 100 percent, or every exception is in the limit table | CI and `docs/EXECUTION_LIMITS.md` | `execution/` does not exist, `docs/EXECUTION_LIMITS.md` does not exist, and 0 test definitions match `fn uel_`. | Red |
| TLG-13 | Tool tests are green in the nightly workflow: Foundry, Hardhat, viem, ethers, CosmJS, Anchor, solana CLI, `@solana/web3.js`, aptos CLI, Aptos TypeScript SDK | CI | No `conformance-nightly.yml` exists. Measured: the workflow directory has 30 files and none of them is that one. | Red |
| TLG-14 | An EVM contract calls a CosmWasm contract in one transaction and the result is atomic | `uel_evm_calls_wasm_atomically` and the rehearsal record | Measured: 0 matches for that test name. The rehearsal record does not exist. | Red |
| TLG-15 | Cross-architecture root equality is green | `determinism.yml` | The workflow exists. No run of it has completed since `20140e87` (TLG-25), so there is no verdict to read. | Unverified |
| TLG-16 | The gas calibration criterion is met | `uel_gas_calibration_bound` | Measured: 0 matches for that test name, and 0 matches for `gas_calibration` in `src/` or `crates/`. | Red |
| TLG-17 | The genesis ceremony rehearsal passed; the supply audit is green; at least 8 Full validators | Ceremony report | No ceremony report exists. `ops/rehearsal/` and `config/rehearsal-genesis.json` do not exist. | Red |
| TLG-18 | NAT traversal: relay, DCUtR and AutoNAT nightly tests are green, and the rehearsal records connection ratios | CI and `docs/rehearsal/RESULTS.md` | No `nat-nightly.yml` exists. `docs/rehearsal/RESULTS.md` does not exist. | Red |
| TLG-19 | Economy: pool split, storage fee and rewards preserve supply; `economy_invariants` is green | CI | The `economy-invariants` gate exists and is wired. No verdict exists for the current commit (TLG-25). | Unverified |
| TLG-20 | RPC: listener rules, method tables and rate limits are green; drill T-7 passed | CI and the rehearsal record | `src/rpc/` carries 40 test definitions, so the area is tested. Drill T-7 has no record. | Red |
| TLG-21 | Faucet, explorer, dashboards and alerts ran in the rehearsal | Rehearsal record | The rehearsal record does not exist. `ops/monitoring/` exists and is unmeasured. | Red |
| TLG-22 | Independent reviews 1 and 2 are complete, and their new Critical and High findings are closed | `docs/audit/REVIEW_1.md`, `docs/audit/REVIEW_2.md` | Neither document exists. | Red |
| TLG-23 | `README.md` equals Appendix A and `README.tr.md` equals Appendix B; the definition blocks are byte-exact; no placeholders; every number comes from CI or the rehearsal | `readme_definition_block_is_verbatim`, `readme_has_no_placeholders`, `readme_claims_are_wired` | Two of the three gates do not exist. The definition blocks themselves are already byte-exact: the first 14 lines of `README.md` hash to `dd9be52...` and the first 15 lines of `README.tr.md` to `c883e00...` under SHA-256 with LF endings, which are the two constants in WP-43. The rest of both files is not the target text, and the target text carries 29 distinct `{{...}}` tokens whose sources (the rehearsal numbers, the ceremony genesis hash and time, the release artifacts, the testnet domain) do not exist in this tree yet. | Red |
| TLG-24 | The concept-name gate is green in absolute mode | `concept_names` | The gate does not exist. `config/naming/concept_map.toml` does not exist. | Red |
| TLG-25 | CI is green, and every nightly workflow has been green for 7 nights | CI | Measured with `gh run list --workflow ci.yml --limit 100`: 41 runs queued or in progress, 59 cancelled, 0 completed successfully. No nightly workflow can satisfy a 7-night window in this state. | Red |
| TLG-26 | Release artifacts are reproducible; SBOM and signatures are published | `release.yml` | No `release.yml` exists. `release-signature.yml` and `provenance.yml` exist and cover signing and attestation, not the reproducible release build the item names. | Red |
| TLG-27 | The bridge decision and the AI-layer decision are written in the TLG report and proved by a test | CI | No decision is recorded for either, because the findings that condition them (BLG-043, BLG-057, BLG-105, BLG-194 for the bridge; BLG-059, BLG-062, BLG-229, BLG-240 for the AI layer) have no live status in this tree (TLG-01). | Red |

## Why TLG-25 is red, measured

The single most useful measurement in this file is the one behind TLG-25, because it
is the reason three other items are `unverified` instead of green and the reason no
package in `docs/work/PACKAGES.md` carries a CI run number.

```
$ gh run list --workflow ci.yml --limit 100 --json conclusion \
    --jq '[.[].conclusion] | group_by(.) | map({(.[0]//"null"): length}) | add'
{"":41,"cancelled":59}
```

Of the newest hundred runs of `ci.yml`, 41 have not finished and 59 were cancelled
(the concurrency group cancels a branch's older run on every push). Zero succeeded. The repository therefore has no green CI
baseline to compare against, and this report cannot claim one for any commit.

## What would turn each red group green

The 22 red items are not 22 independent pieces of work. They collapse into five
groups, and each group is one work package's done criterion.

| Group | Items | Package that closes it |
|---|---|---|
| The finding register: every finding has a live status and a reproduction test name | TLG-01, TLG-02, TLG-27 | WP-01, WP-02, WP-03, WP-04 |
| B.U.D. 3.0 exists: object format, placement, custody, upload, view, fees, and the `bud3_*` tests | TLG-03, TLG-04 | WP-07, WP-10, WP-18 to WP-25 |
| Execution environments exist and are conformant | TLG-12, TLG-13, TLG-14, TLG-16 | WP-26 to WP-35 |
| Mobile validators exist and ran on real hardware | TLG-10, TLG-11 | WP-11, WP-36, WP-37 |
| The rehearsal ran, and its record is in the tree | TLG-06, TLG-07, TLG-08, TLG-09, TLG-17, TLG-18, TLG-20, TLG-21 | WP-46, and the nightly workflows TLG-18 names |
| The documents exist and their gates are green | TLG-22, TLG-23, TLG-24, TLG-26 | WP-43, WP-47, WP-48, WP-41 |

## Approval

No item is approved. Directive 18 rule 1 requires an agent from the other lane to
re-run this report's measurements on its own branch and write the CI run number as
a comment. Until that happens this file is a proposal, and the sentence it exists
to support cannot be written.
