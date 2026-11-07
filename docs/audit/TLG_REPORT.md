# Testnet Launch Gate report

The sentence "Budlum is ready for the testnet" holds only when every row below
is green. Each row carries its evidence type, the commit it was read at, a CI
run number or a record path, and the reviewer. A row with no evidence is red.

Read at commit `c11a463b` (branch `arena/ce59116c-budlum`, base `20140e8`) on
2026-11-07. The reviewer column is blank wherever no second agent has reviewed
the row. No CI run number is written on this page: the environment this report
was written in has no Rust toolchain and no access to the job logs, so a run
number would be invented. Under the directive, an unproven row is red, so those
rows are red here rather than green by optimism.

Status vocabulary: `Green` (evidence exists and is recorded), `Red` (evidence
is missing, the gate is missing, or the artefact is missing), `Red, unproven`
(the evidence must come from a CI run or a rehearsal that has not been recorded).

| Code | Item | Status | Evidence | Package |
| --- | --- | --- | --- | --- |
| TLG-01 | No open Critical or High finding; a feature that stays open is closed on chain id `45261` and a test proves the refusal. | Red | `docs/audit/FINDINGS.md` lists BLG-268 to BLG-275, of which BLG-268 and BLG-272, BLG-273 are Critical or High. | All |
| TLG-02 | Every `Closed` feature of section 1.5 has a `<feature>_is_closed_on_testnet` test. | Red, unproven | 19 such tests exist (for example `object_layer_is_closed_on_testnet`, `foreign_sui_is_closed_on_testnet`, `parallel_scheduler_is_closed_on_testnet`). Not every closed feature has one, and no run is recorded. | All |
| TLG-03 | No legacy storage code remains. | Red | The gate exists now (`no-legacy-storage`) and ratchets the 29 identifiers and 5 paths of directive section 5.5 against `.github/no-legacy-storage-baseline.txt`: 1321 occurrences at the commit above, `path:bud/` alone counting 119 files (the gate excludes its own identifier list, which would otherwise add one per name). The row is red because the condition the gate measures is not met: the baseline is not empty, so the legacy code is still in the tree. | WP-07 |
| TLG-04 | B.U.D. 3.0 acceptance suite and the nightly T3, T4, T6, T7, T17 green for 7 nights. | Red, unproven | No run recorded. `storage-nightly.yml` is in the tree. | WP-18 to WP-25 |
| TLG-05 | Committee finality and seat handoff tests green. | Red, unproven | No run recorded. | WP-12, WP-13 |
| TLG-06 | Instant Duty Handoff tests and the churn simulation green. | Red, unproven | No run recorded. | WP-14 |
| TLG-07 | Rehearsal drill T-1 passed. | Red | No rehearsal record; `docs/rehearsal/RESULTS.md` has no run. | WP-46 |
| TLG-08 | Rehearsal drill T-2 passed. | Red | No rehearsal record. | WP-46 |
| TLG-09 | Rehearsal drills T-3, T-4, T-5, T-7 passed. | Red | No rehearsal record. | WP-46 |
| TLG-10 | At least 20 real Android phones validated in the rehearsal. | Red | `mobile/` is not in the tree. | WP-36, WP-46 |
| TLG-11 | Device matrix results exist. | Red | `docs/MOBILE_DEVICE_MATRIX.md` is not in the tree. | WP-37 |
| TLG-12 | Every execution environment passes conformance, or each exception is in the limit table. | Red, unproven | `docs/EXECUTION_LIMITS.md` exists and carries the budget constants; no conformance run is recorded. | WP-35 |
| TLG-13 | Ecosystem tool tests green in the nightly workflow. | Red, unproven | No run recorded. | WP-28 to WP-32 |
| TLG-14 | An EVM contract calls a CosmWasm contract atomically. | Red, unproven | `uel_evm_calls_wasm_atomically` exists in `src/execution/coordinator/universal_call.rs`. No run recorded. | WP-30, WP-46 |
| TLG-15 | Cross architecture root equality green. | Red, unproven | `determinism.yml` is in the tree; no run recorded. | WP-35 |
| TLG-16 | Gas calibration criterion met. | Red, unproven | `uel_gas_calibration_bound` exists in `execution/conformance/src/lib.rs`; no measured result recorded. | WP-35 |
| TLG-17 | Genesis ceremony rehearsal passed; supply audit green; at least 8 Full validators. | Red | No ceremony report. | WP-16, WP-46 |
| TLG-18 | NAT traversal: relay, DCUtR and AutoNAT green, with recorded ratios. | Red | No nightly run and no rehearsal record. | WP-15, WP-46 |
| TLG-19 | Economy invariants green: pool split and fees preserve supply. | Red, unproven | `economy_invariants` gate exists; no run recorded. | WP-16, WP-25, WP-26 |
| TLG-20 | RPC listener rules, method tables and rate limits green. | Red, unproven | No run recorded. | WP-28 to WP-32, WP-61 |
| TLG-21 | Faucet, explorer, dashboards and alerts worked in the rehearsal. | Red | No rehearsal record. | WP-40, WP-41 |
| TLG-22 | Independent reviews complete; new Critical and High findings closed. | Red | `docs/audit/REVIEW_1.md` and `docs/audit/REVIEW_2.md` are not in the tree. | WP-47, WP-48 |
| TLG-23 | `README.md` equals appendix A and `README.tr.md` equals appendix B; the definition blocks are byte for byte; no placeholder remains. | Red | The text is written and the definition block hashes to `dd9be5206be37e05a39e26d002af633c23f56be7378bc8dfe10861406f063467` as the directive records, and no `{{...}}` token remains. Two of the three gates this row names exist (`readme-definition-block-is-verbatim`, `readme-has-no-placeholders`); the third, `readme-claims-are-wired`, is not written, so the row is red on that gate alone. | WP-43 |
| TLG-24 | The concept name gate is green in absolute mode. | Red | `config/naming/concept_map.toml` is in `count` mode and its counts now equal the baseline (27 entries, 5036 matches, re-measured with an independent counter). Absolute mode needs every count at zero, which is the decision WP-43 records separately; the measurement is green, the mode is not. | WP-43 |
| TLG-25 | CI green and every nightly workflow green for 7 nights. | Red, unproven | No run recorded. | WP-42 |
| TLG-26 | Release artefacts reproducible, SBOM and signatures published. | Red | No release exists. | WP-41, WP-42 |
| TLG-27 | The bridge decision and the AI layer decision are written and proven by a test. | Red | Decision: both stay closed on chain id `45261` because BLG-043, BLG-057, BLG-105, BLG-194 and BLG-059 to BLG-062 are open. `verify_merkle_is_closed_on_testnet` and `verify_inference_is_closed_on_testnet` exist in `src/tests/regression_bridge.rs`; no run recorded. | WP-44, WP-45 |

## What this page changes

The README carries two rows that read this page: the bridge row and the AI
layer row both say `Closed`, which is the TLG-27 decision above.

A row turns green here only when it carries a commit, a CI run number or a
record path and a second reviewer has approved it. Writing a row green without
that is the failure this report exists to prevent.
