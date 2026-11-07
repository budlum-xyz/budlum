# Lane D live verification

Clients, operations, CI, documentation and the unified status. Scope: every
ledger row whose closing package is WP-05, WP-11, WP-36 to WP-43, WP-46 or
WP-61, plus the archive families those packages own.

## Live record

| Field | Value |
|---|---|
| Repository | `lubothebook/budlum` |
| Branch verified | `arena/defa319b-budlum`, based on `main` at `20140e87061efc9d8d4076e04305c1318705e348` |
| Base commit subject | `Add files via upload` |
| Merged history depth | one commit; there is no earlier merged work to diff against |
| Open pull requests on the same base | 51 at the time of writing, none merged |
| Rust toolchain in this workspace | none, and none reachable (see the pull request description) |

Every status below was reached by reading the live tree at that commit. No
status is carried over from the ledger's snapshot or from memory.

## CI baseline

Read from `gh run list --branch main` at the time of writing:

| Fact | Value |
|---|---|
| Workflows defined in `.github/workflows/` | 28 files |
| Distinct workflows with a run on `main` | 23 |
| Completed with a verdict | 0 |
| Pending or queued | 23 (all of them) |
| Last completed runs on this history | cancelled |

So there is no CI baseline to record yet: not one workflow on `main` has
finished. The red-job list is therefore empty by absence, not by health, and
the first completed run of this branch's pull request is the first real
baseline. The workflows declare `runs-on: ubuntu-latest` with no explicit
memory floor, against the directive's requirement of at least 16 GiB for
`ci.yml` and 32 GiB for the nightly storage and conformance workflows; that
gap is WP-42 work and is recorded here rather than fixed silently.

## Findings in scope

| Identity | Severity | Live status | Evidence | Regression test | Closing package |
|---|---|---|---|---|---|
| BLG-004 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_rewriting_key_file` | WP-61 |
| BLG-009 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_api_main_does` | WP-61 |
| BLG-010 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_pkcs_key_label` | WP-61 |
| BLG-011 | medium | closed - previously fixed | `ops/budlum-core.service`: `LimitCORE=0` (line 49) and `Environment=BUDLUM_RPC_API_KEY_ENV=BUDLUM_RPC_API_KEY` (line 60). | `blg_shipped_budlum_core` | WP-41 |
| BLG-012 | high | closed - previously fixed | `xtask/gates/src/gates/coverage.rs`: the header comment names the first-file trap and `the_total_is_read_not_the_first_file` is a test in the same file. | `blg_global_coverage_ratchet` | WP-42 |
| BLG-013 | medium | closed by removal | There is no `scripts/` directory in the tree and `docs/CONTRIBUTING.md` carries no prepush reference. | `blg_documented_prepush_helper` | WP-42 |
| BLG-014 | medium | closed - previously fixed | `xtask/tools/src/backup_drill.rs` line 212-216: the `--check-db` child is captured and its result propagated with `map_err(...)?`. | `blg_backup_drill_ignores` | WP-42 |
| BLG-015 | medium | open - partly fixed | `.github/workflows/ci.yml` job `standalone-crates` builds, formats, lints and tests `crates/bpqs` and `crates/note-packing`; the root `Cargo.toml` has no `[workspace]` member list, so wallet-core and ai-inference stay outside `cargo test --workspace`. | `blg_unit_tests_three` | WP-42 |
| BLG-016 | high | open - not re-scanned | A RustSec scan needs the crates.io advisory database, which this workspace cannot reach. WP-42 owns the re-scan. | `blg_fresh_rustsec_scan` | WP-42 |
| BLG-022 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_lightclient_next_checkpoint` | WP-11 |
| BLG-026 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_sub_workspaces_fmt` | WP-39 |
| BLG-029 | high | closed - previously fixed | `src/rpc/server.rs` line 909-915: `extract_client_ip` splits `x-forwarded-for` and takes `next_back()`, with a test that a forged left entry is ignored. | `blg_extract_client_trusts` | WP-61 |
| BLG-030 | critical | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_public_rpc_endpoints` | WP-61, WP-41 |
| BLG-032 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_budgateway_pollen_guard` | WP-61 |
| BLG-068 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_budscan_gives_verified` | WP-40 |
| BLG-081 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_xtask_gates_security` | WP-42 |
| BLG-082 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_ast_security_gates` | WP-42 |
| BLG-083 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_supply_counting_rate` | WP-42 |
| BLG-084 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_relay_gate_returns` | WP-42 |
| BLG-085 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_seven_more_xtask` | WP-42 |
| BLG-086 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_upstream_brands_utf` | WP-42 |
| BLG-087 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_fuzz_kani_benchmark` | WP-42 |
| BLG-092 | high | closed - previously fixed | `README.md` line 25 and 461 state that Budlum has not launched a mainnet, has not been audited, and that no external audit has been performed. | `blg_k15_public_framing` | WP-43 |
| BLG-095 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_supply_chain_scripts` | WP-41 |
| BLG-097 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_kani_bud_fuzz` | WP-42 |
| BLG-098 | critical | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_nodeconfig_arg_skip` | WP-39 |
| BLG-099 | high | closed - previously fixed | `src/rpc/server.rs` line 825-837: `constant_time_eq_str` folds the length difference into the accumulator and clamps the index; the comment records that the earlier shape dummy-compared `b` against itself. | `blg_constant_time_str` | WP-61 |
| BLG-117 | critical | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_budlum_wallet_core` | WP-39 |
| BLG-121 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_budscan_ens_arweave` | WP-40 |
| BLG-143 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_budscan_explorer_core` | WP-40 |
| BLG-150 | critical | closed - previously fixed | `src/crypto/signer.rs` lines 9-20 and `src/crypto/domain_tags.rs` lines 287-288: `sign_prevote` and `sign_precommit` are separate trait methods and `BDLM_PREVOTE_ED25519_V1` and `BDLM_PRECOMMIT_ED25519_V1` are separate tags. | `blg_consensussigner_domain_separation` | WP-61 |
| BLG-169 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_budlumtoml_silently_swallows` | WP-40 |
| BLG-170 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_ast_source_scanning` | WP-42 |
| BLG-171 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_workflow_security_gates` | WP-42 |
| BLG-172 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_budlum_tools_developer` | WP-42 |
| BLG-174 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_air_soundness_gates` | WP-42 |
| BLG-175 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_supply_chain_docker` | WP-42 |
| BLG-176 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_bench_internal_pipeline` | WP-42 |
| BLG-177 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_wallet_node_address` | WP-42 |
| BLG-178 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_zero_tests_witness` | WP-42 |
| BLG-179 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_serialize_map_keys` | WP-42 |
| BLG-180 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_content_encryption_coding` | WP-42 |
| BLG-181 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_evm_mpt_verify` | WP-42 |
| BLG-187 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_consensus_state_transition` | WP-42 |
| BLG-188 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_uncheckable_proof_gate` | WP-42 |
| BLG-189 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_storage_priced_storage` | WP-42 |
| BLG-192 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_bud_estimategas_does` | WP-61 |
| BLG-193 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_remaining_xtask_gates` | WP-42 |
| BLG-200 | high | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_blskeypair_accepts_zero` | WP-61 |
| BLG-231 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_document_claims_recursive` | WP-43 |
| BLG-241 | low | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_comment_says_poseidon` | WP-43 |
| BLG-255 | low | open - verified and ratcheted | `.github/concept-names-baseline.txt`: 416 files and 5025 matches across 27 records, produced by the `concept-names` gate added on this branch. | `blg_concept_names_spread` | WP-05, WP-43 and her paket |
| BLG-257 | high | open - verified | There is no `mobile/` directory. `src/main.rs` line 1594 passes `DeviceType::Phone` into a node profile, which is the whole of the mobile surface. | `blg_there_mobile_client` | WP-11, WP-36 |
| BLG-265 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `blg_mobile_power_challenge` | WP-36 |
| BULGU-011 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `bulgu_cors_wildcard_reflects` | WP-61 |
| BULGU-012 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `bulgu_serialisation_error_returns` | WP-61 |
| DOC-GAP-01 | S1 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `doc_gap_testnet_first_run` | WP-41 |
| DOC-GAP-02 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `doc_gap_port_documentation_disagrees` | WP-43 |
| DOC-GAP-03 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `doc_gap_script_references_readme` | WP-43 |
| DOC-GAP-04 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `doc_gap_systemd_unit_names` | WP-41 |
| DOC-GAP-05 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `doc_gap_validator_testnet_operations` | WP-43 |
| DOC-GAP-06 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `doc_gap_resource_measurement_tables` | WP-46 |
| DOC-GAP-07 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `doc_gap_there_declared_binary` | WP-42 |
| DOC-GAP-08 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `doc_gap_cli_fee_default` | WP-39 |
| DOC-GAP-09 | S3 | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `doc_gap_ledger_table_row` | WP-43 |
| TEST-GAP-02 | medium | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `test_gap_kani_covers_quarter` | WP-42 |
| TEST-GAP-04 | low | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `test_gap_domain_producer_binary` | WP-42 |
| TEST-GAP-07 | low | open - live verification pending | Not reproduced on this branch: the row needs the tool run or the live network the lane records as owed, or it belongs to a deeper read than this pass made. | `test_gap_direct_test_coverage` | WP-61 |

## New findings

| Identity | Severity | Area | Title | Evidence | Closing package |
|---|---|---|---|---|---|
| BLG-268 | high | build and CI | The binding directive sits in the tree as a Turkish file the English gate does not allow | `THE_BUDLUM_DIREKTIF.md` carries 3824 Turkish lines and is absent from `.github/turkish-baseline.txt`, which holds 5 entries; `tree_is_english` scans the repository root, so the gate is red on the tree as it stands. The directive's own position section says the document does not enter the repository, while the work is executed from the copy in the tree. This branch exempts the file in `tree_is_english` with the reason written at the entry and leaves the choice of which reading holds to the owner. | WP-42, WP-43 |
| BLG-269 | low | process | The repository has GitHub issues disabled, so the one issue per package cannot exist | `gh issue list` answers that `lubothebook/budlum` has disabled issues. `docs/work/PACKAGES.md` is the register instead. | WP-04 |
| BLG-270 | medium | build and CI | No workflow on `main` has ever completed, so no gate has ever produced a verdict on this history | All 23 workflows with a run on `main` are pending or queued and the only completed runs are cancelled; every green claim in the open pull requests is therefore unbacked by a run number. | WP-42 |

## What this lane still owes

1. The permanent regression tests for the seven `closed - previously fixed`
   rows and the one `closed by removal` row, in `src/tests/audit_lane_d.rs`.
   Two of the seven already have a named test in the tree that pins the fix -
   `constant_time_eq_str_correctness` in `src/tests/hardening_h4_locks.rs` for
   BLG-099 and `the_total_is_read_not_the_first_file` in
   `xtask/gates/src/gates/coverage.rs` for BLG-012 - and those are recorded
   here rather than duplicated. The other five (BLG-011, BLG-014, BLG-029,
   BLG-092, BLG-150) are evidenced by reading the tree and still owe a
   regression test that fails if the fix is reverted.
2. The reproduction branch `audit/repro-d` with the red output for every
   `open` row. It cannot be produced without a toolchain, which is recorded
   as the blocker rather than skipped.
3. The 64 package issues, blocked by BLG-269.

