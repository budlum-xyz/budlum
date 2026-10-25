# Coverage ledger (testnet directive, section 5.1)

This ledger lists every file tracked by git, with its line count and its
read status. A file is marked `reviewed` only after every line was read.
The ledger lives in the repository so a later session continues from it.

Measured at commit `f588d62` (branch `ccr-d9229a3f-lgzpy9`, equal to
`claude-code` in `lubothebook/budlum`; it carries `1f7ed99` plus two commits).

## Status legend

| Status | Meaning |
|---|---|
| `reviewed` | Every line read against the checklist in section 5.2. |
| `partial A-B` | Only the listed line ranges were read. The rest is unread. |
| `unread` | Not read yet. No claim is made about the file. |
| `excluded` | Not audited. The reason is in the last column. |

Exclusions are limited to the four classes the directive allows: Lubot
(section 3.2), binary files, generated files and external test vectors.
Fuzz seed corpus files are input data and are counted with the vectors.

## Totals

| Measure | Value |
|---|---|
| Tracked files | 1055 |
| Excluded files | 177 |
| Text lines in tracked files | 461024 |
| Excluded text lines | 40038 |
| In-scope text lines | 420986 |
| Files `reviewed` | 11 |
| Files `partial` | 21 |
| Files `unread` | 846 |

Progress is not a percentage of files: a large file read in part counts as
`partial` until its last line is read.

## Lubot classification

The paths below are Lubot and stay out of scope. The rename that hid them is
commit `b7d4b86` (2 September 2026): `src/lubot/` became
`src/ai_inference/`, `crates/lubot` became `crates/ai-inference/`, and
`src/tests/lubot_runtime.rs` became `src/tests/ai_inference_runtime.rs`. The
three gates `ai_inference_prompt_is_true.rs`, `ai_inference_reads.rs` and
`ai_inference_zk.rs` were renamed from `lubot_*` gates in the same commit, so
they are Lubot as well. `src/ai/` is not Lubot and stays in scope.

The `AI_OPERATOR` role (RoleId 8) and the `AiOperatorBond`,
`AiOperatorUnbond` and `AiOperatorWithdraw` transactions were named
`LubotOperatorBond`, `LubotOperatorUnbond` and `LubotOperatorWithdraw` before
`b7d4b86` (see `git show b7d4b86 -- src/core/transaction.rs`). They are
Lubot. Their executor and transaction arms live in in-scope files; those arms
are listed in `FINDINGS.md` as L-01 and are not changed by this directive.

## Files

| File | Lines | Status | Notes |
|---|---|---|---|
| `.cargo/audit.toml` | 11 | unread |  |
| `.coderabbit.yaml` | 17 | unread |  |
| `.github/CODEOWNERS` | 32 | unread |  |
| `.github/ISSUE_TEMPLATE/bug-report.md` | 40 | unread |  |
| `.github/ISSUE_TEMPLATE/documentation-issue.md` | 39 | unread |  |
| `.github/ISSUE_TEMPLATE/feature-request.md` | 44 | unread |  |
| `.github/ISSUE_TEMPLATE/protocol---consensus-proposal.md` | 80 | unread |  |
| `.github/ISSUE_TEMPLATE/question---discussion.md` | 38 | unread |  |
| `.github/PULL_REQUEST_TEMPLATE.md` | 72 | reviewed | PR template used for every PR of this directive. |
| `.github/cargo-vet-baseline.txt` | 30 | unread |  |
| `.github/clippy-extra-baseline.txt` | 47 | unread |  |
| `.github/codeql/codeql-config.yml` | 66 | unread |  |
| `.github/coverage-badge.json` | 6 | excluded | generated badge data |
| `.github/coverage-baseline.txt` | 1 | unread |  |
| `.github/dead-pub-api-baseline.txt` | 211 | unread |  |
| `.github/dependabot.yml` | 135 | unread |  |
| `.github/gate-panics-baseline.txt` | 41 | unread |  |
| `.github/git-dep-audit.toml` | 167 | unread |  |
| `.github/idle-code-baseline.txt` | 2079 | unread |  |
| `.github/semver-exceptions.txt` | 71 | unread |  |
| `.github/tsan-suppressions-baseline.txt` | 45 | unread |  |
| `.github/tsan-suppressions.txt` | 96 | unread |  |
| `.github/turkish-baseline.txt` | 30 | unread |  |
| `.github/udeps-baseline.txt` | 4 | unread |  |
| `.github/unwired-guards-baseline.txt` | 83 | unread |  |
| `.github/unwritten-metrics-baseline.txt` | 3 | unread |  |
| `.github/workflows/air-mutants-nightly.yml` | 48 | unread |  |
| `.github/workflows/audit-guard.yml` | 47 | unread |  |
| `.github/workflows/benchmark.yml` | 96 | unread |  |
| `.github/workflows/cargo-vet.yml` | 107 | unread |  |
| `.github/workflows/ci.yml` | 2492 | partial 1-570, 840-960 | Main CI: core, PQ, lib test, gates, BudZero. |
| `.github/workflows/dependency-review.yml` | 42 | unread |  |
| `.github/workflows/determinism.yml` | 214 | unread |  |
| `.github/workflows/diverse-double-compiling.yml` | 193 | unread |  |
| `.github/workflows/docker-smoke.yml` | 153 | unread |  |
| `.github/workflows/extra-tooling.yml` | 490 | unread |  |
| `.github/workflows/fmt-diff-surface.yml` | 123 | unread |  |
| `.github/workflows/fuzz-nightly.yml` | 120 | unread |  |
| `.github/workflows/grype.yml` | 118 | unread |  |
| `.github/workflows/kani-slow.yml` | 112 | unread |  |
| `.github/workflows/miri-storage-weekly.yml` | 184 | unread |  |
| `.github/workflows/miri.yml` | 449 | unread |  |
| `.github/workflows/osv-scanner.yml` | 141 | unread |  |
| `.github/workflows/provenance.yml` | 81 | unread |  |
| `.github/workflows/rust.yml` | 104 | unread |  |
| `.github/workflows/security-audit.yml` | 411 | unread |  |
| `.github/workflows/security-hardening.yml` | 847 | unread |  |
| `.github/workflows/semgrep.yml` | 136 | unread |  |
| `.github/workflows/semver.yml` | 150 | unread |  |
| `.github/workflows/solidity.yml` | 49 | unread |  |
| `.github/workflows/supply-chain-extra.yml` | 178 | unread |  |
| `.github/workflows/typos.yml` | 195 | unread |  |
| `.github/workflows/watchdog.yml` | 151 | unread |  |
| `.gitignore` | 9 | reviewed | Does not exclude secrets/ or data/. |
| `.gitleaks.toml` | 29 | unread |  |
| `.gitleaksignore` | 4 | unread |  |
| `.quality/deny.toml` | 136 | unread |  |
| `.quality/grype.yaml` | 41 | unread |  |
| `.quality/typos.toml` | 158 | unread |  |
| `Cargo.lock` | 6159 | excluded | generated lock file |
| `Cargo.toml` | 314 | partial 1-80 | Features and libp2p git pin. |
| `LICENSE.md` | 96 | unread |  |
| `README.md` | 498 | reviewed | Root dashboard. Opening paragraph does not use the K15 definition; line 282 runs a deleted shell script. |
| `README.tr.md` | 507 | unread |  |
| `assets/budlum-consensus-of-consensuses.png` | - | excluded | binary file |
| `assets/budlum-konsensuslerin-konsensusu.png` | - | excluded | binary file |
| `benches/domain_throughput.rs` | 715 | unread |  |
| `benches/micro/erasure_rows.rs` | 253 | unread |  |
| `benches/micro/merkle_scaling.rs` | 59 | unread |  |
| `benches/micro/merkle_update.rs` | 62 | unread |  |
| `benches/micro/ratio_rayon.rs` | 142 | unread |  |
| `benches/micro/sig_verify.rs` | 48 | unread |  |
| `benches/micro/timing_safe.rs` | 531 | unread |  |
| `benches/single_node/internal_pipeline_tps.rs` | 207 | unread |  |
| `bud/Cargo.lock` | 811 | excluded | generated lock file |
| `bud/Cargo.toml` | 104 | unread |  |
| `bud/FORMAT-V2.md` | 175 | unread |  |
| `bud/README.md` | 70 | unread |  |
| `bud/fuzz/Cargo.toml` | 23 | unread |  |
| `bud/fuzz/fuzz_bud_format.rs` | 112 | unread |  |
| `bud/kani/kani_bud_format.rs` | 53 | unread |  |
| `bud/mime.types.bud.json` | 15 | unread |  |
| `bud/src/bin/bud.rs` | 867 | unread |  |
| `bud/src/bin/measure_ratios.rs` | 315 | unread |  |
| `bud/src/bud3_live_test.rs` | 111 | unread |  |
| `bud/src/bud_fixed_point.rs` | 257 | unread |  |
| `bud/src/bud_format.rs` | 1309 | unread |  |
| `bud/src/bud_format_autozstd.rs` | 90 | unread |  |
| `bud/src/bud_format_av2.rs` | 108 | unread |  |
| `bud/src/bud_format_bft.rs` | 608 | unread |  |
| `bud/src/bud_format_block.rs` | 376 | unread |  |
| `bud/src/bud_format_bloom.rs` | 183 | unread |  |
| `bud/src/bud_format_catalog.rs` | 490 | unread |  |
| `bud/src/bud_format_checkpoint.rs` | 248 | unread |  |
| `bud/src/bud_format_columnar.rs` | 845 | unread |  |
| `bud/src/bud_format_container.rs` | 1227 | unread |  |
| `bud/src/bud_format_crop.rs` | 237 | unread |  |
| `bud/src/bud_format_culling.rs` | 326 | unread |  |
| `bud/src/bud_format_das.rs` | 401 | unread |  |
| `bud/src/bud_format_dbdelta.rs` | 100 | unread |  |
| `bud/src/bud_format_dedup.rs` | 150 | unread |  |
| `bud/src/bud_format_dictionary.rs` | 245 | unread |  |
| `bud/src/bud_format_economics.rs` | 578 | unread |  |
| `bud/src/bud_format_edge.rs` | 106 | unread |  |
| `bud/src/bud_format_edition.rs` | 222 | unread |  |
| `bud/src/bud_format_encpact.rs` | 98 | unread |  |
| `bud/src/bud_format_engine.rs` | 988 | unread |  |
| `bud/src/bud_format_erasure.rs` | 394 | unread |  |
| `bud/src/bud_format_exepdf.rs` | 451 | unread |  |
| `bud/src/bud_format_fastcdc.rs` | 324 | unread |  |
| `bud/src/bud_format_fidelitygate.rs` | 116 | unread |  |
| `bud/src/bud_format_fountain.rs` | 342 | unread |  |
| `bud/src/bud_format_genomic.rs` | 159 | unread |  |
| `bud/src/bud_format_governance.rs` | 219 | unread |  |
| `bud/src/bud_format_guardian.rs` | 296 | unread |  |
| `bud/src/bud_format_hardening.rs` | 231 | unread |  |
| `bud/src/bud_format_huffman.rs` | 486 | unread |  |
| `bud/src/bud_format_hw.rs` | 190 | unread |  |
| `bud/src/bud_format_integration.rs` | 251 | unread |  |
| `bud/src/bud_format_jpegre.rs` | 294 | unread |  |
| `bud/src/bud_format_lazyrepair.rs` | 161 | unread |  |
| `bud/src/bud_format_logfield.rs` | 552 | unread |  |
| `bud/src/bud_format_lowrank.rs` | 290 | unread |  |
| `bud/src/bud_format_lrc.rs` | 275 | unread |  |
| `bud/src/bud_format_markdown.rs` | 495 | unread |  |
| `bud/src/bud_format_matrix.rs` | 446 | unread |  |
| `bud/src/bud_format_media.rs` | 140 | unread |  |
| `bud/src/bud_format_model.rs` | 418 | unread |  |
| `bud/src/bud_format_msr.rs` | 357 | unread |  |
| `bud/src/bud_format_multifile.rs` | 524 | unread |  |
| `bud/src/bud_format_nvc.rs` | 264 | unread |  |
| `bud/src/bud_format_office.rs` | 476 | unread |  |
| `bud/src/bud_format_optical.rs` | 178 | unread |  |
| `bud/src/bud_format_optical_transfer.rs` | 224 | unread |  |
| `bud/src/bud_format_pact.rs` | 414 | unread |  |
| `bud/src/bud_format_pcap.rs` | 451 | unread |  |
| `bud/src/bud_format_pgm.rs` | 205 | unread |  |
| `bud/src/bud_format_pipe.rs` | 324 | unread |  |
| `bud/src/bud_format_pointcloud.rs` | 190 | unread |  |
| `bud/src/bud_format_por.rs` | 233 | unread |  |
| `bud/src/bud_format_prodcost.rs` | 185 | unread |  |
| `bud/src/bud_format_production.rs` | 259 | unread |  |
| `bud/src/bud_format_qos.rs` | 85 | unread |  |
| `bud/src/bud_format_qrmatrix.rs` | 242 | unread |  |
| `bud/src/bud_format_qrvideo.rs` | 843 | unread |  |
| `bud/src/bud_format_r3fix.rs` | 268 | unread |  |
| `bud/src/bud_format_ratioconsensus.rs` | 399 | unread |  |
| `bud/src/bud_format_real.rs` | 224 | unread |  |
| `bud/src/bud_format_realcorpus.rs` | 107 | unread |  |
| `bud/src/bud_format_recipe.rs` | 188 | unread |  |
| `bud/src/bud_format_recipe_record.rs` | 262 | unread |  |
| `bud/src/bud_format_regeneration.rs` | 319 | unread |  |
| `bud/src/bud_format_registry.rs` | 302 | unread |  |
| `bud/src/bud_format_repairband.rs` | 116 | unread |  |
| `bud/src/bud_format_revolutionary.rs` | 636 | unread |  |
| `bud/src/bud_format_scrub.rs` | 77 | unread |  |
| `bud/src/bud_format_secure_db.rs` | 88 | unread |  |
| `bud/src/bud_format_securededup.rs` | 136 | unread |  |
| `bud/src/bud_format_segment.rs` | 296 | unread |  |
| `bud/src/bud_format_serviceclass.rs` | 99 | unread |  |
| `bud/src/bud_format_shamir.rs` | 328 | unread |  |
| `bud/src/bud_format_social.rs` | 287 | unread |  |
| `bud/src/bud_format_social2.rs` | 252 | unread |  |
| `bud/src/bud_format_spec.rs` | 268 | unread |  |
| `bud/src/bud_format_telemetry.rs` | 176 | unread |  |
| `bud/src/bud_format_timeseries.rs` | 436 | unread |  |
| `bud/src/bud_format_tiny.rs` | 150 | unread |  |
| `bud/src/bud_format_transpile.rs` | 142 | unread |  |
| `bud/src/bud_format_tricore.rs` | 177 | unread |  |
| `bud/src/bud_format_ultra.rs` | 119 | unread |  |
| `bud/src/bud_format_ux.rs` | 280 | unread |  |
| `bud/src/bud_format_video.rs` | 363 | unread |  |
| `bud/src/bud_format_videopipe.rs` | 177 | unread |  |
| `bud/src/bud_format_view.rs` | 414 | unread |  |
| `bud/src/bud_format_wal.rs` | 224 | unread |  |
| `bud/src/bud_format_wire.rs` | 272 | unread |  |
| `bud/src/bud_format_zkbridge.rs` | 226 | unread |  |
| `bud/src/bud_format_zkproof.rs` | 351 | unread |  |
| `bud/src/churn.rs` | 258 | unread |  |
| `bud/src/cli.rs` | 149 | unread |  |
| `bud/src/fidelity.rs` | 154 | unread |  |
| `bud/src/gates.rs` | 243 | unread |  |
| `bud/src/lib.rs` | 229 | unread |  |
| `bud/src/price.rs` | 166 | unread |  |
| `bud/src/provider.rs` | 191 | unread |  |
| `bud/src/quantum.rs` | 125 | unread |  |
| `bud/src/quantum_chain.rs` | 456 | unread |  |
| `bud/src/ratio.rs` | 90 | unread |  |
| `bud/tests/fixtures/image.png` | - | excluded | binary file |
| `bud/tests/fixtures/text.log` | 2000 | excluded | test fixture data |
| `bud/tests/fixtures/video.yuv` | - | excluded | binary file |
| `bud/tests/test_bud2.rs` | 138 | unread |  |
| `bud/tests/test_integration.rs` | 583 | unread |  |
| `budzero/.gitignore` | 6 | unread |  |
| `budzero/ARCHITECTURE.md` | 32 | unread |  |
| `budzero/Cargo.lock` | 4272 | excluded | generated lock file |
| `budzero/Cargo.toml` | 39 | unread |  |
| `budzero/LICENSE` | 96 | unread |  |
| `budzero/README.md` | 139 | unread |  |
| `budzero/bud-cli/Cargo.toml` | 26 | unread |  |
| `budzero/bud-cli/src/main.rs` | 1476 | unread |  |
| `budzero/bud-cli/tests/toolchain_end_to_end.rs` | 407 | unread |  |
| `budzero/bud-compiler/Cargo.toml` | 20 | unread |  |
| `budzero/bud-compiler/src/ast.rs` | 109 | unread |  |
| `budzero/bud-compiler/src/codegen.rs` | 1046 | unread |  |
| `budzero/bud-compiler/src/ir/display.rs` | 272 | unread |  |
| `budzero/bud-compiler/src/ir/lower.rs` | 1092 | unread |  |
| `budzero/bud-compiler/src/ir/mod.rs` | 397 | unread |  |
| `budzero/bud-compiler/src/ir/verify.rs` | 767 | unread |  |
| `budzero/bud-compiler/src/lexer.rs` | 99 | unread |  |
| `budzero/bud-compiler/src/lib.rs` | 2196 | unread |  |
| `budzero/bud-compiler/src/parser.rs` | 930 | unread |  |
| `budzero/bud-compiler/src/sema.rs` | 947 | unread |  |
| `budzero/bud-isa/Cargo.toml` | 14 | unread |  |
| `budzero/bud-isa/src/lib.rs` | 636 | unread |  |
| `budzero/bud-node/Cargo.toml` | 39 | unread |  |
| `budzero/bud-node/src/bitswap.rs` | 485 | unread |  |
| `budzero/bud-node/src/discovery.rs` | 435 | unread |  |
| `budzero/bud-node/src/lib.rs` | 46 | unread |  |
| `budzero/bud-node/src/sharding.rs` | 238 | unread |  |
| `budzero/bud-node/src/store.rs` | 482 | unread |  |
| `budzero/bud-proof/Cargo.toml` | 48 | unread |  |
| `budzero/bud-proof/benches/canonical_programs.rs` | 293 | unread |  |
| `budzero/bud-proof/benches/proof_baseline.rs` | 106 | unread |  |
| `budzero/bud-proof/src/adapter.rs` | 508 | unread |  |
| `budzero/bud-proof/src/alarm_log.rs` | 356 | unread |  |
| `budzero/bud-proof/src/bud_stark/config.rs` | 149 | unread |  |
| `budzero/bud-proof/src/bud_stark/folder.rs` | 335 | unread |  |
| `budzero/bud-proof/src/bud_stark/mod.rs` | 37 | unread |  |
| `budzero/bud-proof/src/bud_stark/preprocessed.rs` | 70 | unread |  |
| `budzero/bud-proof/src/bud_stark/proof.rs` | 37 | unread |  |
| `budzero/bud-proof/src/bud_stark/prover.rs` | 620 | unread |  |
| `budzero/bud-proof/src/bud_stark/sub_builder.rs` | 174 | unread |  |
| `budzero/bud-proof/src/bud_stark/symbolic.rs` | 239 | unread |  |
| `budzero/bud-proof/src/bud_stark/verifier.rs` | 763 | unread |  |
| `budzero/bud-proof/src/canonical_boot.rs` | 412 | unread |  |
| `budzero/bud-proof/src/canonical_recovery.rs` | 155 | unread |  |
| `budzero/bud-proof/src/canonical_set.rs` | 156 | unread |  |
| `budzero/bud-proof/src/lib.rs` | 31 | unread |  |
| `budzero/bud-proof/src/plonky3_air.rs` | 3384 | unread |  |
| `budzero/bud-proof/src/plonky3_prover.rs` | 11648 | unread |  |
| `budzero/bud-proof/src/quarantine.rs` | 309 | unread |  |
| `budzero/bud-proof/src/relayer.rs` | 1061 | unread |  |
| `budzero/bud-proof/src/trace_layout_tests.rs` | 524 | unread |  |
| `budzero/bud-proof/src/transfer_verdict.rs` | 136 | unread |  |
| `budzero/bud-proof/tests/compiled_branching.rs` | 219 | unread |  |
| `budzero/bud-proof/tests/fiat_shamir_binding.rs` | 479 | unread |  |
| `budzero/bud-proof/tests/soundness_negatives.rs` | 260 | unread |  |
| `budzero/bud-state/Cargo.toml` | 19 | unread |  |
| `budzero/bud-state/src/lib.rs` | 614 | unread |  |
| `budzero/bud-state/src/note.rs` | 260 | unread |  |
| `budzero/bud-vm/Cargo.toml` | 17 | unread |  |
| `budzero/bud-vm/src/lib.rs` | 2691 | unread |  |
| `budzero/bud-vm/src/private_transfer.rs` | 186 | unread |  |
| `budzero/bud-vm/src/syscall_context.rs` | 118 | unread |  |
| `budzero/bud-vm/tests/trace_fixtures.rs` | 384 | unread |  |
| `budzero/control_flow.bud` | 17 | unread |  |
| `budzero/deny.toml` | 63 | unread |  |
| `budzero/docs/BudL_SPEC.md` | 486 | unread |  |
| `budzero/docs/README.md` | 46 | unread |  |
| `budzero/docs/STABILIZATION.md` | 382 | unread |  |
| `budzero/docs/adding_opcodes.md` | 115 | unread |  |
| `budzero/docs/advanced_language_features_and_memory_management.md` | 125 | unread |  |
| `budzero/docs/compiler_and_ecosystem.md` | 144 | unread |  |
| `budzero/docs/development.md` | 62 | unread |  |
| `budzero/docs/introduction.md` | 35 | unread |  |
| `budzero/docs/isa_and_bytecode.md` | 105 | unread |  |
| `budzero/docs/production_hardening_and_soundness.md` | 289 | unread |  |
| `budzero/docs/proof_format_release_checklist.md` | 46 | unread |  |
| `budzero/docs/prover_stabilization_and_tests.md` | 192 | unread |  |
| `budzero/docs/stark_and_plonky3.md` | 139 | unread |  |
| `budzero/docs/virtual_machine.md` | 213 | unread |  |
| `budzero/docs/vm_trace_schema.md` | 189 | unread |  |
| `budzero/docs/zk_friendly_architecture.md` | 65 | unread |  |
| `budzero/example.bud` | 16 | unread |  |
| `budzero/example2.bud` | 7 | unread |  |
| `budzero/example_loop.bud` | 23 | unread |  |
| `budzero/flake.lock` | 96 | unread |  |
| `budzero/flake.nix` | 36 | unread |  |
| `budzero/osv-scanner.toml` | 31 | unread |  |
| `budzero/rust-toolchain.toml` | 15 | unread |  |
| `budzero/state.json` | 73 | unread |  |
| `budzero/test_prover.bud` | 8 | unread |  |
| `budzero/verifier-registry/Cargo.toml` | 16 | unread |  |
| `budzero/verifier-registry/src/address.rs` | 55 | unread |  |
| `budzero/verifier-registry/src/evidence.rs` | 476 | unread |  |
| `budzero/verifier-registry/src/lib.rs` | 39 | unread |  |
| `budzero/verifier-registry/src/params.rs` | 148 | unread |  |
| `budzero/verifier-registry/src/registry.rs` | 1659 | unread |  |
| `budzero/verifier-registry/src/role.rs` | 136 | unread |  |
| `buf.yaml` | 25 | unread |  |
| `build.rs` | 38 | reviewed | Protobuf codegen; locates protoc. |
| `clippy.toml` | 18 | unread |  |
| `config/archive.toml` | 47 | unread |  |
| `config/devnet-genesis.json` | 26 | unread |  |
| `config/devnet.toml` | 41 | unread |  |
| `config/fixtures/real-chain.json` | 93 | excluded | test fixture data |
| `config/mainnet-genesis.json` | 119 | unread |  |
| `config/mainnet.toml` | 93 | unread |  |
| `config/personas/developer.toml` | 55 | unread |  |
| `config/personas/enterprise-poa.toml` | 68 | unread |  |
| `config/personas/user-devnet.toml` | 41 | unread |  |
| `config/testnet-genesis.json` | 32 | reviewed | Placeholder validators 0x40/0x41/0x42, no consensus keys, bud_tokenomics null. |
| `config/testnet.toml` | 54 | reviewed | Testnet profile. Public RPC requires API key; no bootnodes or DNS seeds. |
| `contracts/external-domain/BudlumFinalityVerifier.sol` | 646 | partial 1-20 | Quarantined; licence line reads "Polyfield" (B-11). |
| `crates/ai-inference/.gitignore` | 1 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/ARCHITECTURE.md` | 245 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/Cargo.lock` | 243 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/Cargo.toml` | 37 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/LICENSE.md` | 21 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/README.md` | 66 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-core/Cargo.toml` | 13 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-core/src/dataset.rs` | 197 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-core/src/lib.rs` | 14 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-core/src/manifest.rs` | 154 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-core/src/model.rs` | 160 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-core/src/system_prompt.rs` | 505 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-core/src/tier.rs` | 65 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-data/Cargo.toml` | 16 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-data/src/jsonl.rs` | 84 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-data/src/lib.rs` | 17 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-data/src/source.rs` | 104 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-data/src/template.rs` | 42 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-data/src/verify.rs` | 173 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-integrations/Cargo.toml` | 14 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-integrations/src/lib.rs` | 142 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-integrations/src/rest.rs` | 160 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-integrations/src/ws.rs` | 185 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-knowledge/Cargo.toml` | 15 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-knowledge/src/cache.rs` | 215 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-knowledge/src/chunk.rs` | 203 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-knowledge/src/context.rs` | 247 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-knowledge/src/embed.rs` | 280 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-knowledge/src/lib.rs` | 45 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-knowledge/src/memory.rs` | 372 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-knowledge/src/redact.rs` | 811 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-ops/Cargo.toml` | 22 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-ops/src/cli.rs` | 155 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-ops/src/logparse.rs` | 254 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-ops/src/main.rs` | 319 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/Cargo.toml` | 13 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/bridge.rs` | 672 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/chain.rs` | 67 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/config.rs` | 1024 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/cost_forecast.rs` | 553 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/fee_scenario.rs` | 589 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/health.rs` | 88 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/lib.rs` | 26 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/metric.rs` | 331 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/residency.rs` | 1116 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/staging.rs` | 350 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-serve/src/validator_cost.rs` | 449 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-tune/Cargo.toml` | 14 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-tune/data/ai-behaviour-curriculum.jsonl` | 10 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-tune/src/eval.rs` | 693 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-tune/src/lib.rs` | 14 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-tune/src/lock.rs` | 77 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-tune/src/plan.rs` | 120 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/ai-inference/crates/ai-tune/src/schema.rs` | 153 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `crates/bpqs/Cargo.lock` | 432 | excluded | generated lock file |
| `crates/bpqs/Cargo.toml` | 41 | unread |  |
| `crates/bpqs/SECURITY-ARGUMENT.md` | 578 | unread |  |
| `crates/bpqs/VERIFYMERKLE-EXPRESSIBILITY.md` | 163 | unread |  |
| `crates/bpqs/examples/bench_differential.rs` | 252 | unread |  |
| `crates/bpqs/examples/bench_perm.rs` | 82 | unread |  |
| `crates/bpqs/examples/checksum_domination_exact.expected.txt` | 29 | unread |  |
| `crates/bpqs/examples/checksum_domination_exact.rs` | 476 | unread |  |
| `crates/bpqs/examples/dudect_poseidon2.rs` | 969 | unread |  |
| `crates/bpqs/kat/bpqs-kat-v1.txt` | 13 | excluded | known-answer test vectors |
| `crates/bpqs/src/epoch.rs` | 75 | unread |  |
| `crates/bpqs/src/error.rs` | 74 | unread |  |
| `crates/bpqs/src/hash.rs` | 127 | unread |  |
| `crates/bpqs/src/lib.rs` | 95 | unread |  |
| `crates/bpqs/src/merkle.rs` | 214 | unread |  |
| `crates/bpqs/src/params.rs` | 144 | unread |  |
| `crates/bpqs/src/poseidon2.rs` | 698 | unread |  |
| `crates/bpqs/src/shake256.rs` | 166 | unread |  |
| `crates/bpqs/src/sign.rs` | 729 | unread |  |
| `crates/bpqs/src/tests.rs` | 183 | unread |  |
| `crates/bpqs/src/tests_backends.rs` | 430 | unread |  |
| `crates/bpqs/src/wots.rs` | 223 | unread |  |
| `crates/budscan/Cargo.lock` | 218 | excluded | generated lock file |
| `crates/budscan/Cargo.toml` | 57 | unread |  |
| `crates/budscan/README.md` | 128 | unread |  |
| `crates/budscan/browser/README.md` | 87 | unread |  |
| `crates/budscan/browser/l10n/en-US/budscan.ftl` | 43 | unread |  |
| `crates/budscan/browser/l10n/tr-TR/budscan.ftl` | 47 | unread |  |
| `crates/budscan/browser/mozconfig` | 77 | unread |  |
| `crates/budscan/browser/patches.txt` | 10 | unread |  |
| `crates/budscan/browser/patches/address-bar-verification-badge.patch` | 206 | unread |  |
| `crates/budscan/browser/patches/bud-protocol-handler.patch` | 496 | unread |  |
| `crates/budscan/browser/patches/name-bar-punycode.patch` | 219 | unread |  |
| `crates/budscan/browser/settings/budscan.cfg` | 85 | unread |  |
| `crates/budscan/browser/settings/policies.json` | 56 | unread |  |
| `crates/budscan/src/arweave.rs` | 230 | unread |  |
| `crates/budscan/src/bin/budscan.rs` | 184 | unread |  |
| `crates/budscan/src/bns_proof.rs` | 405 | unread |  |
| `crates/budscan/src/cid.rs` | 303 | unread |  |
| `crates/budscan/src/content_id.rs` | 136 | unread |  |
| `crates/budscan/src/ens.rs` | 211 | unread |  |
| `crates/budscan/src/evidence.rs` | 213 | unread |  |
| `crates/budscan/src/evm_audit.rs` | 303 | unread |  |
| `crates/budscan/src/fetch.rs` | 649 | unread |  |
| `crates/budscan/src/lib.rs` | 85 | unread |  |
| `crates/budscan/src/light_client.rs` | 463 | unread |  |
| `crates/budscan/src/name_rule.rs` | 343 | unread |  |
| `crates/budscan/src/patchset.rs` | 608 | unread |  |
| `crates/budscan/src/punycode.rs` | 185 | unread |  |
| `crates/budscan/src/query.rs` | 410 | unread |  |
| `crates/budscan/src/resolve.rs` | 579 | unread |  |
| `crates/budscan/src/search.rs` | 471 | unread |  |
| `crates/note-packing/Cargo.lock` | 7 | excluded | generated lock file |
| `crates/note-packing/Cargo.toml` | 15 | unread |  |
| `crates/note-packing/src/lib.rs` | 253 | unread |  |
| `crates/wallet-core/Cargo.lock` | 516 | excluded | generated lock file |
| `crates/wallet-core/Cargo.toml` | 69 | unread |  |
| `crates/wallet-core/README.md` | 38 | unread |  |
| `crates/wallet-core/src/bip39_wordlist.rs` | 255 | unread |  |
| `crates/wallet-core/src/lib.rs` | 2709 | unread |  |
| `crates/wallet-core/src/privacy_crypto.rs` | 614 | unread |  |
| `crates/wallet-core/src/privacy_transfer.rs` | 337 | unread |  |
| `crates/wallet-core/src/tee.rs` | 342 | unread |  |
| `docs/AI_VERIFICATION_STATUS.md` | 344 | unread |  |
| `docs/ARCHITECTURE.md` | 4043 | unread |  |
| `docs/BPQS_INDEPENDENT_REVIEW_CALL.md` | 96 | unread |  |
| `docs/BUD_CONTENT_ENCRYPTION.md` | 127 | unread |  |
| `docs/BUD_STORAGE_ROADMAP.md` | 512 | unread |  |
| `docs/CODE_OF_CONDUCT.md` | 128 | unread |  |
| `docs/CONTRIBUTING.md` | 251 | partial 1-12, 85-100, 150-160 | Layer-1 wording and deleted Python script references (B-21). |
| `docs/FSF_ADAPTATION_PLAN.md` | 101 | unread |  |
| `docs/FSF_PROJECT_FIT.md` | 53 | unread |  |
| `docs/NOTICE` | 81 | unread |  |
| `docs/PQ_ANCHOR_RESEARCH.md` | 103 | unread |  |
| `docs/PROVENANCE_NOTES.md` | 135 | unread |  |
| `docs/SECURITY.md` | 322 | unread |  |
| `docs/SPECIFICATION.md` | 144 | reviewed | Protocol spec v0.3. RPC table omits listener classes; says validators receive no emission. |
| `docs/VALIDATOR_ROLES.md` | 65 | reviewed | Role separation. Lists AI_OPERATOR (Lubot origin, see FINDINGS L-01). |
| `examples/print_genesis_hash.rs` | 20 | unread |  |
| `flake.lock` | 96 | excluded | generated lock file |
| `flake.nix` | 49 | unread |  |
| `fuzz/Cargo.lock` | 5728 | excluded | generated lock file |
| `fuzz/Cargo.toml` | 158 | unread |  |
| `fuzz/README.md` | 87 | unread |  |
| `fuzz/corpus/block_deserialize/seed_alt` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/block_deserialize/seed_empty` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/block_deserialize/seed_long` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/block_deserialize/seed_ones` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/block_deserialize/seed_seq` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/block_deserialize/seed_zeros` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/bpqs_wots_reject/seed-damaged.bin` | - | excluded | binary file |
| `fuzz/corpus/bpqs_wots_reject/seed-honest.bin` | - | excluded | binary file |
| `fuzz/corpus/budl_compile/control_flow.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile/example.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile/example2.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile/example_loop.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile/nested_parens.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile/test_prover.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile/unbalanced_parens.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile_then_run/control_flow.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile_then_run/example.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile_then_run/example2.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile_then_run/example_loop.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile_then_run/nested_parens.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/budl_compile_then_run/test_prover.bud` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed0` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed1` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed_alt` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed_deep_reorg` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed_empty` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed_long` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed_ones` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed_produce_few` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed_seq` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_state_transition/seed_zeros` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_validate/seed_alt` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_validate/seed_empty` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_validate/seed_long` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_validate/seed_ones` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_validate/seed_seq` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/consensus_validate/seed_zeros` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/evm_mpt_verify/empty-trie-frame` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/evm_rlp_decode/empty-list.rlp` | - | excluded | binary file |
| `fuzz/corpus/evm_rlp_decode/empty-string.rlp` | - | excluded | binary file |
| `fuzz/corpus/fuzz_blockchain_serialize/seed_alt` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/fuzz_blockchain_serialize/seed_empty` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/fuzz_blockchain_serialize/seed_long` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/fuzz_blockchain_serialize/seed_ones` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/fuzz_blockchain_serialize/seed_seq` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/fuzz_blockchain_serialize/seed_zeros` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed0` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed1` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed_alt` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed_empty` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed_lock_ops` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed_long` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed_ones` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed_seq` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed_sweep` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/relayer_escrow/seed_zeros` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/reputation/01_connect_ratelimit_disconnect.bin` | - | excluded | binary file |
| `fuzz/corpus/reputation/02_ban_then_unban.bin` | - | excluded | binary file |
| `fuzz/corpus/reputation/03_ban_expiry_cleanup.bin` | - | excluded | binary file |
| `fuzz/corpus/reputation/04_reconnect_storm.bin` | - | excluded | binary file |
| `fuzz/corpus/reputation/05_ops_on_unknown_peer.bin` | - | excluded | binary file |
| `fuzz/corpus/snapshot_deserialize/seed_alt` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/snapshot_deserialize/seed_empty` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/snapshot_deserialize/seed_long` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/snapshot_deserialize/seed_ones` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/snapshot_deserialize/seed_seq` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/snapshot_deserialize/seed_zeros` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/transaction_deserialize/seed_alt` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/transaction_deserialize/seed_empty` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/transaction_deserialize/seed_long` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/transaction_deserialize/seed_ones` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/transaction_deserialize/seed_seq` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/transaction_deserialize/seed_zeros` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/vm_execute/01_simple_add.bin` | - | excluded | binary file |
| `fuzz/corpus/vm_execute/02_branch_loop.bin` | - | excluded | binary file |
| `fuzz/corpus/vm_execute/03_verify_merkle_0x1E.bin` | - | excluded | binary file |
| `fuzz/corpus/vm_execute/04_poseidon_hash.bin` | - | excluded | binary file |
| `fuzz/corpus/vm_execute/05_memory_ops.bin` | - | excluded | binary file |
| `fuzz/corpus/zk_verifier/seed0` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/zk_verifier/seed1` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/zk_verifier/seed_alt` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/zk_verifier/seed_empty` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/zk_verifier/seed_long` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/zk_verifier/seed_ones` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/zk_verifier/seed_raw_mode0` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/zk_verifier/seed_seq` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/zk_verifier/seed_struct_mode` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/corpus/zk_verifier/seed_zeros` | - | excluded | fuzz seed corpus (input data, not source) |
| `fuzz/fuzz_targets/block_deserialize.rs` | 21 | unread |  |
| `fuzz/fuzz_targets/bpqs_wots_reject.rs` | 69 | unread |  |
| `fuzz/fuzz_targets/budl_compile.rs` | 56 | unread |  |
| `fuzz/fuzz_targets/budl_compile_then_run.rs` | 50 | unread |  |
| `fuzz/fuzz_targets/consensus_state_transition.rs` | 159 | unread |  |
| `fuzz/fuzz_targets/consensus_validate.rs` | 126 | unread |  |
| `fuzz/fuzz_targets/evm_mpt_verify.rs` | 41 | unread |  |
| `fuzz/fuzz_targets/evm_rlp_decode.rs` | 14 | unread |  |
| `fuzz/fuzz_targets/fuzz_blockchain_serialize.rs` | 44 | unread |  |
| `fuzz/fuzz_targets/relayer_escrow.rs` | 202 | unread |  |
| `fuzz/fuzz_targets/reputation.rs` | 52 | unread |  |
| `fuzz/fuzz_targets/snapshot_deserialize.rs` | 9 | unread |  |
| `fuzz/fuzz_targets/transaction_deserialize.rs` | 7 | unread |  |
| `fuzz/fuzz_targets/vm_execute.rs` | 90 | unread |  |
| `fuzz/fuzz_targets/zk_verifier.rs` | 177 | unread |  |
| `fuzz/osv-scanner.toml` | 42 | unread |  |
| `kani/Cargo.toml` | 34 | unread |  |
| `kani/src/lib.rs` | 1030 | unread |  |
| `ops/Dockerfile` | 166 | unread |  |
| `ops/budlum-core.service` | 64 | unread |  |
| `ops/docker-compose.ci.yml` | 55 | unread |  |
| `ops/docker-compose.yml` | 201 | unread |  |
| `ops/prometheus.yml` | 35 | unread |  |
| `ops/scripts/.gitkeep` | 0 | unread |  |
| `osv-scanner.toml` | 92 | unread |  |
| `proto/budlum/network/protocol.proto` | 735 | unread |  |
| `rust-toolchain.toml` | 5 | reviewed | Pins 1.97.1 with rustfmt and clippy. |
| `src/account_abstraction/mod.rs` | 39 | unread |  |
| `src/account_abstraction/private_transfer_auth.rs` | 332 | unread |  |
| `src/account_abstraction/quantum_account.rs` | 801 | unread |  |
| `src/account_abstraction/registry.rs` | 524 | unread |  |
| `src/account_abstraction/tee_attestation.rs` | 372 | unread |  |
| `src/account_abstraction/threshold_mldsa.rs` | 414 | unread |  |
| `src/ai/README.md` | 76 | unread |  |
| `src/ai/execution/guest.rs` | 1732 | unread |  |
| `src/ai/execution/mod.rs` | 35 | unread |  |
| `src/ai/execution/model_class.rs` | 118 | unread |  |
| `src/ai/execution/stark.rs` | 44 | unread |  |
| `src/ai/execution/verify.rs` | 839 | unread |  |
| `src/ai/mod.rs` | 5002 | unread |  |
| `src/ai/registry.rs` | 2171 | unread |  |
| `src/ai/types.rs` | 1496 | unread |  |
| `src/ai_inference/effort.rs` | 294 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/executor.rs` | 149 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/i18n.rs` | 647 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/inference.rs` | 270 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/metrics.rs` | 107 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/mod.rs` | 699 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/perception.rs` | 539 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/query.rs` | 59 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/social.rs` | 232 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/storage.rs` | 39 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/ai_inference/verify.rs` | 192 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/bin/bud.rs` | 686 | partial 340-365 | Transfer signed with Ed25519 KeyPair (V4) (B-09). |
| `src/bin/budlum-light.rs` | 268 | unread |  |
| `src/bin/budlum-relayer.rs` | 1269 | partial 1-30 | Crate-level allow of pedantic and nursery (B-21). |
| `src/bns/README.md` | 33 | unread |  |
| `src/bns/mod.rs` | 5 | unread |  |
| `src/bns/registry.rs` | 533 | unread |  |
| `src/bns/types.rs` | 93 | unread |  |
| `src/budlumxyz/README.md` | 31 | unread |  |
| `src/budlumxyz/mod.rs` | 633 | unread |  |
| `src/budlumxyz/types.rs` | 49 | unread |  |
| `src/chain/blockchain.rs` | 11283 | partial 1100-1160, 1830-1960, 2160-2330, 2500-2540, 3360-3440, 3755-3830, 5850-5940 | Out-of-block writers (B-02, B-03), global header (B-01), dev credit (B-07). |
| `src/chain/chain_actor.rs` | 5174 | unread |  |
| `src/chain/fee_market.rs` | 424 | unread |  |
| `src/chain/finality.rs` | 1956 | unread |  |
| `src/chain/genesis.rs` | 1716 | unread |  |
| `src/chain/mod.rs` | 7 | unread |  |
| `src/chain/snapshot.rs` | 2916 | unread |  |
| `src/chain/storage_economics_tests.rs` | 690 | unread |  |
| `src/cli/commands.rs` | 1655 | unread |  |
| `src/cli/mod.rs` | 2 | unread |  |
| `src/consensus/merkle_tree.rs` | 475 | unread |  |
| `src/consensus/mod.rs` | 402 | unread |  |
| `src/consensus/poa.rs` | 1037 | unread |  |
| `src/consensus/pos.rs` | 1698 | unread |  |
| `src/consensus/pow.rs` | 918 | unread |  |
| `src/consensus/qc.rs` | 1435 | unread |  |
| `src/consensus/split_resolver.rs` | 168 | unread |  |
| `src/core/account.rs` | 4779 | unread |  |
| `src/core/address.rs` | 87 | unread |  |
| `src/core/block.rs` | 911 | unread |  |
| `src/core/bounded_read.rs` | 428 | unread |  |
| `src/core/chain_config.rs` | 590 | partial 120-165 | Consensus params per network; min_stake in atoms (B-14). |
| `src/core/constitution.rs` | 383 | reviewed | Hard guardrails and two bounded parameters. MaxEmergencyHaltEpochs has no halt path (N-06). |
| `src/core/encoding.rs` | 181 | unread |  |
| `src/core/governance.rs` | 1556 | unread |  |
| `src/core/hash.rs` | 57 | unread |  |
| `src/core/map_keys.rs` | 436 | unread |  |
| `src/core/metrics.rs` | 364 | unread |  |
| `src/core/mod.rs` | 14 | unread |  |
| `src/core/money.rs` | 95 | unread |  |
| `src/core/transaction.rs` | 3043 | partial 270-520 | TransactionType enum; Turkish fragment in a doc comment (N-01). |
| `src/core/transaction_v4.txt` | 6 | unread |  |
| `src/cross_domain/bridge.rs` | 1700 | unread |  |
| `src/cross_domain/bridge_relayer.rs` | 767 | unread |  |
| `src/cross_domain/chain_adapter.rs` | 509 | unread |  |
| `src/cross_domain/event_tree.rs` | 233 | unread |  |
| `src/cross_domain/evm/README.md` | 78 | reviewed | EVM adapter status. Sync committee attestation optional in proof; F10.4 relayer after mainnet. |
| `src/cross_domain/evm/adapter.rs` | 1013 | unread |  |
| `src/cross_domain/evm/bud_to_eth.rs` | 252 | unread |  |
| `src/cross_domain/evm/header.rs` | 353 | unread |  |
| `src/cross_domain/evm/mod.rs` | 30 | unread |  |
| `src/cross_domain/evm/mpt.rs` | 733 | unread |  |
| `src/cross_domain/evm/receipt.rs` | 419 | unread |  |
| `src/cross_domain/evm/rlp.rs` | 559 | unread |  |
| `src/cross_domain/evm/sync_committee.rs` | 1471 | unread |  |
| `src/cross_domain/evm/verify.rs` | 1032 | unread |  |
| `src/cross_domain/external/domain_bridge.rs` | 443 | unread |  |
| `src/cross_domain/external/ethereum.rs` | 874 | unread |  |
| `src/cross_domain/external/evm_hybrid.rs` | 545 | unread |  |
| `src/cross_domain/external/intake.rs` | 1631 | unread |  |
| `src/cross_domain/external/intake_quorum.rs` | 880 | unread |  |
| `src/cross_domain/external/mod.rs` | 1147 | partial 1-400 | Module docs and re-exports; intake written outside block execution (B-02). |
| `src/cross_domain/external/profile.rs` | 220 | unread |  |
| `src/cross_domain/external/prover.rs` | 252 | unread |  |
| `src/cross_domain/external/quorum.rs` | 559 | unread |  |
| `src/cross_domain/external/registry.rs` | 1303 | unread |  |
| `src/cross_domain/external/selftest.rs` | 420 | unread |  |
| `src/cross_domain/external/spec.rs` | 454 | unread |  |
| `src/cross_domain/external/versioning.rs` | 373 | unread |  |
| `src/cross_domain/external/zkvm_proof.rs` | 824 | unread |  |
| `src/cross_domain/message.rs` | 269 | unread |  |
| `src/cross_domain/message_registry.rs` | 258 | unread |  |
| `src/cross_domain/mod.rs` | 31 | unread |  |
| `src/cross_domain/nonce.rs` | 302 | unread |  |
| `src/cross_domain/relayer.rs` | 876 | unread |  |
| `src/crypto/domain_tags.rs` | 391 | unread |  |
| `src/crypto/key_set_preimage.rs` | 278 | unread |  |
| `src/crypto/mainnet_policy.rs` | 345 | unread |  |
| `src/crypto/mod.rs` | 17 | unread |  |
| `src/crypto/pkcs11.rs` | 1191 | unread |  |
| `src/crypto/primitives.rs` | 1333 | unread |  |
| `src/crypto/signer.rs` | 153 | unread |  |
| `src/deed/mod.rs` | 195 | unread |  |
| `src/developer_os.rs` | 529 | unread |  |
| `src/domain/commitment_registry.rs` | 184 | unread |  |
| `src/domain/deal_open.rs` | 808 | unread |  |
| `src/domain/finality_adapter.rs` | 1855 | unread |  |
| `src/domain/fork_choice.rs` | 385 | unread |  |
| `src/domain/mod.rs` | 54 | unread |  |
| `src/domain/plugin.rs` | 284 | unread |  |
| `src/domain/plugin_registry.rs` | 220 | unread |  |
| `src/domain/regen_health.rs` | 590 | unread |  |
| `src/domain/regeneration_stage.rs` | 1424 | unread |  |
| `src/domain/registry.rs` | 730 | unread |  |
| `src/domain/sovereign.rs` | 675 | unread |  |
| `src/domain/storage_deal.rs` | 9176 | unread |  |
| `src/domain/storage_params.rs` | 202 | unread |  |
| `src/domain/storage_tx.rs` | 1203 | unread |  |
| `src/domain/types.rs` | 586 | unread |  |
| `src/error.rs` | 91 | unread |  |
| `src/execution/executor.rs` | 3292 | partial 2191-2290 | Privacy note insertion and private transfer arms (N-05). |
| `src/execution/mod.rs` | 3 | unread |  |
| `src/execution/proof_verifier.rs` | 637 | unread |  |
| `src/execution/zkvm.rs` | 861 | unread |  |
| `src/gateway/atlas.rs` | 695 | unread |  |
| `src/gateway/mod.rs` | 15 | unread |  |
| `src/gateway/passport.rs` | 540 | unread |  |
| `src/gateway/service.rs` | 714 | unread |  |
| `src/lib.rs` | 89 | unread |  |
| `src/light_client/mod.rs` | 1034 | unread |  |
| `src/main.rs` | 1849 | partial 835-860, 1068-1098, 1260-1290, 1640-1665 | HSM VRF refusal (B-13), PoA bootstrap frozen (B-19), memory content store (B-15), EVM relay off (B-10). |
| `src/mempool/mod.rs` | 1 | unread |  |
| `src/mempool/pool.rs` | 1369 | unread |  |
| `src/network/gossip_dedup.rs` | 792 | unread |  |
| `src/network/mobile.rs` | 785 | unread |  |
| `src/network/mod.rs` | 13 | unread |  |
| `src/network/node.rs` | 4383 | unread |  |
| `src/network/peer_manager.rs` | 1567 | unread |  |
| `src/network/privacy.rs` | 518 | unread |  |
| `src/network/proto_conversions.rs` | 2847 | unread |  |
| `src/network/protocol.rs` | 375 | unread |  |
| `src/network/regen_health_tick.rs` | 410 | unread |  |
| `src/network/sync_codec.rs` | 121 | unread |  |
| `src/pollen/README.md` | 51 | unread |  |
| `src/pollen/content_gate.rs` | 536 | unread |  |
| `src/pollen/data_rights.rs` | 773 | unread |  |
| `src/pollen/mod.rs` | 299 | unread |  |
| `src/pollen/offers.rs` | 1629 | unread |  |
| `src/privacy/mod.rs` | 12 | unread |  |
| `src/privacy/note_registry.rs` | 684 | unread |  |
| `src/privacy/submit.rs` | 207 | unread |  |
| `src/prover/mod.rs` | 476 | unread |  |
| `src/registry/d4_merge_tests.rs` | 217 | unread |  |
| `src/registry/evidence.rs` | 1187 | unread |  |
| `src/registry/identity.rs` | 2357 | unread |  |
| `src/registry/identity_fill.rs` | 1020 | unread |  |
| `src/registry/invalid_vote.rs` | 311 | unread |  |
| `src/registry/liveness.rs` | 279 | unread |  |
| `src/registry/mod.rs` | 73 | unread |  |
| `src/registry/params.rs` | 779 | unread |  |
| `src/registry/permissionless.rs` | 1846 | unread |  |
| `src/registry/poa_compliance.rs` | 552 | unread |  |
| `src/registry/poa_membership.rs` | 438 | unread |  |
| `src/registry/poa_onboarding.rs` | 777 | unread |  |
| `src/registry/quarantine_ledger.rs` | 198 | unread |  |
| `src/registry/role.rs` | 179 | unread |  |
| `src/relayer/mod.rs` | 7 | unread |  |
| `src/relayer/policy.rs` | 985 | partial 1-140 | Intent and bid primitives; unwired (B-10). |
| `src/relayer/worker.rs` | 1993 | unread |  |
| `src/rpc/api.rs` | 1312 | unread |  |
| `src/rpc/mod.rs` | 6 | unread |  |
| `src/rpc/server.rs` | 7643 | partial 2640-2730, 2905-2965 | Operator-gated consensus writers (B-02), sealGlobalHeader (B-01). |
| `src/rpc/tests.rs` | 1444 | unread |  |
| `src/sdk/mod.rs` | 252 | unread |  |
| `src/settlement/cold_quorum.rs` | 678 | unread |  |
| `src/settlement/cold_wallet.rs` | 1365 | unread |  |
| `src/settlement/commitment_tree.rs` | 66 | unread |  |
| `src/settlement/global_block.rs` | 325 | unread |  |
| `src/settlement/mod.rs` | 42 | unread |  |
| `src/settlement/pq_anchor.rs` | 1078 | unread |  |
| `src/settlement/pq_anchor_verify.rs` | 162 | unread |  |
| `src/settlement/proof_market.rs` | 1711 | unread |  |
| `src/settlement/proof_verifier.rs` | 240 | unread |  |
| `src/sharding/mod.rs` | 398 | unread |  |
| `src/socialfi/README.md` | 38 | unread |  |
| `src/socialfi/mod.rs` | 448 | unread |  |
| `src/socialfi/types.rs` | 39 | unread |  |
| `src/socialfi/vault.rs` | 768 | unread |  |
| `src/storage/README.md` | 168 | unread |  |
| `src/storage/assignment.rs` | 631 | unread |  |
| `src/storage/content_id.rs` | 217 | unread |  |
| `src/storage/db.rs` | 2805 | unread |  |
| `src/storage/derived.rs` | 1414 | unread |  |
| `src/storage/dictionary.rs` | 744 | unread |  |
| `src/storage/emit.rs` | 1833 | unread |  |
| `src/storage/erasure.rs` | 1605 | unread |  |
| `src/storage/fixed_point.rs` | 242 | unread |  |
| `src/storage/generated.rs` | 1653 | unread |  |
| `src/storage/lifecycle.rs` | 172 | unread |  |
| `src/storage/living_threshold.rs` | 1350 | unread |  |
| `src/storage/lrc.rs` | 583 | unread |  |
| `src/storage/manifest.rs` | 1505 | unread |  |
| `src/storage/merkle_trie.rs` | 808 | unread |  |
| `src/storage/mobile_self.rs` | 701 | unread |  |
| `src/storage/mod.rs` | 202 | unread |  |
| `src/storage/msr.rs` | 206 | unread |  |
| `src/storage/one_share.rs` | 335 | unread |  |
| `src/storage/one_view.rs` | 216 | unread |  |
| `src/storage/pact_binding.rs` | 342 | unread |  |
| `src/storage/payload_crypt.rs` | 323 | unread |  |
| `src/storage/provider.rs` | 720 | unread |  |
| `src/storage/pruning.rs` | 210 | unread |  |
| `src/storage/qr_carousel.rs` | 1677 | unread |  |
| `src/storage/qr_codec.rs` | 282 | unread |  |
| `src/storage/qr_encode.rs` | 1042 | unread |  |
| `src/storage/qr_frame.rs` | 427 | unread |  |
| `src/storage/qr_matrix.rs` | 278 | unread |  |
| `src/storage/qr_payload.rs` | 560 | unread |  |
| `src/storage/qr_png.rs` | 343 | unread |  |
| `src/storage/qr_receive.rs` | 405 | unread |  |
| `src/storage/qr_recipe.rs` | 371 | unread |  |
| `src/storage/qr_reemit.rs` | 316 | unread |  |
| `src/storage/qr_verify.rs` | 410 | unread |  |
| `src/storage/qr_verify_indep.rs` | 939 | unread |  |
| `src/storage/qr_video.rs` | 1077 | unread |  |
| `src/storage/render.rs` | 1155 | unread |  |
| `src/storage/reveal_gateway.rs` | 1090 | unread |  |
| `src/storage/server_admission.rs` | 149 | unread |  |
| `src/storage/social_delete.rs` | 171 | unread |  |
| `src/storage/three_gate.rs` | 158 | unread |  |
| `src/storage/three_hooks.rs` | 90 | unread |  |
| `src/storage/three_meter.rs` | 152 | unread |  |
| `src/storage/three_nft.rs` | 534 | unread |  |
| `src/storage/three_pipe.rs` | 670 | unread |  |
| `src/storage/three_recipe.rs` | 860 | unread |  |
| `src/storage/three_regime.rs` | 279 | unread |  |
| `src/storage/three_reveal.rs` | 224 | unread |  |
| `src/storage/three_rpc.rs` | 370 | unread |  |
| `src/storage/three_visibility.rs` | 72 | unread |  |
| `src/storage/traits.rs` | 324 | unread |  |
| `src/storage/transformed.rs` | 703 | unread |  |
| `src/storage/view_grant.rs` | 1196 | unread |  |
| `src/tests/adversarial_p2p.rs` | 131 | unread |  |
| `src/tests/advisory_reachability.rs` | 560 | unread |  |
| `src/tests/ai_inference_runtime.rs` | 939 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `src/tests/ai_verification_status_locks.rs` | 350 | unread |  |
| `src/tests/audit_findings_locks.rs` | 282 | unread |  |
| `src/tests/audit_p49_locks.rs` | 236 | unread |  |
| `src/tests/bench_performance.rs` | 163 | unread |  |
| `src/tests/block_clock.rs` | 58 | unread |  |
| `src/tests/block_reward.rs` | 92 | unread |  |
| `src/tests/blockchair_fixture_locks.rs` | 847 | unread |  |
| `src/tests/bns.rs` | 59 | unread |  |
| `src/tests/bns_expanded.rs` | 283 | unread |  |
| `src/tests/bridge_lifecycle.rs` | 439 | unread |  |
| `src/tests/bridge_negatives.rs` | 259 | unread |  |
| `src/tests/bud_e2e.rs` | 704 | unread |  |
| `src/tests/byzantine_settlement.rs` | 1202 | unread |  |
| `src/tests/chain_id_registry_locks.rs` | 391 | unread |  |
| `src/tests/chaos.rs` | 1122 | unread |  |
| `src/tests/consensus_bypass_locks.rs` | 274 | partial 40-175 | Dev credit refusals pinned on mainnet only. |
| `src/tests/consensus_digest.rs` | 173 | unread |  |
| `src/tests/consensus_expanded.rs` | 132 | unread |  |
| `src/tests/consensus_lock_order_loom.rs` | 293 | unread |  |
| `src/tests/constitution_engine.rs` | 62 | unread |  |
| `src/tests/deed.rs` | 36 | unread |  |
| `src/tests/disaster_recovery.rs` | 423 | unread |  |
| `src/tests/distributed_settlement.rs` | 430 | unread |  |
| `src/tests/domain_edge_cases.rs` | 331 | unread |  |
| `src/tests/encryption_dao.rs` | 90 | unread |  |
| `src/tests/f20_priority_findings.rs` | 333 | unread |  |
| `src/tests/finality_adversarial.rs` | 1478 | unread |  |
| `src/tests/finality_live_path.rs` | 306 | unread |  |
| `src/tests/fork_choice_locks.rs` | 412 | unread |  |
| `src/tests/genesis_repro.rs` | 145 | unread |  |
| `src/tests/hard_prune.rs` | 156 | unread |  |
| `src/tests/hardening.rs` | 368 | unread |  |
| `src/tests/hardening_h2_locks.rs` | 132 | unread |  |
| `src/tests/hardening_h4_locks.rs` | 187 | unread |  |
| `src/tests/hardening_h5_h7_locks.rs` | 229 | unread |  |
| `src/tests/hardening_locks.rs` | 295 | unread |  |
| `src/tests/hash_input_serialize_locks.rs` | 134 | unread |  |
| `src/tests/identity_tx_door.rs` | 213 | unread |  |
| `src/tests/integration.rs` | 1978 | unread |  |
| `src/tests/liveness_consensus.rs` | 475 | unread |  |
| `src/tests/load_test.rs` | 205 | unread |  |
| `src/tests/manifest_commitment_locks.rs` | 1616 | unread |  |
| `src/tests/mempool_dos_locks.rs` | 189 | unread |  |
| `src/tests/migration_v2.rs` | 117 | unread |  |
| `src/tests/mod.rs` | 219 | unread |  |
| `src/tests/multi_consensus_locks.rs` | 420 | unread |  |
| `src/tests/network_hardening_locks.rs` | 567 | unread |  |
| `src/tests/operator_kill_chaos.rs` | 367 | unread |  |
| `src/tests/p01_consensus_rounds.rs` | 382 | unread |  |
| `src/tests/permissionless.rs` | 1115 | unread |  |
| `src/tests/permissionless_e2e.rs` | 69 | unread |  |
| `src/tests/persistence.rs` | 366 | unread |  |
| `src/tests/poa_isolation.rs` | 563 | unread |  |
| `src/tests/poa_onboarding_matrix.rs` | 246 | unread |  |
| `src/tests/poisoned_lock_locks.rs` | 244 | unread |  |
| `src/tests/pollen_ai_data_rights.rs` | 465 | unread |  |
| `src/tests/ported_slice_redteam.rs` | 705 | unread |  |
| `src/tests/pow_light_client.rs` | 328 | unread |  |
| `src/tests/privacy_ai_execution.rs` | 416 | unread |  |
| `src/tests/private_transfer_fee_market.rs` | 62 | unread |  |
| `src/tests/proptest_core.rs` | 49 | unread |  |
| `src/tests/prover.rs` | 732 | unread |  |
| `src/tests/qcblob_quorum.rs` | 209 | unread |  |
| `src/tests/real_chain_fixtures.rs` | 295 | unread |  |
| `src/tests/regeneration_recovery.rs` | 240 | unread |  |
| `src/tests/regression_lock.rs` | 723 | unread |  |
| `src/tests/relayer_e2e.rs` | 556 | unread |  |
| `src/tests/relayer_gates.rs` | 496 | unread |  |
| `src/tests/relayer_liveness.rs` | 663 | unread |  |
| `src/tests/relayer_worker_locks.rs` | 905 | unread |  |
| `src/tests/replay_audit.rs` | 207 | unread |  |
| `src/tests/security_auditor.rs` | 81 | unread |  |
| `src/tests/settlement_prod.rs` | 2319 | unread |  |
| `src/tests/sharding_e2e.rs` | 157 | unread |  |
| `src/tests/slashing_matrix.rs` | 286 | unread |  |
| `src/tests/snapshot_chaos.rs` | 475 | unread |  |
| `src/tests/socialfi.rs` | 248 | unread |  |
| `src/tests/storage_tx_door.rs` | 1030 | unread |  |
| `src/tests/target_700.rs` | 102 | unread |  |
| `src/tests/tokenomics.rs` | 688 | unread |  |
| `src/tests/tokenomics_proptest.rs` | 248 | unread |  |
| `src/tests/v95_v98_canaries.rs` | 81 | unread |  |
| `src/tests/vault_tx_door.rs` | 297 | unread |  |
| `src/tests/wall_clock_locks.rs` | 197 | unread |  |
| `src/tests/zkvm.rs` | 255 | unread |  |
| `src/tokenomics/mod.rs` | 800 | partial 20-40 | BUD_DECIMALS = 6, BUD_UNIT = 1e6. |
| `src/tokenomics/reward_pool.rs` | 219 | partial 1-40 | Pool schedule; unwired (B-12). |
| `supply-chain/audits.toml` | 193 | unread |  |
| `supply-chain/config.toml` | 114 | unread |  |
| `supply-chain/imports.lock` | 1946 | excluded | generated lock file |
| `xtask/gates/Cargo.lock` | 118 | excluded | generated lock file |
| `xtask/gates/Cargo.toml` | 27 | unread |  |
| `xtask/gates/pins/budzero-tree.pins` | 82 | unread |  |
| `xtask/gates/src/gates/accumulators_pinned.rs` | 369 | unread |  |
| `xtask/gates/src/gates/actionlint.rs` | 68 | unread |  |
| `xtask/gates/src/gates/ai_inference_prompt_is_true.rs` | 1030 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `xtask/gates/src/gates/ai_inference_reads.rs` | 227 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `xtask/gates/src/gates/ai_inference_zk.rs` | 238 | excluded | Lubot (directive section 3.2; renamed from lubot in b7d4b86) |
| `xtask/gates/src/gates/air_selectors.rs` | 406 | unread |  |
| `xtask/gates/src/gates/ast_security_gates.rs` | 1131 | unread |  |
| `xtask/gates/src/gates/badges_current.rs` | 375 | unread |  |
| `xtask/gates/src/gates/binding_claims.rs` | 280 | unread |  |
| `xtask/gates/src/gates/bit_decompositions.rs` | 629 | unread |  |
| `xtask/gates/src/gates/bns_gate.rs` | 28 | unread |  |
| `xtask/gates/src/gates/bns_names_are_safe_in_an_address_bar.rs` | 313 | unread |  |
| `xtask/gates/src/gates/bridge_dual_tree.rs` | 179 | unread |  |
| `xtask/gates/src/gates/bud_e2e.rs` | 31 | unread |  |
| `xtask/gates/src/gates/budscan_parity.rs` | 322 | unread |  |
| `xtask/gates/src/gates/budscan_patchset.rs` | 474 | unread |  |
| `xtask/gates/src/gates/capability_modules_are_wired.rs` | 1266 | unread |  |
| `xtask/gates/src/gates/cargo_vet.rs` | 192 | unread |  |
| `xtask/gates/src/gates/chain_id_is_not_hardcoded.rs` | 342 | unread |  |
| `xtask/gates/src/gates/ci_workflow_guards.rs` | 447 | unread |  |
| `xtask/gates/src/gates/clippy_extra.rs` | 162 | unread |  |
| `xtask/gates/src/gates/coding_audit_samples_the_relationship.rs` | 750 | unread |  |
| `xtask/gates/src/gates/consensus_maps_ordered.rs` | 819 | unread |  |
| `xtask/gates/src/gates/consensus_state_only_changes_in_blocks.rs` | 328 | partial 1-140 | Existing in-block gate (nonce writes only). |
| `xtask/gates/src/gates/containment_defaults.rs` | 184 | unread |  |
| `xtask/gates/src/gates/content_encryption_is_declared_and_bound.rs` | 855 | unread |  |
| `xtask/gates/src/gates/coverage.rs` | 159 | unread |  |
| `xtask/gates/src/gates/cross_table_checks.rs` | 192 | unread |  |
| `xtask/gates/src/gates/dead_pub_api.rs` | 466 | unread |  |
| `xtask/gates/src/gates/derived_content.rs` | 170 | unread |  |
| `xtask/gates/src/gates/docker_toolchain.rs` | 374 | unread |  |
| `xtask/gates/src/gates/domain_tags.rs` | 353 | unread |  |
| `xtask/gates/src/gates/economy_invariants.rs` | 46 | unread |  |
| `xtask/gates/src/gates/every_fuzz_target_is_run.rs` | 394 | unread |  |
| `xtask/gates/src/gates/every_opcode_forgery.rs` | 358 | unread |  |
| `xtask/gates/src/gates/evidence_provenance.rs` | 528 | unread |  |
| `xtask/gates/src/gates/exact_named_tests.rs` | 95 | unread |  |
| `xtask/gates/src/gates/fixture_integrity.rs` | 132 | unread |  |
| `xtask/gates/src/gates/forgery_tests.rs` | 357 | unread |  |
| `xtask/gates/src/gates/fork_choice_gate.rs` | 34 | unread |  |
| `xtask/gates/src/gates/fsf_import_boundaries.rs` | 509 | unread |  |
| `xtask/gates/src/gates/fuzz_targets_wired.rs` | 225 | unread |  |
| `xtask/gates/src/gates/gas_calibration.rs` | 315 | unread |  |
| `xtask/gates/src/gates/gates_are_wired.rs` | 544 | unread |  |
| `xtask/gates/src/gates/gates_do_not_panic.rs` | 475 | unread |  |
| `xtask/gates/src/gates/gating_flags.rs` | 177 | unread |  |
| `xtask/gates/src/gates/geiger.rs` | 219 | unread |  |
| `xtask/gates/src/gates/generated_content.rs` | 255 | unread |  |
| `xtask/gates/src/gates/genesis_schema.rs` | 300 | unread |  |
| `xtask/gates/src/gates/git_deps_audited.rs` | 194 | unread |  |
| `xtask/gates/src/gates/gov_slash_evidence_is_validator_only.rs` | 509 | unread |  |
| `xtask/gates/src/gates/governance_invariants.rs` | 26 | unread |  |
| `xtask/gates/src/gates/guards_reachable.rs` | 368 | unread |  |
| `xtask/gates/src/gates/hash_inputs_are_length_prefixed.rs` | 854 | unread |  |
| `xtask/gates/src/gates/indexing_is_not_new.rs` | 373 | unread |  |
| `xtask/gates/src/gates/kani.rs` | 494 | unread |  |
| `xtask/gates/src/gates/license_consistency.rs` | 463 | unread |  |
| `xtask/gates/src/gates/lock_failures.rs` | 256 | unread |  |
| `xtask/gates/src/gates/logup_multipliers.rs` | 296 | unread |  |
| `xtask/gates/src/gates/master_derivation.rs` | 104 | unread |  |
| `xtask/gates/src/gates/mempool_mev_free.rs` | 211 | unread |  |
| `xtask/gates/src/gates/mermaid.rs` | 534 | unread |  |
| `xtask/gates/src/gates/metrics_are_written.rs` | 796 | unread |  |
| `xtask/gates/src/gates/minting_paths_are_counted.rs` | 413 | unread |  |
| `xtask/gates/src/gates/module_coverage.rs` | 460 | unread |  |
| `xtask/gates/src/gates/multi_ratio_consensus.rs` | 289 | unread |  |
| `xtask/gates/src/gates/named_tests.rs` | 146 | unread |  |
| `xtask/gates/src/gates/network_hardening_gate.rs` | 42 | unread |  |
| `xtask/gates/src/gates/no_conflict_markers.rs` | 323 | unread |  |
| `xtask/gates/src/gates/no_idle_code.rs` | 1923 | unread |  |
| `xtask/gates/src/gates/no_new_shell_gates.rs` | 246 | unread |  |
| `xtask/gates/src/gates/no_orphan_source_files.rs` | 915 | unread |  |
| `xtask/gates/src/gates/no_unicode_dashes.rs` | 327 | unread |  |
| `xtask/gates/src/gates/no_upstream_brands.rs` | 404 | unread |  |
| `xtask/gates/src/gates/node_classification_gate.rs` | 26 | unread |  |
| `xtask/gates/src/gates/one_house_guards.rs` | 480 | unread |  |
| `xtask/gates/src/gates/ownerless_dependencies.rs` | 160 | unread |  |
| `xtask/gates/src/gates/paid_content.rs` | 698 | unread |  |
| `xtask/gates/src/gates/parallel_execution.rs` | 557 | unread |  |
| `xtask/gates/src/gates/pinned_downloads.rs` | 289 | unread |  |
| `xtask/gates/src/gates/poa_compliance_gate.rs` | 30 | unread |  |
| `xtask/gates/src/gates/proof_deps_are_exactly_pinned.rs` | 223 | unread |  |
| `xtask/gates/src/gates/qr_is_derivative_only.rs` | 183 | unread |  |
| `xtask/gates/src/gates/quantum_account.rs` | 203 | unread |  |
| `xtask/gates/src/gates/readme_no_deny.rs` | 151 | unread |  |
| `xtask/gates/src/gates/reduction_claims.rs` | 204 | unread |  |
| `xtask/gates/src/gates/refusals_no_mutate.rs` | 587 | unread |  |
| `xtask/gates/src/gates/regen_health_door.rs` | 365 | unread |  |
| `xtask/gates/src/gates/regeneration.rs` | 1631 | unread |  |
| `xtask/gates/src/gates/rejection_tests.rs` | 496 | unread |  |
| `xtask/gates/src/gates/relay.rs` | 663 | unread |  |
| `xtask/gates/src/gates/release_profile_pins.rs` | 245 | unread |  |
| `xtask/gates/src/gates/repair_fires.rs` | 175 | unread |  |
| `xtask/gates/src/gates/required_tests.rs` | 317 | unread |  |
| `xtask/gates/src/gates/rust_literals.rs` | 330 | unread |  |
| `xtask/gates/src/gates/security_parameters.rs` | 1074 | unread |  |
| `xtask/gates/src/gates/security_scans_can_fail.rs` | 529 | unread |  |
| `xtask/gates/src/gates/self_derived_ids_cover_every_field.rs` | 747 | unread |  |
| `xtask/gates/src/gates/semver.rs` | 924 | unread |  |
| `xtask/gates/src/gates/serialize_map_keys_are_strings.rs` | 703 | unread |  |
| `xtask/gates/src/gates/shard_placement.rs` | 609 | unread |  |
| `xtask/gates/src/gates/slash_expression.rs` | 559 | unread |  |
| `xtask/gates/src/gates/source_reading.rs` | 237 | unread |  |
| `xtask/gates/src/gates/storage_penalties.rs` | 594 | unread |  |
| `xtask/gates/src/gates/storage_priced.rs` | 251 | unread |  |
| `xtask/gates/src/gates/storage_proof_boundary.rs` | 148 | unread |  |
| `xtask/gates/src/gates/storage_provider_gate.rs` | 30 | unread |  |
| `xtask/gates/src/gates/suppressions_are_justified.rs` | 823 | unread |  |
| `xtask/gates/src/gates/tee_trust_boundary_is_structural.rs` | 549 | unread |  |
| `xtask/gates/src/gates/test_modules_can_see_what_they_test.rs` | 378 | unread |  |
| `xtask/gates/src/gates/the_image_builds_what_the_manifest_declares.rs` | 253 | unread |  |
| `xtask/gates/src/gates/three_is_recipe_only.rs` | 127 | unread |  |
| `xtask/gates/src/gates/threshold_rates.rs` | 625 | unread |  |
| `xtask/gates/src/gates/timing_safe.rs` | 223 | unread |  |
| `xtask/gates/src/gates/transcript_mirrors.rs` | 216 | unread |  |
| `xtask/gates/src/gates/tree_is_english.rs` | 1164 | partial 1-60, 147-306 | English tree ratchet and vocabulary. |
| `xtask/gates/src/gates/tree_pin.rs` | 406 | unread |  |
| `xtask/gates/src/gates/typos.rs` | 113 | unread |  |
| `xtask/gates/src/gates/udeps.rs` | 211 | unread |  |
| `xtask/gates/src/gates/uncheckable_proof.rs` | 196 | unread |  |
| `xtask/gates/src/gates/untrusted_manifests.rs` | 646 | unread |  |
| `xtask/gates/src/gates/value_transfers.rs` | 618 | unread |  |
| `xtask/gates/src/gates/wallet_core_gate.rs` | 58 | unread |  |
| `xtask/gates/src/gates/wallet_node_address_agree.rs` | 382 | unread |  |
| `xtask/gates/src/gates/wire_fields_are_signed.rs` | 912 | unread |  |
| `xtask/gates/src/gates/workflows_produce_jobs.rs` | 670 | unread |  |
| `xtask/gates/src/gates/zero_address_sender_is_verified.rs` | 424 | unread |  |
| `xtask/gates/src/gates/zero_storage_frozen.rs` | 239 | unread |  |
| `xtask/gates/src/gates/zero_tests_witness.rs` | 308 | unread |  |
| `xtask/gates/src/gates/zizmor.rs` | 239 | unread |  |
| `xtask/gates/src/gates/zkvm_immune_regeneration.rs` | 317 | unread |  |
| `xtask/gates/src/main.rs` | 1420 | partial 1-80, 180-420, 1250-1420 | Gate table and dispatcher. |
| `xtask/tools/Cargo.lock` | 7 | excluded | generated lock file |
| `xtask/tools/Cargo.toml` | 20 | unread |  |
| `xtask/tools/src/audit_deps.rs` | 273 | unread |  |
| `xtask/tools/src/audit_guard.rs` | 768 | unread |  |
| `xtask/tools/src/backup_drill.rs` | 347 | unread |  |
| `xtask/tools/src/bin/budlum-tools.rs` | 184 | unread |  |
| `xtask/tools/src/clippy_extra_report.rs` | 213 | unread |  |
| `xtask/tools/src/devnet.rs` | 243 | unread |  |
| `xtask/tools/src/docker_smoke.rs` | 388 | unread |  |
| `xtask/tools/src/fsf_fit.rs` | 417 | unread |  |
| `xtask/tools/src/json.rs` | 362 | unread |  |
| `xtask/tools/src/lib.rs` | 301 | unread |  |
| `xtask/tools/src/multinode_smoke.rs` | 432 | partial 1-40 | Claims a PoS devnet; compose runs PoW (B-04). |
| `xtask/tools/src/prepush.rs` | 254 | unread |  |
| `xtask/tools/src/report.rs` | 90 | unread |  |
| `xtask/tools/src/rpc.rs` | 274 | unread |  |
| `xtask/tools/src/sbom.rs` | 278 | unread |  |
| `xtask/tools/src/seed_corpus.rs` | 223 | unread |  |
| `xtask/tools/src/smoke_rpc.rs` | 463 | unread |  |
| `xtask/tools/src/step_reachability.rs` | 754 | unread |  |
| `xtask/tools/src/support.rs` | 120 | unread |  |
