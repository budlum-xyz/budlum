# Budlum Audit Plan

This file lists the audit steps, target operating systems, and every file in the repository.
Every file starts unchecked.
We mark a file done after we read every line and record all findings.

## Operating systems to test

- [ ] Ubuntu 24.04 LTS (x86_64, CI runner and container)
- [ ] Ubuntu 24.04 LTS (aarch64 / ARM64, CI runner)
- [ ] Ubuntu 22.04 LTS (x86_64, container)
- [ ] Debian 13 Trixie (x86_64, local sandbox)
- [ ] Debian 12 Bookworm (x86_64, container and builder image)
- [ ] Chainguard Wolfi (x86_64, runtime container image)
- [ ] Alpine Linux (x86_64, musl container)
- [ ] Fedora Linux (x86_64, container)
- [ ] Rocky Linux 9 (x86_64, container)
- [ ] macOS (Apple Silicon / aarch64, CI runner)
- [ ] Windows Server (x86_64, CI runner)

## Repository file checklist (1063 files)

### Root files (16 files)

- [ ] `.coderabbit.yaml`
- [ ] `.gitignore`
- [ ] `.gitleaks.toml`
- [ ] `.gitleaksignore`
- [ ] `Cargo.lock`
- [ ] `Cargo.toml`
- [ ] `LICENSE.md`
- [ ] `README.md`
- [ ] `README.tr.md`
- [ ] `buf.yaml`
- [ ] `build.rs`
- [ ] `clippy.toml`
- [ ] `flake.lock`
- [ ] `flake.nix`
- [ ] `osv-scanner.toml`
- [ ] `rust-toolchain.toml`

### .cargo (1 files)

- [ ] `.cargo/audit.toml`

### .github (19 files)

- [ ] `.github/CODEOWNERS`
- [ ] `.github/PULL_REQUEST_TEMPLATE.md`
- [ ] `.github/actionlint.yaml`
- [ ] `.github/cargo-vet-baseline.txt`
- [ ] `.github/clippy-extra-baseline.txt`
- [ ] `.github/coverage-badge.json`
- [ ] `.github/coverage-baseline.txt`
- [ ] `.github/dead-pub-api-baseline.txt`
- [ ] `.github/dependabot.yml`
- [ ] `.github/gate-panics-baseline.txt`
- [ ] `.github/git-dep-audit.toml`
- [ ] `.github/idle-code-baseline.txt`
- [ ] `.github/semver-exceptions.txt`
- [ ] `.github/tsan-suppressions-baseline.txt`
- [ ] `.github/tsan-suppressions.txt`
- [ ] `.github/turkish-baseline.txt`
- [ ] `.github/udeps-baseline.txt`
- [ ] `.github/unwired-guards-baseline.txt`
- [ ] `.github/unwritten-metrics-baseline.txt`

### .github/ISSUE_TEMPLATE (5 files)

- [ ] `.github/ISSUE_TEMPLATE/bug-report.md`
- [ ] `.github/ISSUE_TEMPLATE/documentation-issue.md`
- [ ] `.github/ISSUE_TEMPLATE/feature-request.md`
- [ ] `.github/ISSUE_TEMPLATE/protocol---consensus-proposal.md`
- [ ] `.github/ISSUE_TEMPLATE/question---discussion.md`

### .github/codeql (1 files)

- [ ] `.github/codeql/codeql-config.yml`

### .github/workflows (29 files)

- [ ] `.github/workflows/air-mutants-nightly.yml`
- [ ] `.github/workflows/audit-guard.yml`
- [ ] `.github/workflows/benchmark.yml`
- [ ] `.github/workflows/cargo-vet.yml`
- [ ] `.github/workflows/ci.yml`
- [ ] `.github/workflows/code-scanning-sarif.yml`
- [ ] `.github/workflows/dependency-review.yml`
- [ ] `.github/workflows/dependency-submission.yml`
- [ ] `.github/workflows/determinism.yml`
- [ ] `.github/workflows/diverse-double-compiling.yml`
- [ ] `.github/workflows/docker-smoke.yml`
- [ ] `.github/workflows/extra-tooling.yml`
- [ ] `.github/workflows/fmt-diff-surface.yml`
- [ ] `.github/workflows/fuzz-nightly.yml`
- [ ] `.github/workflows/grype.yml`
- [ ] `.github/workflows/kani-slow.yml`
- [ ] `.github/workflows/miri-storage-weekly.yml`
- [ ] `.github/workflows/miri.yml`
- [ ] `.github/workflows/osv-scanner.yml`
- [ ] `.github/workflows/provenance.yml`
- [ ] `.github/workflows/rust.yml`
- [ ] `.github/workflows/security-audit.yml`
- [ ] `.github/workflows/security-hardening.yml`
- [ ] `.github/workflows/semgrep.yml`
- [ ] `.github/workflows/semver.yml`
- [ ] `.github/workflows/solidity.yml`
- [ ] `.github/workflows/supply-chain-extra.yml`
- [ ] `.github/workflows/typos.yml`
- [ ] `.github/workflows/watchdog.yml`

### .quality (3 files)

- [ ] `.quality/deny.toml`
- [ ] `.quality/grype.yaml`
- [ ] `.quality/typos.toml`

### assets (2 files)

- [ ] `assets/budlum-consensus-of-consensuses.png`
- [ ] `assets/budlum-konsensuslerin-konsensusu.png`

### benches (1 files)

- [ ] `benches/domain_throughput.rs`

### benches/micro (6 files)

- [ ] `benches/micro/erasure_rows.rs`
- [ ] `benches/micro/merkle_scaling.rs`
- [ ] `benches/micro/merkle_update.rs`
- [ ] `benches/micro/ratio_rayon.rs`
- [ ] `benches/micro/sig_verify.rs`
- [ ] `benches/micro/timing_safe.rs`

### benches/single_node (1 files)

- [ ] `benches/single_node/internal_pipeline_tps.rs`

### bud (119 files)

- [ ] `bud/Cargo.lock`
- [ ] `bud/Cargo.toml`
- [ ] `bud/FORMAT-V2.md`
- [ ] `bud/README.md`
- [ ] `bud/fuzz/Cargo.toml`
- [ ] `bud/fuzz/fuzz_bud_format.rs`
- [ ] `bud/kani/kani_bud_format.rs`
- [ ] `bud/mime.types.bud.json`
- [ ] `bud/src/bin/bud.rs`
- [ ] `bud/src/bin/measure_ratios.rs`
- [ ] `bud/src/bud3_live_test.rs`
- [ ] `bud/src/bud_fixed_point.rs`
- [ ] `bud/src/bud_format.rs`
- [ ] `bud/src/bud_format_autozstd.rs`
- [ ] `bud/src/bud_format_av2.rs`
- [ ] `bud/src/bud_format_bft.rs`
- [ ] `bud/src/bud_format_block.rs`
- [ ] `bud/src/bud_format_bloom.rs`
- [ ] `bud/src/bud_format_catalog.rs`
- [ ] `bud/src/bud_format_checkpoint.rs`
- [ ] `bud/src/bud_format_columnar.rs`
- [ ] `bud/src/bud_format_container.rs`
- [ ] `bud/src/bud_format_crop.rs`
- [ ] `bud/src/bud_format_culling.rs`
- [ ] `bud/src/bud_format_das.rs`
- [ ] `bud/src/bud_format_dbdelta.rs`
- [ ] `bud/src/bud_format_dedup.rs`
- [ ] `bud/src/bud_format_dictionary.rs`
- [ ] `bud/src/bud_format_economics.rs`
- [ ] `bud/src/bud_format_edge.rs`
- [ ] `bud/src/bud_format_edition.rs`
- [ ] `bud/src/bud_format_encpact.rs`
- [ ] `bud/src/bud_format_engine.rs`
- [ ] `bud/src/bud_format_erasure.rs`
- [ ] `bud/src/bud_format_exepdf.rs`
- [ ] `bud/src/bud_format_fastcdc.rs`
- [ ] `bud/src/bud_format_fidelitygate.rs`
- [ ] `bud/src/bud_format_fountain.rs`
- [ ] `bud/src/bud_format_genomic.rs`
- [ ] `bud/src/bud_format_governance.rs`
- [ ] `bud/src/bud_format_guardian.rs`
- [ ] `bud/src/bud_format_hardening.rs`
- [ ] `bud/src/bud_format_huffman.rs`
- [ ] `bud/src/bud_format_hw.rs`
- [ ] `bud/src/bud_format_integration.rs`
- [ ] `bud/src/bud_format_jpegre.rs`
- [ ] `bud/src/bud_format_lazyrepair.rs`
- [ ] `bud/src/bud_format_logfield.rs`
- [ ] `bud/src/bud_format_lowrank.rs`
- [ ] `bud/src/bud_format_lrc.rs`
- [ ] `bud/src/bud_format_markdown.rs`
- [ ] `bud/src/bud_format_matrix.rs`
- [ ] `bud/src/bud_format_media.rs`
- [ ] `bud/src/bud_format_model.rs`
- [ ] `bud/src/bud_format_msr.rs`
- [ ] `bud/src/bud_format_multifile.rs`
- [ ] `bud/src/bud_format_nvc.rs`
- [ ] `bud/src/bud_format_office.rs`
- [ ] `bud/src/bud_format_optical.rs`
- [ ] `bud/src/bud_format_optical_transfer.rs`
- [ ] `bud/src/bud_format_pact.rs`
- [ ] `bud/src/bud_format_pcap.rs`
- [ ] `bud/src/bud_format_pgm.rs`
- [ ] `bud/src/bud_format_pipe.rs`
- [ ] `bud/src/bud_format_pointcloud.rs`
- [ ] `bud/src/bud_format_por.rs`
- [ ] `bud/src/bud_format_prodcost.rs`
- [ ] `bud/src/bud_format_production.rs`
- [ ] `bud/src/bud_format_qos.rs`
- [ ] `bud/src/bud_format_qrmatrix.rs`
- [ ] `bud/src/bud_format_qrvideo.rs`
- [ ] `bud/src/bud_format_r3fix.rs`
- [ ] `bud/src/bud_format_ratioconsensus.rs`
- [ ] `bud/src/bud_format_real.rs`
- [ ] `bud/src/bud_format_realcorpus.rs`
- [ ] `bud/src/bud_format_recipe.rs`
- [ ] `bud/src/bud_format_recipe_record.rs`
- [ ] `bud/src/bud_format_regeneration.rs`
- [ ] `bud/src/bud_format_registry.rs`
- [ ] `bud/src/bud_format_repairband.rs`
- [ ] `bud/src/bud_format_revolutionary.rs`
- [ ] `bud/src/bud_format_scrub.rs`
- [ ] `bud/src/bud_format_secure_db.rs`
- [ ] `bud/src/bud_format_securededup.rs`
- [ ] `bud/src/bud_format_segment.rs`
- [ ] `bud/src/bud_format_serviceclass.rs`
- [ ] `bud/src/bud_format_shamir.rs`
- [ ] `bud/src/bud_format_social.rs`
- [ ] `bud/src/bud_format_social2.rs`
- [ ] `bud/src/bud_format_spec.rs`
- [ ] `bud/src/bud_format_telemetry.rs`
- [ ] `bud/src/bud_format_timeseries.rs`
- [ ] `bud/src/bud_format_tiny.rs`
- [ ] `bud/src/bud_format_transpile.rs`
- [ ] `bud/src/bud_format_tricore.rs`
- [ ] `bud/src/bud_format_ultra.rs`
- [ ] `bud/src/bud_format_ux.rs`
- [ ] `bud/src/bud_format_video.rs`
- [ ] `bud/src/bud_format_videopipe.rs`
- [ ] `bud/src/bud_format_view.rs`
- [ ] `bud/src/bud_format_wal.rs`
- [ ] `bud/src/bud_format_wire.rs`
- [ ] `bud/src/bud_format_zkbridge.rs`
- [ ] `bud/src/bud_format_zkproof.rs`
- [ ] `bud/src/churn.rs`
- [ ] `bud/src/cli.rs`
- [ ] `bud/src/fidelity.rs`
- [ ] `bud/src/gates.rs`
- [ ] `bud/src/lib.rs`
- [ ] `bud/src/price.rs`
- [ ] `bud/src/provider.rs`
- [ ] `bud/src/quantum.rs`
- [ ] `bud/src/quantum_chain.rs`
- [ ] `bud/src/ratio.rs`
- [ ] `bud/tests/fixtures/image.png`
- [ ] `bud/tests/fixtures/text.log`
- [ ] `bud/tests/fixtures/video.yuv`
- [ ] `bud/tests/test_bud2.rs`
- [ ] `bud/tests/test_integration.rs`

### budzero (17 files)

- [ ] `budzero/.gitignore`
- [ ] `budzero/ARCHITECTURE.md`
- [ ] `budzero/Cargo.lock`
- [ ] `budzero/Cargo.toml`
- [ ] `budzero/LICENSE`
- [ ] `budzero/README.md`
- [ ] `budzero/control_flow.bud`
- [ ] `budzero/deny.toml`
- [ ] `budzero/example.bud`
- [ ] `budzero/example2.bud`
- [ ] `budzero/example_loop.bud`
- [ ] `budzero/flake.lock`
- [ ] `budzero/flake.nix`
- [ ] `budzero/osv-scanner.toml`
- [ ] `budzero/rust-toolchain.toml`
- [ ] `budzero/state.json`
- [ ] `budzero/test_prover.bud`

### budzero/bud-cli (3 files)

- [ ] `budzero/bud-cli/Cargo.toml`
- [ ] `budzero/bud-cli/src/main.rs`
- [ ] `budzero/bud-cli/tests/toolchain_end_to_end.rs`

### budzero/bud-compiler (11 files)

- [ ] `budzero/bud-compiler/Cargo.toml`
- [ ] `budzero/bud-compiler/src/ast.rs`
- [ ] `budzero/bud-compiler/src/codegen.rs`
- [ ] `budzero/bud-compiler/src/ir/display.rs`
- [ ] `budzero/bud-compiler/src/ir/lower.rs`
- [ ] `budzero/bud-compiler/src/ir/mod.rs`
- [ ] `budzero/bud-compiler/src/ir/verify.rs`
- [ ] `budzero/bud-compiler/src/lexer.rs`
- [ ] `budzero/bud-compiler/src/lib.rs`
- [ ] `budzero/bud-compiler/src/parser.rs`
- [ ] `budzero/bud-compiler/src/sema.rs`

### budzero/bud-isa (2 files)

- [ ] `budzero/bud-isa/Cargo.toml`
- [ ] `budzero/bud-isa/src/lib.rs`

### budzero/bud-node (6 files)

- [ ] `budzero/bud-node/Cargo.toml`
- [ ] `budzero/bud-node/src/bitswap.rs`
- [ ] `budzero/bud-node/src/discovery.rs`
- [ ] `budzero/bud-node/src/lib.rs`
- [ ] `budzero/bud-node/src/sharding.rs`
- [ ] `budzero/bud-node/src/store.rs`

### budzero/bud-proof (27 files)

- [ ] `budzero/bud-proof/Cargo.toml`
- [ ] `budzero/bud-proof/benches/canonical_programs.rs`
- [ ] `budzero/bud-proof/benches/proof_baseline.rs`
- [ ] `budzero/bud-proof/src/adapter.rs`
- [ ] `budzero/bud-proof/src/alarm_log.rs`
- [ ] `budzero/bud-proof/src/bud_stark/config.rs`
- [ ] `budzero/bud-proof/src/bud_stark/folder.rs`
- [ ] `budzero/bud-proof/src/bud_stark/mod.rs`
- [ ] `budzero/bud-proof/src/bud_stark/preprocessed.rs`
- [ ] `budzero/bud-proof/src/bud_stark/proof.rs`
- [ ] `budzero/bud-proof/src/bud_stark/prover.rs`
- [ ] `budzero/bud-proof/src/bud_stark/sub_builder.rs`
- [ ] `budzero/bud-proof/src/bud_stark/symbolic.rs`
- [ ] `budzero/bud-proof/src/bud_stark/verifier.rs`
- [ ] `budzero/bud-proof/src/canonical_boot.rs`
- [ ] `budzero/bud-proof/src/canonical_recovery.rs`
- [ ] `budzero/bud-proof/src/canonical_set.rs`
- [ ] `budzero/bud-proof/src/lib.rs`
- [ ] `budzero/bud-proof/src/plonky3_air.rs`
- [ ] `budzero/bud-proof/src/plonky3_prover.rs`
- [ ] `budzero/bud-proof/src/quarantine.rs`
- [ ] `budzero/bud-proof/src/relayer.rs`
- [ ] `budzero/bud-proof/src/trace_layout_tests.rs`
- [ ] `budzero/bud-proof/src/transfer_verdict.rs`
- [ ] `budzero/bud-proof/tests/compiled_branching.rs`
- [ ] `budzero/bud-proof/tests/fiat_shamir_binding.rs`
- [ ] `budzero/bud-proof/tests/soundness_negatives.rs`

### budzero/bud-state (3 files)

- [ ] `budzero/bud-state/Cargo.toml`
- [ ] `budzero/bud-state/src/lib.rs`
- [ ] `budzero/bud-state/src/note.rs`

### budzero/bud-vm (5 files)

- [ ] `budzero/bud-vm/Cargo.toml`
- [ ] `budzero/bud-vm/src/lib.rs`
- [ ] `budzero/bud-vm/src/private_transfer.rs`
- [ ] `budzero/bud-vm/src/syscall_context.rs`
- [ ] `budzero/bud-vm/tests/trace_fixtures.rs`

### budzero/docs (16 files)

- [ ] `budzero/docs/BudL_SPEC.md`
- [ ] `budzero/docs/README.md`
- [ ] `budzero/docs/STABILIZATION.md`
- [ ] `budzero/docs/adding_opcodes.md`
- [ ] `budzero/docs/advanced_language_features_and_memory_management.md`
- [ ] `budzero/docs/compiler_and_ecosystem.md`
- [ ] `budzero/docs/development.md`
- [ ] `budzero/docs/introduction.md`
- [ ] `budzero/docs/isa_and_bytecode.md`
- [ ] `budzero/docs/production_hardening_and_soundness.md`
- [ ] `budzero/docs/proof_format_release_checklist.md`
- [ ] `budzero/docs/prover_stabilization_and_tests.md`
- [ ] `budzero/docs/stark_and_plonky3.md`
- [ ] `budzero/docs/virtual_machine.md`
- [ ] `budzero/docs/vm_trace_schema.md`
- [ ] `budzero/docs/zk_friendly_architecture.md`

### budzero/verifier-registry (7 files)

- [ ] `budzero/verifier-registry/Cargo.toml`
- [ ] `budzero/verifier-registry/src/address.rs`
- [ ] `budzero/verifier-registry/src/evidence.rs`
- [ ] `budzero/verifier-registry/src/lib.rs`
- [ ] `budzero/verifier-registry/src/params.rs`
- [ ] `budzero/verifier-registry/src/registry.rs`
- [ ] `budzero/verifier-registry/src/role.rs`

### config (7 files)

- [ ] `config/archive.toml`
- [ ] `config/devnet-genesis.json`
- [ ] `config/devnet.toml`
- [ ] `config/mainnet-genesis.json`
- [ ] `config/mainnet.toml`
- [ ] `config/testnet-genesis.json`
- [ ] `config/testnet.toml`

### config/fixtures (1 files)

- [ ] `config/fixtures/real-chain.json`

### config/personas (3 files)

- [ ] `config/personas/developer.toml`
- [ ] `config/personas/enterprise-poa.toml`
- [ ] `config/personas/user-devnet.toml`

### contracts (1 files)

- [ ] `contracts/external-domain/BudlumFinalityVerifier.sol`

### crates/ai-inference (54 files)

- [ ] `crates/ai-inference/.gitignore`
- [ ] `crates/ai-inference/ARCHITECTURE.md`
- [ ] `crates/ai-inference/Cargo.lock`
- [ ] `crates/ai-inference/Cargo.toml`
- [ ] `crates/ai-inference/LICENSE.md`
- [ ] `crates/ai-inference/README.md`
- [ ] `crates/ai-inference/crates/ai-core/Cargo.toml`
- [ ] `crates/ai-inference/crates/ai-core/src/dataset.rs`
- [ ] `crates/ai-inference/crates/ai-core/src/lib.rs`
- [ ] `crates/ai-inference/crates/ai-core/src/manifest.rs`
- [ ] `crates/ai-inference/crates/ai-core/src/model.rs`
- [ ] `crates/ai-inference/crates/ai-core/src/system_prompt.rs`
- [ ] `crates/ai-inference/crates/ai-core/src/tier.rs`
- [ ] `crates/ai-inference/crates/ai-data/Cargo.toml`
- [ ] `crates/ai-inference/crates/ai-data/src/jsonl.rs`
- [ ] `crates/ai-inference/crates/ai-data/src/lib.rs`
- [ ] `crates/ai-inference/crates/ai-data/src/source.rs`
- [ ] `crates/ai-inference/crates/ai-data/src/template.rs`
- [ ] `crates/ai-inference/crates/ai-data/src/verify.rs`
- [ ] `crates/ai-inference/crates/ai-integrations/Cargo.toml`
- [ ] `crates/ai-inference/crates/ai-integrations/src/lib.rs`
- [ ] `crates/ai-inference/crates/ai-integrations/src/rest.rs`
- [ ] `crates/ai-inference/crates/ai-integrations/src/ws.rs`
- [ ] `crates/ai-inference/crates/ai-knowledge/Cargo.toml`
- [ ] `crates/ai-inference/crates/ai-knowledge/src/cache.rs`
- [ ] `crates/ai-inference/crates/ai-knowledge/src/chunk.rs`
- [ ] `crates/ai-inference/crates/ai-knowledge/src/context.rs`
- [ ] `crates/ai-inference/crates/ai-knowledge/src/embed.rs`
- [ ] `crates/ai-inference/crates/ai-knowledge/src/lib.rs`
- [ ] `crates/ai-inference/crates/ai-knowledge/src/memory.rs`
- [ ] `crates/ai-inference/crates/ai-knowledge/src/redact.rs`
- [ ] `crates/ai-inference/crates/ai-ops/Cargo.toml`
- [ ] `crates/ai-inference/crates/ai-ops/src/cli.rs`
- [ ] `crates/ai-inference/crates/ai-ops/src/logparse.rs`
- [ ] `crates/ai-inference/crates/ai-ops/src/main.rs`
- [ ] `crates/ai-inference/crates/ai-serve/Cargo.toml`
- [ ] `crates/ai-inference/crates/ai-serve/src/bridge.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/chain.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/config.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/cost_forecast.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/fee_scenario.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/health.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/lib.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/metric.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/residency.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/staging.rs`
- [ ] `crates/ai-inference/crates/ai-serve/src/validator_cost.rs`
- [ ] `crates/ai-inference/crates/ai-tune/Cargo.toml`
- [ ] `crates/ai-inference/crates/ai-tune/data/ai-behaviour-curriculum.jsonl`
- [ ] `crates/ai-inference/crates/ai-tune/src/eval.rs`
- [ ] `crates/ai-inference/crates/ai-tune/src/lib.rs`
- [ ] `crates/ai-inference/crates/ai-tune/src/lock.rs`
- [ ] `crates/ai-inference/crates/ai-tune/src/plan.rs`
- [ ] `crates/ai-inference/crates/ai-tune/src/schema.rs`

### crates/bpqs (22 files)

- [ ] `crates/bpqs/Cargo.lock`
- [ ] `crates/bpqs/Cargo.toml`
- [ ] `crates/bpqs/SECURITY-ARGUMENT.md`
- [ ] `crates/bpqs/VERIFYMERKLE-EXPRESSIBILITY.md`
- [ ] `crates/bpqs/examples/bench_differential.rs`
- [ ] `crates/bpqs/examples/bench_perm.rs`
- [ ] `crates/bpqs/examples/checksum_domination_exact.expected.txt`
- [ ] `crates/bpqs/examples/checksum_domination_exact.rs`
- [ ] `crates/bpqs/examples/dudect_poseidon2.rs`
- [ ] `crates/bpqs/kat/bpqs-kat-v1.txt`
- [ ] `crates/bpqs/src/epoch.rs`
- [ ] `crates/bpqs/src/error.rs`
- [ ] `crates/bpqs/src/hash.rs`
- [ ] `crates/bpqs/src/lib.rs`
- [ ] `crates/bpqs/src/merkle.rs`
- [ ] `crates/bpqs/src/params.rs`
- [ ] `crates/bpqs/src/poseidon2.rs`
- [ ] `crates/bpqs/src/shake256.rs`
- [ ] `crates/bpqs/src/sign.rs`
- [ ] `crates/bpqs/src/tests.rs`
- [ ] `crates/bpqs/src/tests_backends.rs`
- [ ] `crates/bpqs/src/wots.rs`

### crates/budscan (30 files)

- [ ] `crates/budscan/Cargo.lock`
- [ ] `crates/budscan/Cargo.toml`
- [ ] `crates/budscan/README.md`
- [ ] `crates/budscan/browser/README.md`
- [ ] `crates/budscan/browser/l10n/en-US/budscan.ftl`
- [ ] `crates/budscan/browser/l10n/tr-TR/budscan.ftl`
- [ ] `crates/budscan/browser/mozconfig`
- [ ] `crates/budscan/browser/patches.txt`
- [ ] `crates/budscan/browser/patches/address-bar-verification-badge.patch`
- [ ] `crates/budscan/browser/patches/bud-protocol-handler.patch`
- [ ] `crates/budscan/browser/patches/name-bar-punycode.patch`
- [ ] `crates/budscan/browser/settings/budscan.cfg`
- [ ] `crates/budscan/browser/settings/policies.json`
- [ ] `crates/budscan/src/arweave.rs`
- [ ] `crates/budscan/src/bin/budscan.rs`
- [ ] `crates/budscan/src/bns_proof.rs`
- [ ] `crates/budscan/src/cid.rs`
- [ ] `crates/budscan/src/content_id.rs`
- [ ] `crates/budscan/src/ens.rs`
- [ ] `crates/budscan/src/evidence.rs`
- [ ] `crates/budscan/src/evm_audit.rs`
- [ ] `crates/budscan/src/fetch.rs`
- [ ] `crates/budscan/src/lib.rs`
- [ ] `crates/budscan/src/light_client.rs`
- [ ] `crates/budscan/src/name_rule.rs`
- [ ] `crates/budscan/src/patchset.rs`
- [ ] `crates/budscan/src/punycode.rs`
- [ ] `crates/budscan/src/query.rs`
- [ ] `crates/budscan/src/resolve.rs`
- [ ] `crates/budscan/src/search.rs`

### crates/note-packing (3 files)

- [ ] `crates/note-packing/Cargo.lock`
- [ ] `crates/note-packing/Cargo.toml`
- [ ] `crates/note-packing/src/lib.rs`

### crates/wallet-core (8 files)

- [ ] `crates/wallet-core/Cargo.lock`
- [ ] `crates/wallet-core/Cargo.toml`
- [ ] `crates/wallet-core/README.md`
- [ ] `crates/wallet-core/src/bip39_wordlist.rs`
- [ ] `crates/wallet-core/src/lib.rs`
- [ ] `crates/wallet-core/src/privacy_crypto.rs`
- [ ] `crates/wallet-core/src/privacy_transfer.rs`
- [ ] `crates/wallet-core/src/tee.rs`

### docs (15 files)

- [ ] `docs/AI_VERIFICATION_STATUS.md`
- [ ] `docs/ARCHITECTURE.md`
- [ ] `docs/BPQS_INDEPENDENT_REVIEW_CALL.md`
- [ ] `docs/BUD_CONTENT_ENCRYPTION.md`
- [ ] `docs/BUD_STORAGE_ROADMAP.md`
- [ ] `docs/CODE_OF_CONDUCT.md`
- [ ] `docs/CONTRIBUTING.md`
- [ ] `docs/FSF_ADAPTATION_PLAN.md`
- [ ] `docs/FSF_PROJECT_FIT.md`
- [ ] `docs/NOTICE`
- [ ] `docs/PQ_ANCHOR_RESEARCH.md`
- [ ] `docs/PROVENANCE_NOTES.md`
- [ ] `docs/SECURITY.md`
- [ ] `docs/SPECIFICATION.md`
- [ ] `docs/VALIDATOR_ROLES.md`

### examples (1 files)

- [ ] `examples/print_genesis_hash.rs`

### fuzz (4 files)

- [ ] `fuzz/Cargo.lock`
- [ ] `fuzz/Cargo.toml`
- [ ] `fuzz/README.md`
- [ ] `fuzz/osv-scanner.toml`

### fuzz/corpus (88 files)

- [ ] `fuzz/corpus/block_deserialize/seed_alt`
- [ ] `fuzz/corpus/block_deserialize/seed_empty`
- [ ] `fuzz/corpus/block_deserialize/seed_long`
- [ ] `fuzz/corpus/block_deserialize/seed_ones`
- [ ] `fuzz/corpus/block_deserialize/seed_seq`
- [ ] `fuzz/corpus/block_deserialize/seed_zeros`
- [ ] `fuzz/corpus/bpqs_wots_reject/seed-damaged.bin`
- [ ] `fuzz/corpus/bpqs_wots_reject/seed-honest.bin`
- [ ] `fuzz/corpus/budl_compile/control_flow.bud`
- [ ] `fuzz/corpus/budl_compile/example.bud`
- [ ] `fuzz/corpus/budl_compile/example2.bud`
- [ ] `fuzz/corpus/budl_compile/example_loop.bud`
- [ ] `fuzz/corpus/budl_compile/nested_parens.bud`
- [ ] `fuzz/corpus/budl_compile/test_prover.bud`
- [ ] `fuzz/corpus/budl_compile/unbalanced_parens.bud`
- [ ] `fuzz/corpus/budl_compile_then_run/control_flow.bud`
- [ ] `fuzz/corpus/budl_compile_then_run/example.bud`
- [ ] `fuzz/corpus/budl_compile_then_run/example2.bud`
- [ ] `fuzz/corpus/budl_compile_then_run/example_loop.bud`
- [ ] `fuzz/corpus/budl_compile_then_run/nested_parens.bud`
- [ ] `fuzz/corpus/budl_compile_then_run/test_prover.bud`
- [ ] `fuzz/corpus/consensus_state_transition/seed0`
- [ ] `fuzz/corpus/consensus_state_transition/seed1`
- [ ] `fuzz/corpus/consensus_state_transition/seed_alt`
- [ ] `fuzz/corpus/consensus_state_transition/seed_deep_reorg`
- [ ] `fuzz/corpus/consensus_state_transition/seed_empty`
- [ ] `fuzz/corpus/consensus_state_transition/seed_long`
- [ ] `fuzz/corpus/consensus_state_transition/seed_ones`
- [ ] `fuzz/corpus/consensus_state_transition/seed_produce_few`
- [ ] `fuzz/corpus/consensus_state_transition/seed_seq`
- [ ] `fuzz/corpus/consensus_state_transition/seed_zeros`
- [ ] `fuzz/corpus/consensus_validate/seed_alt`
- [ ] `fuzz/corpus/consensus_validate/seed_empty`
- [ ] `fuzz/corpus/consensus_validate/seed_long`
- [ ] `fuzz/corpus/consensus_validate/seed_ones`
- [ ] `fuzz/corpus/consensus_validate/seed_seq`
- [ ] `fuzz/corpus/consensus_validate/seed_zeros`
- [ ] `fuzz/corpus/evm_mpt_verify/empty-trie-frame`
- [ ] `fuzz/corpus/evm_rlp_decode/empty-list.rlp`
- [ ] `fuzz/corpus/evm_rlp_decode/empty-string.rlp`
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_alt`
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_empty`
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_long`
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_ones`
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_seq`
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_zeros`
- [ ] `fuzz/corpus/relayer_escrow/seed0`
- [ ] `fuzz/corpus/relayer_escrow/seed1`
- [ ] `fuzz/corpus/relayer_escrow/seed_alt`
- [ ] `fuzz/corpus/relayer_escrow/seed_empty`
- [ ] `fuzz/corpus/relayer_escrow/seed_lock_ops`
- [ ] `fuzz/corpus/relayer_escrow/seed_long`
- [ ] `fuzz/corpus/relayer_escrow/seed_ones`
- [ ] `fuzz/corpus/relayer_escrow/seed_seq`
- [ ] `fuzz/corpus/relayer_escrow/seed_sweep`
- [ ] `fuzz/corpus/relayer_escrow/seed_zeros`
- [ ] `fuzz/corpus/reputation/01_connect_ratelimit_disconnect.bin`
- [ ] `fuzz/corpus/reputation/02_ban_then_unban.bin`
- [ ] `fuzz/corpus/reputation/03_ban_expiry_cleanup.bin`
- [ ] `fuzz/corpus/reputation/04_reconnect_storm.bin`
- [ ] `fuzz/corpus/reputation/05_ops_on_unknown_peer.bin`
- [ ] `fuzz/corpus/snapshot_deserialize/seed_alt`
- [ ] `fuzz/corpus/snapshot_deserialize/seed_empty`
- [ ] `fuzz/corpus/snapshot_deserialize/seed_long`
- [ ] `fuzz/corpus/snapshot_deserialize/seed_ones`
- [ ] `fuzz/corpus/snapshot_deserialize/seed_seq`
- [ ] `fuzz/corpus/snapshot_deserialize/seed_zeros`
- [ ] `fuzz/corpus/transaction_deserialize/seed_alt`
- [ ] `fuzz/corpus/transaction_deserialize/seed_empty`
- [ ] `fuzz/corpus/transaction_deserialize/seed_long`
- [ ] `fuzz/corpus/transaction_deserialize/seed_ones`
- [ ] `fuzz/corpus/transaction_deserialize/seed_seq`
- [ ] `fuzz/corpus/transaction_deserialize/seed_zeros`
- [ ] `fuzz/corpus/vm_execute/01_simple_add.bin`
- [ ] `fuzz/corpus/vm_execute/02_branch_loop.bin`
- [ ] `fuzz/corpus/vm_execute/03_verify_merkle_0x1E.bin`
- [ ] `fuzz/corpus/vm_execute/04_poseidon_hash.bin`
- [ ] `fuzz/corpus/vm_execute/05_memory_ops.bin`
- [ ] `fuzz/corpus/zk_verifier/seed0`
- [ ] `fuzz/corpus/zk_verifier/seed1`
- [ ] `fuzz/corpus/zk_verifier/seed_alt`
- [ ] `fuzz/corpus/zk_verifier/seed_empty`
- [ ] `fuzz/corpus/zk_verifier/seed_long`
- [ ] `fuzz/corpus/zk_verifier/seed_ones`
- [ ] `fuzz/corpus/zk_verifier/seed_raw_mode0`
- [ ] `fuzz/corpus/zk_verifier/seed_seq`
- [ ] `fuzz/corpus/zk_verifier/seed_struct_mode`
- [ ] `fuzz/corpus/zk_verifier/seed_zeros`

### fuzz/fuzz_targets (15 files)

- [ ] `fuzz/fuzz_targets/block_deserialize.rs`
- [ ] `fuzz/fuzz_targets/bpqs_wots_reject.rs`
- [ ] `fuzz/fuzz_targets/budl_compile.rs`
- [ ] `fuzz/fuzz_targets/budl_compile_then_run.rs`
- [ ] `fuzz/fuzz_targets/consensus_state_transition.rs`
- [ ] `fuzz/fuzz_targets/consensus_validate.rs`
- [ ] `fuzz/fuzz_targets/evm_mpt_verify.rs`
- [ ] `fuzz/fuzz_targets/evm_rlp_decode.rs`
- [ ] `fuzz/fuzz_targets/fuzz_blockchain_serialize.rs`
- [ ] `fuzz/fuzz_targets/relayer_escrow.rs`
- [ ] `fuzz/fuzz_targets/reputation.rs`
- [ ] `fuzz/fuzz_targets/snapshot_deserialize.rs`
- [ ] `fuzz/fuzz_targets/transaction_deserialize.rs`
- [ ] `fuzz/fuzz_targets/vm_execute.rs`
- [ ] `fuzz/fuzz_targets/zk_verifier.rs`

### kani (2 files)

- [ ] `kani/Cargo.toml`
- [ ] `kani/src/lib.rs`

### ops (5 files)

- [ ] `ops/Dockerfile`
- [ ] `ops/budlum-core.service`
- [ ] `ops/docker-compose.ci.yml`
- [ ] `ops/docker-compose.yml`
- [ ] `ops/prometheus.yml`

### ops/scripts (1 files)

- [ ] `ops/scripts/.gitkeep`

### proto (1 files)

- [ ] `proto/budlum/network/protocol.proto`

### src (4 files)

- [ ] `src/developer_os.rs`
- [ ] `src/error.rs`
- [ ] `src/lib.rs`
- [ ] `src/main.rs`

### src/account_abstraction (6 files)

- [ ] `src/account_abstraction/mod.rs`
- [ ] `src/account_abstraction/private_transfer_auth.rs`
- [ ] `src/account_abstraction/quantum_account.rs`
- [ ] `src/account_abstraction/registry.rs`
- [ ] `src/account_abstraction/tee_attestation.rs`
- [ ] `src/account_abstraction/threshold_mldsa.rs`

### src/ai (9 files)

- [ ] `src/ai/README.md`
- [ ] `src/ai/execution/guest.rs`
- [ ] `src/ai/execution/mod.rs`
- [ ] `src/ai/execution/model_class.rs`
- [ ] `src/ai/execution/stark.rs`
- [ ] `src/ai/execution/verify.rs`
- [ ] `src/ai/mod.rs`
- [ ] `src/ai/registry.rs`
- [ ] `src/ai/types.rs`

### src/ai_inference (11 files)

- [ ] `src/ai_inference/effort.rs`
- [ ] `src/ai_inference/executor.rs`
- [ ] `src/ai_inference/i18n.rs`
- [ ] `src/ai_inference/inference.rs`
- [ ] `src/ai_inference/metrics.rs`
- [ ] `src/ai_inference/mod.rs`
- [ ] `src/ai_inference/perception.rs`
- [ ] `src/ai_inference/query.rs`
- [ ] `src/ai_inference/social.rs`
- [ ] `src/ai_inference/storage.rs`
- [ ] `src/ai_inference/verify.rs`

### src/bin (3 files)

- [ ] `src/bin/bud.rs`
- [ ] `src/bin/budlum-light.rs`
- [ ] `src/bin/budlum-relayer.rs`

### src/bns (4 files)

- [ ] `src/bns/README.md`
- [ ] `src/bns/mod.rs`
- [ ] `src/bns/registry.rs`
- [ ] `src/bns/types.rs`

### src/budlumxyz (3 files)

- [ ] `src/budlumxyz/README.md`
- [ ] `src/budlumxyz/mod.rs`
- [ ] `src/budlumxyz/types.rs`

### src/chain (8 files)

- [ ] `src/chain/blockchain.rs`
- [ ] `src/chain/chain_actor.rs`
- [ ] `src/chain/fee_market.rs`
- [ ] `src/chain/finality.rs`
- [ ] `src/chain/genesis.rs`
- [ ] `src/chain/mod.rs`
- [ ] `src/chain/snapshot.rs`
- [ ] `src/chain/storage_economics_tests.rs`

### src/cli (2 files)

- [ ] `src/cli/commands.rs`
- [ ] `src/cli/mod.rs`

### src/consensus (7 files)

- [ ] `src/consensus/merkle_tree.rs`
- [ ] `src/consensus/mod.rs`
- [ ] `src/consensus/poa.rs`
- [ ] `src/consensus/pos.rs`
- [ ] `src/consensus/pow.rs`
- [ ] `src/consensus/qc.rs`
- [ ] `src/consensus/split_resolver.rs`

### src/core (15 files)

- [ ] `src/core/account.rs`
- [ ] `src/core/address.rs`
- [ ] `src/core/block.rs`
- [ ] `src/core/bounded_read.rs`
- [ ] `src/core/chain_config.rs`
- [ ] `src/core/constitution.rs`
- [ ] `src/core/encoding.rs`
- [ ] `src/core/governance.rs`
- [ ] `src/core/hash.rs`
- [ ] `src/core/map_keys.rs`
- [ ] `src/core/metrics.rs`
- [ ] `src/core/mod.rs`
- [ ] `src/core/money.rs`
- [ ] `src/core/transaction.rs`
- [ ] `src/core/transaction_v4.txt`

### src/cross_domain (33 files)

- [ ] `src/cross_domain/bridge.rs`
- [ ] `src/cross_domain/bridge_relayer.rs`
- [ ] `src/cross_domain/chain_adapter.rs`
- [ ] `src/cross_domain/event_tree.rs`
- [ ] `src/cross_domain/evm/README.md`
- [ ] `src/cross_domain/evm/adapter.rs`
- [ ] `src/cross_domain/evm/bud_to_eth.rs`
- [ ] `src/cross_domain/evm/header.rs`
- [ ] `src/cross_domain/evm/mod.rs`
- [ ] `src/cross_domain/evm/mpt.rs`
- [ ] `src/cross_domain/evm/receipt.rs`
- [ ] `src/cross_domain/evm/rlp.rs`
- [ ] `src/cross_domain/evm/sync_committee.rs`
- [ ] `src/cross_domain/evm/verify.rs`
- [ ] `src/cross_domain/external/domain_bridge.rs`
- [ ] `src/cross_domain/external/ethereum.rs`
- [ ] `src/cross_domain/external/evm_hybrid.rs`
- [ ] `src/cross_domain/external/intake.rs`
- [ ] `src/cross_domain/external/intake_quorum.rs`
- [ ] `src/cross_domain/external/mod.rs`
- [ ] `src/cross_domain/external/profile.rs`
- [ ] `src/cross_domain/external/prover.rs`
- [ ] `src/cross_domain/external/quorum.rs`
- [ ] `src/cross_domain/external/registry.rs`
- [ ] `src/cross_domain/external/selftest.rs`
- [ ] `src/cross_domain/external/spec.rs`
- [ ] `src/cross_domain/external/versioning.rs`
- [ ] `src/cross_domain/external/zkvm_proof.rs`
- [ ] `src/cross_domain/message.rs`
- [ ] `src/cross_domain/message_registry.rs`
- [ ] `src/cross_domain/mod.rs`
- [ ] `src/cross_domain/nonce.rs`
- [ ] `src/cross_domain/relayer.rs`

### src/crypto (7 files)

- [ ] `src/crypto/domain_tags.rs`
- [ ] `src/crypto/key_set_preimage.rs`
- [ ] `src/crypto/mainnet_policy.rs`
- [ ] `src/crypto/mod.rs`
- [ ] `src/crypto/pkcs11.rs`
- [ ] `src/crypto/primitives.rs`
- [ ] `src/crypto/signer.rs`

### src/deed (1 files)

- [ ] `src/deed/mod.rs`

### src/domain (15 files)

- [ ] `src/domain/commitment_registry.rs`
- [ ] `src/domain/deal_open.rs`
- [ ] `src/domain/finality_adapter.rs`
- [ ] `src/domain/fork_choice.rs`
- [ ] `src/domain/mod.rs`
- [ ] `src/domain/plugin.rs`
- [ ] `src/domain/plugin_registry.rs`
- [ ] `src/domain/regen_health.rs`
- [ ] `src/domain/regeneration_stage.rs`
- [ ] `src/domain/registry.rs`
- [ ] `src/domain/sovereign.rs`
- [ ] `src/domain/storage_deal.rs`
- [ ] `src/domain/storage_params.rs`
- [ ] `src/domain/storage_tx.rs`
- [ ] `src/domain/types.rs`

### src/execution (4 files)

- [ ] `src/execution/executor.rs`
- [ ] `src/execution/mod.rs`
- [ ] `src/execution/proof_verifier.rs`
- [ ] `src/execution/zkvm.rs`

### src/gateway (4 files)

- [ ] `src/gateway/atlas.rs`
- [ ] `src/gateway/mod.rs`
- [ ] `src/gateway/passport.rs`
- [ ] `src/gateway/service.rs`

### src/light_client (1 files)

- [ ] `src/light_client/mod.rs`

### src/mempool (2 files)

- [ ] `src/mempool/mod.rs`
- [ ] `src/mempool/pool.rs`

### src/network (10 files)

- [ ] `src/network/gossip_dedup.rs`
- [ ] `src/network/mobile.rs`
- [ ] `src/network/mod.rs`
- [ ] `src/network/node.rs`
- [ ] `src/network/peer_manager.rs`
- [ ] `src/network/privacy.rs`
- [ ] `src/network/proto_conversions.rs`
- [ ] `src/network/protocol.rs`
- [ ] `src/network/regen_health_tick.rs`
- [ ] `src/network/sync_codec.rs`

### src/pollen (5 files)

- [ ] `src/pollen/README.md`
- [ ] `src/pollen/content_gate.rs`
- [ ] `src/pollen/data_rights.rs`
- [ ] `src/pollen/mod.rs`
- [ ] `src/pollen/offers.rs`

### src/privacy (3 files)

- [ ] `src/privacy/mod.rs`
- [ ] `src/privacy/note_registry.rs`
- [ ] `src/privacy/submit.rs`

### src/prover (1 files)

- [ ] `src/prover/mod.rs`

### src/registry (14 files)

- [ ] `src/registry/d4_merge_tests.rs`
- [ ] `src/registry/evidence.rs`
- [ ] `src/registry/identity.rs`
- [ ] `src/registry/identity_fill.rs`
- [ ] `src/registry/invalid_vote.rs`
- [ ] `src/registry/liveness.rs`
- [ ] `src/registry/mod.rs`
- [ ] `src/registry/params.rs`
- [ ] `src/registry/permissionless.rs`
- [ ] `src/registry/poa_compliance.rs`
- [ ] `src/registry/poa_membership.rs`
- [ ] `src/registry/poa_onboarding.rs`
- [ ] `src/registry/quarantine_ledger.rs`
- [ ] `src/registry/role.rs`

### src/relayer (3 files)

- [ ] `src/relayer/mod.rs`
- [ ] `src/relayer/policy.rs`
- [ ] `src/relayer/worker.rs`

### src/rpc (4 files)

- [ ] `src/rpc/api.rs`
- [ ] `src/rpc/mod.rs`
- [ ] `src/rpc/server.rs`
- [ ] `src/rpc/tests.rs`

### src/sdk (1 files)

- [ ] `src/sdk/mod.rs`

### src/settlement (9 files)

- [ ] `src/settlement/cold_quorum.rs`
- [ ] `src/settlement/cold_wallet.rs`
- [ ] `src/settlement/commitment_tree.rs`
- [ ] `src/settlement/global_block.rs`
- [ ] `src/settlement/mod.rs`
- [ ] `src/settlement/pq_anchor.rs`
- [ ] `src/settlement/pq_anchor_verify.rs`
- [ ] `src/settlement/proof_market.rs`
- [ ] `src/settlement/proof_verifier.rs`

### src/sharding (1 files)

- [ ] `src/sharding/mod.rs`

### src/socialfi (4 files)

- [ ] `src/socialfi/README.md`
- [ ] `src/socialfi/mod.rs`
- [ ] `src/socialfi/types.rs`
- [ ] `src/socialfi/vault.rs`

### src/storage (55 files)

- [ ] `src/storage/README.md`
- [ ] `src/storage/assignment.rs`
- [ ] `src/storage/column_commitment.rs`
- [ ] `src/storage/content_id.rs`
- [ ] `src/storage/db.rs`
- [ ] `src/storage/derived.rs`
- [ ] `src/storage/dictionary.rs`
- [ ] `src/storage/emit.rs`
- [ ] `src/storage/erasure.rs`
- [ ] `src/storage/fixed_point.rs`
- [ ] `src/storage/generated.rs`
- [ ] `src/storage/lifecycle.rs`
- [ ] `src/storage/living_threshold.rs`
- [ ] `src/storage/lrc.rs`
- [ ] `src/storage/manifest.rs`
- [ ] `src/storage/merkle_trie.rs`
- [ ] `src/storage/mobile_self.rs`
- [ ] `src/storage/mod.rs`
- [ ] `src/storage/msr.rs`
- [ ] `src/storage/one_share.rs`
- [ ] `src/storage/one_view.rs`
- [ ] `src/storage/pact_binding.rs`
- [ ] `src/storage/payload_crypt.rs`
- [ ] `src/storage/provider.rs`
- [ ] `src/storage/pruning.rs`
- [ ] `src/storage/qr_carousel.rs`
- [ ] `src/storage/qr_codec.rs`
- [ ] `src/storage/qr_encode.rs`
- [ ] `src/storage/qr_frame.rs`
- [ ] `src/storage/qr_matrix.rs`
- [ ] `src/storage/qr_payload.rs`
- [ ] `src/storage/qr_png.rs`
- [ ] `src/storage/qr_receive.rs`
- [ ] `src/storage/qr_recipe.rs`
- [ ] `src/storage/qr_reemit.rs`
- [ ] `src/storage/qr_verify.rs`
- [ ] `src/storage/qr_verify_indep.rs`
- [ ] `src/storage/qr_video.rs`
- [ ] `src/storage/render.rs`
- [ ] `src/storage/reveal_gateway.rs`
- [ ] `src/storage/server_admission.rs`
- [ ] `src/storage/social_delete.rs`
- [ ] `src/storage/three_gate.rs`
- [ ] `src/storage/three_hooks.rs`
- [ ] `src/storage/three_meter.rs`
- [ ] `src/storage/three_nft.rs`
- [ ] `src/storage/three_pipe.rs`
- [ ] `src/storage/three_recipe.rs`
- [ ] `src/storage/three_regime.rs`
- [ ] `src/storage/three_reveal.rs`
- [ ] `src/storage/three_rpc.rs`
- [ ] `src/storage/three_visibility.rs`
- [ ] `src/storage/traits.rs`
- [ ] `src/storage/transformed.rs`
- [ ] `src/storage/view_grant.rs`

### src/tests (89 files)

- [ ] `src/tests/adversarial_p2p.rs`
- [ ] `src/tests/advisory_reachability.rs`
- [ ] `src/tests/ai_inference_runtime.rs`
- [ ] `src/tests/ai_verification_status_locks.rs`
- [ ] `src/tests/audit_findings_locks.rs`
- [ ] `src/tests/audit_p49_locks.rs`
- [ ] `src/tests/bench_performance.rs`
- [ ] `src/tests/block_clock.rs`
- [ ] `src/tests/block_door_harness.rs`
- [ ] `src/tests/block_reward.rs`
- [ ] `src/tests/blockchair_fixture_locks.rs`
- [ ] `src/tests/bns.rs`
- [ ] `src/tests/bns_expanded.rs`
- [ ] `src/tests/bridge_lifecycle.rs`
- [ ] `src/tests/bridge_negatives.rs`
- [ ] `src/tests/bud_e2e.rs`
- [ ] `src/tests/byzantine_settlement.rs`
- [ ] `src/tests/chain_id_registry_locks.rs`
- [ ] `src/tests/chaos.rs`
- [ ] `src/tests/consensus_bypass_locks.rs`
- [ ] `src/tests/consensus_digest.rs`
- [ ] `src/tests/consensus_expanded.rs`
- [ ] `src/tests/consensus_lock_order_loom.rs`
- [ ] `src/tests/constitution_engine.rs`
- [ ] `src/tests/deed.rs`
- [ ] `src/tests/disaster_recovery.rs`
- [ ] `src/tests/distributed_settlement.rs`
- [ ] `src/tests/domain_edge_cases.rs`
- [ ] `src/tests/encryption_dao.rs`
- [ ] `src/tests/f20_priority_findings.rs`
- [ ] `src/tests/finality_adversarial.rs`
- [ ] `src/tests/finality_live_path.rs`
- [ ] `src/tests/fork_choice_locks.rs`
- [ ] `src/tests/genesis_repro.rs`
- [ ] `src/tests/hard_prune.rs`
- [ ] `src/tests/hardening.rs`
- [ ] `src/tests/hardening_h2_locks.rs`
- [ ] `src/tests/hardening_h4_locks.rs`
- [ ] `src/tests/hardening_h5_h7_locks.rs`
- [ ] `src/tests/hardening_locks.rs`
- [ ] `src/tests/hash_input_serialize_locks.rs`
- [ ] `src/tests/identity_tx_door.rs`
- [ ] `src/tests/integration.rs`
- [ ] `src/tests/liveness_consensus.rs`
- [ ] `src/tests/load_test.rs`
- [ ] `src/tests/manifest_commitment_locks.rs`
- [ ] `src/tests/mempool_dos_locks.rs`
- [ ] `src/tests/migration_v2.rs`
- [ ] `src/tests/mod.rs`
- [ ] `src/tests/multi_consensus_locks.rs`
- [ ] `src/tests/network_hardening_locks.rs`
- [ ] `src/tests/operator_kill_chaos.rs`
- [ ] `src/tests/p01_consensus_rounds.rs`
- [ ] `src/tests/permissionless.rs`
- [ ] `src/tests/permissionless_e2e.rs`
- [ ] `src/tests/persistence.rs`
- [ ] `src/tests/poa_isolation.rs`
- [ ] `src/tests/poa_onboarding_matrix.rs`
- [ ] `src/tests/poisoned_lock_locks.rs`
- [ ] `src/tests/pollen_ai_data_rights.rs`
- [ ] `src/tests/ported_slice_redteam.rs`
- [ ] `src/tests/pow_light_client.rs`
- [ ] `src/tests/privacy_ai_execution.rs`
- [ ] `src/tests/private_transfer_fee_market.rs`
- [ ] `src/tests/proptest_core.rs`
- [ ] `src/tests/prover.rs`
- [ ] `src/tests/qcblob_quorum.rs`
- [ ] `src/tests/real_chain_fixtures.rs`
- [ ] `src/tests/regeneration_recovery.rs`
- [ ] `src/tests/regression_lock.rs`
- [ ] `src/tests/relayer_e2e.rs`
- [ ] `src/tests/relayer_gates.rs`
- [ ] `src/tests/relayer_liveness.rs`
- [ ] `src/tests/relayer_worker_locks.rs`
- [ ] `src/tests/replay_audit.rs`
- [ ] `src/tests/security_auditor.rs`
- [ ] `src/tests/settlement_prod.rs`
- [ ] `src/tests/sharding_e2e.rs`
- [ ] `src/tests/slashing_matrix.rs`
- [ ] `src/tests/snapshot_chaos.rs`
- [ ] `src/tests/socialfi.rs`
- [ ] `src/tests/storage_tx_door.rs`
- [ ] `src/tests/target_700.rs`
- [ ] `src/tests/tokenomics.rs`
- [ ] `src/tests/tokenomics_proptest.rs`
- [ ] `src/tests/v95_v98_canaries.rs`
- [ ] `src/tests/vault_tx_door.rs`
- [ ] `src/tests/wall_clock_locks.rs`
- [ ] `src/tests/zkvm.rs`

### src/tokenomics (2 files)

- [ ] `src/tokenomics/mod.rs`
- [ ] `src/tokenomics/reward_pool.rs`

### supply-chain (3 files)

- [ ] `supply-chain/audits.toml`
- [ ] `supply-chain/config.toml`
- [ ] `supply-chain/imports.lock`

### xtask/gates (136 files)

- [ ] `xtask/gates/Cargo.lock`
- [ ] `xtask/gates/Cargo.toml`
- [ ] `xtask/gates/pins/budzero-tree.pins`
- [ ] `xtask/gates/src/gates/accumulators_pinned.rs`
- [ ] `xtask/gates/src/gates/actionlint.rs`
- [ ] `xtask/gates/src/gates/ai_inference_prompt_is_true.rs`
- [ ] `xtask/gates/src/gates/ai_inference_reads.rs`
- [ ] `xtask/gates/src/gates/ai_inference_zk.rs`
- [ ] `xtask/gates/src/gates/air_selectors.rs`
- [ ] `xtask/gates/src/gates/ast_security_gates.rs`
- [ ] `xtask/gates/src/gates/badges_current.rs`
- [ ] `xtask/gates/src/gates/binding_claims.rs`
- [ ] `xtask/gates/src/gates/bit_decompositions.rs`
- [ ] `xtask/gates/src/gates/bns_gate.rs`
- [ ] `xtask/gates/src/gates/bns_names_are_safe_in_an_address_bar.rs`
- [ ] `xtask/gates/src/gates/bridge_dual_tree.rs`
- [ ] `xtask/gates/src/gates/bud_e2e.rs`
- [ ] `xtask/gates/src/gates/budscan_parity.rs`
- [ ] `xtask/gates/src/gates/budscan_patchset.rs`
- [ ] `xtask/gates/src/gates/capability_modules_are_wired.rs`
- [ ] `xtask/gates/src/gates/cargo_vet.rs`
- [ ] `xtask/gates/src/gates/chain_id_is_not_hardcoded.rs`
- [ ] `xtask/gates/src/gates/ci_workflow_guards.rs`
- [ ] `xtask/gates/src/gates/clippy_extra.rs`
- [ ] `xtask/gates/src/gates/coding_audit_samples_the_relationship.rs`
- [ ] `xtask/gates/src/gates/consensus_maps_ordered.rs`
- [ ] `xtask/gates/src/gates/consensus_state_only_changes_in_blocks.rs`
- [ ] `xtask/gates/src/gates/containment_defaults.rs`
- [ ] `xtask/gates/src/gates/content_encryption_is_declared_and_bound.rs`
- [ ] `xtask/gates/src/gates/coverage.rs`
- [ ] `xtask/gates/src/gates/cross_table_checks.rs`
- [ ] `xtask/gates/src/gates/dead_pub_api.rs`
- [ ] `xtask/gates/src/gates/derived_content.rs`
- [ ] `xtask/gates/src/gates/docker_toolchain.rs`
- [ ] `xtask/gates/src/gates/domain_tags.rs`
- [ ] `xtask/gates/src/gates/economy_invariants.rs`
- [ ] `xtask/gates/src/gates/every_fuzz_target_is_run.rs`
- [ ] `xtask/gates/src/gates/every_opcode_forgery.rs`
- [ ] `xtask/gates/src/gates/evidence_provenance.rs`
- [ ] `xtask/gates/src/gates/exact_named_tests.rs`
- [ ] `xtask/gates/src/gates/fixture_integrity.rs`
- [ ] `xtask/gates/src/gates/forgery_tests.rs`
- [ ] `xtask/gates/src/gates/fork_choice_gate.rs`
- [ ] `xtask/gates/src/gates/fsf_import_boundaries.rs`
- [ ] `xtask/gates/src/gates/fuzz_targets_wired.rs`
- [ ] `xtask/gates/src/gates/gas_calibration.rs`
- [ ] `xtask/gates/src/gates/gates_are_wired.rs`
- [ ] `xtask/gates/src/gates/gates_do_not_panic.rs`
- [ ] `xtask/gates/src/gates/gating_flags.rs`
- [ ] `xtask/gates/src/gates/geiger.rs`
- [ ] `xtask/gates/src/gates/generated_content.rs`
- [ ] `xtask/gates/src/gates/genesis_schema.rs`
- [ ] `xtask/gates/src/gates/git_deps_audited.rs`
- [ ] `xtask/gates/src/gates/gov_slash_evidence_is_validator_only.rs`
- [ ] `xtask/gates/src/gates/governance_invariants.rs`
- [ ] `xtask/gates/src/gates/guards_reachable.rs`
- [ ] `xtask/gates/src/gates/hash_inputs_are_length_prefixed.rs`
- [ ] `xtask/gates/src/gates/indexing_is_not_new.rs`
- [ ] `xtask/gates/src/gates/kani.rs`
- [ ] `xtask/gates/src/gates/license_consistency.rs`
- [ ] `xtask/gates/src/gates/lock_failures.rs`
- [ ] `xtask/gates/src/gates/logup_multipliers.rs`
- [ ] `xtask/gates/src/gates/master_derivation.rs`
- [ ] `xtask/gates/src/gates/mempool_mev_free.rs`
- [ ] `xtask/gates/src/gates/mermaid.rs`
- [ ] `xtask/gates/src/gates/metrics_are_written.rs`
- [ ] `xtask/gates/src/gates/minting_paths_are_counted.rs`
- [ ] `xtask/gates/src/gates/module_coverage.rs`
- [ ] `xtask/gates/src/gates/multi_ratio_consensus.rs`
- [ ] `xtask/gates/src/gates/named_tests.rs`
- [ ] `xtask/gates/src/gates/network_hardening_gate.rs`
- [ ] `xtask/gates/src/gates/no_conflict_markers.rs`
- [ ] `xtask/gates/src/gates/no_idle_code.rs`
- [ ] `xtask/gates/src/gates/no_new_shell_gates.rs`
- [ ] `xtask/gates/src/gates/no_orphan_source_files.rs`
- [ ] `xtask/gates/src/gates/no_unicode_dashes.rs`
- [ ] `xtask/gates/src/gates/no_upstream_brands.rs`
- [ ] `xtask/gates/src/gates/node_classification_gate.rs`
- [ ] `xtask/gates/src/gates/one_house_guards.rs`
- [ ] `xtask/gates/src/gates/ownerless_dependencies.rs`
- [ ] `xtask/gates/src/gates/paid_content.rs`
- [ ] `xtask/gates/src/gates/parallel_execution.rs`
- [ ] `xtask/gates/src/gates/pinned_downloads.rs`
- [ ] `xtask/gates/src/gates/poa_compliance_gate.rs`
- [ ] `xtask/gates/src/gates/proof_deps_are_exactly_pinned.rs`
- [ ] `xtask/gates/src/gates/qr_is_derivative_only.rs`
- [ ] `xtask/gates/src/gates/quantum_account.rs`
- [ ] `xtask/gates/src/gates/readme_no_deny.rs`
- [ ] `xtask/gates/src/gates/reduction_claims.rs`
- [ ] `xtask/gates/src/gates/refusals_no_mutate.rs`
- [ ] `xtask/gates/src/gates/regen_health_door.rs`
- [ ] `xtask/gates/src/gates/regeneration.rs`
- [ ] `xtask/gates/src/gates/rejection_tests.rs`
- [ ] `xtask/gates/src/gates/relay.rs`
- [ ] `xtask/gates/src/gates/release_profile_pins.rs`
- [ ] `xtask/gates/src/gates/repair_fires.rs`
- [ ] `xtask/gates/src/gates/required_tests.rs`
- [ ] `xtask/gates/src/gates/rust_literals.rs`
- [ ] `xtask/gates/src/gates/security_parameters.rs`
- [ ] `xtask/gates/src/gates/security_quality_wired.rs`
- [ ] `xtask/gates/src/gates/security_scans_can_fail.rs`
- [ ] `xtask/gates/src/gates/self_derived_ids_cover_every_field.rs`
- [ ] `xtask/gates/src/gates/semver.rs`
- [ ] `xtask/gates/src/gates/serialize_map_keys_are_strings.rs`
- [ ] `xtask/gates/src/gates/shard_placement.rs`
- [ ] `xtask/gates/src/gates/slash_expression.rs`
- [ ] `xtask/gates/src/gates/source_reading.rs`
- [ ] `xtask/gates/src/gates/storage_penalties.rs`
- [ ] `xtask/gates/src/gates/storage_priced.rs`
- [ ] `xtask/gates/src/gates/storage_proof_boundary.rs`
- [ ] `xtask/gates/src/gates/storage_provider_gate.rs`
- [ ] `xtask/gates/src/gates/suppressions_are_justified.rs`
- [ ] `xtask/gates/src/gates/tee_trust_boundary_is_structural.rs`
- [ ] `xtask/gates/src/gates/test_modules_can_see_what_they_test.rs`
- [ ] `xtask/gates/src/gates/the_image_builds_what_the_manifest_declares.rs`
- [ ] `xtask/gates/src/gates/three_is_recipe_only.rs`
- [ ] `xtask/gates/src/gates/threshold_rates.rs`
- [ ] `xtask/gates/src/gates/timing_safe.rs`
- [ ] `xtask/gates/src/gates/transcript_mirrors.rs`
- [ ] `xtask/gates/src/gates/tree_is_english.rs`
- [ ] `xtask/gates/src/gates/tree_pin.rs`
- [ ] `xtask/gates/src/gates/typos.rs`
- [ ] `xtask/gates/src/gates/udeps.rs`
- [ ] `xtask/gates/src/gates/uncheckable_proof.rs`
- [ ] `xtask/gates/src/gates/untrusted_manifests.rs`
- [ ] `xtask/gates/src/gates/value_transfers.rs`
- [ ] `xtask/gates/src/gates/wallet_core_gate.rs`
- [ ] `xtask/gates/src/gates/wallet_node_address_agree.rs`
- [ ] `xtask/gates/src/gates/wire_fields_are_signed.rs`
- [ ] `xtask/gates/src/gates/workflows_produce_jobs.rs`
- [ ] `xtask/gates/src/gates/zero_address_sender_is_verified.rs`
- [ ] `xtask/gates/src/gates/zero_storage_frozen.rs`
- [ ] `xtask/gates/src/gates/zero_tests_witness.rs`
- [ ] `xtask/gates/src/gates/zizmor.rs`
- [ ] `xtask/gates/src/gates/zkvm_immune_regeneration.rs`
- [ ] `xtask/gates/src/main.rs`

### xtask/tools (23 files)

- [ ] `xtask/tools/Cargo.lock`
- [ ] `xtask/tools/Cargo.toml`
- [ ] `xtask/tools/src/audit_deps.rs`
- [ ] `xtask/tools/src/audit_guard.rs`
- [ ] `xtask/tools/src/backup_drill.rs`
- [ ] `xtask/tools/src/bin/budlum-tools.rs`
- [ ] `xtask/tools/src/clippy_extra_report.rs`
- [ ] `xtask/tools/src/dep_snapshot.rs`
- [ ] `xtask/tools/src/devnet.rs`
- [ ] `xtask/tools/src/docker_smoke.rs`
- [ ] `xtask/tools/src/fsf_fit.rs`
- [ ] `xtask/tools/src/json.rs`
- [ ] `xtask/tools/src/lib.rs`
- [ ] `xtask/tools/src/multinode_smoke.rs`
- [ ] `xtask/tools/src/prepush.rs`
- [ ] `xtask/tools/src/report.rs`
- [ ] `xtask/tools/src/rpc.rs`
- [ ] `xtask/tools/src/sarif.rs`
- [ ] `xtask/tools/src/sbom.rs`
- [ ] `xtask/tools/src/seed_corpus.rs`
- [ ] `xtask/tools/src/smoke_rpc.rs`
- [ ] `xtask/tools/src/step_reachability.rs`
- [ ] `xtask/tools/src/support.rs`
