# Budlum audit plan

This is a working checklist, not a claim that an unchecked item is complete.
Captured PR inventory: 2026-11-15T13:37:15.914292+00:00.
Branch: audit-testnet-2026-11, based on main 95c07fd72faaf21656e1e44d2dff51ed4dee05f3.
The attached main directive is an external input; it is not present as a tracked file in these trees. Do not commit the attachment or credentials.

## Process

- [ ] Trace every finding end to end and record evidence, including all same-class paths.
- [ ] Fix each valid root cause on the relevant PR branch and add negative and positive regression tests.
- [ ] Establish activation, historical replay and snapshot compatibility for every consensus change.
- [ ] Run fmt, clippy with warnings denied, tests, and applicable CI/security gates without weakening checks.
- [ ] Commit focused changes referencing finding identifiers and push to the correct branch.
- [ ] Record commit SHA and green CI run before replying, resolving or attempting to delete review comments.
- [ ] Keep the Strix ledger and capture current before any permitted deletion; obtain Strix approval.
- [ ] Review every file and every line below; check an item only after recording evidence.
- [ ] Inspect all PR diffs in full and verify current head, base, protection, checks and reviews before any merge.
- [ ] Produce detailed implementation designs for every main directive requirement, including deferred items.
- [ ] Test every planned operating system using an actual runner, container or virtual machine.
- [ ] Preserve the definition blocks in both READMEs byte for byte and keep the two structures aligned.
- [ ] Never add allow/ignore attributes, disable security gates, force-push or bypass branch protection.

## Open PRs at capture

- [ ] #110 Testnet and Quantum: testnet-quantum -> main; head `a52933e131050a2027a0d90d582881a68d4e7405`; base `95c07fd72faaf21656e1e44d2dff51ed4dee05f3`. Threads unresolved: 6. Merge state: blocked. Checks at capture: completed/failure: 1, completed/neutral: 1, completed/skipped: 1, completed/success: 124.
- [ ] #126 testnet: testnet -> testnet-quantum; head `ea1440975ad4b82aef2a92b95d43f275727d9e33`; base `a52933e131050a2027a0d90d582881a68d4e7405`. Threads unresolved: 61. Merge state: blocked. Checks at capture: completed/neutral: 1, completed/skipped: 33, completed/success: 13, in_progress/pending: 4, queued/pending: 82.
- [ ] #164 Garden: garden -> main; head `d4a76a7521de3e06ac2c582670bacca3e206b3db`; base `95c07fd72faaf21656e1e44d2dff51ed4dee05f3`. Threads unresolved: 19. Merge state: blocked. Checks at capture: completed/failure: 1, completed/neutral: 1, completed/skipped: 1, completed/success: 113.

The audit PR itself is not part of the initial open-PR baseline. Recheck live before acting.

## Operating systems

- [ ] Debian 13 x86_64: sandbox; complete builds, applications and tests remain pending.
- [ ] Ubuntu 24.04 LTS x86_64: CI runner and container.
- [ ] Ubuntu 24.04 LTS aarch64: CI runner.
- [ ] Ubuntu 22.04 LTS x86_64: container.
- [ ] Debian 12 x86_64: container.
- [ ] Fedora x86_64: container.
- [ ] Rocky Linux 9 x86_64: container.
- [ ] Alpine Linux x86_64 and musl: container.
- [ ] Chainguard Wolfi x86_64: runtime image.
- [ ] macOS arm64 and x86_64: CI runner.
- [ ] Windows Server x86_64: CI runner.
- [ ] Android aarch64 and x86_64: emulator or CI cross-target plus runtime.
- [ ] iOS arm64 and simulator: runner plus runtime.

A cross-compile alone is not a runtime or an end-to-end test. Record unavailable environments rather than claiming coverage.

## Tracked directory and file inventory

The union of the four captured Git trees contains 1789 unique tracked files in 311 file-containing directories. Brackets list the source branches; every item starts unchecked. Parent directories are represented by their file-bearing descendants. Gitlinks, binary assets and generated artifacts must be reviewed by their appropriate method.

### `.` (16 files)

- [ ] `.coderabbit.yaml` (main, testnet-quantum, garden, testnet)
- [ ] `.gitignore` (main, testnet-quantum, garden, testnet)
- [ ] `.gitleaks.toml` (main, testnet-quantum, garden, testnet)
- [ ] `.gitleaksignore` (main, testnet-quantum, garden, testnet)
- [ ] `Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `Cargo.toml` (main, testnet-quantum, garden, testnet)
- [ ] `LICENSE.md` (main, testnet-quantum, garden, testnet)
- [ ] `README.md` (main, testnet-quantum, garden, testnet)
- [ ] `README.tr.md` (main, testnet-quantum, garden, testnet)
- [ ] `buf.yaml` (main, testnet-quantum, garden, testnet)
- [ ] `build.rs` (main, testnet-quantum, garden, testnet)
- [ ] `clippy.toml` (main, testnet-quantum, garden, testnet)
- [ ] `flake.lock` (main, testnet-quantum, garden, testnet)
- [ ] `flake.nix` (main, testnet-quantum, garden, testnet)
- [ ] `osv-scanner.toml` (main, testnet-quantum, garden, testnet)
- [ ] `rust-toolchain.toml` (main, testnet-quantum, garden, testnet)

### `.cargo` (1 files)

- [ ] `.cargo/audit.toml` (main, testnet-quantum, garden, testnet)

### `.github` (25 files)

- [ ] `.github/CODEOWNERS` (main, testnet-quantum, garden, testnet)
- [ ] `.github/PULL_REQUEST_TEMPLATE.md` (main, testnet-quantum, garden, testnet)
- [ ] `.github/actionlint.yaml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/bud3-forbidden-phrases-baseline.txt` (testnet)
- [ ] `.github/cargo-vet-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/clippy-extra-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/concept-names-baseline.txt` (testnet)
- [ ] `.github/coverage-badge.json` (main, testnet-quantum, garden, testnet)
- [ ] `.github/coverage-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/dead-pub-api-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/dependabot.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/gate-panics-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/git-dep-audit.toml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/idle-code-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/no-legacy-storage-baseline.txt` (testnet)
- [ ] `.github/readme-placeholders-baseline.txt` (testnet)
- [ ] `.github/rpc-method-coverage-baseline.txt` (testnet)
- [ ] `.github/rpc-test-coverage-baseline.txt` (testnet)
- [ ] `.github/semver-exceptions.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/tsan-suppressions-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/tsan-suppressions.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/turkish-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/udeps-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/unwired-guards-baseline.txt` (main, testnet-quantum, garden, testnet)
- [ ] `.github/unwritten-metrics-baseline.txt` (main, testnet-quantum, garden, testnet)

### `.github/ISSUE_TEMPLATE` (5 files)

- [ ] `.github/ISSUE_TEMPLATE/bug-report.md` (main, testnet-quantum, garden, testnet)
- [ ] `.github/ISSUE_TEMPLATE/documentation-issue.md` (main, testnet-quantum, garden, testnet)
- [ ] `.github/ISSUE_TEMPLATE/feature-request.md` (main, testnet-quantum, garden, testnet)
- [ ] `.github/ISSUE_TEMPLATE/protocol---consensus-proposal.md` (main, testnet-quantum, garden, testnet)
- [ ] `.github/ISSUE_TEMPLATE/question---discussion.md` (main, testnet-quantum, garden, testnet)

### `.github/codeql` (1 files)

- [ ] `.github/codeql/codeql-config.yml` (main, testnet-quantum, garden, testnet)

### `.github/workflows` (38 files)

- [ ] `.github/workflows/air-mutants-nightly.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/audit-guard.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/benchmark.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/cargo-vet.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/churn-nightly.yml` (testnet)
- [ ] `.github/workflows/ci.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/code-scanning-sarif.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/conformance-nightly.yml` (testnet)
- [ ] `.github/workflows/contract-lockfiles.yml` (testnet)
- [ ] `.github/workflows/dependency-review.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/dependency-submission.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/determinism.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/diverse-double-compiling.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/docker-smoke.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/extra-tooling.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/fmt-diff-surface.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/fuzz-nightly.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/garden-nat-nightly.yml` (garden)
- [ ] `.github/workflows/grype.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/kani-slow.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/miri-storage-weekly.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/miri.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/mobile-ios.yml` (testnet)
- [ ] `.github/workflows/mobile.yml` (testnet)
- [ ] `.github/workflows/osv-scanner.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/pkcs11-pq.yml` (testnet-quantum, testnet)
- [ ] `.github/workflows/provenance.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/release-signature.yml` (testnet-quantum, testnet)
- [ ] `.github/workflows/rust.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/security-audit.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/security-hardening.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/semgrep.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/semver.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/solidity.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/supply-chain-extra.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/testnet-rehearsal.yml` (testnet-quantum, testnet)
- [ ] `.github/workflows/typos.yml` (main, testnet-quantum, garden, testnet)
- [ ] `.github/workflows/watchdog.yml` (main, testnet-quantum, garden, testnet)

### `.quality` (5 files)

- [ ] `.quality/deny-fuzz.toml` (testnet-quantum, testnet)
- [ ] `.quality/deny-mobile-ffi.toml` (testnet)
- [ ] `.quality/deny.toml` (main, testnet-quantum, garden, testnet)
- [ ] `.quality/grype.yaml` (main, testnet-quantum, garden, testnet)
- [ ] `.quality/typos.toml` (main, testnet-quantum, garden, testnet)

### `assets` (2 files)

- [ ] `assets/budlum-consensus-of-consensuses.png` (main, testnet-quantum, garden, testnet)
- [ ] `assets/budlum-konsensuslerin-konsensusu.png` (main, testnet-quantum, garden, testnet)

### `benches` (1 files)

- [ ] `benches/domain_throughput.rs` (main, testnet-quantum, garden, testnet)

### `benches/micro` (6 files)

- [ ] `benches/micro/erasure_rows.rs` (main, testnet-quantum, garden, testnet)
- [ ] `benches/micro/merkle_scaling.rs` (main, testnet-quantum, garden, testnet)
- [ ] `benches/micro/merkle_update.rs` (main, testnet-quantum, garden, testnet)
- [ ] `benches/micro/ratio_rayon.rs` (main, testnet-quantum, garden, testnet)
- [ ] `benches/micro/sig_verify.rs` (main, testnet-quantum, garden, testnet)
- [ ] `benches/micro/timing_safe.rs` (main, testnet-quantum, garden, testnet)

### `benches/single_node` (1 files)

- [ ] `benches/single_node/internal_pipeline_tps.rs` (main, testnet-quantum, garden, testnet)

### `bud` (5 files)

- [ ] `bud/Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `bud/Cargo.toml` (main, testnet-quantum, garden, testnet)
- [ ] `bud/FORMAT-V2.md` (main, testnet-quantum, garden, testnet)
- [ ] `bud/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `bud/mime.types.bud.json` (main, testnet-quantum, garden, testnet)

### `bud/fuzz` (2 files)

- [ ] `bud/fuzz/Cargo.toml` (main, testnet-quantum, garden, testnet)
- [ ] `bud/fuzz/fuzz_bud_format.rs` (main, testnet-quantum, garden, testnet)

### `bud/kani` (1 files)

- [ ] `bud/kani/kani_bud_format.rs` (main, testnet-quantum, garden, testnet)

### `bud/src` (104 files)

- [ ] `bud/src/bud3_live_test.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_fixed_point.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_autozstd.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_av2.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_bft.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_block.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_bloom.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_catalog.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_checkpoint.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_columnar.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_container.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_crop.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_culling.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_das.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_dbdelta.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_dedup.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_dictionary.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_economics.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_edge.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_edition.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_encpact.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_engine.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_erasure.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_exepdf.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_fastcdc.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_fidelitygate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_fountain.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_genomic.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_governance.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_guardian.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_hardening.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_huffman.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_hw.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_integration.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_jpegre.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_lazyrepair.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_logfield.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_lowrank.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_lrc.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_markdown.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_matrix.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_media.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_model.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_msr.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_multifile.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_nvc.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_office.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_optical.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_optical_transfer.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_pact.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_pcap.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_pgm.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_pipe.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_pointcloud.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_por.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_prodcost.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_production.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_qos.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_qrmatrix.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_qrvideo.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_r3fix.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_ratioconsensus.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_real.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_realcorpus.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_recipe.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_recipe_record.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_regeneration.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_repairband.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_revolutionary.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_scrub.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_secure_db.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_securededup.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_segment.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_serviceclass.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_shamir.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_social.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_social2.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_spec.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_telemetry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_timeseries.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_tiny.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_transpile.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_tricore.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_ultra.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_ux.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_video.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_videopipe.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_view.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_wal.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_wire.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_zkbridge.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bud_format_zkproof.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/churn.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/cli.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/fidelity.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/gates.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/price.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/provider.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/quantum.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/quantum_chain.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/ratio.rs` (main, testnet-quantum, garden, testnet)

### `bud/src/bin` (2 files)

- [ ] `bud/src/bin/bud.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/src/bin/measure_ratios.rs` (main, testnet-quantum, garden, testnet)

### `bud/tests` (2 files)

- [ ] `bud/tests/test_bud2.rs` (main, testnet-quantum, garden, testnet)
- [ ] `bud/tests/test_integration.rs` (main, testnet-quantum, garden, testnet)

### `bud/tests/fixtures` (3 files)

- [ ] `bud/tests/fixtures/image.png` (main, testnet-quantum, garden, testnet)
- [ ] `bud/tests/fixtures/text.log` (main, testnet-quantum, garden, testnet)
- [ ] `bud/tests/fixtures/video.yuv` (main, testnet-quantum, garden, testnet)

### `budzero` (17 files)

- [ ] `budzero/.gitignore` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/ARCHITECTURE.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/Cargo.toml` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/LICENSE` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/control_flow.bud` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/deny.toml` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/example.bud` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/example2.bud` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/example_loop.bud` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/flake.lock` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/flake.nix` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/osv-scanner.toml` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/rust-toolchain.toml` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/state.json` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/test_prover.bud` (main, testnet-quantum, garden, testnet)

### `budzero/bud-cli` (1 files)

- [ ] `budzero/bud-cli/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `budzero/bud-cli/src` (1 files)

- [ ] `budzero/bud-cli/src/main.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-cli/tests` (1 files)

- [ ] `budzero/bud-cli/tests/toolchain_end_to_end.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-compiler` (1 files)

- [ ] `budzero/bud-compiler/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `budzero/bud-compiler/src` (6 files)

- [ ] `budzero/bud-compiler/src/ast.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-compiler/src/codegen.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-compiler/src/lexer.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-compiler/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-compiler/src/parser.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-compiler/src/sema.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-compiler/src/ir` (4 files)

- [ ] `budzero/bud-compiler/src/ir/display.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-compiler/src/ir/lower.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-compiler/src/ir/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-compiler/src/ir/verify.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-compiler/tests` (1 files)

- [ ] `budzero/bud-compiler/tests/regression.rs` (testnet)

### `budzero/bud-isa` (1 files)

- [ ] `budzero/bud-isa/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `budzero/bud-isa/src` (1 files)

- [ ] `budzero/bud-isa/src/lib.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-node` (1 files)

- [ ] `budzero/bud-node/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `budzero/bud-node/src` (5 files)

- [ ] `budzero/bud-node/src/bitswap.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-node/src/discovery.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-node/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-node/src/sharding.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-node/src/store.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-proof` (1 files)

- [ ] `budzero/bud-proof/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `budzero/bud-proof/benches` (2 files)

- [ ] `budzero/bud-proof/benches/canonical_programs.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/benches/proof_baseline.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-proof/src` (15 files)

- [ ] `budzero/bud-proof/src/adapter.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/alarm_log.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/canonical_boot.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/canonical_recovery.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/canonical_set.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/hiding.rs` (testnet)
- [ ] `budzero/bud-proof/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/plonky3_air.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/plonky3_prover.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/predicates.rs` (testnet)
- [ ] `budzero/bud-proof/src/quarantine.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/relayer.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/sigagg.rs` (testnet)
- [ ] `budzero/bud-proof/src/trace_layout_tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/transfer_verdict.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-proof/src/bud_stark` (9 files)

- [ ] `budzero/bud-proof/src/bud_stark/config.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/bud_stark/folder.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/bud_stark/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/bud_stark/preprocessed.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/bud_stark/proof.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/bud_stark/prover.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/bud_stark/sub_builder.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/bud_stark/symbolic.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/src/bud_stark/verifier.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-proof/tests` (5 files)

- [ ] `budzero/bud-proof/tests/compiled_branching.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/tests/fiat_shamir_binding.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-proof/tests/poseidon_parity.rs` (testnet-quantum, testnet)
- [ ] `budzero/bud-proof/tests/regression.rs` (testnet)
- [ ] `budzero/bud-proof/tests/soundness_negatives.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-pul` (1 files)

- [ ] `budzero/bud-pul/Cargo.toml` (testnet-quantum, testnet)

### `budzero/bud-pul/examples` (1 files)

- [ ] `budzero/bud-pul/examples/pul_measure.rs` (testnet-quantum, testnet)

### `budzero/bud-pul/src` (5 files)

- [ ] `budzero/bud-pul/src/keccak_chip.rs` (testnet-quantum, testnet)
- [ ] `budzero/bud-pul/src/lib.rs` (testnet-quantum, testnet)
- [ ] `budzero/bud-pul/src/mldsa_ntt.rs` (testnet-quantum, testnet)
- [ ] `budzero/bud-pul/src/pul_air.rs` (testnet-quantum, testnet)
- [ ] `budzero/bud-pul/src/threshold.rs` (testnet-quantum, testnet)

### `budzero/bud-state` (1 files)

- [ ] `budzero/bud-state/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `budzero/bud-state/src` (2 files)

- [ ] `budzero/bud-state/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-state/src/note.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-vm` (1 files)

- [ ] `budzero/bud-vm/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `budzero/bud-vm/src` (3 files)

- [ ] `budzero/bud-vm/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-vm/src/private_transfer.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/bud-vm/src/syscall_context.rs` (main, testnet-quantum, garden, testnet)

### `budzero/bud-vm/tests` (1 files)

- [ ] `budzero/bud-vm/tests/trace_fixtures.rs` (main, testnet-quantum, garden, testnet)

### `budzero/docs` (16 files)

- [ ] `budzero/docs/BudL_SPEC.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/STABILIZATION.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/adding_opcodes.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/advanced_language_features_and_memory_management.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/compiler_and_ecosystem.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/development.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/introduction.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/isa_and_bytecode.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/production_hardening_and_soundness.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/proof_format_release_checklist.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/prover_stabilization_and_tests.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/stark_and_plonky3.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/virtual_machine.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/vm_trace_schema.md` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/docs/zk_friendly_architecture.md` (main, testnet-quantum, garden, testnet)

### `budzero/verifier-registry` (1 files)

- [ ] `budzero/verifier-registry/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `budzero/verifier-registry/src` (6 files)

- [ ] `budzero/verifier-registry/src/address.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/verifier-registry/src/evidence.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/verifier-registry/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/verifier-registry/src/params.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/verifier-registry/src/registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `budzero/verifier-registry/src/role.rs` (main, testnet-quantum, garden, testnet)

### `budzero/verifier-registry/tests` (1 files)

- [ ] `budzero/verifier-registry/tests/regression.rs` (testnet)

### `config` (11 files)

- [ ] `config/archive.toml` (main, testnet-quantum, garden, testnet)
- [ ] `config/ceremony-rehearsal-genesis.json` (testnet)
- [ ] `config/ceremony-rehearsal-template.json` (testnet)
- [ ] `config/devnet-genesis.json` (main, testnet-quantum, garden, testnet)
- [ ] `config/devnet.toml` (main, testnet-quantum, garden, testnet)
- [ ] `config/mainnet-genesis.json` (main, testnet-quantum, garden, testnet)
- [ ] `config/mainnet.toml` (main, testnet-quantum, garden, testnet)
- [ ] `config/rehearsal-genesis.json` (testnet)
- [ ] `config/testnet-ethereum.toml` (testnet-quantum, testnet)
- [ ] `config/testnet-genesis.json` (main, testnet-quantum, garden, testnet)
- [ ] `config/testnet.toml` (main, testnet-quantum, garden, testnet)

### `config/fixtures` (1 files)

- [ ] `config/fixtures/real-chain.json` (main, testnet-quantum, garden, testnet)

### `config/naming` (1 files)

- [ ] `config/naming/concept_map.toml` (testnet)

### `config/personas` (3 files)

- [ ] `config/personas/developer.toml` (main, testnet-quantum, garden, testnet)
- [ ] `config/personas/enterprise-poa.toml` (main, testnet-quantum, garden, testnet)
- [ ] `config/personas/user-devnet.toml` (main, testnet-quantum, garden, testnet)

### `contracts` (2 files)

- [ ] `contracts/README.md` (testnet-quantum, testnet)
- [ ] `contracts/foundry.toml` (testnet-quantum, testnet)

### `contracts/app_binding` (3 files)

- [ ] `contracts/app_binding/AppBindingExecutor.sol` (testnet)
- [ ] `contracts/app_binding/BudlumPaymentReceiver.sol` (testnet)
- [ ] `contracts/app_binding/BudlumRemoteAccountFactory.sol` (testnet)

### `contracts/external-domain` (1 files)

- [ ] `contracts/external-domain/BudlumFinalityVerifier.sol` (main, testnet-quantum, garden, testnet)

### `contracts/graft` (3 files)

- [ ] `contracts/graft/BudlumPaymentReceiver.sol` (testnet-quantum)
- [ ] `contracts/graft/BudlumRemoteAccountFactory.sol` (testnet-quantum)
- [ ] `contracts/graft/GraftExecutor.sol` (testnet-quantum)

### `contracts/lib` (3 files)

- [ ] `contracts/lib/BudlumBls.sol` (testnet-quantum, testnet)
- [ ] `contracts/lib/BudlumHash.sol` (testnet-quantum, testnet)
- [ ] `contracts/lib/BudlumOutbound.sol` (testnet-quantum, testnet)

### `contracts/mikoriza` (3 files)

- [ ] `contracts/mikoriza/BudlumRegistrar.sol` (testnet-quantum, testnet)
- [ ] `contracts/mikoriza/BudlumSlasher.sol` (testnet-quantum, testnet)
- [ ] `contracts/mikoriza/IAllocationManager.sol` (testnet-quantum, testnet)

### `contracts/object-layer` (3 files)

- [ ] `contracts/object-layer/BudlumFinalityVerifier.sol` (testnet)
- [ ] `contracts/object-layer/BudlumSettlementEndpoint.sol` (testnet)
- [ ] `contracts/object-layer/README.md` (testnet)

### `contracts/object-layer/cosmwasm` (1 files)

- [ ] `contracts/object-layer/cosmwasm/Cargo.toml` (testnet)

### `contracts/object-layer/cosmwasm/src` (3 files)

- [ ] `contracts/object-layer/cosmwasm/src/contract.rs` (testnet)
- [ ] `contracts/object-layer/cosmwasm/src/lib.rs` (testnet)
- [ ] `contracts/object-layer/cosmwasm/src/verifier.rs` (testnet)

### `contracts/object-layer/move` (1 files)

- [ ] `contracts/object-layer/move/Move.toml` (testnet)

### `contracts/object-layer/move/sources` (2 files)

- [ ] `contracts/object-layer/move/sources/budlum_verifier.move` (testnet)
- [ ] `contracts/object-layer/move/sources/settlement_endpoint.move` (testnet)

### `contracts/object-layer/svm` (1 files)

- [ ] `contracts/object-layer/svm/Cargo.toml` (testnet)

### `contracts/object-layer/svm/src` (2 files)

- [ ] `contracts/object-layer/svm/src/lib.rs` (testnet)
- [ ] `contracts/object-layer/svm/src/verifier.rs` (testnet)

### `contracts/test` (5 files)

- [ ] `contracts/test/AppBinding.t.sol` (testnet)
- [ ] `contracts/test/BudlumFinalityVerifier.t.sol` (testnet-quantum, testnet)
- [ ] `contracts/test/Graft.t.sol` (testnet-quantum)
- [ ] `contracts/test/Harness.sol` (testnet-quantum, testnet)
- [ ] `contracts/test/Mikoriza.t.sol` (testnet-quantum, testnet)

### `contracts/uel` (1 files)

- [ ] `contracts/uel/BudlumUniversal.sol` (testnet)

### `crates/ai-inference` (6 files)

- [ ] `crates/ai-inference/.gitignore` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/ARCHITECTURE.md` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/Cargo.toml` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/LICENSE.md` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/README.md` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-core` (1 files)

- [ ] `crates/ai-inference/crates/ai-core/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-core/src` (7 files)

- [ ] `crates/ai-inference/crates/ai-core/src/dataset.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-core/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-core/src/manifest.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-core/src/model.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-core/src/system_prompt.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-core/src/tier.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-core/src/verification.rs` (testnet)

### `crates/ai-inference/crates/ai-data` (1 files)

- [ ] `crates/ai-inference/crates/ai-data/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-data/src` (5 files)

- [ ] `crates/ai-inference/crates/ai-data/src/jsonl.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-data/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-data/src/source.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-data/src/template.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-data/src/verify.rs` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-integrations` (1 files)

- [ ] `crates/ai-inference/crates/ai-integrations/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-integrations/src` (3 files)

- [ ] `crates/ai-inference/crates/ai-integrations/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-integrations/src/rest.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-integrations/src/ws.rs` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-knowledge` (1 files)

- [ ] `crates/ai-inference/crates/ai-knowledge/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-knowledge/src` (7 files)

- [ ] `crates/ai-inference/crates/ai-knowledge/src/cache.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-knowledge/src/chunk.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-knowledge/src/context.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-knowledge/src/embed.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-knowledge/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-knowledge/src/memory.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-knowledge/src/redact.rs` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-ops` (1 files)

- [ ] `crates/ai-inference/crates/ai-ops/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-ops/src` (3 files)

- [ ] `crates/ai-inference/crates/ai-ops/src/cli.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-ops/src/logparse.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-ops/src/main.rs` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-serve` (1 files)

- [ ] `crates/ai-inference/crates/ai-serve/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-serve/src` (11 files)

- [ ] `crates/ai-inference/crates/ai-serve/src/bridge.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/chain.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/config.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/cost_forecast.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/fee_scenario.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/health.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/metric.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/residency.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/staging.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-serve/src/validator_cost.rs` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-tune` (1 files)

- [ ] `crates/ai-inference/crates/ai-tune/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-tune/data` (1 files)

- [ ] `crates/ai-inference/crates/ai-tune/data/ai-behaviour-curriculum.jsonl` (main, testnet-quantum, garden, testnet)

### `crates/ai-inference/crates/ai-tune/src` (5 files)

- [ ] `crates/ai-inference/crates/ai-tune/src/eval.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-tune/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-tune/src/lock.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-tune/src/plan.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/ai-inference/crates/ai-tune/src/schema.rs` (main, testnet-quantum, garden, testnet)

### `crates/bpqs` (4 files)

- [ ] `crates/bpqs/Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/Cargo.toml` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/SECURITY-ARGUMENT.md` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/VERIFYMERKLE-EXPRESSIBILITY.md` (main, testnet-quantum, garden, testnet)

### `crates/bpqs/examples` (5 files)

- [ ] `crates/bpqs/examples/bench_differential.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/examples/bench_perm.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/examples/checksum_domination_exact.expected.txt` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/examples/checksum_domination_exact.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/examples/dudect_poseidon2.rs` (main, testnet-quantum, garden, testnet)

### `crates/bpqs/kat` (1 files)

- [ ] `crates/bpqs/kat/bpqs-kat-v1.txt` (main, testnet-quantum, garden, testnet)

### `crates/bpqs/src` (12 files)

- [ ] `crates/bpqs/src/epoch.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/error.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/hash.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/merkle.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/params.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/poseidon2.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/shake256.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/sign.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/tests_backends.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/bpqs/src/wots.rs` (main, testnet-quantum, garden, testnet)

### `crates/bud-codec` (2 files)

- [ ] `crates/bud-codec/Cargo.lock` (testnet)
- [ ] `crates/bud-codec/Cargo.toml` (testnet)

### `crates/bud-codec/src` (4 files)

- [ ] `crates/bud-codec/src/codecs.rs` (testnet)
- [ ] `crates/bud-codec/src/lib.rs` (testnet)
- [ ] `crates/bud-codec/src/registry.rs` (testnet)
- [ ] `crates/bud-codec/src/shared_context.rs` (testnet)

### `crates/budlum-explorer` (3 files)

- [ ] `crates/budlum-explorer/Cargo.lock` (testnet)
- [ ] `crates/budlum-explorer/Cargo.toml` (testnet)
- [ ] `crates/budlum-explorer/README.md` (testnet)

### `crates/budlum-explorer/browser` (3 files)

- [ ] `crates/budlum-explorer/browser/README.md` (testnet)
- [ ] `crates/budlum-explorer/browser/mozconfig` (testnet)
- [ ] `crates/budlum-explorer/browser/patches.txt` (testnet)

### `crates/budlum-explorer/browser/l10n/en-US` (1 files)

- [ ] `crates/budlum-explorer/browser/l10n/en-US/budlum-explorer.ftl` (testnet)

### `crates/budlum-explorer/browser/l10n/tr-TR` (1 files)

- [ ] `crates/budlum-explorer/browser/l10n/tr-TR/budlum-explorer.ftl` (testnet)

### `crates/budlum-explorer/browser/patches` (3 files)

- [ ] `crates/budlum-explorer/browser/patches/address-bar-verification-badge.patch` (testnet)
- [ ] `crates/budlum-explorer/browser/patches/bud-protocol-handler.patch` (testnet)
- [ ] `crates/budlum-explorer/browser/patches/name-bar-punycode.patch` (testnet)

### `crates/budlum-explorer/browser/settings` (2 files)

- [ ] `crates/budlum-explorer/browser/settings/budlum-explorer.cfg` (testnet)
- [ ] `crates/budlum-explorer/browser/settings/policies.json` (testnet)

### `crates/budlum-explorer/src` (17 files)

- [ ] `crates/budlum-explorer/src/arweave.rs` (testnet)
- [ ] `crates/budlum-explorer/src/bns_proof.rs` (testnet)
- [ ] `crates/budlum-explorer/src/cid.rs` (testnet)
- [ ] `crates/budlum-explorer/src/content_id.rs` (testnet)
- [ ] `crates/budlum-explorer/src/ens.rs` (testnet)
- [ ] `crates/budlum-explorer/src/evidence.rs` (testnet)
- [ ] `crates/budlum-explorer/src/evm_audit.rs` (testnet)
- [ ] `crates/budlum-explorer/src/fetch.rs` (testnet)
- [ ] `crates/budlum-explorer/src/indexer.rs` (testnet)
- [ ] `crates/budlum-explorer/src/lib.rs` (testnet)
- [ ] `crates/budlum-explorer/src/light_client.rs` (testnet)
- [ ] `crates/budlum-explorer/src/name_rule.rs` (testnet)
- [ ] `crates/budlum-explorer/src/patchset.rs` (testnet)
- [ ] `crates/budlum-explorer/src/punycode.rs` (testnet)
- [ ] `crates/budlum-explorer/src/query.rs` (testnet)
- [ ] `crates/budlum-explorer/src/resolve.rs` (testnet)
- [ ] `crates/budlum-explorer/src/search.rs` (testnet)

### `crates/budlum-explorer/src/bin` (1 files)

- [ ] `crates/budlum-explorer/src/bin/budlum-explorer.rs` (testnet)

### `crates/budlum-types` (2 files)

- [ ] `crates/budlum-types/Cargo.lock` (testnet)
- [ ] `crates/budlum-types/Cargo.toml` (testnet)

### `crates/budlum-types/src` (3 files)

- [ ] `crates/budlum-types/src/class.rs` (testnet)
- [ ] `crates/budlum-types/src/lib.rs` (testnet)
- [ ] `crates/budlum-types/src/presence.rs` (testnet)

### `crates/budscan` (3 files)

- [ ] `crates/budscan/Cargo.lock` (main, testnet-quantum, garden)
- [ ] `crates/budscan/Cargo.toml` (main, testnet-quantum, garden)
- [ ] `crates/budscan/README.md` (main, testnet-quantum, garden)

### `crates/budscan/browser` (3 files)

- [ ] `crates/budscan/browser/README.md` (main, testnet-quantum, garden)
- [ ] `crates/budscan/browser/mozconfig` (main, testnet-quantum, garden)
- [ ] `crates/budscan/browser/patches.txt` (main, testnet-quantum, garden)

### `crates/budscan/browser/l10n/en-US` (1 files)

- [ ] `crates/budscan/browser/l10n/en-US/budscan.ftl` (main, testnet-quantum, garden)

### `crates/budscan/browser/l10n/tr-TR` (1 files)

- [ ] `crates/budscan/browser/l10n/tr-TR/budscan.ftl` (main, testnet-quantum, garden)

### `crates/budscan/browser/patches` (3 files)

- [ ] `crates/budscan/browser/patches/address-bar-verification-badge.patch` (main, testnet-quantum, garden)
- [ ] `crates/budscan/browser/patches/bud-protocol-handler.patch` (main, testnet-quantum, garden)
- [ ] `crates/budscan/browser/patches/name-bar-punycode.patch` (main, testnet-quantum, garden)

### `crates/budscan/browser/settings` (2 files)

- [ ] `crates/budscan/browser/settings/budscan.cfg` (main, testnet-quantum, garden)
- [ ] `crates/budscan/browser/settings/policies.json` (main, testnet-quantum, garden)

### `crates/budscan/src` (17 files)

- [ ] `crates/budscan/src/arweave.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/bns_proof.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/cid.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/content_id.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/ens.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/evidence.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/evm_audit.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/fetch.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/indexer.rs` (testnet-quantum)
- [ ] `crates/budscan/src/lib.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/light_client.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/name_rule.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/patchset.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/punycode.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/query.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/resolve.rs` (main, testnet-quantum, garden)
- [ ] `crates/budscan/src/search.rs` (main, testnet-quantum, garden)

### `crates/budscan/src/bin` (1 files)

- [ ] `crates/budscan/src/bin/budscan.rs` (main, testnet-quantum, garden)

### `crates/note-packing` (2 files)

- [ ] `crates/note-packing/Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `crates/note-packing/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `crates/note-packing/src` (3 files)

- [ ] `crates/note-packing/src/digest4.rs` (testnet)
- [ ] `crates/note-packing/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/note-packing/src/poseidon.rs` (testnet-quantum, testnet)

### `crates/uel-abi` (3 files)

- [ ] `crates/uel-abi/Cargo.lock` (testnet)
- [ ] `crates/uel-abi/Cargo.toml` (testnet)
- [ ] `crates/uel-abi/build.rs` (testnet)

### `crates/uel-abi/src` (7 files)

- [ ] `crates/uel-abi/src/frame.rs` (testnet)
- [ ] `crates/uel-abi/src/host.rs` (testnet)
- [ ] `crates/uel-abi/src/lib.rs` (testnet)
- [ ] `crates/uel-abi/src/mock.rs` (testnet)
- [ ] `crates/uel-abi/src/transport.rs` (testnet)
- [ ] `crates/uel-abi/src/types.rs` (testnet)
- [ ] `crates/uel-abi/src/wire.rs` (testnet)

### `crates/uel-abi/tests` (5 files)

- [ ] `crates/uel-abi/tests/frames.rs` (testnet)
- [ ] `crates/uel-abi/tests/transport.rs` (testnet)
- [ ] `crates/uel-abi/tests/transport_deadlines.rs` (testnet)
- [ ] `crates/uel-abi/tests/transport_host_guards.rs` (testnet)
- [ ] `crates/uel-abi/tests/transport_worker_frames.rs` (testnet)

### `crates/wallet-core` (3 files)

- [ ] `crates/wallet-core/Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `crates/wallet-core/Cargo.toml` (main, testnet-quantum, garden, testnet)
- [ ] `crates/wallet-core/README.md` (main, testnet-quantum, garden, testnet)

### `crates/wallet-core/src` (12 files)

- [ ] `crates/wallet-core/src/api_surface_tests.rs` (testnet)
- [ ] `crates/wallet-core/src/bip39_wordlist.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/wallet-core/src/bns.rs` (testnet)
- [ ] `crates/wallet-core/src/consent_screen.rs` (testnet)
- [ ] `crates/wallet-core/src/crypto.rs` (testnet-quantum, testnet)
- [ ] `crates/wallet-core/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/wallet-core/src/privacy_crypto.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/wallet-core/src/privacy_transfer.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/wallet-core/src/rpc.rs` (testnet-quantum, testnet)
- [ ] `crates/wallet-core/src/tee.rs` (main, testnet-quantum, garden, testnet)
- [ ] `crates/wallet-core/src/transfer.rs` (testnet-quantum, testnet)
- [ ] `crates/wallet-core/src/wallet_v3.rs` (testnet-quantum, testnet)

### `crates/wallet-core/web` (1 files)

- [ ] `crates/wallet-core/web/index.html` (testnet-quantum, testnet)

### `docs` (47 files)

- [ ] `docs/AI_VERIFICATION_LAYER.md` (testnet)
- [ ] `docs/AI_VERIFICATION_STATUS.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/APP_BINDING.md` (testnet)
- [ ] `docs/APTOS_RPC.md` (testnet)
- [ ] `docs/ARCHITECTURE.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/BPQS_INDEPENDENT_REVIEW_CALL.md` (main, testnet-quantum, garden)
- [ ] `docs/BUDZERO_RECURSION_AND_BATCH_PROOFS.md` (testnet)
- [ ] `docs/BUD_CODEC_CONTEXT_AND_DEDUP.md` (testnet)
- [ ] `docs/BUD_CONTENT_ENCRYPTION.md` (main, testnet-quantum, garden)
- [ ] `docs/BUD_STORAGE_ROADMAP.md` (main, testnet-quantum, garden)
- [ ] `docs/CODE_OF_CONDUCT.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/CONTRIBUTING.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/DELEGATION.md` (testnet-quantum, testnet)
- [ ] `docs/DOMAIN_ADAPTER_GUIDE.md` (testnet-quantum, testnet)
- [ ] `docs/EVM_MIGRATION.md` (testnet)
- [ ] `docs/EXECUTION.md` (testnet)
- [ ] `docs/EXECUTION_LIMITS.md` (testnet)
- [ ] `docs/EXECUTION_PARALLEL_SCHEDULER.md` (testnet)
- [ ] `docs/FSF_ADAPTATION_PLAN.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/FSF_PROJECT_FIT.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/GRAFT.md` (testnet-quantum)
- [ ] `docs/LIGHT_CLIENT.md` (testnet)
- [ ] `docs/MAINNET_READINESS.md` (testnet-quantum, testnet)
- [ ] `docs/MIKORIZA.md` (testnet-quantum)
- [ ] `docs/MOBILE_DEVICE_MATRIX.md` (testnet)
- [ ] `docs/MOBILE_STORE_DISTRIBUTION.md` (testnet)
- [ ] `docs/NAMING.md` (testnet)
- [ ] `docs/NOTICE` (main, testnet-quantum, garden, testnet)
- [ ] `docs/OBJECT_LAYER.md` (testnet)
- [ ] `docs/OPERATIONS.md` (testnet-quantum, testnet)
- [ ] `docs/PARALLEL_EXECUTION.md` (testnet)
- [ ] `docs/PQ_ANCHOR_RESEARCH.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/PROVENANCE_NOTES.md` (main, testnet-quantum, garden)
- [ ] `docs/RPC_COMPAT.md` (testnet)
- [ ] `docs/SECURITY.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/SETTLEMENT.md` (testnet-quantum, testnet)
- [ ] `docs/SHARED_SECURITY.md` (testnet)
- [ ] `docs/SOLANA_RPC.md` (testnet)
- [ ] `docs/SPECIFICATION.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/STORAGE.md` (testnet)
- [ ] `docs/STORAGE_ENCRYPTION.md` (testnet)
- [ ] `docs/STORAGE_MEASUREMENTS.md` (testnet)
- [ ] `docs/STORAGE_REDUCTION.md` (testnet)
- [ ] `docs/TESTNET.md` (testnet-quantum, testnet)
- [ ] `docs/VALIDATOR_GUIDE.md` (testnet-quantum, testnet)
- [ ] `docs/VALIDATOR_ROLES.md` (main, testnet-quantum, garden, testnet)
- [ ] `docs/explorer-api.openapi.yaml` (testnet-quantum, testnet)

### `docs/audit` (6 files)

- [ ] `docs/audit/APP_BINDING_READINESS.md` (testnet)
- [ ] `docs/audit/FINDINGS.md` (testnet)
- [ ] `docs/audit/G_INVARIANTS.md` (testnet)
- [ ] `docs/audit/LIVE_STATUS.md` (testnet)
- [ ] `docs/audit/PRODUCTION_EVIDENCE_AUDIT.md` (testnet)
- [ ] `docs/audit/TLG_REPORT.md` (testnet)

### `docs/audit/evidence` (1 files)

- [ ] `docs/audit/evidence/ubuntu-45261-e2e-rehearsal.md` (testnet)

### `docs/budzero` (1 files)

- [ ] `docs/budzero/HASH_SUITES.md` (testnet)

### `docs/pq` (10 files)

- [ ] `docs/pq/ASSISTANT_CHECKPOINTS.md` (testnet)
- [ ] `docs/pq/AUDIT_SCOPE.md` (testnet-quantum, testnet)
- [ ] `docs/pq/CLAIMS.md` (testnet-quantum, testnet)
- [ ] `docs/pq/LUBOT_CHECKPOINTS.md` (testnet-quantum)
- [ ] `docs/pq/MEASUREMENTS.md` (testnet-quantum, testnet)
- [ ] `docs/pq/PROPAGATION.md` (testnet-quantum, testnet)
- [ ] `docs/pq/README.md` (testnet-quantum, testnet)
- [ ] `docs/pq/RECURSION_PLAN.md` (testnet-quantum, testnet)
- [ ] `docs/pq/THREAT_MODEL.md` (testnet-quantum, testnet)
- [ ] `docs/pq/classical_allowlist.toml` (testnet-quantum, testnet)

### `docs/pq/drafts` (1 files)

- [ ] `docs/pq/drafts/README.md` (testnet-quantum, testnet)

### `docs/rehearsal` (3 files)

- [ ] `docs/rehearsal/DRILLS.md` (testnet)
- [ ] `docs/rehearsal/DRILLS_AND_RUNBOOK.md` (testnet)
- [ ] `docs/rehearsal/RESULTS.md` (testnet)

### `examples` (2 files)

- [ ] `examples/pq_measure.rs` (testnet-quantum, testnet)
- [ ] `examples/print_genesis_hash.rs` (main, testnet-quantum, garden, testnet)

### `execution/budzero` (1 files)

- [ ] `execution/budzero/Cargo.toml` (testnet)

### `execution/budzero/src` (2 files)

- [ ] `execution/budzero/src/lib.rs` (testnet)
- [ ] `execution/budzero/src/main.rs` (testnet)

### `execution/cairo` (1 files)

- [ ] `execution/cairo/Cargo.toml` (testnet)

### `execution/cairo/src` (2 files)

- [ ] `execution/cairo/src/lib.rs` (testnet)
- [ ] `execution/cairo/src/main.rs` (testnet)

### `execution/conformance` (1 files)

- [ ] `execution/conformance/Cargo.toml` (testnet)

### `execution/conformance/src` (1 files)

- [ ] `execution/conformance/src/lib.rs` (testnet)

### `execution/evm` (1 files)

- [ ] `execution/evm/Cargo.toml` (testnet)

### `execution/evm/src` (5 files)

- [ ] `execution/evm/src/abi.rs` (testnet)
- [ ] `execution/evm/src/db.rs` (testnet)
- [ ] `execution/evm/src/lib.rs` (testnet)
- [ ] `execution/evm/src/main.rs` (testnet)
- [ ] `execution/evm/src/precompile_universal.rs` (testnet)

### `execution/mock` (1 files)

- [ ] `execution/mock/Cargo.toml` (testnet)

### `execution/mock/src` (1 files)

- [ ] `execution/mock/src/main.rs` (testnet)

### `execution/move` (2 files)

- [ ] `execution/move/Cargo.toml` (testnet)
- [ ] `execution/move/deny.toml` (testnet)

### `execution/move-sui` (1 files)

- [ ] `execution/move-sui/Cargo.toml` (testnet)

### `execution/move-sui/src` (2 files)

- [ ] `execution/move-sui/src/lib.rs` (testnet)
- [ ] `execution/move-sui/src/main.rs` (testnet)

### `execution/move/src` (3 files)

- [ ] `execution/move/src/framework.rs` (testnet)
- [ ] `execution/move/src/lib.rs` (testnet)
- [ ] `execution/move/src/main.rs` (testnet)

### `execution/move/src/pointer` (1 files)

- [ ] `execution/move/src/pointer/mod.rs` (testnet)

### `execution/near` (1 files)

- [ ] `execution/near/Cargo.toml` (testnet)

### `execution/near/src` (2 files)

- [ ] `execution/near/src/lib.rs` (testnet)
- [ ] `execution/near/src/main.rs` (testnet)

### `execution/plutus` (1 files)

- [ ] `execution/plutus/Cargo.toml` (testnet)

### `execution/plutus/src` (2 files)

- [ ] `execution/plutus/src/lib.rs` (testnet)
- [ ] `execution/plutus/src/main.rs` (testnet)

### `execution/polkavm` (1 files)

- [ ] `execution/polkavm/Cargo.toml` (testnet)

### `execution/polkavm/src` (2 files)

- [ ] `execution/polkavm/src/lib.rs` (testnet)
- [ ] `execution/polkavm/src/main.rs` (testnet)

### `execution/svm` (1 files)

- [ ] `execution/svm/Cargo.toml` (testnet)

### `execution/svm/src` (3 files)

- [ ] `execution/svm/src/lib.rs` (testnet)
- [ ] `execution/svm/src/main.rs` (testnet)
- [ ] `execution/svm/src/programs.rs` (testnet)

### `execution/svm/src/pointer` (1 files)

- [ ] `execution/svm/src/pointer/mod.rs` (testnet)

### `execution/tvm` (1 files)

- [ ] `execution/tvm/Cargo.toml` (testnet)

### `execution/tvm/src` (2 files)

- [ ] `execution/tvm/src/lib.rs` (testnet)
- [ ] `execution/tvm/src/main.rs` (testnet)

### `execution/utxo` (1 files)

- [ ] `execution/utxo/Cargo.toml` (testnet)

### `execution/utxo/src` (2 files)

- [ ] `execution/utxo/src/lib.rs` (testnet)
- [ ] `execution/utxo/src/main.rs` (testnet)

### `execution/wasm` (1 files)

- [ ] `execution/wasm/Cargo.toml` (testnet)

### `execution/wasm/src` (4 files)

- [ ] `execution/wasm/src/abi.rs` (testnet)
- [ ] `execution/wasm/src/budlum_msg.rs` (testnet)
- [ ] `execution/wasm/src/lib.rs` (testnet)
- [ ] `execution/wasm/src/main.rs` (testnet)

### `fuzz` (4 files)

- [ ] `fuzz/Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/Cargo.toml` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/osv-scanner.toml` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/block_deserialize` (6 files)

- [ ] `fuzz/corpus/block_deserialize/seed_alt` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/block_deserialize/seed_empty` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/block_deserialize/seed_long` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/block_deserialize/seed_ones` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/block_deserialize/seed_seq` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/block_deserialize/seed_zeros` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/bpqs_wots_reject` (2 files)

- [ ] `fuzz/corpus/bpqs_wots_reject/seed-damaged.bin` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/bpqs_wots_reject/seed-honest.bin` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/bud3_bof1_decode` (1 files)

- [ ] `fuzz/corpus/bud3_bof1_decode/abc.bof1` (testnet)

### `fuzz/corpus/bud3_qr_frame_decode` (3 files)

- [ ] `fuzz/corpus/bud3_qr_frame_decode/canonical-frame` (testnet)
- [ ] `fuzz/corpus/bud3_qr_frame_decode/header-only` (testnet)
- [ ] `fuzz/corpus/bud3_qr_frame_decode/ignorable-flag-nibble` (testnet)

### `fuzz/corpus/bud3_symbol_decode` (1 files)

- [ ] `fuzz/corpus/bud3_symbol_decode/two.sym` (testnet)

### `fuzz/corpus/budl_compile` (7 files)

- [ ] `fuzz/corpus/budl_compile/control_flow.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile/example.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile/example2.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile/example_loop.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile/nested_parens.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile/test_prover.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile/unbalanced_parens.bud` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/budl_compile_then_run` (6 files)

- [ ] `fuzz/corpus/budl_compile_then_run/control_flow.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile_then_run/example.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile_then_run/example2.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile_then_run/example_loop.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile_then_run/nested_parens.bud` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/budl_compile_then_run/test_prover.bud` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/consensus_state_transition` (10 files)

- [ ] `fuzz/corpus/consensus_state_transition/seed0` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_state_transition/seed1` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_state_transition/seed_alt` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_state_transition/seed_deep_reorg` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_state_transition/seed_empty` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_state_transition/seed_long` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_state_transition/seed_ones` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_state_transition/seed_produce_few` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_state_transition/seed_seq` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_state_transition/seed_zeros` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/consensus_validate` (6 files)

- [ ] `fuzz/corpus/consensus_validate/seed_alt` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_validate/seed_empty` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_validate/seed_long` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_validate/seed_ones` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_validate/seed_seq` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/consensus_validate/seed_zeros` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/evm_deployment_proof` (1 files)

- [ ] `fuzz/corpus/evm_deployment_proof/direct-create.tx` (testnet)

### `fuzz/corpus/evm_mpt_verify` (1 files)

- [ ] `fuzz/corpus/evm_mpt_verify/empty-trie-frame` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/evm_rlp_decode` (2 files)

- [ ] `fuzz/corpus/evm_rlp_decode/empty-list.rlp` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/evm_rlp_decode/empty-string.rlp` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/fuzz_blockchain_serialize` (6 files)

- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_alt` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_empty` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_long` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_ones` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_seq` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/fuzz_blockchain_serialize/seed_zeros` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/light_client_header_chain` (6 files)

- [ ] `fuzz/corpus/light_client_header_chain/seed_empty` (testnet)
- [ ] `fuzz/corpus/light_client_header_chain/seed_gap` (testnet)
- [ ] `fuzz/corpus/light_client_header_chain/seed_linked` (testnet)
- [ ] `fuzz/corpus/light_client_header_chain/seed_not_forward` (testnet)
- [ ] `fuzz/corpus/light_client_header_chain/seed_stale_hash` (testnet)
- [ ] `fuzz/corpus/light_client_header_chain/seed_wrong_parent` (testnet)

### `fuzz/corpus/relayer_escrow` (10 files)

- [ ] `fuzz/corpus/relayer_escrow/seed0` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/relayer_escrow/seed1` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/relayer_escrow/seed_alt` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/relayer_escrow/seed_empty` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/relayer_escrow/seed_lock_ops` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/relayer_escrow/seed_long` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/relayer_escrow/seed_ones` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/relayer_escrow/seed_seq` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/relayer_escrow/seed_sweep` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/relayer_escrow/seed_zeros` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/reputation` (5 files)

- [ ] `fuzz/corpus/reputation/01_connect_ratelimit_disconnect.bin` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/reputation/02_ban_then_unban.bin` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/reputation/03_ban_expiry_cleanup.bin` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/reputation/04_reconnect_storm.bin` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/reputation/05_ops_on_unknown_peer.bin` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/snapshot_deserialize` (6 files)

- [ ] `fuzz/corpus/snapshot_deserialize/seed_alt` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/snapshot_deserialize/seed_empty` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/snapshot_deserialize/seed_long` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/snapshot_deserialize/seed_ones` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/snapshot_deserialize/seed_seq` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/snapshot_deserialize/seed_zeros` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/transaction_deserialize` (6 files)

- [ ] `fuzz/corpus/transaction_deserialize/seed_alt` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/transaction_deserialize/seed_empty` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/transaction_deserialize/seed_long` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/transaction_deserialize/seed_ones` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/transaction_deserialize/seed_seq` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/transaction_deserialize/seed_zeros` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/uel_abi_frame` (4 files)

- [ ] `fuzz/corpus/uel_abi_frame/hello.frame` (testnet)
- [ ] `fuzz/corpus/uel_abi_frame/host-ok.frame` (testnet)
- [ ] `fuzz/corpus/uel_abi_frame/oversize-header.frame` (testnet)
- [ ] `fuzz/corpus/uel_abi_frame/wrong-version.frame` (testnet)

### `fuzz/corpus/uel_foreign_envelopes` (1 files)

- [ ] `fuzz/corpus/uel_foreign_envelopes/seed_01.bin` (testnet)

### `fuzz/corpus/vm_execute` (5 files)

- [ ] `fuzz/corpus/vm_execute/01_simple_add.bin` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/vm_execute/02_branch_loop.bin` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/vm_execute/03_verify_merkle_0x1E.bin` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/vm_execute/04_poseidon_hash.bin` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/vm_execute/05_memory_ops.bin` (main, testnet-quantum, garden, testnet)

### `fuzz/corpus/zk_verifier` (10 files)

- [ ] `fuzz/corpus/zk_verifier/seed0` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/zk_verifier/seed1` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/zk_verifier/seed_alt` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/zk_verifier/seed_empty` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/zk_verifier/seed_long` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/zk_verifier/seed_ones` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/zk_verifier/seed_raw_mode0` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/zk_verifier/seed_seq` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/zk_verifier/seed_struct_mode` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/corpus/zk_verifier/seed_zeros` (main, testnet-quantum, garden, testnet)

### `fuzz/fuzz_targets` (22 files)

- [ ] `fuzz/fuzz_targets/block_deserialize.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/bpqs_wots_reject.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/bud3_bof1_decode.rs` (testnet)
- [ ] `fuzz/fuzz_targets/bud3_qr_frame_decode.rs` (testnet)
- [ ] `fuzz/fuzz_targets/bud3_symbol_decode.rs` (testnet)
- [ ] `fuzz/fuzz_targets/budl_compile.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/budl_compile_then_run.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/consensus_state_transition.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/consensus_validate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/evm_deployment_proof.rs` (testnet)
- [ ] `fuzz/fuzz_targets/evm_mpt_verify.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/evm_rlp_decode.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/fuzz_blockchain_serialize.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/light_client_header_chain.rs` (testnet)
- [ ] `fuzz/fuzz_targets/relayer_escrow.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/reputation.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/snapshot_deserialize.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/transaction_deserialize.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/uel_abi_frame.rs` (testnet)
- [ ] `fuzz/fuzz_targets/uel_foreign_envelopes.rs` (testnet)
- [ ] `fuzz/fuzz_targets/vm_execute.rs` (main, testnet-quantum, garden, testnet)
- [ ] `fuzz/fuzz_targets/zk_verifier.rs` (main, testnet-quantum, garden, testnet)

### `kani` (2 files)

- [ ] `kani/Cargo.lock` (testnet)
- [ ] `kani/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `kani/src` (1 files)

- [ ] `kani/src/lib.rs` (main, testnet-quantum, garden, testnet)

### `mobile/android` (6 files)

- [ ] `mobile/android/.gitignore` (testnet)
- [ ] `mobile/android/PLAY_DECLARATION.md` (testnet)
- [ ] `mobile/android/README.md` (testnet)
- [ ] `mobile/android/build.gradle.kts` (testnet)
- [ ] `mobile/android/gradle.properties` (testnet)
- [ ] `mobile/android/settings.gradle.kts` (testnet)

### `mobile/android/app` (2 files)

- [ ] `mobile/android/app/build.gradle.kts` (testnet)
- [ ] `mobile/android/app/proguard-rules.pro` (testnet)

### `mobile/android/app/src/androidTest/java/network/budlum/validator/core` (1 files)

- [ ] `mobile/android/app/src/androidTest/java/network/budlum/validator/core/AndroidKeystoreWrappingKeyProviderInstrumentedTest.kt` (testnet)

### `mobile/android/app/src/androidTest/java/network/budlum/validator/service` (1 files)

- [ ] `mobile/android/app/src/androidTest/java/network/budlum/validator/service/BootCompletedReceiverInstrumentedTest.kt` (testnet)

### `mobile/android/app/src/main` (1 files)

- [ ] `mobile/android/app/src/main/AndroidManifest.xml` (testnet)

### `mobile/android/app/src/main/java/network/budlum/validator/core` (6 files)

- [ ] `mobile/android/app/src/main/java/network/budlum/validator/core/AndroidKeystoreWrappingKeyProvider.kt` (testnet)
- [ ] `mobile/android/app/src/main/java/network/budlum/validator/core/KeystoreKeyVault.kt` (testnet)
- [ ] `mobile/android/app/src/main/java/network/budlum/validator/core/MobileCoreBridge.kt` (testnet)
- [ ] `mobile/android/app/src/main/java/network/budlum/validator/core/OemBatteryGuide.kt` (testnet)
- [ ] `mobile/android/app/src/main/java/network/budlum/validator/core/TestnetAccountReader.kt` (testnet)
- [ ] `mobile/android/app/src/main/java/network/budlum/validator/core/TestnetFaucetClient.kt` (testnet)

### `mobile/android/app/src/main/java/network/budlum/validator/service` (2 files)

- [ ] `mobile/android/app/src/main/java/network/budlum/validator/service/BootCompletedReceiver.kt` (testnet)
- [ ] `mobile/android/app/src/main/java/network/budlum/validator/service/ValidatorService.kt` (testnet)

### `mobile/android/app/src/main/java/network/budlum/validator/ui` (1 files)

- [ ] `mobile/android/app/src/main/java/network/budlum/validator/ui/MainActivity.kt` (testnet)

### `mobile/android/app/src/main/java/network/budlum/validator/worker` (1 files)

- [ ] `mobile/android/app/src/main/java/network/budlum/validator/worker/DutyPeriodicWorker.kt` (testnet)

### `mobile/android/app/src/main/res/values` (1 files)

- [ ] `mobile/android/app/src/main/res/values/strings.xml` (testnet)

### `mobile/android/app/src/main/res/values-tr` (1 files)

- [ ] `mobile/android/app/src/main/res/values-tr/strings.xml` (testnet)

### `mobile/android/app/src/main/res/xml` (1 files)

- [ ] `mobile/android/app/src/main/res/xml/data_extraction_rules.xml` (testnet)

### `mobile/android/app/src/test/java/network/budlum/validator` (5 files)

- [ ] `mobile/android/app/src/test/java/network/budlum/validator/AndroidBackupPolicyTest.kt` (testnet)
- [ ] `mobile/android/app/src/test/java/network/budlum/validator/MobileValidatorJUnitTest.kt` (testnet)
- [ ] `mobile/android/app/src/test/java/network/budlum/validator/MobileValidatorUnitTest.kt` (testnet)
- [ ] `mobile/android/app/src/test/java/network/budlum/validator/TestnetAccountReaderTest.kt` (testnet)
- [ ] `mobile/android/app/src/test/java/network/budlum/validator/TestnetFaucetClientTest.kt` (testnet)

### `mobile/android/app/src/test/java/network/budlum/validator/core` (1 files)

- [ ] `mobile/android/app/src/test/java/network/budlum/validator/core/JvmMemoryWrappingKeyProvider.kt` (testnet)

### `mobile/android/devicetests` (2 files)

- [ ] `mobile/android/devicetests/DeviceFieldHarness.kt` (testnet)
- [ ] `mobile/android/devicetests/DeviceFieldTelemetry.kt` (testnet)

### `mobile/android/fdroid` (1 files)

- [ ] `mobile/android/fdroid/network.budlum.validator.yml` (testnet)

### `mobile/core` (3 files)

- [ ] `mobile/core/Cargo.lock` (testnet)
- [ ] `mobile/core/Cargo.toml` (testnet)
- [ ] `mobile/core/DB_CHOICE.md` (testnet)

### `mobile/core/src` (13 files)

- [ ] `mobile/core/src/crypto.rs` (testnet)
- [ ] `mobile/core/src/custody.rs` (testnet)
- [ ] `mobile/core/src/duty.rs` (testnet)
- [ ] `mobile/core/src/error.rs` (testnet)
- [ ] `mobile/core/src/handover.rs` (testnet)
- [ ] `mobile/core/src/hash.rs` (testnet)
- [ ] `mobile/core/src/keys.rs` (testnet)
- [ ] `mobile/core/src/lib.rs` (testnet)
- [ ] `mobile/core/src/policy.rs` (testnet)
- [ ] `mobile/core/src/presence.rs` (testnet)
- [ ] `mobile/core/src/quota.rs` (testnet)
- [ ] `mobile/core/src/relay.rs` (testnet)
- [ ] `mobile/core/src/store.rs` (testnet)

### `mobile/core/tests` (2 files)

- [ ] `mobile/core/tests/duty_boundaries.rs` (testnet)
- [ ] `mobile/core/tests/operator_key.rs` (testnet)

### `mobile/ffi` (4 files)

- [ ] `mobile/ffi/Cargo.lock` (testnet)
- [ ] `mobile/ffi/Cargo.toml` (testnet)
- [ ] `mobile/ffi/uniffi-bindgen.rs` (testnet)
- [ ] `mobile/ffi/uniffi.toml` (testnet)

### `mobile/ffi/src` (1 files)

- [ ] `mobile/ffi/src/lib.rs` (testnet)

### `mobile/ios` (4 files)

- [ ] `mobile/ios/APP_STORE_REVIEW_NOTES.md` (testnet)
- [ ] `mobile/ios/Info.plist` (testnet)
- [ ] `mobile/ios/Package.swift` (testnet)
- [ ] `mobile/ios/README.md` (testnet)

### `mobile/ios/Scripts` (2 files)

- [ ] `mobile/ios/Scripts/check_class_parity.py` (testnet)
- [ ] `mobile/ios/Scripts/test_check_class_parity.py` (testnet)

### `mobile/ios/Sources/BudlumValidator` (4 files)

- [ ] `mobile/ios/Sources/BudlumValidator/OpportunisticValidatorEngine.swift` (testnet)
- [ ] `mobile/ios/Sources/BudlumValidator/SecureEnclaveKeyStore.swift` (testnet)
- [ ] `mobile/ios/Sources/BudlumValidator/TurkishLocalization.swift` (testnet)
- [ ] `mobile/ios/Sources/BudlumValidator/ValidatorDashboardView.swift` (testnet)

### `mobile/ios/Tests/BudlumValidatorTests` (1 files)

- [ ] `mobile/ios/Tests/BudlumValidatorTests/OpportunisticValidatorTests.swift` (testnet)

### `mobile/tools/log-analyzer` (3 files)

- [ ] `mobile/tools/log-analyzer/Cargo.lock` (testnet)
- [ ] `mobile/tools/log-analyzer/Cargo.toml` (testnet)
- [ ] `mobile/tools/log-analyzer/README.md` (testnet)

### `mobile/tools/log-analyzer/fixtures` (2 files)

- [ ] `mobile/tools/log-analyzer/fixtures/report.json` (testnet)
- [ ] `mobile/tools/log-analyzer/fixtures/samples.jsonl` (testnet)

### `mobile/tools/log-analyzer/src` (2 files)

- [ ] `mobile/tools/log-analyzer/src/lib.rs` (testnet)
- [ ] `mobile/tools/log-analyzer/src/main.rs` (testnet)

### `mobile/tools/log-analyzer/tests` (1 files)

- [ ] `mobile/tools/log-analyzer/tests/golden_reports.rs` (testnet)

### `ops` (12 files)

- [ ] `ops/BACKUP_AND_RESTORE.md` (testnet)
- [ ] `ops/Caddyfile.testnet` (testnet-quantum, testnet)
- [ ] `ops/Dockerfile` (main, testnet-quantum, garden, testnet)
- [ ] `ops/TESTNET_FIRST_RUN.md` (testnet)
- [ ] `ops/budlum-core.service` (main, testnet-quantum, garden, testnet)
- [ ] `ops/docker-compose.ci.yml` (main, testnet-quantum, garden, testnet)
- [ ] `ops/docker-compose.yml` (main, testnet-quantum, garden, testnet)
- [ ] `ops/hsm.env.example` (testnet)
- [ ] `ops/prometheus.yml` (main, testnet-quantum, garden, testnet)
- [ ] `ops/softhsm2.conf` (testnet)
- [ ] `ops/testnet-local-validator.py` (testnet)
- [ ] `ops/testnet-local.yml` (testnet-quantum, testnet)

### `ops/gateway` (3 files)

- [ ] `ops/gateway/Dockerfile` (testnet)
- [ ] `ops/gateway/budlum-gateway.service` (testnet)
- [ ] `ops/gateway/gateway.toml` (testnet)

### `ops/monitoring` (2 files)

- [ ] `ops/monitoring/alerts.yml` (testnet-quantum, testnet)
- [ ] `ops/monitoring/testnet-local-prometheus.yml` (testnet-quantum, testnet)

### `ops/monitoring/grafana` (1 files)

- [ ] `ops/monitoring/grafana/budlum-testnet.json` (testnet-quantum, testnet)

### `ops/monitoring/grafana-provisioning/dashboards` (1 files)

- [ ] `ops/monitoring/grafana-provisioning/dashboards/budlum.yml` (testnet-quantum, testnet)

### `ops/monitoring/grafana-provisioning/datasources` (1 files)

- [ ] `ops/monitoring/grafana-provisioning/datasources/prometheus.yml` (testnet-quantum, testnet)

### `ops/rehearsal` (3 files)

- [ ] `ops/rehearsal/genesis_rehearsal.py` (testnet)
- [ ] `ops/rehearsal/rehearsal-topology.toml` (testnet)
- [ ] `ops/rehearsal/topology.toml` (testnet)

### `ops/rehearsal/tests` (5 files)

- [ ] `ops/rehearsal/tests/test_genesis_rehearsal.py` (testnet)
- [ ] `ops/rehearsal/tests/test_node_exporter_alert.py` (testnet)
- [ ] `ops/rehearsal/tests/test_rehearsal_publication.py` (testnet)
- [ ] `ops/rehearsal/tests/test_testnet_restore_paths.py` (testnet)
- [ ] `ops/rehearsal/tests/test_testnet_validator_state.py` (testnet)

### `ops/scripts` (1 files)

- [ ] `ops/scripts/.gitkeep` (main, testnet-quantum, garden, testnet)

### `proptest-regressions/execution/coordinator/scheduler` (1 files)

- [ ] `proptest-regressions/execution/coordinator/scheduler/tests.txt` (testnet)

### `proptest-regressions/storage` (1 files)

- [ ] `proptest-regressions/storage/erasure.txt` (testnet)

### `proto/budlum/execution/v1` (1 files)

- [ ] `proto/budlum/execution/v1/ee.proto` (testnet)

### `proto/budlum/network` (1 files)

- [ ] `proto/budlum/network/protocol.proto` (main, testnet-quantum, garden, testnet)

### `proto/budlum/storage/v3` (1 files)

- [ ] `proto/budlum/storage/v3/bud3.proto` (testnet)

### `release` (2 files)

- [ ] `release/README.md` (testnet-quantum, testnet)
- [ ] `release/RELEASE_PUBKEY.hex` (testnet-quantum, testnet)

### `src` (5 files)

- [ ] `src/developer_os.rs` (main, testnet-quantum, garden)
- [ ] `src/error.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/main.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/project_manifest.rs` (testnet)

### `src/account_abstraction` (6 files)

- [ ] `src/account_abstraction/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/account_abstraction/private_transfer_auth.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/account_abstraction/quantum_account.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/account_abstraction/registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/account_abstraction/tee_attestation.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/account_abstraction/threshold_mldsa.rs` (main, testnet-quantum, garden, testnet)

### `src/ai` (7 files)

- [ ] `src/ai/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai/answer_proof_bundle.rs` (testnet)
- [ ] `src/ai/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai/registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai/types.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai/verification_layer.rs` (testnet)
- [ ] `src/ai/verification_level.rs` (testnet)

### `src/ai/execution` (6 files)

- [ ] `src/ai/execution/blind_compute.rs` (testnet)
- [ ] `src/ai/execution/guest.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai/execution/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai/execution/model_class.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai/execution/stark.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai/execution/verify.rs` (main, testnet-quantum, garden, testnet)

### `src/ai_inference` (11 files)

- [ ] `src/ai_inference/effort.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/executor.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/i18n.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/inference.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/metrics.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/perception.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/query.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/social.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/storage.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/ai_inference/verify.rs` (main, testnet-quantum, garden, testnet)

### `src/app_registry` (1 files)

- [ ] `src/app_registry/mod.rs` (testnet)

### `src/bin` (9 files)

- [ ] `src/bin/bud-migrate.rs` (testnet)
- [ ] `src/bin/bud.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/bin/budlum-domain-producer.rs` (testnet-quantum, testnet)
- [ ] `src/bin/budlum-domain-reporter.rs` (testnet-quantum, testnet)
- [ ] `src/bin/budlum-faucet.rs` (testnet-quantum, testnet)
- [ ] `src/bin/budlum-gateway.rs` (testnet)
- [ ] `src/bin/budlum-indexer.rs` (testnet-quantum, testnet)
- [ ] `src/bin/budlum-light.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/bin/budlum-relayer.rs` (main, testnet-quantum, garden, testnet)

### `src/bin/support` (2 files)

- [ ] `src/bin/support/faucet_client.rs` (testnet)
- [ ] `src/bin/support/http.rs` (testnet-quantum, testnet)

### `src/bns` (6 files)

- [ ] `src/bns/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `src/bns/bud3.rs` (testnet)
- [ ] `src/bns/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/bns/offers.rs` (testnet)
- [ ] `src/bns/registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/bns/types.rs` (main, testnet-quantum, garden, testnet)

### `src/budlumxyz` (3 files)

- [ ] `src/budlumxyz/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `src/budlumxyz/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/budlumxyz/types.rs` (main, testnet-quantum, garden, testnet)

### `src/chain` (10 files)

- [ ] `src/chain/blockchain.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/chain/chain_actor.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/chain/fee_market.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/chain/finality.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/chain/genesis.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/chain/genesis_ceremony.rs` (testnet-quantum, testnet)
- [ ] `src/chain/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/chain/snapshot.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/chain/storage_economics_tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/chain/storage_maintenance.rs` (testnet-quantum, testnet)

### `src/chain/state_recovery` (5 files)

- [ ] `src/chain/state_recovery/health.rs` (testnet)
- [ ] `src/chain/state_recovery/mempool.rs` (testnet)
- [ ] `src/chain/state_recovery/mod.rs` (testnet)
- [ ] `src/chain/state_recovery/stage.rs` (testnet)
- [ ] `src/chain/state_recovery/tick.rs` (testnet)

### `src/cli` (3 files)

- [ ] `src/cli/bud3_commands.rs` (testnet)
- [ ] `src/cli/commands.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cli/mod.rs` (main, testnet-quantum, garden, testnet)

### `src/consensus` (13 files)

- [ ] `src/consensus/block_signature.rs` (testnet-quantum, testnet)
- [ ] `src/consensus/budget.rs` (testnet-quantum, testnet)
- [ ] `src/consensus/filiz.rs` (testnet-quantum, testnet)
- [ ] `src/consensus/handoff.rs` (testnet-quantum, testnet)
- [ ] `src/consensus/merkle_tree.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/consensus/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/consensus/poa.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/consensus/pos.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/consensus/pow.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/consensus/qc.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/consensus/registration.rs` (testnet-quantum, testnet)
- [ ] `src/consensus/split_resolver.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/consensus/zk_verifier.rs` (testnet)

### `src/core` (16 files)

- [ ] `src/core/account.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/address.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/block.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/bounded_read.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/chain_config.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/constitution.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/encoding.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/governance.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/hash.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/map_keys.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/metrics.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/money.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/transaction.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/transaction_v4.txt` (main, testnet-quantum, garden, testnet)
- [ ] `src/core/tx_bundle.rs` (testnet-quantum, testnet)

### `src/cross_domain` (10 files)

- [ ] `src/cross_domain/bridge.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/bridge_relayer.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/bridge_tx.rs` (testnet-quantum, testnet)
- [ ] `src/cross_domain/chain_adapter.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/event_tree.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/message.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/message_registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/nonce.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/relayer.rs` (main, testnet-quantum, garden, testnet)

### `src/cross_domain/evm` (12 files)

- [ ] `src/cross_domain/evm/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/evm/account_proof.rs` (testnet)
- [ ] `src/cross_domain/evm/adapter.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/evm/bud_to_eth.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/evm/header.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/evm/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/evm/mpt.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/evm/outbound.rs` (testnet-quantum, testnet)
- [ ] `src/cross_domain/evm/receipt.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/evm/rlp.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/evm/sync_committee.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/evm/verify.rs` (main, testnet-quantum, garden, testnet)

### `src/cross_domain/external` (16 files)

- [ ] `src/cross_domain/external/domain_bridge.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/ethereum.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/evm_hybrid.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/external_tx.rs` (testnet-quantum, testnet)
- [ ] `src/cross_domain/external/intake.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/intake_quorum.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/phase_a_dual.rs` (testnet)
- [ ] `src/cross_domain/external/profile.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/prover.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/quorum.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/selftest.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/spec.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/versioning.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/cross_domain/external/zkvm_proof.rs` (main, testnet-quantum, garden, testnet)

### `src/crypto` (19 files)

- [ ] `src/crypto/address_v3.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/composite.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/ctx.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/domain_tags.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/crypto/facts.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/hpke.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/key_derivation.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/key_file.rs` (testnet)
- [ ] `src/crypto/key_set_preimage.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/crypto/mainnet_policy.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/crypto/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/crypto/pkcs11.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/crypto/pq.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/pq_vector_tests.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/primitives.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/crypto/scheme.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/secp256k1_recover.rs` (testnet-quantum, testnet)
- [ ] `src/crypto/signer.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/crypto/tls.rs` (testnet-quantum, testnet)

### `src/data_market` (1 files)

- [ ] `src/data_market/mod.rs` (testnet)

### `src/deed` (2 files)

- [ ] `src/deed/education_domain.rs` (testnet)
- [ ] `src/deed/mod.rs` (main, testnet-quantum, garden, testnet)

### `src/domain` (18 files)

- [ ] `src/domain/commitment_registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/deal_open.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/finality_adapter.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/fork_choice.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/plugin.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/plugin_registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/pq_canonical.rs` (testnet-quantum, testnet)
- [ ] `src/domain/producer.rs` (testnet-quantum, testnet)
- [ ] `src/domain/regen_health.rs` (main, testnet-quantum, garden)
- [ ] `src/domain/regen_mempool.rs` (testnet-quantum)
- [ ] `src/domain/regeneration_stage.rs` (main, testnet-quantum, garden)
- [ ] `src/domain/registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/sovereign.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/storage_deal.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/storage_params.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/storage_tx.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/domain/types.rs` (main, testnet-quantum, garden, testnet)

### `src/education_domain` (1 files)

- [ ] `src/education_domain/mod.rs` (testnet)

### `src/execution` (5 files)

- [ ] `src/execution/ee.rs` (testnet)
- [ ] `src/execution/executor.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/execution/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/execution/proof_verifier.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/execution/zkvm.rs` (main, testnet-quantum, garden, testnet)

### `src/execution/budzero_ee` (2 files)

- [ ] `src/execution/budzero_ee/budzero_ee_tests.rs` (testnet)
- [ ] `src/execution/budzero_ee/mod.rs` (testnet)

### `src/execution/coordinator` (21 files)

- [ ] `src/execution/coordinator/alias.rs` (testnet)
- [ ] `src/execution/coordinator/conformance.rs` (testnet)
- [ ] `src/execution/coordinator/conformance_tests.rs` (testnet)
- [ ] `src/execution/coordinator/coordinator_tests.rs` (testnet)
- [ ] `src/execution/coordinator/deploy_policy.rs` (testnet)
- [ ] `src/execution/coordinator/evm_ee.rs` (testnet)
- [ ] `src/execution/coordinator/evm_wasm_universal_call_tests.rs` (testnet)
- [ ] `src/execution/coordinator/expansion_ee.rs` (testnet)
- [ ] `src/execution/coordinator/gas.rs` (testnet)
- [ ] `src/execution/coordinator/mod.rs` (testnet)
- [ ] `src/execution/coordinator/move_ee.rs` (testnet)
- [ ] `src/execution/coordinator/overlay.rs` (testnet)
- [ ] `src/execution/coordinator/review_2_attack_tests.rs` (testnet)
- [ ] `src/execution/coordinator/state.rs` (testnet)
- [ ] `src/execution/coordinator/stateful_contract.rs` (testnet)
- [ ] `src/execution/coordinator/svm_ee.rs` (testnet)
- [ ] `src/execution/coordinator/svm_move_tests.rs` (testnet)
- [ ] `src/execution/coordinator/universal_call.rs` (testnet)
- [ ] `src/execution/coordinator/wasm_ee.rs` (testnet)
- [ ] `src/execution/coordinator/worker.rs` (testnet)
- [ ] `src/execution/coordinator/worker_identity_tests.rs` (testnet)

### `src/execution/coordinator/assets` (1 files)

- [ ] `src/execution/coordinator/assets/mod.rs` (testnet)

### `src/execution/coordinator/foreign` (7 files)

- [ ] `src/execution/coordinator/foreign/aptos.rs` (testnet)
- [ ] `src/execution/coordinator/foreign/cosmos.rs` (testnet)
- [ ] `src/execution/coordinator/foreign/ethereum.rs` (testnet)
- [ ] `src/execution/coordinator/foreign/foreign_tests.rs` (testnet)
- [ ] `src/execution/coordinator/foreign/mod.rs` (testnet)
- [ ] `src/execution/coordinator/foreign/solana.rs` (testnet)
- [ ] `src/execution/coordinator/foreign/sui.rs` (testnet)

### `src/execution/coordinator/migration` (6 files)

- [ ] `src/execution/coordinator/migration/dependencies.rs` (testnet)
- [ ] `src/execution/coordinator/migration/deployment.rs` (testnet)
- [ ] `src/execution/coordinator/migration/fee.rs` (testnet)
- [ ] `src/execution/coordinator/migration/mod.rs` (testnet)
- [ ] `src/execution/coordinator/migration/non_evm.rs` (testnet)
- [ ] `src/execution/coordinator/migration/storage_root.rs` (testnet)

### `src/execution/coordinator/scheduler` (2 files)

- [ ] `src/execution/coordinator/scheduler/mod.rs` (testnet)
- [ ] `src/execution/coordinator/scheduler/tests.rs` (testnet)

### `src/explorer_evidence` (1 files)

- [ ] `src/explorer_evidence/mod.rs` (testnet)

### `src/garden` (10 files)

- [ ] `src/garden/invite.rs` (garden)
- [ ] `src/garden/mod.rs` (garden)
- [ ] `src/garden/net.rs` (garden)
- [ ] `src/garden/node.rs` (garden)
- [ ] `src/garden/service.rs` (garden)
- [ ] `src/garden/settlement.rs` (garden)
- [ ] `src/garden/state.rs` (garden)
- [ ] `src/garden/storage.rs` (garden)
- [ ] `src/garden/testkit.rs` (garden)
- [ ] `src/garden/types.rs` (garden)

### `src/gateway` (4 files)

- [ ] `src/gateway/atlas.rs` (main, testnet-quantum, garden)
- [ ] `src/gateway/mod.rs` (main, testnet-quantum, garden)
- [ ] `src/gateway/passport.rs` (main, testnet-quantum, garden)
- [ ] `src/gateway/service.rs` (main, testnet-quantum, garden)

### `src/light_client` (1 files)

- [ ] `src/light_client/mod.rs` (main, testnet-quantum, garden, testnet)

### `src/mempool` (5 files)

- [ ] `src/mempool/authority_cache.rs` (testnet-quantum, testnet)
- [ ] `src/mempool/duty_lane.rs` (testnet)
- [ ] `src/mempool/lanes.rs` (testnet)
- [ ] `src/mempool/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/mempool/pool.rs` (main, testnet-quantum, garden, testnet)

### `src/network` (15 files)

- [ ] `src/network/bounded_bincode.rs` (testnet)
- [ ] `src/network/deferred_votes.rs` (testnet-quantum, testnet)
- [ ] `src/network/fork_rewalk.rs` (testnet-quantum, testnet)
- [ ] `src/network/gossip_dedup.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/network/mobile.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/network/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/network/node.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/network/peer_auth.rs` (testnet-quantum, testnet)
- [ ] `src/network/peer_manager.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/network/privacy.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/network/proto_conversions.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/network/protocol.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/network/regen_health_tick.rs` (main, testnet-quantum, garden)
- [ ] `src/network/sync_codec.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/network/witness_protocol.rs` (testnet-quantum, testnet)

### `src/object_layer` (9 files)

- [ ] `src/object_layer/charter.rs` (testnet)
- [ ] `src/object_layer/ids.rs` (testnet)
- [ ] `src/object_layer/metrics.rs` (testnet)
- [ ] `src/object_layer/mod.rs` (testnet)
- [ ] `src/object_layer/pairs.rs` (testnet)
- [ ] `src/object_layer/registry.rs` (testnet)
- [ ] `src/object_layer/rule.rs` (testnet)
- [ ] `src/object_layer/tests.rs` (testnet)
- [ ] `src/object_layer/tx.rs` (testnet)

### `src/object_layer/family` (6 files)

- [ ] `src/object_layer/family/cosmwasm.rs` (testnet)
- [ ] `src/object_layer/family/encoding.rs` (testnet)
- [ ] `src/object_layer/family/evm.rs` (testnet)
- [ ] `src/object_layer/family/mod.rs` (testnet)
- [ ] `src/object_layer/family/move.rs` (testnet)
- [ ] `src/object_layer/family/svm.rs` (testnet)

### `src/persistence` (6 files)

- [ ] `src/persistence/db.rs` (testnet)
- [ ] `src/persistence/mod.rs` (testnet)
- [ ] `src/persistence/pruning.rs` (testnet)
- [ ] `src/persistence/state_trie.rs` (testnet)
- [ ] `src/persistence/traits.rs` (testnet)
- [ ] `src/persistence/witness_retention.rs` (testnet)

### `src/pollen` (6 files)

- [ ] `src/pollen/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `src/pollen/content_gate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/pollen/data_market.rs` (testnet)
- [ ] `src/pollen/data_rights.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/pollen/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/pollen/offers.rs` (main, testnet-quantum, garden, testnet)

### `src/privacy` (4 files)

- [ ] `src/privacy/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/privacy/note_registry.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/privacy/submit.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/privacy/threshold_escrow.rs` (testnet)

### `src/prover` (1 files)

- [ ] `src/prover/mod.rs` (main, testnet-quantum, garden, testnet)

### `src/registry` (19 files)

- [ ] `src/registry/d4_merge_tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/evidence.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/handover.rs` (testnet)
- [ ] `src/registry/identity.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/identity_fill.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/invalid_vote.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/liveness.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/mobile_runtime.rs` (testnet)
- [ ] `src/registry/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/params.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/permissionless.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/poa_compliance.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/poa_membership.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/poa_onboarding.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/presence.rs` (testnet)
- [ ] `src/registry/quarantine_ledger.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/rehearsal.rs` (testnet)
- [ ] `src/registry/role.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/registry/validator_profile.rs` (testnet-quantum, testnet)

### `src/relayer` (3 files)

- [ ] `src/relayer/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/relayer/policy.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/relayer/worker.rs` (main, testnet-quantum, garden, testnet)

### `src/rpc` (8 files)

- [ ] `src/rpc/api.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/rpc/client_auth.rs` (testnet-quantum, testnet)
- [ ] `src/rpc/method_class.rs` (testnet-quantum, testnet)
- [ ] `src/rpc/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/rpc/server.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/rpc/subscriptions.rs` (testnet-quantum, testnet)
- [ ] `src/rpc/tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/rpc/tls.rs` (testnet-quantum, testnet)

### `src/rpc/compat` (6 files)

- [ ] `src/rpc/compat/aptos.rs` (testnet)
- [ ] `src/rpc/compat/compat_tests.rs` (testnet)
- [ ] `src/rpc/compat/cosmos.rs` (testnet)
- [ ] `src/rpc/compat/ethereum.rs` (testnet)
- [ ] `src/rpc/compat/mod.rs` (testnet)
- [ ] `src/rpc/compat/solana.rs` (testnet)

### `src/rpc/compat/aptos` (1 files)

- [ ] `src/rpc/compat/aptos/tests.rs` (testnet)

### `src/rpc/compat/ethereum` (2 files)

- [ ] `src/rpc/compat/ethereum/filters.rs` (testnet)
- [ ] `src/rpc/compat/ethereum/opening.rs` (testnet)

### `src/rpc/compat/ethereum/opening` (1 files)

- [ ] `src/rpc/compat/ethereum/opening/tests.rs` (testnet)

### `src/rpc/compat/solana` (2 files)

- [ ] `src/rpc/compat/solana/subscriptions.rs` (testnet)
- [ ] `src/rpc/compat/solana/tests.rs` (testnet)

### `src/rpc/compat/starknet` (1 files)

- [ ] `src/rpc/compat/starknet/mod.rs` (testnet)

### `src/rpc/compat/sui` (1 files)

- [ ] `src/rpc/compat/sui/mod.rs` (testnet)

### `src/sdk` (1 files)

- [ ] `src/sdk/mod.rs` (main, testnet-quantum, garden, testnet)

### `src/security` (3 files)

- [ ] `src/security/alarm_effects.rs` (testnet-quantum, testnet)
- [ ] `src/security/mod.rs` (testnet-quantum, testnet)
- [ ] `src/security/quantum_canary.rs` (testnet-quantum, testnet)

### `src/settlement` (18 files)

- [ ] `src/settlement/anchor_ledger.rs` (testnet-quantum, testnet)
- [ ] `src/settlement/anchor_production.rs` (testnet-quantum, testnet)
- [ ] `src/settlement/app_binding.rs` (testnet)
- [ ] `src/settlement/cold_quorum.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/settlement/cold_wallet.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/settlement/commitment_tree.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/settlement/domains.rs` (testnet-quantum, testnet)
- [ ] `src/settlement/global_block.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/settlement/graft.rs` (testnet-quantum)
- [ ] `src/settlement/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/settlement/pq_anchor.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/settlement/pq_anchor_verify.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/settlement/proof_market.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/settlement/proof_verifier.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/settlement/registries.rs` (testnet-quantum, testnet)
- [ ] `src/settlement/reseal.rs` (testnet-quantum, testnet)
- [ ] `src/settlement/root_seal.rs` (testnet-quantum, testnet)
- [ ] `src/settlement/shared_security.rs` (testnet-quantum, testnet)

### `src/sharding` (1 files)

- [ ] `src/sharding/mod.rs` (main, testnet-quantum, garden, testnet)

### `src/socialfi` (5 files)

- [ ] `src/socialfi/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `src/socialfi/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/socialfi/nft_folders.rs` (testnet)
- [ ] `src/socialfi/types.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/socialfi/vault.rs` (main, testnet-quantum, garden, testnet)

### `src/storage` (58 files)

- [ ] `src/storage/README.md` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/assignment.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/column_commitment.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/content_gateway.rs` (testnet)
- [ ] `src/storage/content_id.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/db.rs` (main, testnet-quantum, garden)
- [ ] `src/storage/derived.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/dictionary.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/emit.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/erasure.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/fixed_point.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/generated.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/key_package.rs` (testnet-quantum, testnet)
- [ ] `src/storage/lifecycle.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/living_threshold.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/lrc.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/manifest.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/merkle_trie.rs` (main, testnet-quantum, garden)
- [ ] `src/storage/mobile_self.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/msr.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/one_share.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/one_view.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/pact_binding.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/payload_crypt.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/provider.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/pruning.rs` (main, testnet-quantum, garden)
- [ ] `src/storage/qr_carousel.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_codec.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_encode.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_frame.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_matrix.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_payload.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_png.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_receive.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_recipe.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_reemit.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_verify.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_verify_indep.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/qr_video.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/render.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/reveal_gateway.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/server_admission.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/social_delete.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/three_gate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/three_hooks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/three_meter.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/three_nft.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/three_pipe.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/three_recipe.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/three_regime.rs` (main, testnet-quantum, garden)
- [ ] `src/storage/three_reveal.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/three_rpc.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/three_visibility.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/traits.rs` (main, testnet-quantum, garden)
- [ ] `src/storage/transformed.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/view_grant.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/storage/witness_retention.rs` (testnet-quantum)

### `src/storage/bud3` (38 files)

- [ ] `src/storage/bud3/access_tiering.rs` (testnet)
- [ ] `src/storage/bud3/bof1.rs` (testnet)
- [ ] `src/storage/bud3/compression_context.rs` (testnet)
- [ ] `src/storage/bud3/content_gateway.rs` (testnet)
- [ ] `src/storage/bud3/content_id.rs` (testnet)
- [ ] `src/storage/bud3/content_ref.rs` (testnet)
- [ ] `src/storage/bud3/custody.rs` (testnet)
- [ ] `src/storage/bud3/dedup_index.rs` (testnet)
- [ ] `src/storage/bud3/delete.rs` (testnet)
- [ ] `src/storage/bud3/fees.rs` (testnet)
- [ ] `src/storage/bud3/fountain.rs` (testnet)
- [ ] `src/storage/bud3/frame.rs` (testnet)
- [ ] `src/storage/bud3/grants.rs` (testnet)
- [ ] `src/storage/bud3/keys.rs` (testnet)
- [ ] `src/storage/bud3/limits.rs` (testnet)
- [ ] `src/storage/bud3/live.rs` (testnet)
- [ ] `src/storage/bud3/live_broadcast.rs` (testnet)
- [ ] `src/storage/bud3/maintenance.rs` (testnet)
- [ ] `src/storage/bud3/meter.rs` (testnet)
- [ ] `src/storage/bud3/mod.rs` (testnet)
- [ ] `src/storage/bud3/pipeline.rs` (testnet)
- [ ] `src/storage/bud3/placement.rs` (testnet)
- [ ] `src/storage/bud3/private_dedup.rs` (testnet)
- [ ] `src/storage/bud3/qr.rs` (testnet)
- [ ] `src/storage/bud3/registry.rs` (testnet)
- [ ] `src/storage/bud3/repair.rs` (testnet)
- [ ] `src/storage/bud3/replace.rs` (testnet)
- [ ] `src/storage/bud3/rpc.rs` (testnet)
- [ ] `src/storage/bud3/seal.rs` (testnet)
- [ ] `src/storage/bud3/segment.rs` (testnet)
- [ ] `src/storage/bud3/symbol_protocol.rs` (testnet)
- [ ] `src/storage/bud3/two_path.rs` (testnet)
- [ ] `src/storage/bud3/tx.rs` (testnet)
- [ ] `src/storage/bud3/upload.rs` (testnet)
- [ ] `src/storage/bud3/varint.rs` (testnet)
- [ ] `src/storage/bud3/video.rs` (testnet)
- [ ] `src/storage/bud3/view.rs` (testnet)
- [ ] `src/storage/bud3/volume.rs` (testnet)

### `src/storage/bud3/compression_context` (2 files)

- [ ] `src/storage/bud3/compression_context/committed.rs` (testnet)
- [ ] `src/storage/bud3/compression_context/corpus.rs` (testnet)

### `src/storage/bud3/private_dedup` (2 files)

- [ ] `src/storage/bud3/private_dedup/committee.rs` (testnet)
- [ ] `src/storage/bud3/private_dedup/threshold.rs` (testnet)

### `src/storage/bud3/repair` (1 files)

- [ ] `src/storage/bud3/repair/scheduler.rs` (testnet)

### `src/tests` (130 files)

- [ ] `src/tests/adversarial_p2p.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/advisory_reachability.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/ai_inference_runtime.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/ai_verification_status_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/alert_rules_reference_existing_metrics.rs` (testnet)
- [ ] `src/tests/alerts_have_runbook_entries.rs` (testnet)
- [ ] `src/tests/audit_findings_locks.rs` (main, testnet-quantum, garden)
- [ ] `src/tests/audit_lane_a.rs` (testnet)
- [ ] `src/tests/audit_lane_d_locks.rs` (testnet)
- [ ] `src/tests/audit_p49_locks.rs` (main, garden)
- [ ] `src/tests/backup_covers_persisted_paths.rs` (testnet)
- [ ] `src/tests/bench_performance.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/block_clock.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/block_door_harness.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/block_reward.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/blockchair_fixture_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/bns.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/bns_expanded.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/bns_safety.rs` (testnet)
- [ ] `src/tests/bridge_lifecycle.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/bridge_negatives.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/bridge_safety.rs` (testnet)
- [ ] `src/tests/bud3_door.rs` (testnet)
- [ ] `src/tests/bud3_replace.rs` (testnet)
- [ ] `src/tests/bud_e2e.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/byzantine_settlement.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/caddy_edges_match_the_services.rs` (testnet)
- [ ] `src/tests/ceremony_and_drills.rs` (testnet)
- [ ] `src/tests/chain_id_registry_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/chaos.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/compose_topology_matches_services.rs` (testnet)
- [ ] `src/tests/conformance_locks.rs` (testnet)
- [ ] `src/tests/consensus_bypass_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/consensus_digest.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/consensus_expanded.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/consensus_lock_order_loom.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/consensus_round_boundaries.rs` (testnet)
- [ ] `src/tests/consensus_rounds.rs` (testnet-quantum, testnet)
- [ ] `src/tests/consensus_safety.rs` (testnet)
- [ ] `src/tests/constitution_engine.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/cross_domain_nonce_extended.rs` (testnet)
- [ ] `src/tests/deed.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/disaster_recovery.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/distributed_settlement.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/domain_edge_cases.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/domains_bridge_settlement.rs` (testnet)
- [ ] `src/tests/encryption_dao.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/evm_finality_contract.rs` (testnet-quantum, testnet)
- [ ] `src/tests/f20_priority_findings.rs` (main, garden)
- [ ] `src/tests/finality_adversarial.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/finality_live_path.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/fork_choice_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/genesis_repro.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/global_header_sequence.rs` (testnet-quantum, testnet)
- [ ] `src/tests/handover_mechanics.rs` (testnet)
- [ ] `src/tests/handover_recovery.rs` (testnet)
- [ ] `src/tests/hard_prune.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/hardening.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/hardening_h2_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/hardening_h4_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/hardening_h5_h7_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/hardening_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/hash_input_serialize_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/identity_tx_door.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/integration.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/liveness_consensus.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/load_test.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/manifest_commitment_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/mempool_dos_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/migration_v2.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/multi_consensus_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/network_hardening_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/object_layer_metrics.rs` (testnet)
- [ ] `src/tests/operator_kill_chaos.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/p01_consensus_rounds.rs` (main, testnet-quantum, garden)
- [ ] `src/tests/permissionless.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/permissionless_e2e.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/persistence.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/persistence_move.rs` (testnet)
- [ ] `src/tests/poa_isolation.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/poa_onboarding_matrix.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/poisoned_lock_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/pollen_ai_data_rights.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/ported_slice_redteam.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/pow_light_client.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/priority_findings.rs` (testnet-quantum)
- [ ] `src/tests/privacy_ai_execution.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/private_transfer_fee_market.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/proptest_core.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/protocol_guardrails.rs` (testnet)
- [ ] `src/tests/prover.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/qcblob_quorum.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/readiness_metrics.rs` (testnet)
- [ ] `src/tests/real_chain_fixtures.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/refusal_locks.rs` (testnet-quantum, testnet)
- [ ] `src/tests/regeneration_recovery.rs` (main, testnet-quantum, garden)
- [ ] `src/tests/regression_ai_storage.rs` (testnet)
- [ ] `src/tests/regression_bridge.rs` (testnet)
- [ ] `src/tests/regression_canaries.rs` (testnet-quantum, testnet)
- [ ] `src/tests/regression_chain.rs` (testnet)
- [ ] `src/tests/regression_lock.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/regression_ops_crypto.rs` (testnet)
- [ ] `src/tests/relayer_e2e.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/relayer_gates.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/relayer_liveness.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/relayer_worker_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/replay_audit.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/scrape_topology_covers_the_rules.rs` (testnet)
- [ ] `src/tests/security_auditor.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/security_invariant_tests.rs` (testnet)
- [ ] `src/tests/security_review.rs` (testnet)
- [ ] `src/tests/settlement_prod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/sharding_e2e.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/slashing_matrix.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/snapshot_chaos.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/socialfi.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/state_hardening.rs` (testnet)
- [ ] `src/tests/state_recovery.rs` (testnet)
- [ ] `src/tests/storage_tx_door.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/target_700.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/testnet_closed_features.rs` (testnet)
- [ ] `src/tests/tokenomics.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/tokenomics_proptest.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/v95_v98_canaries.rs` (main, garden)
- [ ] `src/tests/validator_classes.rs` (testnet)
- [ ] `src/tests/vault_tx_door.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/wall_clock_locks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tests/wallet_safety.rs` (testnet)
- [ ] `src/tests/zkvm.rs` (main, testnet-quantum, garden, testnet)

### `src/tokenomics` (2 files)

- [ ] `src/tokenomics/mod.rs` (main, testnet-quantum, garden, testnet)
- [ ] `src/tokenomics/reward_pool.rs` (main, testnet-quantum, garden, testnet)

### `src/validators` (3 files)

- [ ] `src/validators/committee.rs` (testnet)
- [ ] `src/validators/handover.rs` (testnet)
- [ ] `src/validators/mod.rs` (testnet)

### `src/wallet` (2 files)

- [ ] `src/wallet/identity_profile.rs` (testnet)
- [ ] `src/wallet/mod.rs` (testnet-quantum, testnet)

### `src/web_gateway` (5 files)

- [ ] `src/web_gateway/host.rs` (testnet)
- [ ] `src/web_gateway/manifest.rs` (testnet)
- [ ] `src/web_gateway/mod.rs` (testnet)
- [ ] `src/web_gateway/policy.rs` (testnet)
- [ ] `src/web_gateway/resolve.rs` (testnet)

### `supply-chain` (3 files)

- [ ] `supply-chain/audits.toml` (main, testnet-quantum, garden, testnet)
- [ ] `supply-chain/config.toml` (main, testnet-quantum, garden, testnet)
- [ ] `supply-chain/imports.lock` (main, testnet-quantum, garden, testnet)

### `tests/churn` (1 files)

- [ ] `tests/churn/main.rs` (testnet)

### `tests/garden` (2 files)

- [ ] `tests/garden/garden_nat.rs` (garden)
- [ ] `tests/garden/garden_scenario.rs` (garden)

### `tests/rehearsal` (1 files)

- [ ] `tests/rehearsal/main.rs` (testnet)

### `tests/vectors/aptos` (1 files)

- [ ] `tests/vectors/aptos/pinned_scheme_ids.json` (testnet)

### `tests/vectors/bud3/bof1` (1 files)

- [ ] `tests/vectors/bud3/bof1/README.md` (testnet)

### `tests/vectors/bud3/codec` (1 files)

- [ ] `tests/vectors/bud3/codec/README.md` (testnet)

### `tests/vectors/bud3/custody` (1 files)

- [ ] `tests/vectors/bud3/custody/README.md` (testnet)

### `tests/vectors/bud3/fountain` (2 files)

- [ ] `tests/vectors/bud3/fountain/README.md` (testnet)
- [ ] `tests/vectors/bud3/fountain/p0_k17.sha256` (testnet)

### `tests/vectors/bud3/placement` (1 files)

- [ ] `tests/vectors/bud3/placement/README.md` (testnet)

### `tests/vectors/pq` (9 files)

- [ ] `tests/vectors/pq/README.md` (testnet-quantum, testnet)
- [ ] `tests/vectors/pq/acvp-mldsa-keygen.json` (testnet-quantum, testnet)
- [ ] `tests/vectors/pq/acvp-mldsa-siggen.json` (testnet-quantum, testnet)
- [ ] `tests/vectors/pq/acvp-mldsa-sigver.json` (testnet-quantum, testnet)
- [ ] `tests/vectors/pq/acvp-slhdsa-keygen.json` (testnet-quantum, testnet)
- [ ] `tests/vectors/pq/acvp-slhdsa-siggen.json` (testnet-quantum, testnet)
- [ ] `tests/vectors/pq/acvp-slhdsa-sigver.json` (testnet-quantum, testnet)
- [ ] `tests/vectors/pq/wycheproof-mldsa-65.json` (testnet-quantum, testnet)
- [ ] `tests/vectors/pq/wycheproof-mldsa-87.json` (testnet-quantum, testnet)

### `tests/vectors/presence/v1` (3 files)

- [ ] `tests/vectors/presence/v1/README.md` (testnet)
- [ ] `tests/vectors/presence/v1/digest.bin` (testnet)
- [ ] `tests/vectors/presence/v1/preimage.bin` (testnet)

### `xtask/gates` (2 files)

- [ ] `xtask/gates/Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `xtask/gates/pins` (1 files)

- [ ] `xtask/gates/pins/budzero-tree.pins` (main, testnet-quantum, garden, testnet)

### `xtask/gates/src` (2 files)

- [ ] `xtask/gates/src/main.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/sha256.rs` (testnet)

### `xtask/gates/src/gates` (180 files)

- [ ] `xtask/gates/src/gates/accumulators_pinned.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/actionlint.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/ai_inference_prompt_is_true.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/ai_inference_reads.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/ai_inference_zk.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/air_selectors.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/ast_security_gates.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/badges_current.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/binding_claims.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/bit_decompositions.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/bns_gate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/bns_names_are_safe_in_an_address_bar.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/bridge_dual_tree.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/bud3_codec_and_replace.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_custody_proofs.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_custody_rewards.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_dependent_modules.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_fee_uses_physical_bytes.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_forbidden_phrases.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_module_claims.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_object_is_universal.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_paid_view.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_placement.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_proto_is_total.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_qr_is_presentation.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_repair_fires.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud3_sealed_and_deletion.rs` (testnet)
- [ ] `xtask/gates/src/gates/bud_e2e.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/budscan_parity.rs` (main, testnet-quantum, garden)
- [ ] `xtask/gates/src/gates/budscan_patchset.rs` (main, testnet-quantum, garden)
- [ ] `xtask/gates/src/gates/canonical_programs_reproduce.rs` (testnet)
- [ ] `xtask/gates/src/gates/capability_modules_are_wired.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/cargo_vet.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/chain_id_is_not_hardcoded.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/ci_jobs_end_on_cancel.rs` (testnet)
- [ ] `xtask/gates/src/gates/ci_workflow_guards.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/classical_crypto_is_paired.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/clippy_extra.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/coding_audit_samples_the_relationship.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/concept_names.rs` (testnet)
- [ ] `xtask/gates/src/gates/consensus_maps_ordered.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/consensus_state_only_changes_in_blocks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/containment_defaults.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/content_encryption_is_declared_and_bound.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/coverage.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/cross_table_checks.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/dead_pub_api.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/derived_content.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/docker_toolchain.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/domain_tags.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/economy_invariants.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/ee_workers_build_with_unwind.rs` (testnet)
- [ ] `xtask/gates/src/gates/every_fuzz_target_is_run.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/every_opcode_forgery.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/evidence_provenance.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/exact_named_tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/explorer_parity.rs` (testnet)
- [ ] `xtask/gates/src/gates/explorer_patchset.rs` (testnet)
- [ ] `xtask/gates/src/gates/fixture_integrity.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/forgery_tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/fork_choice_gate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/fsf_import_boundaries.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/fuzz_targets_wired.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/garden_nat.rs` (garden)
- [ ] `xtask/gates/src/gates/garden_scenario.rs` (garden)
- [ ] `xtask/gates/src/gates/gas_calibration.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/gates_are_wired.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/gates_do_not_panic.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/gateway_gate.rs` (testnet)
- [ ] `xtask/gates/src/gates/gating_flags.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/geiger.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/generated_content.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/genesis_schema.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/git_deps_audited.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/gov_slash_evidence_is_validator_only.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/governance_invariants.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/guards_reachable.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/handover_and_recovery.rs` (testnet)
- [ ] `xtask/gates/src/gates/hash_inputs_are_length_prefixed.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/indexing_is_not_new.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/kani.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/launch_evidence.rs` (testnet)
- [ ] `xtask/gates/src/gates/launch_matrix_tests_exist.rs` (testnet)
- [ ] `xtask/gates/src/gates/license_consistency.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/lock_failures.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/logup_multipliers.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/master_derivation.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/mempool_mev_free.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/mermaid.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/metrics_are_written.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/minting_paths_are_counted.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/mobile_validator_apps.rs` (testnet)
- [ ] `xtask/gates/src/gates/module_coverage.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/multi_ratio_consensus.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/named_tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/network_hardening_gate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/nightly_workflows_are_required.rs` (testnet)
- [ ] `xtask/gates/src/gates/no_conflict_markers.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/no_constant_security_verdicts.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/no_float_in_consensus_paths.rs` (testnet)
- [ ] `xtask/gates/src/gates/no_idle_code.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/no_legacy_storage.rs` (testnet)
- [ ] `xtask/gates/src/gates/no_new_shell_gates.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/no_orphan_source_files.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/no_out_of_block_consensus_writes.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/no_pairing_snark_in_verification_path.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/no_unicode_dashes.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/no_upstream_brands.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/node_classification_gate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/offline_never_slashes.rs` (testnet)
- [ ] `xtask/gates/src/gates/one_house_guards.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/ownerless_dependencies.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/paid_content.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/parallel_execution.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/pinned_downloads.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/poa_compliance_gate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/pq_claims_are_backed.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/pq_core_gate.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/pq_ctx_is_bound.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/pq_scan.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/proof_deps_are_exactly_pinned.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/qr_is_derivative_only.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/quantum_account.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/readme_definition_block_is_verbatim.rs` (testnet)
- [ ] `xtask/gates/src/gates/readme_has_no_placeholders.rs` (testnet)
- [ ] `xtask/gates/src/gates/readme_no_deny.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/reduction_claims.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/refusals_no_mutate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/regen_health_door.rs` (main, testnet-quantum, garden)
- [ ] `xtask/gates/src/gates/regeneration.rs` (main, testnet-quantum, garden)
- [ ] `xtask/gates/src/gates/rehearsal_and_field_matrix.rs` (testnet)
- [ ] `xtask/gates/src/gates/rejection_tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/relay.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/release_profile_pins.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/repair_fires.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/required_tests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/rust_literals.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/rust_syntax_is_parseable.rs` (testnet)
- [ ] `xtask/gates/src/gates/scheme_is_never_inferred.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/security_parameters.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/security_quality_wired.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/security_scans_can_fail.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/self_derived_ids_cover_every_field.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/semver.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/serialize_map_keys_are_strings.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/shard_placement.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/slash_expression.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/source_reading.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/state_recovery_door.rs` (testnet)
- [ ] `xtask/gates/src/gates/storage_penalties.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/storage_priced.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/storage_proof_boundary.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/storage_provider_gate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/suppressions_are_justified.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/tee_trust_boundary_is_structural.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/test_modules_can_see_what_they_test.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/testnet_runtime_hardening.rs` (testnet-quantum, testnet)
- [ ] `xtask/gates/src/gates/the_image_builds_what_the_manifest_declares.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/three_is_recipe_only.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/threshold_rates.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/timing_safe.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/transcript_mirrors.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/tree_is_english.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/tree_pin.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/typos.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/udeps.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/uncheckable_proof.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/untrusted_manifests.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/value_transfers.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/wallet_core_gate.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/wallet_node_address_agree.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/wire_fields_are_signed.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/workflows_cover_every_workspace.rs` (testnet)
- [ ] `xtask/gates/src/gates/workflows_produce_jobs.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/zero_address_sender_is_verified.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/zero_storage_frozen.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/zero_tests_witness.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/zizmor.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/gates/src/gates/zkvm_immune_regeneration.rs` (main, testnet-quantum, garden)
- [ ] `xtask/gates/src/gates/zkvm_refuses_untrusted_proofs.rs` (testnet)

### `xtask/gates/tests` (1 files)

- [ ] `xtask/gates/tests/repository_locks.rs` (testnet)

### `xtask/release` (2 files)

- [ ] `xtask/release/Cargo.lock` (testnet-quantum, testnet)
- [ ] `xtask/release/Cargo.toml` (testnet-quantum, testnet)

### `xtask/release/src` (1 files)

- [ ] `xtask/release/src/main.rs` (testnet-quantum, testnet)

### `xtask/tools` (2 files)

- [ ] `xtask/tools/Cargo.lock` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/Cargo.toml` (main, testnet-quantum, garden, testnet)

### `xtask/tools/src` (29 files)

- [ ] `xtask/tools/src/ai_test_verifier.rs` (testnet-quantum, testnet)
- [ ] `xtask/tools/src/audit_deps.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/audit_guard.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/backup_drill.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/clippy_extra_report.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/contracts.rs` (testnet-quantum, testnet)
- [ ] `xtask/tools/src/dep_snapshot.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/devnet.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/docker_smoke.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/fsf_fit.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/json.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/lib.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/multinode_smoke.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/placement_table.rs` (testnet)
- [ ] `xtask/tools/src/pq_measure.rs` (testnet-quantum, testnet)
- [ ] `xtask/tools/src/prepush.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/propagation.rs` (testnet-quantum, testnet)
- [ ] `xtask/tools/src/report.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/resource_sample.rs` (testnet-quantum, testnet)
- [ ] `xtask/tools/src/rpc.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/sarif.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/sbom.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/seed_corpus.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/smoke_rpc.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/stark_soundness.rs` (testnet-quantum, testnet)
- [ ] `xtask/tools/src/step_reachability.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/support.rs` (main, testnet-quantum, garden, testnet)
- [ ] `xtask/tools/src/testnet_genesis.rs` (testnet-quantum, testnet)
- [ ] `xtask/tools/src/testnet_rehearsal.rs` (testnet-quantum, testnet)

### `xtask/tools/src/bin` (1 files)

- [ ] `xtask/tools/src/bin/budlum-tools.rs` (main, testnet-quantum, garden, testnet)
