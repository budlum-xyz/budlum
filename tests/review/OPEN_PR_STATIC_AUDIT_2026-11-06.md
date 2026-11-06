# Open-PR static audit (snapshot, 2026-11-06)

Read-only run of `tests/review/pr_static_audit.py` at this commit. Counts and
PR numbers are a snapshot; re-run the tool for the live state. A collision here
means two open PRs create the same path, which directive 15.3.3 forbids; the
report does not decide which PR should keep it.

Pull requests read: 76. Read-only: nothing was checked out, compiled or merged.

## Parse and generation findings

- #92 `ops/rehearsal/genesis_rehearsal.sh` — generated source interpolates a shell variable into python -c

## Paths created by more than one open PR

- `.github/no-legacy-storage-baseline.txt` — #69, #75, #84
- `.github/rpc-method-coverage-baseline.txt` — #41, #53
- `.github/workflows/conformance-nightly.yml` — #29, #30
- `.github/workflows/mobile.yml` — #45, #92
- `budzero/bud-proof/tests/audit_lane_c.rs` — #12, #16
- `config/rehearsal-genesis.json` — #45, #92
- `contracts/uel/BudlumUniversal.sol` — #24, #36
- `crates/budlum-types/Cargo.lock` — #44, #91
- `crates/budlum-types/Cargo.toml` — #44, #91
- `crates/budlum-types/src/lib.rs` — #44, #91
- `crates/uel-abi/tests/transport_deadlines.rs` — #77, #80
- `crates/uel-abi/tests/transport_host_guards.rs` — #77, #80
- `docs/APTOS_RPC.md` — #89, #95
- `docs/EXECUTION.md` — #24, #36
- `docs/EXECUTION_LIMITS.md` — #36, #45, #79
- `docs/MOBILE_DEVICE_MATRIX.md` — #45, #92
- `docs/OBJECT_LAYER.md` — #55, #60
- `docs/RPC_COMPAT.md` — #72, #75
- `docs/SOLANA_RPC.md` — #83, #95
- `docs/STORAGE.md` — #47, #69, #75
- `docs/STORAGE_MEASUREMENTS.md` — #45, #55
- `docs/audit/FINDINGS.md` — #13, #31, #35, #36, #41, #44, #48, #50, #68, #77, #80, #88, #93, #95, #96
- `docs/audit/LIVE_STATUS.md` — #35, #68, #87
- `docs/audit/OPEN_PR_RECONCILIATION.md` — #77, #80
- `docs/audit/REVIEW_2.md` — #36, #60, #77
- `docs/audit/STACK_INTEGRATION_AUDIT_2026-11-06.md` — #93, #95, #96
- `docs/audit/live/engine-inventory.md` — #12, #16
- `docs/audit/live/lane-a.md` — #12, #68, #87
- `docs/audit/live/lane-b.md` — #12, #68, #87
- `docs/audit/live/lane-c.md` — #12, #16, #68, #87
- `docs/audit/live/lane-d.md` — #18, #35, #68, #87
- `docs/rehearsal/RESULTS.md` — #45, #92
- `docs/work/PACKAGES.md` — #13, #14, #16, #20, #29, #30, #31, #35, #36, #41, #47, #48, #50, #51, #56, #57, #59, #63, #65, #68, #72, #73, #75, #82, #83, #84, #93, #95, #96
- `docs/work/PR_COORDINATION.md` — #72, #75
- `execution/budzero/Cargo.toml` — #24, #36
- `execution/budzero/src/main.rs` — #24, #36
- `execution/evm/Cargo.toml` — #24, #36
- `execution/evm/src/main.rs` — #24, #36
- `execution/wasm/Cargo.toml` — #24, #36
- `execution/wasm/src/budlum_msg.rs` — #24, #36
- `execution/wasm/src/main.rs` — #24, #36
- `fuzz/corpus/bud3_qr_frame_decode/canonical-frame` — #29, #30
- `fuzz/corpus/bud3_qr_frame_decode/header-only` — #29, #30
- `fuzz/corpus/bud3_qr_frame_decode/ignorable-flag-nibble` — #29, #30
- `fuzz/corpus/evm_deployment_proof/direct-create.tx` — #61, #75
- `fuzz/fuzz_targets/bud3_qr_frame_decode.rs` — #29, #30
- `fuzz/fuzz_targets/evm_deployment_proof.rs` — #36, #61, #75
- `mobile/android/PLAY_DECLARATION.md` — #45, #92
- `mobile/android/app/build.gradle.kts` — #45, #92
- `mobile/android/app/proguard-rules.pro` — #45, #92
- `mobile/android/app/src/main/AndroidManifest.xml` — #45, #92
- `mobile/android/app/src/main/res/values-tr/strings.xml` — #45, #92
- `mobile/android/app/src/main/res/values/strings.xml` — #45, #92
- `mobile/android/build.gradle.kts` — #45, #92
- `mobile/android/settings.gradle.kts` — #45, #92
- `ops/scripts/pr_coordination.py` — #72, #75
- `src/bin/bud-migrate.rs` — #36, #46, #75
- `src/chain/state_recovery/mod.rs` — #8, #11, #84
- `src/cross_domain/evm/account_proof.rs` — #36, #46, #75
- `src/execution/budzero_ee/mod.rs` — #24, #36
- `src/execution/coordinator/foreign/cosmos.rs` — #24, #36
- `src/execution/coordinator/foreign/ethereum.rs` — #24, #36
- `src/execution/coordinator/foreign/mod.rs` — #24, #36
- `src/execution/coordinator/gas.rs` — #24, #36
- `src/execution/coordinator/migration/dependencies.rs` — #36, #46, #75
- `src/execution/coordinator/migration/deployment.rs` — #36, #61, #75
- `src/execution/coordinator/migration/fee.rs` — #36, #61, #75
- `src/execution/coordinator/migration/mod.rs` — #36, #46, #75
- `src/execution/coordinator/migration/storage_root.rs` — #36, #61, #75
- `src/execution/coordinator/overlay.rs` — #24, #36
- `src/mempool/duty_lane.rs` — #31, #40
- `src/mempool/lanes.rs` — #24, #36
- `src/persistence/mod.rs` — #8, #11, #84
- `src/rpc/compat/aptos/mod.rs` — #89, #95
- `src/rpc/compat/aptos/tests.rs` — #89, #95
- `src/rpc/compat/ethereum/filters.rs` — #24, #75
- `src/rpc/compat/ethereum/mod.rs` — #24, #56, #72, #75
- `src/rpc/compat/ethereum/tests.rs` — #72, #75
- `src/rpc/compat/mod.rs` — #24, #36, #56, #72, #75, #83, #89, #95
- `src/rpc/compat/solana/mod.rs` — #51, #83, #95
- `src/rpc/compat/solana/tests.rs` — #83, #95
- `src/storage/bud3/access_tiering.rs` — #8, #45
- `src/storage/bud3/content_ref.rs` — #8, #45, #69, #75, #84
- `src/storage/bud3/fees.rs` — #40, #45
- `src/storage/bud3/live.rs` — #55, #86
- `src/storage/bud3/repair.rs` — #45, #59, #60
- `src/storage/bud3/replace.rs` — #8, #45
- `src/storage/bud3/volume.rs` — #45, #55, #57
- `src/tests/alert_rules_reference_existing_metrics.rs` — #52, #59
- `src/tests/audit_lane_a.rs` — #12, #68
- `src/tests/audit_lane_b.rs` — #12, #68
- `src/tests/audit_lane_c.rs` — #12, #16, #68
- `src/tests/audit_lane_d.rs` — #18, #35, #68
- `src/tests/bud3_replace.rs` — #65, #75
- `src/validators/committee.rs` — #9, #81
- `src/validators/presence.rs` — #70, #75
- `tests/churn/main.rs` — #45, #60
- `xtask/gates/src/gates/bud3_custody_proofs.rs` — #13, #45, #59
- `xtask/gates/src/gates/bud3_custody_rewards.rs` — #40, #45
- `xtask/gates/src/gates/bud3_fee_uses_physical_bytes.rs` — #40, #45
- `xtask/gates/src/gates/bud3_placement.rs` — #13, #45, #59
- `xtask/gates/src/gates/bud3_repair_fires.rs` — #13, #45, #59
- `xtask/gates/src/gates/ee_workers_build_with_unwind.rs` — #24, #36
- `xtask/gates/src/gates/no_float_in_consensus_paths.rs` — #24, #29, #30, #31, #84
- `xtask/gates/src/gates/no_legacy_storage.rs` — #69, #75, #84
- `xtask/gates/src/gates/workflows_cover_every_workspace.rs` — #24, #29, #30, #31
