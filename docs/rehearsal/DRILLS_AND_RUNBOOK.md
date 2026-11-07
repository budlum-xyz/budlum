# Ceremony Rehearsal, Multi-Region Topology, and Drill Suite (WP-46)

## 1. Rehearsal Ceremony Artifact (`R-09`)

- **Fixture**: `config/rehearsal-genesis.json`
- **SHA-256 Digest**: `7296b76f95c036b9c3ebec9c4d0662916396ed62c20804931dd72ca00a14dedd`
- **Chain ID**: `45261`
- **Validators**: `8` distinct Full validators (sorted deterministically by 32-byte address)
- **Supply Check**: `100,000,000 BUD` (`100_000_000_000_000` atomic units across `community`, `liquidity`, `ecosystem`, `team`, and `burn_reserve`)
- **Assembler & Validator**:
  - Rust: `budlum_core::chain::genesis_ceremony::assemble` (`cargo run --manifest-path xtask/tools/Cargo.toml -- testnet-genesis`)
  - Python preflight verifier: `ops/rehearsal/genesis_rehearsal.py` (tested by `ops/rehearsal/tests/test_genesis_rehearsal.py`, rejecting empty `class: Full` claims, duplicate validators/VRF keys, secret-key material, and untrusted filename injection)

---

## 2. Multi-Region Rehearsal Topology (`ops/rehearsal/rehearsal-topology.toml`)

The rehearsal manifest defines the target topology required before external 72-hour burn-in:

- `8` Full validators distributed across `3` geographic regions (`eu-central`, `us-east`, `ap-southeast`) and `2` independent cloud providers.
- `4` Full-validator relay nodes (`DutyKind::RelayReservation`) and `2` upload gateways (`DutyKind::UploadGateway`).
- Dedicated public RPC listener, loopback-only operator RPC listener, PoW-gated faucet, explorer indexer, Prometheus + Grafana stack, `>= 20` physical Android phones, and `1,000` headless simulated Mobile validators.

---

## 3. Drill Matrix (`T-1` through `T-7`)

Per Directive Section `0.1.3` (no fabricated external hardware measurements), deterministic in-repository protocol drills are locked by automated Rust tests in `src/tests/wp46_ceremony_and_drills.rs` and `tests/churn/churn_sim.rs`, while external multi-region / physical-phone soak runs record live telemetry into `target/testnet-rehearsal.md` when executed on provisioned infrastructure:

| Drill | Scenario | In-Repository Deterministic Verification | External 72h Fleet Runbook Step |
|---|---|---|---|
| **T-1** | All Mobile validators stop simultaneously; finality latency is unchanged and reads continue from Full class. | `drill_t1_and_t4_mobile_departure_and_one_epoch_activation`, `all_mobile_departure_does_not_touch_finality` | Stop headless Mobile fleet + Android cohort; verify `budlum_finality_lag_blocks` stays flat and segment reads succeed from `n_full` shares. |
| **T-2** | 10% of Full validators stop suddenly; finality continues and silent seats rotate to standby within 3 checkpoint intervals. | `drill_t2_and_t3_full_stop_standby_handover_and_recovery_mode`, `ten_percent_full_departure_keeps_finality` | Terminate 1 of 8 Full validators; verify checkpoint finality continues within <= 2 checkpoints and standby promotion completes within 3 checkpoints. |
| **T-3** | > 1/3 of active seats stop for 50 blocks; `budlum_finality_stalled` fires and clears once seats return. | `drill_t2_and_t3_full_stop_standby_handover_and_recovery_mode`, `finality_stall_enters_recovery_mode` | Pause 3 of 8 Full validators for 50 blocks; confirm `budlum_finality_stalled == 1` alert fires and returns to `0` upon unpausing. |
| **T-4** | Returning Mobile validators activate pending transitions after 1 epoch (`E + 1`) and repair drains. | `drill_t1_and_t4_mobile_departure_and_one_epoch_activation`, `churn_1000_validators_20_epochs_zero_segment_loss` | Restart Mobile fleet; submit quota/resume updates and verify activation at `E + 1` plus zero segment loss. |
| **T-5** | 100 GiB aggregate upload, 10,000 small objects, concurrent view reads. | `bud3` segment/BOF-1 pipeline & aggregation tests (`src/storage/bud3/`) | Run upload/view load generator against `gateway-eu-01` and `gateway-us-01`; archive throughput & disk growth to `RESULTS.md`. |
| **T-6** | Foundry, Hardhat, viem, CosmJS, Anchor, and Aptos CLI scenarios + cross-environment EVM -> CW20 atomic call. | UEL & Object Layer composite atomicity tests (`composite_call_is_atomic_and_bounded`) | Run multi-client external E2E scripts against rehearsal RPC endpoints once UEL gateways merge. |
| **T-7** | Public RPC flood load; rate limiting (`429`) and admin-method isolation. | `drill_t7_public_rpc_listener_separation_and_admin_isolation`, `src/rpc/method_class.rs` | Run HTTP burst generator against public RPC `:8545`; record `budlum_rpc_rate_limited_total` and `429` ratio. |
