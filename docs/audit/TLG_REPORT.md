# Testnet Launch Gate Report (`TLG_REPORT.md`)

- **Target network**: Budlum Public Testnet (`chain_id = 45261`, `BDLT`)
- **Primary author**: Lane D Engineering Verifier
- **Independent co-signer**: Lane A/B/C Cross-Review Verifier (`docs/audit/REVIEW_1.md`, `docs/audit/REVIEW_2.md`)
- **Explicit feature decisions (`TLG-27`)**:
  - **Native lock/mint/burn/unlock bridge (`WP-44`)**: **Open** (`BLG-043`, `BLG-057`, `BLG-105`, and `BLG-194` closed and regression-locked in `src/tests/wp44_domains_bridge_settlement.rs`).
  - **On-chain AI inference layer (`WP-45`)**: **Closed** on public testnet `45261` (`ai_layer_is_closed_on_testnet` in `src/execution/executor.rs`).

## Gate Verdict Matrix (`TLG-01` .. `TLG-27`)

| ID | Requirement | Status | Evidence / Gate / Record | Reviewer |
| --- | --- | --- | --- | --- |
| `TLG-01` | Zero open Critical/High findings on active testnet surfaces; deferred features gated closed with tests | Green | `docs/audit/FINDINGS.md`, `docs/audit/LIVE_STATUS.md`, `src/tests/audit_findings_locks.rs` | Lane A/B |
| `TLG-02` | Every closed/deferred feature carries `<feature>_is_closed_on_testnet` test | Green | `ai_layer_is_closed_on_testnet`, `ethereum_sync_committee_is_closed_on_testnet`, `object_layer_is_closed_on_testnet` | Lane A/C |
| `TLG-03` | Legacy storage code (`bud/`, `budzero/bud-node`, pre-3.0 paths) removed | Green | `budlum-gates no-legacy-storage`, `xtask/gates/tests/repository_locks.rs` | Lane B |
| `TLG-04` | `B.U.D. 3.0` acceptance suite (`T1..T12`, `T14..T26`, `T34..T41`) and nightly heavy storage jobs wired | Green | `src/tests/bud3_types.rs`, `src/tests/bud3_door.rs`, `src/tests/bud3_custody_and_repair.rs`, `bud3-*` gates | Lane B |
| `TLG-05` | 128-seat committee finality and deterministic seat rotation tests pass | Green | `src/validators/committee.rs`, `src/tests/finality_live_path.rs`, `src/tests/finality_adversarial.rs` | Lane A |
| `TLG-06` | Instant Duty Handover and churn simulator pass | Green | `src/tests/wp14_handover_recovery.rs`, `tests/churn/` | Lane A |
| `TLG-07` | Rehearsal drill `T-1` (simultaneous Mobile exit: zero finality stall, zero lost objects) | Green | `src/tests/wp46_ceremony_and_drills.rs`, `docs/rehearsal/DRILLS_AND_RUNBOOK.md` | Lane D |
| `TLG-08` | Rehearsal drill `T-2` (10% Full validator exit: bounded `<= 2` extra checkpoints) | Green | `src/tests/wp46_ceremony_and_drills.rs`, `docs/rehearsal/DRILLS_AND_RUNBOOK.md` | Lane D |
| `TLG-09` | Rehearsal drills `T-3`, `T-4`, `T-5`, `T-7` deterministic harnesses and runbooks verified | Green | `src/tests/wp46_ceremony_and_drills.rs`, `ops/rehearsal/` | Lane D |
| `TLG-10` | Android Mobile validator custody/audit/reward pipeline verified end-to-end | Green | `mobile/core/`, `mobile/android/`, `crates/budlum-explorer/src/pages.rs` | Lane D |
| `TLG-11` | Mobile 24h duty, battery budget, and NAT matrix documented and enforced | Green | `docs/MOBILE_DEVICE_MATRIX.md`, `mobile/tools/log-analyzer/` | Lane D |
| `TLG-12` | `EVM`, `WASM`, `SVM`, `Move`, and `BudZero` conformance & limits catalog locked | Green | `src/tests/conformance_locks.rs`, `docs/EXECUTION_LIMITS.md` | Lane C |
| `TLG-13` | Nightly ecosystem compatibility workflows (`compatibility.yml`, `conformance-nightly.yml`) wired and required | Green | `.github/workflows/compatibility.yml`, `budlum-gates nightly-workflows-are-required` | Lane C |
| `TLG-14` | Atomic single-transaction `EVM -> CosmWasm` `0xB001` Universal Call verified | Green | `src/execution/coordinator/uel_wp27_wp29_wp30_tests.rs`, `src/tests/wp46_ceremony_and_drills.rs` | Lane C |
| `TLG-15` | Cross-architecture (`x86_64` / `aarch64`) deterministic state root workflow wired | Green | `.github/workflows/determinism.yml`, `budlum-gates no-float-in-consensus-paths` | Lane C |
| `TLG-16` | `BGU` gas calibration bound (`16 ns/BGU`, `60,000,000 BGU` block limit) locked | Green | `src/tests/conformance_locks.rs`, `budlum-gates gas-calibration` | Lane C |
| `TLG-17` | Clean genesis ceremony verifier (`>= 8` Full validators, supply conservation) verified | Green | `config/rehearsal-genesis.json`, `src/chain/genesis_ceremony.rs`, `src/tests/wp46_ceremony_and_drills.rs` | Lane A |
| `TLG-18` | `libp2p` relay, `DCUtR` hole-punching, and `AutoNAT` network hardening verified | Green | `budlum-gates network-hardening`, `budlum-gates relay` | Lane A |
| `TLG-19` | Fee split, physical-byte storage pricing, and supply conservation invariants verified | Green | `budlum-gates economy-invariants`, `budlum-gates bud3-fee-uses-physical-bytes` | Lane A/B |
| `TLG-20` | RPC listener separation, method classification, CORS, and per-peer rate limits verified | Green | `ops/scripts/rpc_surface_audit.py`, `src/rpc/method_coverage.rs`, `src/tests/regression_ops_crypto.rs` | Lane D |
| `TLG-21` | `budlum-faucet`, `budlum-explorer`, `budlum-indexer`, Prometheus alerts, and Grafana dashboards verified | Green | `src/tests/alerts_have_runbook_entries.rs`, `src/tests/alert_rules_reference_existing_metrics.rs`, `crates/budlum-explorer/` | Lane D |
| `TLG-22` | Independent Reviews 1 and 2 completed; all discovered Critical/High issues closed | Green | `docs/audit/REVIEW_1.md`, `docs/audit/REVIEW_2.md`, `src/tests/wp48_review2_security.rs` | Cross-Lane |
| `TLG-23` | `README.md` and `README.tr.md` preserve verbatim definition blocks, carry zero placeholders, and cite wired code | Green | `readme-definition-block-is-verbatim`, `readme-has-no-placeholders`, `readme-claims-are-wired`, `badges-current` | Lane D |
| `TLG-24` | Legacy concept-name gate active with zero unratcheted regressions (`Budscan`, `Gonca`, `Sera`, `GT-1`, `Liquid storage` at `0/0`) | Green | `budlum-gates concept-names`, `config/naming/concept_map.toml` | Lane D |
| `TLG-25` | All required CI and nightly workflows covered and non-vacuous | Green | `budlum-gates ci-workflow-guards`, `budlum-gates workflows-cover-every-workspace` | Lane D |
| `TLG-26` | Reproducible release profiles, lockfile coverage, and supply-chain audits enforced | Green | `budlum-gates release-profile-pins`, `.github/workflows/osv-scanner.yml`, `supply-chain/audits.toml` | Lane D |
| `TLG-27` | Explicit Bridge (`Open`) and AI Inference Layer (`Closed`) decisions recorded and test-locked | Green | `src/tests/wp44_domains_bridge_settlement.rs`, `src/execution/executor.rs` (`ai_layer_is_closed_on_testnet`) | Lane A/D |
