# Production evidence triage: launch gates and findings

Inspection base: `62b7beeca453dda88693b928c69f7e5c8d585490`. This is a **bounded
source audit**, not a 72-hour rehearsal or a CI verdict. The existing
[TLG ledger](TLG_REPORT.md) has 27 unverified entries and
[finding ledger](FINDINGS.md) has 267 unknown entries. No CI run IDs, current
merged closure SHAs, physical-device records, cross-chain origin transaction
proofs, or independent approvals were supplied. Do not mark any row green
because a module or `#[test]` exists. The `launch-evidence` gate in
`xtask/gates/src/gates/launch_evidence.rs` now rejects the incomplete ledgers:
**27 TLG + 267 BLG = 294 missing-evidence rows** on this snapshot, plus a
separate fail-closed AppBinding direct-door finding (the configured devnet-only
flag is never called at that entry). It checks metadata and current source
citations; it cannot independently authenticate
a GitHub run, prove test semantics, or substitute for human review. A
"passing" static gate is never sufficient launch evidence by itself.

## All 27 launch conditions: first production/evidence boundary to verify

| TLG | Existing path or gate to inspect | Missing verification before green |
|---|---|---|
| 01 | `docs/audit/FINDINGS.md`, `xtask/gates/src/gates/rejection_tests.rs` | Per-Critical/High closure or tested 45261 feature rejection; count is unknown. |
| 02 | `src/execution/executor.rs:183-200`, `src/tests/privacy_ai_execution.rs:541-580` | All Section 1.5 closed/conditional transactions at actual admission and execution doors, not just a named-test scan. |
| 03 | `xtask/gates/src/gates/no_legacy_storage.rs`, `bud/`, `src/storage/` | Full removed-path inventory and passing gate; legacy paths still exist in inspected tree. |
| 04 | `src/storage/bud3/`; no `.github/workflows/storage-nightly.yml` was found on this commit | Required acceptance test list and seven nights of specific storage results. |
| 05 | `src/chain/finality.rs`, `src/validators/` | Committee/seat tests on closing SHA and production block path. |
| 06 | `src/registry/handover.rs`, `tests/churn/` | Handover and churn runs, with actual failure outcomes. |
| 07 | `tests/rehearsal/main.rs:146-165` | Real T-1 phone departure and unchanged finality/objects; fixture numbers are hard-coded. |
| 08 | `tests/rehearsal/main.rs:151-152` | Real T-2 Full departures with timed checkpoint evidence. |
| 09 | `tests/rehearsal/main.rs:153-163` | Real T-3/T-4/T-5/T-7 records, not fixture `true` values. |
| 10 | `mobile/android/app/src/main/java/network/budlum/validator/ui/MainActivity.kt:42-48`, `tests/rehearsal/main.rs:167-181` | Real phones, wallet/balance onboarding, storage audits/symbols/rewards and explorer transactions. |
| 11 | `docs/MOBILE_DEVICE_MATRIX.md:34-66` | Physical-device 24-hour logs, battery and NAT measurements; campaign marked pending. |
| 12 | `execution/`, `docs/EXECUTION_LIMITS.md` | Actual EVM/WASM/SVM/Move/BudZero conformance output with bounded exceptions. |
| 13 | `.github/workflows/conformance-nightly.yml` | Named ecosystem-tool command outputs and nightlies on target SHA. |
| 14 | `src/execution/coordinator/`, `tests/rehearsal/main.rs:160-161` | Actual atomic EVM -> CosmWasm transaction and T-6 drill; synthetic report sets `true`. |
| 15 | `.github/workflows/determinism.yml:80-99,224-245` | x86_64/aarch64 identical state/execution roots; aarch64 matrix here covers PQ vectors, not block roots. |
| 16 | `docs/EXECUTION.md`, `xtask/gates/src/gates/gas_calibration.rs` | Measured gas-bound CI output, not only a gate definition. |
| 17 | `ops/rehearsal/genesis_rehearsal.py`, `config/ceremony-rehearsal-genesis.json` | Distinct real operators' signed genesis ceremony, minimum Full validator records, supply audit. |
| 18 | `docs/rehearsal/RESULTS.md`; no dedicated `nat-nightly.yml` was found on this commit | NAT relay/DCUtR/AutoNAT nightly IDs and field ratios (not target thresholds). |
| 19 | `src/tokenomics/`, `src/storage/bud3/fees.rs`, `xtask/gates/src/gates/economy_invariants.rs` | Pool/fee/reward conservation across actual block transition and CI. |
| 20 | `src/rpc/method_class.rs`, `config/testnet.toml:42-51`, `src/main.rs:1819-1846` | Resolve keyless-public/authenticated-operator mismatch; proposed split is uncommitted/unpublished. Run method, quota and T-7 refusal/load tests. |
| 21 | `src/bin/budlum-faucet.rs`, `src/bin/budlum-indexer.rs`, `ops/testnet-local.yml` | Persisted faucet cooldown/nonce, challenge/PoW, explorer, dashboards and alerting in actual rehearsal. |
| 22 | `docs/audit/` | Independent reviews 1 and 2, remediation commits and CI run IDs. |
| 23 | `README.md`, `README.tr.md`, README gates under `xtask/gates/src/gates/` | Full appendix equality, claims wired in production, accurate CI-measured badges; definition-block checks alone are insufficient. |
| 24 | `config/naming/concept_map.toml`, `xtask/gates/src/gates/concept_names.rs` | Absolute mode with zero residual names; current profile says `mode = "count"`. |
| 25 | `.github/workflows/ci.yml` and nightly workflows | Passing commit-specific CI and all required nightlies for seven nights. |
| 26 | `release/`, release workflow sources | Reproduced binaries, SBOM and signatures with published hashes. |
| 27 | `src/cross_domain/`, `src/ai/`, `src/core/chain_config.rs:229-236` | Bridge and AI open/closed decision with rejection tests; do not substitute AppBinding's devnet-only capability for a testnet activation. |

The path inventory above is a **triage map**, not a claim that each path is
wired or each issue fixed. In particular, `tests/rehearsal/main.rs:146-181`
constructs pass values and synthetic phones. A CI pass of that fixture only
proves the evaluator accepts those hand-entered values.

## All 267 BLG findings: verification protocol and coverage gap

[Live source index](LIVE_STATUS.md) maps each BLG-001..267 to a directive
line, severity, and planned package; [closure ledger](FINDINGS.md) has a row
for each ID with named-test, live file:line, closing SHA, CI run, reviewer and
closed-feature evidence fields. **All 267 production paths remain unverified**
in that ledger. The historical Section 14 "code traces", source titles and
planned removal packages are not a live reproduction or proof of production
wiring. No finding is marked fixed, removed or invalid by this audit.

- **BLG-001..207:** prior finding-ledger snapshot; verify each alleged issue
  on live code with a regression, including BLG-005 (historically "closed")
  and BLG-008 (testnet public RPC auth mismatch). Do not import old severity
  counts as today's open count.
- **BLG-208..245:** storage/BudZero source-directive issues. A listed
  `src/storage/*` or `bud/*` file is not proof of reachability or deletion;
  removed-code closures require the actual path list and green
  `no-legacy-storage` run on the closing commit.
- **BLG-246..267:** newer directive observations; e.g. BLG-257 mobile
  onboarding and BLG-249 ecosystem RPC are *source observations*, not proof
  that an app or foreign ecosystem tool works on an open testnet.
- Prioritize complete flows through signed request -> admission -> block
  execution -> persisted state -> RPC/readback on the same chain ID. For
  cross-network app binding, test origin-network proof, BUD settlement and
  origin-app response, not just `AppBindingTx` helpers or method-class strings.
  `docs/APP_BINDING.md:6-13`, `src/core/chain_config.rs:229-236` and
  `src/tests/domains_bridge_settlement.rs:333-375` describe/dev-test the
  feature but explicitly **close it on testnet**. An unwired CLI or a green
  rejection test is not a working end-user application flow.

## Remaining G invariants and app-binding conflict

The separate [G audit](G_INVARIANTS.md) records exact source lines. G-1
(block-only write) is unverified; the RPC auth mismatch is a distinct
exposure blocker, not proof of an out-of-block mutation. G-2 lacks x86_64/
aarch64 same-block state/execution-root run evidence. G-3 requires verified
supply conservation, not only a call-count rationale. G-4's identified sequential-credit issue in
`Executor::pay_agreeing_verifiers` was preflighted in `a0aec24a`, but its
state-equality regression remains unrun and the static refusal gate only scans
`remove`-then-`Err`; other partial-write paths remain unverified. G-5's length-prefix scan excludes some workspaces and
helper preimages; tag inventory does not prove framing. G-6 has baseline and
`Convenience:` exemptions and uncalled optical helpers. G-7 has testnet
closure tests but no complete run/coverage evidence. G-8 needs live domain
and operator-independence evidence, not a guide. None is asserted green.

For the user report that "G does not work": **AppBinding/app_binding is the most
literal cross-network-app interpretation** and is disabled on testnet by
profile; do not re-enable it simply to make a source-only demo pass. The
underlying signed foreign-network application/return path needs a scoped
security review and end-to-end test before any activation-height decision.
