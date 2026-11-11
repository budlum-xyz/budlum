# Testnet launch gate: evidence and gaps

**Verdict: NOT VERIFIED / NOT READY TO CLAIM.** None of the 27 launch-gate
conditions has a complete, reviewed evidence set in this report. "Unverified"
does not mean a test failed; it means the required run result, rehearsal record,
or independent approval has not been supplied. Do not advertise a public testnet
or claim testnet readiness on the basis of source files or synthetic fixtures.

Inspection baseline: `f37e5c4d5b9faa33af554489ede48986c529157e`
(2026-11-09). This SHA identifies the tree inspected, **not** a passing
rehearsal or CI run. CI run numbers: **not supplied/verified**. Rehearsal
artifact IDs: **not supplied/verified**. Independent approver: **none
recorded**. An author must attach a run URL/ID, exact commit SHA, recorded
outputs and an approval by a different reviewer for each condition before
marking it green. The targets below are the directive's Section 18 criteria,
not measured results.

| Gate | Source/evidence inspected | Missing evidence or demonstrated gap | Verdict |
|---|---|---|---|
| TLG-01 | `docs/SECURITY.md`; `docs/audit/` had no findings register at inspection. | Count and dispositions of all open Critical/High findings, closure or testnet rejection tests. | Unverified |
| TLG-02 | `config/testnet.toml`, `src/cli/bud3_commands.rs`. | CI results for every closed and conditional feature's on-testnet rejection test. | Unverified |
| TLG-03 | `xtask/gates/src/gates/no_legacy_storage.rs`; `bud/` and legacy files under `src/storage/` remain in tree. | Zero-legacy-storage gate result and a justified inventory; presence of the gate alone does not prove removal. | Unverified |
| TLG-04 | `src/storage/bud3/`, `docs/STORAGE.md`. | Complete acceptance T1-T12, T14-T26, T34-T41 and last seven nightly runs of T3, T4, T6, T7, T17. | Unverified |
| TLG-05 | `src/validators/`, `src/chain/`. | Committee-finality and seat-handover test run for this commit. | Unverified |
| TLG-06 | `src/registry/handover.rs`, `tests/churn/`. | CI results for all handover and churn scenarios. | Unverified |
| TLG-07 | `tests/rehearsal/main.rs` uses in-memory symbols and hard-coded latency. | T-1 field drill: stop actual Mobile cohort, record finality before/after and object reads. | Unverified |
| TLG-08 | `tests/rehearsal/main.rs` supplies hard-coded T-2 lag. | T-2 field drill with actual Full validator departures and checkpoint timings. | Unverified |
| TLG-09 | `tests/rehearsal/main.rs` supplies fixture outcomes for T-3, T-4, T-5, T-7. | Dated T-3/T-4/T-5/T-7 field drill results, failures and raw records. | Unverified |
| TLG-10 | `tests/rehearsal/main.rs` synthesizes `phone-00` through `phone-19`; Android client onboarding currently includes a hard-coded address and synthetic balance flow pending fail-closed fixes. | Real Android phones with verified wallet and balance onboarding, storing, answering audits, serving symbols and receiving rewards; explorer and rehearsal records. | Unverified |
| TLG-11 | `docs/MOBILE_DEVICE_MATRIX.md` labels its physical-device campaign pending. | Actual 24-hour device logs, battery methodology and NAT observations. | Unverified |
| TLG-12 | `execution/` and `docs/EXECUTION_LIMITS.md`. | CI conformance results for EVM, CosmWasm, SVM, Aptos Move and BudZero; documented exceptions. | Unverified |
| TLG-13 | `.github/workflows/conformance-nightly.yml`. | Nightly run IDs showing unchanged ecosystem tools pass or bounded exceptions. | Unverified |
| TLG-14 | `tests/rehearsal/main.rs` assigns T-6 success `true` in a fixture. | Atomic EVM-to-CosmWasm test result and actual T-6 rehearsal record. | Unverified |
| TLG-15 | `.github/workflows/determinism.yml`. | Green x86_64/aarch64 state and execution root comparison on the target commit. | Unverified |
| TLG-16 | `docs/EXECUTION.md`. | CI output from the gas calibration bound and supporting measurement. | Unverified |
| TLG-17 | `ops/rehearsal/genesis_rehearsal.py`, `docs/rehearsal/DRILLS_AND_RUNBOOK.md`. | Ceremony report with distinct operators, at least eight actual Full validators, signed genesis digest and supply audit. | Unverified |
| TLG-18 | `docs/rehearsal/RESULTS.md` has targets, no measured NAT ratios. | Green relay/DCUtR/AutoNAT nightlies and recorded live connectivity breakdown. | Unverified |
| TLG-19 | `src/tokenomics/`, `src/storage/bud3/fees.rs`. | Green economy invariant run including storage and pool payouts. | Unverified |
| TLG-20 | `src/rpc/method_class.rs`; T-7 fixture is hard-coded. `config/testnet.toml` sets public `auth_required = true` while `src/main.rs` uses unauthenticated `operator_default()` on loopback; `xtask/tools/src/testnet_rehearsal.rs` preflight expects public auth. | Reconcile the intended keyless-public/authenticated-operator policy with config, runtime and tests, then supply CI and actual T-7 load records. Do not advertise the public listener as keyless yet. | Unverified: policy conflict |
| TLG-21 | `src/bin/budlum-faucet.rs`, `src/bin/budlum-indexer.rs`, `ops/testnet-local.yml`. | Live rehearsal showing faucet, explorer, dashboards and alerting work; verify persisted `--state-file` and restart behavior. The inspected baseline lacked server-side PoW and `bud faucet request`; this branch adds `budlum-faucet request` plus the challenge handler, but focused Rust tests could not compile without `protoc`. No running transfer, restart test or Prometheus scrape result has been recorded. The directive's `bud faucet request` command is still missing. | Unverified |
| TLG-22 | `docs/audit/` had no independent review records at inspection. | Two independent reviews and closure of new Critical/High findings. | Unverified |
| TLG-23 | `README.md`, `README.tr.md`, README gate implementations in `xtask/gates/src/gates/`. | Appendix equality and claim-wiring results, measured badge count and all other required README gates on the final tree. Definition blocks are preserved; this does not prove full appendix equality. | Unverified |
| TLG-24 | `xtask/gates/src/gates/concept_names.rs`. | CI result in absolute mode with zero matches. | Unverified |
| TLG-25 | `.github/workflows/ci.yml` and nightly workflow definitions. | Green final-tree CI and all required nightlies for the last seven nights. Workflow files are not run evidence. | Unverified |
| TLG-26 | `release/` and release workflow definitions. | Published reproducible artifacts, hashes, SBOM and signatures with build records. | Unverified |
| TLG-27 | `docs/AI_VERIFICATION_STATUS.md`; domain and bridge sources. | Recorded bridge and AI activation/closure decisions with test results for chain 45261. | Unverified |

## Evidence boundaries and next steps

- `docs/rehearsal/RESULTS.md` currently contains **targets**, not 72-hour fleet
  measurements. The hard-coded fixture topology and outcomes in
  `tests/rehearsal/main.rs` are not substitutes for a physical-device campaign.
  The nightly local compose workflow publishes `target/testnet-rehearsal.md`
  as an artifact, but this report has no verified run ID or artifact to cite.
- `docs/MOBILE_DEVICE_MATRIX.md` explicitly marks the real-device campaign
  pending. No measured battery, throughput, finality, redundancy or network
  connectivity figure may be copied from a target or fixture into a README.
- The directive's README appendices describe a **target public network** and
  include values that depend on operator DNS, genesis ceremony, release and
  rehearsal. Those prerequisites are not documented as completed. The README
  definition blocks stay byte-for-byte unchanged; the rest must not be
  advertised as an operational public launch before the gate passes.
- Preserve gate specificity: attach exact SHA, CI run ID, required result and
  independent approval for each row; do not turn all rows green merely because
  an aggregate CI job succeeds. After a second reviewer approves every row,
  operators may perform the separate launch steps (genesis, release, DNS,
  service smoke tests) and announce a public endpoint.
