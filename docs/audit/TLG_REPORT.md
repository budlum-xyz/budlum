# Testnet launch gate: evidence and gaps

**Verdict: NOT VERIFIED / NOT READY TO CLAIM.** None of the 27 launch-gate
conditions has a complete, reviewed evidence set in this report. "Unverified"
is a launch-evidence verdict, not a synonym for green CI: the exact-head
rehearsal failures below are real failures. Do not advertise a public testnet
or claim testnet readiness on the basis of source files or synthetic fixtures.

Inspection baseline: `f37e5c4d5b9faa33af554489ede48986c529157e`
(2026-11-09). This SHA identifies the tree originally inspected, **not** a
passing rehearsal or CI run. Later, PR #110 at `8af1ae75f34e27078f4372c25c27c9e42a4a3f72`
had [rehearsal run 43120893142](https://github.com/budlum-xyz/budlum/actions/runs/43120893142):
its Compose job passed, but native E2E job `130860772628` **failed** when
finality did not advance with one validator stopped. PR #126 at
`5db82e189103499e2d4c5a53a7b72b67c51b8160` had
[rehearsal run 43123295605](https://github.com/budlum-xyz/budlum/actions/runs/43123295605):
Compose job `130868924459` **failed before startup** because the builder
image omitted eight embedded `contracts/object-layer/` source files. The
source tree now adds a Dockerfile COPY and an image-input gate; that old run
is not evidence that the fix passed. Passing final-tree CI, a 72-hour
rehearsal and independent approval are **not verified**. An author must attach
a run URL/ID, exact commit SHA, recorded outputs and an approval by a different
reviewer for each condition before marking it green. The targets below are
the directive's Section 18 criteria, not measured results.

| Gate | Source/evidence inspected | Missing evidence or demonstrated gap | Verdict |
|---|---|---|---|
| TLG-01 | `docs/SECURITY.md`; `docs/audit/` had no findings register at inspection. | Count and dispositions of all open Critical/High findings, closure or testnet rejection tests. | Unverified |
| TLG-02 | `config/testnet.toml`, `src/cli/bud3_commands.rs`. | CI results for every closed and conditional feature's on-testnet rejection test. | Unverified |
| TLG-03 | `xtask/gates/src/gates/no_legacy_storage.rs`; `bud/` and legacy files under `src/storage/` remain in tree. | Zero-legacy-storage gate result and a justified inventory; presence of the gate alone does not prove removal. | Unverified |
| TLG-04 | `src/storage/bud3/`, `docs/STORAGE.md`. | Complete acceptance T1-T12, T14-T26, T34-T41 and last seven nightly runs of T3, T4, T6, T7, T17. | Unverified |
| TLG-05 | `src/validators/`, `src/chain/`; #110 native E2E job `130860772628` stopped one validator and saw finality stay at height 30. | Diagnose that real failure; then supply green committee-finality and seat-handover tests on the final commit. One green Compose run cannot erase the native failure. | Unverified: native chaos red |
| TLG-06 | `src/registry/handover.rs`, `tests/churn/`. | CI results for all handover and churn scenarios, plus a successful native loss/rejoin rehearsal. | Unverified |
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
| TLG-20 | `config/testnet.toml` now declares keyless public RPC (`auth_required = false`) and authenticated operator RPC (`operator_auth_required = true`); `src/main.rs` reads the split, and the eight-seat preflight checks both flags. The T-7 fixture remains hard-coded. | Obtain exact-head CI for public/operator method classification, rate limits and denial of unauthenticated operator calls, plus a real T-7 load record and independent review. A correct-looking profile and local preflight are not a field test. | Unverified |
| TLG-21 | `src/bin/bud.rs` implements `bud faucet request`; `src/bin/budlum-faucet.rs` shares its in-process client. #110 native rehearsal reported a faucet grant and explorer read, but failed later at finality; #126 Compose image build failed before startup at `5db82e18`. | Capture a real signed 100 BUD transfer, verified receipt, persisted `--state-file` and restart behaviour, explorer read, Prometheus scrape and alerts on the exact final build. The sandbox's full core build hit its 2 GiB memory limit; the available earlier CI is not a complete rehearsal for this commit. | Unverified |
| TLG-22 | `docs/audit/` had no independent review records at inspection. | Two independent reviews and closure of new Critical/High findings. | Unverified |
| TLG-23 | `README.md`, `README.tr.md`, README gate implementations in `xtask/gates/src/gates/`. | Appendix equality and claim-wiring results, measured badge count and all other required README gates on the final tree. Definition blocks are preserved; this does not prove full appendix equality. | Unverified |
| TLG-24 | `xtask/gates/src/gates/concept_names.rs`. | CI result in absolute mode with zero matches. | Unverified |
| TLG-25 | `.github/workflows/ci.yml` and nightly workflow definitions; #110 native rehearsal `43120893142` and #126 Compose rehearsal `43123295605` have failed jobs at their recorded heads. | Green CI for the exact *subsequent* final tree, resolution of both failures and all required nightlies for the last seven nights. Queued jobs and workflow files are not passing run evidence. | Unverified: recorded CI failures |
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
