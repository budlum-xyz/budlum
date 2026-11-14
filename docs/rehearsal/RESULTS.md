# Ceremony Rehearsal Measurements and Drill Ledger

This file distinguishes acceptance targets and synthetic tests from measured
field results. `tests/rehearsal/main.rs` builds a fixture (`chain_id = 45262`):
it hard-codes a topology with 20 Android-phone entries, a 72-hour duration,
and reported drill outcomes. Those inputs do **not** show that physical phones
participated, a multi-region rehearsal ran for 72 hours, or a drill met its
threshold in the field. No dated field report, CI run number, real-device logs,
or published genesis ceremony evidence is recorded below. The local compose
workflow (`.github/workflows/testnet-rehearsal.yml`) is a separate, shorter
four-validator rehearsal whose report is uploaded as a CI artifact, not
appended to this file. The [TLG ledger](../audit/TLG_REPORT.md) stays unverified
until actual run artifacts and approvals are attached.

## 1. Drill targets (not measured results)

| Drill | Synthetic check in tree | Acceptance target | Field status |
|---|---|---|---|
| `T-1` | In-memory symbols and fabricated latency in `tests/rehearsal/main.rs` | No lost objects, Full reads green, bounded finality delta | Not recorded |
| `T-2` | Fixture report supplies lag and handover fields | Finality lag at most 2 checkpoints, seat handover at most 3 | Not recorded |
| `T-3` | In-memory handover tracker observes synthetic block heights | Recovery alert after eight checkpoints and resumption on quorum | Not recorded |
| `T-4` | Fixture report supplies resumption and backlog fields | Resume in next epoch, zero slash, repair backlog drained | Not recorded |
| `T-5` | Test packs 32 small objects; report uses constants for upload totals | At least 100 GiB, 10,000 small objects, no view errors | Not recorded |
| `T-6` | Fixture report sets toolchains and atomic call to `true` | Actual ecosystem tools and atomic cross-environment transfer | Not recorded |
| `T-7` | Fixture report hard-codes HTTP 429 and server-error counts | Observe rate limiting without unhandled errors under real load | Not recorded |

## 2. Resource acceptance bounds, not measurements

- **Peak RSS ceiling:** at most 256 MiB across the Android tiers specified in [the device matrix](../MOBILE_DEVICE_MATRIX.md).
- **Background battery ceiling:** at most 5% over an uncharged 24-hour Wi-Fi duty cycle.
- **Metered network policy:** zero custody symbol bytes over cellular unless `allow_cellular_opt_in = true`.

`analyze_mobile_field_logs` validates submitted records; the synthetic JSONL
in `tests/rehearsal/main.rs` does not measure a device. To change a TLG status,
record device and build identifiers, operator, UTC start/end, input logs, actual
measurements including failures, commit SHA and CI run or rehearsal artifact,
then have a reviewer other than the author approve the evidence.

## 3. Local testnet user attempt (2026-11-09; not a rehearsal pass)

On branch `testnet`, the operator attempted to launch and drive the actual
node/faucet/user flow. `cargo run --locked --bin budlum-core -- --help` exited
`101` during the `budlum-uel-abi` build script: system `protoc` is not installed.
The node binary did not start. The configured package installation was denied
by the session's external-code permission gate; no downloaded compiler was
substituted. `docker compose -f ops/testnet-local.yml up -d --build` was also
blocked before execution by the permission gate because the local profile
sets public RPC authentication off. Docker was not installed in this host
session. No validator process, finalized block, faucet grant, explorer page,
AppBinding payment, object upload or physical-device test was observed. These are
**startup blockers**, not passing runtime measurements and not a failed field
drill. Re-run the actual user journey on the final commit in an authorized
environment before changing any TLG verdict.
