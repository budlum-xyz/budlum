# Ceremony Rehearsal Measurements and Drill Ledger (WP-46)

This file tracks the binding pass thresholds and verified simulation/rehearsal
ledger for `config/rehearsal-genesis.json` (`chain_id = 45262`). Live 72-hour
hardware soak numbers are appended by the rehearsal harness (`budlum::registry::rehearsal`).

## 1. Drill Verification Ledger

| Drill | Verified In-Tree Suite | Target Threshold | Status |
|---|---|---|---|
| `T-1` | `tests/rehearsal/main.rs` | `0` lost objects, Full reads green, finality delta `<= 500 ms` | Harness verified |
| `T-2` | `tests/rehearsal/main.rs` | Finality lag `<= 2` checkpoints, seat handover `<= 3` checkpoints | Harness verified |
| `T-3` | `tests/rehearsal/main.rs` | `40`-block disaster recovery alert fires at `<= 50` blocks; resumes on quorum | Harness verified |
| `T-4` | `tests/rehearsal/main.rs` | `ResumeValidator` active in `+1` epoch; `0` slash; repair backlog `0` | Harness verified |
| `T-5` | `tests/rehearsal/main.rs` | `>= 100 GiB` total upload, `>= 10,000` small objects, `0` view errors | Harness verified |
| `T-6` | `tests/rehearsal/main.rs` | Multi-EE toolchains + atomic EVM -> CW20 transfer | Harness verified |
| `T-7` | `tests/rehearsal/main.rs` | HTTP `429` rate limit enforced, `0` unhandled `5xx` or panics | Harness verified |

## 2. Resource Envelopes Enforced by `analyze_mobile_field_logs`

- **Mobile peak RSS ceiling:** `<= 256 MiB` across Entry (`4 GB`), Midrange (`8 GB`), and Flagship (`12 GB`) Android tiers.
- **Mobile background battery ceiling:** `<= 5.00%` per 24 hours (`<= 500 bps`) on Wi-Fi duty.
- **Metered network policy:** `0` custody symbol bytes served over cellular unless the operator explicitly enables `allow_cellular_opt_in = true`.
