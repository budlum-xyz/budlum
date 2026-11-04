# Live baseline (WP-01 to WP-04)

Recorded per directive section 0.4 and WP-04 task 2. This file is the shared entry point for all four lanes.

| Field | Value |
|---|---|
| Live branch | `main` |
| Live commit | `14d9a18130b5147e9f0e9412e57b3f8b31b45449` (2026-11-04) |
| Working branch | `wp/01-04-live-verification` (single PR shared by every lane agent) |
| Rust toolchain pin | `1.97.1` (`rust-toolchain.toml`) |
| Source files | see `docs/audit/live/lane-*.md` |

## CI status on `main` at baseline

Latest run per workflow (queried with `gh run list --branch main`). Most recent PR-triggered runs are at commit `451ea26e`.

- Result: every `pull_request` workflow run at `451ea26e` ended in `failure` after about 57 seconds.
- Cause shown by `gh run view 41902082061` (workflow `CI`): "This run likely failed because of a workflow file issue." No job logs exist.
- Scheduled runs at `c5b06799`: `Fuzz Nightly` success, `Kani Slow Proofs` success, `Dependabot Updates` success, `Miri Storage Weekly Full Sweep` cancelled, `Security Hardening` failure, `Watchdog` failure.
- Consequence: CI cannot yet act as the single verifier (invariant S-1) on this repository. Fixing the workflow-file issue is WP-42 scope. Until then each lane records local evidence (test name, command, output) and marks the CI run number as `n/a (workflow file issue)`.

## Environment limits seen at baseline

- No Rust toolchain installed in the agent environment at start. 2 CPU cores, 7 GB RAM.
- Full workspace builds are expensive. Lanes build only the single test target they need.

## Lane files

| Lane | Findings file | Test file |
|---|---|---|
| A | `docs/audit/live/lane-a.md` | `src/tests/audit_lane_a.rs` |
| B | `docs/audit/live/lane-b.md` | `src/tests/audit_lane_b.rs` |
| C | `docs/audit/live/lane-c.md` | `src/tests/audit_lane_c.rs`, `budzero/tests/audit_lane_c.rs` |
| D | `docs/audit/live/lane-d.md` | `src/tests/audit_lane_d.rs` |
