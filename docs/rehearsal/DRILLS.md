# Ceremony Rehearsal Runbook and Drill Specifications (WP-46)

This document defines the ceremony rehearsal topology (`ops/rehearsal/topology.toml`,
`config/rehearsal-genesis.json`) and the seven mandatory chaos, load, and cross-environment
drills (`T-1` through `T-7`) verified by `src/registry/rehearsal.rs` and `tests/rehearsal/main.rs`.

## 1. Topology Floors

- **Full validators:** at least `8` independent Full-class validators across at least `3`
  cloud regions and at least `2` cloud providers (`chain_id = 45262`).
- **P2P relays and gateways:** at least `4` circuit-relay v2 nodes and at least `2`
  B.U.D. 3.0 upload gateways.
- **Mobile validators:** at least `20` physical Android phones plus at least `1,000`
  headless simulated Mobile validators running the mobile validator core.
- **Steady-state soak:** at least `72` continuous hours (`259,200` seconds) prior to
  running `T-1..T-7`.

## 2. Mandatory Drills and Pass Criteria

| Drill | Scenario | Binding Pass Criterion |
|---|---|---|
| `T-1` | Simultaneous shutdown of 100% of Mobile validators | Finality latency remains within 500 ms baseline, `0` objects are lost, and Full-class reads continue without interruption |
| `T-2` | Sudden crash of 10% (at least 1) of Full validators | Finality lags by at most `2` checkpoints and standby seat handover completes within `3` checkpoints |
| `T-3` | More than 1/3 of active seats halted for `50` blocks, then restored | `budlum_finality_stalled` alert fires (`40`-block disaster recovery threshold) and finality resumes cleanly once seats return |
| `T-4` | Mobile validators reconnect and submit `ResumeValidator` | Duty activates after `1` epoch boundary, zero stake is slashed (`V-4`), and lazy repair drains backlog to `0` |
| `T-5` | Storage load test: `>= 100 GiB` uploaded plus `>= 10,000` small objects with concurrent views | All uploads register, sub-symbol objects pack into `AggregationVolume`, and concurrent view failure count equals `0` |
| `T-6` | Multi-environment execution: Foundry, Hardhat, viem, CosmJS, Anchor, Aptos CLI, plus atomic EVM-to-CW20 transfer | All six toolchains complete green and the single-transaction cross-environment EVM -> CW20 call commits atomically |
| `T-7` | Public JSON-RPC load test under rate limiting | Rate limiter emits HTTP `429` (`budlum_rpc_rate_limited_total > 0`) with `0` unhandled `5xx` responses or panics |
