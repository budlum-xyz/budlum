# Universal Execution Layer Resource Limits and Cross-Architecture Determinism (WP-35)

This document specifies the deterministic gas bounds, memory ceilings, call-depth
limits, and cross-architecture (`x86_64` and `aarch64`) execution rules enforced
across Budlum's execution environments.

## 1. Per-Transaction and Per-Block Ceilings

| Limit | Value | Scope | Notes |
|---|---:|---|---|
| Maximum block gas | `30,000,000` | Per block | Shared across native and UEL execution envelopes |
| Maximum single-transaction gas | `15,000,000` | Per transaction | Prevents single-call block monopolization |
| Maximum cross-environment call depth | `8` | `UniversalCall` stack | Bounds nested EVM <-> WASM <-> SVM <-> Move invocations |
| Worker linear memory ceiling | `64 MiB` | Per EE worker invocation | Enforced identically on `x86_64` and `aarch64` |
| Maximum contract / module bytecode | `512 KiB` | Deploy / store | Applies to EVM initcode, CosmWasm `.wasm`, SVM ELF, and Move modules |
| Base transfer gas | `21,000` | Native / EVM | Matches `config/testnet-genesis.json` `gas_schedule.transfer_gas` |
| Per-byte calldata gas | `1` | All envelopes | Matches `gas_schedule.gas_per_byte` |
| Post-quantum signature verification gas | `500` | `ML-DSA-65` | Matches `gas_schedule.gas_per_signature` |

## 2. Cross-Architecture Determinism Rules (`x86_64` == `aarch64`)

1. **Zero floating-point instructions in consensus or contract execution:** WASM float
   opcodes and host floating-point arithmetic are rejected at validation time so NaN
   payload differences between `x86_64` and `aarch64` never arise.
2. **Canonical integer serialization:** All state commitments, gas counters, and cross-EE
   `UniversalCall` envelopes encode integers in explicit little-endian fixed-width fields
   (`u64` / `u128`), never target-dependent `usize`.
3. **Failure-atomic call frames:** Every nested `UniversalCall` executes against a candidate
   state overlay; any frame revert rolls back its child state mutations while charging
   exact consumed gas.
