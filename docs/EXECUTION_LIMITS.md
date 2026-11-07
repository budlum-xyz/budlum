# Execution limits

Every execution environment of the Universal Execution Layer runs inside a
budget. This page records the budget the code enforces and the exceptions a
conformance run may find. A limit that is not written here is not a limit that
anybody can hold the network to.

## Budget constants in the tree

| Item | Value | Where |
| --- | --- | --- |
| Block budget | `60_000_000 BGU` | `src/execution/coordinator/gas.rs` |
| EIP-1559 target | `30_000_000 BGU` (half of the block budget) | `src/execution/coordinator/gas.rs` |
| Per environment soft limit, EVM | `30_000_000 BGU` | `ee_soft_bgu_limit(EeId::EVM)` |
| Per environment soft limit, WASM | `24_000_000 BGU` | `ee_soft_bgu_limit(EeId::WASM)` |
| Call depth rule | the EIP-150 `63/64` rule | `src/execution/coordinator/gas.rs` |

The soft limits of the remaining environments are returned by
`ee_soft_bgu_limit`; read the function rather than this table, because the
function is what the coordinator calls and this table is a copy.

## Environments

`execution/` holds one crate per environment: `evm`, `wasm`, `svm`, `move`,
`move-sui`, `cairo`, `polkavm`, `budzero`, plus the `conformance` runner. Each
crate builds its own worker binary. The workers build with `panic = "unwind"`
so a failing contract cannot take the node down; the node binary keeps
`panic = "abort"`. The `ee_workers_build_with_unwind` gate holds that split.

## Exceptions

The conformance suite of the launch gate must pass completely, or every
exception must be listed in the table below with the reason it cannot be
closed. No exception is recorded yet, because no conformance run is recorded
yet.

| Environment | Test | Exception | Reason |
| --- | --- | --- | --- |
| none | none | none | No conformance run recorded. |

## Status

- The constants and the crate set above exist in the tree.
- No conformance run number is written here. A run number is evidence; this
  page does not invent one.
- `docs/audit/TLG_REPORT.md` carries the launch-gate row (TLG-12) that this page
  fills when a run exists.

Related pages: [execution layer architecture](EXECUTION.md),
[storage](STORAGE.md).
