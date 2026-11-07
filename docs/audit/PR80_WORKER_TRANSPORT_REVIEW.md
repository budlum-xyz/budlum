# PR #80 worker-transport and economic-boundary integration review

| Field | Value |
|---|---|
| Reviewed source | PR #80, `bfe2876f57de0657d39581d57fe5c5c10040f4b0` |
| Integration target | PR #140 / `arena/8f90e12c-budlum` |
| Source check inventory | 6 failed, 4 successful, 35 cancelled, 55 pending and 3 skipped checks in the captured inventory. The source's historical substitute-compiler results are not current-tree or pinned-toolchain evidence. |
| Current execution evidence | Static/source checks, tree-sitter parsing and Python suites only; no Rust toolchain, Cargo build, Rust test or live worker run was available |

## Source-to-current disposition

The source branch combines worker transport, transaction-cost, supply-accounting,
gate and older execution-limit deliveries. The current tree already contained the
atomic block candidate, checked amount-plus-fee primitive, exact required-fee read
classification, vesting regressions, indexing fixes and the separately integrated
PR #79 budget. Those newer trees and ledgers are retained; historical reconciliation
snapshots and the obsolete no-runner conformance catalog are not restored.

The following still-applicable behavior is adapted rather than copied wholesale:

1. **Absolute transport budgets.** `DeadlineIo` refreshes socket timeouts from one
   checked `Instant`; `WorkerFrameIo` lets an idle connection wait but starts the
   watchdog on the first byte. Reconnect handshake, request writes, host callbacks
   and response reads share the request budget. An unrepresentable deadline is a
   timeout, not a panic.
2. **Connection poisoning and callback shape.** Every final client decode/shape
   error drops the stream. Worker host callbacks require the successful oneof arm
   for their operation or a defined, nonzero error code. Malformed callbacks mark
   the proxy broken so an engine cannot turn transport corruption into a receipt.
3. **Deploy panic boundary.** Deploy validation is caught like execute/query. Its
   response has no fault variant, so a panic closes the connection with a transport
   error. The existing shared `host::panic_digest`/`panic_message` implementation is
   retained instead of the source's duplicate hashing code.
4. **One liquid-cost rule.** Admission, pending-balance projection, precheck and
   execution use `checked_liquid_cost`. The current zero-liquid-cost
   `AiOperatorWithdraw` exit is deliberately preserved; the older source helper did
   not know that later rule. Transfer/stake/delegation keep their specific error
   codes, and the generic gate no longer reads raw balance. The stale fee-only test
   assertion now names the shared gate's actual `vesting_locked` class.
5. **Exact destruction accounting.** Saturating burn/counter operations become
   checked operations. External slash preflights its burn and challenger balance,
   `burn_from` computes the counter before taking its mutable account borrow, each
   timed-burn increment preflights its counters, and no-producer fee summation uses
   `try_fold`. New production `expect` calls are not introduced under the root
   `expect_used = "deny"` lint; explicit `match`/`panic!` preserves fail-stop behavior.
6. **Narrow read-chain gate.** Only the two live read-only subregistry `query_json`
   chains are recognized. Direct/unknown/mutating queries and a chained write after
   an allowed read remain refusals.

The current CI workspace job already runs format, all-target Clippy and all tests
for `crates/uel-abi`, so the three new integration-test files need no workflow or
manifest addition. All three have `#![cfg(unix)]`; this is not Windows execution
evidence. No protobuf field, frame version, RPC name or wire tag changes.

## Regression inventory

Ten new Unix-socket integration tests are present:

- five deadline/client-poisoning tests in `transport_deadlines.rs`;
- three malformed/valid host-callback tests in `transport_host_guards.rs`;
- two deploy-panic/partial-worker-frame tests in `transport_worker_frames.rs`.

Additional unit regressions cover fee-only and amount-bearing liquid costs, the
zero-cost AI withdrawal control, counter-overflow refusal without balance/escrow
movement, challenger-overflow refusal, the no-raw-sender-gate source invariant,
and allowed/refused subregistry gate chains.

## Executed integration checks

- Tree-sitter parsed all nine changed Rust production/test/gate files without a
  syntax error. This is not type checking, borrow checking or compilation.
- Static assertions verified all three client `finish` calls, absolute-deadline and
  discriminant checks, deploy panic isolation, ten transport test entry points,
  all four liquid-cost callers, the zero-cost withdrawal arm, absence of the raw
  executor gate, burn preflight ordering, and both live read-only gate chains.
- Integration audit: 14/14 current-tree checks passed; its 14 injected canaries
  each produced the required refusal.
- Genesis rehearsal unit suite: 12/12 passed. This is not a live rehearsal.
- Diff whitespace/error checks passed; no new production `unwrap`/`expect` candidate
  was introduced in the reviewed production prefixes.
- The 32-byte presence digest was verified after repairing a transport-time UTF-8
  replacement-character corruption in the local snapshot. Its restored value is
  `26a5bec8b11098debd4eeffbe797638d295a08aa570cb3c176d9c5e41bfbb2a3`.

BLG-303 through BLG-308 remain **open; locally corrected, pinned Rust/gate CI
pending**. Rust 1.97.1 compilation, format, strict Clippy, all new Rust tests, the
standalone gate self-test, required CI, cross-platform transport runs and live
worker supervision/restart behavior remain outstanding. No source red check is
represented as fixed by these static checks, and no package-completion, testnet or
performance claim is made.
