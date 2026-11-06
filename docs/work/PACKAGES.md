# Work package status

This file is the state record of Section 15.5 item 7: one row per work package,
its status, its pull requests, the last commit of each, the CI runs that
verified it, and the findings it closes. A package is `done` only when every
criterion of its card in Section 15.8 has evidence; a self-report is not
evidence (Section 0.3 item 5).

`WP-NN` here and the directive's own package id are the same package.

## Live state

| Package | Lane | Status | Pull request | Last commit | CI run | Findings closed |
|---|---|---|---|---|---|---|
| WP-28 | C | 1/2 in review: the Ethereum namespace, its class table, the chain-level reads and the named refusals | this PR | see the head commit | no verdict yet: the run is queued | BLG-249 (Ethereum foot, partial: the namespace exists and refuses by name; the state methods wait for WP-27) |

## WP-28: Ethereum JSON-RPC gateway

Delivery 1/2 of the card. What is in the tree and what it proves:

| Card item | State | Evidence |
|---|---|---|
| Method table, in the `method_class.rs` pattern | delivered | `src/rpc/compat/ethereum/mod.rs`, `eth_rpc_method_table_is_complete` |
| Every Section 8.11.2 method present in the table | delivered | `eth_rpc_method_table_is_complete` compares the table to the directive list |
| The table, `api.rs` and `method_class.rs` agree | delivered | `eth_served_set_matches_the_declared_api`, `eth_class_table_matches_the_gateway_table`, and the startup check `method_class::check_served_methods` |
| `eth_getProof` answers `-32601` | delivered | `eth_get_proof_returns_method_not_found` |
| Every refusal names a door that exists | delivered | `eth_refusals_name_an_existing_door` |
| `debug_traceTransaction` and `debug_traceCall` are operator only | delivered | `eth_debug_methods_are_operator_only`, and the Budlum listener test `the_listener_column_matches_the_handlers` |
| Listeners on `127.0.0.1:18547` (HTTP and WebSocket) | 2/2 | not in this delivery |
| Bounded filters, timeouts, per-peer quota | 2/2 | `eth_subscribe` and `eth_unsubscribe` are table rows marked pending; the startup check refuses to serve them |
| Block and receipt shapes with `stateRoot = execution_root` | 2/2 | needs the `GlobalBlockHeader` v8 field of WP-27 |
| Foundry, Hardhat, viem, ethers tool tests (nightly) | 2/2 | they cannot pass before WP-27; no green claim is made |

The read side is honest about the dependency: WP-28 depends on WP-27 in Section
15.7, and the EVM execution environment is not merged. Serving state methods
before it would be the `eth_getBalance`-returns-a-Budlum-balance mistake, which
is why those answers are refusals with a named door rather than numbers.
