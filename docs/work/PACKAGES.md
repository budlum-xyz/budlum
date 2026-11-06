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
| WP-04 (audit) | D | the open-pull-request coordination report, first edition | this PR | see the head commit | no verdict yet: the run is queued | none; the report is a measurement, and the decisions it names are not taken by an agent |

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

## WP-04: the open pull request coordination report

`docs/work/PR_COORDINATION.md` measures where the 52 open pull requests collide,
which is the question Section 15.1 and Section 15.3 assume away by allowing only
four agents and one owner per lock path. The measurement is reproducible:

```sh
python3 ops/scripts/pr_coordination.py
```

It found three things worth a human decision rather than a commit:

1. **Two histories.** Three open pull requests (#8, #9, #71) have no common
   ancestor with `main`; #8's own diff is 344 files and 94 617 deleted lines.
   The directive's analysis base lives in that second history too. Which tree
   is the repository of record is a decision (Section 0.3 item 2), and the
   report names it rather than taking it.
2. **44 new files implemented twice or more with different content**, including
   one gate implemented four ways across five pull requests.
3. **332 paths shared by two or more pull requests**, 12 of them among the
   directive's own append-only list and the rest lock collisions that are still
   rebase work because nothing is merged.

The report also records what was verified about `main` itself, so the queue is
not blamed for defects the base does not have: the method-class table (218
methods, declaration order), the operator-gate column, gate registration (142 of
142), the required test names (241 across 14 gates) and metric writes (122) all
pass when replayed.
