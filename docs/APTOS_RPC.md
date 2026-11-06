# Aptos REST compatibility

WP-32, deliveries 1/N and 2/N, add the Aptos REST route table, production routing, and its dedicated listener. This is an early compatibility surface, not a claim that the Move execution environment or the Aptos SDK conformance suite is complete.

## Current listener and wire behavior

The normal public node startup opens the dedicated `127.0.0.1:18549` listener from Section 8.11.1. It serves Aptos REST only; it has no JSON-RPC dispatcher. The bind must be a numeric loopback socket. A non-loopback bind, a shared JSON-RPC/Aptos address, or a bind failure stops startup instead of silently exposing or dropping the gateway.

The dedicated listener reuses the RPC IP admission, authentication, CORS, rate, and TLS configuration. A bounded semaphore applies the configured connection limit. POST bodies are not read while Move is unavailable, so the refusal path does not allocate from an untrusted body. The public reverse-proxy address `https://aptos.<TESTNET_DOMAIN>/v1` still needs the WP-41 proxy configuration before it is ready.

An embedded or test `RpcServer` does not open a port implicitly. Without `with_aptos_listener`, its configured HTTP listener can route `/v1` to the same Aptos handler. Normal node startup sets the dedicated listener, so `/v1` stays off the JSON-RPC port.

The route table is `src/rpc/compat/aptos/mod.rs`. Like `method_class.rs`, it records the listener and effect of every method. `RpcServer::run` checks the table at startup and invokes the handler for every matching request. The tests check the directive's complete list, route matching, listener/effect consistency, response shapes, and native refusal doors.

## Served routes

### `GET /v1/-/healthy`

Returns `200` and the plain-text body `aptos-node:ok` when the node is not syncing. While the node is syncing, returns `503` and `aptos-node:syncing`. This route does not return a JSON-RPC wrapper.

### `GET /v1`

Returns Aptos-shaped node information derived from the current Budlum head:

- `chain_id` is `205`, the Aptos foreign-envelope chain id assigned by Section 8.6.2.
- `epoch`, `block_height`, and `ledger_timestamp` come from the head block. Budlum milliseconds become Aptos microseconds with checked arithmetic.
- `ledger_version` is the Budlum head height in this early delivery. This is a compatibility progress counter only. It is not evidence that a Move transaction version exists. Every route that resolves or executes a Move version currently refuses.
- `oldest_ledger_version` and `oldest_block_height` are `0` only when the node can still read genesis. A node without genesis returns `503`; it does not claim that version zero is available.
- `node_role` is `full_node`. `git_hash` uses the optional build-time `BUDLUM_GIT_HASH`, or the explicit string `unknown` when the build did not record one.

## Named refusals in this delivery

These routes return HTTP `503`. The JSON body has `error_code = move_execution_environment_unavailable`, names `WP-32`, and includes the native Budlum `door`. No route reads a POST body while the Move worker is absent, and no route mutates consensus state.

| Route | Native door |
|---|---|
| `GET /v1/accounts/{addr}` | `bud_getAccountProof` |
| `GET /v1/accounts/{addr}/resources` | `bud_getAccountProof` |
| `GET /v1/accounts/{addr}/resource/{type}` | `bud_getAccountProof` |
| `GET /v1/accounts/{addr}/modules` | `bud_getAccountProof` |
| `GET /v1/accounts/{addr}/module/{name}` | `bud_getAccountProof` |
| `GET /v1/accounts/{addr}/transactions` | `bud_getTransactionByHash` |
| `POST /v1/transactions` | `bud_sendRawTransaction` |
| `POST /v1/transactions/simulate` | `bud_txPrecheck` |
| `GET /v1/transactions/by_hash/{h}` | `bud_getTransactionByHash` |
| `GET /v1/transactions/wait_by_hash/{h}` | `bud_getTransactionReceipt` |
| `GET /v1/transactions/by_version/{v}` | `bud_getTransactionByHash` |
| `POST /v1/view` | `bud_txPrecheck` |
| `GET /v1/estimate_gas_price` | `bud_gasPrice` |
| `GET /v1/blocks/by_height/{h}` | `bud_getBlockByNumber` |
| `POST /v1/tables/{handle}/item` | `bud_getAccountProof` |
| `GET /v1/accounts/{addr}/events/{creation_number}` | `bud_getTransactionReceipt` |

The native door identifies the closest existing Budlum read or transaction entry point. It does not assert that a native account, transaction, block, or proof has the Aptos/Move meaning. A client must not translate the refusal into an empty account, a zero balance, a missing transaction, or a successful submission.

An unknown `/v1` path returns `404`. A known path with the wrong HTTP method returns `405`.

## Work not claimed by this delivery

- The `aptos-vm` worker, its pinned revision, sequential execution, and `Block-STM` disabled configuration.
- The `0xBD` alias-scheme-byte check and the `ee/move/account` state namespace.
- The pinned Aptos framework, disabled staking/governance modules, and Budlum epoch-randomness binding.
- `Foreign::Aptos`, chain id `205`, sequence-number checks, expiration checks, BCS decoding, and replay protection.
- Move resources, modules, tables, events, views, simulation, gas estimation, transaction submission, and transaction-version reads.
- The native `0x1::budlum_universal` module.
- The public Aptos reverse-proxy endpoint and the Aptos CLI/TypeScript SDK nightly tests.

BLG-249 remains open. This delivery supplies the Aptos route vocabulary and two honest node reads; it does not close the Move execution or ecosystem-compatibility finding.
