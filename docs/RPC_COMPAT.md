# Compatibility RPC gateways

A compatibility gateway answers another ecosystem's client in that
ecosystem's own vocabulary. It is a translation layer over Budlum state, never
a second source of truth: an answer is a read of the chain, and a call that
would need an execution environment unavailable on this RPC surface is refused
by name instead of answered with a guess.

The gateways are listed in Section 8.11.1 of the directive:

| Gateway | Local listener (target) | Code |
|---|---|---|
| Budlum (`bud_*`) | `127.0.0.1:18545` | `src/rpc` |
| Ethereum JSON-RPC | `127.0.0.1:18547` (HTTP and WebSocket) | `src/rpc/compat/ethereum.rs`; opening RPC table in `ethereum/opening.rs` |
| Solana JSON-RPC | `127.0.0.1:18548` (HTTP and WebSocket) | existing standalone module: `src/rpc/compat/solana.rs` |
| Aptos REST | `127.0.0.1:18549` | existing standalone module: `src/rpc/compat/aptos.rs` |
| CometBFT RPC subset | `127.0.0.1:18550` | existing standalone module: `src/rpc/compat/cosmos.rs` |
| Cosmos REST (LCD) subset | `127.0.0.1:18551` | existing standalone module: `src/rpc/compat/cosmos.rs` |

The standalone modules are not, by themselves, evidence that dedicated sockets
or third-party client conformance are live. The opening delivery below is the
subset wired into the main `RpcServer`; dedicated-listener work remains open.

## The Ethereum gateway

`src/rpc/compat/ethereum/opening.rs` holds one table for the Ethereum subset of
Section 8.11.2. Each row says what the method answers. Three places must agree
before a method is served, and a test holds them together
(`eth_served_set_matches_the_declared_api`,
`eth_class_table_matches_the_gateway_table`):

1. the gateway table (what the method answers),
2. the declaration in `src/rpc/api.rs` (the wire name a client sends),
3. the row in `src/rpc/method_class.rs` (listener and effect), which every
   server start validates.

`method_class::check_served_methods` also asks the gateway
(`ethereum::opening::check_served`) about every foreign method a listener registers, so a
method that the gateway marks pending cannot be served at all.

### Served today

These are chain-level facts: every node at the same block answers them the same
way, and no execution environment is involved.

| Method | Answer |
|---|---|
| `web3_clientVersion` | `budlum-core/v<version>/chain-<id>` |
| `net_version` | the chain id in decimal |
| `net_listening` | `true` |
| `eth_chainId` | the chain id as a quantity |
| `eth_syncing` | `false`, or the sync state |
| `eth_blockNumber` | the head height as a quantity |
| `eth_gasPrice` | the base fee per BGU, in wei (Section 8.9.7) |
| `eth_maxPriorityFeePerGas` | `0x0`: this chain charges no priority fee |
| `eth_accounts` | `[]`: this node holds no unlocked key |

Two units are worth stating once. Section 8.5 makes one attoBUD equal to one
wei, so the base fee in attoBUD per BGU is the gas price in wei per gas unit.
Section 8.9 fixes 1 EVM gas to 1 BGU, so no conversion factor sits between the
two numbers.

### Refused, with the door named

Every method that needs EVM state answers `-32004` and names the Budlum method
that answers the same question. The reason is the dependency order in Section
15.7: WP-28 depends on WP-27, and the opening RPC surface does not expose a
validated end-to-end EVM execution environment. An answer built from the Budlum
account ledger would report a
balance for an address whose EVM account does not exist, and a wallet sizing a
transfer from that number would send a transaction the chain refuses. A refusal
that names the door is true; a plausible number is not.

| Refused methods | Door |
|---|---|
| `eth_getBalance` | `bud_getBalance` |
| `eth_getCode`, `eth_getStorageAt` | `bud_getAccountProof` |
| `eth_getTransactionCount` | `bud_getNonce` |
| `eth_call`, `eth_createAccessList`, `debug_traceCall` | `bud_txPrecheck` |
| `eth_estimateGas` | `bud_estimateGas` |
| `eth_feeHistory` | `bud_gasPrice` |
| `eth_sendRawTransaction` | `bud_sendRawTransaction` |
| `eth_getBlockByNumber`, `eth_getBlockTransactionCountByNumber`, `eth_getTransactionByBlockNumberAndIndex`, `eth_getBlockReceipts` | `bud_getBlockByNumber` |
| `eth_getBlockByHash`, `eth_getBlockTransactionCountByHash` | `bud_getBlockByHash` |
| `eth_getTransactionByHash` | `bud_getTransactionByHash` |
| `eth_getTransactionReceipt`, `eth_getLogs`, `debug_traceTransaction` | `bud_getTransactionReceipt` |

The refusal carries the door in the error data as well as in the message, so a
client can render it without parsing prose:

```json
{"code": -32004, "message": "eth_getBalance: EVM execution environment is not available on this RPC surface (WP-27); use bud_getBalance", "data": {"door": "bud_getBalance", "package": "WP-27"}}
```

`debug_traceTransaction` and `debug_traceCall` are operator-listener methods
(Section 8.11.2). On the public listener they answer with the operator refusal,
the same one every other operator method uses.

### Bounded filter table (delivery 2/N)

The five filter methods share one bounded, expiring, per-connection table
(`src/rpc/compat/ethereum/filters.rs`) held on the `RpcServer`. Creating a log
or block filter and uninstalling a filter are node-local administration, so
`eth_newFilter`, `eth_newBlockFilter` and `eth_uninstallFilter` are
`LocalAdmin`. Their successful creation result is a direct JSON string containing
a hex quantity id, not an object wrapping that id. The two read methods validate
ownership and freshness through the same pool but remain `Refused` until WP-27.
The limits are testnet defaults until WP-35 measures them:

| Bound | Value |
|---|---|
| filters on one node | 128 |
| filters for one connection | 8 |
| idle lifetime before a record is dropped | 300 seconds |
| serialized filter object | 16 KiB |

The owner key is only the server-assigned `jsonrpsee::ConnectionId`. A socket
address or anonymous bucket is not accepted as a substitute: a stateful call
without the server identity fails with `connection_identity_unavailable`. A
filter id belongs to one connection. Foreign reads return the same
`unknown_filter` refusal as unknown or expired ids, and a foreign or unknown
uninstall returns `false` without removing the owner's record. Malformed ids
remain `invalid_filter_id` errors.

`eth_getFilterChanges` and `eth_getFilterLogs` still answer `-32004` with the
`bud_subscribe` door after validating the filter, because the log data itself
needs WP-27's execution environment. Their class remains `Refused`: no successful
log response exists to cover or advertise. An empty change list would be a plausible but false answer, so no
change list is invented. The bound is real today: a client cannot open an
unbounded number of filters while it waits for that environment.

### `eth_getProof` answers `-32601`

This is not a wait. Section 8.10.6 makes it permanent at the opening layer: the Budlum
state root is not an MPT root, so an MPT proof over it would prove nothing. The
Budlum native proof is `bud_getAccountProof`. A client that asks anyway gets
`-32601`, and no code path can turn it into a partial answer.

### What remains for delivery 2/2

* the dedicated listener on `127.0.0.1:18547` (HTTP and WebSocket) and its
  `[compat.ethereum]` configuration,
* `eth_subscribe` / `eth_unsubscribe` (`newHeads`, `logs`,
  `newPendingTransactions`): the gateway table marks both rows pending and the
  startup check refuses to serve them,
* the block and receipt shapes, with `stateRoot` set to `execution_root` and not
  to an MPT root (Section 8.10.5),
* the tool tests of Section 8.13 in the nightly workflow: Foundry, Hardhat,
  viem and ethers, unchanged.

A client that asks for a pending method gets `-32601`: the gateway table lists
it, the startup check refuses to serve it, and no half-built subscription feed
is reachable.

## Measurement

This document claims no measurement. The four filter limits above are declared
testnet defaults, not measured values. The tool tests of Section 8.13 and the
gas calibration of Section 8.9 are WP-35 and WP-28 2/2 work; their numbers go
into this file only with a CI run number beside them.
