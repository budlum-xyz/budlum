# Compatibility RPC gateways

A compatibility gateway answers another ecosystem's client in that
ecosystem's own vocabulary. It is a translation layer over Budlum state, never
a second source of truth: an answer is a read of the chain, and a call that
would need an execution environment this node does not run is refused by name
instead of answered with a guess.

The gateways are listed in Section 8.11.1 of the directive:

| Gateway | Local listener (target) | Code |
|---|---|---|
| Budlum (`bud_*`) | `127.0.0.1:18545` | `src/rpc` |
| Ethereum JSON-RPC | `127.0.0.1:18547` (HTTP and WebSocket) | `src/rpc/compat/ethereum` |
| Solana JSON-RPC | `127.0.0.1:18548` (HTTP and WebSocket) | not started (WP-31) |
| Aptos REST | `127.0.0.1:18549` | not started (WP-32) |
| CometBFT RPC subset | `127.0.0.1:18550` | not started (WP-29) |
| Cosmos REST (LCD) subset | `127.0.0.1:18551` | not started (WP-29) |

## The Ethereum gateway

`src/rpc/compat/ethereum/mod.rs` holds one table for the Ethereum subset of
Section 8.11.2. Each row says what the method answers. Three places must agree
before a method is served, and a test holds them together
(`eth_served_set_matches_the_declared_api`,
`eth_class_table_matches_the_gateway_table`):

1. the gateway table (what the method answers),
2. the declaration in `src/rpc/api.rs` (the wire name a client sends),
3. the row in `src/rpc/method_class.rs` (listener and effect), which every
   server start validates.

`method_class::check_served_methods` also asks the gateway
(`ethereum::check_served`) about every foreign method a listener registers, so a
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
15.7: WP-28 depends on WP-27, and this node does not run the EVM execution
environment yet. An answer built from the Budlum account ledger would report a
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
| `eth_newFilter`, `eth_newBlockFilter`, `eth_getFilterChanges`, `eth_getFilterLogs`, `eth_uninstallFilter` | `bud_subscribe` |

The refusal carries the door in the error data as well as in the message, so a
client can render it without parsing prose:

```json
{"code": -32004, "message": "eth_getBalance: no EVM execution environment (WP-27); use bud_getBalance", "data": {"door": "bud_getBalance", "package": "WP-27"}}
```

`debug_traceTransaction` and `debug_traceCall` are operator-listener methods
(Section 8.11.2). On the public listener they answer with the operator refusal,
the same one every other operator method uses.

### `eth_getProof` answers `-32601`

This is not a wait. Section 8.10.6 makes it permanent at the opening layer: the Budlum
state root is not an MPT root, so an MPT proof over it would prove nothing. The
bud native proof is `bud_getAccountProof`. A client that asks anyway gets
`-32601`, and no code path can turn it into a partial answer.

### What waits for delivery 2/2

* the dedicated listener on `127.0.0.1:18547` (HTTP and WebSocket) and its
  `[compat.ethereum]` configuration,
* the bounded filter pool with a timeout and a per-peer quota, and
  `eth_subscribe` / `eth_unsubscribe` (`newHeads`, `logs`,
  `newPendingTransactions`),
* the block and receipt shapes, with `stateRoot` set to `execution_root` and not
  to an MPT root (Section 8.10.5),
* the tool tests of Section 8.13 in the nightly workflow: Foundry, Hardhat,
  viem and ethers, unchanged.

Until then a client that asks for a pending method gets `-32601`: the gateway
table lists it, the startup check refuses to serve it, and no half-built filter
table is reachable.

## Measurement

This document claims no measurement. The tool tests of Section 8.13 and the
gas calibration of Section 8.9 are WP-35 and WP-28 2/2 work; their numbers go
into this file only with a CI run number beside them.
