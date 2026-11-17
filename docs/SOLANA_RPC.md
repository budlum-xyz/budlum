# Solana JSON-RPC compatibility gateway

The gateway translates a deliberately small Solana RPC subset into Budlum
chain facts. It is not a Solana node, a second ledger, or evidence that an
Anchor/SPL client workflow is interoperable. Native Budlum state is never
presented as an invented SVM account, balance, blockhash, or transaction.

## Listeners and admission

The public node opens `127.0.0.1:18548` for HTTP and WebSocket JSON-RPC. The
bind must be loopback and distinct from the primary and Aptos listeners. The
dedicated listener contains only the Solana method table: native `bud_*` and
operator methods are not registered there.

It uses the same IP/origin/API-key/rate admission, body and connection limits,
batch limit, and optional TLS configuration as the primary public listener.
Embedded and test servers may serve the namespace on their primary listener
when no dedicated listener is configured.

## Successful HTTP methods

| Method | Answer |
|---|---|
| `getHealth` | `"ok"` while this RPC handler is running |
| `getVersion` | `{"solana-core":"budlum-core/<package-version>"}` |
| `getSlot` | processed head or finalized height, according to `commitment` |
| `getBlockHeight` | the same height rule as `getSlot` |

`commitment` accepts only `"processed"` (the default) and `"finalized"`.
`"confirmed"` and unknown configuration fields are rejected. A Budlum height
is not a 400 ms Solana slot and carries no claim about Solana votes.

## Named refusals

Unwired state mappings return `-32004`, no `result`, and error data containing
the closest native `door`. A refusal never reports that a transaction or grant
was accepted.

| Methods | Native door or service |
|---|---|
| `getGenesisHash`, `getLatestBlockhash`, `isBlockhashValid`, `getBlock` | `bud_getBlockByNumber` |
| `getEpochInfo`, `getTokenSupply`, `getMinimumBalanceForRentExemption` | `bud_getStatus` |
| `getBalance`, `getTokenAccountBalance` | `bud_getBalance` |
| `getAccountInfo`, `getMultipleAccounts`, `getProgramAccounts`, `getTokenAccountsByOwner` | `bud_getAccountProof` |
| `getFeeForMessage`, `getRecentPrioritizationFees` | `bud_gasPrice` |
| `sendTransaction` | `bud_sendRawTransaction` |
| `simulateTransaction` | `bud_txPrecheck` |
| `getSignatureStatuses` | `bud_getTransactionReceipt` |
| `getSignaturesForAddress`, `getTransaction` | `bud_getTransactionByHash` |
| `requestAirdrop` | testnet faucet; this node queues no grant |

The standalone HTTP adapter used by low-level compatibility tests has no
chain actor or subscription sink. It preserves the four reads but rejects a
commitment configuration it cannot honor and refuses every subscription.

## WebSocket subscriptions

`slotSubscribe` emits `slotNotification` objects with `parent`, `root`, and
`slot`; `slotUnsubscribe` closes the feed. Processed subscriptions follow the
local head. Finalized subscriptions follow finalized height. The initial
notification describes the current height; subsequent polls emit only new
heights.

The feed is bounded and failure-explicit:

- one poll per second;
- at most 64 catch-up notifications per tick, skipping older backlog;
- five-second send timeout before the slow subscription is dropped;
- the shared node-wide feed semaphore, with `-32005` when full;
- a backward processed head closes the feed rather than leaving a stale
  subscriber waiting indefinitely;
- disconnect or unsubscribe releases the feed permit.

`accountSubscribe`, `signatureSubscribe`, `logsSubscribe`, and
`programSubscribe` are rejected before acceptance, so they allocate neither a
subscription ID nor a feed task. Their generated unsubscribe doors remain
available to the dispatcher.

## Table locks and verification boundary

`src/rpc/compat/solana.rs`, `src/rpc/api.rs`, and
`src/rpc/method_class.rs` must contain the same 35 wire names in API order.
Tests also check listener/effect classes, existing native refusal doors,
commitment parsing, bounded catch-up, response integrity, dedicated-listener
admission, and method filtering.

These tests and this document do not certify web3.js, Anchor, Solana CLI, SPL,
SVM transaction submission, or Mainnet readiness. Compilation, lint, live
client, and interoperability evidence must be reported separately with the
commands and versions that produced it.
