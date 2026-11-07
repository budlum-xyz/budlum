# Solana JSON-RPC compatibility gateway (WP-31, 1/N and 2/N)

This document is the delivery record for the first two slices of WP-31 (the
directive's IP-31, "SVM and Solana RPC subset"). 1/N delivered the namespace,
the class table, four honest chain reads and twenty-one named refusals on the
shared Budlum listener. 2/N delivers the dedicated loopback listener and the
five WebSocket subscriptions (one served, four refused by name). It says what
the gateway answers, what it refuses and why, and what waits for the SVM
worker. It is the companion to `src/rpc/compat/solana/mod.rs`; the three
tables (the gateway table, `src/rpc/api.rs`, `src/rpc/method_class.rs`) are
held to each other by the tests in `src/rpc/compat/solana/tests.rs`.

## What this gateway is

A Solana tool (web3.js, Anchor, the Solana CLI) speaks one vocabulary. The
gateway answers that vocabulary from Budlum state. It is not a Solana node
and it holds no state of its own: every answer is a read of the same chain
`bud_*` serves.

The gateway is a translation layer, never a second source of truth. A call
that would need an SVM account, token program, message fee or transaction
is refused by name, with the Budlum door for the same fact in the message
and in the error data. A plausible number for an account that does not
exist would be worse than a refusal: a wallet sizing a transfer from it
would send a transaction the chain refuses.

## Served (four node or chain facts)

| Method | Answer |
|---|---|
| `getHealth` | `"ok"` (the node is up) |
| `getVersion` | `{"solana-core": "budlum-core/<version>", "feature-set": 0}` |
| `getSlot` | the head height, as a Solana slot |
| `getBlockHeight` | the head height |

`getSlot` and `getBlockHeight` are the same Budlum height. A Solana client
that assumes a 400 ms slot is making an assumption the gateway does not
support; the height is the chain's height, not a Solana slot. The mapping
is the same one `eth_blockNumber` uses for the Ethereum gateway.

## Refused, with the door named (twenty-one methods)

Each answers `-32004` and names the Budlum method that answers the same
question, in the message and in the error data
(`{"door": "...", "package": "WP-31"}`).

| Method | Door |
|---|---|
| `getGenesisHash` | `bud_getBlockByNumber` |
| `getEpochInfo` | `bud_getStatus` |
| `getLatestBlockhash` | `bud_getBlockByNumber` |
| `isBlockhashValid` | `bud_getBlockByNumber` |
| `getBalance` | `bud_getBalance` |
| `getAccountInfo` | `bud_getAccountProof` |
| `getMultipleAccounts` | `bud_getAccountProof` |
| `getProgramAccounts` | `bud_getAccountProof` |
| `getTokenAccountsByOwner` | `bud_getAccountProof` |
| `getTokenAccountBalance` | `bud_getBalance` |
| `getTokenSupply` | `bud_getStatus` |
| `getMinimumBalanceForRentExemption` | `bud_getStatus` |
| `getFeeForMessage` | `bud_gasPrice` |
| `getRecentPrioritizationFees` | `bud_gasPrice` |
| `sendTransaction` | `bud_sendRawTransaction` |
| `simulateTransaction` | `bud_txPrecheck` |
| `getSignatureStatuses` | `bud_getTransactionReceipt` |
| `getSignaturesForAddress` | `bud_getTransactionByHash` |
| `getTransaction` | `bud_getTransactionByHash` |
| `getBlock` | `bud_getBlockByNumber` |
| `requestAirdrop` | the testnet faucet (WP-41), not an SVM program |

`requestAirdrop` is a special case: the faucet is a separate service, not a
Budlum RPC method, so the refusal names the faucet and the door
`bud_sendRawTransaction`. The node does not mint.

Four of the refusals are chain facts rather than SVM facts: `getGenesisHash`,
`getEpochInfo`, `getLatestBlockhash` and `isBlockhashValid`. They are refused
with "not exposed on this node yet" and the closest Budlum read, not with
"no SVM execution environment", because the SVM is not the reason they are
unavailable. The reason is that the Solana shape of the fact (a base58
blockhash, an epoch/slot pair) is not exposed yet.

## Subscriptions (one served, four refused by name)

`slotSubscribe` is served. The other four subscriptions are refused by name
with `-32004` before a subscription id or feed slot is created, so a client
that asks for `accountSubscribe` without the SVM worker does not hold a feed
slot. The refusal names the Budlum door (`bud_getAccountProof` or
`bud_getTransactionReceipt`) in the message and in the error data.

* `slotSubscribe` -> `slotNotification` (`slotUnsubscribe` to close) - reports
  Budlum chain progress in the Solana slot shape (`{"parent","root","slot"}`).
  `slot` is the Budlum head height, `parent` is `slot-1` (genesis clamped to
  `0`), `root` is the last finalized Budlum height, never above `slot`. The
  mapping is the same one `eth_blockNumber` uses: the height is the chain's
  height, not a 400 ms Solana slot. The gateway does not invent SVM votes;
  `"confirmed"` is not accepted, only `"processed"` (head) and `"finalized"`.
  A slow subscriber never makes the node replay unbounded history: at most
  64 slots are burst per tick, older heights are skipped, and a 5 s send
  timeout drops the subscription.
* `accountSubscribe`, `signatureSubscribe`, `logsSubscribe`,
  `programSubscribe` - refused by name (`-32004`) with the closest Budlum
  door. They wait for the SVM worker.

`slotSubscribe` shares the node-wide feed-slot budget (`MAX_SUBSCRIPTION_FEEDS`)
with the native Budlum feed. When the pool is full the sink is refused with
`-32005`. This is the same pool the 2/N delivery introduced for the Aptos
listener; the dedicated Solana listener reuses the same admission, body and
connection limits as the primary public listener.

```json
// request
{"jsonrpc":"2.0","id":1,"method":"slotSubscribe","params":[{"commitment":"finalized"}]}
// first notification shape
{"jsonrpc":"2.0","method":"slotNotification","params":{"subscription":"<id>","result":{"parent":6,"root":5,"slot":7}}}
```

Four of the refused methods are also chain facts rather than SVM facts:
`getGenesisHash`, `getEpochInfo`, `getLatestBlockhash` and `isBlockhashValid`.
They are refused with "not exposed on this node yet" and the closest Budlum
read, not with "no SVM execution environment", because the SVM is not the
reason they are unavailable.

## Listener

The Solana gateway is served on two listeners:

* the shared Budlum JSON-RPC listener - all `bud_*` methods plus the Solana
  namespace (so a node without `--solana-listener` still answers the same
  vocabulary);
* the dedicated loopback listener on `127.0.0.1:18548` (HTTP and WebSocket)
  - only the Solana method table, so a Solana client cannot reach Budlum or
  operator methods through the compatibility port. It reuses the same
  `RpcSecurityLayer` (IP, origin, rate, authentication), body/connection
  limits and optional TLS as the primary public listener. The public node in
  `src/main.rs` opens it; tests and embedded servers keep the opt-in default
  of closed.

## What waits for the SVM worker

* The SVM worker (`budlum-ee-svm`, `solana-svm` and `solana-sbpf`, Agave
  version pinned, JIT off), the `Foreign::Solana` envelope and the
  `ue/svm/account` namespace.
* The built-in programs (System, SPL Token, Token-2022, Associated Token
  Account, Memo, BPF loader) and the Universal Call program.
* The account, signature, log and program subscriptions (they currently
  refuse by name).
* The nightly tool tests (web3.js, Anchor, Solana CLI) and the
  `spl_token_suite_passes`, `anchor_deploy_and_test_run_unchanged`,
  `solana_web3js_transfer_runs_unchanged`, `uel_foreign_tx_replay_refused`
  and `svm_jit_is_disabled` tests.

The dependency is the point: WP-31 depends on WP-26 (the Execution
Coordinator), and this node does not run the SVM execution environment
yet. The namespace, refusals, subscription doors and dedicated listener
are delivered now, exactly as the Ethereum gateway's 1/2 delivery did; the
worker is 3/N.

## The three tables agree

A method is served only when three places say the same thing:

1. `src/rpc/compat/solana/mod.rs` (the gateway table: listener and answer),
2. `src/rpc/api.rs` (the wire name the client sends),
3. `src/rpc/method_class.rs` (the listener and effect, checked at every
   server start).

The tests compare all three, so a method cannot be half-added: a row
without a declaration, a declaration without a row, or a pending row that
is served all fail.

## Verification status, stated plainly

The work is committed and pushed. No Rust toolchain exists in this
environment, so `cargo`/`rustfmt`/clippy were **not** run locally; the
syntax was parsed with a Rust grammar and the three tables were compared
with a script. CI is the verifier. Nothing in this document claims a green
run, a CI run number, or a completed package. The closing condition of
WP-31 (an Anchor program deployed and tested) is not claimed.

## Wire formats, field tags, RPC names

None. No protocol, codec, genesis, enum or transaction type changes. The
new wire names are the read-only Solana namespace above; no existing
Budlum method changes.
