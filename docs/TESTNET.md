# Budlum testnet

Budlum is the consensus of consensuses. Every network keeps its own rules.
Budlum unifies their finality into a single proof.

The testnet is the mainnet rehearsal: the same code path, the same supply
rules and the same validator ceremony. Only the profile, the genesis and the
parameter values differ. Values marked TESTNET-DEFAULT are testnet
parameters.

`<TESTNET_DOMAIN>` stands for the testnet's DNS name. It is filled in when
the operators publish it; until then no public endpoint exists, and every
address below is the one a node, faucet or indexer listens on locally.

## Endpoint map

| Service | Public address | Local listener | Status |
|---|---|---|---|
| Chain id | `45261` | - | fixed |
| Network magic | `BDLT` | - | fixed |
| P2P | `/dns4/seed1.<TESTNET_DOMAIN>/tcp/5001/p2p/<peer id>` | `0.0.0.0:5001` | waits for operators |
| JSON-RPC (HTTPS) | `https://rpc.<TESTNET_DOMAIN>` | `127.0.0.1:28545` | waits for the domain |
| WebSocket subscriptions | `wss://rpc.<TESTNET_DOMAIN>` | `127.0.0.1:28545` | `bud_subscribe("newHeads" \| "finalizedHeads" \| "logs", address?)` |
| Faucet | `https://faucet.<TESTNET_DOMAIN>/request` | `127.0.0.1:18600` | binary ready (`budlum-faucet`) |
| Explorer API | `https://explorer-api.<TESTNET_DOMAIN>` | `127.0.0.1:18700` | `budlum-indexer`; contract `docs/explorer-api.openapi.yaml` |
| Metrics | not public | `127.0.0.1:29091` | ready |
| Sepolia contracts | see below | - | not deployed |

TLS is terminated by Caddy (`ops/Caddyfile.testnet`); the node, the faucet
and the indexer speak plain HTTP on loopback. The operator RPC listener
(`127.0.0.1:18546`) is never exposed.

The public RPC needs no API key (decision A-06). It serves reads,
`bud_sendRawTransaction`, `bud_estimateGas`, `bud_txPrecheck` and the
`*Prepare*` methods that build unsigned transactions. Nothing on it can write
consensus state outside a signed transaction (`src/rpc/method_class.rs`).
Each client IP is rate limited (600 requests per minute).

## Use the testnet

1. **Open a wallet.** `bud wallet create --key-file ./secrets/wallet.json`
   prints 24 words once and seals the key with your password
   (`--password-file` or `BUD_WALLET_PASSWORD`). The key is ML-DSA-87 (V5);
   12-word phrases are refused (A-07). `bud wallet import` restores from the
   24 words (read from standard input); `bud wallet address` prints the
   address.
2. **Get BUD.** Ask the faucet for 100 BUD (TESTNET-DEFAULT; one
   request per address and per IP every 24 hours; 100,000 BUD per day in
   total):

   ```
   curl -X POST https://faucet.<TESTNET_DOMAIN>/request -d '{"address":"0x<your address>"}'
   ```

   The faucet sends an ordinary signed transfer; it appears in a block like
   any other transaction.
3. **Send a transaction.** `bud` speaks plain HTTP, so point it at a node
   you run (or reach over an SSH tunnel):

   ```
   bud --rpc-url http://127.0.0.1:28545 tx send \
     --key-file ./secrets/wallet.json --to 0x<recipient> --amount 1000000 --fee 1000
   ```

   Amounts are in base units: 1 BUD = 1,000,000 units. `bud stake`,
   `bud unstake`, `bud bns register`, `bud bns renew` and `bud bns transfer`
   sign the same way.
4. **See it.** `GET https://explorer-api.<TESTNET_DOMAIN>/v1/txs/<hash>`
   once its block is finalized, or `/v1/addresses/<address>/txs` for the
   history. On the RPC: `bud_getTransactionByHash`, `bud query balance`.
5. **Become a validator.** Follow `docs/VALIDATOR_GUIDE.md`: `bud validator
   init`, then `bud validator join` with at least 1,000 BUD of stake.
6. **Delegate.** `bud delegate --validator 0x<validator> --amount-bud <n>`
   delegates from the same wallet; `bud undelegate` starts the exit and
   `bud withdraw-delegation` pays it out after the unbonding period
. `bud_validatorProfile` and `bud_validatorList` show each
   validator's commission, stake and record (`docs/DELEGATION.md`).

## Parameters

| Parameter | Value |
|---|---|
| Slot | 3 s |
| Epoch | 50 slots |
| Finality checkpoint | every 5 blocks, two-thirds stake quorum |
| Minimum validator stake | 1,000 BUD |
| Reward pool | 10M BUD over 100,000 epochs, paid by stake every epoch |
| Mempool | 50,000 entries, 200 per sender, minimum fee 1 |
| Supply | 100M BUD fixed; the testnet genesis carries the mainnet distribution |

## Run a node

```
budlum-core --config config/testnet.toml
```

Add `--validator-key-file` for a validator (see the validator guide). The
operations runbook is `docs/OPERATIONS.md`.

Two local rehearsals use the same image:

- `ops/testnet-local.yml`: the testnet profile end to end on one machine:
  ceremony, four validators, an RPC node (`127.0.0.1:28545`), the faucet
  (`127.0.0.1:28600`), the explorer API (`127.0.0.1:28700`), Prometheus and
  Grafana (`127.0.0.1:23000`).
  `docker compose -f ops/testnet-local.yml up -d --build`
- `ops/docker-compose.yml`: the four-validator devnet the CI smoke drives
  (`cargo run --manifest-path xtask/tools/Cargo.toml -- devnet-multinode-smoke`).

## Sepolia contracts

None are deployed yet. `contracts deploy` writes the addresses to
`config/testnet-ethereum.toml`; they are listed here after the deployment
ceremony. See `contracts/README.md`.

| Contract | Address |
|---|---|
| `BudlumFinalityVerifier` | not deployed |
| `GraftExecutor` | not deployed |
| `BudlumRemoteAccountFactory` | not deployed |
| `BudlumRegistrar` (Mikoriza AVS) | not deployed |
| `BudlumSlasher` (deployed by the registrar) | not deployed |

## Validator resources

Measured, never estimated. Run against a live validator:

```
cargo run --manifest-path xtask/tools/Cargo.toml -- resource-sample --pid <node pid> --data-dir <data dir> --seconds 600
```

| Profile | CPU | Peak RSS | Disk growth | Network |
|---|---|---|---|---|
| Server validator | not yet measured | not yet measured | not yet measured | not yet measured |
| Personal validator (mini PC, phone) | not yet measured | not yet measured | not yet measured | not yet measured |
