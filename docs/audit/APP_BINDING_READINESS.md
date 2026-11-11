# Remote app binding (AppBinding): readiness and user path

Inspected source at `62b7beeca453dda88693b928c69f7e5c8d585490`.
**Do not advertise another network's application as working through the
Budlum testnet.** The directive Section 1.5 (`THE_BUDLUM_DIREKTIF.md:164-166`)
closes the Universal Object Layer at launch and closes remote app binding
until a separate decision after WP-49. Section 19, KR-29 repeats that launch
boundary. `docs/APP_BINDING.md:6-13` also says closed on chain `45261` and
devnet-only for integration. A fixture or a configured chain flag cannot
replace a working origin-chain user journey.

## Activation gate: wired, not runtime-verified

`src/core/chain_config.rs:229-236,340-341` defines
`app_binding_enabled_for_chain_id`, true only on devnet. The earlier audit
found that the flag was **not called** from the direct AppBinding transaction door.
That contradiction was addressed in commit `eb79e144`: the pre-match guard in
`src/settlement/app_binding.rs:735` now refuses chain `45261` before moving a
balance or registering an application. The outer `SettlementTx::AppBinding` arm
uses that same door. `src/tests/domains_bridge_settlement.rs:335` tests both
entry points, and the new `launch-evidence` gate checks for a production
preflight rather than accepting the profile flag alone. **The core Rust test
has not executed** because its build requires unavailable `protoc`; the guard
and named test are source evidence, not a successful testnet rehearsal.

## Devnet implementation by level, not an end-to-end assertion

| Level | Production code present | Missing evidence before a "works" claim |
|---|---|---|
| **0: register and pay BUD** | `src/bin/bud.rs:389-428,1640-1684,1773-1778` assembles signed `AppBindingTx::Register`/`Pay`; `src/settlement/domains.rs:1374-1376` forwards in-block; `src/settlement/app_binding.rs:700-738,819-857` handles registry and payment/mirror accounting. | A funded, registered origin-domain/app transaction finalized on devnet; an origin app that checks the resulting payment against its own trust anchor. The application is **not** invoked merely by paying its Budlum mirror. |
| **1: payment proof** | `src/rpc/api.rs:116-136` declares application and payment-proof reads; `src/chain/blockchain.rs:1806` serves the payment proof; `src/settlement/app_binding.rs:361-379` defines verification. `src/settlement/app_binding.rs:1` explicitly says this verifier has no in-tree caller. | A real finalized checkpoint through state root -> global header -> AppBinding root -> payment window -> payment, validated by an independently anchored origin app or contract. `contracts/app_binding/BudlumPaymentReceiver.sol` exists but code presence is not deployment/verifier evidence. |
| **2: cross-network call by bonded solver** | `src/bin/bud.rs:429-480,510-518,1685-1729,1761-1769` forms intent/bid/award/fulfilment; `src/settlement/app_binding.rs:876-949,990-1131` checks executor registration, bonded bid and anchored fulfilment; `contracts/app_binding/AppBindingExecutor.sol` emits events. | Origin-domain executor deployed and recognized, real solver with bond, awarded intent, origin-chain call, anchored outbound event and paid/refunded settlement, including failure and replay tests. No origin-network execution receipt or live contract address is recorded here. |
| **3: remote origin account** | `contracts/app_binding/BudlumRemoteAccountFactory.sol` and the payment-receiver contract provide a proposed CREATE2/pay-to-authorize surface (`contracts/README.md:18-24`). | Deployed factory and verifier, externally verified finality and authorization, actual contract call and replay/double-spend refusal. `config/testnet-ethereum.toml:38-40` leaves AppBinding executor/factory addresses empty. No evidence of a user-operated remote account on the testnet. |

These entries identify **source call sites**, not passing tests or live
operation. The CLI `bud app_binding id` computes an identifier and mirror address
locally; it does not register the app or interact with the origin chain.
Even a devnet `register` or `pay` receipt alone does not demonstrate that a
foreign app performed the requested action.

## Conditions for future public testnet instructions

1. Keep `45261` closed until WP-49's object-layer prerequisite and a
   **separate app-binding activation decision** are recorded; do not bypass
   the chain-ID gate for a demo. Run `app_binding_is_closed_on_testnet` at
   both direct and signed/in-block entry points on the shipped SHA; the
   source-level guard alone is not a passing test.
2. Complete origin-domain verifier/executor configuration, deploy contracts,
   pin addresses and finality trust roots, and pass both positive and negative
   cross-chain tests. Record real genesis, network URL, activation height,
   verifier contracts, wallet format, and exact chain ID. A synthetically
   passing `AppBindingTx` unit test is insufficient.
3. Run a fresh external-chain application journey and publish artifacts:
   origin-app identity and domain registration, funded wallet, Budlum
   transaction hashes and finalized payment proof, origin-chain receipt/event,
   linked settlement result, reviewer and CI/rehearsal run IDs. Only then
   publish runnable URLs to users.

**Conditional command shape after legitimate activation only.** These
commands match `src/bin/bud.rs:389-518,1640-1778`; they are not runnable
on today's public testnet. The operator must supply a live authenticated
`RPC_URL`, activated `CHAIN_ID`, a funded V5 `KEY_FILE`, and genuine domain,
origin-app and manifest identifiers. `--signing-chain-id` is required for
signing; the remote network's chain ID is **not** the Budlum signing chain ID.

```bash
bud app_binding id --domain "$DOMAIN" --origin-app "$ORIGIN_APP_HEX"
bud --rpc-url "$RPC_URL" --signing-chain-id "$CHAIN_ID" app_binding register \
  --key-file "$KEY_FILE" --domain "$DOMAIN" --origin-app "$ORIGIN_APP_HEX" \
  --manifest "$MANIFEST_HEX"
bud --rpc-url "$RPC_URL" --signing-chain-id "$CHAIN_ID" app_binding pay \
  --key-file "$KEY_FILE" --app_binding-id "$app_binding_ID_HEX" --amount "$AMOUNT_ATOMS" \
  --origin-recipient "$RECIPIENT_HEX"
```

For Level 1, query `bud_app_bindingPaymentProof` with a payment ID
(`src/rpc/api.rs:130-138`) and verify the returned proof at the origin app
against its own finalized checkpoint anchor. This requires a live receipt,
not a source-only method name.
For Level 2, `bud app_binding intent`, `bud app_binding bid`, `bud app_binding award`, and
`bud app_binding fulfill --evidence <anchored-result.json>` require bonded actors,
origin-chain execution and a valid anchored event. Do not treat `bud app_binding
pay` as an immediate call into an application. The Level 3 factory has no
published testnet address, so there is no Level 3 user command yet.
