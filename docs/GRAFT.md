# Graft: integrator guide (testnet)

Budlum is the consensus of consensuses. Every network keeps its own rules.
Budlum unifies their finality into a single proof.

Graft lets a person use an application that lives on another network from
inside Budlum and pay for it in BUD. The application does not move. Budlum
holds a Graft row for it, like a bud grafted onto another rootstock. Code
name `graft` (`src/settlement/graft.rs`); every write is a signed
`SettlementTx::Graft` transaction applied in a block.

Values marked TESTNET-DEFAULT are genesis parameters.

## 1. The Graft row

| Field | Meaning |
|---|---|
| `graft_id` | `H("BDLM_GRAFT_APP_V1", domain_key, len, origin_app)`, deterministic |
| `domain_key` | the origin domain, a registered consensus domain id |
| `origin_app` | the application's identifier on its own network (an EVM address is 20 bytes), at most 256 bytes |
| `mirror_account` | `H("BDLM_GRAFT_MIRROR_V1", graft_id)`: an address no key controls |
| `owner` | zero until a claim proves one |
| `manifest_hash` | the B.U.D. content id of the application's metadata |
| `status` | `Active`, `Paused`, `Retired` (retired is final) |

Value leaves the mirror account only by a rule of this module. There is no
administrator key, no pause hook outside the owner's own row, and no
allowlist.

## 2. Levels

| Level | The application changes | What works |
|---|---|---|
| 0 | nothing | register, pay; the app checks payments with a Budlum light client |
| 1 | runs a verifier | `bud_graftPaymentProof` + `verify_graft_payment` |
| 2 | nothing | intents: a bonded solver makes the call on the origin chain, paid in BUD |
| 3 | after | a remote account on the origin chain, controlled by Budlum proofs |

## 3. Register

```
bud graft register --key-file wallet.key --domain <id> \
  --origin-app <hex> --manifest <hex>
```

Permissionless. Registering the same application again with the same
manifest changes nothing and costs nothing; another manifest is refused.
Registering names no owner: whoever registers gains nothing over the
application. The registration fee (`graft_registration_fee`, TESTNET-DEFAULT
one base unit) is destroyed.

## 4. Claim the application

The application itself names its Budlum payout. On its own network it emits
an event that the domain adapter turns into a cross-domain message:

| Message field | Value |
|---|---|
| `kind` | `Custom("budlum/graft/claim/v1")` |
| `sender` (the emitter) | `origin_emitter(origin_app)`: the identifier right-aligned in a 32-byte word |
| `recipient` | the payout address |
| `correlation_id` | the `graft_id` |
| `payload_hash` | `H("BDLM_GRAFT_CLAIM_EVENT_V1", graft_id, payout)` |
| `source_domain` | the `domain_key` |

Anyone may submit the anchored result (`bud graft claim --evidence
result.json`): the result's leaf must reach the external root consensus has
anchored for that domain. The payout becomes the owner, and everything that
accrued in the mirror account moves to it. A later claim event rotates the
owner. Each claim event works once.

An externally owned account (no contract) cannot emit an event. It claims
with its own key instead (`GraftTx::ClaimBySignature`, `bud graft claim-signed`):
an EIP-191 personal-sign signature (65 bytes, `r || s || v`, low `s`) over

```
eoa_claim_hash = H("BDLM_GRAFT_EOA_CLAIM_V1", chain_id, graft_id, payout, valid_until_block)
```

The recovered address must be the application's 20-byte `origin_app`. The
signature is refused after `valid_until_block` (at most 100,000 blocks ahead),
so an old signature cannot undo a later rotation once its window is over, and
each signature works once. Recovery is in-tree on the `k256` curve arithmetic
(`src/crypto/secp256k1_recover.rs`); no dependency was added.

A contract application inherits `BudlumGraftClaimer`
(`contracts/graft/GraftExecutor.sol`) and calls `_claimBudlumPayout`.

## 5. Pay (levels 0 and 1)

```
bud graft pay --key-file wallet.key --graft-id <hex> --amount <units> \
  --origin-recipient <hex> [--memo-hash <hex>]
```

The amount goes to the owner, or into the mirror account while nobody has
claimed the application. The payment is recorded in a window of the last
10,000 payments; the window's Merkle root is part of the Graft root.

An application checks a payment itself:

1. `bud_graftPaymentProof(payment_id)` returns the payment, its Merkle path,
   the registry opening, the checkpoint global header and the state root
   opening of the checkpoint block.
2. `verify_graft_payment(proof, checkpoint)` checks: finalized checkpoint ->
   state root -> global header -> `graft_root` -> payment window -> payment.
   `checkpoint` is a `VerifiedCheckpoint` the application's light client
   reached from its trust anchor.

A payment is provable once a checkpoint passes after it (every 5 blocks on
the testnet), and while it stays in the window.

## 6. Intents (level 2)

A person who holds no coin of the origin network asks for a call there:

```
bud graft intent --key-file wallet.key --graft-id <hex> --call-hash <hex> \
  --max-payment <units> --solver-fee-cap <units> --service-price <units> \
  --beneficiary <hex> [--value <n>] [--deadline-block <n>]
```

- `max_payment` is escrowed at once. It must cover the solver fee cap and the
  service price.
- The deadline defaults to `graft_default_intent_deadline_blocks`
  (TESTNET-DEFAULT 600 blocks).
- The domain must have an executor: its operator names it with `SetExecutor`.
- Only an active RELAYER bids: `bud graft bid --intent-id <hex> --cost <units>
  --fee <units>`, with `fee <= solver_fee_cap` and
  `cost + fee + service_price <= max_payment`.
- The solver makes the call through the domain's executor contract and
  submits its fulfilment event (`bud graft fulfill --evidence result.json`):

| Message field | Value |
|---|---|
| `kind` | `Custom("budlum/graft/fulfilled/v1")` |
| `sender` | `origin_emitter(executor)` |
| `correlation_id` | the intent id |
| `payload_hash` | `H("BDLM_GRAFT_FULFILLED_EVENT_V1", intent_id, len, origin_app, call_hash, value, len, beneficiary, solver)` |

- On a proven fulfilment the solver receives `cost + fee`, the application
  receives `service_price`, and the rest returns to the person.
- After the deadline anyone may `bud graft refund --intent-id <hex>`: the
  escrow returns, and every bidder that did not deliver is slashed on its
  RELAYER bond at the liveness rate.

The solver may fill the call on the origin chain before Budlum finality and
carries that risk itself; settlement happens only on the anchored proof.

## 7. Fees

Graft cannot change the protocol fee. A Graft payment, a Graft intent, or a
contract call addressed to the application's mirror account carries the
application share of the protocol fee: `app_fee_share_ppm` (TESTNET-DEFAULT
400,000, 40 percent) of the fee after the metabolic burn, to the owner (or
the mirror while unclaimed). The rest follows the normal fee path. A share
never returns to the transaction's own sender. The unclaimed share has no
time limit; a limit would be an economic decision.

## 8. Reading

| RPC | Returns |
|---|---|
| `bud_getGraftApplication(graft_id)` | the Graft row |
| `bud_graftPaymentProof(payment_id)` | the payment proof of section 5 |
| `bud_getSettlementInfo` | the Graft root and row counts |

The Ethereum-side contracts (`GraftExecutor`, `BudlumPaymentReceiver`,
`BudlumRemoteAccountFactory`) are work; the testnet
Sepolia addresses will be listed in `docs/TESTNET.md`.
