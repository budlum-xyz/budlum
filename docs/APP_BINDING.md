# Remote App Binding (`app_binding`): integrator guide

Budlum is the consensus of consensuses. Every network keeps its own rules.
Budlum unifies their finality into a single proof.

Remote app binding (`app_binding`) lets a person use an application that lives
on another network from inside Budlum and pay for it in BUD. The application
does not move. Budlum holds a binding row for it, and every write is a signed
in-block settlement transaction.

Status: **closed on testnet** (`45261`, proven by `app_binding_is_closed_on_testnet`)
pending Universal Object Layer activation; enabled on devnet (`45262`) for
end-to-end verification. Values marked TESTNET-DEFAULT are genesis parameters.

## 1. The application binding row

| Field | Meaning |
|---|---|
| `app_id` | Deterministic 32-byte identifier derived from `(domain_key, len, origin_app)` |
| `domain_key` | The origin domain, a registered consensus domain id |
| `origin_app` | The application's identifier on its own network (an EVM address is 20 bytes), at most 256 bytes |
| `mirror_account` | Deterministic keyless mirror address derived from `app_id` |
| `owner` | Zero until a verified claim proves one |
| `manifest_hash` | The B.U.D. content id of the application's metadata |
| `status` | `Active`, `Paused`, `Retired` (`Retired` is terminal) |

Value leaves the mirror account only by a rule of this module. There is no
administrator key, no pause hook outside the owner's own row, and no
allowlist.

## 2. Levels

| Level | The application changes | What works |
|---|---|---|
| 0 | nothing | register, pay; the app checks payments with a Budlum light client |
| 1 | runs a verifier | payment proof RPC + payment inclusion verification |
| 2 | nothing | intents: a bonded solver makes the call on the origin chain, paid in BUD |
| 3 | after | a remote account on the origin chain, controlled by Budlum proofs |

## 3. Register

Registration is permissionless on networks where `app_binding` is enabled.
Registering the same application again with the same manifest changes nothing
and costs nothing; another manifest is refused. Registering names no owner:
whoever registers gains nothing over the application. The registration fee
(TESTNET-DEFAULT one base unit) is destroyed.

## 4. Claim the application

The application itself names its Budlum payout. On its own network it emits
an event that the domain adapter turns into a cross-domain message:

| Message field | Value |
|---|---|
| `sender` (the emitter) | `origin_emitter(origin_app)`: the identifier right-aligned in a 32-byte word |
| `recipient` | the payout address |
| `correlation_id` | the `app_id` |
| `payload_hash` | domain-separated digest over `(app_id, payout)` |
| `source_domain` | the `domain_key` |

Anyone may submit the anchored result: the result's leaf must reach the
external root consensus has anchored for that domain. The payout becomes the
owner, and everything that accrued in the mirror account moves to it. A later
claim event rotates the owner. Each claim event works once.

An externally owned account (no contract) cannot emit an event. It claims
with its own key instead via an EIP-191 personal-sign signature (65 bytes,
`r || s || v`, low `s`) over the domain-separated digest of
`(chain_id, app_id, payout, valid_until_block)`. The recovered address must be
the application's 20-byte `origin_app`. The signature is refused after
`valid_until_block` (at most 100,000 blocks ahead), so an old signature cannot
undo a later rotation once its window is over, and each signature works once.
Recovery is in-tree on the `k256` curve arithmetic
(`src/crypto/secp256k1_recover.rs`); no dependency was added.

## 5. Pay (levels 0 and 1)

The amount goes to the owner, or into the mirror account while nobody has
claimed the application. The payment is recorded in a window of the last
10,000 payments; the window's Merkle root is part of the settlement root.

An application checks a payment itself:

1. Query the payment proof RPC for the payment, its Merkle path, the registry
   opening, the checkpoint global header and the state root opening of the
   checkpoint block.
2. Verify: finalized checkpoint -> state root -> global header -> app binding
   root -> payment window -> payment, against a `VerifiedCheckpoint` the
   application's light client reached from its trust anchor.

A payment is provable once a checkpoint passes after it (every 5 blocks on
the testnet), and while it stays in the window.

## 6. Intents (level 2)

A person who holds no coin of the origin network asks for a call there:

- `max_payment` is escrowed at once. It must cover the solver fee cap and the
  service price.
- The deadline defaults to 600 blocks (TESTNET-DEFAULT).
- The domain must have an executor: its operator names it with `SetExecutor`.
- Only an active RELAYER bids, with `fee <= solver_fee_cap` and
  `cost + fee + service_price <= max_payment`.
- The owner freezes the cheapest offer (ties go to the earliest bid). The
  award must leave at least 8 blocks before expiry, and no new bid is accepted
  after it. A solver should wait for the award to be finalized before acting.
- The awarded solver makes the call through the domain's executor contract and
  submits its anchored fulfilment event. The executor takes no solver argument:
  the origin-chain account binds its Budlum solver address once with
  `registerSolverKey`, the binding is immutable, and every fulfilment it emits
  names that address. An unbound account cannot fulfil, and one account cannot
  name another solver's key.
- On a proven fulfilment the solver receives `cost + fee`, the application
  receives `service_price`, and the rest returns to the person.
- After the deadline anyone may trigger a refund: the escrow returns, and only
  the awarded solver that did not deliver may be slashed on its RELAYER bond
  at the liveness rate. Unawarded bidders owe no delivery and are not slashed.

## 7. Fees

Remote app binding cannot change the protocol fee. A payment, an intent, or a
contract call addressed to the application's mirror account carries the
application share of the protocol fee: `app_fee_share_ppm` (TESTNET-DEFAULT
400,000, 40 percent) of the fee after the metabolic burn, to the owner (or
the mirror while unclaimed). The rest follows the normal fee path. A share
never returns to the transaction's own sender.

## 8. Reading

`bud_getSettlementInfo` exposes the app-binding root and row counts alongside
read-only application and payment-proof queries. The Ethereum-side contracts
(`BudlumPaymentReceiver`, `BudlumRemoteAccountFactory`) are verified in
`contracts/`.
