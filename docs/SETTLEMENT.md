# Settlement and AppBinding

Settlement writes are block-only. A signed `TransactionType::Settlement`
transaction is the only production write path for the settlement registries;
RPC methods expose reads and point writers at `bud_sendRawTransaction`.

## Doors

`SettlementTx` carries every settlement write:

| Variant | Writes |
|---|---|
| `RegisterDomain`, `SubmitCommitment`, `RegisterSovereignTemplate`, `SetZkProgram`, `SubmitZkProof` | consensus domains, their commitments and anchors |
| `ProofMarket` | proof-market escrow, tasks, receipts, payments and refunds |
| `RelayerIntent` | outbound relayer intents, solver bids, settlement and expiry |
| `AppBinding` | AppBinding applications, payments, ownership claims and solver intents |

Proof-market escrow is never a one-way deposit. `FundEscrow` moves unassigned
BUD into the market and `WithdrawEscrow` returns any amount not reserved by a
live task to the same signed sender. Retired task IDs are retained only through
the epoch in which they were used: every admitted ID commits to the chain's
current `created_epoch`, so an older ID cannot be re-derived after the boundary
and lifetime market use cannot fill a permanent global denylist.

## External evidence

A relayer intent, an AppBinding claim and an AppBinding fulfilment prove something that
happened on another domain the same way the bridge relay does: a
`RelayerExternalResult` whose cross-domain message is committed by its
result leaf, and a Merkle path from that leaf to the external root consensus
has anchored for the domain (`verify_anchored_result`). The door then checks
that the message says the specific thing it needs: the intent it executed,
the payout an application names, or the call a fulfilment made. A real but
unrelated anchored event settles nothing.

## Remote App Binding (`app_binding`)

In-block settlement transactions implement remote app binding (`docs/APP_BINDING.md`
is the integrator guide). The door is active only on devnet `45262`; public
testnet `45261` and mainnet `45260` fail closed. In short:

- `Register` is permissionless and idempotent and names no owner.
- `Claim` sets the owner from an anchored claim event of the application.
- `Pay` pays the owner, or the keyless mirror account while unclaimed.
- `OpenIntent`, `Bid`, `Award`, `Fulfill`, `Refund` buy a call on the origin chain with
  escrowed BUD from a bonded solver.

The registry, the payment window, open intents, domain executors and the
claim replay set are part of the settlement root and of the global header
(`app_binding_root`, V7). `bud_getAppBindingApplication`, `bud_appBindingPaymentProof` and the
remote-app-binding fields of `bud_getSettlementInfo` are read-only; these
legacy wire identifiers remain unchanged for compatibility.

### Relayer intent awards

Before executing externally, the intent owner submits a signed
`RelayerIntentTx::Award { intent_id }`. It locks the lowest eligible live bid
(ties: larger bond, then address). A later underbid cannot displace that award.
The bid and intent must each have at least eight blocks left; operators should
choose longer windows when the target chain needs more time for finality. After
the selected bid expires, the owner can award another eligible bid. Solvers
should wait for the award to finalize before acting. The intent-executed
receipt must name the awarded Budlum relayer in `message.recipient`; a public
receipt for another solver cannot be reused. On intent expiry only an awarded
bid still live through the deadline can be slashed; unawarded or earlier-lapsed
bids are not liveness offences. This is a consensus/protocol upgrade, so use a
fresh testnet genesis or coordinate activation with all validators.
