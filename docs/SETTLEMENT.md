# Settlement and Graft

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
| `Graft` | Graft applications, payments, ownership claims and solver intents |

## External evidence

A relayer intent, a Graft claim and a Graft fulfilment prove something that
happened on another domain the same way the bridge relay does: a
`RelayerExternalResult` whose cross-domain message is committed by its
result leaf, and a Merkle path from that leaf to the external root consensus
has anchored for the domain (`verify_anchored_result`). The door then checks
that the message says the specific thing it needs: the intent it executed,
the payout an application names, or the call a fulfilment made. A real but
unrelated anchored event settles nothing.

## Graft

`SettlementTx::Graft` is the in-block side of Graft; `docs/GRAFT.md` is the
integrator guide. In short:

- `Register` is permissionless and idempotent and names no owner.
- `Claim` sets the owner from an anchored claim event of the application.
- `Pay` pays the owner, or the keyless mirror account while unclaimed.
- `OpenIntent`, `Bid`, `Fulfill`, `Refund` buy a call on the origin chain with
  escrowed BUD from a bonded solver.

The registry, the payment window, open intents, domain executors and the
claim replay set are part of the settlement root and of the global header
(`graft_root`, V7). `bud_getGraftApplication`, `bud_graftPaymentProof` and the
Graft fields of `bud_getSettlementInfo` are read-only.
