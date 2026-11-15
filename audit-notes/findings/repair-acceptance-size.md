# B-0004: A repair acceptance prices and challenges a size its consent never names

- **Identifier:** B-0004
- **Severity:** medium (as reported by Strix on PR #110 head `ea384116`; the bond of a well-behaved operator is at risk, not chain state)
- **Status:** fix in the PR #110 working tree on top of `ea384116`, verification running. No CI result and no push yet at the time of writing.
- **Origin:** Strix inline finding `1d0558c0-cfdd-444f-86e5-336c180bc96a` on PR #110, three comments at 2026-11-15T15:04Z. Independently traced in the code below; the trace agrees with the report.

## Location

`src/domain/storage_tx.rs:142` `StorageReallocationAccept` (before the change):

```rust
pub struct StorageReallocationAccept {
    pub ticket_id: u64,
    pub replacement_operator: Address,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub economics: StorageEconomicsParams,
    pub merkle_proof: Vec<u8>,
    pub storage_root: Hash32,
    pub operator_consent: GrantAuthorization,
}
```

`src/domain/storage_tx.rs:482` `accept_reallocation_consent_digest` commits `ticket_id`, operator, epochs, `operator_bond`, `fee_per_byte_epoch`, `merkle_proof` and `storage_root` — and no size. `src/domain/deal_open.rs:143` `accept_reallocation_escrowed` prices the escrow on `held_bytes` of the ticket's shard, which comes from the registered manifest entry.

## What is wrong

The replacement operator signs a consent that does not mention the number of bytes it is agreeing to store, while the chain prices the deal, bounds the retrieval-challenge range and computes the repair obligation from that number. Compare `StorageDealOpen::shard_size` (`src/domain/storage_tx.rs`, the open path), which is in the body and in `open_deal_consent_digest` and is required to equal the registered shard entry.

## Why it is wrong

The two doors ask the operator different questions. An operator opening its own deal agrees to a length it can measure. An operator accepting a repair agrees to a ticket id — and the length arrives from a manifest it never saw, registered by someone else. The consent is what binds it, and the consent is silent about the quantity it is paid on and challenged against.

## What it leads to

1. **Unanswerable challenge, slashed bond.** A manifest whose declared shard size exceeds the shard id's real bytes produces a challenge range past the end of the stored shard. The replacement operator cannot answer it, and the missed-answer path slashes the bond.
2. **Signed into a different deal than the one described.** Because `fee_per_byte_epoch` and `operator_bond` are signed but the byte count is not, the same signature authorises any length the registry happens to hold for the ticket's shard. The economic terms the operator checked are multiplied by a number it never saw.
3. **No operator-side mitigation.** There is no measuring helper for this door — `operator_open_deal_consent_digest` exists for the open — and for a `NeverPlaced` ticket there are no bytes to measure before signing, which is precisely the case where a lie about size is cheapest.

## How to fix it

Make the acceptance name the length, and make the chain compare it to the manifest:

1. Add `shard_size: u32` to `StorageReallocationAccept` with the same meaning as the open's field.
2. Commit it in `accept_reallocation_consent_digest`, after `ticket_id`.
3. Commit it in the transaction signing preimage (`src/core/transaction.rs`, the `AcceptReallocation` arm) so a relay cannot drop or change it.
4. In `accept_reallocation`, after the consent verifies, read the ticket, read the registered manifest's entry for the ticket's shard, and refuse unless the two agree. The refusal happens before any write, so a refused acceptance leaves no escrow and no bond lock.

The change is wire-visible: it alters the consent preimage and the signed transaction bytes for this variant. Every pre-existing `AcceptReallocation` transaction would be refused after the change, so it needs an activation boundary or a fresh testnet genesis, exactly as the bridge-namespacing change does.

## Verification

- `the_repair_consent_digest_commits_the_shard_size` — two accepts differing only in `shard_size` produce different consent digests and different transaction hashes.
- `a_repair_acceptance_must_name_the_size_the_manifest_lists` — an otherwise valid, correctly signed acceptance naming `listed_size + 1` is refused with `consent names N bytes but the registered shard's entry is M`, the state root does not move, and no replacement deal is opened.

Both tests are in `src/domain/storage_tx.rs` and run under the `wallet-ml-dsa` feature. The red-before-fix direction is structural rather than observed: before the change the field did not exist, so the mismatched consent could not be expressed at all — the compiler refuses the old test. What the tests pin is that the *new* field is inside both preimages and that the chain enforces it.
