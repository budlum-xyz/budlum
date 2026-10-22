# B.U.D.: Broad Universal Database (module README)

**By the module-separation rule this is B.U.D.'s own README.**
The root `README.md` is a dashboard only; maturity and risk warnings live here.

## Status

- **Maturity:** devnet-only. Whether it ships on mainnet is a separate decision.
- **Code location:** `src/storage/` (manifest, deal, params), RPC endpoints in `src/rpc/api.rs` (`bud_storage*`),
  E2E tests in `src/tests/bud_e2e.rs`.
- **RPC surface:** `bud_storageRegisterManifest`, `bud_storageOpenDeal`,
  `bud_storageGetManifest`, `bud_storageGetDealsByManifest`, `bud_storageGetDealsByShard`,
  `bud_storageOpenChallenge`, `bud_storageAnswerChallenge`,
  `bud_storageGetOutcome`, `bud_storageGetEconomicsSummary`,
  `bud_storageGetEconomicsEvents`, `bud_storageGetOperatorEconomics`.
- **Data sovereignty rule:** there is NO whitelist/admin/pause/freeze hook; every RPC can be
  served by every node. This rule is locked by the 9 invariants in CI.

## Maturity warnings (they stay here rather than moving to the root dashboard)

1. **Risk of a false green:** `RetrievalChallenge` is not a real Proof-of-Storage;
   the answer only accepts a `range_hash` (see the note in `api.rs`), so an operator can pass
   the gate by storing only the requested byte range instead of the full data.
   `bud_storageGetOutcome` therefore returns `proofKind` / `proof_kind = "interim_availability_only"`
   on every answer. A full proof depends on the BudZKVM `VerifyMerkle` 64-depth production gate (closed).
2. **No permission/consent layer:** manifest and deal information is fully public;
   the `AccessGrant` concept will be designed in the permission layer
   (aimed at hard enforcement; the sovereignty rule rules out soft enforcement).
3. **`ContentManifest` carries an owner, but it is not mandatory.** F01 added the `owner`
   field and the `manifest_id` computation covers the owner (fields:
   `manifest_id/owner/total_size/shard_count/shards`). However `from_shards()`
   initialises the owner with the zero address and the real owner is set separately with
   `with_owner()`. If that call is skipped the manifest is registered as "ownerless", and two
   different users uploading the same content produce the same `manifest_id`. Making the owner
   mandatory on the registration path is the permission layer's job.
4. **Replicas are indistinguishable (outsourcing/Sybil).** Because `ContentId` is a plain content
   hash, N operators storing the same shard hold byte-identical data. One physical copy can
   satisfy N deals and one machine can collect N rewards under N identities. Filecoin's PoRep
   solves this with per-replica encoding; B.U.D. has **no** such encoding. Detail and roadmap:
   `docs/BUD_STORAGE_ROADMAP.md`.
5. **Erasure coding exists, but parity generation is not wired into the production flow.**
   `ShardRef` now carries a `kind` (`Data` / `Parity`) and `ContentManifest`
   carries an `ErasureScheme { k, n }`; `src/storage/erasure.rs` is a real Reed-Solomon
   encoder over GF(2^8) and tests all fifteen two-loss patterns of a `(4,6)` code.

   Two points remain open and both touch the durability promise.

   First: **nobody computes the parity bytes**. `encode_object` and
   `to_manifest` are called from nowhere in the production tree; the manifest arrives at the
   chain ready-made from the client. The `WIRING: unwired` marker at the top of the module
   says exactly this.

   Second, and deeper: the chain **never sees the shard bytes**, only their
   hashes. `validate_untrusted` checks the consistency of the counts
   (Data count `k`, Parity count `n - k`), but it cannot check whether a parity shard really
   is correct parity. A manifest declaring `(k=4, n=6)` with six random byte strings is
   accepted today; the error only surfaces when data is actually lost, which is too late.

   This second point is not a missing line but a design item. Ethereum's danksharding faced the
   same question and defined two routes: a fraud proof, where a party that downloads the bytes
   proves the encoding is wrong; or a polynomial commitment (KZG) / FRI, a proof of correct
   encoding that does not require downloading the data. B.U.D.'s current challenge mechanism
   sits close to the first: `RetrievalChallenge` already requests a byte range and verifies its hash.

   The repair side was measured and the arithmetic is right: `objects_needing_repair` takes the
   distinct shard count as the denominator, not the replica count, and puts objects that have
   fallen below `k` on the alarm list rather than the repair queue. But there is not yet a
   production path or an RPC endpoint calling these functions.

6. **A missed challenge costs two things.** Burning the bond is a one-off cost and an operator
   can price it in: fail, pay, re-register, fail again. Hence a second cost:
   `MISSED_CHALLENGE_COOLDOWN_SECS`, six hours. During that period the operator cannot open new
   deals. Existing deals are not cut; cutting them would immediately leave those shards
   under-replicated and the penalty would hit the user rather than the operator.

   The duration is written in seconds, not epochs. An epoch means
   `slot_duration_secs * epoch_length_slots` and both are governance
   parameters; a penalty written as "67 epochs" would silently become four hours or twelve when
   either of those two dials is adjusted.

   The penalty is extended by `begin_operator_cooldown`, never shortened. A second failure does
   not reset the clock; the later of the two dates is taken, because that is the only ordering
   that cannot be gamed by failing again on purpose.

   The chain cannot reach into a machine's disk and delete anything. What it can do is state,
   somewhere the operator's own software reads, which shards no longer belong to it:
   `stale_shards_for`. A node returning from an outage asks this and deletes what it finds. The
   same shape as Storj's bloom filter: the network says what should stop, the node removes the rest.

7. **A phone cannot hold a primary copy.** `OperatorClass` takes two values,
   `AlwaysOn` (default) and `Mobile`. Only the first may take
   `replica_index = 0`. The primary is the copy a reader reaches first and the one a repair
   sources from when rebuilding; a device that is online while its owner is awake cannot be that.

   The class is the operator's own declaration and the chain cannot verify it. Nor does it try:
   what it does is bind the operator to their declaration. A phone that says `AlwaysOn` and
   reaches for the primary replica has accepted a primary's obligations and loses its bond the
   first time it sleeps.

8. **The economic direction is provider-side:** operators are paid for storing; the "consumer
   access" economics where AI pays for access is designed as a separate layer.
9. **Slashed-bond flow:** in devnet interim accounting, after a missed challenge
   `slashedBondDisposition = "burn_from_operator_liquid_balance_best_effort"`
   appears in RPC; this is not the final mainnet tokenomics decision.

## Test suite

- **Gate:** the `B.U.D. E2E Invariants (9/9 name-locked)` CI job (`ci.yml`) -
  `cargo test --lib bud_e2e` + the `scripts/check-bud-e2e.sh` name canary
  (vacuous-gate protection: if an invariant is deleted or renamed the gate FAILs).
- **Coverage:** 9 module-independence invariants + 4 E2E flows (13 required tests),
  including a malicious cached-range operator scenario against an entropy-chosen challenge
  range. Registry unit tests additionally lock the `Slashed ->
  ReallocationPending -> ActiveReplacement` and `UnderReplicated` repair-state
  transitions.
- Unit tests (manifest validation, chunk params, prune/slash idempotence)
  run inside the Core lib suite (`cargo test --lib`; total count badge 755 lib,
  2026-07-18).

## Content encryption: declared, not enforced

`ContentManifest.encryption` **declares** what the uploader did before splitting the
bytes, and the declaration is inside `manifest_id`, so it cannot be rewritten under a fixed
identity. The default is `Plaintext`, because manifests written before this field
were written by a tree that contained no encryption at all.

Because the chain sees no bytes it cannot verify that anything is really
encrypted. The only thing it can verify is arithmetic: all three named AEADs
add a 16-byte tag, so an object declaring `ClientSide` and shorter than 16 bytes
is refused. This catches the careless client, not the
determined liar.

Detail, what is not claimed, and why: `docs/BUD_CONTENT_ENCRYPTION.md`.
Gate: `scripts/check-content-encryption-is-declared-and-bound.sh` (14 canaries).

## Coding audit: is the parity really parity

A retrieval challenge asks "do you still have these bytes". It CANNOT ask "are these bytes
correct parity", because the chain never sees shard content. An operator being paid for a parity
shard can store anything under that `ContentId` and will pass every retrieval challenge. The
difference surfaces during the repair that needs that parity, which is the moment the object can
least afford it.

Because Reed-Solomon works symbol by symbol, a single byte column is a complete instance of the
relationship. `derive_coding_audit` derives a parity index and a column from block entropy, and
`verify_coding_audit` compares the answer against the encoder's own generator. The cost is `k`
data bytes + 1 parity byte, however large the object is.

Passing says the relationship holds IN THAT COLUMN, and no more.
An operator corrupting a fraction `f` of the columns is caught with probability `f` each round,
so their survival probability after `r` rounds is `(1 - f)^r`. This is a probabilistic tool
and describing it any other way would be wrong.

What it does not prove: that the operator STORES anything. Parity can be computed on the fly by
someone holding nothing. Replicated objects are not audited but refused: if every shard is data
there is no `i`, and saying "passed" would report a check that was never performed.

Detail and probability table: `docs/BUD_STORAGE_ROADMAP.md` Gap 3b.
Gate: `scripts/check-coding-audit-samples-the-relationship.sh` (13 canaries).

## Roadmap markers

- Permission layer: `AccessGrant` + `AccessRevocation` + owner-signed provenance
  (`StorageCommitment`) + -2 key wrapping (hard enforcement).
- Mandatory integration: if `AiInferenceRequest.input_ref` points at a
  `DataAsset`, the AiVerifier cannot compute WITHOUT a grant check.
- Until the full-PoS (Merkle-64) gate closes, no claim of "data integrity proved" can be made,
  and the false-green warning stays in this README until that day.
