# B-0002: Manifest registration never binds declared shard sizes or parity roots to bytes

- **Identifier:** B-0002
- **Severity:** high
- **Status:** open. No fix commit exists on this branch. The reasoning below was verified against PR #110 head `a52933e131050a2027a0d90d582881a68d4e7405` on 2026-11-15; refresh before using it.
- **Related:** PR #110 unresolved review threads on storage shard-size verification, and the Strix master-summary finding "unverified manifest shard sizes".

## Location

`src/domain/storage_tx.rs:940` `register_manifest` is the whole admission path for a manifest inside a block:

```rust
fn register_manifest(
    state: &mut AccountState,
    sender: &Address,
    manifest: &ContentManifest,
) -> Result<(), StorageTxError> {
    // The id is re-derived from the contents, so a manifest whose id does not
    // match what it carries never reaches the registry. The signing preimage
    // commits the whole manifest as well.
    manifest
        .validate_untrusted()
        .map_err(StorageTxError::InvalidManifest)?;
```

`src/storage/manifest.rs:785` `validate_untrusted` is what that call reaches. It checks that the shard list is non-empty and below the ceiling, that indices are unique, that `shard_count` equals the list length, that `total_size` equals the arithmetic sum of the declared `size` fields (`src/storage/manifest.rs:829`), that `content_size <= total_size`, that the erasure geometry matches the shard kinds, that an encrypted claim is at least one authentication tag long, that edition and source agree, and finally that `manifest_id` matches the fields. Every one of those quantities comes from the manifest itself; none is compared with bytes.

The only function that does compare is `src/storage/erasure.rs:747` `verify_object_encoding`, and its own doc comment states the gap it leaves:

```rust
/// The usual path is client-built: the client encodes, builds a manifest, and
/// registers it. The node then trusts the structural checks in
/// `validate_untrusted` but never re-runs the coder, so a client that lies
/// about parity (or pads a different payload into the same listed sizes) can
/// still pass registration. This function is the optional, costly half of
/// that path [...]
```

Its only non-test caller is the read-only RPC method at `src/rpc/server.rs:3555`. No consensus path calls it.

## What is wrong

A registrant chooses every shard `size`, every shard id, and (for a codeword manifest) every parity `column_root`, and the block accepts the manifest if those fields are internally consistent. Nothing proves that any of those declared lengths or roots describes a byte string the registrant has ever produced. The registration is a claim about geometry, not a statement about content.

The encryption, geometry and provenance fields do enter `manifest_id` (V3/V4 preimages, `src/storage/manifest.rs:1126`), so a later claimant cannot silently rewrite them under a stable id. That protects the *consistency* of the claim. It does not make the claim true, and truth is what the storage economics are priced on.

## Why it is wrong

The chain's storage accounting consumes exactly these declared numbers:

- Deal pricing, replication factors, quota and self-host size limits are computed from `ShardRef::size` / `total_size`.
- The coding audit (`src/storage/erasure.rs`, `CodingAuditOutcome`) verifies a holder's answer against the parity `column_roots` committed in the manifest — not against bytes the registrant holds. An unregistered-but-valid codeword column satisfies "is a column of *some* codeword"; the manifest's root is what ties it to *this* object.
- Repair decisions compare surviving shard counts against `erasure.k`.

A `validate_untrusted`-clean manifest with false sizes is accepted today. A test placed against a tree without the byte-proof path registers a manifest whose single shard declares 13 bytes for a 12-byte payload and succeeds (this is the counterexample written for the red-evidence run; see "How to reproduce"). Because `total_size` is only required to equal the sum of the declared sizes, the false number propagates consistently.

Because the id excludes `owner` (deliberately, so the id means "what the object is" — see the `register_manifest` comment about contested ids) and nothing binds the id to bytes, two honest nodes agree on a false statement with no local signal that it is false. This is not a nondeterminism bug: it is a shared, committed falsehood.

## What it leads to

1. **Priced storage for unpriced content.** A registrant can register a large object it does not hold, then let the lapse/repair machinery treat it as present or lost, distorting repair load and any size-derived pricing or quota.
2. **Audits that prove the wrong thing.** A holder answering an audit for such a manifest is checked for internal consistency against the registrant's root, not for possession of the original object. If the registrant also supplies the codeword, the "object" is whatever the registrant invented.
3. **Denial of the honest path.** An honest client that later uploads the real object at the same content geometry produces a different `manifest_id` (its ids and sizes differ), so it registers a second entry; the false one is not displaced.
4. **No activation-free fix.** Making a byte proof mandatory changes admission for every storage transaction, so it needs the same activation and replay analysis as the bridge namespacing change; a historical block containing an unproven registration must still replay.

## How to fix it

Do not change admission to "trust the RPC". A signer-side helper proves nothing about what other signers inspected. Options, with the constraints that decide them:

1. **Mandatory, bounded proof at registration.** Make registration carry a commitment that can be checked without the full body, e.g. a Merkle commitment to the shard ciphertexts plus inclusion proofs for each declared `(shard_id, size, column_root)`, and verify those proofs in `register_manifest`. Cost: registration must remain under the transaction size ceiling (see below), so the proof must be per-shard and small, not the body.
2. **Deferred-but-mandatory verification in the deal path.** Keep registration cheap, but refuse `OpenDeal` (or the first audit) for a manifest whose bytes have not been verified by a party with skin in the game, and price the verification explicitly. This keeps block size honest and puts the cost where the revenue is, but it means an unverified manifest exists on chain for a while — the state root must record that status explicitly so nodes cannot disagree.
3. **Bind the id to the bytes' commitment, not the byte count.** The cheapest structural improvement: require `shard_id`s (which are content ids) to be checked against a commitment the registrant cannot fabricate without the content. Note this still does not prove possession at registration time.

Constraints that make the naive version wrong:

- A default shard is 256 KiB while the transaction ceiling is 160 KiB, so the whole body cannot be carried in the transaction for the default geometry. Any design that requires bytes inline must either raise the ceiling deliberately (with a block-size analysis) or use a smaller shard geometry for the proof.
- Confidentiality: the chain must not receive plaintext for `ClientSide` content; proving sizes of ciphertext is fine, proving plaintext is not.
- Replay: the rule must be gated by an activation height, with the old behaviour for blocks below it, and the storage registry must record which manifests were verified under which rule so a re-executed historical block produces the same root.
- Work budget: a full re-encode is O(len) with a coder; `verify_object_encoding` caps at `MAX_VERIFY_ENCODING_BYTES = 64 MiB` (`src/storage/erasure.rs:729`) precisely because it is not block-safe at arbitrary size.

## How to reproduce

Against a tree without the byte proof, add to `src/tests/storage_tx_door.rs`:

```rust
#[test]
fn audit_110_admission_accepts_forged_shard_length() {
    let owner = addr(0x51);
    let bytes = b"actual shard";
    let mut shard = crate::storage::ShardRef::from_bytes(0, bytes);
    shard.size += 1;                                        // the lie
    let m = ContentManifest::from_shards(vec![shard]).unwrap().with_owner(owner);
    m.validate_untrusted().expect("forgery is structurally consistent");
    let mut state = AccountState::new();
    state.add_balance(&owner, 1_000);
    apply(&mut state, storage_tx(owner, 0, StorageTx::RegisterManifest { manifest: m.clone() }, 0))
        .expect("baseline registration accepts a forged byte length");
    assert_eq!(state.storage_registry.get_manifest(&m.manifest_id), Some(&m));
    assert_ne!(m.shards[0].size as usize, bytes.len());
}
```

A parity variant flips one byte of `column_roots[0]` through `with_column_roots` and shows registration accepts it as well. `verify_object_encoding` refuses both, which is the evidence that the check exists and is unreachable from admission; that refusal is pinned by `storage::erasure::tests::strix_110_encoding_verifier_rejects_forged_parity_roots` on the PR #110 working tree.

The counterexamples above were written into a detached worktree at PR #110's head for an isolated baseline run; the run has not completed, so no red result is claimed here yet.
