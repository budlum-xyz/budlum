# Independent review 2: execution, mobile and clients

## Scope of this delivery

WP-48, review slice 1/N, performed from lane B for this review. M4 is not merged,
so this is an early compatibility review of open deliveries, not a claim that
WP-48 or the launch gate is complete. The reviewer wrote the WP-09 transport
changes in this PR and therefore excludes those changes from this independent
review, as section 15.1 item 8 requires.

This slice compares the mobile duty surface in PR #82 at
`5685e03d87c257e7e1ecc6fd3355eee5cebdbf94` with the node storage contract on
`cccf1da1f4bcfe97503a3a00cfba24b172b49b31`, the presence implementation in PR
#70 at `d611e8aa6624147762da096cb68f447cf29b65d8`, and the release transaction in
PR #45. It does not edit their locked source paths.

## Result

| Finding | Severity | Result |
|---|---|---|
| BLG-288 | High | Node and mobile sign different presence preimages |
| BLG-289 | High | Mobile proof batches omit the object key required by the node |
| BLG-290 | High | Mobile share release cannot be encoded as the proposed node transaction |

All three remain open. A passing unit test inside either implementation does
not establish cross-implementation compatibility.

## BLG-288: presence signatures cannot verify across the two implementations

Evidence:

- PR #70 `src/validators/presence.rs::presence_message` writes the domain tag
  directly, then length-prefixes chain id, window and class.
- PR #82 `mobile/core/src/presence.rs::presence_preimage` length-prefixes the
  domain tag as well, then the same three fields.
- Both use SHA3-256, the same tag bytes, little-endian integers and the same
  class tags. The sole difference is the eight-byte length before the tag.

The following byte-level reproduction was executed locally with Python's
standard `hashlib` and `struct`, using chain id 45261, window 11 and Mobile class
1. It reproduces the two Rust constructions without requiring a Rust toolchain:

```text
node PR #70 preimage:
42444c4d5f50524553454e43455f56310800000000000000cdb000000000000008000000000000000b00000000000000010000000000000001
mobile PR #82 preimage:
100000000000000042444c4d5f50524553454e43455f56310800000000000000cdb000000000000008000000000000000b00000000000000010000000000000001
node SHA3-256:
f14a3db552fa9b83037c7b5f0a4749ff05ea1390b436b40c8b071ef45d6ab7fd
mobile SHA3-256:
26a5bec8b11098debd4eeffbe797638d295a08aa570cb3c176d9c5e41bfbb2a3
equal: false
```

Impact: a mobile presence signature is refused by the node, or a node-produced
signature is refused by the mobile verifier. Presence aggregation and the
absence/suspension path cannot interoperate.

Resolution requirement: choose one canonical encoding and put its golden
vector in the shared types delivery. G-5 requires length-prefixed digest inputs;
under that invariant the domain tag receives a length too, matching #82's
construction. The specific shorthand in section 7.8 must be read consistently
with that invariant. Both implementations must consume the same definition or
at least the same locked vector before merge. Required regression:
`presence_preimage_matches_shared_golden_vector` on both sides, followed by a
real BLS sign-on-mobile/verify-on-node test.

## BLG-289: a mobile proof batch loses its object identity

Evidence:

- Node `src/storage/bud3/tx.rs::StorageTxV3::CustodyProofBatch` carries
  `Vec<(ObjectKey, CustodyProof)>`.
- Node `Bud3Registry::submit_proofs` takes `&[(ObjectKey, CustodyProof)]` and
  looks up the object before checking the holder's open audit.
- PR #82 `mobile/core/src/custody.rs::CustodyProofBatch` carries only
  `Vec<CustodyProof>`.
- PR #82 `ShareStore::matching_audit` and `ShareStore::answer` select a share by
  segment and position only. `MobileCore::answer_audit` returns the unkeyed
  batch. `Audit` itself contains no object key.

Impact: two objects can use the same segment index and position. The mobile
core can select the first matching local share for the wrong object, and the
host cannot reconstruct the node transaction's required object keys from the
returned batch. Self-verification against the selected share's own root does
not detect that selection error.

Resolution requirement: carry the object key with each audit answer and proof,
select by `(object, segment, position)`, and use the shared proof-batch type.
Required regressions: `mobile_audit_selects_the_named_object` with two colliding
segment indexes, and `mobile_proof_batch_encodes_object_proof_pairs`.

## BLG-290: share release has no compatible transaction payload

Evidence:

- Directive section 6.22.1 names a share list and a new quota for
  `ReleaseShares`; section 7.9.5 requires releasing excess shares when the user
  lowers quota or the free-space floor fires.
- PR #82 `DutyTx::ReleaseShares` carries only `Vec<ShareId>`, where `ShareId` is
  a process-local monotonic `u64`. It carries no object, segment or quota value.
- PR #45 instead proposes `StorageTxV3::ReleaseShares { object, segment:
  Option<u64>, lower_quota_bytes }`.

Impact: local share ids have no chain identity. The host cannot turn the mobile
duty into either the directive's payload or #45's proposed transaction. A
free-space release can delete local bytes without producing a valid on-chain
release, so chain placement and repair continue to assume the phone holds them.

Resolution requirement: reconcile #45 with the directive's share-list/new-quota
contract, then make the mobile duty carry the same chain share identities and
quota fields. Do not serialize the local store id as a chain id. Required
regressions: `mobile_release_duty_encodes_chain_share_identities` and
`quota_floor_release_round_trips_through_storage_tx_v3`.

## Remaining review work

This slice does not cover the rest of WP-48: foreign-envelope replay and signer
confusion, cross-environment BUD conservation, mobile key custody and operator
authority, the full risk attack set, wallet/CLI/explorer/faucet review, or the
execution coordinator authored in other deliveries. Those remain open. No Rust
build, Rust test, device run or CI-green result is claimed here.
