# Standard 3 - Finality certificate and inclusion proof

| Field | Value |
|---|---|
| Domain tag | `BDLM_FINALITY_CERT_V1` (certificate), `BDLM_FINALITY_CERT_ROW_V1` (row) |
| Hash | Keccak-256 (legacy padding `0x01`), **not** SHA3-256 (`0x06`) |
| Integer encoding | big-endian for every field in this standard |
| Vectors | `docs/standards/vectors/finality-certificate-v1.json` |
| Production source | `src/settlement/universal_finality.rs` |

A `GlobalFinalityCertificate` is Budlum's answer to one question: *at settlement
checkpoint H, what verdict did Budlum record for each consensus domain, and what was the
weakest guarantee across the domains it accepted as final?* It is the object an external
chain, wallet or bridge consumes. Nothing in this document depends on Budlum's node
internals: the certificate is self-contained and its digest is recomputable from the rows.

## 1. Row: one domain's certified verdict

```text
DomainFinalityEntry {
  domain_id              u32     registry identifier
  height                 u64     finalized height the verdict refers to
  checkpoint_height      u64     settlement checkpoint at which the row was sealed
  state_root             bytes32 domain state root the verdict commits to
  adapter_id             string  registered finality adapter identifier, UTF-8
  adapter_version        u32
  finality_proof_hash    bytes32 digest of the verified finality proof bound to this row
  guarantee_backing_hash bytes32 digest of the economic/cryptographic backing anchor
  bond_atoms             u128    escrowed slashable operator bond, in atoms
  guarantee              AssuranceBundle (standard 1)
  verdict                Established | Refuted{code:u16} | Pending{reason}
}
```

`row_digest = Keccak256(preimage)` where preimage is the concatenation, in this order:

| # | Bytes | Notes |
|---|---|---|
| 1 | `BDLM_FINALITY_CERT_ROW_V1` | 25 ASCII bytes, no terminator |
| 2 | `domain_id` | u32 BE |
| 3 | `height` | u64 BE |
| 4 | `checkpoint_height` | u64 BE |
| 5 | `state_root` | 32 raw bytes |
| 6 | `len(adapter_id)` | u64 BE, saturating |
| 7 | `adapter_id` | UTF-8, no terminator; length-prefixed so `["ab",""]` cannot collide with `["a","b"]` |
| 8 | `adapter_version` | u32 BE |
| 9 | `finality_proof_hash` | 32 raw bytes |
| 10 | `guarantee_backing_hash` | 32 raw bytes |
| 11 | `bond_atoms` | u128 BE |
| 12 | guarantee | section 2, 17 bytes |
| 13 | verdict | section 3, 3 bytes |

## 2. Guarantee (assurance bundle) inside a row

| # | Bytes | Values |
|---|---|---|
| 1 | `reversibility_tag` | 0 `ProbabilisticWork{confirmations}`, 1 `DataAvailabilitySampled{min_samples}`, 2 `DeterministicQuorum`, 3 `CryptographicValidity` |
| 2 | `reversibility_param` | u64 BE: confirmations or min_samples; **0 for tags 2 and 3** |
| 3 | `quantum_tag` | 0 `Classical`, 1 `Lattice`, 2 `Hash` |
| 4 | `attestation` | 4 bytes, in order `state_root, tx_root, event_root, parent`, each 0 or 1 |
| 5 | `slashable_backing` | 1 byte, 0 or 1 |
| 6 | `fault_tolerance_bps` | u16 BE, `0..=10000` |

Tagged fields exist so that two different guarantees never share a digest, and so that a
`ProbabilisticWork{4}` folded from one domain cannot be replayed as a
`DataAvailabilitySampled{4}`.

## 3. Verdict

| Verdict | tag | detail (u16 BE) |
|---|---|---|
| `Established` | 0 | 0 |
| `Refuted{code}` | 1 | the domain's own rejection code, verbatim |
| `Pending{EvidenceMissing}` | 2 | 1 |
| `Pending{AttestationUnbound}` | 2 | 2 |
| `Pending{RuleNotSatisfied}` | 2 | 3 |
| `Pending{BondUnverified}` | 2 | 4 |

`Pending` is a debt with a named cause, never a rejection. A consumer that maps
`Pending` to "false" silently turns a missing measurement into a final no, and the
domain's honest operator is punished for the gap.

## 4. Bucket tree

Rows are partitioned into three buckets by verdict - `Established`, `Pending`,
`Refuted` - each **sorted by `domain_id` ascending**, and each committed by its own
binary tree.

```text
leaf(row)      = Keccak256("BDLM_FINALITY_CERT_LEAF_V1" || row_digest(row))
node(l, r)     = Keccak256("BDLM_FINALITY_CERT_NODE_V1" || l || r)
empty_root     = Keccak256("BDLM_FINALITY_CERT_EMPTY_V1")

depth(n)       = 0                                   if n <= 1
               = 1 + depth(ceil(n / 2))              otherwise

root(rows):
  if rows is empty: return empty_root
  level = [ leaf(r) for r in rows ]
  while len(level) > 1:
      next = []
      for i in steps of 2 over level:
          left  = level[i]
          right = level[i+1] if it exists else level[i]   # odd tail pairs with itself
          next.append(node(left, right))
      level = next
  return level[0]
```

Leaf and node tags differ, so a digest can never be reinterpreted as the other kind of
node. An empty bucket has its own root rather than the all-zero string, because a zero
root is a value an attacker can supply for free.

> **Not the settlement tree.** `src/settlement/commitment_tree.rs` uses SHA-256 with
> `BDLM_MERKLE_NODE_V1` and, for an odd tail, a *promotion* tag
> (`BDLM_MERKLE_ODD_PROMOTE_V1`) instead of self-pairing. Two tree shapes exist on
> purpose: the certificate tree is the one an EVM verifier must reproduce inside a
> `keccak256` opcode, where a promotion tag costs an extra hash for no forgery gain.
> A verifier must pick the shape by the domain tag, never by "the Merkle tree".

## 5. Certificate digest

```text
digest = Keccak256(
    "BDLM_FINALITY_CERT_V1"
 || checkpoint_height          u64 BE
 || established_count           u32 BE
 || pending_count               u32 BE
 || refuted_count               u32 BE
 || established_root           bytes32
 || pending_root                bytes32
 || refuted_root                bytes32
 || (0x00                      if no Established row
    0x01 || guarantee_bytes    otherwise  -- section 2, the folded bundle)
)
```

`established_count`, `pending_count`, `refuted_count` are the **bucket sizes**, not a
total. The folded guarantee is the `meet` (weakest link) of every `Established` row, in
`domain_id` order; with no `Established` row it is absent, and the `0x00` byte commits
that absence so an absent bundle cannot be forged as an empty one.

## 6. Composition rules a producer must satisfy

A certificate is rejected, fail-closed, if any of these hold. A consumer that trusts a
certificate it did not re-derive inherits every one of these bugs.

| Rule | Why it is not pedantry |
|---|---|
| rows must be non-empty | an empty certificate proves nothing, and "nothing" is what an attacker wants recorded |
| at most 4096 rows | the registry ceiling; an unbounded set is a memory-DoS on every verifying contract |
| `domain_id` unique | two rows for one domain means two final heights, both "final" |
| one `checkpoint_height` for all rows | a certificate mixing checkpoints claims a verdict about a block that did not exist yet for some domain |
| every `Established` row attests all four commitments | a proof binding the state root but not the event root is not "almost final"; it is a different claim |
| every `Established` row has `fault_tolerance_bps != 0` | 0 bps tolerated faults means the domain grants no safety at all |

## 7. Inclusion proof

```text
DomainFinalityInclusionProof {
  bucket      Established | Pending | Refuted
  leaf_index  u32   zero-based position inside the sorted bucket
  leaf_count  u32   bucket size
  entry       DomainFinalityEntry
  siblings    [bytes32]   bottom-up, exactly depth(leaf_count) of them
}

verify(proof, expected_bucket_root) -> bool:
  if leaf_count == 0 or leaf_index >= leaf_count:            return false
  if bucket does not match entry.verdict:                      return false
  if len(siblings) != depth(leaf_count):                       return false
  acc = leaf(entry); cursor = leaf_index; width = leaf_count
  for s in siblings:
      odd_tail = (width is odd) and (cursor == width - 1)
      if odd_tail != (s == acc):                               return false
      acc = node(acc, s) if cursor is even else node(s, acc)
      cursor = cursor / 2; width = ceil(width / 2)
  return acc == expected_bucket_root
```

The `odd_tail != (s == acc)` line is the whole point of the shape check. The producer
pairs an odd tail with itself, so a proof must be allowed to repeat the running digest -
but **only** at the last node of an odd-width level. Without it the root of a
three-row bucket also opens as a forged four-row proof that presents the duplicated tail
as a second, distinct position: same root, different set.

## 8. Security properties, and the boundary of this document

| Claim | Status |
|---|---|
| Second-preimage resistance of a row digest | reduces to Keccak-256 collision resistance; every field is length-prefixed or fixed-width, and each variable field carries a domain tag |
| A proof for bucket A does not verify against bucket B's root | `verify` re-checks that `bucket` matches the row's verdict; a pending row cannot be presented as established |
| A certificate cannot be extended with an extra domain | counts and the root are inside the digest; adding a row changes the root and the count |
| `Pending` cannot be silently re-read as `Refuted` | both carry distinct tags and a named reason; a rejections-only encoding is not representable |
| The verdicts are *correct* | **not** in scope. This standard proves what Budlum recorded. Whether a domain's own finality rule is sound is the adapter's contract, verified separately before its row exists |
| Liveness / availability of rows | not in scope; a proof is useless without the bucket root, which is why it is anchored in `GlobalBlockHeader::finality_certificate_root` |
| Chain binding | **not inside this digest.** The header commits `checkpoint_height`, three bucket roots, three counts and the folded guarantee - no `chain_id`. Two Budlum networks with an identical checkpoint would produce byte-identical certificates, and nothing in a standalone verifier would notice. The chain id is bound one level up (`GlobalBlockHeader::chain_id`, and `budlumChainId` in the EVM attestation path of standard 4); a consumer that verifies a certificate *without* checking it came from the chain it is on is trusting a cross-network replay |

## 9. Consuming a certificate from a contract

1. Read the checkpoint's certificate root from `IBudlumFinality` (standard 4);
2. `require(certificate.digest == expected_cert_digest_from_the_settlement_root_chain)`;
3. `require(proof.verify(bucket_root_of(the_bucket_you_need)))`;
4. `require(entry.domain_id == the_domain_you_are_routing_for)`;
5. act on `entry.verdict`, and on the **bundle**, not on the domain's own claim:
   `guarantee.fault_tolerance_bps` and `slashable_backing` are the numbers that pay you
   when the domain lies.

Step 5 is where a bridge usually dies: it verifies the signature of the attestation and
forwards value, then the attesting domain reorganises because its own guarantee was
`ProbabilisticWork{1}`. Budlum records the weakness in the row precisely so a consumer
cannot accidentally average it away.

## 10. Vectors

`docs/standards/vectors/finality-certificate-v1.json` is the normative test set. Three rules make it checkable without trusting
anyone's code:

1. **A positive case states its input, not just its answer.** Recompute `expected` from `input`
   with the rules above; every published number must fall out, including the ones a producer is
   tempted to shortcut.
2. **A negative case states how it was made.** Proof-level negatives carry a full `proof`
   object and a one-line `why_rejected`; compose-level negatives carry a full `rows` array plus
   `"expect": "compose_rejects"`. A vector that nothing rejects is not a negative test.
3. **Nothing is unexplained.** Every integer in `input` is either a documented discriminant or a
   filler value derived from the domain id, so re-deriving the inputs from the published rules
   reproduces the
   file byte for byte.

`python3 docs/standards/check_vectors.py` performs rules 1 and 2 with the Python standard library
alone - no node, no toolchain, milliseconds. `--self-test` additionally mutates one published
value at a time and fails if the check does not notice, so a checker that always prints OK cannot
be mistaken for a verification.
