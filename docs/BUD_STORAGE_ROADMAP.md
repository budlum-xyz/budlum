# B.U.D. — where the storage layer stands and how it gets stronger

B.U.D. is the system's heart: Lubot's training corpora, SocialFi content and
every large object the chain refers to live behind it. This document records
what the layer does today, measured against how comparable networks solve the
same problems, and what the next steps are. It is a design note, not a promise
of delivery dates.

## What exists today

```
ContentId::of(chunk)          SHA-256 + "BDLM_CONTENT_V1" tag, 256 KiB chunks
        ↓
ContentManifest               manifest_id from (owner, total_size, shards)
        ↓
StorageDeal                   operator posts a bond, deal goes Active
        ↓
RetrievalChallenge            anyone may open one; opener posts a bond
        ↓
RetrievalResponse             range_hash + mandatory Ed25519 signature
        ↓
Answered | Mismatched | Missed        last two slash the operator bond
```

Content addressing is deterministic and domain-separated, the challenge path is
permissionless, responses are signed, and the RPC labels every outcome
`proof_kind = "interim_availability_only"` so no caller can mistake the current
guarantee for a real storage proof. That honesty is worth keeping.

## Gap 1 — a challenge answer is not a storage proof

`RetrievalResponse` carries `range_hash` for the challenged byte range. An
operator that keeps only the ranges it expects to be asked about passes every
challenge while discarding the rest of the shard. The module README already
states this.

**How other networks close it.** Filecoin's Proof-of-Spacetime iterates the
proof so each round's output seeds the next; one bad round poisons the chain of
proofs, which makes "store transiently, prove once" unprofitable. Walrus goes
further and is the first design to support storage challenges under asynchronous
networks, so an adversary cannot exploit network delay to fetch missing data
from honest nodes just in time to answer.

**Direction for B.U.D.** `RetrievalResponse` already has an optional
`proof_bytes: Option<ProofEnvelope>` field. Making it mandatory requires the
BudZKVM `VerifyMerkle` 64-depth gate, which is currently closed and whose path
verification is a known TODO. Sequencing: finish `VerifyMerkle`, then require
`proof_bytes`, then retire the `interim_availability_only` label.

## Gap 2 — replica answers — **closed at the challenge layer**

### What was wrong

`ContentId::of_subrange` hashed the bytes and nothing else, so every operator
holding a replica of the same shard produced the *same* answer to a challenge.
Two attacks came free, both named in the SoK on decentralized storage networks:

- **outsourcing** — several operators keep one physical copy between them and
  collect a payment each, because any of them can produce the answer the others
  would have produced;
- **Sybil** — one machine registers N identities, claims N replicas, stores one.

### What changed

`ContentId::of_subrange_for_deal` binds the answer to
`(operator, deal_id, shard_id)`, and the provider's `prove`/`settle` path uses
it. A challenge can now only be answered by whoever holds *that deal's* copy.

Five tests cover it. Two state the gap directly: the unbound hash really is
identical across operators, and the bound one really is not. One checks the
same operator on two deals for the same shard still gets different answers, so
one response cannot cover two payments. One is end to end — a proof computed by
a second provider holding identical bytes fails to settle the first provider's
challenge with `ProofRangeMismatch`. The last is the canary: the operator that
actually holds the deal still settles, so the check is not passing by rejecting
everything.

### What is still open

This binds *answers*, not *bytes*. Filecoin's PoRep goes further: each replica
is encoded under a per-replica key, so the stored data is physically different
and incompressible and the copies cannot be shared at all. That is a change to
what an operator writes to disk.

What this removes is the free version of the attack. Colluding operators can no
longer precompute one answer set and split the payments — they have to relay
each other's live challenges in real time, within the deadline, for every
challenge. That is a running cost and a detectable pattern rather than a
one-off setup.

## Gap 3 — erasure coding — **schema landed, coder pending**

`ShardRef` now carries a `kind` (`Data` or `Parity`) and `ContentManifest`
carries an `ErasureScheme { k, n }`: any `k` of the `n` shards reconstruct the
object.

The saving is the point of the gap. For the same loss tolerance:

| scheme | tolerates | stored per byte |
|---|---|---|
| replication ×3 | 2 losses | **3.0×** |
| `(k=4, n=6)` code | 2 losses | **1.5×** |

`with_erasure` refuses a scheme the shard list cannot deliver — `n` has to
equal `shard_count`, `k` has to equal the data shards present, and the
difference has to equal the parity shards present. A manifest claiming
tolerance it does not have is worse than one claiming none, because a repair
trigger reads the claim and concludes the object is safe.

Manifests written before this deserialize to `ShardKind::Data` and
`ErasureScheme::default()`, which is replication — exactly what they were.
`legacy_json_deserialises_without_the_new_fields` pins that.

**Still open:** the coder itself. Nothing computes parity shards or
reconstructs from them yet; the schema describes redundancy that an off-chain
chunker has to produce. `reed-solomon-erasure` (GF(2^8) or GF(2^16)) is the
obvious dependency when that lands.

## Gap 4 — repair trigger — **expressible now**

With `k` known, "how much redundancy is left" is a number, and repair becomes a
condition rather than a wish:

```rust
manifest.is_recoverable(live)        // live >= k
manifest.needs_repair(live, margin)  // k <= live < k + margin
```

Repair fires with headroom, not at the edge. Waiting until `live == k` means
the next loss is fatal with nothing in flight — Storj triggers on a safety
threshold above `k` for the same reason.

`needs_repair` returns false once the object is already unrecoverable: there is
nothing to reconstruct from, and a repair deal opened then would only burn an
operator bond. Both directions are pinned by tests.

**Still open:** wiring the trigger to the deal lifecycle. `needs_repair` is a
predicate; nobody calls it on a slash yet, and nothing opens the replacement
deal. That work depends on the coder, since a repair with no parity to rebuild
from is just a re-upload.

## Gap 5 — challenge economics — **measured and partly closed**

### What the measurement showed

The opener bond was checked only for being non-zero, so one unit bought any
challenge. Answer cost for the operator, on commodity NVMe (~2 GB/s read,
~1.5 GB/s SHA-256):

| challenged range | read | hash | total |
|---|---|---|---|
| 256 KiB (default chunk) | 0.13 ms | 0.17 ms | **0.31 ms** |
| 16 MiB (`MAX_CHUNK_SIZE`) | 8.39 ms | 11.18 ms | **19.57 ms** |

The rate limit is keyed on `(operator, manifest)` with
`MIN_OPERATOR_MANIFEST_CHALLENGE_EPOCHS = 4`, so it scales with the number of
manifests an operator serves rather than capping the operator's total load:

| manifests held | challenges/epoch | operator I/O per epoch |
|---|---|---|
| 1 | 0.25 | 4.9 ms |
| 10 | 2.5 | 48.9 ms |
| 100 | 25 | 489 ms |
| 1000 | 250 | **4.9 s** |

And the attacker's cost was **zero**: the bond is refunded whenever the
operator answers correctly, which is exactly the case a griefer wants — the
goal is to burn disk bandwidth, not to win a slash.

### What changed

`opener_bond` now has to cover the range being challenged:

```
required = max(MIN_OPENER_BOND, ceil(range_len / 1024) * OPENER_BOND_PER_KIB)
```

A 16 MiB challenge needs 16384 units instead of 1. Rounding is up, so the last
partial KiB is not free.

This does not make griefing *expensive* — the capital still comes back — but it
makes it **capital-bound**: sustaining the attack means locking stake
proportional to the damage, in parallel, for the whole challenge window. That
is the same shape as the operator bond, so the two scale together.

### What is still open

`OPENER_BOND_PER_KIB = 1` is a unit, not a calibrated price. Setting it against
real hardware and the token's value is a governance parameter question, and it
belongs with the rest of the storage economics rather than being guessed here.
The rate limit is also still per `(operator, manifest)`; a per-operator ceiling
would bound total load directly and is the better long-term shape.

## Suggested order

1. **Gap 2** (replica encoding) — the challenge-layer half has landed;
   per-replica byte encoding remains and still changes the stored format.
2. **Gap 3** (erasure coding) — schema landed; the Reed-Solomon coder remains.
3. **Gap 1** (real storage proof) — blocked on `VerifyMerkle`.
4. **Gap 4** (repair) — predicates landed; wiring them to the deal lifecycle
   needs the coder from Gap 3.
5. **Gap 5** (bond calibration) — measured; the range-proportional bond has
   landed, calibrating `OPENER_BOND_PER_KIB` and moving the rate limit to a
   per-operator ceiling remain.

Gaps 1, 2 and 3 all change on-disk or on-chain formats. Doing them before B.U.D.
is included in mainnet avoids a migration; doing them after does not.

## References consulted

- Filecoin PoRep / PoSt — per-replica encoding, iterated proofs
- Walrus (RedStuff) — 4.5× replication, self-healing, asynchronous challenges
- Storj — erasure coding vs replication durability analysis, repair thresholds
- CrustChain — hybrid Reed-Solomon + network coding cost figures
- SoK: Decentralized Storage Networks — Sybil and outsourcing attack taxonomy
