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

## Gap 2 — replicas are indistinguishable

`ContentId` is a plain content hash, so N operators storing the same shard hold
byte-identical data. Two consequences, both documented in the SoK on
decentralized storage networks:

- **outsourcing**: several operators share one physical copy and collect N
  payments;
- **Sybil**: one machine registers N identities and claims N replicas.

**How other networks close it.** Filecoin's Proof-of-Replication encodes each
replica under a distinct key derived from the provider id, sector id and content
commitment, so every replica is physically different and incompressible.

**Direction for B.U.D.** A per-deal encoding key derived from
`(operator, deal_id, manifest_id)` would make each operator's bytes unique, and
challenges would then be answerable only by whoever actually performed the
encoding. This changes what an operator stores, so it is a format change, not a
patch — it belongs before mainnet inclusion, not after.

## Gap 3 — redundancy is replication, not erasure coding

`ShardRef` is `(index, shard_id, size)`; there are no parity shards, and
`manifest.rs` says the chunking algorithm is left to the caller. Durability
therefore costs one full copy per replica.

**What the numbers look like elsewhere.** Storj's own analysis shows erasure
codes reach higher durability at lower overhead than full replication, and the
saving flows to operators because the same payment covers less stored data.
Walrus reports a 4.5× replication factor with two-dimensional coding and
self-healing recovery — recovery bandwidth proportional to the data actually
lost, rather than to the whole blob. CrustChain reports roughly 82% cost
reduction from combining Reed-Solomon with network coding.

**Direction for B.U.D.** Add parity shards to `ContentManifest` as an explicit
`(k, n)` scheme: any `k` of `n` shards reconstruct the object. `ShardRef` would
gain a kind discriminator (data or parity). The manifest already validates that
shard indices are unique and sizes are non-zero, which is the right place to
also validate `k <= n`.

## Gap 4 — recovery has no defined path

When an operator is slashed for a missed challenge, nothing repairs the lost
redundancy. Storj triggers repair when available pieces fall below a safety
threshold; Walrus's self-healing recovers a lost sliver using bandwidth
proportional to that sliver.

**Direction for B.U.D.** With erasure coding in place, a repair trigger becomes
expressible: when live shards for a manifest drop below `k + margin`, open a
repair deal. Without erasure coding there is nothing to reconstruct from, so
this depends on Gap 3.

## Gap 5 — challenge economics are unmeasured

Anyone may open a challenge and posts a bond to do so. Whether that bond exceeds
the I/O the operator must spend to answer has not been calculated. If it does
not, repeated challenges are a cheap way to grief an operator — Immunefi
classifies griefing as its own impact category precisely because there is no
profit motive to deter it.

**Direction for B.U.D.** Measure the answer cost for the largest permitted range
and set the opener bond above it, or rate-limit challenges per (opener, deal)
pair per epoch.

## Suggested order

1. **Gap 2** (replica encoding) — changes the stored format, so earliest.
2. **Gap 3** (erasure coding) — changes the manifest shape; Gap 4 depends on it.
3. **Gap 1** (real storage proof) — blocked on `VerifyMerkle`.
4. **Gap 4** (repair) — needs Gap 3.
5. **Gap 5** (bond calibration) — independent, cheap, can happen any time.

Gaps 1, 2 and 3 all change on-disk or on-chain formats. Doing them before B.U.D.
is included in mainnet avoids a migration; doing them after does not.

## References consulted

- Filecoin PoRep / PoSt — per-replica encoding, iterated proofs
- Walrus (RedStuff) — 4.5× replication, self-healing, asynchronous challenges
- Storj — erasure coding vs replication durability analysis, repair thresholds
- CrustChain — hybrid Reed-Solomon + network coding cost figures
- SoK: Decentralized Storage Networks — Sybil and outsourcing attack taxonomy
