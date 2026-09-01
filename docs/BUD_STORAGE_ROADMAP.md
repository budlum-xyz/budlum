# B.U.D.: where the storage layer stands and how it gets stronger

B.U.D. is the system's heart: the AI inference layer's training corpora, SocialFi content and
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

## Gap 1: a challenge answer is not a storage proof

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
BudZKVM `VerifyMerkle` 64-depth gate, which is still closed. What "unfinished
path verification" actually meant has now been pinned down; see
`budzero/docs/BudL_SPEC.md`. Of the three things missing, one is fixed:

1. **Direction bits were unconstrained**: *fixed*. `merkle_bit` was only
   asserted boolean, never tied to `merkle_key`. Measured: flipping the round-0
   bit and recomputing the chain produced a different root that the AIR
   accepted, which is the whole security property of a Merkle path.
   `COL_MERKLE_KEY_REM` now carries `key >> round` and the AIR walks
   `rem == 2 * rem' + bit`, seeded from the key and terminating at zero.
2. **Siblings were not bound to memory**, *fixed*.
3. **The key was not bound to memory**, *fixed*.

(2) and (3) needed the path reads to enter the memory argument, which the VM
did not emit for the 65 words it reads. Measured: 64 expansion rows, none
carrying a `memory_addr`, and none of the 65 path words present in the
argument. Each expansion row now emits its sibling read and the original step
emits the key read, with the LogUp demanding them at addresses the AIR derives
(`imm` for the key, `imm + 8 + 8 * round` for round `r`) rather than the
prover choosing.

So the STARK side of `VerifyMerkle` is sound: the path a proof walks is the
path the program read, in the order the key describes, hashing to the root it
claims. `verify_merkle_enabled` stays false pending external review of the
opcode against a real sparse-Merkle-tree deployment, a process gate now, not
a known hole. Sequencing is unchanged: finish `VerifyMerkle`, then require
`proof_bytes`, then retire the `interim_availability_only` label.

## Gap 2: replica answers: **closed at the challenge layer**

### What was wrong

`ContentId::of_subrange` hashed the bytes and nothing else, so every operator
holding a replica of the same shard produced the *same* answer to a challenge.
Two attacks came free, both named in the SoK on decentralized storage networks:

- **outsourcing**: several operators keep one physical copy between them and
  collect a payment each, because any of them can produce the answer the others
  would have produced;
- **Sybil**: one machine registers N identities, claims N replicas, stores one.

### What changed

`ContentId::of_subrange_for_deal` binds the answer to
`(operator, deal_id, shard_id)`, and the provider's `prove`/`settle` path uses
it. A challenge can now only be answered by whoever holds *that deal's* copy.

Five tests cover it. Two state the gap directly: the unbound hash really is
identical across operators, and the bound one really is not. One checks the
same operator on two deals for the same shard still gets different answers, so
one response cannot cover two payments. One is end to end, a proof computed by
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
longer precompute one answer set and split the payments, they have to relay
each other's live challenges in real time, within the deadline, for every
challenge. That is a running cost and a detectable pattern rather than a
one-off setup.

## Gap 3: erasure coding: **schema and coder closed, coding correctness open**

`ShardRef` now carries a `kind` (`Data` or `Parity`) and `ContentManifest`
carries an `ErasureScheme { k, n }`: any `k` of the `n` shards reconstruct the
object.

Two things are not closed, and calling the whole gap closed hid both.

**Nothing computes the parity in production.** `encode_object` and
`to_manifest` are called from tests only; the manifest reaches the chain
already built by a client. The module carries a `WIRING: unwired` marker
saying so.

**The chain cannot check that a parity shard is parity.** It never sees shard
bytes, only their `ContentId` hashes. `validate_untrusted` verifies the counts
line up, data shards equal `k` and parity shards equal `n - k`, and stops
there, because checking the arithmetic would mean holding the bytes. Six
random byte strings declared `(k=4, n=6)` are accepted today. The manifest is
internally consistent, the id derives correctly, and reconstruction fails only
when a real loss makes someone try it, which is after the point of the
redundancy.

This is the same question Celestia answers with Bad Encoding Fraud Proofs: a
full node that holds the data reconstructs it, finds the commitment does not
match, and publishes a proof that light nodes can check. The cost there is
that the proof is proportional to the data, which is why they moved to a
two-dimensional code, one row or column suffices. The alternative family is a
polynomial commitment or a FRI proof that the leaves are close to a
Reed-Solomon codeword, which proves correct coding without downloading
anything.

B.U.D. is closer to the first shape than it looks. `RetrievalChallenge`
already asks an operator for a byte range and verifies the hash of what comes
back, so the machinery for "someone holds the bytes and can be asked" exists.
What is missing is a challenge whose subject is the coding relation across
shards rather than the contents of one shard. That is a design item, and it
belongs on this list rather than inside a gap marked closed.

The saving is the point of the gap. For the same loss tolerance:

| scheme | tolerates | stored per byte |
|---|---|---|
| replication ×3 | 2 losses | **3.0×** |
| `(k=4, n=6)` code | 2 losses | **1.5×** |

`with_erasure` refuses a scheme the shard list cannot deliver, `n` has to
equal `shard_count`, `k` has to equal the data shards present, and the
difference has to equal the parity shards present. A manifest claiming
tolerance it does not have is worse than one claiming none, because a repair
trigger reads the claim and concludes the object is safe.

Manifests written before this deserialize to `ShardKind::Data` and
`ErasureScheme::default()`, which is replication, exactly what they were.
`legacy_json_deserialises_without_the_new_fields` pins that.

### The coder

`src/storage/erasure.rs` computes the parity and rebuilds from it:

```rust
let enc = encode_object(&bytes, ErasureScheme { k: 4, n: 6 })?;
let manifest = enc.to_manifest()?;          // 4 Data + 2 Parity shards
let bytes = reconstruct_object(&manifest, &survivors)?;  // any 4 of the 6
```

Encoding is a matrix product over GF(2^8) with a systematic generator: an
identity block on top, so data shards pass through byte-for-byte and reading
an intact object needs no decode pass, and a Cauchy block underneath that
produces the parity. The Cauchy entries are `1 / (x_i + y_j)` over disjoint
index sets, which makes every square submatrix invertible, the MDS condition
(Blomer et al., Theorem 2.2). That is what makes recovery work from
*whichever* `k` shards survived rather than a privileged subset; a Vandermonde
block does not give it for free, because a Vandermonde matrix over a finite
field can have singular submatrices even when the full matrix is invertible.
`any_k_of_n_reconstructs_the_object` walks every one of the 15 two-loss
patterns of a `(4,6)` code rather than a convenient one.

**Why not a dependency.** `reed-solomon-erasure` is what this document
previously named. Its owner stopped maintaining it in 2021 and asked for a new
owner (darrenldl/reed-solomon-erasure#88); Solana, its largest user, moved
off. `reed-solomon-simd` is maintained, but its speed comes from
target-specific `unsafe` and `src/lib.rs` is `#![forbid(unsafe_code)]`. The
in-tree coder is table-driven finite-field arithmetic with no dependencies and
no `unsafe`.

**Reconstruction is verified, not assumed.** The inverse matrix mixes every
survivor into every recovered shard, so a single corrupted survivor silently
poisons the whole object, the output still looks like plausible bytes.
`reconstruct_object` re-derives each shard's `ContentId` and checks it against
the manifest before returning, turning that into a detected failure
(`a_corrupted_survivor_is_caught_not_propagated`).

### Two things the schema alone got wrong

Landing the coder surfaced two gaps in the manifest that replication had been
hiding.

**The object's length was not recorded.** `total_size` is the sum of the
stored shard sizes. Under replication that is also the object's length, so
nothing had to tell them apart. Erasure coding separates them twice: parity
shards are stored bytes that are not object bytes, and the last data stripe is
zero-padded to keep shards equal-length, which Reed-Solomon requires. A
reconstructor holding only the manifest could not find where the object ended,
and would return trailing zeroes as content. `content_size` records it;
manifests written before the field read it as `total_size`, which is what they
meant.

**`kind` and `erasure` were outside the manifest commitment.** V1 hashed
`(index, shard_id, size)` per shard and nothing else, complete while
replication was the only scheme. Erasure coding added two fields that change
what a manifest *means* without changing any byte V1 hashed. Measured:

```
kind flipped Data -> Parity, id unchanged -> true
```

Relabelling a data shard as parity changes which shards a reconstructor treats
as content. Worse, `k` is the number a repair trigger compares against: a
manifest claiming `k = 1` when four shards are needed reads as safe at one
surviving shard, so no repair ever opens and the object is lost quietly. Both
are now bound by `manifest_id_from_parts` under `BDLM_MANIFEST_V2`.

## Gap 3b: is the parity actually parity: **sampled**

Gap 3 gave the chain a coder and bound `(k, n)` into `manifest_id`. Neither
answers a question that only appears once parity exists: an operator paid to
hold parity shard `i` can store anything at all under that shard's
`ContentId`, and a retrieval challenge cannot tell.

The retrieval challenge asks whether the operator still has the bytes. That
is a different question from whether those bytes satisfy

```
parity_i[c] == XOR_j coeff(i, j) * data_j[c]
```

An operator storing garbage passes every retrieval challenge it is given. The
discovery happens during the repair that needed the parity, which is the one
moment the object cannot afford it.

### What was built

Reed-Solomon works symbol-wise, so a single byte column is a complete,
self-contained instance of the relationship. `derive_coding_audit` reduces
block entropy into a parity index and a column; `verify_coding_audit` runs
the answer through the same coder the encoder uses.

```
audit cost:  k data bytes + 1 parity byte
full check:  every data shard, end to end
```

A `(4, 6)` audit reads five bytes whether the object is 800 bytes or 800 MB.

### What a pass means, exactly

That the relationship holds at that column. An operator who miscomputed a
fraction `f` of columns fails a uniformly random one with probability `f`, so
`r` rounds leave a cheat standing with probability `(1 - f)^r`:

| corrupted fraction | 1 round | 50 rounds |
|---|---|---|
| 1% | 1.0% | 39.5% |
| 5% | 5.0% | 92.3% |
| 10% | 10.0% | 99.5% |

This is the trade provable-data-possession schemes have always made. Ateniese
et al. measured it as 460 sampled blocks out of 10,000 detecting a 1%
deletion with 99% confidence.

### What it does not do

It does not prove the operator *stores* anything. Parity can be computed on
demand by someone holding nothing, and bytes can be held that are not parity.
The two questions are separate and answering one does not answer the other.

It also refuses replicated objects rather than passing them. There is no `i`
to range over when every shard is data, and a pass there would report an
audit that never happened, on the objects with no redundancy to lose.

### Still open

Nothing opens these audits on a schedule yet. `derive_coding_audit` and
`verify_coding_audit` are the mechanism; a production path that samples live
deals is the next step, along with what a failed audit costs the operator.
Recorded here rather than left for a reader to find: the arithmetic is real
and the trigger is not there yet.

## Gap 4: repair trigger: **closed**

With `k` known, "how much redundancy is left" is a number, and repair becomes a
condition rather than a wish:

```rust
manifest.is_recoverable(live)        // live >= k
manifest.needs_repair(live, margin)  // k <= live < k + margin
```

Repair fires with headroom, not at the edge. Waiting until `live == k` means
the next loss is fatal with nothing in flight, Storj triggers on a safety
threshold above `k` for the same reason.

`needs_repair` returns false once the object is already unrecoverable: there is
nothing to reconstruct from, and a repair deal opened then would only burn an
operator bond. Both directions are pinned by tests.

**Wired:** the maintenance sweep in `chain_actor` calls
`objects_below_own_repair_margin` each epoch, logs the band, and for every
shard with zero active replicas opens an expiry-reallocation ticket against a
historic deal when one exists. Unrecoverable objects are surfaced on a separate
list so they cannot hide inside the repairable set. The `repair-fires` gate
pins the presence of those call sites. A never-placed shard still has no ticket
type; that residual is logged rather than papered over.

## Gap 6: what a failure costs: **closed**

Losing the bond was the whole punishment for missing a challenge, and a bond
is a price. An operator can pay it, re-register, and fail again; the cost is
linear in failures and buys the network nothing back.

A second cost now runs alongside it. `MISSED_CHALLENGE_COOLDOWN_SECS` keeps
the operator out of new deals for six hours. Existing deals continue, because
cutting them would leave those shards under-replicated immediately and the
punishment would land on the client rather than the operator.

The constant is in seconds rather than epochs. An epoch is
`slot_duration_secs * epoch_length_slots`, both governance parameters, so a
cooldown expressed in epochs would silently become four hours or twelve the
next time either was tuned. A punishment whose severity moves with an
unrelated timing knob cannot be reasoned about.

`begin_operator_cooldown` extends and never shortens. A second failure while
one is running takes the later of the two expiries, which is the only
ordering that cannot be gamed by failing again on purpose.

Both maps are hashed into the registry root. They decide who may open a deal,
so two nodes disagreeing about them would accept different blocks.

### Data that is no longer yours

The chain cannot reach into a machine and erase anything. What it can do is
state, where the operator's own software reads it, which shards are no longer
that operator's to serve: `stale_shards_for`. A node coming back from an
outage asks and deletes what it finds. Storj's bloom filter has the same
shape: the network says what should still be there and the node removes the
rest.

It is derived, not stored. A list written at slash time would go stale the
moment a replacement deal handed the same operator the same shard again, and
an operator deleting data it now legitimately holds is worse than one keeping
data it should not.

### Phones cannot hold the primary

`OperatorClass` is `AlwaysOn` or `Mobile`, and only the first may take
`replica_index = 0`. The primary is the copy a reader reaches for first and a
repair rebuilds from; a device online when its owner is awake cannot be that.

The class is self-declared and unverifiable. The chain does not try to verify
it, it holds the operator to the claim: declaring `AlwaysOn` to reach a
primary means accepting a primary's obligations, and a phone that does so
loses its bond the first time it sleeps through a challenge.

**Still open.** Nothing declares a class yet. `set_operator_class` cannot
simply be wired to a caller, because one account reclassifying another as
mobile would lock it out of primary replicas; it needs a signed transaction
type, which is its own change. Until then every operator is `AlwaysOn` by
default and the mobile rule is enforceable but unexercised.

## Gap 5: challenge economics: **measured and partly closed**

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
operator answers correctly, which is exactly the case a griefer wants, the
goal is to burn disk bandwidth, not to win a slash.

### What changed

`opener_bond` now has to cover the range being challenged:

```
required = max(MIN_OPENER_BOND, ceil(range_len / 1024) * OPENER_BOND_PER_KIB)
```

A 16 MiB challenge needs 16384 units instead of 1. Rounding is up, so the last
partial KiB is not free.

This does not make griefing *expensive*: the capital still comes back, but it
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

1. **Gap 2** (replica encoding): the challenge-layer half has landed;
   per-replica byte encoding remains and still changes the stored format.
2. **Gap 3** (erasure coding): **closed**: schema, coder, and verified
   reconstruction.
3. **Gap 1** (real storage proof): blocked on `VerifyMerkle`.
4. **Gap 4** (repair): **closed** - predicates, coder, and maintenance wiring landed; residual never-placed shard ticket type remains. Prior note was:
   the deal lifecycle remains.
5. **Gap 5** (bond calibration): measured; the range-proportional bond has
   landed, calibrating `OPENER_BOND_PER_KIB` and moving the rate limit to a
   per-operator ceiling remain.

Gaps 1, 2 and 3 all change on-disk or on-chain formats. Doing them before B.U.D.
is included in mainnet avoids a migration; doing them after does not.

## What a reduction claim is allowed to say

Every saving in `src/storage/` was measured, and for a while the totals were
still wrong. The measurements were right; the weights were guesses.

A published crawl of a comparable content-addressed network (Trautwein et al.,
*A Closer Look into IPFS*, ACM POMACS 2024) measured the same corpus two ways:

| class | share of files | share of bytes |
|---|---|---|
| JSON (NFT metadata) | 40.2% | 0.09% |
| image | 34.8% | 58.4% |
| video / stream | 13.8% | 33.6% |
| unknown (binary) | 5.7% | 7.1% |
| HTML / text | 0.2% | 0.07% |

JSON is two fifths of the objects and under a thousandth of the volume, a
factor of 447. Storage is billed in bytes, so a lever weighted by object count
is weighted by the wrong unit, and the shared-dictionary result (a measured
49% to 92% on small structured objects) applies to 0.16% of the bytes.

Reweighted by volume, the whole-corpus multiplier is 0.82x against today's 3x
replication, a **72.6% reduction**, which is below the pessimistic end of the
74.8%-93.3% range previously quoted here. The range was wide only because the
weights were estimates, and the pessimistic end was still optimistic.

Zeroing each class in turn says where the remaining volume is:

| class zeroed | resulting multiplier | gained |
|---|---|---|
| image | 0.364x | 0.458 |
| video | 0.482x | 0.339 |
| unknown binary | 0.797x | 0.024 |
| JSON | 0.821x | 0.0003 |

So the rule this project holds itself to: **a reduction claim states both
units or neither.** "40% of your objects are free" and "0.1% of your bytes are
free" are the same measurement, and each on its own misleads a reader in the
opposite direction. `DerivedSpec::stored_versus_independent` returns a pair
rather than a ratio for this reason, and
`check-derived-content-stays-byte-exact.sh` refuses a version that collapses
it to one number.

The derived-content path exists because of this table. It is the only lever
that reaches a zero multiplier inside the image class, which is where 58.4% of
the bytes are, and it stays byte-exact: measured on quantised DCT
coefficients, a block-aligned crop reproduces the master's own coefficients
exactly, while a misaligned one reproduces none of them.

## References consulted

- Filecoin PoRep / PoSt: per-replica encoding, iterated proofs
- Walrus (RedStuff): 4.5× replication, self-healing, asynchronous challenges
- Storj: erasure coding vs replication durability analysis, repair thresholds
- CrustChain: hybrid Reed-Solomon + network coding cost figures
- SoK: Decentralized Storage Networks: Sybil and outsourcing attack taxonomy
- Trautwein et al., *A Closer Look into IPFS: Accessibility, Content, and
  Performance*, ACM POMACS 2024 (DOI 10.1145/3656015): measured corpus
  composition, by file count and by volume
