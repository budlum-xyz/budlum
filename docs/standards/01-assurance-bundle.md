# Standard 1 - Assurance bundle (`FinalityGuarantee`)

| Field | Value |
|---|---|
| Hash for the bundle's own digest | none; the bundle is absorbed into standard 3's row/certificate preimages |
| Wire order | fixed, 17 bytes, all integers big-endian |
| Vectors | `docs/standards/vectors/assurance-bundle-v1.json` |
| Production source | `src/settlement/universal_finality.rs` |

The assurance bundle is the single object that answers *"what did you actually get?"*
for any finality claim reaching Budlum, whichever consensus family produced it. Every
other settlement decision - can value leave, is this domain quarantined, does a verifier
contract accept this attestation - is a function of these five fields and nothing else.

```text
FinalityGuarantee {
  reversibility       ProbabilisticWork{confirmations:u64}
                    | DataAvailabilitySampled{min_samples:u16}
                    | DeterministicQuorum
                    | CryptographicValidity
  quantum_posture     Classical | Lattice | Hash
  attestation         { state_root:bool, tx_root:bool, event_root:bool, parent:bool }
  slashable_backing   bool
  fault_tolerance_bps u16   (0..=10_000)
}
```

## Wire encoding

| # | Bytes | Rule |
|---|---|---|
| 1 | `reversibility_tag` u8 | `ProbabilisticWork` 0, `DataAvailabilitySampled` 1, `DeterministicQuorum` 2, `CryptographicValidity` 3 |
| 2 | `reversibility_param` u64 BE | confirmations for tag 0; `min_samples` for tag 1; **must be 0 for tags 2 and 3** |
| 3 | `quantum_tag` u8 | `Classical` 0, `Lattice` 1, `Hash` 2 |
| 4 | `attestation` 4 x u8 | `state_root`, `tx_root`, `event_root`, `parent`, each 0 or 1, in that order |
| 5 | `slashable_backing` u8 | 0 or 1 |
| 6 | `fault_tolerance_bps` u16 BE | must be `<= 10_000`; a value above the scale is clamped by `meet`, never wrapped |

Total 17 bytes. Two rules make the encoding non-negotiable: a zero parameter on an
unparameterised variant, and one boolean per byte rather than a bitfield. A bitfield
invites every reader to invent its own bit order, and an unparameterised variant
carrying a stale parameter makes `DeterministicQuorum{confirmations: 6}` a different
digest from `DeterministicQuorum{0}` for no semantic reason.

## The lattice: `meet` is the answer to "and also"

A bundle describing a *route* across N domains must be no stronger than the weakest
domain on it. `meet` is that fold, and it is a commutative, associative, idempotent
lower bound:

| Field | `meet(a, b)` |
|---|---|
| `reversibility` | same tag: keep the **smaller** parameter; different tags: keep the **lower-ranked** tag (rank = the tag value) |
| `quantum_posture` | the lower-ranked class |
| `attestation` | component-wise AND |
| `slashable_backing` | AND |
| `fault_tolerance_bps` | `min(a, b)` capped at 10 000 |

Folding order cannot change the result. A verifier that recomputes a route guarantee
from a set of domains in any order must arrive at the same bundle; the vector file pins
that with a permutation test, because a fold that is order-dependent is a bug that only
appears when the registry reorders, i.e. in production.

## Why each field is here

| Field | The attack it closes |
|---|---|
| `reversibility` | "final" from a PoW chain with 1 confirmation and from a BFT chain with a 1/3 quorum are not the same word. Averaging them is how a bridge loses money |
| `quantum_posture` | a domain that signs with ECDSA keeps ECDSA's own exposure, whatever Budlum's layer does; the bundle is the only place that fact survives into the verdict, which is why it is a field and not a comment |
| `attestation` | binding the state root but not the event root means logs are unauthenticated, so an "event finalised" claim is unsupported even though the block is final |
| `slashable_backing` | without escrowed stake, a wrong verdict costs the attester nothing, so the verdict is a prediction, not a guarantee |
| `fault_tolerance_bps` | the exact fraction of adversarial power the domain's own rule tolerates, so a consumer can price risk instead of assuming it away |

## Constants the derivation uses

| Name | Value | Meaning |
|---|---|---|
| `BPS_SCALE` | 10 000 | one basis point is `1/10_000` |
| `BFT_FAULT_TOLERANCE_BPS` | 3 333 | `floor(10_000 / 3) - 1`, optimal partially-synchronous BFT |
| `POW_FAULT_TOLERANCE_BPS` | 4 999 | honest-majority Nakamoto, `< 50 %` hashpower |
| `VALIDITY_PROOF_FAULT_TOLERANCE_BPS` | 9 999 | STARK soundness: bounded by hash collision resistance, not by a quorum |
| `MIN_VALUE_SAFE_POW_CONFIRMATIONS` | 6 | below this, `ProbabilisticWork` may not carry value without slashable backing |
| `MIN_TIER1_WORK_BITS` | 64 | cumulative difficulty below this is toy-chain work and carries no adversarial cost |

`9 999` and not `10 000` for validity proofs is deliberate: a claim of *perfect*
tolerance is a claim about a hash function nobody has proven, and a number that cannot be
met by any other family invites consumers to treat it as the ceiling of the market.

## The one decision the bundle makes

`admits_cross_domain_value()` - can value move out of this domain:

```text
false  if not attestation.event_root
false  if fault_tolerance_bps == 0 or > 10_000
true   if slashable_backing
true   if reversibility == CryptographicValidity
true   if reversibility == ProbabilisticWork{confirmations >= 6}
false  otherwise (DeterministicQuorum alone, DataAvailabilitySampled alone)
```

`DeterministicQuorum` alone does **not** open the value path. That is the least obvious
line in this document and the most load-bearing: a BFT domain with a healthy quorum, no
escrow and no validity proof has an economic security property Budlum cannot verify, so
its verdict is trusted for settlement and *not* for value transfer. An implementation
that "simplifies" this by treating deterministic quorum as strong enough will pass every
honest-path test and fail only during a correlated-forge.

## Derivation and honesty

The bundle is **derived from consensus state**, never declared by the submitter:
`FinalityGuarantee::for_domain` (internal domains), `for_proof` (validity proofs) and
`for_external_spec_declared` (external adapters). The last one is the honest limit of
this standard: an external adapter's bundle comes from its registered spec, so a
misregistered spec produces a wrong bundle that this layer cannot see. It is the reason
the settlement gate keeps `guarantee_backing_hash` in every row of standard 3 - the
declaration is at least pinned, so a quiet change of terms is detectable after the fact.

## Vectors

`docs/standards/vectors/assurance-bundle-v1.json` is the normative test set. Three rules make it checkable without trusting
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

## Boundary of this document

| Claimed | Not claimed |
|---|---|
| the encoding is total and injective for reachable values | that every domain's *real* security equals its declared bundle |
| `meet` is a lattice fold, order-independent | that a lower bound is a *tight* bound |
| the value gate is one decision point, tested | that 6 confirmations is enough against a given adversary budget - that is a pricing question, not a protocol invariant |
