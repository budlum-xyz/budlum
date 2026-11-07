# Light Client

A light client verifies that a block is final without downloading or replaying a
single transaction. It starts from one commitment it was given out of band and
advances that commitment by verifying finality proofs. Everything in this document
describes code that exists in this tree today:
[`src/light_client/mod.rs`](../src/light_client/mod.rs) for the verifier and
[`src/bin/budlum-light.rs`](../src/bin/budlum-light.rs) for the command-line driver.

## The trust anchor

The client holds exactly one thing it cannot prove, and the code names it:

| Field | Meaning |
|---|---|
| `height` | The block height the client trusts |
| `block_hash` | The canonical block hash at that height |
| `set_hash` | The hash of the validator set that finalized that height |

Both hashes must be canonical 64-character hex digests, and bootstrap refuses
anything else (`LightClient::new`). The anchor must come from outside the data being
verified. An export that carries its own trust anchor proves nothing, in the same way
a signature that carries its own public key proves nothing.

## What verification adds

Every step below produces a verdict, not a suggestion. A refusal is a typed
`LightClientError` carrying the reason, never a boolean.

1. **Header chain.** `verify_header_chain` walks headers strictly above the anchor
   and requires each one to be hash self-consistent, contiguous, and parent-linked,
   starting at `trusted.height + 1` and `trusted.block_hash`. Headers that pass are
   recorded in a map keyed by height.
2. **Certificate binding.** A finality certificate is accepted only for a header
   that the map holds. A finalized header from an unrelated fork is therefore
   refused: the anchor cannot be moved by a certificate for a block nobody linked to
   the anchor.
3. **Quorum.** The BLS path checks the certificate's height, block hash, validator
   set hash, and then the stake-weighted quorum over the aggregate signature.
4. **Post-quantum half.** The hybrid path checks the same checkpoint again with the
   ML-DSA-65 quorum blob of the same signers. A blob with a duplicate signer is
   refused; a blob that does not bind to the certificate is refused.
5. **Move.** `advance` moves the anchor forward and prunes recorded headers at or
   below the new height.

## Two certificate paths, and the mainnet rule

| Path | Entry point | What it proves | Where it is allowed |
|---|---|---|---|
| BLS only | `verify_checkpoint` | The committee's stake-weighted BLS quorum | Testnet and devnet. Refused on mainnet |
| Hybrid | `verify_hybrid_checkpoint` | The BLS quorum and the ML-DSA-65 quorum of the same signers | Everywhere |
| Post-quantum only | `verify_pq_checkpoint` | The ML-DSA-65 quorum, judged under the scheme statuses the caller pinned | Everywhere |

`LightClient::for_chain` sets the mainnet rule from the chain id. A client built for
mainnet refuses a BLS-only checkpoint with a named error rather than degrading to
"less proof than the network requires". This is deliberate: a light client is the
easiest place in the system to quietly accept a weaker proof, and the refusal is the
only thing that stops it.

## The scheme registry, and why it is pinned

A client that judged signatures by genesis statuses would keep verifying a lattice
family that the network has already disabled after a Frost Alarm demotion. The
verdict on a signature and the network's verdict on the same signature would then
differ, and the client would advance its trust anchor on a checkpoint the network
rejects.

The wire carries no registry, so `with_scheme_registry` pins one, exactly as the
anchor is pinned. Omitted means genesis statuses, which is correct only for a chain
that has never moved a scheme out of its genesis state.

## Validator-set change

`advance` refuses a checkpoint whose `set_hash` differs from the trusted one: a
certificate over another set is another chain, and following it without a new
out-of-band anchor would hand an adversary the client's trust.

The sanctioned path is `follow_handoffs`. It walks the Handoff Certificate chain
from the trusted set, checking only ML-DSA-65 signatures, so the move holds without
trusting BLS. The caller supplies `epoch_randomness` for each epoch on the way: the
certificate's own `randomness` field seats the handoff committee, so a certificate
may not be allowed to name it. The anchor height stays put; the next checkpoint
verified over the new set advances it.

## Global headers

`verify_global_header` binds a finalized checkpoint to an external chain's state
root: the header must have been built at the checkpoint's height, and the
checkpoint's state root must reopen from the supplied opening and the header hash.
The resulting chain of evidence is anchor, finality certificate, block, global
header, and from there any root the header carries. `bud_getGlobalHeaderProof`
returns the two fields the check consumes.

## Sync plan

`sync_plan` is the transport contract. It returns the `GetHeaders` locator, rooted
at the trusted block hash, and the next checkpoint height a certificate is needed
for. The transport is not part of this crate: the verifier says what to ask for and
what to do with the answer, and any transport that can carry those requests can
drive it.

`next_checkpoint_height` is closed form: one division and two checked additions,
with `None` when the anchor is already at or past the target. It does not walk the
interval. The previous implementation walked up to the interval and looped at the
`u64::MAX` boundary; finding BLG-022 in the register is what this shape answers.

## Trust modes, stated for the user

`TrustMode` exists so that every answer the client gives can be shown next to the
assumption it rests on. `Committee` is what the client returns today, and it reads
"trusts a two-thirds majority of the validator set". The `Anchor` variant is a
declared surface whose doors are not in this tree yet, and the type says so at its
definition rather than in a document.

## The command-line driver

`budlum-light` verifies a chain export against an operator-supplied anchor:

```text
budlum-light --chain-file export.json --network testnet \
  --trusted-height <h> --trusted-hash <64 hex> --trusted-set-hash <64 hex> \
  [--checkpoint-interval <n>] [--target-height <h>] \
  [--require-global-headers] [--scheme-registry registry.json]
```

The export carries the validator-set snapshot, the headers, the certificates or the
QC blobs, and optionally the global-header openings. The network is a command-line
decision and never a value read from the file: an export whose headers name another
chain is refused before anything is verified, because otherwise the exporter would
choose the verifier's security level.

## Error taxonomy

| Variant | Raised when |
|---|---|
| `MalformedHash` | A hash is not a canonical 64-hex digest |
| `InvalidHeader` | A header is not hash self-consistent |
| `CertificateBinding` | The certificate does not bind to the header it claims to finalize |
| `TrustBinding` | The certificate or snapshot does not bind to the trusted set |
| `VerificationFailed` | The cryptographic quorum check failed, or a path is refused on this network |
| `NotForward` | The move is backwards or sideways |
| `SetChanged` | The checkpoint is over a different validator set |
| `HeaderChain` | Headers are not contiguous, not parent-linked, or absent |
| `GlobalHeaderBinding` | The global header does not reopen the finalized state root |

## What the client does not do

1. It does not discover a trust anchor. That is an out-of-band decision, and the
   code refuses to pretend otherwise.
2. It does not follow a validator-set change without the handoff chain.
3. It does not download transaction bodies, balances or contract state. It proves
   finality; what a finalized root means is the reader's problem.
4. `requires_pq` and `follow_handoffs` have no caller in this tree yet. Both carry a
   `WIRING:` note saying so, which is the repository's convention for a declared
   surface that no production path consumes yet.

## Tests

16 tests in the module, each named for the property it protects rather than for the
function it calls: malformed anchor hashes, a real BLS checkpoint that advances, a
certificate for another header, a certificate over another set, a certificate below
quorum, a mainnet client refusing a BLS-only checkpoint, the PQ path with and
without a pinned registry, a duplicate signer in a blob, header contiguity, a
checkpoint whose header was never linked, the closed-form next-checkpoint
arithmetic, the sync-plan target, and the global-header state-root binding.
