# Light client trust model

This document states what a Budlum light client trusts, what it verifies,
and what it costs a phone to verify it. It answers the second half of
BLG-259 (the undocumented trust model); the certificate format that sets the
sizes below is WP-12's. Every behaviour named here is in
`src/light_client/mod.rs` unless the section says it is planned.

## The one thing a light client trusts

A light client starts from a single trust anchor, `TrustedCheckpoint`:

| Field | Meaning |
|---|---|
| `height` | A finalized checkpoint height |
| `block_hash` | The block hash at that height, a canonical 64-hex digest |
| `set_hash` | The hash of the validator set that finalized it |

The anchor is not fetched from the network. It arrives out of band, and a
release of the mobile application embeds one: that is the weak-subjectivity
checkpoint of WP-11 job 3 and the mitigation of risk R-27 (a long-range
attack that leads a client to a forged chain). `LightClient::new` refuses an
anchor whose hashes are not canonical, because a malformed anchor would
poison every later verification.

The chain's scheme status registry (which signature families the chain has
enabled or disabled) is also pinned out of band, with
`LightClient::with_scheme_registry`. It is consensus state, not wire data;
without it the client verifies under the genesis statuses, and a family the
chain has since disabled would keep verifying.

Everything else the client receives (headers, certificates, validator set
snapshots, handoff certificates) is untrusted input and is checked against
the anchor.

## What it verifies

### Headers

`LightClient::verify_header_chain` links a run of headers to the anchor by
hash. A header that is not linked to the anchor cannot be the subject of a
checkpoint. Transaction bodies are never downloaded or replayed.

### Checkpoints: BLS at every checkpoint

A checkpoint is proven by a `FinalityCert`, a BLS aggregate signature over
the checkpoint by a quorum of the trusted set (BLS12-381 in the min-sig
arrangement: a 48-byte signature in G1, 96-byte public keys in G2, hashed to
the curve per RFC 9380). `LightClient::verify_checkpoint` checks, in order:

1. the validator set snapshot is self-consistent: its `set_hash` and total
   stake are recomputed from its member list, so a crafted snapshot cannot
   lower the total and let a minority pass the quorum;
2. the header hashes to itself and is linked to the anchor;
3. the certificate names exactly that header (height and hash);
4. the certificate and the snapshot carry the trusted `set_hash`;
5. the aggregate signature verifies and carries the stake and signer quorum.

A certificate whose `set_hash` differs from the trusted one is refused. It is
never silently followed: a set change is handled only by the handoff chain
below.

### Mainnet: the post-quantum half is required

A client built with `LightClient::for_chain` for the mainnet chain id refuses
a BLS-only checkpoint. It advances only through
`LightClient::verify_hybrid_checkpoint` (the BLS certificate plus the
ML-DSA-65 `QcBlob` of the same signers over the same checkpoint) or through
`LightClient::verify_pq_checkpoint` (the ML-DSA-65 quorum alone, with the same
binding chain and the same stake and count quorum, and no validator counted
twice). On testnet and devnet the BLS certificate alone advances the anchor.

### Set changes: post-quantum handoffs only

When the validator set changes, `LightClient::follow_handoffs` moves the
trusted `set_hash` along the chain of `HandoffCertificate`s. Each step is
signed by the outgoing set and names the incoming set. Only ML-DSA-65
signatures are checked on this path, so the move holds without trusting BLS:
a quantum adversary that can forge BLS signatures still cannot hand the
client to a set of its choosing. The epoch randomness that seats each
handoff committee is supplied by the caller from an independent source; a
certificate is not allowed to name its own randomness. The anchor height does
not move during a handoff; the next checkpoint verified over the new set
advances it.

This is the split BLG-259 asks to have written down: **BLS at every
checkpoint, post-quantum signatures at every set change.** On mainnet the
checkpoint carries the post-quantum half as well.

## What it costs a phone

The sizes below are computed from the signature sizes, not measured. They
assume WP-12's committee of 128 seats.

| Object | Computation | Size |
|---|---|---|
| ML-DSA-65 signature | FIPS 204 | 3309 bytes |
| BLS aggregate signature | one G1 point, compressed | 48 bytes |
| Seat bitmap | 128 bits | 16 bytes |
| Checkpoint, BLS half | aggregate signature plus bitmap | 64 bytes plus the header fields |
| Checkpoint or handoff, post-quantum, every seat signing | 128 x 3309 | 423 552 bytes (about 420 KB) |
| Same, at the smallest quorum | (floor(2 x 128 / 3) + 1) x 3309 = 86 x 3309 | 284 574 bytes |

So a testnet phone pays tens of bytes per checkpoint, and the post-quantum
cost only when the set changes. A mainnet phone pays the post-quantum half at
every checkpoint it verifies; that is the cost BLG-259 records as high for a
phone, and reducing it (fewer checkpoints verified, or a smaller
post-quantum attestation) belongs to WP-12 together with the certificate
format.

## What it does not do

- It does not execute transactions or recompute state roots. A verified
  checkpoint carries the header's `state_root`; a state proof is checked
  against that root by whoever needs one.
- It does not guarantee data availability. A certificate proves a quorum
  signed a header, not that the block's data can be fetched.
- It does not discover the anchor. If the embedded checkpoint is too old to
  link to the chain the client sees, the client warns and the response is to
  update the checkpoint (R-27); it does not pick a chain by itself.

## Status in the mobile core

The node's light client above is the reference implementation. The mobile
core (`mobile/core`, WP-11) must verify with the same types, and WP-11 job 1
moves the handoff and checkpoint certificate types into `crates/budlum-types`
for that (K-4). The move waits for WP-12, which changes those types (vote V3,
the seat bitmap, the handoff certificate signed by seat holders); moving
them before the format settles would move them twice. Until then the mobile
core carries no checkpoint verifier, and it does not carry one that accepts
everything either.
