# B.U.D. content encryption: what the chain says and what it does not

This document explains what the `ContentManifest.encryption` field is and,
more importantly, **what it is not**. The second part is longer, because the
most dangerous state of a security field is being believed to carry a
guarantee it does not carry.

## The measured state: nothing was being said

Before this field was added there was not a single line of encryption in
`src/storage/`, and **not a single declaration** about encryption either.
Every manifest was silent, so everyone reading that silence drew their own
conclusion:

- An operator holding a shard did not know whether the bytes in hand were
  readable content.
- A client that tried to decrypt and failed could not tell a wrong key from a
  corrupt shard.
- The repair path redistributed the bytes it recovered without knowing
  whether they were cleartext.

Silence is not a default; it is an unanswered question.

## The chain cannot encrypt

`src/storage/` is an on-chain commitment layer; it holds no bytes. So the
chain can neither encrypt nor verify that someone else did. A manifest saying
`ClientSide` is a fact **declared** by the uploader.

The only thing the chain can do is carry that declaration and make it
**immutable**. The only way to make it immutable is to put it inside
`manifest_id`. A claim left outside the commitment can be rewritten under a
fixed identity:

```text
1. The uploader records the manifest as ClientSide.
2. A node serves a manifest saying Plaintext under the same id.
3. Every later reader concludes the bytes it fetched were never protected.
```

That is why the gate checks not the presence of the field but its
**boundness**: `scripts/check-content-encryption-is-declared-and-bound.sh`
catches, with a separate canary, the case where the commitment function takes
the argument and discards it without reading, because every signature-based
check passes in that state too.

## Commitment V3

`manifest_id_from_parts` now covers three things:

| Version | Coverage | Why it was added |
|---|---|---|
| V1 | `(index, shard_id, size)` | the original form |
| V2 | `+ kind, k, n` | the parity tag and the redundancy claim could be altered |
| V3 | `+ encryption declaration` | the confidentiality claim could be rewritten under a fixed id |

The domain string is `BDLM_MANIFEST_V3`. Adding a field without advancing the
domain string would let V2 and V3 identities carry different meanings and
still collide on the same value.

The `Plaintext` tag is 0, and every manifest written before this field was
added deserializes as `Plaintext`. This is not an interpretation but a
measured fact: those manifests were written by a tree that contained no
encryption at all. Making `ClientSide` the default would invent a
confidentiality claim nobody made, which is worse than making no claim,
because a reader would trust it.

## No key material is carried

The declaration **does not** carry: a key, a key identifier, a wrapped key, or
a nonce. A key placed in a public commitment is a key published to a public
chain. One of the tests (`the_declaration_carries_no_key_material`) locks the
width of the type to two bytes, and the gate scans the field names. Together
they stop a "let us just add one wrapped key" change from passing silently.

Key delivery is the job of the access-grant layer: `AccessGrant` on chain
first, with the DM as notification only.

## Why only authenticated ciphers

`ContentCipher` names three AEADs: AES-256-GCM, ChaCha20-Poly1305, and
XChaCha20-Poly1305. An unauthenticated mode was deliberately left out.

The 2024 study "End-to-End Encrypted Cloud Storage in the Wild" showed that
unauthenticated CBC mode in Icedrive let the server reshape the ciphertext;
the same study measured that unauthenticated chunking in Seafile let the
server assemble new files out of chunks of other files that still decrypted
validly. Naming an unauthenticated cipher here would mean the manifest
declares confidentiality while leaving integrity to the node holding the
bytes.

## The one thing the chain can verify

There is a single arithmetic check: all three named ciphers append a 16-byte
authentication tag, so even a zero-length plaintext encrypts to 16 bytes. An
object that declares `ClientSide` and is shorter than 16 bytes is not the
output of any of these ciphers.

This check catches the **careless case**, not the determined attacker. A
writer who wants to lie adds padding. It is still worth having, because the
form that reaches the field is the careless one: a client that forgets to
encrypt but remembers to declare produces exactly this shape when the object
is small.

The tests `an_object_at_the_tag_length_is_accepted` and
`a_small_plaintext_object_is_untouched_by_the_tag_check` lock the fact that
this bound refuses only the impossible and does not reach ordinary small
objects.

## What this document does NOT claim

To avoid overstating the scope, explicitly:

1. **Nothing is verified as encrypted.** The chain sees no bytes.
2. **Shard bytes are not verified as consistent with the declaration.** An
   uploader can say `ClientSide` and upload cleartext; beyond the 16-byte
   bound there is no mechanism that catches it.
3. **Key distribution is not solved.** The declaration does not say how the
   key arrives.
4. **The operator is not forced to honour the declaration.** An operator
   seeing `Plaintext` can read the content, and nothing prevents that reading.
   A TEE on the storage node is being designed for this; it does not exist
   yet.
5. **Encryption is not mandatory.** `Plaintext` is a valid state.

Of these, (1) and (2) cannot be solved on chain. Items (3), (4) and (5) are
follow-up work.
