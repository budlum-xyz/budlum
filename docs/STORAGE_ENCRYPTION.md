# Storage encryption: sealed content

A sealed object encrypts its payload. The compression happens first; the
seal is last.

## The declaration and its bindings

The declaration is one bit: BOF-1 `flags` bit0. The bindings are two:

1. The content id of sealed content is the keyed HMAC-SHA-256 of the content
   under the owner's mac key, and the content length. Only a granted key
   derives the id, so an ungranted reader cannot even name the content.
2. The object commitment covers the header bytes, so the sealed flag rides
   into every custody share and cannot be swapped out per holder.

A public object uses SHA-256 and the length. The id kind matches the flag:
a sealed flag with a bare digest is refused at the object door.

## Key delivery

The chain carries no key material. The view grant delivers the key through
an HPKE package to the grantee's public key, and the sealed-object consent
is signed with ML-DSA-87 (the consent format of the sealed object rule).
The view path opens the grant, decrypts the payload and then verifies the
content id before showing anything.

## Cipher rules

Only authenticated ciphers. Compression runs before encryption, never
after; an encryption step that runs before compression destroys the
compression gains and invites compression-oracle style probing.

## What the chain verifies

The chain verifies the bindings above and the grant signatures. It cannot
and does not verify the secrecy of a key after delivery: key custody is the
client's, and crypto-shredding (burning the NFT that carries the grant) is
how access is revoked.

## What this document does not claim

It does not claim metadata privacy (the record is public), and it does not
claim protection against a compromised client device.
