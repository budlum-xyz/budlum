# Presence preimage v1

This vector locks directive invariant G-5: every hash input field, including
the domain tag, has an eight-byte little-endian length prefix.

| Field | Value | Encoding |
|---|---|---|
| Domain tag | `BDLM_PRESENCE_V1` | 16 ASCII bytes |
| Chain id | `45261` | u64 little-endian |
| Window | `11` | u64 little-endian |
| Class | Mobile | one byte, `01` |

`preimage.bin` is the concatenation of the four length-prefixed fields (65
bytes). `digest.bin` is its 32-byte SHA3-256 digest:

```text
26a5bec8b11098debd4eeffbe797638d295a08aa570cb3c176d9c5e41bfbb2a3
```

The mobile regression is `presence_preimage_matches_shared_golden_vector`.
It also checks class, window and chain-id separation. The vector was generated
independently with Python's standard `hashlib` and is checked by the Rust SHA3
implementation. It is a test vector, not a BLS interoperability measurement.

At review time PR #70 omits the length before the domain tag and instead hashes
to `f14a3db552fa9b83037c7b5f0a4749ff05ea1390b436b40c8b071ef45d6ab7fd`.
That difference is the presence finding recorded in PR #77 as BLG-288 and must
be reconciled before the node and phone can interoperate. This fixture does not
change a node wire format or claim the finding closed. Both implementations
must eventually use the shared types definition rather than duplicate it.
