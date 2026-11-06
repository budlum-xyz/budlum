# src/storage

The storage layer is B.U.D. 3.0. The key-value store that used to live
here moved to `src/persistence/` (it is node-local durability, not content
storage); the content stack under `bud3/` is the single content storage
system.

## The module tree

| Module | Content |
|---|---|
| `bud3/content_id` | `ContentId`: SHA-256 and length for public content, keyed HMAC-SHA-256 and length for sealed content |
| `bud3/content_ref` | `ContentRef`, the temporary interface dependent modules compile against |
| `bud3/limits` | Profiles (P0) and the genesis limits |
| `bud3/meter` | The parser and decoder budget |
| `bud3/varint` | Bounded LEB128 |
| `bud3/bof1` | The object: canonical binary header and payload |
| `bud3/segment` | Segmentation, segment digests and the object commitment |
| `bud3/fountain` | RFC 6330 per-segment encoder and decoder |
| `bud3/placement` | Stake-weighted rendezvous placement, diversity caps, the placement table |
| `bud3/registry` | Chain state: objects, dedup, references, deletion, shares, audits |
| `bud3/tx` | The storage transaction and its one apply door |
| `bud3/custody` | Sub-block tree, symbol root, the audit draw and custody proofs |
| `bud3/pipeline` | Upload (content to record and symbols) and view (symbols to checked content) |
| `bud3/dedup_index` | The node-local dedup filter in front of the public index |
| `bud3/access_tiering` | Tier transitions |
| `bud3/replace` | Object replacement under a stable content id |
| `bud3/meter` | Parser and decoder budget |

The remaining module homes of the plan (object presentation frames, the
optical paths, the view sessions, the fee surface and the gateway adapter)
are filled by the rebuild packages, each ported from the 2.0 implementations
recovered from git history (see `docs/STORAGE.md`).

## Rules this layer enforces

- The commitment is fixed-size (32 bytes); the object is not fixed-size.
- The fee input is the physical byte (object bytes times redundancy).
- A sealed flag (BOF-1 `flags` bit0) binds to the keyed content id and to
  the object commitment (`docs/STORAGE_ENCRYPTION.md`).
- Content registration requests are refused with `Bud3NotReady` until the
  registry door is wired in.
