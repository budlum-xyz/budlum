# Storage: B.U.D. 3.0

The single content storage system. A user uploads content; the system finds
its shortest complete representation (A0), writes the payload and the header
into an object (BOF-1), segments the object and codes each segment with
RFC 6330. The source and repair symbols ride the optical QR frames and the
custody shares at the same time. The network holds the symbols; the object
and the content are rebuilt on the viewer's device and shown only when the
rebuilt content hashes to the content id the record carries.

## The pipeline

| Step | Rule | Module |
|---|---|---|
| S0 classify | magic and signature, extension, entropy, size; a wrong class is safe | `crates/bud-codec` (classify) |
| A0 payload | one codec chain of the adopted lossless methods | `crates/bud-codec` |
| A1 object | canonical header plus payload | `src/storage/bud3/bof1.rs` |
| A2 segments | bounded segments, per-segment digests, one object commitment | `src/storage/bud3/segment.rs` |
| A3 symbols | RFC 6330 source and repair symbols per segment | `src/storage/bud3/fountain.rs` |
| placement | stake-weighted rendezvous, sticky, class-aware, capped per account and segment | `src/storage/bud3/placement.rs` |
| custody | sub-block tree, symbol root, the audit draw, custody proofs | `src/storage/bud3/custody.rs` |
| registry | objects, dedup, references, deletion, shares, audits | `src/storage/bud3/registry.rs` |
| transactions | the storage transaction and its one apply door | `src/storage/bud3/tx.rs` |

The commitment is fixed-size (32 bytes). The object is not: it is the header
plus the payload, at most one header larger than the content.

## Fees

The fee input is the physical byte: object bytes times redundancy. A shared
public object divides its physical bytes equally among the NFTs that
reference it. The fee record splits the physical bytes into the user's share
and the decentralization share.

## Where the 2.0 source material lives

The B.U.D. 2.0 implementations are the build material the rebuild packages
port; they are not thrown away. The adopted lossless codec methods are
already ported into `crates/bud-codec/` (the source-mapping table of the
removal plan). The rest is recovered from git history and adapted:

- the compression tree at its last full state: commit `81459e0`
- the legacy storage stack, domain and gateway layers: commit `8458de3`

The empty module homes (`object`, `frame`, `qr`, `video`, `receive`,
`verify`, `upload`, `view`, `nft`, `classify`, `hooks`, `meter`,
`visibility`, `keys`, `seal`, `grants`, `delete`, `fees`,
`content_gateway`, `dictionary`, `repair`, `volume`, `maintenance`) are
filled in the packages the plan assigns them to, each ported from the
recovered code and re-cast to the rules above: content ids, the object
format, fountain codes and the sealed flag.

## Related documents

- `docs/STORAGE_ENCRYPTION.md`: sealed content and key delivery.
- `docs/ARCHITECTURE.md`: where the storage layer sits in the node.
