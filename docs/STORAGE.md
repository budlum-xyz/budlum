# Storage: B.U.D. 3.0

B.U.D. 3.0 is the only storage system of the network. This page says where its
code lives, what a read and a write do, and which parts of it are not finished.
The rule that no other storage system stays in the tree is enforced by the
`no_legacy_storage` gate.

## Where the code is

| Path | Role |
| --- | --- |
| `src/storage/bud3/bof1.rs` | The B.U.D. 3.0 object format (BOF-1): header, flags, object commitment. |
| `src/storage/bud3/content_id.rs` | Content identity and the content key. |
| `src/storage/bud3/segment.rs` | Segmentation, segment digests and the object commitment. |
| `src/storage/bud3/fountain.rs` | RFC 6330 symbol coding for the repair symbols. |
| `src/storage/bud3/placement.rs` | Class aware placement of segments on validators. |
| `src/storage/bud3/custody.rs` | Custody proofs: a stored segment answers an audit with a sub block path. |
| `src/storage/bud3/dedup_index.rs` | Reference counting and the deduplication index. |
| `src/storage/bud3/limits.rs` | The per profile object limits (`Bud3Limits`, `Profile`, `ProfileId`). |
| `src/storage/bud3/meter.rs` | The meter that prices physical bytes. |
| `src/storage/bud3/pipeline.rs` | The upload and read pipeline. |
| `src/storage/bud3/registry.rs` | The registry the pipeline writes to. |
| `src/storage/bud3/tx.rs` | The `StorageTx` v3 wire form. |
| `src/storage/bud3/varint.rs` | The canonical variable length integer. |
| `src/storage/db.rs` | The sled database, its snapshots and the restore path. |

The modules are re-exported from `src/storage/bud3/mod.rs`, so a caller writes
`crate::storage::bud3::pipeline`, not a deep path.

## Properties the gates hold

1. **Every content class is an object.** An empty payload is an object too. The
   `bud3_object_is_universal` gate holds this.
2. **QR is a presentation, never an identity.** No QR module or PNG byte enters a
   content id or a durable record. The `bud3_qr_is_presentation` gate holds this.
3. **The sealed flag is bound.** A sealed object binds the flag to the content id
   and to the object commitment, so a rewritten flag invalidates the object. The
   `content_encryption_is_declared_and_bound` gate holds this.
4. **The fee input is the physical byte.** Compression and coding change the
   price only through the bytes they actually save. The
   `bud3_fee_uses_physical_bytes` gate holds this.
5. **A missed audit costs reward, it is not a slash.** The
   `bud3_custody_rewards` gate holds this.

## Status

The modules above are in the tree. Two limits of this page are deliberate:

- No test run is recorded in this document. Test results come from CI, and a
  number that no run produced is not written here.
- The B.U.D. 3.0 acceptance suite of the launch gate (T1 to T12, T14 to T26,
  T34 to T41, plus the nightly T3, T4, T6, T7 and T17) is not recorded as green
  in `docs/audit/TLG_REPORT.md`. The report is the place where that changes.

Related pages: [content encryption](STORAGE_ENCRYPTION.md),
[execution limits](EXECUTION_LIMITS.md), [work package register](work/PACKAGES.md).
