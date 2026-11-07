# B.U.D. 3.0: storage

Status: under construction. This page states the target model and the part of it
that is in the tree with a test. It claims nothing that a test does not show.

## The one model

B.U.D. 3.0 is the only content storage system. Content becomes an *object*, an
object becomes *segments*, a segment becomes *symbols*, and the symbols are the
custody shares a validator holds and the payloads of the QR frames an optical
transfer carries. A validator never holds a whole object. There is no second
storage system beside this one: the retired 2.0 modules are removed by the
package that owns their path (WP-07), and the content pipeline in
`src/storage/bud3/` is what stays.

| Stage | Where | What it produces |
|---|---|---|
| BOF-1 object | `src/storage/bud3/bof1.rs` | The canonical binary object: header and payload |
| Segmentation | `src/storage/bud3/segment.rs` | Segment layout, segment digest, object commitment |
| Fountain code | `src/storage/bud3/fountain.rs` | RFC 6330 source and repair symbols per segment |
| Upload and view | `src/storage/bud3/pipeline.rs` | `ObjectRecord`, symbols, checked content |
| Chain state | `src/storage/bud3/registry.rs` | Objects, references, shares, audits, repairs |
| Transaction door | `src/storage/bud3/tx.rs` | `StorageTx` v3 |

## Segmentation and the fountain code

- The object bytes are cut into segments of `K_MAX x symbol_size` bytes; the last
  segment is shorter. With the canonical profile P0 (`K_MAX` 4096, symbol 2911
  bytes) one segment is 11 923 456 bytes.
- Every segment is one RFC 6330 source block, coded on its own, so there is no
  per-object source-block ceiling.
- All lengths and offsets are `u64`. Nothing in the layout or the streamer
  truncates at 4 GiB.
- The object ceiling is the genesis parameter `Bud3Limits::max_content_bytes`
  (TESTNET-DEFAULT 16 GiB). `fountain::check_object_ceiling` applies it, and
  `fountain::encode_stream` calls it before the first byte is read.
- The code is systematic: source symbols 0 to `k - 1` are the segment bytes, and
  repair symbols have an ESI at or above `k` and are derived, never stored.
  Symbol identity is the 24-bit ESI; there is no degree counter to saturate.

### What the retired carousel did

The 2.0 carousel (`src/storage/qr_carousel.rs`) repaired losses with a
low-degree random XOR rule and a `u8` degree cap. Past degree 255 the rule
saturated and its "independent" repair symbols began repeating each other, so a
large segment could not recover from loss (BLG-216). Its ceilings were `u32`
(preview 1 MiB, package 64 MiB, `k <= 4096`, video 50 000 frames), so an object
past 4 GiB was silently cut (BLG-213). The file sits on this package's own lock
path, so it is removed by the second half of WP-18 together with its call sites
in `qr_frame`, `qr_payload`, `qr_recipe`, `qr_receive`, `qr_reemit`, `qr_video`
and `emit`. Until that lands, both models exist in the tree and only B.U.D. 3.0
is on the target path.

## Tests that state the above

| Test | What it shows |
|---|---|
| `bud3_old_ceilings_are_gone` | 4096 source symbols and 2048 distinct repair ESIs; a repair symbol from ESI 20 000 is not a repeat and still builds the segment |
| `bud3_sixteen_gib_object` | A 16 GiB object is admitted by the genesis ceiling, refused one byte above it, and the layout has no `u32` truncation point |
| `bud3_fountain_acceptance` | `k + 2` distinct symbols recover the segment under independent and burst loss for `k` in `{100, 1000, 4096}`, at 99.99 % or better |
| `an_over_ceiling_object_is_refused_before_it_is_read` | The ceiling is applied before the reader is touched |
| `fountain_golden_vectors_lock_crate_version` | The pinned `raptorq` version produces the recorded symbols |

`bud3_fountain_acceptance` repeats each loss case `BUDLUM_BUD3_ACCEPTANCE_TRIALS`
times. The default keeps an ordinary test run short; the nightly figure of
10 000 trials is reached by setting that variable. `BUDLUM_BUD3_ACCEPTANCE_TRIALS=10000`.

The night-only cases the directive lists separately, T3 (64 MiB + 1 byte and
4 GiB + 1 byte under a memory ceiling) and T4 (16 GiB), need a 16 GiB corpus and
a measured peak, so they run against a generated corpus rather than in this
repository's default test run. What a test can state without that corpus is
stated above: the ceiling, the layout and the absence of a `u32` truncation
point are checked, and the peak memory is not claimed.

## Not in the tree yet

The upload and view paths (`pipeline.rs`), the chain state (`registry.rs`) and
the transaction door (`tx.rs`) exist and have their own tests, but nothing on the
block execution path reaches them: they carry a `WIRING: unwired` note. The
legacy 2.0 storage modules are still present, so the "no legacy storage" gate
(`no_legacy_storage`) does not exist yet. This page will say so until it does.
