# B.U.D. 2.0 Container Format - the .bud v2 spec (2026-08-16)

This document is the BYTE-LEVEL contract of the `.bud` v2 container and its chunk encoders.
Goal: an open, structured, machine-readable format (K72 - Data Act compliance) with verifier
tests (K38). The document and the tests together form the format's proof chain.

## 1. General principles

- **Losslessness completeness:** `restore(store(d)) == d` for EVERY d (including corrupt input).
- **Deterministic:** the same input -> the same bytes (a dedup/proof anchor).
- **Bomb protection:** every size field is bounded by ceilings (K25/K38).
- **Panic-free:** no parse path panics; corrupt input -> an error (None/Err).
- **Type independence:** the structural chunking type does NOT affect losslessness, only chunk
  granularity (dedup/proof efficiency).

## 2. BudV2File - the full file layout (little-endian)

```
+0   [8]  magic:        \xB5 0x55 0x44 0xB0 0x02 0x00 0x00 0x00
                         (high-bit prefix: it cannot be confused with file(1)/ASCII - S.47)
+8   [2]  codec:        u16 - the FormatCodec registry code (1=Json 2=Csv 3=Log 4=Text
                         10=Mp4 11=Jpeg 12=Png 16=Pdf 0=Unknown)
+10  [34] multihash:    [1] algo (0x16=SHA3-256) + [1] length (32) + [32] digest
+44  [4]  chunk_count:  u32 (ceiling: 1_000_000)
+48  [8]  total_len:    u64 - the total length of the chunk data (the STORED bytes)
+56  [1]  chunk_codec:  u8 - 0=Raw, 1=Huffman (ChunkCodec; unknown -> refused)
+57  [4]  count:        u32 - the chunk count (must equal header.chunk_count)
+61  ...  chunks:       each one:
         +0 [8]  len:   u64 - the chunk data length (ceiling: 64 MiB)
         +8 [32] cid:   content_id (SHA3-256, see below)
         +40[L]  data:  len bytes of chunk data (Raw is raw; Huffman is compressed)
```
Total length: `57 + 4 + sum(40 + len_i)`. Trailing bytes -> STRICT REFUSAL (tamper detection).

### content_id (K3/K31)
```
SHA3-256("BDLM_CONTENT_V1" || u64_le(length) || bytes)
```
- The root: `SHA3-256("BDLM_BUD_V2" || cid_0 || cid_1 || ... || cid_n)` - header.content_id.digest.
- A chunk cid is always computed over the STORED bytes (Raw: raw; Huffman: compressed).
- **The K31 decision (2026-08-16):** 32 bytes (SHA3-256) is KEPT - 256-bit collision resistance,
  about 128-bit post-quantum security (Grover halves it), and it fits the dedup index/proof size.
  If an upgrade to 48-64 B (SHA3-384/512, BLAKE3) is needed it is done through the `MultiHash.algo`
  field (K34): a reader REFUSES an unknown algo, the format does not break.

## K60 zero egress (the business model)

Access INSIDE the network (the same B.U.D. network / CDN / peer) has zero egress; only leaving to
the Internet is charged (`EgressZone`, `egress_cost`, `holds_egress`). Egress is not added to the
storage cost - access to user data is free (the R2-like zero-egress advantage).

### Verification (decode)
1. magic, the version bit, algo == 0x16 -> otherwise refused.
2. An unknown chunk_codec -> refused.
3. chunk_count > 1_000_000 -> refused; len > 64 MiB -> refused; total > 4 GiB -> refused.
4. In EVERY chunk `content_id(data) != cid` -> refused (payload tampering).
5. `sum(len_i) != total_len` or `count != chunk_count` -> refused.
6. If the root digest does not match -> refused.

## 3. ChunkCodec::Huffman - BUD-HFM1 (bud_format_huffman)

```
+0 [8] magic:  \xB5 'H' 'F' 'M' '1' 0x00 0x00 0x00
+8 [1] version: 1
+9 [8] original length: u64 (ceiling: 4 GiB)
+17[2] symbol count: u16 (n)
+19    table: n x { [1] symbol, [1] code length }   (a repeated symbol -> refused)
+body: canonical Huffman codes, MSB-first bit packing
```
- Code lengths: canonical assignment ordered by (length, symbol) (DEFLATE-like).
- If the Kraft inequality is violated -> refused; a code length > 32 -> refused.
- A single symbol -> length 1; empty input -> n=0, an empty body.
- The padding bits of the last byte are free; decoding stops once the original length is reached.

## 4. Structural chunking (structural_split, K38)

- **Json:** delimiters are embedded into the chunks; a depth-1 comma is a boundary and is kept at
  the start of the NEXT chunk (`start = i`). Even if it is not an array or is malformed, a single
  chunk -> lossless.
- **Csv/Log/Text:** `split_inclusive('\n')` - every chunk ends with a line break.
- **Binary:** fixed 64 KiB blocks.
- **Joining:** PURE concatenation - no `[`/`]` is added for any type.
- **Compaction (K35):** adjacent chunks below min_chunk are merged (losslessly).

## 5. Format detection (bud_format_pipe::detect)

The order: JSON (starts with `[`/`{`) -> CSV (commas + lines) -> LOG (a 4-digit year on the first
line) -> Text (it contains lines or is entirely printable ASCII) -> Unknown (binary).
A wrong match is safe: losslessness is independent of the type (Section 1).

## 6. Backwards compatibility and evolution

- The v2 magic carries the v2 code; `from_bytes` requires an exact match.
- To add a new format code, `FormatCodec` and `bud_format_registry.rs` are updated together.
- To add a new chunk encoder, `ChunkCodec::from_u8` is extended (refusing the unknown is deliberate
  forward compatibility: an old reader refuses a new encoder rather than corrupting).
- The IMPLEMENTATION of this spec is the `bud_format_container` tests (roundtrip, tampering, bombs,
  a mini-fuzz); if the spec changes the tests must change too (the proof chain).

## 8. Lossless JSON columnar transform (bud_format_columnar, an invention - 2026-08-16)

A transform BEFORE compression: an array of JSON records is split into column arrays (the values of
the same key become adjacent -> zstd sees the repetitions). Two modes:
- **Exact (mode 0):** the columns stay in the original record order -> `decode(encode(d)) == d`
  BYTE FOR BYTE (K38). Key order is preserved via serde preserve_order.
- **OrderFree (mode 1):** the records are sorted deterministically -> the record SET is preserved
  (KF2); the sorting gain depends on the corpus (an extra gain with repeated key values).

The blob layout: magic `\xB5COL` + version + mode + key count + (len,key)* + record count
+ (len,value)* + a SHA3-256 digest (the "BDLM_BUD_COLUMNAR_V1" domain) - tampering is REFUSED.
Measurement (seed=7, 50k records, zstd19): RAW 7.83x -> Exact 8.53x -> OrderFree 11.49x.
Irregular JSON (records with different key sets) -> None; the pipeline falls back to the raw path
(losslessness is preserved). Ceilings: MAX_RECORDS 10M, MAX_COLUMNS 256, MAX_VALUE_BYTES 1 MiB.

## 9. The production ratio proof (bud_format_production, an invention - 2026-08-16)

Every .bud may carry a `BudProductionRecord` at production time:
`{format_codec, pipe, original_len, stored_len, payload_root(=content_id(original)), ts, claimed_ratio}`
- `record_hash()` = SHA3("BDLM_BUD_PRODUCTION_V1" || fields) - it can be written to the chain.
- `verify()`: claimed_ratio is approximately original_len/stored_len (tolerance 0.01); an invalid
  value is REFUSED.
- `ProductionGates::k_bud_production(rec, measured)`: if the claim exceeds 1.5x the measurement
  table it is REFUSED (K19) - unmeasured claims such as "17.19x" CANNOT PASS the production proof.
- CLI: `bud produce-proof -i x.bud --pipe <pipe>`.

The economic link: the $0.016/TB/month commitment is bound to the REAL ratio in the production
proof; if the ratio is insufficient the price is revised (an honest contract). The current honest
price: 0.23342 x 1.143 / 8.53 = about $0.031/TB/month (Exact columnar, a single file).

## 7. Measurements (2026-08-16 - REPRODUCIBLE with scripts/measure_ratios.py --seed 7)

A deterministic corpus: 50k JSON records / 60k CSV lines / 80k LOG lines (seed=7).
These values are identical to the runner's inline measurement (verified). The old table's
8.48x/5.51x/7.68x values came from a different, non-reproducible corpus - by K19 honesty they were
replaced with verified values (EK13).

| Pipeline | Verified ratio |
|---|---|
| structural+zstd19 JSON | 7.83x |
| structural+xz9 JSON | 8.07x |
| structural+zstd19 CSV | 3.55x |
| structural+zstd19 LOG | 6.17x |
| structural+xz9 LOG | 6.30x |
| BUD-HFM1 (the built-in Huffman, log) | ~1.69x (a 13.98 MB sample, CLI evidence) |
| ZSTD-19 container (ChunkCodec::Zstd, log) | ~6.55x (a 10.48 MB sample, CLI --zstd evidence) |
| JSON columnar Exact (zstd19) | 8.53x (seed=7, 50k) - the invention transform |
| JSON columnar OrderFree (zstd19) | 11.49x (seed=7, 50k; if record order is free) |

The 17.19x JSON claim DOES NOT HOLD against these measurements (the K19 canary: 7.83x < 17.19x);
the $0.016/TB/month ceiling requires 18.76x for EVENODD (1.286) and 16.68x for flat 7+1 (1.143).
