# B.U.D. 3.0 A0 Codec Register and Storage Measurements

This document records the B.U.D. 3.0 A0 lossless compression register (`crates/bud-codec`),
the fast-probe selection rule (`src/storage/bud3/replace.rs`), and the physical-byte
cost model (`src/storage/bud3/fees.rs`).

## 1. Frozen A0 Codec Register (`CodecId` `0..=26`)

Every codec identifier in `crates/bud-codec::REGISTER` is permanently assigned and
frozen (`D-7`): no identifier is ever deleted or repurposed. Codecs marked `closed`
are present in the register and refused on testnet (`CodecError::Closed`).

| Codec ID | Name | Speed Class | Testnet Status | Notes |
|---:|---|---|---|---|
| 0 | `raw` | Fast | open | Identity baseline; selected whenever compressed output is not strictly shorter |
| 1 | `zstd` | Medium | open | General-purpose dictionary-free Zstandard level 3 |
| 2 | `lz4` | Fast | open | Fast LZ4 block frame with 8-byte little-endian uncompressed length prefix |
| 3 | `zstd-dict` | Medium | open | Zstandard with pre-shared corpus dictionary |
| 4 | `columnar-zstd` | Medium | open | Fixed-stride byte-transpose followed by Zstandard |
| 5 | `delta-int-zstd` | Medium | open | Little-endian integer delta transform followed by Zstandard |
| 6 | `brotli` | Slow | closed | Closed for testnet launch |
| 7 | `lzma2` | Slow | closed | Closed for testnet launch |
| 8 | `kanzi` | Slow | closed | Closed for testnet launch |
| 9 | `reserved-9` | Slow | closed | Reserved slot |
| 10 | `crop-derive` | Fast | open | Same-owner base-slice derivation (`base_id[32] \|\| offset_u64 \|\| len_u64`) |
| 11 | `delta-object` | Medium | open | Same-owner copy/literal patch stream compressed with Zstandard |
| 12 | `shared-ctx` | Medium | closed | Shared compression context (expansion tier) |
| 13 | `private-dedup` | Medium | closed | Private deduplication codec (expansion tier) |
| 14 | `utf8-pack` | Medium | closed | Closed pending post-launch corpus gate |
| 15 | `json-columnar` | Medium | closed | Closed pending post-launch corpus gate |
| 16 | `csv-typed` | Medium | closed | Closed pending post-launch corpus gate |
| 17 | `log-template` | Medium | closed | Closed pending post-launch corpus gate |
| 18 | `wasm-sect` | Medium | closed | Closed pending post-launch corpus gate |
| 19 | `exe-bcj` | Medium | closed | Closed pending post-launch corpus gate |
| 20 | `png-repack` | Slow | closed | Closed pending post-launch corpus gate |
| 21 | `jpeg-lepton` | Slow | closed | Closed pending post-launch corpus gate |
| 22 | `audio-lpc` | Slow | closed | Closed pending post-launch corpus gate |
| 23 | `parquet-repack` | Slow | closed | Closed (expansion tier) |
| 24 | `protobuf-col` | Medium | closed | Closed (expansion tier) |
| 25 | `dna-2bit` | Medium | closed | Closed (expansion tier) |
| 26 | `timeseries-xor` | Fast | closed | Closed (expansion tier) |

## 2. Selection Rule and Fast Probe (`src/storage/bud3/replace.rs`)

1. Empty payloads (`0` bytes) select `CODEC_RAW` (`0`) directly.
2. High-entropy inputs (`entropy_millibits(probe) > 7_900` over the first `4_096` bytes)
   skip compression candidates and select `CODEC_RAW` (`0`).
3. Fast probe (`FAST_PROBE_BYTES = 4_096`, `FAST_PROBE_RATIO_THRESHOLD_BPS = 9_800`):
   for inputs larger than `4 KiB`, `CODEC_LZ4` (`2`) is evaluated on the first `4 KiB`.
   If `probe_compressed_len * 10_000 > probe_len * 9_800`, slower `Medium` / `Slow`
   codecs are skipped.
4. Otherwise open codecs are evaluated deterministically and decoded back to verify
   bit-for-bit equality before any candidate can beat `CODEC_RAW` (`0`).

## 3. Physical-Byte Fee Formula (`src/storage/bud3/fees.rs`)

Every stored B.U.D. 3.0 object is priced from physical bytes (`object_bytes * redundancy`)
using integer ceiling division (`div_ceil`) over `1 GiB * 365 days`:

- Minimum storage fee: `0.001 BUD` (`1_000` base units).
- Custody Endowment share: `95%` (`9_500 bps`), distributed per epoch across audited
  custody shares weighted by `symbol_bytes * presence_multiplier_bps`.
- Upload gateway share: `5%` (`500 bps`).
- Mobile `30%` placement floor (`decentralization_physical_bytes`) is accounted
  separately and paid from the Network Security Pool (`reward_pool::storage_share`),
  never surcharged to the uploader.
