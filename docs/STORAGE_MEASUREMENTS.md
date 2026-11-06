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

## 4. Expansion-Tier Codecs and Supply-Chain Decisions (`WP-54`, Section 6.6.5)

Expansion codecs (`6, 7, 8, 12, 13, 23..=26`) remain closed at testnet launch and open
individually only after clearing the Section 6.6.3 item 10 bit-exact round-trip and
bounded-decoder gate:

| Codec | Domain | License & Dependency Decision | Measured Corpus Ratio (Section 6.6.5) |
|---:|---|---|---|
| 6 | Preflate + LZMA2 | Pure-Rust Apache-2.0 / MIT (`lzma-rust2` / in-tree preflate) required prior to opening; copyleft C libraries refused | Recompressed deflate / ZIP streams `1.15x` to `1.35x` |
| 7 | Lossless WAV / PCM audio | Pure-Rust FLAC LPC frame encoder preserving RIFF header bytes bit-for-bit | `6.04x` to `6.26x` on synthetic / studio PCM corpus |
| 8 | Context mixing (`SlowY`) | Bounded-memory deterministic integer mixer (`bud3::meter` capped) | Cold archival text/structured corpus `3.8x` to `5.4x` |
| 12 | Fast shared context (`BCX1`) | In-tree `src/storage/bud3/compression_context.rs` (zero external deps, public-only) | Small JSON/schema records `1.35x` to `2.75x` |
| 13 | Archival shared context (`BCX1`) | In-tree `src/storage/bud3/compression_context.rs` (`Cold` tier or `>= 25%` floor) | Cold structured records `1.80x` to `3.40x` |
| 23 | Genomic FASTQ 2-bit delta | In-tree lossless base + quality stream split (`bud_format_genomic`) | `3.0x` to `6.0x` on FASTQ reads |
| 24 | Office OPC (`DOCX`/`XLSX`) | Store-ZIP canonical repack staged behind Codec 6 gate | `1.0x` to `1.1x` (`DOCX`), `1.0x` to `1.6x` (`XLSX`) |
| 25 | Lossless point cloud | Integer grid + exact residual only (lossy quantization permanently banned by `D-3`) | Lossless residual baseline (`>= 1.0x` bit-exact) |
| 26 | Raw pixel lossless (`BMP`/`TIFF`) | In-tree header-preserving lossless row predictor (zero external C codecs) | `15.84x` on uncompressed BMP/TIFF pixel bodies |

## 5. Shared Compression Context and Private Cross-Owner Deduplication (`WP-54`, Section 6.20)

1. **Shared Compression Context (`K15`..`K19`, `src/storage/bud3/compression_context.rs`):**
   - Chain state stores only the fixed [`ContextManifest`] (`context_id` derived via length-prefixed SHA-256 over `class_tag`, `generation`, sorted `corpus_objects`, `dictionary_digest`, and `created_epoch`); materialized dictionary bytes live strictly in each node's local [`LocalContextCache`].
   - Public objects are corpus candidates by default; sealed content is unconditionally rejected (`ContextError::SealedContentForbidden`).
   - Burned corpus members are evicted on the next [`SharedContextEngine::rotate_context`]; dependent objects re-encode under their existing NFTs (`ReplaceObject`) with zero change to `ContentId`.
   - Context-compressed uploads pay `20%` (`CONTEXT_SAVINGS_FEE_SHARE_BPS = 2_000`) of saved physical-byte fees into the `ContextMaintenancePool`; exact full-content deduplication matches pay `0` extra fee.
2. **Private Cross-Owner Sealed Deduplication (`K20`, `src/storage/bud3/private_dedup.rs`):**
   - Combines `>= 3` threshold OPRF shares (`combine_threshold_oprf_shares`), enforces `MAX_PRIVATE_DEDUP_QUERIES_PER_EPOCH = 16` per `(epoch, account)`, and requires a valid BudZero plaintext-ownership proof (`OwnershipProofBundle`) bound to `(claimant, epoch, oprf_tag, padme_bucket_bytes)`.
   - Emits unlinkable [`BlindedDedupRecord`] descriptors, prices every sealed upload at `sealed_pool_average_fee_atoms`, and defers reference-count updates to `flush_epoch_batch` at epoch boundaries.
   - **Accepted residual risk (`Section 6.20.2.6`):** The designated upload validator executing the admission session observes whether the blinded OPRF tag matched an existing entry, while all public chain observers see indistinguishable NFT slots, Padme bucket sizes, and uniform pool-average fees.
