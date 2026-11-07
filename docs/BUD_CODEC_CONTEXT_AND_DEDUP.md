# Domain Transforms, Shared `CompressionContext`, & Convergent Private Dedup (WP-54)

## 1. Pure-Rust Decodable Domain Transforms (`crates/bud-codec/src/shared_context.rs`)

All decoders run through pure-Rust `ruzstd` (`bud_codec::decode(ZSTD, ...)`) with
strict `content_len` bounds and zero `unsafe`:

- **Codec 3 (`encode_small_with_context` / `decode_small_with_context`)**:
  `< 16 KiB` small objects compressed against an immutable `CompressionContext`
  dictionary window.
- **Codec 15 (`encode_timeseries_delta_xor` / `decode_timeseries_delta_xor`)**:
  `(u64 timestamp, u64 value_bits)` planar timestamp-delta + value-XOR + `zstd`.
- **Codec 18 (`encode_page_xor_delta` / `decode_page_xor_delta`)**:
  equal-size page XOR delta + `zstd`.
- **Codec 19 (`encode_fp32_exponent_split` / `decode_fp32_exponent_split`)**:
  planar IEEE-754 FP32 exponent stream (`1 B/weight`) + sign/mantissa stream
  (`3 B/weight`) + `zstd`.

---

## 2. Shared `CompressionContext` Lifecycle

- Contexts transition monotonically `Active -> Deprecated -> Retired`.
- `Deprecated` blocks new writes while historical objects continue to decode.
- `Retired` is refused while `ref_count > 0`.

---

## 3. Cross-Owner Convergent Private Deduplication (`ConvergentDedupStore`)

- `convergent_mode = false`: bypasses deduplication completely to prevent
  confirmation attacks on low-entropy secrets.
- `convergent_mode = true`: stores a single convergent ciphertext across owners
  with independent `OwnerKeyWrap` entries; releasing Owner A (`ref_count: 2 -> 1`)
  leaves Owner B's decryption intact until `ref_count == 0`.
