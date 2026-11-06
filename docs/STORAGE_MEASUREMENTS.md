# B.U.D. 3.0 Storage Measurements and Expansion Ledger (WP-54)

This ledger records codec registry status, deterministic payload geometry, and
prototype baseline references for `crates/bud-codec` and
`src/storage/bud3/{compression_context,private_dedup}.rs`.

Every table below explicitly labels whether its values are **Deterministic
Frame Geometry** (exact byte formulas), **Prototype Reference** (non-binding
research prototype figures recorded for comparison), or **Pending Hardware
Measurement** (requires single-core reference benchmark before opening a closed
codec on chain `45261`).

## 1. Codec Openness and Gate Status on Testnet (`45261`)

| Codec ID | Name | Testnet `45261` Launch State | Gate / Prerequisite |
| --- | --- | --- | --- |
| `0` | `raw` | Open | Frozen identity decoder (`crates/bud-codec/src/lib.rs`) |
| `1` | `zstd` (level 19, LDM, 8 MiB window) | Open | Frozen pure-Rust `ruzstd` decoder (`crates/bud-codec/src/lib.rs`) |
| `6` | `preflate and LZMA2` | Closed | License review + pure-Rust bounded decoder benchmark (`>= 5 MB/s`) |
| `7` | `lossless audio and header` | Closed | Pure-Rust WAV/AIFF PCM predictor decoder benchmark (`>= 5 MB/s`) |
| `8` | `context mixing` | Closed | Reference single-core floor (`>= 0.5 MB/s`) + deterministic memory cap |
| `12` | `LZ and context` (`compression_context`) | Closed (`ACTIVATION.height = None`) | Governance activation height after corpus snapshot benchmark |
| `13` | `context machine` | Closed | Cold-tier (`AccessTier::Cold`) slow floor (`>= 0.5 MB/s`) |
| `23..26` | Domain codecs (genome, OPC, point cloud, lossless image) | Closed | Dependency license audit + frozen pure-Rust decoder vectors |

## 2. Deterministic Frame Geometry (`compression_context` & `private_dedup`)

*Table type: Deterministic Frame Geometry (exact byte counts from implementation, not throughput claims).*

| Structure | Exact Byte Formula | Notes |
| --- | --- | --- |
| `ContextManifest` digest | `32` bytes (`SHA-256`) | Tagged with `BDLM_BUD3_CONTEXT_MANIFEST_V1` |
| `ContextEncodedPayload` header | `54` bytes (`8` magic + `8` generation + `32` manifest digest + `2` residual codec + `4` residual len) | Followed by `residual_payload` (`RAW` or `ZSTD`) |
| Max materialized context dictionary | `16_777_216` bytes (`16 MiB`) | `MAX_CONTEXT_DICTIONARY_BYTES` |
| Minimum sealed Padme bucket | `256` bytes | `MIN_SEALED_BUCKET_BYTES`; hides exact short plaintext lengths |
| `PublicSealedNftView` | `48` bytes (`32` blinded commitment + `8` Padme bucket + `8` uniform fee) | Identical layout on cross-owner hit and miss |
| `OwnershipProof` | `104` bytes (`32` SHA-256 + `8` len + `32` challenge nonce + `32` sampled window MAC) | Tagged with `BDLM_BUD3_PRIVATE_DEDUP_OWNERSHIP_V1` |

## 3. Prototype Reference Baselines (AR-03 Comparison Target)

*Table type: Prototype Reference (from historical single-core prototype corpus runs; Rust hardware benchmark run is scheduled prior to governance activation on chain `45261`).*

| Metric | Prototype Reference Value | Verification Lock in Rust Tree |
| --- | --- | --- |
| QR framing overhead at `1 MiB` | `11` bytes | `src/storage/bud3/bof1.rs` & `segment.rs` |
| Context-conditioned ratio vs standalone on same-class corpus (`26` new files) | `0.637x` standalone size | `bud3_context_codec_vectors` |
| Incremental edit of existing corpus object | `0.026x` standalone size | `bud3_context_codec_vectors` |
| `ContentId` invariance across context generation rotation | `100%` invariant (`SHA-256(plaintext)`) | `bud3_context_rotation_keeps_content_id` |
| Burned corpus eviction on next generation rotation | `0` retained bytes in next manifest | `bud3_context_burned_corpus_leaves` |
| Context savings fee routing | `100%` to `context_maintenance_pool` (`0` on exact dedup) | `bud3_context_fee_goes_to_pool` |
| Cross-owner sealed deduplication public leakage | `0` bits (uniform Padme bucket + batched epoch counter) | `bud3_private_dedup_hides_match_from_public` |

## 4. Verification Locks

- `cargo test --lib storage::bud3::compression_context::tests`
  - `compression_context_is_closed_on_testnet`
  - `bud3_context_codec_vectors`
  - `bud3_context_rotation_keeps_content_id`
  - `bud3_context_burned_corpus_leaves`
  - `bud3_context_fee_goes_to_pool`
  - `access_tiering_tracks_hot_and_cold_transitions`
- `cargo test --lib storage::bud3::private_dedup::tests`
  - `private_dedup_is_closed_on_testnet`
  - `bud3_private_dedup_rate_limited`
  - `bud3_private_dedup_needs_ownership_proof`
  - `bud3_private_dedup_hides_match_from_public`
