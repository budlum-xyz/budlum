# B.U.D. Core (bud-core): 1.0 / 2.0 / 3.0

Broad Universal Database 2.0: a multi-format, lossless, quantum-resistant
storage core. This crate is the real Rust implementation of the `.bud` v2
container format and its pipeline.

**Status:** 137 tests green (132 unit, 1 test_bud2, 4 integration), 0 warnings,
`#![forbid(unsafe_code)]`. The format contract is
[`FORMAT-V2.md`](FORMAT-V2.md), a byte-level spec with measurements.

## Build and test

```bash
cargo build            # all modules plus the CLI binary
cargo test             # 126 unit and 4 integration tests
```

## CLI (bin/bud)

```bash
bud store  -i input.json -o output.bud              # v2 container, RAW
bud store  -i input.log -o output.bud --compress    # v2 container, Huffman, real shrinkage
bud store  -i input.log -o output.bud --zstd        # v2 container, real zstd, best ratio at roughly 6.5x
bud restore -i output.bud -o back.json              # verify and restore, losslessly
bud check  -i output.bud                            # integrity: magic, chunk cid, root
bud encode -i input.json -o v1.bud --class json     # v1 format
bud bench  -f input.log                             # speed and cost, against the $0.016 ceiling gate
bud bft-vote --pipe-id 3 --ratio 17.19 --validator v   # BFT finality, more than two thirds
```

## Module map

| Module | What it does |
|---|---|
| `bud_format_container` | Structural chunking (lossless COMPLETENESS, K38), BudV2File (bomb-guarded), ChunkCodec |
| `bud_format_pipe` | The end-to-end `store` and `restore` pipeline, plus format detection |
| `bud_format_huffman` | A real lossless Huffman codec (BUD-HFM1, zero dependencies) |
| `bud_format_real` | Real zstd FFI (`zstd_compress` and `zstd_decompress_safe`, capped by K25) |
| `bud_format` | The v1 format, ratio consensus, the K-BUD gates and `decode_streaming` (K25) |
| `bud_format_checkpoint` | Hash-chained checkpoint consensus, in the SEC 17a-4 pattern |
| `bud_format_por` | Shacham-Waters PoR, a proof of retrievability, bounds-safe |
| `bud_format_dedup` | Intra-tenant dedup plus PoW ownership (K20) |
| `bud_format_social` | Social bridge records and the K74 ownership split (Owned/Licensed, EU 2426) |
| `bud_format_bft` | Ratio finality, more than two thirds, GRANDPA-like |
| `quantum_chain` | Ed25519 plus ML-DSA-87 hybrid signatures and a dual wallet (K3/K4/B1) |
| `bud_format_economics` | The cost model with its honest ceiling gate, plus K60 zero-egress |
| `bud_format_registry` | The MIME and format registry, plus the proof gates |

## Honesty (K19/K38)

- Measured ratios live in `RealBench::measured_ratios()`, `FORMAT-V2.md`
  section 7, and `scripts/measure_ratios.py --seed 7`, which is REPRODUCIBLE:
  JSON zstd19 at 7.83x, CSV at 3.55x, LOG at 6.17x, and the zstd container at
  roughly 6.55x. No invented numbers (EK13).
- The `17.19x JSON` claim DOES NOT HOLD against the real measurement, which is
  7.83x. The canary tests and the CLI bench report that honestly, as
  "ceiling $0.016: NOT MET".
- The stub `RealCompressor` that produced fake zstd and xz magic was removed, in
  favour of real Huffman (BUD-HFM1) and real zstd FFI (`ChunkCodec::Zstd`).

## Security posture

- Panic-free parsing: every decode and parse path returns `None` on untrusted
  input, checked by a mini-fuzz plus exhaustive truncation sweeps.
- No alloc bombs: `with_capacity` is NEVER used from untrusted length fields;
  growth is lazy.
- Bomb guards: `MAX_CHUNK_COUNT`, `MAX_CHUNK_BYTES`, `MAX_TOTAL_BYTES`, the K25
  stream limits, the Kraft inequality, and the ratio ceiling that refuses
  anything above 100:1.
- `#![forbid(unsafe_code)]` in every module.
