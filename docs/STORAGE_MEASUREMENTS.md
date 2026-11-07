# B.U.D. 3.0 Storage Measurements

## Measurement status

No Rust corpus measurements have been verified in this branch. Compression
ratios, throughput, and device resource figures must not be treated as
measured results until the corpus, toolchain, commands, and outputs are recorded
and independently reviewed. The directive's external figures are not a
substitute for those measurements.

## Codec register

`crates/bud-codec/src/registry.rs` is the source of the registered identifiers
and their current states. The implementation currently opens raw (0) and zstd
(1); the other registered codecs are closed or reserved. The register describes
speed classes, not measured performance. Opening another codec requires its
actual decoder, bounded decoding, reproducible round-trip tests, and the
applicable measurement and review gates.

`bud_codec::select` verifies candidate decoding before choosing a smaller
representation. `src/storage/bud3/replace.rs` contains a separate candidate
selection policy. These paths have not yet been validated together against the
full directive's codec requirements.

## Physical-byte pricing

`src/storage/bud3/fees.rs` contains the proposed storage fee and custody
settlement calculations. Their relationship to actual placement, physical-byte
accounting, and chain settlement still requires end-to-end verification. A
formula or unit test does not establish measured operational cost.

## Expansion features

Shared context and private cross-owner deduplication are closed at testnet
launch. The experimental private-dedup transcript helpers are neither a
threshold OPRF nor a BudZero ownership proof. The submission path refuses
requests even when its enable flag is set; no privacy or ownership guarantee is
claimed until real cryptographic verification and independent review are in
place. Context codec admission and rotation also require end-to-end tests.

## Evidence to collect

Record the exact corpus and its provenance, data sizes, codec and compiler
versions, commands, hardware, encoded sizes, throughput, memory use, and
round-trip outcomes. Publish failures and limits as well as successes. Do not
open a codec or change testnet defaults based on unverified figures.
