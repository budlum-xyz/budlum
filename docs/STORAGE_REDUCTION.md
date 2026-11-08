# Storage reduction measurements

This preserves the corpus evidence formerly kept in the retired legacy storage
roadmap. It is a historical measurement record, not a new benchmark or a claim
that the removed legacy RPC surface remains available.

## Measured corpus and the two-unit rule

Every saving in `src/storage/` was measured, and for a while the totals were
still wrong. The measurements were right; the weights were guesses.

A published crawl of a comparable content-addressed network (Trautwein et al.,
*A Closer Look into IPFS*, ACM POMACS 2024) measured the same corpus two ways:

| class | share of files | share of bytes |
|---|---|---|
| JSON (NFT metadata) | 40.2% | 0.09% |
| image | 34.8% | 58.4% |
| video / stream | 13.8% | 33.6% |
| unknown (binary) | 5.7% | 7.1% |
| HTML / text | 0.2% | 0.07% |

JSON is two fifths of the objects and under a thousandth of the volume, a
factor of 447. Storage is billed in bytes, so a lever weighted by object count
is weighted by the wrong unit, and the shared-dictionary result (a measured
49% to 92% on small structured objects) applies to 0.16% of the bytes.

Reweighted by volume, the whole-corpus multiplier is 0.82x against today's 3x
replication, a **72.6% reduction**, which is below the pessimistic end of the
74.8%-93.3% range previously quoted here. The range was wide only because the
weights were estimates, and the pessimistic end was still optimistic.

Zeroing each class in turn says where the remaining volume is:

| class zeroed | resulting multiplier | gained |
|---|---|---|
| image | 0.364x | 0.458 |
| video | 0.482x | 0.339 |
| unknown binary | 0.797x | 0.024 |
| JSON | 0.821x | 0.0003 |

So the rule this project holds itself to: **a reduction claim states both
units or neither.** "40% of your objects are free" and "0.1% of your bytes are
free" are the same measurement, and each on its own misleads a reader in the
opposite direction. `DerivedSpec::stored_versus_independent` returns a pair
rather than a ratio for this reason, and
`check-derived-content-stays-byte-exact.sh` refuses a version that collapses
it to one number.

The derived-content path exists because of this table. It is the only lever
that reaches a zero multiplier inside the image class, which is where 58.4% of
the bytes are, and it stays byte-exact: measured on quantised DCT
coefficients, a block-aligned crop reproduces the master's own coefficients
exactly, while a misaligned one reproduces none of them.


## Measurement reference

Trautwein et al., *A Closer Look into IPFS: Accessibility, Content, and
Performance*, ACM POMACS 2024 (DOI 10.1145/3656015): measured corpus
composition, by file count and by volume.
