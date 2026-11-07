# Fountain golden vectors

`p0_k17.sha256`: SHA-256 over `esi (u32 LE) || symbol` for the 17 source
symbols and the first 16 repair symbols of one P0 segment of
`2911 * 16 + 123` bytes (the xorshift pattern with seed 42 in
`src/storage/bud3/fountain.rs`). It was produced by `raptorq = "=2.0.0"`.
A change of the pinned crate that changes one symbol byte fails
`fountain_golden_vectors_lock_crate_version`.
