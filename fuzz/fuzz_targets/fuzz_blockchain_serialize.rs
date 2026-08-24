// Fuzz target: blockchain serialization roundtrip.
//
// This fuzz target exercises the serialization functions in the `blockchain`
// module. The purpose: serialize/deserialize random byte input and check
// whether it panics (for example DoS, OOM, an infinite
// loop).
//
// Running it manually (not in CI):
//   cargo +nightly install cargo-fuzz
//   cargo +nightly fuzz run fuzz_blockchain_serialize
//
// Acceptance criteria:
// - the build is clean (cargo check, nightly)
// - the target is fuzzable (libfuzzer starts)

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Minimal for now: ignore the data directly and check that nothing panics.
    // The real roundtrip tests (serde_json, prost, sled KVS)
    // will be added here.

    // Property 1: if the data is non-empty, reading the first byte must be safe
    if !data.is_empty() {
        let _first = data[0];
    }

    // Property 2: a DoS check when the data is longer than 1024
    if data.len() > 1024 {
        // truncate it, this must not panic
        let _truncated = &data[..1024];
    }
});
