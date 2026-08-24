//! B.U.D. 2.0 invariant tests.
//!
//! This file used to be `#[test] fn placeholder() { assert!(true); }`: a record
//! that verified nothing yet looked green. `assert!(true)` tripped clippy's
//! `assertions_on_constants` gate, and tripping it was correct: an empty test
//! is worse than untested code, because it leaves the impression of coverage.
//!
//! In its place the **1st invariant** of the 2.0 specification is exercised:
//! LOSSLESSNESS, that is, the original bytes are reproduced byte for byte. The
//! tests drive the `engine_store`/`engine_restore_container` round trip over
//! different content classes, because the pipeline picks a different transform
//! per class (columnar / logfield / none) and if losslessness breaks it breaks
//! at a transform boundary.

use bud_core::bud_format_engine::{engine_restore_container, engine_store};

/// A fixed timestamp: the PACT record depends on time, and the test must be deterministic.
const TS: u64 = 1_768_000_000;

/// Drives the round trip and verifies the original bytes come back byte for byte.
fn roundtrip_bytes_equal(data: &[u8], label: &str) {
    let res = engine_store(data, false, TS)
        .unwrap_or_else(|| panic!("{label}: engine_store returned None"));

    // `res.container` holds the CONTAINER bytes (not the engine blob), which is
    // why `engine_restore_container` is used; the `bud` CLI calls the same one.
    let back = engine_restore_container(&res.container, res.transform_kind as u8, false)
        .unwrap_or_else(|| panic!("{label}: engine_restore_container returned None"));

    assert_eq!(
        back.len(),
        data.len(),
        "{label}: length changed ({} -> {})",
        data.len(),
        back.len()
    );
    assert!(
        back == data,
        "{label}: bytes did not come back byte for byte (format={}, transform={:?})",
        res.format_name,
        res.transform_kind
    );
    assert_eq!(
        res.original_len,
        data.len() as u64,
        "{label}: recorded original_len does not match the input"
    );
}

#[test]
fn json_returns_losslessly() {
    // Columnar transform path: repeated keys are split into columns.
    let mut rows = Vec::new();
    for i in 0..200 {
        rows.push(format!(
            r#"{{"user":"u{}","day":"2026-08-{:02}","value":{},"status":{}}}"#,
            i % 40,
            (i % 28) + 1,
            i,
            [200, 201, 404, 500][i % 4]
        ));
    }
    let json = format!("[{}]", rows.join(",")).into_bytes();
    roundtrip_bytes_equal(&json, "json");
}

#[test]
fn plain_text_returns_losslessly() {
    // The second line is written with escapes on purpose: multi-byte UTF-8 must
    // survive the round trip, and the source file itself stays ASCII.
    let text = "B.U.D. 2.0 losslessness invariant.\n\
                 multi-byte characters must return byte for byte: \
                 \u{e7}\u{11f}\u{131}\u{f6}\u{15f}\u{fc} \u{c7}\u{11e}\u{130}\u{d6}\u{15e}\u{dc}.\n"
        .repeat(80)
        .into_bytes();
    roundtrip_bytes_equal(&text, "text");
}

#[test]
fn incompressible_data_returns_losslessly() {
    // Imitation of the entropy-coded/random class: it does not compress, the
    // pipeline MUST SKIP compression and still return the bytes byte for byte.
    // Corrupting the container path once compression is skipped is a classic
    // bug; the gate sits here.
    let mut data = Vec::with_capacity(8192);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..8192 {
        // xorshift: deterministic but incompressible
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        data.push((x & 0xFF) as u8);
    }
    roundtrip_bytes_equal(&data, "random");
}

#[test]
fn single_byte_and_small_input_return_losslessly() {
    // Boundary: inputs far below the chunk size.
    roundtrip_bytes_equal(b"x", "single byte");
    roundtrip_bytes_equal(b"short input", "short");
}

#[test]
fn empty_input_is_rejected_not_silently_corrupted() {
    // An empty input cannot be stored; what matters is a clear rejection, not a panic.
    assert!(
        engine_store(b"", false, TS).is_none(),
        "an empty input must not be accepted"
    );
}

#[test]
fn measured_ratio_is_consistent_with_the_sizes() {
    // K19: the ratio is not CLAIMED, it is MEASURED from the sizes. Verify that
    // the recorded ratio really is original_len/stored_len; this is the number
    // the claim-above-measurement gate rests on.
    let mut rows = Vec::new();
    for i in 0..300 {
        rows.push(format!(
            "2026-08-21T00:00:{:02}Z level=info code={}",
            i % 60,
            i
        ));
    }
    let log = rows.join("\n").into_bytes();

    let res = engine_store(&log, false, TS).expect("engine_store");
    assert!(res.stored_len > 0, "stored_len cannot be zero");

    let expected = res.original_len as f64 / res.stored_len as f64;
    assert!(
        (res.measured_ratio - expected).abs() < 1e-9,
        "measured_ratio ({}) does not match the size ratio ({})",
        res.measured_ratio,
        expected
    );
}
