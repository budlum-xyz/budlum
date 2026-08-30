//! Parity-row throughput and cross-validation: an INDEPENDENT scalar
//! reference coder against the pool dispatch that `ReedSolomon::encode_parity`
//! chooses above its window, plus the generate-to-reference round trip the
//! node can run against a client-built manifest. `harness = false`; this
//! binary prints measurements and refuses when the two implementations
//! disagree.
//!
//! # Why the reference is independent
//!
//! `BUD-3.0-SARTNAME.md` item 12 asks for real absolute numbers on the Rust
//! side, and parity is what manifest commitments fold over: if the pool
//! dispatch returned bytes that depended on how the rows were scheduled, the
//! optimization would be a fork. Comparing `encode_parity` against itself
//! would prove nothing, so the reference below rebuilds each row from
//! `ReedSolomon::parity_coefficient` and a shift-and-add field product, while
//! the coder multiplies through log/exp tables. Two different computations of
//! the same field product; one byte of disagreement exits with status 2
//! before any throughput line is printed.
//!
//! # What is measured and what is not
//!
//! Measured: wall-clock cost of one k=4, m=2, 256 KiB-per-shard corpus,
//! reference rows against coder pool dispatch, fastest of a fixed number of
//! repetitions, byte equality of the two results; and the `encode_object` to
//! `verify_object_encoding` roundtrip. Not measured: SIMD width. Explicit
//! SIMD is not runnable here: the crate root carries `#![forbid(unsafe_code)]`
//! and the pinned stable 1.97.1 toolchain rejects `portable_simd` (measured
//! as E0658), which is the same reason the tree keeps its own table coder
//! instead of `reed-solomon-simd`. The rayon row window is the measured
//! alternative, and this file is what logs it, per line, on the host that ran
//! the step.

use std::process::exit;
use std::time::{Duration, Instant};

use budlum_core::storage::manifest::ErasureScheme;
use budlum_core::storage::{encode_object, verify_object_encoding, ReedSolomon};

/// Shard length: above the window the pool dispatch engages, so the
/// comparison measures the dispatch and not only the loop.
const SHARD: usize = 256 * 1024;
/// Data shards and parity shards; k=4, n=6 is the scheme the object tests run.
const K: usize = 4;
const M: usize = 2;
/// Repetitions. The fastest is reported so a scheduler hiccup cannot become
/// a measurement.
const REPEAT: usize = 7;

/// A deterministic corpus: the striding mix the ratio benches use, so the
/// files measure the same kind of bytes.
fn corpus() -> Vec<Vec<u8>> {
    (0..K)
        .map(|i| {
            (0..SHARD)
                .map(|j| {
                    let mixed = (i * 0x9E37_79B9).wrapping_add(j * 0x85EB_CAF0);
                    (((mixed >> ((j % 17) + 3)) ^ (mixed >> 21)) & 0xFF) as u8
                })
                .collect()
        })
        .collect()
}

/// GF(2^8) product under the field the coder documents (primitive
/// polynomial 0x11D), by shift and add. Deliberately not the coder's log/exp
/// table: the equality check below crosses two implementations.
fn gf_product(a: u8, b: u8) -> u8 {
    let mut acc = 0u8;
    let mut x = a;
    let mut y = b;
    while y != 0 {
        if y & 1 != 0 {
            acc ^= x;
        }
        let hi = x & 0x80;
        x <<= 1;
        if hi != 0 {
            x ^= 0x1D;
        }
        y >>= 1;
    }
    acc
}

/// The reference path: rows one after another on the calling thread,
/// coefficients from the public audit accessor, products from `gf_product`.
fn run_rows(rs: &ReedSolomon, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    (0..M)
        .map(|i| {
            let mut out = vec![0u8; data[0].len()];
            for (j, shard) in data.iter().enumerate() {
                let coeff = match rs.parity_coefficient(i, j) {
                    Some(c) => c,
                    None => {
                        eprintln!("erasure_rows: the scheme has no coefficient ({i}, {j})");
                        exit(2);
                    }
                };
                if coeff == 0 {
                    continue;
                }
                for (o, s) in out.iter_mut().zip(shard.iter()) {
                    *o ^= gf_product(coeff, *s);
                }
            }
            out
        })
        .collect()
}

/// The production entry: `encode_parity` dispatches the coder's own rows
/// through the rayon pool above the window.
fn run_pool(rs: &ReedSolomon, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    match rs.encode_parity(data) {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("erasure_rows: pool dispatch refused the corpus: {e:?}");
            exit(2);
        }
    }
}

/// One measured path: the fastest repetition, and the output it produced.
fn measure<F>(rs: &ReedSolomon, data: &[Vec<u8>], run: F) -> (Duration, Vec<Vec<u8>>)
where
    F: Fn(&ReedSolomon, &[Vec<u8>]) -> Vec<Vec<u8>>,
{
    let mut best: Option<(Duration, Vec<Vec<u8>>)> = None;
    for _ in 0..REPEAT {
        let start = Instant::now();
        let out = run(rs, data);
        let spent = start.elapsed();
        let better = match &best {
            None => true,
            Some((prev, _)) => spent < *prev,
        };
        if better {
            best = Some((spent, out));
        }
    }
    match best {
        Some(pair) => pair,
        None => {
            eprintln!("erasure_rows: no repetition ran, refusing to report");
            exit(2);
        }
    }
}

/// MB/s from an input size and an elapsed time, guarded against a zero.
#[must_use]
fn mb_per_second(bytes: usize, spent: Duration) -> f64 {
    let wide: u32 = u32::try_from(bytes).unwrap_or(u32::MAX);
    let secs = spent.as_secs_f64();
    if secs <= 0.0 {
        return f64::MAX;
    }
    (f64::from(wide) / 1e6) / secs
}

/// Serial duration over pool duration, guarded against a zero.
#[must_use]
fn speedup(serial: Duration, pool: Duration) -> f64 {
    let a = u32::try_from(serial.as_micros()).unwrap_or(u32::MAX);
    let b = u32::try_from(pool.as_micros()).unwrap_or(u32::MAX);
    if b == 0 {
        return f64::MAX;
    }
    f64::from(a) / f64::from(b)
}

fn main() {
    let coder = match ReedSolomon::new(K, M) {
        Ok(rs) => rs,
        Err(e) => {
            eprintln!("erasure_rows: the scheme was refused: {e:?}");
            exit(2);
        }
    };
    let data = corpus();
    let parity_bytes = SHARD * M;

    let (serial_time, serial_out) = measure(&coder, &data, run_rows);
    let (pool_time, pool_out) = measure(&coder, &data, run_pool);

    if serial_out != pool_out {
        eprintln!(
            "erasure_rows: the coder pool dispatch produced different parity bytes than the
  \
             independent reference rows. Two implementations of the same field product must
  \
             agree byte for byte; a disagreement is a bug in one of them. Refusing to report
             throughput."
        );
        exit(2);
    }
    println!(
        "erasure_rows: k={K} m={M}, {SHARD} B shards, {parity_bytes} B parity per pass, {REPEAT} \
         repetitions, fastest reported"
    );
    println!(
        "erasure_rows: reference rows {:.1} MB/s ({} us), coder pool dispatch {:.1} MB/s ({} us),
         ratio {:.2}x",
        mb_per_second(parity_bytes, serial_time),
        serial_time.as_micros(),
        mb_per_second(parity_bytes, pool_time),
        pool_time.as_micros(),
        speedup(serial_time, pool_time),
    );

    // Generate then reference: encode one object, build its manifest, and run
    // the re-encode-and-compare check a node performs against a client
    // manifest. The refusal below is the point of the number: a reference that
    // rejects its own generation would make the throughput meaningless.
    let object: Vec<u8> = data.iter().flatten().copied().collect();
    let scheme = ErasureScheme { k: 4, n: 6 };
    let encoded = match encode_object(&object, scheme) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("erasure_rows: encode_object refused its own corpus: {e:?}");
            exit(2);
        }
    };
    let manifest = match encoded.to_manifest() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("erasure_rows: the manifest for the encoding was refused: {e}");
            exit(2);
        }
    };
    let mut best: Option<Duration> = None;
    for _ in 0..REPEAT {
        let start = Instant::now();
        if let Err(e) = verify_object_encoding(&object, &manifest) {
            eprintln!("erasure_rows: the reference refused its own generation: {e:?}");
            exit(2);
        }
        let spent = start.elapsed();
        best = Some(match best {
            None => spent,
            Some(prev) => prev.min(spent),
        });
    }
    if let Some(spent) = best {
        println!(
            "erasure_rows: generate->reference roundtrip {} B object, verify {:.1} MB/s ({} us), \
             ids matched",
            object.len(),
            mb_per_second(object.len(), spent),
            spent.as_micros(),
        );
    }
}
