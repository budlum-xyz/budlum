//! Ratio pipeline throughput: one core against a rayon pool, on the packing
//! function the carousel and the recipe pipe feed. `harness = false`; this binary
//! prints measurements and refuses when the two paths disagree.
//!
//! # Why this file both measures and refuses
//!
//! `BUD-3.0-SARTNAME.md` item 12 asks for real rayon-side numbers rather than an
//! estimate. A bare number is unrepeatable, and a speedup is worth nothing if the
//! parallel path returns different bytes: the packed output is what a commitment
//! folds over, so a result that depends on how the work was split is a fork, not
//! an optimization. The comparison below is part of the measurement - any
//! difference in the packed bytes exits with status 2 before a throughput line is
//! printed.
//!
//! # What is measured and what is not
//!
//! Measured: wall-clock cost of packing one corpus serially and through `rayon`,
//! the fastest of a fixed number of repetitions, and byte equality of the two
//! results. Not measured: SIMD width, allocator behaviour under load, and how the
//! numbers move across hosts. The ratio belongs to the machine that ran the step,
//! which is why it is quoted with its measurement site and never as a constant of
//! the protocol.

use std::process::exit;
use std::time::{Duration, Instant};

use budlum_core::storage::{pack_payload, PayloadKind};
use rayon::prelude::*;

/// Chunk size: the size class the pipe actually sees, not a synthetic byte count.
const CHUNK: usize = 64 * 1024;
/// Enough chunks for the pool to have work to spread, few enough to stay quick.
const COUNT: usize = 96;
/// Repetitions. The fastest is reported so a scheduler hiccup cannot become a
/// measurement.
const REPEAT: usize = 7;

/// Pack one chunk. A packing error means the corpus is malformed, and measuring
/// nothing is worse than not measuring.
fn pack_one(chunk: &[u8]) -> Vec<u8> {
    match pack_payload(PayloadKind::ContentBytes, chunk) {
        Ok(packed) => packed,
        Err(e) => {
            eprintln!("ratio_rayon: pack_payload refused the corpus: {e:?}");
            exit(2);
        }
    }
}

/// A deterministic corpus with real compressibility: a striding mix, so chunks
/// differ from each other and from random noise.
fn corpus() -> Vec<Vec<u8>> {
    (0..COUNT)
        .map(|i| {
            (0..CHUNK)
                .map(|j| {
                    let mixed = (i * 0x9E37_79B9).wrapping_add(j * 0x85EB_CAF0);
                    (((mixed >> ((j % 17) + 3)) ^ (mixed >> 21)) & 0xFF) as u8
                })
                .collect()
        })
        .collect()
}

/// One measured path: the fastest repetition and the output it produced.
fn measure<F>(data: &[Vec<u8>], run: F) -> (Duration, Vec<Vec<u8>>)
where
    F: Fn(&[Vec<u8>]) -> Vec<Vec<u8>>,
{
    let mut best: Option<(Duration, Vec<Vec<u8>>)> = None;
    for _ in 0..REPEAT {
        let start = Instant::now();
        let out = run(data);
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
            eprintln!("ratio_rayon: no repetition ran, refusing to report");
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
    let data = corpus();
    let bytes: usize = data.iter().map(|c| c.len()).sum();

    let (serial_time, serial_out) = measure(&data, |d| d.iter().map(|c| pack_one(c)).collect());
    let (pool_time, pool_out) = measure(&data, |d| d.par_iter().map(|c| pack_one(c)).collect());

    if serial_out != pool_out {
        eprintln!(
            "ratio_rayon: the rayon path packed a different byte string than the serial path.\n  \
             The packed output is what a commitment folds over, so a result that depends on how\n  \
             the work was split is not an optimization. Refusing to report throughput."
        );
        exit(2);
    }
    let packed: usize = serial_out.iter().map(|p| p.len()).sum();
    println!(
        "ratio_rayon: {COUNT} chunks of {CHUNK} B, {bytes} B in, {packed} B packed, {REPEAT} \
         repetitions, fastest reported"
    );
    println!(
        "ratio_rayon: serial {:.1} MB/s ({} us), rayon pool {:.1} MB/s ({} us), speedup {:.2}x",
        mb_per_second(bytes, serial_time),
        serial_time.as_micros(),
        mb_per_second(bytes, pool_time),
        pool_time.as_micros(),
        speedup(serial_time, pool_time)
    );
}
