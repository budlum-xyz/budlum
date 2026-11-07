//! B.U.D. 3.0 lossless compression pipeline throughput: serial vs rayon pool,
//! asserting bit-identical deterministic output across serial and parallel runs.

use std::process::exit;
use std::time::{Duration, Instant};

use rayon::prelude::*;

const CHUNK: usize = 64 * 1024;
const COUNT: usize = 96;
const REPEAT: usize = 7;

fn pack_one(chunk: &[u8]) -> Vec<u8> {
    match bud_codec::encode(bud_codec::ZSTD, chunk) {
        Ok(packed) => packed,
        Err(e) => {
            eprintln!("ratio_rayon: bud_codec::encode refused corpus: {e:?}");
            exit(2);
        }
    }
}

fn corpus() -> Vec<Vec<u8>> {
    (0..COUNT)
        .map(|i| {
            (0..CHUNK)
                .map(|j| ((j.wrapping_mul(13) ^ i.wrapping_mul(7)) & 0x3F) as u8)
                .collect()
        })
        .collect()
}

fn fastest<F: FnMut() -> Vec<Vec<u8>>>(mut f: F) -> (Duration, Vec<Vec<u8>>) {
    let mut best = Duration::MAX;
    let mut sample = Vec::new();
    for _ in 0..REPEAT {
        let start = Instant::now();
        let out = f();
        let elapsed = start.elapsed();
        if elapsed < best {
            best = elapsed;
            sample = out;
        }
    }
    (best, sample)
}

fn main() {
    let chunks = corpus();
    let total_bytes = CHUNK * COUNT;
    let (serial_dt, serial_out) = fastest(|| chunks.iter().map(|c| pack_one(c)).collect());
    let (par_dt, par_out) = fastest(|| chunks.par_iter().map(|c| pack_one(c)).collect());
    if serial_out != par_out {
        eprintln!("ratio_rayon: parallel and serial encoded outputs diverged");
        exit(2);
    }
    let packed_bytes: usize = serial_out.iter().map(Vec::len).sum();
    let mib = total_bytes as f64 / (1024.0 * 1024.0);
    println!(
        "ratio_rayon OK: {:.2} MiB -> {} bytes | serial {:.2} MiB/s | rayon {:.2} MiB/s",
        mib,
        packed_bytes,
        mib / serial_dt.as_secs_f64().max(1e-9),
        mib / par_dt.as_secs_f64().max(1e-9),
    );
}
