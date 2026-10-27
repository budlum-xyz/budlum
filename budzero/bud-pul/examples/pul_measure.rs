//! Proof size and proving time of the PUL chips per batch size.
//!
//! Prints a Markdown table. Today the only chip is Keccak-f[1600]: the ML-DSA-87
//! verification chips and `PulAir` do not exist yet, so this measures the Keccak
//! chip only and says so in its output. Timings depend on the machine and are not committed.

use bud_pul::keccak_chip::{prove_keccak_f, verify_keccak_f, ROWS_PER_PERMUTATION};
use std::time::Instant;

fn main() {
    println!(
        "| Keccak-f permutations | Trace rows (padded) | Proof bytes | Prove ms | Verify ms |"
    );
    println!("|---|---|---|---|---|");
    for batch in [1usize, 4, 16, 64] {
        let inputs: Vec<[u64; 25]> = (0..batch)
            .map(|i| core::array::from_fn(|j| (i as u64 + 1).wrapping_mul(j as u64 + 7)))
            .collect();
        let rows = (batch * ROWS_PER_PERMUTATION).next_power_of_two();
        let start = Instant::now();
        let Ok(proof) = prove_keccak_f(&inputs) else {
            eprintln!("proving failed for batch {batch}");
            std::process::exit(1);
        };
        let prove_ms = start.elapsed().as_secs_f64() * 1e3;
        let size = postcard::to_allocvec(&proof).map_or(0, |b| b.len());
        let start = Instant::now();
        let verified = verify_keccak_f(&proof).is_ok();
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;
        println!(
            "| {batch} | {rows} | {size} | {prove_ms:.1} | {verify_ms:.1}{} |",
            if verified { "" } else { " (REJECTED)" }
        );
    }
    println!();
    println!(
        "Keccak chip only: no ML-DSA-87 verification is proven inside bud-pul yet."
    );
}
