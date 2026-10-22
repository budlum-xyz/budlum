//! Throughput of the Poseidon2 permutation. Not a security measurement -
//! `dudect_poseidon2` is that one. This answers the separate question "what
//! does the constant-time guarantee cost", which had been answered by
//! guesswork until it was measured.
//!
//! Measured 2026-09-24 on the CI-class host, 200k permutations per run,
//! best of three. `cmov` counts and conditional-jump counts are from
//! `objdump -d` over the `permute16` body; the jumps in the accepted variant
//! are backward round-loop control, not data-dependent branches.
//!
//! | variant                                   | ns/perm | cmov | cond. jumps |
//! | :---------------------------------------- | ------: | ---: | ----------: |
//! | A. `cmov` crate (SHIPPED)                 |    5714 |   59 |           6 |
//! | B. masked select (pre-Strix)              |    3796 |   69 |          41 |
//! | D. correction by multiply, no select      |    7789 |   56 |          28 |
//! | E. correction by mask-AND, no select      |    7745 |   56 |          28 |
//! | F. A with `#[inline(always)]`             |    5674 |   59 |           6 |
//!
//! Reading, and the reason the slow one ships:
//!
//! - B is 1.5x faster and is exactly what Strix reported: dropping the
//!   conditional-move backend lets LLVM recover the branch, and the jump
//!   count goes 6 -> 41. That is the leak, measured, not argued.
//! - D and E replace the select with arithmetic on a 0/1. Both are WORSE on
//!   both axes - slower than A and still branchier - so "avoid the select"
//!   is not a free win here.
//! - A hand-rolled `asm!` cmov with `options(pure, nomem)` was tried and
//!   rejected: this crate forbids `unsafe`, and trading a zero-unsafe surface
//!   for throughput is a worse deal than the throughput is worth. The `cmov`
//!   crate exists to hold that `unsafe` behind a reviewed boundary.
//! - F is inside run-to-run noise, so it is not treated as a win.
//!
//! Conclusion: the 1.5-1.6x is the honest price of the guarantee on this
//! target, not an implementation slip. Anyone proposing to reclaim it should
//! beat 5714 ns/perm while keeping the jump count at 6.

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let batches: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    // Same shape the dudect harness uses: a pool, so the loop is not replaying
    // one cache-hot input and calling that a throughput number.
    const POOL: usize = 256;
    let mut pool = Vec::with_capacity(POOL);
    let mut seed = 0x243F_6A88_85A3_08D3u64;
    for _ in 0..POOL {
        let mut st = [0u64; budlum_bpqs::poseidon2::WIDTH];
        for lane in st.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *lane = seed % budlum_bpqs::poseidon2::GOLDILOCKS_P;
        }
        pool.push(st);
    }

    // Warm up, so the first timed batch is not paying for page faults.
    for st in pool.iter().take(64) {
        let mut s = *st;
        budlum_bpqs::poseidon2::permute16(&mut s);
        black_box(s);
    }

    let start = Instant::now();
    let mut acc = 0u64;
    for i in 0..batches {
        let mut s = pool[i % POOL];
        budlum_bpqs::poseidon2::permute16(black_box(&mut s));
        acc ^= s[0];
    }
    let elapsed = start.elapsed();
    black_box(acc);

    let per = elapsed.as_secs_f64() * 1e9 / batches as f64;
    println!("{batches} permutations in {elapsed:?}");
    println!("per permutation: {per:.1} ns");
}
