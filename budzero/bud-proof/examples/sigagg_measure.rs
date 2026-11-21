//! Proof size, proving time, and verification time of the bound sigagg chips.
//!
//! Prints Markdown tables for:
//! 1. `BoundKeccakAir` (Keccak-f[1600] permutations with preprocessed I/O binding),
//! 2. `BoundBatchProof` (bound Keccak-256 sponge over 16, 64, and 256 statement batches),
//! 3. `NttButterflyAir` (FIPS 204 ML-DSA-87 forward NTTs modulo q = 8_380_417).
//!
//! Every proof produced is verified before its timing is printed.

use bud_proof::chips::batch::{prove_bound_batch, verify_bound_batch, BatchStatement};
use bud_proof::chips::keccak::{prove_bound_keccak_f, verify_bound_keccak_f, ROWS_PER_PERMUTATION};
use bud_proof::chips::mldsa_ntt::{prove_ntt_batch, verify_ntt_batch, BUTTERFLIES_PER_NTT, N, Q};
use std::time::Instant;

fn sample_poly(seed: u64) -> [u64; N] {
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    let mut out = [0u64; N];
    for slot in &mut out {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *slot = (state >> 33) % Q;
    }
    out
}

fn sample_statement(index: usize) -> BatchStatement {
    let mut txid = [0u8; 32];
    txid[..8].copy_from_slice(&(index as u64).to_le_bytes());
    let mut from_address = [0xA5u8; 32];
    from_address[..8].copy_from_slice(&(index as u64).to_be_bytes());
    BatchStatement {
        txid,
        from_address,
        suite_id: 0x0103, // ML-DSA-87
    }
}

fn main() {
    let mut perm_batches: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|arg| arg.parse().ok())
        .collect();
    if perm_batches.is_empty() {
        perm_batches = vec![1, 16, 64, 256];
    }

    println!("### 1. BoundKeccakAir (Keccak-f[1600] with Preprocessed I/O Binding)");
    println!("| Permutations | Trace rows | Proof bytes | Prove ms | Verify ms |");
    println!("|---|---|---|---|---|");
    for &batch in &perm_batches {
        let inputs: Vec<[u64; 25]> = (0..batch)
            .map(|i| core::array::from_fn(|j| (i as u64 + 1).wrapping_mul(j as u64 + 7)))
            .collect();
        let rows = (batch * ROWS_PER_PERMUTATION).next_power_of_two();
        let start = Instant::now();
        let Ok((proof, outputs)) = prove_bound_keccak_f(&inputs) else {
            eprintln!("bound keccak proving failed for batch {batch}");
            std::process::exit(1);
        };
        let prove_ms = start.elapsed().as_secs_f64() * 1e3;
        let size = postcard::to_allocvec(&proof.proof).map_or(0, |b| b.len());
        let start = Instant::now();
        let verified = verify_bound_keccak_f(&inputs, &outputs, &proof).is_ok();
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;
        println!(
            "| {batch} | {rows} | {size} | {prove_ms:.1} | {verify_ms:.1}{} |",
            if verified { "" } else { " (REJECTED)" }
        );
    }

    println!();
    println!("### 2. BoundBatchProof (Tick Statement Batch Sponge: 16 / 64 / 256 Signatures)");
    println!("| Signatures | Sponge perms | Trace rows | Proof bytes | Prove ms | Verify ms |");
    println!("|---|---|---|---|---|---|");
    for sig_count in [16usize, 64, 256] {
        let statements: Vec<BatchStatement> = (0..sig_count).map(sample_statement).collect();
        let start = Instant::now();
        let Ok(proof) = prove_bound_batch(statements) else {
            eprintln!("bound batch proving failed for {sig_count} signatures");
            std::process::exit(1);
        };
        let prove_ms = start.elapsed().as_secs_f64() * 1e3;
        let perms = proof.outputs.len();
        let rows = (perms * ROWS_PER_PERMUTATION).next_power_of_two();
        let size = postcard::to_allocvec(&proof.keccak.proof).map_or(0, |b| b.len())
            + proof.outputs.len() * 25 * 8;
        let start = Instant::now();
        let verified = verify_bound_batch(&proof).is_ok();
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;
        println!(
            "| {sig_count} | {perms} | {rows} | {size} | {prove_ms:.1} | {verify_ms:.1}{} |",
            if verified { "" } else { " (REJECTED)" }
        );
    }

    println!();
    println!("### 3. NttButterflyAir (FIPS 204 ML-DSA-87 Forward NTT mod q = 8_380_417)");
    println!("| NTT polynomials | Trace rows | Proof bytes | Prove ms | Verify ms |");
    println!("|---|---|---|---|---|");
    for poly_count in [1usize, 4, 8] {
        let inputs: Vec<[u64; N]> = (0..poly_count).map(|i| sample_poly(i as u64 + 1)).collect();
        let rows = (poly_count * BUTTERFLIES_PER_NTT).next_power_of_two();
        let start = Instant::now();
        let Ok((outputs, proof)) = prove_ntt_batch(&inputs) else {
            eprintln!("ntt proving failed for {poly_count} polys");
            std::process::exit(1);
        };
        let prove_ms = start.elapsed().as_secs_f64() * 1e3;
        let size = postcard::to_allocvec(&proof.proof).map_or(0, |b| b.len());
        let start = Instant::now();
        let verified = verify_ntt_batch(&inputs, &outputs, &proof).is_ok();
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;
        println!(
            "| {poly_count} | {rows} | {size} | {prove_ms:.1} | {verify_ms:.1}{} |",
            if verified { "" } else { " (REJECTED)" }
        );
    }
}
