//! Dedicated Plonky3 STARK coprocessor chips for post-quantum signature
//! aggregation (`BoundKeccakAir`, `NttButterflyAir`, and batch sponge proofs).
//!
//! WIRING: `budlum_core::aggregation::programs::chip_offload` drives these
//! chips to offload `Keccak-f[1600]` and `ML-DSA-87` NTT butterflies out of
//! the `BudZKVM` CPU trace.

pub mod batch;
pub mod fib;
pub mod fold;
pub mod keccak;
pub mod merkle_path;
pub mod mldsa_ntt;
