//! Differential bench (research bar item 2, pre-registration SS7.6): BPQS
//! under all three hash backends against the two reference PQ crates:
//!
//! - `ml-dsa` 0.1.1 - THE SAME VERSION THE ROOT PACKAGE LINKS in production
//!   (validator ML-DSA-65), so this table compares like for like against the
//!   operator-visible incumbent, not a strawman.
//! - `slh-dsa` 0.1.0 (SLH-DSA-Sha2-128s) - the conservative stateless-hash
//!   family baseline the research doc's size model cites.
//!
//! Honesty notes, printed into the table on purpose:
//!
//! 1. BPQS timings run on a FAST parameter lane (T_LOG2 = 6) so the bench
//!    finishes in seconds. The per-signature work is dominated by chain and
//!    path hashes whose counts are depth-independent, so verify timings
//!    carry over to the canonical row within a small additive term (ten
//!    extra node hashes for T_LOG2 = 16). Keygen time does NOT carry over:
//!    the canonical 2^16-ceremony is the deliberately offline cost measured
//!    separately by the ignored machine-lane test.
//! 2. Signature sizes are the WIRE CONTRACT numbers (canonical rows, bytes),
//!    not the fast-lane allocations.
//! 3. This is a research instrument behind dev-dependencies; it never links
//!    into the library, the production tree, or CI's benchmark job.
//!
//! Run: `cargo run --release --example bench_differential` (inside crates/bpqs).

use std::time::Instant;

use budlum_bpqs::sign::BpqsSigner;
use budlum_bpqs::{
    keygen_root, sign_at_height, verify_at_height, BpqsParams, EpochWindow,
    Poseidon2GoldilocksHash, Sha3_256Hash, Shake256Hash,
};
use ml_dsa::signature::{Signer as MlSigner, Verifier as MlVerifier};
use ml_dsa::Keypair as _;
use sha3::{Digest, Sha3_256};
use slh_dsa::signature::Verifier as SlhVerifier;
use slh_dsa::{Sha2_128s, SigningKey as SlhSigningKey, VerifyingKey as SlhVerifyingKey};

/// Fast timing lane for the bench (documented above; NOT a canonical row).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct BenchFast;

impl BpqsParams for BenchFast {
    const N: usize = 32;
    const WIN: u32 = 16;
    const LEN1: usize = 64;
    const LEN2: usize = 3;
    const LEN: usize = 67;
    const T_LOG2: usize = 6;
    const NAME: &'static str = "bpqs-bench-fast-lane";
}

/// Deterministic RNG for SLH-DSA keygen (research instrument: wall-clock
/// comparability wants a repeatable stream, not entropy). keystream =
/// SHA3-256("bench-rng-v1" || seed || counter_le) blocks.
struct BenchRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    pos: usize,
}

impl BenchRng {
    fn new(seed: [u8; 32]) -> Self {
        BenchRng {
            seed,
            counter: 0,
            block: [0u8; 32],
            pos: 32,
        }
    }
}

impl rand_core::RngCore for BenchRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for slot in dest.iter_mut() {
            if self.pos == 32 {
                let mut h = Sha3_256::new();
                h.update(b"bench-rng-v1");
                h.update(self.seed);
                h.update(self.counter.to_le_bytes());
                self.block.copy_from_slice(&h.finalize());
                self.counter += 1;
                self.pos = 0;
            }
            *slot = self.block[self.pos];
            self.pos += 1;
        }
    }
}

impl rand_core::CryptoRng for BenchRng {}

const MSG: &[u8] = b"bench: repeatable differential payload, not an anchor draft";

fn row(label: &str, keygen_us: f64, sign_us: f64, verify_us: f64, sig_bytes: usize) {
    println!(
        "| {label:<42} | {keygen_us:>10.0} | {sign_us:>10.0} | {verify_us:>10.0} | {sig_bytes:>6} |"
    );
}

fn bench_bpqs_row<H: budlum_bpqs::BpqsHash>(label: &str) {
    let t0 = Instant::now();
    let signer = BpqsSigner::<BenchFast, H>::ceremonial_keygen([7u8; 32], EpochWindow(3))
        .unwrap_or_else(|e| panic!("keygen: {e}"));
    let keygen_us = t0.elapsed().as_micros() as f64;

    // EpochWindow(3): rotate heights so every epoch sees at most 3 mints,
    // staying under q_max=4 the way the ceremony would.
    let iters = 20u32;
    let t1 = Instant::now();
    for i in 0..iters {
        let h = (i / 3) as u64 * 9 + [0u64, 3, 6][(i % 3) as usize];
        let _ = sign_at_height::<H, BenchFast>(&signer, h, i % 3, MSG)
            .unwrap_or_else(|e| panic!("sign: {e}"));
    }
    let sign_us = t1.elapsed().as_micros() as f64 / iters as f64;

    let sig =
        sign_at_height::<H, BenchFast>(&signer, 1, 0, MSG).unwrap_or_else(|e| panic!("s: {e}"));
    let t2 = Instant::now();
    for _ in 0..iters {
        verify_at_height::<H, BenchFast>(signer.public(), 1, MSG, &sig)
            .unwrap_or_else(|e| panic!("verify: {e}"));
    }
    let verify_us = t2.elapsed().as_micros() as f64 / iters as f64;

    // Wire contract of the CANONICAL L5 row (4 + 67*32 + 16*32 bytes).
    row(label, keygen_us, sign_us, verify_us, 2660);
}

fn bench_ml_dsa() {
    let seed = ml_dsa::Seed::try_from([9u8; 32].as_slice()).unwrap_or_else(|_| panic!("seed"));
    let t0 = Instant::now();
    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
    let keygen_us = t0.elapsed().as_micros() as f64;

    let iters = 50u32;
    let t1 = Instant::now();
    for _ in 0..iters {
        let _ = MlSigner::sign(&sk, MSG);
    }
    let sign_us = t1.elapsed().as_micros() as f64 / iters as f64;

    let sig = MlSigner::sign(&sk, MSG);
    let vk = sk.verifying_key();
    let t2 = Instant::now();
    for _ in 0..iters {
        if MlVerifier::verify(&vk, MSG, &sig).is_err() {
            panic!("ml-dsa verify failed");
        }
    }
    let verify_us = t2.elapsed().as_micros() as f64 / iters as f64;
    row(
        "ml-dsa-65 (root-linked 0.1.1)",
        keygen_us,
        sign_us,
        verify_us,
        3309,
    );
}

fn bench_slh_dsa() {
    let mut rng = BenchRng::new([3u8; 32]);
    let t0 = Instant::now();
    let sk = SlhSigningKey::<Sha2_128s>::new(&mut rng);
    let keygen_us = t0.elapsed().as_micros() as f64;

    let iters = 3u32; // Sha2-128s signing is deliberately slow; keep the wall clock sane
    let t1 = Instant::now();
    for i in 0..iters {
        let _ = sk
            .try_sign_with_context(MSG, &[i as u8], None)
            .unwrap_or_else(|_| panic!("slh sign"));
    }
    let sign_us = t1.elapsed().as_micros() as f64 / iters as f64;

    let sig = sk
        .try_sign_with_context(MSG, b"", None)
        .unwrap_or_else(|_| panic!("slh sign"));
    let vk: &SlhVerifyingKey<Sha2_128s> = sk.as_ref();
    let t2 = Instant::now();
    for _ in 0..iters {
        if SlhVerifier::verify(vk, MSG, &sig).is_err() {
            panic!("slh-dsa verify failed");
        }
    }
    let verify_us = t2.elapsed().as_micros() as f64 / iters as f64;
    let size = sig.to_bytes().len();
    row(
        "slh-dsa-sha2-128s (0.1.0)",
        keygen_us,
        sign_us,
        verify_us,
        size,
    );
}

fn main() {
    println!(
        "BPQS differential bench (research line F2, M2; fast lane timings, canonical wire sizes)"
    );
    println!();
    println!(
        "| {:<42} | {:>10} | {:>10} | {:>10} | {:>6} |",
        "scheme", "keygen us", "sign us", "verify us", "sig B"
    );
    println!(
        "|{:-<44}|{:-<12}|{:-<12}|{:-<12}|{:-<8}|",
        "", "", "", "", ""
    );
    bench_bpqs_row::<Poseidon2GoldilocksHash>("bpqs-l5 canonical backend: Poseidon2-GL16");
    bench_bpqs_row::<Sha3_256Hash>("bpqs-l5 cross-check 1: SHA3-256");
    bench_bpqs_row::<Shake256Hash>("bpqs-l5 cross-check 2: SHAKE-256");
    bench_ml_dsa();
    bench_slh_dsa();
    println!();
    println!("BPQS keygen cell is the T_LOG2=6 fast lane; the canonical 2^16 ceremony");
    println!("is the machine-lane measurement (ignored test), by design offline.");
    println!("BPQS verify work is chain-hash dominated and depth-independent to a");
    println!("small additive term; see the module header honesty notes.");

    // Frankly guard: canonical-row root derivability under Poseidon is the
    // differential anchor of the whole research line; fail loudly if the
    // three backends were ever aliased.
    let a = keygen_root::<Poseidon2GoldilocksHash, BenchFast>([1u8; 32], EpochWindow(3));
    let b = keygen_root::<Sha3_256Hash, BenchFast>([1u8; 32], EpochWindow(3));
    match (a, b) {
        (Ok(pa), Ok(pb)) => assert_ne!(pa.root, pb.root, "backends must not alias"),
        _ => panic!("sanity keygen failed"),
    }
}
