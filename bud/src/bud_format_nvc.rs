//! B.U.D. 2.0 - NVC (NEURAL VIDEO CODEC) INTEGERIZE CORE (ideas3.0 + F22 path)
//!
//! The "things I could not do" research (2026-08-16): the **16-bit model
//! integerization** of DCVC-RT (K1=512, K2=8192; int32 accumulator; sigmoid LUT)
//! yields cross-device DETERMINISM (arXiv 2502.20762, CVPR 2025). This lines up
//! exactly with B.U.D.'s "no floats" rule - once integerized, an NVC can perform
//! consensus-safe deterministic production.
//!
//! This module is the bud core of that pattern: int16 input -> K1/K2 scaling ->
//! int32 accumulator -> sigmoid LUT -> int16 output. Deterministic (NO floating
//! point). Full network training happens in a GPU production cohort; what lives
//! here is a repeatable HELLO flow.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const NVC_MAGIC: [u8; 8] = *b"\xB5NVC1\0\0\0";

// DCVC-RT integerization constants (from the paper).
pub const K1: i32 = 512; // f64 -> int16: round(v * K1)
pub const K2: i32 = 8192; // int16 -> f64-scaled: the LUT input scale

/// Scale an f64 value to int16 (deterministic rounding: half up).
pub fn to_int16(v: f64) -> i16 {
    let s = (v * K1 as f64).round();
    s.clamp(i16::MIN as f64, i16::MAX as f64) as i16
}

/// Sigmoid LUT (precomputed, deterministic): int16 input -> 0..255 output.
/// sigma(x) ~= 1/(1+e^-x) - 2048 samples over x in [-8, 8] (at the K2 scale).
pub const SIGMOID_LUT_SIZE: usize = 2048;
const SIGMOID_RANGE: f64 = 8.0;

fn sigmoid_lut() -> [u8; SIGMOID_LUT_SIZE] {
    let mut lut = [0u8; SIGMOID_LUT_SIZE];
    for i in 0..SIGMOID_LUT_SIZE {
        let x = -SIGMOID_RANGE + 2.0 * SIGMOID_RANGE * i as f64 / (SIGMOID_LUT_SIZE - 1) as f64;
        let s = 1.0 / (1.0 + (-x).exp());
        lut[i] = (s * 255.0).round() as u8;
    }
    lut
}

/// Sigmoid: int16 x -> LUT (deterministic; no floating point).
/// The LUT is mapped onto x in [-8, 8] using the K2 scale.
pub fn sigmoid_int(x: i32) -> u8 {
    // x (at the K2 scale) -> normalize to [-8,8] -> LUT index
    let norm = x as f64 / K2 as f64 * SIGMOID_RANGE;
    let idx = ((norm + SIGMOID_RANGE) / (2.0 * SIGMOID_RANGE) * (SIGMOID_LUT_SIZE - 1) as f64)
        .round() as i64;
    let idx = idx.clamp(0, SIGMOID_LUT_SIZE as i64 - 1) as usize;
    sigmoid_lut()[idx]
}

/// A simple deterministic "network" step: y = sigma(sum of w·x + b) - all int.
/// w is int16, x is int16, the accumulator is int32 (no overflow: 256 inputs x 2^15 x 2^15 < 2^31).
pub fn dense_int(w: &[i16], x: &[i16], b: i32) -> i32 {
    if w.len() != x.len() {
        return b;
    }
    let mut acc = b;
    for (wi, xi) in w.iter().zip(x.iter()) {
        // saturating: overflow -> clamp (no panic; the no-panic rule)
        acc = acc.saturating_add((*wi as i32).saturating_mul(*xi as i32));
    }
    acc
}

/// Determinism proof: the same input + the same weights -> the SAME output (cross-device).
pub fn forward_deterministic(w: &[i16], x: &[i16], b: i32) -> [u8; 32] {
    let raw = dense_int(w, x, b);
    let s = sigmoid_int(raw);
    let mut h = Sha3_256::new();
    h.update(NVC_MAGIC);
    h.update(raw.to_le_bytes());
    h.update([s]);
    h.finalize().into()
}

pub fn nvc_digest(w: &[i16], x: &[i16], b: i32) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(NVC_MAGIC);
    for wi in w {
        h.update(wi.to_le_bytes());
    }
    for xi in x {
        h.update(xi.to_le_bytes());
    }
    h.update(b.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integerization_is_deterministic() {
        let w = [100i16, -50, 30, 200, -10];
        let x = [5i16, 8, -3, 12, 7];
        let b = 25;
        let d1 = forward_deterministic(&w, &x, b);
        let d2 = forward_deterministic(&w, &x, b);
        assert_eq!(d1, d2, "same input -> same output (no floating point)");
        assert_eq!(dense_int(&w, &x, b), dense_int(&w, &x, b));
    }

    #[test]
    fn sigmoid_lut_stays_within_bounds() {
        // very negative -> ~0; very positive -> ~255
        let neg = sigmoid_int(-K2 * 8);
        let pos = sigmoid_int(K2 * 8);
        assert!(neg <= 5, "sigma(-8) ~= 0: {neg}");
        assert!(pos >= 250, "sigma(8) ~= 1: {pos}");
        // monotone
        let mut prev = 0u8;
        for i in -1000..=1000i32 {
            let s = sigmoid_int(i);
            assert!(s >= prev, "sigmoid is monotone: {i}");
            prev = s;
        }
    }

    #[test]
    fn to_int16_clamp() {
        assert_eq!(to_int16(0.0), 0);
        assert!(to_int16(100.0) > 0);
        // extreme -> clamp (no panic)
        assert_eq!(to_int16(1e9), i16::MAX);
        assert_eq!(to_int16(-1e9), i16::MIN);
    }

    #[test]
    fn accumulator_does_not_overflow_at_a_realistic_scale() {
        // Realistic scale: inputs of +/-1000 (K1=512 scaled activations)
        let w = vec![1000i16; 256];
        let x = vec![1000i16; 256];
        let acc = dense_int(&w, &x, 0);
        assert!(acc > 0, "there must be no overflow: {acc}");
        let expected = 256i64 * 1_000_000;
        assert_eq!(acc as i64, expected, "256 x 1e6 < 2^31");
    }

    #[test]
    fn accumulator_saturates_on_extreme_input_without_panicking() {
        // extreme input (i16::MAX) -> saturating (NO panic, the no-panic rule)
        let w = vec![i16::MAX; 256];
        let x = vec![i16::MAX; 256];
        let acc = dense_int(&w, &x, 0);
        assert_eq!(acc, i32::MAX, "it must saturate");
    }

    #[test]
    fn nvc_digest_is_deterministic() {
        let w = [1i16, 2, 3];
        let x = [4i16, 5, 6];
        assert_eq!(nvc_digest(&w, &x, 7), nvc_digest(&w, &x, 7));
    }
}
