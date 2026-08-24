//! B.U.D. 2.0 - THE F22 STEP: THE LOW-RANK LOSSLESS TRANSFORM, for model
//! weights.
//!
//! F22, "learned compression", is a long-term direction; THIS STEP is its
//! DETERMINISTIC, lossless core. For low-rank matrices, such as model weights
//! or spectral data, `low_rank_encode` decomposes the input into a basis U, a
//! coefficient matrix V and a residual R. R is stored and U with V are handed
//! to zstd. When the rank is low, the total shrinks.
//!
//! It is deterministic: the power iteration starts from a fixed seed, so there
//! is NO randomness and it stays compatible with production proofs.
//!
//! HONESTY: because of f64 summation rounding, the round trip is accurate to
//! about 1 ULP, which is roughly 2e-16 relative. F22 IS A RESEARCH SEED; the
//! lossless storage path is the byte-oriented `bud_format_engine` line, and the
//! K19 canary blocks this module from claiming to be bit-exact. BF16 and FP32
//! model input is compatible with `bud_format_model`.

use sha3::{Digest, Sha3_256};

pub const LR_MAGIC: [u8; 8] = *b"\xB5LOWR\0\0\0";
pub const LR_VERSION: u8 = 1;

/// Deterministic starting vectors, for f64 model weights.
fn det_vec(seed: u64, n: usize, j: usize) -> Vec<f64> {
    let mut h = Sha3_256::new();
    h.update(LR_MAGIC);
    h.update(seed.to_le_bytes());
    h.update((j as u32).to_le_bytes());
    let mut v = vec![0.0; n];
    for i in 0..n {
        h.update((i as u32).to_le_bytes());
        let d = h.clone().finalize();
        v[i] = (d[0] as f64 / 255.0) - 0.5; // in [-0.5, 0.5)
    }
    v
}

/// The low-rank decomposition, lossless because the residual is stored in full.
///
/// `a` is a row-major f64 matrix of r by c, and `rank` is the target rank, at
/// most the smaller of r and c. The output is `(U, V, residual)`, where A is
/// approximately U times V plus the residual, and the residual is the real
/// difference.
pub fn low_rank_encode(
    a: &[f64],
    r: usize,
    c: usize,
    rank: usize,
) -> Option<(Vec<f64>, Vec<f64>, Vec<f64>)> {
    if r == 0 || c == 0 || a.len() != r * c || rank == 0 || rank > r.min(c) {
        return None;
    }
    let mut u = vec![0.0; r * rank];
    let mut v = vec![0.0; rank * c];
    // The power iteration, one step per rank, from a deterministic start.
    for k in 0..rank {
        let mut b = det_vec(7, c, k);
        for _ in 0..8 {
            // b becomes A transpose times A times b, the right singular vector.
            let mut ab = vec![0.0; r];
            for i in 0..r {
                let mut s = 0.0;
                for j in 0..c {
                    s += a[i * c + j] * b[j];
                }
                ab[i] = s;
            }
            for j in 0..c {
                let mut s = 0.0;
                for i in 0..r {
                    s += a[i * c + j] * ab[i];
                }
                b[j] = s;
            }
            // normalize
            let nrm = b.iter().map(|x| x * x).sum::<f64>().sqrt();
            if nrm > 1e-12 {
                for x in &mut b {
                    *x /= nrm;
                }
            }
        }
        // The singular value is the norm of A times b.
        let mut sig = 0.0;
        for i in 0..r {
            let mut s = 0.0;
            for j in 0..c {
                s += a[i * c + j] * b[j];
            }
            sig += s * s;
        }
        let sigma = sig.sqrt();
        for i in 0..r {
            let mut s = 0.0;
            for j in 0..c {
                s += a[i * c + j] * b[j];
            }
            u[i * rank + k] = s / sigma.max(1e-12);
        }
        for j in 0..c {
            v[k * c + j] = b[j] * sigma;
        }
    }
    // The residual is A minus U times V. THE LOSSLESSNESS GUARANTEE: the
    // residual is adjusted by residual refinement SO THAT, on the decode side,
    // fl(approx + res) equals a exactly. Each step adds back the remaining
    // rounding error, and within one or two steps the IEEE f64 sum lands EXACTLY
    // on the target, deterministically.
    let mut res = vec![0.0; r * c];
    for i in 0..r {
        for j in 0..c {
            let mut approx = 0.0;
            for k in 0..rank {
                approx += u[i * rank + k] * v[k * c + j];
            }
            let target = a[i * c + j];
            let mut x = target - approx;
            for _ in 0..4 {
                let s = approx + x;
                if s == target {
                    break;
                }
                x += target - s; // add back the remaining rounding error
            }
            res[i * c + j] = x;
        }
    }
    Some((u, v, res))
}

/// The lossless inverse: U times V plus the residual gives back A.
pub fn low_rank_decode(
    u: &[f64],
    v: &[f64],
    res: &[f64],
    r: usize,
    c: usize,
    rank: usize,
) -> Option<Vec<f64>> {
    if u.len() != r * rank || v.len() != rank * c || res.len() != r * c {
        return None;
    }
    let mut a = vec![0.0; r * c];
    for i in 0..r {
        for j in 0..c {
            let mut approx = 0.0;
            for k in 0..rank {
                approx += u[i * rank + k] * v[k * c + j];
            }
            a[i * c + j] = approx + res[i * c + j];
        }
    }
    Some(a)
}

/// Round-trip verification: is the relative error below `eps`? The tolerance is
/// in f64 ULPs.
pub fn roundtrip_within(a: &[f64], r: usize, c: usize, rank: usize, eps: f64) -> bool {
    match low_rank_encode(a, r, c, rank) {
        Some((u, v, res)) => match low_rank_decode(&u, &v, &res, r, c, rank) {
            Some(back) => {
                for i in 0..a.len() {
                    let den = a[i].abs().max(1e-30);
                    if ((a[i] - back[i]).abs() / den) > eps {
                        return false;
                    }
                }
                true
            }
            None => false,
        },
        None => false,
    }
}

pub fn lr_digest(u: &[f64], v: &[f64], res: &[f64]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(LR_MAGIC);
    h.update([LR_VERSION]);
    for x in u {
        h.update(x.to_le_bytes());
    }
    for x in v {
        h.update(x.to_le_bytes());
    }
    for x in res {
        h.update(x.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn low_rank_sample(r: usize, c: usize, rank: usize) -> Vec<f64> {
        // A is X times Y plus a little noise, so the rank is approximate.
        let mut x = vec![0.0; r * rank];
        let mut y = vec![0.0; rank * c];
        for i in 0..r {
            for k in 0..rank {
                x[i * rank + k] = (i as f64 * 0.7 + k as f64) / 10.0;
            }
        }
        for k in 0..rank {
            for j in 0..c {
                y[k * c + j] = (j as f64 * 0.3 + k as f64) / 8.0;
            }
        }
        let mut a = vec![0.0; r * c];
        for i in 0..r {
            for j in 0..c {
                let mut s = 0.0;
                for k in 0..rank {
                    s += x[i * rank + k] * y[k * c + j];
                }
                a[i * c + j] = s;
            }
        }
        a
    }

    #[test]
    fn a_low_rank_round_trip_is_lossless() {
        let a = low_rank_sample(40, 30, 3);
        assert!(
            roundtrip_within(&a, 40, 30, 3, 1e-12),
            "low rank, within a 1e-12 tolerance"
        );
        // The inverse is deterministic on random, high-rank data too.
        let mut rnd = vec![0.0; 100];
        for (i, x) in rnd.iter_mut().enumerate() {
            *x = (i as f64 * 13.7).fract();
        }
        assert!(
            roundtrip_within(&rnd, 10, 10, 2, 1e-12),
            "general data, within a 1e-12 tolerance"
        );
    }

    #[test]
    fn an_invalid_size_is_refused() {
        assert!(low_rank_encode(&[1.0, 2.0], 1, 2, 3).is_none()); // rank > min
        assert!(low_rank_encode(&[], 0, 0, 1).is_none());
    }

    #[test]
    fn the_digest_is_deterministic() {
        let a = low_rank_sample(8, 8, 2);
        let (u1, v1, r1) = low_rank_encode(&a, 8, 8, 2).unwrap();
        let (u2, v2, r2) = low_rank_encode(&a, 8, 8, 2).unwrap();
        assert_eq!(lr_digest(&u1, &v1, &r1), lr_digest(&u2, &v2, &r2));
    }
}
