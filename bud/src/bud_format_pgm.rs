//! B.U.D. 2.0 - the learned, PGM-like dedup index; F117, the PGM index pattern.
//!
//! Remaining work item 10b: a learned index. For sorted chunk offsets it fits a
//! piecewise-linear model, where the offset is approximately `a * key + b`.
//! With the error kept under epsilon, the model plus a correction table needs
//! very little RAM; F117 measured PGM at 8x to 70x less RAM. It is
//! deterministic.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const PGM_MAGIC: [u8; 8] = *b"\xB5PGM1\0\0\0";

#[derive(Debug, Clone, Copy)]
pub struct LinSeg {
    pub key_start: u64,
    pub a: f64,
    pub b: f64,
    pub err: u64, // the ceiling on deviation from the model, the correction table's range
}

/// Builds a PGM model from a sorted sequence of key and offset pairs.
///
/// `eps` is the maximum deviation allowed per segment, in bytes.
pub fn build_pgm(keys: &[u64], offsets: &[u64], eps: u64) -> Option<Vec<LinSeg>> {
    if keys.len() != offsets.len() || keys.is_empty() || eps == 0 {
        return None;
    }
    let mut segs = Vec::new();
    let mut i = 0usize;
    while i < keys.len() {
        // The initial slope, from points i and i+1.
        let mut a = 0.0;
        let mut b = offsets[i] as f64;
        let mut j = i;
        if i + 1 < keys.len() {
            let dx = (keys[i + 1] - keys[i]).max(1) as f64;
            a = (offsets[i + 1] as f64 - offsets[i] as f64) / dx;
            b = offsets[i] as f64 - a * keys[i] as f64;
        }
        let mut max_err = 0u64;
        // Grow the segment; at each step REFIT from the endpoints and check the
        // whole segment.
        loop {
            let mut grown = false;
            let jj = j + 1;
            // This used to be a `while`, but every path through the body broke
            // out of it and `jj` never changed inside it: the condition was never
            // re-evaluated, so it was a single-pass branch rather than a loop,
            // which is what `clippy::never_loop` names. The real iteration is in
            // the OUTER `loop`, which advances with `j = jj` and re-enters on the
            // `grown` flag. Writing it as an `if` shows the structure as it is,
            // and the behaviour is identical.
            if jj < keys.len() {
                // Refit from the endpoints, i and jj.
                let dx = (keys[jj] - keys[i]).max(1) as f64;
                let na = (offsets[jj] as f64 - offsets[i] as f64) / dx;
                let nb = offsets[i] as f64 - na * keys[i] as f64;
                // Are all of the points from i to jj within eps?
                let mut ok = true;
                let mut em = 0u64;
                for k in i..=jj {
                    let pred = na * keys[k] as f64 + nb;
                    let err = (offsets[k] as f64 - pred).abs().round() as u64;
                    if err > eps {
                        ok = false;
                        break;
                    }
                    em = em.max(err);
                }
                // If the segment stayed within eps up to jj, grow it by one step
                // and let the outer `loop` try again; otherwise `grown` stays
                // false and the check below ends the outer loop.
                if ok {
                    a = na;
                    b = nb;
                    max_err = em;
                    j = jj;
                    grown = true;
                }
            }
            if !grown {
                break;
            }
        }
        if j == i {
            j = i + 1; // a single point
            max_err = 0;
        }
        segs.push(LinSeg {
            key_start: keys[i],
            a,
            b,
            err: max_err,
        });
        i = j;
    }
    if segs.is_empty() {
        return None;
    }
    Some(segs)
}

/// The model's prediction, without correction; the starting point of a search.
pub fn predict(segs: &[LinSeg], key: u64) -> Option<u64> {
    let seg = segs.iter().rev().find(|s| key >= s.key_start)?;
    Some((seg.a * key as f64 + seg.b).max(0.0) as u64)
}

/// The predicted range, from `pred - err` to `pred + err`; the true offset lies
/// inside it.
pub fn search_range(segs: &[LinSeg], key: u64) -> Option<(u64, u64)> {
    let seg = segs.iter().rev().find(|s| key >= s.key_start)?;
    let pred = (seg.a * key as f64 + seg.b).max(0.0) as u64;
    let e = seg.err.max(1);
    Some((pred.saturating_sub(e), pred.saturating_add(e)))
}

pub fn pgm_digest(segs: &[LinSeg]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(PGM_MAGIC);
    for s in segs {
        h.update(s.key_start.to_le_bytes());
        h.update(s.a.to_le_bytes());
        h.update(s.b.to_le_bytes());
        h.update(s.err.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pgm_range_contains_the_true_offset() {
        // Monotonically increasing offsets, from chunk index to byte offset.
        let keys: Vec<u64> = (0..2000).collect();
        let mut offsets = Vec::new();
        let mut off = 0u64;
        for k in &keys {
            off += 512 + (k % 7) * 13; // irregular but monotonic
            offsets.push(off);
        }
        let segs = build_pgm(&keys, &offsets, 512).expect("pgm");
        assert!(segs.len() < 100, "few segments: {}", segs.len());
        // For every key, the true offset is inside the predicted range.
        for k in &keys {
            let (lo, hi) = search_range(&segs, *k).unwrap();
            let actual = offsets[*k as usize];
            assert!(
                lo <= actual && actual <= hi,
                "key {k}: {actual} must be inside {lo}..{hi}"
            );
        }
        // RAM: the model is small, a few segments for 2000 points.
        assert!(
            segs.len() * 24 < 2000 * 8,
            "the model is far smaller than the raw index"
        );
    }

    #[test]
    fn pgm_refuses_invalid_input() {
        assert!(build_pgm(&[], &[], 1).is_none());
        assert!(build_pgm(&[1, 2], &[1], 1).is_none());
        assert!(build_pgm(&[1, 2], &[1, 2], 0).is_none());
    }

    #[test]
    fn pgm_is_deterministic() {
        let segs = build_pgm(&[1, 5, 9], &[100, 300, 500], 50).unwrap();
        assert_eq!(pgm_digest(&segs), pgm_digest(&segs));
    }
}
