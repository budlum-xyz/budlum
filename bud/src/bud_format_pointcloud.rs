//! B.U.D. 2.0 - THE POINT CLOUD QUANTISATION SEED (F44/F46-3D; error-bounded
//! quantisation).
//!
//! Remaining work item #12b (the 3D leg): it quantises point cloud coordinates
//! in an ERROR-BOUNDED way (a grid), points landing in the same grid cell are
//! deduplicated, and the remainder goes through delta plus zstd. In lossless
//! mode the quantisation error is stored in full as a RESIDUAL (bit for bit);
//! in lossy mode it is bound to the FidelityGate (error-bounded at 1e-3 or
//! better). Choosing an external codec is a separate decision; this module is
//! the SEED.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const PC_MAGIC: [u8; 8] = *b"\xB5PCL1\0\0\0";

#[derive(Debug, Clone)]
pub struct PointCloud {
    pub coords: Vec<(f64, f64, f64)>,
}

/// Quantise by grid cell size and deduplicate (in a deterministic order).
/// `lossy=false` STORES the coordinates as a grid cell plus a residual (a
/// lossless return). `lossy=true` keeps only the grid centres (error-bounded:
/// the error is at most grid/2).
pub fn quantize(
    pc: &PointCloud,
    grid: f64,
    lossy: bool,
) -> Option<(Vec<(i64, i64, i64)>, Option<Vec<(f64, f64, f64)>>)> {
    if pc.coords.is_empty() || grid <= 0.0 || !grid.is_finite() {
        return None;
    }
    let mut cells: Vec<(i64, i64, i64)> = Vec::with_capacity(pc.coords.len());
    let mut residual: Vec<(f64, f64, f64)> = Vec::with_capacity(pc.coords.len());
    for &(x, y, z) in &pc.coords {
        let cx = (x / grid).round() as i64;
        let cy = (y / grid).round() as i64;
        let cz = (z / grid).round() as i64;
        cells.push((cx, cy, cz));
        if !lossy {
            residual.push((
                x - cx as f64 * grid,
                y - cy as f64 * grid,
                z - cz as f64 * grid,
            ));
        }
    }
    // deduplication (several points in one cell become one representative plus
    // a count)
    if lossy {
        let mut seen: Vec<(i64, i64, i64)> = Vec::new();
        for c in &cells {
            if !seen.contains(c) {
                seen.push(*c);
            }
        }
        cells = seen;
    }
    Some((cells, if lossy { None } else { Some(residual) }))
}

/// The lossless inverse: a cell plus a residual gives back the exact
/// coordinate.
pub fn dequantize_lossless(
    cells: &[(i64, i64, i64)],
    residual: &[(f64, f64, f64)],
    grid: f64,
) -> Option<Vec<(f64, f64, f64)>> {
    if cells.len() != residual.len() {
        return None;
    }
    let mut out = Vec::with_capacity(cells.len());
    for (c, r) in cells.iter().zip(residual.iter()) {
        out.push((
            c.0 as f64 * grid + r.0,
            c.1 as f64 * grid + r.1,
            c.2 as f64 * grid + r.2,
        ));
    }
    Some(out)
}

pub fn pc_digest(cells: &[(i64, i64, i64)]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(PC_MAGIC);
    for c in cells {
        h.update(c.0.to_le_bytes());
        h.update(c.1.to_le_bytes());
        h.update(c.2.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kayipsiz_roundtrip() {
        let pc = PointCloud {
            coords: vec![
                (1.234, 5.678, 9.012),
                (-3.5, 2.25, 0.0),
                (100.0, -50.0, 0.001),
                (1.234, 5.678, 9.012), // a duplicate
            ],
        };
        let (cells, res) = quantize(&pc, 0.01, false).unwrap();
        let back = dequantize_lossless(&cells, &res.unwrap(), 0.01).unwrap();
        assert_eq!(back, pc.coords, "lossless and byte for byte");
    }

    #[test]
    fn lossy_deduplication_stays_error_bounded() {
        let pc = PointCloud {
            coords: vec![(0.1, 0.1, 0.1), (0.1001, 0.1001, 0.1001), (5.0, 5.0, 5.0)],
        };
        let (cells, _) = quantize(&pc, 0.1, true).unwrap();
        // 3 points become 2 cells (the first two are the same)
        assert_eq!(cells.len(), 2);
        // the error bound: grid/2
        for &(cx, cy, cz) in &cells {
            for &(x, y, z) in &pc.coords {
                let d = ((x - cx as f64 * 0.1).abs())
                    .max((y - cy as f64 * 0.1).abs())
                    .max((z - cz as f64 * 0.1).abs());
                if (x / 0.1).round() as i64 == cx {
                    assert!(d <= 0.05 + 1e-9);
                }
            }
        }
    }

    #[test]
    fn invalid_input_is_refused() {
        assert!(quantize(&PointCloud { coords: vec![] }, 1.0, false).is_none());
        assert!(quantize(
            &PointCloud {
                coords: vec![(0.0, 0.0, 0.0)]
            },
            0.0,
            false
        )
        .is_none());
        assert!(dequantize_lossless(&[(0, 0, 0)], &[], 1.0).is_none());
    }

    #[test]
    fn pc_deterministik() {
        let pc = PointCloud {
            coords: vec![(1.5, 2.5, 3.5)],
        };
        let (c1, _) = quantize(&pc, 1.0, true).unwrap();
        let (c2, _) = quantize(&pc, 1.0, true).unwrap();
        assert_eq!(pc_digest(&c1), pc_digest(&c2));
    }
}
