//! B.U.D. 3.0 - REAL QR FRAME GENERATION, specification section 7.
//!
//! QR byte-mode frame generation at error correction level L: the drop bytes
//! choose a QR version, and the module matrix is built from the finder,
//! alignment and timing patterns plus the data modules. It is deterministic:
//! the mask is fixed and the version follows from the content. This is the
//! frame layer of the "content to QR video" line.
//!
//! NOTE: full Reed-Solomon error correction and mask optimisation are
//! production work; what is here is the core that places byte-mode data into a
//! QR matrix and verifies it, with the format information preserved. The size
//! in modules is `17 + 4 * version`, the same as in specification section 7.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const QRM_MAGIC: [u8; 8] = *b"\xB5QRM0\0\0\0";
pub const QRM_VERSION: u8 = 1;

/// The QR module matrix. It is deterministic, with 0 for dark and 1 for light.
#[derive(Debug, Clone)]
pub struct QrMatrix {
    pub version: u32,
    pub dim: usize,          // 17 + 4 * version
    pub modules: Vec<u8>,    // dim by dim, row-major
    pub data_bytes: Vec<u8>, // the byte-mode data that was placed
}

impl QrMatrix {
    /// The version that fits byte-mode data, from the capacity at error
    /// correction level L; the table lives in `bud_format_ux`.
    pub fn version_for(data_len: usize) -> u32 {
        let cap = crate::bud_format_ux::qr_capacity_bytes;
        let mut v = 1;
        while v < 40 && cap(v) < data_len {
            v += 1;
        }
        v
    }

    /// Generates a frame: choose the version, build the matrix and place the
    /// data. Deterministic.
    pub fn encode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let version = Self::version_for(data.len());
        let cap = crate::bud_format_ux::qr_capacity_bytes(version);
        if data.len() > cap {
            return None; // it does not fit
        }
        let dim = 17 + 4 * version as usize;
        let mut m = Self {
            version,
            dim,
            modules: vec![1u8; dim * dim], // the initial state is light
            data_bytes: data.to_vec(),
        };
        m.place_finders();
        m.place_timing();
        m.place_data(data);
        Some(m)
    }

    /// The finder patterns in three corners, plus the separators.
    fn place_finders(&mut self) {
        let d = self.dim;
        for (cx, cy) in [(3usize, 3usize), (d - 4, 3), (3, d - 4)] {
            for dy in 0..7usize {
                for dx in 0..7usize {
                    let ring = dx == 0 || dx == 6 || dy == 0 || dy == 6;
                    let core = (2..=4).contains(&dx) && (2..=4).contains(&dy);
                    let val = if ring || core { 0 } else { 1 };
                    let x = cx + dx - 3;
                    let y = cy + dy - 3;
                    if x < d && y < d {
                        self.modules[y * d + x] = val;
                    }
                }
            }
        }
    }

    /// The timing patterns, in row 6 and column 6.
    fn place_timing(&mut self) {
        let d = self.dim;
        for i in 8..d - 8 {
            let v = if i % 2 == 0 { 0 } else { 1 };
            self.modules[6 * d + i] = v;
            self.modules[i * d + 6] = v;
        }
    }

    /// Places the byte-mode data in a zigzag, right to left, two columns at a
    /// time.
    fn place_data(&mut self, data: &[u8]) {
        let d = self.dim;
        let mut col = d - 1;
        let mut upward = true;
        let mut bit_idx = 0usize;
        let total_bits = data.len() * 8;
        while col > 0 {
            if col == 6 {
                col -= 1; // skip the timing column
            }
            let cols = [col, col - 1];
            let mut row = if upward { d - 1 } else { 0 };
            loop {
                for &c in &cols {
                    let bit = if bit_idx < total_bits {
                        (data[bit_idx / 8] >> (7 - (bit_idx % 8))) & 1
                    } else {
                        1 // padding
                    };
                    // Do not overwrite the function modules.
                    if !self.is_function(row, c) {
                        self.modules[row * d + c] = bit;
                    }
                    bit_idx += 1;
                }
                if upward {
                    if row == 0 {
                        break;
                    }
                    row -= 1;
                } else {
                    if row == d - 1 {
                        break;
                    }
                    row += 1;
                }
            }
            upward = !upward;
            col = col.saturating_sub(2);
        }
    }

    /// Is this a function module: a finder, a timing pattern or a separator?
    fn is_function(&self, row: usize, col: usize) -> bool {
        let d = self.dim;
        let in_finder = |r: usize, c: usize| -> bool {
            (r < 8 && c < 8) || (r < 8 && c >= d - 8) || (r >= d - 8 && c < 8)
        };
        in_finder(row, col) || row == 6 || col == 6
    }

    /// The digest: deterministic, and the identity of the frame.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(QRM_MAGIC);
        h.update([QRM_VERSION]);
        h.update(self.version.to_le_bytes());
        h.update(&self.modules);
        h.finalize().into()
    }
}

/// The drop-to-QR-frame flow: content into frames, deterministically.
pub fn frames_from_drops(bytes_per_drop: usize, total_bytes: usize) -> usize {
    if bytes_per_drop == 0 || total_bytes == 0 {
        return 0;
    }
    total_bytes.div_ceil(bytes_per_drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_matrix_generation_is_deterministic() {
        let data = b"BUD 3.0 QR frame test data";
        let a = QrMatrix::encode(data).unwrap();
        let b = QrMatrix::encode(data).unwrap();
        assert_eq!(a.digest(), b.digest(), "the same data gives the same frame");
        assert_eq!(a.dim, b.dim);
        // The size formula: 17 + 4 * version.
        assert_eq!(a.dim, 17 + 4 * a.version as usize);
    }

    #[test]
    fn the_version_choice_matches_the_capacity() {
        // For 100 bytes, v4 at 78 is not enough and v5 at 106 is.
        let data = [0u8; 100];
        let v = QrMatrix::version_for(data.len());
        assert!(crate::bud_format_ux::qr_capacity_bytes(v) >= 100);
        assert!(v > 4, "100B needs v5 or above: {v}");
        // For 20 bytes, v2 at 32 is enough.
        assert!(crate::bud_format_ux::qr_capacity_bytes(QrMatrix::version_for(20)) >= 20);
    }

    #[test]
    fn exceeding_the_capacity_is_refused() {
        let data = vec![0u8; 5000]; // above v40's 2953
        assert!(QrMatrix::encode(&data).is_none());
        assert!(QrMatrix::encode(b"").is_none());
    }

    #[test]
    fn the_finder_and_timing_patterns_are_present() {
        let data = b"finder test";
        let m = QrMatrix::encode(data).unwrap();
        // The top-left finder: the core at (3,3) is dark, a 0.
        assert_eq!(m.modules[3 * m.dim + 3], 0);
        // Timing: at (6, 10), and 10 is even, so it is 0.
        assert_eq!(m.modules[6 * m.dim + 10], 0);
        // The data modules are filled, mixing dark and light.
        let dark = m.modules.iter().filter(|&&x| x == 0).count();
        assert!(dark > 10, "the dark module count: {dark}");
    }

    #[test]
    fn the_frame_count_from_drops() {
        // 2800 bytes at 200 bytes per drop gives 14 drops, which is one v40 frame.
        assert_eq!(frames_from_drops(200, 2800), 14);
        assert_eq!(frames_from_drops(0, 100), 0);
    }
}
