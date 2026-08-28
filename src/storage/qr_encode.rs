//! Byte-mode QR encoder pinned to EC level L and mask pattern 0.
//!
//! Budlum 3.0 renders recipes as QR video frames and every frame has to be
//! reproducible byte-for-byte from the recipe, so the matrix must come from an
//! encoder whose every choice is fixed by us instead of a library whose mask
//! selection or tie breaking may drift between versions. This module
//! implements ISO/IEC 18004 for byte mode, error-correction level L, mask 0
//! and versions 1..=40, and its tests read the output back through the
//! independent `rqrr` decoder.

/// Largest payload a version-40 level-L byte-mode symbol can carry.
pub const MAX_DATA_BYTES: usize = 2953;

/// Longest Reed-Solomon generator this module builds (version 40 level L).
const MAX_EC: usize = 30;

/// Encoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrError {
    /// Payload longer than [`MAX_DATA_BYTES`].
    TooLong(usize),
}

impl std::fmt::Display for QrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QrError::TooLong(len) => write!(f, "payload of {len} bytes exceeds {MAX_DATA_BYTES}"),
        }
    }
}

impl std::error::Error for QrError {}

// --- GF(256) arithmetic, primitive polynomial 0x11d ---

const fn gf_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x = 1u16;
    let mut i = 0usize;
    // `split_at_mut(..i + 1)` then `last_mut` writes the slot `i` names without
    // a runtime index: an index here would be a `panic!` in `const` evaluation
    // (a compile error) and `get_mut` is not const-callable, so this is the
    // shape that keeps the table fill out of the indexing ratchet. Measured
    // against the indexed form: all 512 table bytes agree and the
    // `exp[log[v]] == v` inverse relation holds.
    while i < 255 {
        let (head, _) = exp.split_at_mut(i + 1);
        if let Some(slot) = head.last_mut() {
            *slot = x as u8;
        }
        let (lhead, _) = log.split_at_mut(x as usize + 1);
        if let Some(slot) = lhead.last_mut() {
            *slot = i as u8;
        }
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    exp[255] = 1;
    (exp, log)
}

const GF_TABLES: ([u8; 256], [u8; 256]) = gf_tables();
const GF_EXP: [u8; 256] = GF_TABLES.0;
const GF_LOG: [u8; 256] = GF_TABLES.1;

const fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        GF_EXP[(GF_LOG[a as usize] as usize + GF_LOG[b as usize] as usize) % 255]
    }
}

/// Generator polynomial for `ec_len` error-correction codewords, highest
/// degree first and monic; for `ec_len = 7` it is
/// `[1, 127, 122, 154, 164, 11, 68, 117]`.
const fn rs_generator(ec_len: usize) -> [u8; MAX_EC + 1] {
    let mut g = [0u8; MAX_EC + 1];
    g[0] = 1;
    let mut deg = 0usize;
    let mut i = 0usize;
    while i < ec_len {
        let root = GF_EXP[i];
        let mut k = deg + 1;
        while k > 0 {
            g[k] ^= gf_mul(g[k - 1], root);
            k -= 1;
        }
        deg += 1;
        i += 1;
    }
    g
}

/// Reed-Solomon error-correction codewords for one data block.
fn rs_encode(data: &[u8], ec_len: usize) -> Vec<u8> {
    let gen = rs_generator(ec_len);
    let mut res = data.to_vec();
    res.resize(data.len() + ec_len, 0);
    for i in 0..data.len() {
        let lead = res[i];
        if lead != 0 {
            let log_lead = GF_LOG[lead as usize] as usize;
            for k in 0..ec_len {
                res[i + 1 + k] ^= GF_EXP[(GF_LOG[gen[k + 1] as usize] as usize + log_lead) % 255];
            }
        }
    }
    res.split_off(data.len())
}

// --- ISO/IEC 18004 tables, error-correction level L ---

/// Per-version structure: total codewords, ec codewords per block,
/// short-block data codewords, short-block count, long-block data codewords,
/// long-block count. Indexed by `version - 1`.
const CAP_L: [(u16, u16, u16, u16, u16, u16); 40] = [
    (26, 7, 19, 1, 0, 0),
    (44, 10, 34, 1, 0, 0),
    (70, 15, 55, 1, 0, 0),
    (100, 20, 80, 1, 0, 0),
    (134, 26, 108, 1, 0, 0),
    (172, 18, 68, 2, 0, 0),
    (196, 20, 78, 2, 0, 0),
    (242, 24, 97, 2, 0, 0),
    (292, 30, 116, 2, 0, 0),
    (346, 18, 68, 2, 69, 2),
    (404, 20, 81, 4, 0, 0),
    (466, 24, 92, 2, 93, 2),
    (532, 26, 107, 4, 0, 0),
    (581, 30, 115, 3, 116, 1),
    (655, 22, 87, 5, 88, 1),
    (733, 24, 98, 5, 99, 1),
    (815, 28, 107, 1, 108, 5),
    (901, 30, 120, 5, 121, 1),
    (991, 28, 113, 3, 114, 4),
    (1085, 28, 107, 3, 108, 5),
    (1156, 28, 116, 4, 117, 4),
    (1258, 28, 111, 2, 112, 7),
    (1364, 30, 121, 4, 122, 5),
    (1474, 30, 117, 6, 118, 4),
    (1588, 26, 106, 8, 107, 4),
    (1706, 28, 114, 10, 115, 2),
    (1828, 30, 122, 8, 123, 4),
    (1921, 30, 117, 3, 118, 10),
    (2051, 30, 116, 7, 117, 7),
    (2185, 30, 115, 5, 116, 10),
    (2323, 30, 115, 13, 116, 3),
    (2465, 30, 115, 17, 0, 0),
    (2611, 30, 115, 17, 116, 1),
    (2761, 30, 115, 13, 116, 6),
    (2876, 30, 121, 12, 122, 7),
    (3034, 30, 121, 6, 122, 14),
    (3196, 30, 122, 17, 123, 4),
    (3362, 30, 122, 4, 123, 18),
    (3532, 30, 117, 20, 118, 4),
    (3706, 30, 118, 19, 119, 6),
];

/// Alignment-pattern centre coordinates per version, zero padded to seven
/// entries. Indexed by `version - 1`.
const ALIGN: [[u8; 7]; 40] = [
    [0, 0, 0, 0, 0, 0, 0],
    [6, 18, 0, 0, 0, 0, 0],
    [6, 22, 0, 0, 0, 0, 0],
    [6, 26, 0, 0, 0, 0, 0],
    [6, 30, 0, 0, 0, 0, 0],
    [6, 34, 0, 0, 0, 0, 0],
    [6, 22, 38, 0, 0, 0, 0],
    [6, 24, 42, 0, 0, 0, 0],
    [6, 26, 46, 0, 0, 0, 0],
    [6, 28, 50, 0, 0, 0, 0],
    [6, 30, 54, 0, 0, 0, 0],
    [6, 32, 58, 0, 0, 0, 0],
    [6, 34, 62, 0, 0, 0, 0],
    [6, 26, 46, 66, 0, 0, 0],
    [6, 26, 48, 70, 0, 0, 0],
    [6, 26, 50, 74, 0, 0, 0],
    [6, 30, 54, 78, 0, 0, 0],
    [6, 30, 56, 82, 0, 0, 0],
    [6, 30, 58, 86, 0, 0, 0],
    [6, 34, 62, 90, 0, 0, 0],
    [6, 28, 50, 72, 94, 0, 0],
    [6, 26, 50, 74, 98, 0, 0],
    [6, 30, 54, 78, 102, 0, 0],
    [6, 28, 54, 80, 106, 0, 0],
    [6, 32, 58, 84, 110, 0, 0],
    [6, 30, 58, 86, 114, 0, 0],
    [6, 34, 62, 90, 118, 0, 0],
    [6, 26, 50, 74, 98, 122, 0],
    [6, 30, 54, 78, 102, 126, 0],
    [6, 26, 52, 78, 104, 130, 0],
    [6, 30, 56, 82, 108, 134, 0],
    [6, 34, 60, 86, 112, 138, 0],
    [6, 30, 58, 86, 114, 142, 0],
    [6, 34, 62, 90, 118, 146, 0],
    [6, 30, 54, 78, 102, 126, 150],
    [6, 24, 50, 76, 102, 128, 154],
    [6, 28, 54, 80, 106, 132, 158],
    [6, 32, 58, 84, 110, 136, 162],
    [6, 26, 54, 82, 110, 138, 166],
    [6, 30, 58, 86, 114, 142, 170],
];

const fn side_len(version: u8) -> usize {
    17 + 4 * version as usize
}

fn data_codewords(version: u8) -> usize {
    let (_, _, sd, sn, ld, ln) = CAP_L[(version - 1) as usize];
    (sd * sn + ld * ln) as usize
}

/// Byte-mode payload capacity of a version: data codewords minus the 4-bit
/// mode indicator and the 8- or 16-bit character count.
fn capacity_bytes(version: u8) -> usize {
    let header_bits = if version < 10 { 12 } else { 20 };
    (data_codewords(version) * 8 - header_bits) / 8
}

fn version_for(len: usize) -> Result<u8, QrError> {
    (1..=40u8)
        .find(|&v| capacity_bytes(v) >= len)
        .ok_or(QrError::TooLong(len))
}

struct BitWriter {
    bytes: Vec<u8>,
    len: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            len: 0,
        }
    }

    fn push(&mut self, value: u32, bits: u32) {
        for i in (0..bits).rev() {
            let idx = self.len / 8;
            if idx >= self.bytes.len() {
                self.bytes.resize(idx + 1, 0);
            }
            if (value >> i) & 1 != 0 {
                self.bytes[idx] |= 0x80 >> (self.len % 8);
            }
            self.len += 1;
        }
    }

    fn into_bytes(mut self) -> Vec<u8> {
        self.bytes.truncate(self.len.div_ceil(8));
        self.bytes
    }
}

/// Terminated, padded and block-interleaved codeword stream.
fn build_codewords(data: &[u8]) -> Result<(Vec<u8>, u8), QrError> {
    let version = version_for(data.len())?;
    let dcw = data_codewords(version);
    let count_bits = if version < 10 { 8 } else { 16 };
    let mut bits = BitWriter::new();
    bits.push(0b0100, 4);
    bits.push(data.len() as u32, count_bits);
    for &b in data {
        bits.push(b as u32, 8);
    }
    let term = core::cmp::min(4, dcw * 8 - bits.len);
    bits.push(0, term as u32);
    let pad = (8 - bits.len % 8) % 8;
    bits.push(0, pad as u32);
    let mut bytes = bits.into_bytes();
    let mut alt = false;
    while bytes.len() < dcw {
        bytes.push(if alt { 0x11 } else { 0xec });
        alt = !alt;
    }

    let (_, ec, sd, sn, ld, ln) = CAP_L[(version - 1) as usize];
    let (sd, sn, ld, ln, ec) = (
        sd as usize,
        sn as usize,
        ld as usize,
        ln as usize,
        ec as usize,
    );
    let mut blocks: Vec<&[u8]> = Vec::with_capacity(sn + ln);
    let mut at = 0usize;
    for _ in 0..sn {
        blocks.push(&bytes[at..at + sd]);
        at += sd;
    }
    for _ in 0..ln {
        blocks.push(&bytes[at..at + ld]);
        at += ld;
    }
    debug_assert_eq!(at, dcw);
    let ecs: Vec<Vec<u8>> = blocks.iter().map(|b| rs_encode(b, ec)).collect();

    let mut stream = Vec::with_capacity(CAP_L[(version - 1) as usize].0 as usize);
    for i in 0..core::cmp::max(sd, ld) {
        for b in &blocks {
            if i < b.len() {
                stream.push(b[i]);
            }
        }
    }
    for i in 0..ec {
        for e in &ecs {
            stream.push(e[i]);
        }
    }
    Ok((stream, version))
}

// --- format information ---

const FORMAT_XOR_MASK: u32 = 0x5412;

/// 15-bit format word for a 5-bit `(ec level, mask)` payload. Level L is
/// `01`, so mask 0 gives `0b01_000` and the word `0x77c4`.
const fn format_word(data: u32) -> u32 {
    let mut rem = data;
    let mut i = 0;
    while i < 10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        i += 1;
    }
    ((data << 10) | (rem & 0x3ff)) ^ FORMAT_XOR_MASK
}

/// Cell of format bit `i` in the copy around the top-left finder. Bit 0 sits
/// at (0,8) and the strip runs down column 8 to (5,8), steps over the timing
/// row at (7,8), takes the corner (8,8)/(8,7) and finishes left along row 8.
/// This is the orientation `qrcode` writes and `rqrr` reads; a mirrored
/// layout still carries a BCH-valid word yet fails every independent decoder,
/// which is how the sweep that settled it was run.
const fn format_cell_main(i: usize) -> (usize, usize) {
    if i < 6 {
        (i, 8)
    } else if i == 6 {
        (7, 8)
    } else if i == 7 {
        (8, 8)
    } else if i == 8 {
        (8, 7)
    } else {
        (8, 14 - i)
    }
}

/// Cell of format bit `i` in the second copy: bits 0-6 down column 8 below
/// the top-right finder, bits 7-14 right along row 8 left of the bottom-left
/// finder.
const fn format_cell_side(i: usize, side: usize) -> (usize, usize) {
    if i < 7 {
        (side - 1 - i, 8)
    } else {
        (8, side - 15 + i)
    }
}

// --- matrix construction ---

/// A finished symbol: the module grid plus the version it was built for.
#[derive(Clone)]
pub struct EncodedMatrix {
    version: u8,
    dark: Vec<Vec<bool>>,
}

impl EncodedMatrix {
    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn side_len(&self) -> usize {
        self.dark.len()
    }

    pub fn is_dark(&self, row: usize, col: usize) -> bool {
        self.dark[row][col]
    }
}

/// Encodes a byte-mode, level-L, mask-0 symbol for `data`.
pub fn encode(data: &[u8]) -> Result<EncodedMatrix, QrError> {
    let (stream, version) = build_codewords(data)?;
    let side = side_len(version);
    let mut dark = vec![vec![false; side]; side];
    let mut reserved = vec![vec![false; side]; side];
    let set =
        |dark: &mut Vec<Vec<bool>>, reserved: &mut Vec<Vec<bool>>, r: usize, c: usize, v: bool| {
            if let (Some(row), Some(res)) = (dark.get_mut(r), reserved.get_mut(r)) {
                if let (Some(cell), Some(flag)) = (row.get_mut(c), res.get_mut(c)) {
                    *cell = v;
                    *flag = true;
                }
            }
        };

    // finder patterns with their light separators
    for (fr, fc) in [(0usize, 0usize), (0, side - 7), (side - 7, 0)] {
        for r in fr.saturating_sub(1)..=(fr + 7).min(side - 1) {
            for c in fc.saturating_sub(1)..=(fc + 7).min(side - 1) {
                let dr = r as isize - (fr + 3) as isize;
                let dc = c as isize - (fc + 3) as isize;
                let dist = dr.abs().max(dc.abs()) as usize;
                set(&mut dark, &mut reserved, r, c, dist != 2 && dist < 4);
            }
        }
    }

    // timing patterns
    for i in 8..side - 8 {
        let bit = i % 2 == 0;
        set(&mut dark, &mut reserved, 6, i, bit);
        set(&mut dark, &mut reserved, i, 6, bit);
    }

    // alignment patterns, skipping the three that collide with finders
    let last = side - 7;
    let centers: Vec<usize> = ALIGN[(version - 1) as usize]
        .iter()
        .copied()
        .filter(|&p| p != 0)
        .map(|p| p as usize)
        .collect();
    for &ar in &centers {
        for &ac in &centers {
            if (ar, ac) == (6, 6) || (ar, ac) == (6, last) || (ar, ac) == (last, 6) {
                continue;
            }
            for dr in -2isize..=2 {
                for dc in -2isize..=2 {
                    let r = (ar as isize + dr) as usize;
                    let c = (ac as isize + dc) as usize;
                    set(&mut dark, &mut reserved, r, c, dr.abs().max(dc.abs()) != 1);
                }
            }
        }
    }

    // dark module and format reservations (values written after masking)
    set(&mut dark, &mut reserved, side - 8, 8, true);
    for i in 0..15 {
        let (r, c) = format_cell_main(i);
        reserved[r][c] = true;
        let (r, c) = format_cell_side(i, side);
        reserved[r][c] = true;
    }

    // version information, versions 7 and up
    if version >= 7 {
        let mut rem = version as u32;
        for _ in 0..12 {
            rem = (rem << 1) ^ ((rem >> 11) * 0x1f25);
        }
        let word = ((version as u32) << 12) | (rem & 0xfff);
        for i in 0..18 {
            let bit = (word >> i) & 1 != 0;
            set(&mut dark, &mut reserved, side - 11 + i % 3, i / 3, bit);
            set(&mut dark, &mut reserved, i / 3, side - 11 + i % 3, bit);
        }
    }

    // data placement: two-module-wide zigzag, column 6 skipped
    let total_bits = stream.len() * 8;
    let mut bit_at = 0usize;
    let mut col = side as isize - 1;
    let mut upward = true;
    while col >= 1 {
        if col == 6 {
            col -= 1;
        }
        for i in 0..side {
            let row = if upward { side - 1 - i } else { i };
            for dx in 0..2 {
                let c = (col - dx as isize) as usize;
                if reserved[row][c] {
                    continue;
                }
                if bit_at < total_bits {
                    dark[row][c] = stream[bit_at / 8] >> (7 - bit_at % 8) & 1 != 0;
                    bit_at += 1;
                }
            }
        }
        col -= 2;
        upward = !upward;
    }
    debug_assert_eq!(bit_at, total_bits);

    // mask 0 on every data module
    for r in 0..side {
        for c in 0..side {
            if !reserved[r][c] && (r + c) % 2 == 0 {
                dark[r][c] = !dark[r][c];
            }
        }
    }

    // format information, level L mask 0, then the forced dark module
    let word = format_word(0b01_000);
    for i in 0..15 {
        let bit = (word >> i) & 1 != 0;
        let (r, c) = format_cell_main(i);
        dark[r][c] = bit;
        let (r, c) = format_cell_side(i, side);
        dark[r][c] = bit;
    }
    dark[side - 8][8] = true;

    Ok(EncodedMatrix { version, dark })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_roundtrip(data: &[u8]) {
        let m = encode(data).unwrap();
        let side = m.side_len();
        let (quiet, scale) = (4usize, 4usize);
        let img = (side + 2 * quiet) * scale;
        let mut prepared = rqrr::PreparedImage::prepare_from_bitmap(img, img, |x, y| {
            let (c, r) = (x / scale, y / scale);
            let inside = quiet..quiet + side;
            inside.contains(&r) && inside.contains(&c) && m.is_dark(r - quiet, c - quiet)
        });
        let grids = prepared.detect_grids();
        assert_eq!(grids.len(), 1, "one grid must be detectable");
        // decode_to, decode'un String'e zorlayan UTF-8 adimini atlar;
        // the frames carry a binary payload, so the raw bytes are compared.
        let mut out = Vec::new();
        grids[0].decode_to(&mut out).expect("grid must decode");
        assert_eq!(out.as_slice(), data);
    }

    #[test]
    fn gf_arithmetic_matches_field_laws() {
        assert_eq!(gf_mul(0, 123), 0);
        assert_eq!(gf_mul(1, 123), 123);
        assert_eq!(gf_mul(2, 2), 4);
        assert_eq!(gf_mul(0x53, 140), 1); // 140 = 0x8c is the inverse of 0x53
    }

    #[test]
    fn generator_polynomial_matches_known_vector() {
        let g = rs_generator(7);
        assert_eq!(&g[..8], &[1, 127, 122, 154, 164, 11, 68, 117]);
    }

    #[test]
    fn rs_encode_matches_known_vector() {
        let data = b" [\x0bx\xd1r\xdcMC@\xec\x11\xec\x11\xec\x11";
        assert_eq!(rs_encode(data, 10), b"\xc4#'w\xeb\xd7\xe7\xe2]\x17");
    }

    #[test]
    fn capacity_table_anchors() {
        assert_eq!(CAP_L[0], (26, 7, 19, 1, 0, 0));
        assert_eq!(CAP_L[9], (346, 18, 68, 2, 69, 2));
        assert_eq!(capacity_bytes(1), 17);
        assert_eq!(capacity_bytes(10), 271);
        assert_eq!(capacity_bytes(40), MAX_DATA_BYTES);
    }

    #[test]
    fn version_selection_boundaries() {
        assert_eq!(version_for(0).unwrap(), 1);
        assert_eq!(version_for(17).unwrap(), 1);
        assert_eq!(version_for(18).unwrap(), 2);
        assert_eq!(version_for(271).unwrap(), 10);
        assert_eq!(version_for(272).unwrap(), 11);
        assert_eq!(version_for(MAX_DATA_BYTES).unwrap(), 40);
        assert_eq!(version_for(MAX_DATA_BYTES + 1), Err(QrError::TooLong(2954)));
    }

    #[test]
    fn format_words_match_the_level_l_table() {
        let expected = [
            0x77c4u32, 0x72f3, 0x7daa, 0x789d, 0x662f, 0x6318, 0x6c41, 0x6976,
        ];
        for (mask, want) in expected.iter().enumerate() {
            assert_eq!(format_word(0b01_000 | mask as u32), *want, "mask {mask}");
        }
    }

    #[test]
    fn format_covers_the_standard_cells() {
        let side = side_len(3);
        let mut main: Vec<(usize, usize)> = (0..15).map(format_cell_main).collect();
        main.sort_unstable();
        let mut want: Vec<(usize, usize)> = Vec::new();
        for r in 0..6 {
            want.push((r, 8));
        }
        want.extend([(7, 8), (8, 8), (8, 7)]);
        for c in 0..6 {
            want.push((8, c));
        }
        want.sort_unstable();
        assert_eq!(main, want);

        let mut side_cells: Vec<(usize, usize)> =
            (0..15).map(|i| format_cell_side(i, side)).collect();
        side_cells.sort_unstable();
        let mut want: Vec<(usize, usize)> = Vec::new();
        for r in side - 7..side {
            want.push((r, 8));
        }
        for c in side - 8..side {
            want.push((8, c));
        }
        want.sort_unstable();
        assert_eq!(side_cells, want);
    }

    #[test]
    fn symbol_carries_the_function_patterns() {
        let m = encode(b"A").unwrap();
        assert_eq!(m.version(), 1);
        assert_eq!(m.side_len(), 21);
        for (fr, fc) in [(0, 0), (0, 14), (14, 0)] {
            for r in 0..7 {
                for c in 0..7 {
                    let dr = (r as isize - 3).abs();
                    let dc = (c as isize - 3).abs();
                    let want = dr.max(dc) != 2;
                    assert_eq!(
                        m.is_dark(fr + r, fc + c),
                        want,
                        "finder at ({},{})",
                        fr + r,
                        fc + c
                    );
                }
            }
        }
        for i in 8..13 {
            assert_eq!(m.is_dark(6, i), i % 2 == 0);
            assert_eq!(m.is_dark(i, 6), i % 2 == 0);
        }
        assert!(m.is_dark(13, 8), "dark module");
    }

    #[test]
    fn encoded_matrix_reads_back_through_an_independent_decoder() {
        for data in [
            &b"A"[..],
            &b"Budlum 3.0 recipe frame"[..],
            &vec![0xa5; 17][..],
            &vec![0x5a; 18][..],
            &vec![7; 32][..],
            &vec![9; 271][..],
            &vec![11; 272][..],
            &vec![13; 1000][..],
            &vec![17; MAX_DATA_BYTES][..],
        ] {
            decode_roundtrip(data);
        }
    }

    #[test]
    fn every_version_boundary_roundtrips() {
        let mut size = 1usize;
        let mut checked = 0;
        while size <= MAX_DATA_BYTES {
            decode_roundtrip(&vec![size as u8; size]);
            checked += 1;
            size = (size + size / 8 + 1).min(MAX_DATA_BYTES + 1);
        }
        assert!(
            checked >= 30,
            "sweep must cover the versions, got {checked}"
        );
    }
}
