//! B.U.D. 2.0 Invention - A Real Lossless Huffman Codec (2026-08-16)
//!
//! A REAL lossless compressor with zero external dependencies: canonical
//! Huffman. (The previous "RealCompressor" was a STUB that imitated the
//! zstd/xz magic and returned the first 100 bytes - it was not real
//! compression and produced a fake envelope; this module replaces it.)
//!
//! Design:
//! - Magic: a high-bit `\xB5` prefix (so file(1)/ASCII do not mix it up, S.47)
//!   plus "HFM1".
//! - Compact table: the used symbol count (u16) plus (sym, len) pairs
//!   (2 bytes per symbol).
//! - Canonical code assignment: (length, symbol) order - DEFLATE-like,
//!   deterministic.
//! - Body: MSB-first bit-packed codes.
//! - Bounds safe: an original_len ceiling (bomb), the Kraft inequality, an
//!   invalid prefix -> None.
//! - Losslessness: compress -> decompress = the original (property test).
//!   No panics.
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, no unsafe.

#![forbid(unsafe_code)]

pub const BUD_HFM_MAGIC: [u8; 8] = *b"\xB5HFM1\0\0\0";
pub const BUD_HFM_VERSION: u8 = 1;
pub const MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB bomb ceiling
pub const MAX_CODE_LEN: usize = 32; // code length bound against table corruption

#[derive(Debug, Clone)]
pub struct HuffmanCoder;

impl HuffmanCoder {
    /// Compress: a BUD-HFM1 envelope (magic + version + length + compact table + body).
    pub fn compress(data: &[u8]) -> Vec<u8> {
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let lens = Self::lengths_by_freq(&freq);
        let mut out = Vec::new();
        out.extend_from_slice(&BUD_HFM_MAGIC);
        out.push(BUD_HFM_VERSION);
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        // compact table: the used symbol count plus (sym, len) pairs
        let used: Vec<(u8, u8)> = lens
            .iter()
            .enumerate()
            .filter(|(_, &l)| l > 0)
            .map(|(s, &l)| (s as u8, l))
            .collect();
        out.extend_from_slice(&(used.len() as u16).to_le_bytes());
        for (s, l) in &used {
            out.push(*s);
            out.push(*l);
        }
        // build the canonical code table up front, in (length, symbol) order
        let mut codes = [0u64; 256];
        let mut order: Vec<usize> = (0..256).filter(|&s| lens[s] > 0).collect();
        order.sort_by_key(|&s| (lens[s], s));
        let mut code: u64 = 0;
        let mut prev_len = 0usize;
        for &s in &order {
            let l = lens[s] as usize;
            if prev_len > 0 {
                code = (code + 1) << (l - prev_len);
            }
            codes[s] = code;
            prev_len = l;
        }
        // body: bit-pack the codes (MSB-first)
        let mut bit_buf: u64 = 0;
        let mut bit_cnt: u32 = 0;
        for &b in data {
            let sym = b as usize;
            let len = lens[sym];
            debug_assert!(len > 0);
            bit_buf = (bit_buf << len) | codes[sym];
            bit_cnt += len as u32;
            while bit_cnt >= 8 {
                let byte = ((bit_buf >> (bit_cnt - 8)) & 0xFF) as u8;
                out.push(byte);
                bit_cnt -= 8;
            }
        }
        if bit_cnt > 0 {
            let byte = ((bit_buf << (8 - bit_cnt)) & 0xFF) as u8;
            out.push(byte);
        }
        out
    }

    /// Decompress: verify strictly (magic, version, length ceiling, Kraft, code validity) -> the original.
    pub fn decompress(bytes: &[u8]) -> Option<Vec<u8>> {
        const FIXED: usize = 8 + 1 + 8 + 2; // magic + version + len + table count
        if bytes.len() < FIXED {
            return None;
        }
        if bytes[0..8] != BUD_HFM_MAGIC {
            return None;
        }
        if bytes[8] != BUD_HFM_VERSION {
            return None;
        }
        let orig_len = u64::from_le_bytes(bytes[9..17].try_into().ok()?);
        if orig_len > MAX_DECOMPRESSED_BYTES {
            return None; // bomba
        }
        let sym_count = u16::from_le_bytes([bytes[17], bytes[18]]) as usize;
        if bytes.len() < FIXED + sym_count * 2 {
            return None;
        }
        let mut lens = [0u8; 256];
        for i in 0..sym_count {
            let sym = bytes[FIXED + i * 2] as usize;
            let l = bytes[FIXED + i * 2 + 1];
            if lens[sym] != 0 {
                return None; // duplicate symbol -> corrupt table
            }
            lens[sym] = l;
        }
        let body = &bytes[FIXED + sym_count * 2..];
        if orig_len == 0 {
            // empty input: there must be no symbols and the body must be empty
            if sym_count != 0 || !body.is_empty() {
                return None;
            }
            return Some(Vec::new());
        }
        let lens_usize: Vec<usize> = lens.iter().map(|&l| l as usize).collect();
        if sym_count == 0 {
            return None; // there is an original but no symbols - inconsistent
        }
        // Kraft inequality: a corrupt table -> refuse
        if !Self::kraft_ok(&lens_usize) {
            return None;
        }
        let max_len = *lens_usize.iter().max().unwrap_or(&0);
        if max_len == 0 || max_len > MAX_CODE_LEN {
            return None;
        }
        // canonical construction: count[len], first_code[len], symbols
        let mut count = [0usize; MAX_CODE_LEN + 1];
        let mut syms_by_len: Vec<Vec<usize>> = vec![Vec::new(); MAX_CODE_LEN + 1];
        for (sym, &l) in lens_usize.iter().enumerate() {
            if l > 0 && l <= MAX_CODE_LEN {
                count[l] += 1;
                syms_by_len[l].push(sym);
            }
        }
        let mut first = [0u64; MAX_CODE_LEN + 1];
        let mut c: u64 = 0;
        for l in 1..=MAX_CODE_LEN {
            first[l] = c;
            c = (c + count[l] as u64) << 1;
        }
        // walk the body bits - K38: orig_len comes from an UNTRUSTED header;
        // with_capacity(orig_len) would make a huge allocation for a small file
        // (OOM DoS). Lazy growth: a genuinely large decompression is already
        // bounded by the body size.
        let mut out: Vec<u8> = Vec::new();
        let mut bit_pos = 0usize;
        let total_bits = body.len() * 8;
        let mut code: u64 = 0;
        let mut cur_len = 0usize;
        while (out.len() as u64) < orig_len {
            if bit_pos >= total_bits {
                return None; // the body ended early
            }
            let byte = body[bit_pos / 8];
            let bit = (byte >> (7 - (bit_pos % 8))) & 1;
            bit_pos += 1;
            code = (code << 1) | bit as u64;
            cur_len += 1;
            if cur_len > max_len {
                return None; // invalid prefix (corrupt body)
            }
            let cnt = count[cur_len];
            if cnt > 0 && code >= first[cur_len] && code < first[cur_len] + cnt as u64 {
                let sym = syms_by_len[cur_len][(code - first[cur_len]) as usize];
                out.push(sym as u8);
                code = 0;
                cur_len = 0;
            }
        }
        // The padding bits in the last byte are free (DEFLATE-like). Losslessness is exact.
        Some(out)
    }

    /// Code lengths: at every step the two smallest nodes (by freq, then by
    /// index) are merged; a DFS from the root gives leaf depths = code lengths.
    /// Deterministic.
    fn lengths_by_freq(freq: &[u64; 256]) -> [u8; 256] {
        let mut fs: Vec<(u64, Option<usize>, Option<usize>, Option<usize>)> = Vec::new();
        let mut used: Vec<bool> = Vec::new();
        for (sym, &f) in freq.iter().enumerate() {
            if f > 0 {
                fs.push((f, None, None, Some(sym)));
                used.push(false);
            }
        }
        if fs.is_empty() {
            return [0u8; 256];
        }
        if fs.len() == 1 {
            let mut lens = [0u8; 256];
            // A tree with a single leaf: the leaf always carries a symbol, but
            // we say so with pattern matching rather than with `unwrap`.
            if let Some(sym) = fs[0].3 {
                lens[sym] = 1;
            }
            return lens;
        }
        let mut internal = fs.len();
        while internal > 1 {
            let mut best1: Option<usize> = None;
            let mut best2: Option<usize> = None;
            // The same comparison, with pattern matching instead of `unwrap`.
            // The ordering criterion did not change: frequency first, then the
            // smaller index on a tie - the Huffman tree stays deterministic
            // because of it.
            let better = |cand: usize, cur: Option<usize>| -> bool {
                match cur {
                    None => true,
                    Some(c) => fs[cand].0 < fs[c].0 || (fs[cand].0 == fs[c].0 && cand < c),
                }
            };
            for i in 0..fs.len() {
                if used[i] {
                    continue;
                }
                if better(i, best1) {
                    best2 = best1;
                    best1 = Some(i);
                } else if better(i, best2) {
                    best2 = Some(i);
                }
            }
            // The loop condition (`internal > 1`) leaves at least two unused
            // nodes; even so, on a shortfall we return the tree as it is
            // birakip cikiyoruz.
            let (Some(i1), Some(i2)) = (best1, best2) else {
                break;
            };
            let f = fs[i1].0 + fs[i2].0;
            fs.push((f, Some(i1), Some(i2), None));
            used.push(false);
            used[i1] = true;
            used[i2] = true;
            internal -= 1;
        }
        let mut lens = [0u8; 256];
        if let Some(root_idx) = (0..fs.len()).find(|&i| !used[i]) {
            Self::dfs_lengths(&fs, root_idx, 0, &mut lens);
        }
        lens
    }

    fn dfs_lengths(
        fs: &[(u64, Option<usize>, Option<usize>, Option<usize>)],
        idx: usize,
        depth: usize,
        lens: &mut [u8; 256],
    ) {
        let (_, l, r, sym) = fs[idx];
        if let Some(s) = sym {
            lens[s] = depth.max(1) as u8;
            return;
        }
        if let Some(li) = l {
            Self::dfs_lengths(fs, li, depth + 1, lens);
        }
        if let Some(ri) = r {
            Self::dfs_lengths(fs, ri, depth + 1, lens);
        }
    }

    fn kraft_ok(lens: &[usize]) -> bool {
        // Kraft: sum 2^(-len) <= 1 - with integer arithmetic
        let mut maxl = 0usize;
        for &l in lens {
            maxl = maxl.max(l);
        }
        if maxl > MAX_CODE_LEN {
            return false;
        }
        let mut acc: u128 = 0;
        for &l in lens {
            if l > 0 {
                acc += 1u128 << (MAX_CODE_LEN - l);
            }
        }
        acc <= (1u128 << MAX_CODE_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        // On small inputs the header cost does not amortise (honest Huffman
        // behaviour); real compression is shown with a repetitive input of
        // SUFFICIENT length.
        let line = b"2026-08-16 INFO req=123 /api/a s=200 b=42 reg=tr\n";
        let mut data = Vec::new();
        for _ in 0..40 {
            data.extend_from_slice(line);
        }
        let c = HuffmanCoder::compress(&data);
        assert!(
            c.len() < data.len(),
            "repetitive data must compress: {} -> {}",
            data.len(),
            c.len()
        );
        let d = HuffmanCoder::decompress(&c).unwrap();
        assert_eq!(d, data);
    }

    #[test]
    fn roundtrip_uniform() {
        let data = vec![b'a'; 20_000];
        let c = HuffmanCoder::compress(&data);
        // one symbol -> ~1 bit/symbol; with the table/header constant around ~7x
        assert!(
            c.len() * 7 < data.len(),
            "one symbol must be about 7x: {} -> {}",
            data.len(),
            c.len()
        );
        assert_eq!(HuffmanCoder::decompress(&c).unwrap(), data);
    }

    #[test]
    fn roundtrip_empty() {
        let c = HuffmanCoder::compress(b"");
        assert_eq!(HuffmanCoder::decompress(&c).unwrap(), b"");
    }

    #[test]
    fn roundtrip_all_bytes_random() {
        // deterministic PRNG - 300 different inputs, every size
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() & 0xff) as u8
            }
        }
        let mut rng = Rng(0x48_55_46_46_20_31_00_00);
        for round in 0..300u32 {
            let n = (rng.next() % 5000) as usize;
            let mut data = vec![0u8; n];
            for b in &mut data {
                *b = if round % 3 == 0 {
                    rng.byte() % 8
                } else {
                    rng.byte()
                };
            }
            let c = HuffmanCoder::compress(&data);
            let d =
                HuffmanCoder::decompress(&c).unwrap_or_else(|| panic!("round {round} decompress"));
            assert_eq!(d, data, "round {round} lossless");
        }
    }

    #[test]
    fn reject_tampered_and_bombs() {
        let data = b"merhaba dunya bu bir test verisi";
        let c = HuffmanCoder::compress(data);
        // payload kurcalama (panik yok)
        let mut t = c.clone();
        let last = t.len() - 1;
        t[last] ^= 0xFF;
        let _ = HuffmanCoder::decompress(&t);
        // magic boz
        let mut t2 = c.clone();
        t2[0] = 0x00;
        assert!(HuffmanCoder::decompress(&t2).is_none());
        // short input
        assert!(HuffmanCoder::decompress(&[]).is_none());
        assert!(HuffmanCoder::decompress(&c[..20]).is_none());
        // size bomb: original_len = 1 GiB (under MAX but with no body -> fast refusal)
        let mut b = BUD_HFM_MAGIC.to_vec();
        b.push(BUD_HFM_VERSION);
        b.extend_from_slice(&(1u64 << 30).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        assert!(HuffmanCoder::decompress(&b).is_none(), "size bomb refused");
        // alloc bomb: 3.9 GiB orig_len + one-symbol table + small body -> fast refusal WITHOUT OOM
        let mut bomb = BUD_HFM_MAGIC.to_vec();
        bomb.push(BUD_HFM_VERSION);
        bomb.extend_from_slice(&((4u64 << 30) - 1).to_le_bytes()); // under MAX
        bomb.extend_from_slice(&1u16.to_le_bytes());
        bomb.extend_from_slice(&[65, 1]); // one symbol 'A', length 1
        bomb.extend_from_slice(&[0u8; 64]); // small body
        let start = std::time::Instant::now();
        for _ in 0..100 {
            assert!(HuffmanCoder::decompress(&bomb).is_none());
        }
        assert!(
            start.elapsed().as_secs() < 5,
            "alloc-bomb yok: {:?}",
            start.elapsed()
        );
        // invalid table (Kraft broken): 256 symbols, all of length 32
        let mut b2 = BUD_HFM_MAGIC.to_vec();
        b2.push(BUD_HFM_VERSION);
        b2.extend_from_slice(&64u64.to_le_bytes());
        b2.extend_from_slice(&256u16.to_le_bytes());
        for s in 0u16..256 {
            b2.push(s as u8);
            b2.push(32);
        }
        assert!(
            HuffmanCoder::decompress(&b2).is_none(),
            "a Kraft-broken table is refused"
        );
        // duplicate symbol -> corrupt table is refused
        let mut b3 = BUD_HFM_MAGIC.to_vec();
        b3.push(BUD_HFM_VERSION);
        b3.extend_from_slice(&8u64.to_le_bytes());
        b3.extend_from_slice(&2u16.to_le_bytes());
        b3.extend_from_slice(&[65, 3, 65, 3]); // the same symbol twice
        assert!(
            HuffmanCoder::decompress(&b3).is_none(),
            "yinelenen sembol red"
        );
        // garbage body (no panic)
        let mut b4 = BUD_HFM_MAGIC.to_vec();
        b4.push(BUD_HFM_VERSION);
        b4.extend_from_slice(&16u64.to_le_bytes());
        b4.extend_from_slice(&1u16.to_le_bytes());
        b4.extend_from_slice(&[65, 8]); // one symbol, length 8
        b4.extend_from_slice(&[0b1010_1010]);
        let _ = HuffmanCoder::decompress(&b4);
    }
}
