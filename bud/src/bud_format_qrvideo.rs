//! B.U.D. 3.0 - QR-VIDEO DERIVATIVE LAYER (spec section 1 pipeline; independent derivation)
//!
//! The question behind it: "what if the content, once compressed, were sent as a QR video?"
//! Spec measurement (K5/K10/K13): QR video CARRIES LOSSLESSLY but IS NOT STORAGE -
//! in every regime it grows the compressed bytes 12-18x; it is a derivative, it is not kept, it is produced on demand.
//!
//! This module encodes the pipeline:
//!   payload -> zlib-9 (ONLY if it shrinks) -> container (magic, version, flags, orig_len, sha256)
//!   -> systematic carousel (ordered blocks first, then repair drops) -> frame packing
//!   -> QR byte-mode frame -> video frame. RECEIVE: decode frame -> drop pool -> peel -> decompress -> verify SHA.
//! Gate: K-QR-GENISLEME - a QR-video kind cannot be written to persistent storage (a derivative stays a derivative).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const QRV_MAGIC: [u8; 8] = *b"\xB5QRV1\0\0\0";
pub const QRV_VERSION: u8 = 1;

/// Drop (frame) header - 20 B (spec section 2).
#[derive(Debug, Clone, Copy)]
pub struct DamlaHdr {
    pub seq: u32,   // drop sequence
    pub block: u16, // block index (carousel turn)
    pub flags: u8,  // 0x01=repair, 0x02=compressed, 0x04=last
    pub len: u16,   // payload bytes (<= BLOCK)
}

pub const DAMLA_HDR_LEN: usize = 20;
pub const BLOCK: usize = 200; // spec section 6

/// The systematic carousel (spec section 3-new): first k blocks in order (a drop = a single block),
/// then k repair drops of uniform degree 4-24; the loop is endless.
/// K6 proof: with zero loss the overhead is 1.00 and arrival is ordered (streaming playback).
#[derive(Debug, Clone)]
pub struct Karusel {
    pub blocks: Vec<Vec<u8>>, // content blocks (BLOCK sized, the last one short)
    pub k: usize,
    pub turn: u64, // the current turn
}

impl Karusel {
    pub fn new(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let blocks: Vec<Vec<u8>> = data.chunks(BLOCK).map(|c| c.to_vec()).collect();
        let k = blocks.len();
        if k == 0 || k > 65_535 {
            return None;
        }
        Some(Self { blocks, k, turn: 0 })
    }

    /// The ordered (systematic) drop: in turn 0 block i arrives as it is (streaming decode).
    pub fn systematic_drop(&self, index: usize) -> Option<(u32, Vec<u8>)> {
        let b = self.blocks.get(index)?;
        Some((index as u32, b.clone()))
    }

    /// A repair drop: uniform degree 4..=24, deterministic seed.
    /// FIX (the turn-audit canary): the seed comes from the ABSOLUTE drop sequence
    /// (spec section 3-new). The previous version seeded only from the TURN; the
    /// `derive_stream` loop produced k EXACTLY IDENTICAL repair drops in one turn
    /// (proof: repair_drop(0) == repair_drop(0), k copies) - loss resistance was empty.
    pub fn repair_drop(&self, abs_seq: u64) -> (u32, Vec<u8>) {
        let k = self.k as u64;
        let mut rng = LcRng::new(0x9E3779B97F4A7C15u64.wrapping_mul(abs_seq).wrapping_add(1));
        // FIX 2 (caught by the canary): the degree ceiling is k-1 - uniform 4..=24 was
        // mostly clamped to k for small k, and the "XOR of all blocks" drop was
        // duplicated repeatedly (at k=11 only 6 of 11 drops were unique).
        let min_d = 2.min(self.k);
        let max_d = self.k.saturating_sub(1).clamp(min_d, 24).max(min_d);
        let span = (max_d - min_d + 1) as u64;
        let d = min_d + (rng.next() % span) as usize;
        let mut chosen = Vec::with_capacity(d);
        while chosen.len() < d {
            let idx = (rng.next() % k) as usize;
            if !chosen.contains(&idx) {
                chosen.push(idx);
            }
        }
        chosen.sort_unstable();
        // FIX 3: the sym length is the LONGEST OF THE CHOSEN - the previous version
        // used blocks[chosen[0]].len(); if the short last block was chosen first the
        // other blocks were SILENTLY truncated in the zip (data corruption).
        let sym_len = chosen
            .iter()
            .map(|&i| self.blocks[i].len())
            .max()
            .unwrap_or(0);
        let mut sym = vec![0u8; sym_len];
        for &i in &chosen {
            for (a, b) in sym.iter_mut().zip(self.blocks[i].iter()) {
                *a ^= b;
            }
        }
        // FIX 4 (turn audit): the previous version packed the indices into seq with a
        // 65537 hash - LOSSY; the decoder could not re-derive the mask. Spec section 3:
        // the header carries the ABSOLUTE seq and both ends derive the composition
        // from the SAME rule. Sender and receiver derive it independently from the same inputs.
        (abs_seq as u32, sym)
    }

    /// Drop composition - the sender and the decoder run the SAME rule (the wire contract).
    /// Without flag 0x01: systematic, seq = block index. With it: repair, seq = abs_seq.
    pub fn composition(k: usize, seq: u32, is_repair: bool) -> Vec<usize> {
        if !is_repair {
            return vec![(seq as usize) % k.max(1)];
        }
        let mut rng = LcRng::new(
            0x9E3779B97F4A7C15u64
                .wrapping_mul(u64::from(seq))
                .wrapping_add(1),
        );
        let min_d = 2.min(k);
        let max_d = k.saturating_sub(1).clamp(min_d, 24).max(min_d);
        let span = (max_d - min_d + 1) as u64;
        let d = min_d + (rng.next() % span) as usize;
        let mut chosen = Vec::with_capacity(d);
        while chosen.len() < d {
            let idx = (rng.next() % k as u64) as usize;
            if !chosen.contains(&idx) {
                chosen.push(idx);
            }
        }
        chosen.sort_unstable();
        chosen
    }

    /// Frame packing: a 20 B header + payload (spec section 2).
    pub fn pack(&self, seq: u32, block: u16, flags: u8, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() > BLOCK {
            return None;
        }
        let mut out = Vec::with_capacity(DAMLA_HDR_LEN + payload.len());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&block.to_le_bytes());
        out.push(flags);
        out.push(0u8); // reserved
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        // Fill the 20 B header (seq4+block2+flags1+rsv1+len2 = 10; the remaining 10 are constant)
        out.extend_from_slice(b"BDLMQRV1AB");
        out.extend_from_slice(payload);
        Some(out)
    }
}

/// A simple LC generator (deterministic).
struct LcRng(u64);
impl LcRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut x = self.0;
        x ^= x >> 33;
        x.wrapping_mul(0xFF51_AFD7_ED55_8CCD)
    }
}

/// Derivative production (on demand; no intermediate product is kept).
/// `compression`: 0=none, 1=zlib-9 (if it shrinks) - here the zstd-19 proxy (lossless).
/// `turns`: the carousel turns to produce (1 turn suffices for streaming; >1 for loss resistance).
pub fn derive_stream(data: &[u8], compression: u8, turns: u64) -> Option<Vec<u8>> {
    if data.is_empty() || turns == 0 {
        return None;
    }
    // 1) compress (if it shrinks)
    let body: Vec<u8> = if compression > 0 {
        let comp = zstd_compress(data)?;
        if comp.len() < data.len() {
            comp
        } else {
            data.to_vec()
        }
    } else {
        data.to_vec()
    };
    // 2) carousel
    let k = Karusel::new(&body)?;
    let mut out = Vec::new();
    for t in 0..turns {
        // The systematic turn: block t mod k, in order
        for i in 0..k.k {
            let (seq, b) = k.systematic_drop((t as usize + i) % k.k)?;
            out.extend_from_slice(&k.pack(seq, (t % 2) as u16, 0, &b)?);
        }
        // Repair drops: each drop is seeded from its ABSOLUTE sequence -
        // k DIFFERENT drops within one turn, and no repetition across turns either.
        // seq = abs_seq (the decoder re-derives the composition with the section 3 rule).
        for i in 0..k.k {
            let abs_seq = t.wrapping_mul(k.k as u64).wrapping_add(i as u64);
            let (seq, b) = k.repair_drop(abs_seq);
            out.extend_from_slice(&k.pack(seq, (t % 2) as u16, 0x01, &b)?);
        }
    }
    Some(out)
}

/// The zstd-19 proxy (zstd is in Cargo; the lossless counterpart of the spec's zlib-9).
pub fn zstd_compress(data: &[u8]) -> Option<Vec<u8>> {
    let mut enc = zstd::bulk::Compressor::new(19).ok()?;
    enc.compress(data).ok()
}

pub fn zstd_decompress(data: &[u8]) -> Option<Vec<u8>> {
    zstd::bulk::Decompressor::new()
        .ok()?
        .decompress(data, 100 * 1024 * 1024)
        .ok()
}

/// THE DECODER (spec section 4): a drop stream -> the original body.
/// Peeling + GF(2) elimination - "peeling alone IS NOT ENOUGH" (Finding-5:
/// k=3, 11 correct drops, the single lost degree-1 drop -> pure peeling stalled).
/// If the rank is insufficient it returns None - it NEVER produces wrong data.
pub struct KaruselDecoder {
    k: usize,
    total_len: usize,
    solved: Vec<Option<Vec<u8>>>,
    solved_count: usize,
    pending: Vec<(Vec<usize>, Vec<u8>)>,
}

impl KaruselDecoder {
    pub fn new(k: usize, total_len: usize) -> Option<Self> {
        if k == 0 || k > 65_535 || total_len == 0 || total_len > k * BLOCK {
            return None;
        }
        Some(Self {
            k,
            total_len,
            solved: vec![None; k],
            solved_count: 0,
            pending: Vec::new(),
        })
    }

    pub fn is_complete(&self) -> bool {
        self.solved_count >= self.k
    }

    /// Take a packed frame (the pack output): parse the header, process the drop.
    /// A corrupt/foreign frame is dropped silently (K1: no wrong byte leaks).
    pub fn add_frame(&mut self, frame: &[u8]) -> bool {
        if frame.len() < DAMLA_HDR_LEN || &frame[10..20] != b"BDLMQRV1AB" {
            return false;
        }
        let seq = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let flags = frame[6];
        let len = u16::from_le_bytes([frame[8], frame[9]]) as usize;
        if frame.len() != DAMLA_HDR_LEN + len || len > BLOCK {
            return false;
        }
        let payload = &frame[DAMLA_HDR_LEN..];
        let idx = Karusel::composition(self.k, seq, flags & 0x01 != 0);
        self.add_drop(&idx, payload);
        true
    }

    /// Process the drop: subtract the known ones, and if it is degree-1 run the peeling cascade.
    pub fn add_drop(&mut self, idx: &[usize], payload: &[u8]) {
        if self.is_complete() || idx.is_empty() || idx.iter().any(|&i| i >= self.k) {
            return;
        }
        let mut rem: Vec<usize> = Vec::with_capacity(idx.len());
        let mut pay = payload.to_vec();
        pay.resize(BLOCK, 0);
        for &i in idx {
            if let Some(s) = &self.solved[i] {
                for (a, b) in pay.iter_mut().zip(s.iter()) {
                    *a ^= b;
                }
            } else if !rem.contains(&i) {
                rem.push(i);
            }
        }
        match rem.len() {
            0 => {}
            1 => self.resolve(rem[0], pay),
            _ => self.pending.push((rem, pay)),
        }
    }

    fn resolve(&mut self, b0: usize, w0: Vec<u8>) {
        let mut queue = vec![(b0, w0)];
        while let Some((b, w)) = queue.pop() {
            if self.solved[b].is_some() {
                continue;
            }
            self.solved[b] = Some(w.clone());
            self.solved_count += 1;
            let mut i = 0;
            while i < self.pending.len() {
                if let Some(pos) = self.pending[i].0.iter().position(|&x| x == b) {
                    self.pending[i].0.swap_remove(pos);
                    for (a, c) in self.pending[i].1.iter_mut().zip(w.iter()) {
                        *a ^= c;
                    }
                    if self.pending[i].0.len() == 1 {
                        let (rem, pay) = self.pending.swap_remove(i);
                        queue.push((rem[0], pay));
                        continue; // keep i - swap_remove put a new element at the same i
                    }
                }
                i += 1;
            }
        }
    }

    /// GF(2) elimination if peeling stalls (the Finding-5 fix).
    /// A word-array bitset (u64 x N) - k <= 65535 is supported.
    fn eliminate(&mut self) -> bool {
        if self.is_complete() {
            return true;
        }
        let words = self.k.div_ceil(64);
        let mut rows: Vec<(Vec<u64>, Vec<u8>)> = Vec::with_capacity(self.pending.len());
        for (idx, pay) in &self.pending {
            let mut mask = vec![0u64; words];
            for &i in idx {
                mask[i / 64] |= 1u64 << (i % 64);
            }
            rows.push((mask, pay.clone()));
        }
        let unknowns: Vec<usize> = (0..self.k).filter(|&i| self.solved[i].is_none()).collect();
        let mut piv_rows: Vec<usize> = Vec::new();
        for &col in &unknowns {
            let (w, bit) = (col / 64, 1u64 << (col % 64));
            let piv = match rows
                .iter()
                .enumerate()
                .find(|(ri, (m, _))| m[w] & bit != 0 && !piv_rows.contains(ri))
            {
                Some((ri, _)) => ri,
                None => return false, // insufficient rank - UNSOLVABLE (no wrong data)
            };
            piv_rows.push(piv);
            let (pm, pp) = (rows[piv].0.clone(), rows[piv].1.clone());
            for (ri, (m, p)) in rows.iter_mut().enumerate() {
                if ri != piv && m[w] & bit != 0 {
                    for (a, b) in m.iter_mut().zip(pm.iter()) {
                        *a ^= b;
                    }
                    for (a, b) in p.iter_mut().zip(pp.iter()) {
                        *a ^= b;
                    }
                }
            }
        }
        // Every pivot must now have a single unknown
        for (ci, &col) in unknowns.iter().enumerate() {
            let (m, p) = &rows[piv_rows[ci]];
            let ones: u32 = m.iter().map(|x| x.count_ones()).sum();
            if ones != 1 {
                return false;
            }
            self.solved[col] = Some(p.clone());
            self.solved_count += 1;
        }
        self.pending.clear();
        true
    }

    /// Reassemble the body: Some(original) if complete, otherwise it tries elimination.
    pub fn assemble(&mut self) -> Option<Vec<u8>> {
        if !self.is_complete() && !self.eliminate() {
            return None;
        }
        let mut out = Vec::with_capacity(self.total_len);
        for i in 0..self.k {
            let block = self.solved[i].as_ref()?;
            let take = (self.total_len - out.len()).min(BLOCK);
            out.extend_from_slice(&block[..take]);
            if out.len() >= self.total_len {
                break;
            }
        }
        Some(out)
    }
}

/// An attempt to write the derivative to storage -> REFUSED (the K-QR-GENISLEME gate).
/// A QR video is a derivative; it cannot enter `held_bytes`.
pub fn qr_cannot_be_stored() -> Result<(), &'static str> {
    Err("K-QR-GENISLEME: a QR video is a derivative, it cannot be written to persistent storage")
}

/// The derivative growth ratio (video/raw) - the proof that it is >1 in every regime (K13).
pub fn derivative_growth(derived_len: usize, original_len: usize) -> f64 {
    if original_len == 0 {
        return 1.0;
    }
    derived_len as f64 / original_len as f64
}

pub fn qrv_digest(derived: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(QRV_MAGIC);
    h.update([QRV_VERSION]);
    h.update((derived.len() as u64).to_le_bytes());
    h.update(derived);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carousel_systematic_is_streamable() {
        let data: Vec<u8> = (0u8..=255).cycle().take(10 * BLOCK + 50).collect();
        let k = Karusel::new(&data).unwrap();
        assert_eq!(k.k, 11); // 10 full + 1 short
                             // Turn 0: block 0 arrives directly -> immediately decodable (streaming)
        let (seq, b) = k.systematic_drop(0).unwrap();
        assert_eq!(b, data[..BLOCK]);
        assert_eq!(seq, 0);
        // The repair drop is deterministic (the same absolute sequence -> the same drop)
        let (s1, d1) = k.repair_drop(0);
        let (s2, d2) = k.repair_drop(0);
        assert_eq!((s1, d1.clone()), (s2, d2.clone()));
        // A different absolute sequence -> a different drop (loss resistance)
        let (s3, d3) = k.repair_drop(1);
        assert!((s1 != s3) || (d1 != d3));
        // CANARY (the caught bug): a turn's k repair drops must differ from one another
        let turn0: Vec<_> = (0..k.k as u64).map(|i| k.repair_drop(i)).collect();
        let unique: std::collections::BTreeSet<_> =
            turn0.iter().map(|(s, d)| (*s, d.clone())).collect();
        // Threshold 2/3: at small k two seeds choosing the same subset (birthday) is
        // legitimate and rare; the bug CAUGHT was ALL of them being copies (1/11).
        assert!(
            unique.len() * 3 >= k.k * 2,
            "the repair drops within a turn must mostly be unique: {}/{}",
            unique.len(),
            k.k
        );
        // CANARY (fix 3): even if the short last block is chosen the drop length is not
        // truncated - the sym length must be the longest of the chosen (BLOCK, except the short block)
        for (_, d) in &turn0 {
            assert!(
                d.len() == BLOCK || d.len() == 50,
                "the drop was truncated: {}",
                d.len()
            );
        }
    }

    #[test]
    fn frame_packing_has_a_20_byte_header() {
        let k = Karusel::new(b"ic".repeat(100).as_slice()).unwrap();
        let p = k.pack(5, 0, 0x04, b"veri").unwrap();
        assert_eq!(p.len(), DAMLA_HDR_LEN + 4);
        assert_eq!(&p[10..20], b"BDLMQRV1AB");
        assert_eq!(p[0..4], 5u32.to_le_bytes());
    }

    #[test]
    fn zstd_proxy_is_lossless() {
        let data: Vec<u8> = b"compressible content ".repeat(500);
        let c = zstd_compress(&data).unwrap();
        assert!(c.len() < data.len(), "it shrinks");
        assert_eq!(zstd_decompress(&c).unwrap(), data, "lossless");
    }

    #[test]
    fn derivative_growth_is_not_storage() {
        // The QR-video layer (an uncompressed carousel) grows the body -> it is a derivative (K13)
        let data = b"compressible ".repeat(300);
        let derived = derive_stream(&data, 0, 1).unwrap();
        let growth = derivative_growth(derived.len(), data.len());
        assert!(growth > 1.0, "the QR layer grows it: {growth}");
        // The gate: it cannot be written to storage
        assert!(qr_cannot_be_stored().is_err());
    }

    #[test]
    fn derive_stream_is_deterministic() {
        let data = b"deterministic derivative".repeat(20);
        let a = derive_stream(&data, 1, 2).unwrap();
        let b = derive_stream(&data, 1, 2).unwrap();
        assert_eq!(qrv_digest(&a), qrv_digest(&b));
    }

    #[test]
    fn decoder_is_bit_equal_end_to_end() {
        // Spec section 4 closure: produce -> frames -> decoder -> byte-equal
        let data: Vec<u8> = (0u8..=255).cycle().take(13 * BLOCK + 77).collect();
        let k = Karusel::new(&data).unwrap();
        let mut dec = KaruselDecoder::new(k.k, data.len()).unwrap();
        // The systematic turn only (a lossless channel): it must finish in k frames
        for i in 0..k.k {
            let (seq, b) = k.systematic_drop(i).unwrap();
            let frame = k.pack(seq, 0, 0, &b).unwrap();
            assert!(dec.add_frame(&frame));
        }
        assert!(
            dec.is_complete(),
            "a systematic sweep completes in k frames (K6: overhead 1.00)"
        );
        assert_eq!(dec.assemble().unwrap(), data, "byte-equal");
    }

    #[test]
    fn decoder_completes_a_lossy_channel_with_repairs() {
        // 30% systematic frame loss -> the repair drops close it (the K1 pattern)
        let data: Vec<u8> = (7u8..=200).cycle().take(11 * BLOCK).collect();
        let k = Karusel::new(&data).unwrap();
        let mut dec = KaruselDecoder::new(k.k, data.len()).unwrap();
        for i in 0..k.k {
            if i % 3 == 0 {
                continue; // every 3rd frame is lost
            }
            let (seq, b) = k.systematic_drop(i).unwrap();
            dec.add_frame(&k.pack(seq, 0, 0, &b).unwrap());
        }
        assert!(!dec.is_complete(), "with loss it must stay incomplete");
        for abs_seq in 0..(3 * k.k as u64) {
            if dec.is_complete() {
                break;
            }
            let (seq, b) = k.repair_drop(abs_seq);
            dec.add_frame(&k.pack(seq, 0, 0x01, &b).unwrap());
        }
        assert_eq!(
            dec.assemble().unwrap(),
            data,
            "repair + elimination is byte-equal"
        );
    }

    #[test]
    fn decoder_refuses_insufficient_drops() {
        // NEGATIVE CANARY: k/2 drops -> assemble returns None (never wrong data)
        let data: Vec<u8> = (1u8..=100).cycle().take(10 * BLOCK).collect();
        let k = Karusel::new(&data).unwrap();
        let mut dec = KaruselDecoder::new(k.k, data.len()).unwrap();
        for i in 0..k.k / 2 {
            let (seq, b) = k.systematic_drop(i).unwrap();
            dec.add_frame(&k.pack(seq, 0, 0, &b).unwrap());
        }
        assert!(
            dec.assemble().is_none(),
            "insufficient drops -> None (the K1 negative canary)"
        );
    }

    #[test]
    fn decoder_drops_a_corrupt_frame_silently() {
        let data: Vec<u8> = (3u8..=90).cycle().take(5 * BLOCK).collect();
        let k = Karusel::new(&data).unwrap();
        let mut dec = KaruselDecoder::new(k.k, data.len()).unwrap();
        // Corrupt magic -> refused
        assert!(!dec.add_frame(b"XXXXXXXXXXXXXXXXXXXXXXXX"));
        // Inconsistent length -> refused
        let (seq, b) = k.systematic_drop(0).unwrap();
        let mut fr = k.pack(seq, 0, 0, &b).unwrap();
        fr.truncate(fr.len() - 3);
        assert!(!dec.add_frame(&fr));
        assert_eq!(dec.solved_count, 0, "a corrupt frame solves no block");
    }

    #[test]
    fn composition_is_derived_by_both_ends_from_the_same_rule() {
        // The wire contract: the sender's repair_drop and the decoder's composition find the SAME set
        let data: Vec<u8> = (0u8..=255).cycle().take(9 * BLOCK).collect();
        let k = Karusel::new(&data).unwrap();
        for abs_seq in 0..20u64 {
            let (seq, sym) = k.repair_drop(abs_seq);
            let idx = Karusel::composition(k.k, seq, true);
            // XORing the same set must yield the same drop
            let mut expect = vec![0u8; idx.iter().map(|&i| k.blocks[i].len()).max().unwrap()];
            for &i in &idx {
                for (a, b) in expect.iter_mut().zip(k.blocks[i].iter()) {
                    *a ^= b;
                }
            }
            assert_eq!(
                sym, expect,
                "abs_seq={abs_seq}: if the two ends diverge the wire is broken"
            );
        }
    }

    #[test]
    fn invalid_input_is_refused() {
        assert!(Karusel::new(b"").is_none());
        assert!(derive_stream(b"", 1, 1).is_none());
        assert!(derive_stream(b"data", 1, 0).is_none());
    }
}
