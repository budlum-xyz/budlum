//! .bud real compression - REAL lossless compression (2026-08-16)
//!
//! THE PREVIOUS VERSION WAS A STUB: `zstd_compress`/`xz_compress` imitated the
//! zstd/xz MAGIC and returned the first 100 bytes - it was not real compression,
//! it produced a fake envelope (no real decompressor could open it). This
//! version REPLACES it: the real, lossless, zero-dependency Huffman codec
//! (bud_format_huffman) is used, and the magic is specific to B.U.D. (no
//! imitation). Real zstd/xz/avif FFI integration is a separate step (its
//! measurements are documented separately).

#![forbid(unsafe_code)]

use crate::bud_format_huffman::{HuffmanCoder, BUD_HFM_MAGIC};

/// A real lossless compressor (Huffman based, no unsafe, deterministic).
pub struct RealCompressor;

/// Real zstd FFI (the V21 roadmap - the zstd crate).
/// `zstd_compress`: real zstd compression at a level (the unsafe lives in the
/// crate, not in our code).
/// `zstd_decompress_safe`: decompression with a CEILING on both the frame
/// content size and the output size (K25 bomb protection).
pub fn zstd_compress(data: &[u8], level: i32) -> Option<Vec<u8>> {
    zstd::encode_all(data, level).ok()
}

pub const ZSTD_MAX_DECOMPRESSED: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB (the K25 ceiling)

pub fn zstd_decompress_safe(bytes: &[u8], max_out: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    // the original size from the frame header (zstd_safe::get_frame_content_size)
    let frame_sz = zstd::zstd_safe::get_frame_content_size(bytes).ok()?;
    if let Some(sz) = frame_sz {
        if sz > max_out {
            return None; // bomb: the frame claims an original size above the ceiling
        }
    }
    // The header check above only helps when the frame states its content
    // size; a streaming frame states none, and the old code then decompressed
    // the whole stream into memory and compared the length afterwards, which
    // is the bomb the ceiling exists to stop. Read at most `max_out + 1`
    // bytes: one past the ceiling is enough to know the stream is too large,
    // and nothing beyond that is ever allocated.
    let dec = zstd::stream::read::Decoder::new(bytes).ok()?;
    let mut out = Vec::new();
    dec.take(max_out.saturating_add(1))
        .read_to_end(&mut out)
        .ok()?;
    if out.len() as u64 > max_out {
        return None; // the stream passed the ceiling; it is refused, not held
    }
    Some(out)
}

impl RealCompressor {
    /// Compress: a BUD-HFM1 envelope. The returned data can be opened on ITS OWN (decompress).
    pub fn compress(data: &[u8]) -> Vec<u8> {
        HuffmanCoder::compress(data)
    }

    /// Decompress: verify strictly (magic + ceiling + Kraft + code validity)
    /// -> the original.
    /// Any inconsistency -> None (no panic).
    pub fn decompress(bytes: &[u8]) -> Option<Vec<u8>> {
        HuffmanCoder::decompress(bytes)
    }

    /// Is this data a B.U.D.-Huffman envelope? (For v1/v2 discrimination and diagnostics.)
    pub fn is_bud_hfm(bytes: &[u8]) -> bool {
        bytes.len() >= 8 && bytes[0..8] == BUD_HFM_MAGIC
    }
}

/// The real measurement table (2026-08-16 runner: Python zstd-19/xz9, a
/// deterministic corpus). NO invented numbers - every row was measured; a
/// pipeline name plus a real ratio. (Since there is no Rust FFI for zstd/xz, no
/// speed values are given; the ratio is the size reduction.)
pub struct RealBench;

impl RealBench {
    /// Verified ratios: REPRODUCIBLE with `scripts/measure_ratios.py --seed 7`
    /// (a deterministic corpus of 50k JSON / 60k CSV / 80k LOG). The
    /// 8.48x/5.51x/7.68x values written in the old table came from a different
    /// (non-reproducible) corpus - as K19 honesty requires, they were replaced
    /// with the verified values (EK13).
    pub fn measured_ratios() -> Vec<(&'static str, f64)> {
        vec![
            ("structural+zstd19 JSON", 7.83), // measure_ratios.py seed=7 (50k records)
            ("structural+xz9 JSON", 8.07),    // measure_ratios.py seed=7
            ("structural+zstd19 CSV", 3.55),  // measure_ratios.py seed=7 (60k lines)
            ("structural+zstd19 LOG", 6.17),  // measure_ratios.py seed=7 (80k lines)
            ("structural+xz9 LOG", 6.30),     // measure_ratios.py seed=7
            ("BUD-HFM1 (built-in Huffman) LOG", 1.69), // over a 13.98MB sample (CLI evidence)
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_compress_roundtrip() {
        let line = b"a=b c=d e=f g=h repeat repeat repeat repeat repeat\n";
        let mut data = Vec::new();
        for _ in 0..30 {
            data.extend_from_slice(line);
        }
        let c = RealCompressor::compress(&data);
        assert!(
            c.len() < data.len(),
            "repetitive data must genuinely compress: {} -> {}",
            data.len(),
            c.len()
        );
        assert!(RealCompressor::is_bud_hfm(&c), "a BUD-HFM envelope");
        let d = RealCompressor::decompress(&c).unwrap();
        assert_eq!(d, data, "lossless roundtrip");
    }

    #[test]
    fn there_is_no_fake_zstd_magic() {
        // The old stub started with the zstd magic (28 B5 2F FD) - it must never be produced again.
        let data = vec![b'x'; 1000];
        let c = RealCompressor::compress(&data);
        assert_ne!(
            &c[..4],
            &[0x28, 0xB5, 0x2F, 0xFD],
            "zstd magic taklidi YASAK"
        );
        assert_ne!(
            &c[..6],
            &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
            "xz magic taklidi YASAK"
        );
    }

    #[test]
    fn measured_ratios_documented() {
        // Every ratio is > 1.0 (real compression) and consistent with the ceiling (K19)
        for (name, r) in RealBench::measured_ratios() {
            assert!(r > 1.0, "{name} ratio must be > 1");
            assert!(
                r < 30.0,
                "{name} ratio is realistic (<30) - no zip-bomb claim"
            );
        }
    }
    #[test]
    fn zstd_roundtrip_and_beats_huffman() {
        // REAL zstd: compress -> decompress = the original; better than Huffman on repetitive data
        let line = b"2026-08-16 INFO req=123 /api/a s=200 b=42 reg=tr\n";
        let mut data = Vec::new();
        for _ in 0..5000 {
            data.extend_from_slice(line);
        }
        let c = zstd_compress(&data, 19).expect("zstd compression");
        assert!(
            c.len() < data.len(),
            "zstd must compress: {} -> {}",
            data.len(),
            c.len()
        );
        let d = zstd_decompress_safe(&c, ZSTD_MAX_DECOMPRESSED).expect("zstd decompression");
        assert_eq!(d, data, "zstd is lossless");
        // compare against Huffman
        let h = RealCompressor::compress(&data);
        assert!(
            c.len() < h.len(),
            "zstd must beat Huffman: zstd {} vs hfm {}",
            c.len(),
            h.len()
        );
    }
    #[test]
    fn zstd_decompress_bomb_guards() {
        // K25: a fake zstd frame (a very large content size) -> None, no panic
        // zstd frame header: magic + frame header; it claims a content size
        // above 2^32
        let fake = [
            0x28u8, 0xB5, 0x2F, 0xFD, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        ];
        let _ = zstd_decompress_safe(&fake, ZSTD_MAX_DECOMPRESSED); // panik yok
                                                                    // corrupt data -> None
        assert!(zstd_decompress_safe(b"BUD", 1024).is_none());
        // decompression with a small ceiling: opening 1MB of data under a 1KB ceiling -> None
        let data = vec![b'a'; 1024 * 1024];
        let c = zstd_compress(&data, 3).expect("zstd");
        assert!(
            zstd_decompress_safe(&c, 1024).is_none(),
            "passing the ceiling must return None"
        );
    }

    /// A frame written without its content size (the streaming encoder does
    /// this) bypassed the header check and was fully decompressed before the
    /// ceiling was compared. It is now refused at the ceiling, and the
    /// refusal is reached by reading at most one byte past it.
    #[test]
    fn a_streaming_frame_past_the_ceiling_is_refused_without_being_held() {
        use std::io::Write;
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 3).expect("encoder");
        for _ in 0..64 {
            enc.write_all(&[0u8; 4096]).expect("write");
        }
        let frame = enc.finish().expect("finish"); // 256 KiB of zeros, no content size
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&frame).ok().flatten(),
            None,
            "the fixture must be a frame without a stated size, or the header check hides the path"
        );
        assert!(zstd_decompress_safe(&frame, 4096).is_none(), "past the ceiling: refused");
        assert_eq!(
            zstd_decompress_safe(&frame, 256 * 1024).map(|v| v.len()),
            Some(256 * 1024),
            "at the ceiling: accepted"
        );
    }
}
