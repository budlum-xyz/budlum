//! B.U.D. 2.0 Invention - An End-to-End Lossless Pipeline (format detection + container)
//!
//! K38 hardening: from raw bytes to a .bud v2 container, and back again.
//! With `store(data) -> Option<Vec<u8>>` and `restore(bytes) -> Option<Vec<u8>>`
//! the LOSSLESSNESS GUARANTEE is: `restore(store(d)) == d` for EVERY `d` (the
//! K38 property).
//!
//! Layer model:
//!   1. Format detection (heuristic, deterministic) - a wrong detection is NOT
//!      a security problem, because losslessness is independent of the type;
//!      the type only affects chunk granularity (dedup/proof efficiency).
//!   2. Structural chunking + compaction (K35: against small-chunk amplification).
//!   3. A full BudV2File: header + a content_id per chunk + bomb guards.
//!
//! Compression is NOT in this layer: the expert pipeline (structural+zstd19 and
//! so on) is a separate step measured in the runner; this module is the
//! container layer guaranteeing integrity, losslessness and dedup
//! compatibility.
//!
//! Code: no unsafe, deterministic, with property tests. #![forbid(unsafe_code)]
//! is kept.

#![forbid(unsafe_code)]

use crate::bud_format_columnar::{
    columnar_decode, columnar_encode, columnar_to_blob, ColumnarMode,
};
use crate::bud_format_container::{structural_split_compact, BudV2File, FormatCodec};

/// Default compaction threshold (K35): adjacent chunks under 64 KiB are merged.
pub const DEFAULT_MIN_CHUNK: usize = 64 * 1024;

/// Format detection (heuristic, deterministic, independent of losslessness).
/// Order: JSON (first meaningful character `[`/`{`) -> CSV (comma + lines) ->
/// LOG (a line starting with a year) -> Text (contains lines) -> Unknown
/// (binary). A wrong match is safe: chunking is lossless for every type (K38),
/// only the granularity changes.
pub fn detect(data: &[u8]) -> FormatCodec {
    if data.is_empty() {
        return FormatCodec::Unknown;
    }
    // JSON: drop leading whitespace, start with `[` or `{`
    let t = String::from_utf8_lossy(data);
    let first = t.trim_start();
    if first.starts_with('[') || first.starts_with('{') {
        return FormatCodec::Json;
    }
    // CSV: plain text containing commas and lines
    let mut comm = 0u32;
    let mut nl = 0u32;
    for b in data.iter().take(4096) {
        match b {
            b',' => comm += 1,
            b'\n' => nl += 1,
            _ => {}
        }
    }
    if comm > 0 && nl > 0 {
        return FormatCodec::Csv;
    }
    // LOG: the first line starts with a four-digit year (2026-...)
    if let Some(fl) = t.lines().next() {
        let fl = fl.trim_start();
        let b = fl.as_bytes();
        if b.len() >= 4
            && b[0].is_ascii_digit()
            && b[1].is_ascii_digit()
            && b[2].is_ascii_digit()
            && b[3].is_ascii_digit()
        {
            return FormatCodec::Log;
        }
    }
    if nl > 0 {
        return FormatCodec::Text;
    }
    // Last signal: if it is all printable ASCII (line breaks included) it is
    // plain text. A wrong match is safe - losslessness is independent of the
    // type (K38), only the granularity changes.
    let printable = data
        .iter()
        .all(|b| (0x20..0x7F).contains(b) || *b == b'\n' || *b == b'\t' || *b == b'\r');
    if printable {
        return FormatCodec::Text;
    }
    FormatCodec::Unknown // Binary (jpeg/png/mp4/pdf and so on default to binary when undetected)
}

/// Store (RAW): detect -> chunk structurally (compact) -> serialise a BudV2File.
pub fn store(data: &[u8]) -> Option<Vec<u8>> {
    store_with_min(data, DEFAULT_MIN_CHUNK)
}

/// The same as `store`, with the compaction threshold as a parameter (for tests/flexibility).
pub fn store_with_min(data: &[u8], min_chunk: usize) -> Option<Vec<u8>> {
    let codec = detect(data);
    let kind = codec.structural_kind();
    let chunks = structural_split_compact(kind, data, min_chunk);
    let file = BudV2File::new(codec, chunks)?;
    Some(file.encode())
}

/// Store (HUFFMAN): every chunk is compressed with real lossless Huffman - the
/// .bud file GENUINELY shrinks on repetitive content (K38). Losslessness:
/// `restore` returns the original.
pub fn store_compressed(data: &[u8]) -> Option<Vec<u8>> {
    store_compressed_with_min(data, DEFAULT_MIN_CHUNK)
}

/// The same as `store_compressed`, with the compaction threshold as a parameter.
pub fn store_compressed_with_min(data: &[u8], min_chunk: usize) -> Option<Vec<u8>> {
    let codec = detect(data);
    let kind = codec.structural_kind();
    let chunks = structural_split_compact(kind, data, min_chunk);
    let file = BudV2File::new_compressed(codec, chunks)?;
    Some(file.encode())
}

/// Store (ZSTD): every chunk is compressed with real zstd level 19 (the V21
/// roadmap). A better ratio than Huffman; decompression is safe under the K25
/// ceiling. Losslessness: `restore` returns the original.
pub fn store_zstd(data: &[u8]) -> Option<Vec<u8>> {
    store_zstd_with_min(data, DEFAULT_MIN_CHUNK)
}

/// The same as `store_zstd`, with the compaction threshold as a parameter.
pub fn store_zstd_with_min(data: &[u8], min_chunk: usize) -> Option<Vec<u8>> {
    let codec = detect(data);
    let kind = codec.structural_kind();
    let chunks = structural_split_compact(kind, data, min_chunk);
    let file = BudV2File::new_zstd(codec, chunks)?;
    Some(file.encode())
}

/// Restore: verify strictly + decompress the chunks (RAW/Huffman/Zstd detected automatically) + join -> the ORIGINAL.
/// A LOSSLESS JSON COLUMNAR pipeline (invention): it splits a JSON array into
/// columns and writes a zstd-compressed container. Exact -> byte-identical
/// (K38); OrderFree -> the record set is preserved (KF2) at a higher ratio
/// (measured: 7.83x -> 8.53x / 11.49x, seed=7). Irregular JSON -> None
/// (losslessness is preserved, the caller falls back to the raw path).
pub fn store_json_columnar(data: &[u8], mode: ColumnarMode, _min_chunk: usize) -> Option<Vec<u8>> {
    let col = columnar_encode(data, mode)?;
    let blob = columnar_to_blob(&col);
    let chunk = crate::bud_format_container::StructuralChunk {
        content_id: crate::bud_format_container::content_id(&blob),
        data: blob,
    };
    let file = BudV2File::new_zstd(FormatCodec::Json, vec![chunk])?;
    Some(file.encode())
}

/// Restore from a columnar container: zstd decompress -> columnar decode -> JSON.
pub fn restore_json_columnar(bytes: &[u8], mode: ColumnarMode) -> Option<Vec<u8>> {
    let file = BudV2File::decode(bytes)?;
    let raw = file.restore_original()?;
    let col = crate::bud_format_columnar::columnar_from_blob(&raw)?;
    if col.mode != mode {
        return None; // mode mismatch -> refuse
    }
    columnar_decode(&col)
}

pub fn restore(bytes: &[u8]) -> Option<Vec<u8>> {
    let file = BudV2File::decode(bytes)?;
    file.restore_original()
}

/// Chunk count (a helper for tracking dedup/proof efficiency).
pub fn chunk_count(bytes: &[u8]) -> Option<usize> {
    BudV2File::decode(bytes).map(|f| f.chunks.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLES: &[&[u8]] = &[
        // JSON
        br#"[{"user":"u1","ts":"2026-08-16","a":"r","v":42}]"#,
        br#"{"tek":"nesne"}"#,
        br#"[1,2,3,4]"#,
        // CSV
        b"u,ts,a,v\nu1,2026-08-16,r,42\nu2,2026-08-16,w,7\n",
        b"a,b\n1,2\n",
        // LOG
        b"2026-08-16T10:00:00Z INFO req=1 /a s=200\n2026-08-16T10:01:00Z WARN req=2 /b s=404\n",
        // TEXT
        b"line 1\nline 2\nline 3\n",
        b"single line without a terminator",
        // BINARY
        &[0x89, 0x50, 0x4E, 0x47, 0x00, 0x01, 0x02, 0xFF],
        b"",
    ];

    #[test]
    fn detect_classifies_samples() {
        // JSON
        assert_eq!(detect(SAMPLES[0]), FormatCodec::Json);
        assert_eq!(detect(SAMPLES[1]), FormatCodec::Json);
        assert_eq!(detect(SAMPLES[2]), FormatCodec::Json);
        // CSV
        assert_eq!(detect(SAMPLES[3]), FormatCodec::Csv);
        assert_eq!(detect(SAMPLES[4]), FormatCodec::Csv);
        // LOG
        assert_eq!(detect(SAMPLES[5]), FormatCodec::Log);
        // TEXT
        assert_eq!(detect(SAMPLES[6]), FormatCodec::Text);
        assert_eq!(detect(SAMPLES[7]), FormatCodec::Text);
        // BINARY
        assert_eq!(detect(SAMPLES[8]), FormatCodec::Unknown);
        assert_eq!(detect(SAMPLES[9]), FormatCodec::Unknown);
    }

    #[test]
    fn store_restore_roundtrip_all_samples() {
        // K38: restore(store(d)) == d for EVERY sample
        for (i, data) in SAMPLES.iter().enumerate() {
            let enc = store(data).unwrap_or_else(|| panic!("sample {i} must store"));
            let dec = restore(&enc).unwrap_or_else(|| panic!("sample {i} must restore"));
            assert_eq!(&dec[..], *data, "sample {i} must be lossless");
            // every sample must contain at least 1 chunk (0 chunks only for empty input)
            let cc = chunk_count(&enc).unwrap();
            if data.is_empty() {
                assert_eq!(cc, 0);
            } else {
                assert!(cc >= 1, "sample {i} needs at least 1 chunk");
            }
        }
    }

    #[test]
    fn store_restore_property_random() {
        // 150 random inputs from a deterministic PRNG - the losslessness property (K38)
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
            fn below(&mut self, n: usize) -> usize {
                (self.next() % n as u64) as usize
            }
        }
        let mut rng = Rng(0x501F_2026_0816_0001);
        for round in 0..150u32 {
            let mut data = Vec::new();
            let n = rng.below(4000);
            for _ in 0..n {
                match rng.below(5) {
                    0 => data.push(b'\n'),
                    1 => data.push(b','),
                    2 => data.push(b'"'),
                    3 => data.push(b'a' + (rng.below(26) as u8)),
                    _ => data.push((rng.next() & 0xff) as u8),
                }
            }
            let enc = store_with_min(&data, 1 + rng.below(1024)).expect("store");
            let dec = restore(&enc).expect("restore");
            assert_eq!(dec, data, "round {round} must be lossless");
        }
    }

    #[test]
    fn store_compressed_roundtrip_all_samples() {
        // K38: the compressed pipeline is lossless on EVERY sample too; restore detects RAW/HFM/Zstd
        for (i, data) in SAMPLES.iter().enumerate() {
            let enc = store_compressed(data).unwrap_or_else(|| panic!("sample {i} must store"));
            let dec = restore(&enc).unwrap_or_else(|| panic!("sample {i} must restore"));
            assert_eq!(
                &dec[..],
                *data,
                "sample {i} lossless in the compressed round"
            );
            // zstd turu
            let encz = store_zstd(data).unwrap_or_else(|| panic!("sample {i} must store_zstd"));
            let decz = restore(&encz).unwrap_or_else(|| panic!("sample {i} must restore_zstd"));
            assert_eq!(&decz[..], *data, "sample {i} lossless in the zstd round");
        }
        // repetitive log: the compressed .bud must be smaller than RAW (real compression)
        let line = b"2026-08-16 INFO req=1 /api/a s=200 b=42 reg=tr\n";
        let mut log = Vec::new();
        for _ in 0..2000 {
            log.extend_from_slice(line);
        }
        let raw = store(&log).unwrap();
        let comp = store_compressed(&log).unwrap();
        assert!(
            comp.len() < raw.len(),
            "the compressed .bud must shrink: {} vs {}",
            raw.len(),
            comp.len()
        );
        assert_eq!(restore(&comp).unwrap(), log);
        let z = store_zstd(&log).unwrap();
        assert!(
            z.len() < comp.len(),
            "zstd is smaller than Huffman: {} vs {}",
            z.len(),
            comp.len()
        );
        assert_eq!(restore(&z).unwrap(), log);
    }

    #[test]
    fn restore_rejects_corruption_and_bombs() {
        let data = br#"[{"a":1},{"a":2},{"a":3}]"#;
        let enc = store(data).unwrap();
        // payload kurcalama
        let mut t1 = enc.clone();
        *t1.last_mut().unwrap() ^= 0x40;
        assert!(restore(&t1).is_none());
        // truncation
        let mut t2 = enc.clone();
        t2.truncate(enc.len() - 2);
        assert!(restore(&t2).is_none());
        // garbage
        assert!(restore(&[0xFF; 64]).is_none());
        assert!(restore(&[]).is_none());
    }
}
