//! Structural splitting: a format-aware cut before content-defined chunking.
//!
//! Content is divided at structural boundaries (JSON record / CSV row / log
//! line / code block), and each piece gets its own content id - a lossless
//! cut that keeps dedup and proof granularity aligned with the format.
//! Compaction gathers under-minimum adjacent pieces back together; the join
//! is byte-identical to the original.
//!
//! Code: no unsafe, deterministic, with tests. #![forbid(unsafe_code)] is kept.
//! Exposed for the B.U.D. 3.0 codec registry: the registry wires these
//! transforms.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

// -- 1. Structural splitting (format-aware, lossless) ------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StructuralKind {
    Json,   // JSON array: cut at record boundaries
    Csv,    // CSV: cut at row boundaries
    Log,    // Log: cut at line boundaries (templating comes later)
    Text,   // Text: sentence/paragraph boundary (simple: line)
    Binary, // Binary: CDC (content-defined) - fixed average
}

#[derive(Debug, Clone)]
pub struct StructuralChunk {
    pub content_id: [u8; 32], // BDLM_CONTENT_V1 || len || bytes (cryptographic)
    pub data: Vec<u8>,
}

/// Cuts content at structural boundaries (lossless: join = original).
/// JSON: the delimiters are embedded in the pieces, a depth-1 comma is a piece
/// boundary (the comma is kept at the start of the NEXT piece). Even if the
/// input is not an array or is malformed it becomes a single piece, so every
/// input is lossless.
/// CSV/Log/Text: line boundary.
/// Binary: fixed block (a simplified CDC pre-step - average size).
///
/// COMPLETENESS of losslessness: `structural_join(kind, structural_split(kind, d)) == d`
/// holds for EVERY `d` (empty, malformed UTF-8, unframed JSON, negative depth
/// included); the join is a pure concatenation and the delimiter information
/// travels inside the pieces.
pub fn structural_split(kind: StructuralKind, data: &[u8]) -> Vec<StructuralChunk> {
    if data.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    match kind {
        StructuralKind::Json => {
            // Because every scanned piece is a contiguous subslice of the
            // original bytes and no byte is skipped, the join always produces
            // the original. The depth is an i32; on malformed input it
            // goes negative but does not panic, and losslessness holds.
            let s = match std::str::from_utf8(data) {
                Ok(s) => s,
                Err(_) => return split_fixed(data, 65536),
            };
            let mut start = 0usize;
            let mut depth = 0i32;
            let mut in_str = false;
            let mut esc = false;
            for (i, c) in s.char_indices() {
                match c {
                    '"' if !esc => in_str = !in_str,
                    '\\' if in_str => esc = !esc,
                    _ => esc = false,
                }
                if !in_str {
                    match c {
                        '{' | '[' => depth += 1,
                        '}' | ']' => depth -= 1,
                        // depth-1 comma: the array's top-level record boundary
                        ',' if depth == 1 => {
                            if i > start {
                                push_chunk(&mut out, &s[start..i]);
                            }
                            // the comma is kept at the start of the NEXT
                            // piece: start = i (not i+1!), otherwise the comma
                            // falls between the pieces and the JSON breaks.
                            start = i;
                        }
                        _ => {}
                    }
                }
            }
            push_chunk(&mut out, &s[start..]);
            out
        }
        StructuralKind::Csv | StructuralKind::Log | StructuralKind::Text => {
            // Line boundary (lossless: \n is kept - every piece ends with a newline)
            for line in data.split_inclusive(|&b| b == b'\n') {
                let chunk = line.to_vec();
                out.push(StructuralChunk {
                    content_id: content_id(&chunk),
                    data: chunk,
                });
            }
            out
        }
        StructuralKind::Binary => split_fixed(data, 65536),
    }
}

fn push_chunk(out: &mut Vec<StructuralChunk>, seg: &str) {
    if seg.is_empty() {
        return;
    }
    let chunk = seg.as_bytes().to_vec();
    out.push(StructuralChunk {
        content_id: content_id(&chunk),
        data: chunk,
    });
}

fn split_fixed(data: &[u8], block: usize) -> Vec<StructuralChunk> {
    let mut out = Vec::new();
    for chunk in data.chunks(block) {
        let v = chunk.to_vec();
        out.push(StructuralChunk {
            content_id: content_id(&v),
            data: v,
        });
    }
    out
}

pub fn content_id(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_CONTENT_V1");
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}

/// Proof of losslessness: join the pieces -> the original.
/// A PURE join - the splitting delimiters (`[`, `]`, comma) are embedded
/// in the pieces and the join adds no `[`/`]` for any kind, so the round trip
/// is byte-identical to the original for EVERY input (unframed JSON, malformed
/// UTF-8, empty input included).
pub fn structural_join(_kind: StructuralKind, chunks: &[StructuralChunk]) -> Vec<u8> {
    let total: usize = chunks.iter().map(|c| c.data.len()).sum();
    let mut out = Vec::with_capacity(total);
    for c in chunks {
        out.extend_from_slice(&c.data);
    }
    out
}

pub enum FormatCodec {
    Json = 1,
    Csv = 2,
    Log = 3,
    Text = 4,
    Jpeg = 11,
    Png = 12,
    Mp4 = 10,
    Pdf = 16,
    Unknown = 0,
}

impl FormatCodec {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::Json,
            2 => Self::Csv,
            3 => Self::Log,
            4 => Self::Text,
            10 => Self::Mp4,
            11 => Self::Jpeg,
            12 => Self::Png,
            16 => Self::Pdf,
            _ => Self::Unknown,
        }
    }
    pub fn structural_kind(self) -> StructuralKind {
        match self {
            Self::Json => StructuralKind::Json,
            Self::Csv => StructuralKind::Csv,
            Self::Log => StructuralKind::Log,
            Self::Text => StructuralKind::Text,
            _ => StructuralKind::Binary,
        }
    }
}

/// compaction: merge pieces below the minimum size (lossless).
/// The fix for small-object amplification (the S.61 MinIO/Ceph
/// lesson): very small pieces lower dedup/proof efficiency, so adjacent
/// under-minimum pieces are gathered into one. Still byte-identical to the
/// original under `structural_join`.
pub fn structural_split_compact(
    kind: StructuralKind,
    data: &[u8],
    min_chunk: usize,
) -> Vec<StructuralChunk> {
    let raw = structural_split(kind, data);
    if raw.is_empty() {
        return raw;
    }
    let mut out: Vec<StructuralChunk> = Vec::new();
    let mut acc: Vec<u8> = Vec::new();
    for c in raw {
        if acc.is_empty() && c.data.len() >= min_chunk {
            // a large piece goes straight through
            out.push(c);
        } else if acc.len() + c.data.len() <= min_chunk.max(1) {
            acc.extend_from_slice(&c.data);
        } else {
            // flush the accumulator, then start a new piece
            if !acc.is_empty() {
                let v = std::mem::take(&mut acc);
                out.push(StructuralChunk {
                    content_id: content_id(&v),
                    data: v,
                });
            }
            if c.data.len() >= min_chunk {
                out.push(c);
            } else {
                acc = c.data;
            }
        }
    }
    if !acc.is_empty() {
        out.push(StructuralChunk {
            content_id: content_id(&acc),
            data: acc,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_structural_split_roundtrip() {
        // lossless: split + join = the original
        let json = br#"[{"a":1,"b":2},{"a":3,"b":4},{"a":5,"b":6}]"#;
        let chunks = structural_split(StructuralKind::Json, json);
        assert!(
            chunks.len() >= 3,
            "as many pieces as JSON records: {}",
            chunks.len()
        );
        let joined = structural_join(StructuralKind::Json, &chunks);
        assert_eq!(
            &joined[..],
            &json[..],
            "JSON structural splitting must be lossless"
        );
    }

    #[test]
    fn csv_structural_split_roundtrip() {
        let csv = b"a,b,c\n1,2,3\n4,5,6\n";
        let chunks = structural_split(StructuralKind::Csv, csv);
        assert!(chunks.len() >= 3);
        let joined = structural_join(StructuralKind::Csv, &chunks);
        assert_eq!(&joined[..], &csv[..]);
    }

    #[test]
    fn content_id_deterministic_and_cryptographic() {
        let a = content_id(b"budlum");
        let b = content_id(b"budlum");
        assert_eq!(a, b, "deterministik");
        assert_ne!(a, content_id(b"budlu"), "different input, different hash");
        assert_ne!(a, [0u8; 32], "not zero (cryptographic)");
    }

    #[test]
    fn compact_merges_small_chunks_lossless() {
        // CSV: every row is ~12B; must merge under a 64B minimum, lossless
        let csv = b"a,b,c\n1,2,3\n4,5,6\n7,8,9\n10,11,12\n";
        let raw = structural_split(StructuralKind::Csv, csv);
        let comp = structural_split_compact(StructuralKind::Csv, csv, 64);
        assert!(
            raw.len() > comp.len(),
            "compaction must lower the piece count"
        );
        let joined = structural_join(StructuralKind::Csv, &comp);
        assert_eq!(joined, csv, "compaction kayipsiz");
        // the content_id is correct in every merged piece
        for c in &comp {
            assert_eq!(c.content_id, content_id(&c.data));
        }
    }
    #[test]
    fn log_split_preserves_lines() {
        let log = b"2026-08-16 INFO a\n2026-08-16 WARN b\n";
        let chunks = structural_split(StructuralKind::Log, log);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].data.ends_with(b"\n"));
        let joined = structural_join(StructuralKind::Log, &chunks);
        assert_eq!(joined, log);
    }

    // --: COMPLETENESS of losslessness - property tests --------------------

    /// Deterministic xorshift64* - no external dependency (no rand crate).
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
        fn byte(&mut self) -> u8 {
            (self.next() & 0xff) as u8
        }
    }

    fn gen_string(rng: &mut Rng) -> Vec<u8> {
        let mut out = vec![b'"'];
        let n = rng.below(10);
        for _ in 0..n {
            match rng.below(6) {
                0 => out.push(b'\\'), // escape (exercises the string state)
                1 => out.push(b'"'),  // escaped quote
                2 => out.push(b'{'),
                3 => out.push(b','),
                _ => {
                    // ascii or multi-byte UTF-8
                    if rng.below(2) == 0 {
                        out.push(0xC3);
                        out.push(0xA9);
                    } else {
                        out.push(b'a');
                    }
                }
            }
        }
        out.push(b'"');
        out
    }

    fn gen_json(rng: &mut Rng, depth: usize) -> Vec<u8> {
        if depth > 8 {
            return b"0".to_vec();
        }
        let mut out = Vec::new();
        match rng.below(4) {
            0 => {
                out.push(b'{');
                let n = rng.below(4);
                for i in 0..n {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(&gen_string(rng));
                    out.push(b':');
                    out.extend_from_slice(&gen_json(rng, depth + 1));
                }
                out.push(b'}');
            }
            1 => {
                out.push(b'[');
                let n = rng.below(5);
                for i in 0..n {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(&gen_json(rng, depth + 1));
                }
                out.push(b']');
            }
            2 => out.extend_from_slice(&gen_string(rng)),
            _ => out.extend_from_slice(&format!("{}", rng.below(1000)).into_bytes()),
        }
        out
    }

    fn gen_lines(rng: &mut Rng) -> Vec<u8> {
        let mut out = Vec::new();
        let n = 1 + rng.below(30);
        for _ in 0..n {
            let len = rng.below(40);
            for _ in 0..len {
                out.push(b'a' + (rng.below(26) as u8));
                if rng.below(5) == 0 {
                    out.push(b','); // an inline comma
                }
            }
            match rng.below(4) {
                0 => {}               // no line ending (last line)
                1 => out.push(b'\r'), // a lone \r (not a line ending)
                _ => out.push(b'\n'),
            }
        }
        out
    }

    #[test]
    fn total_losslessness_property() {
        // For EVERY input split+join = the original; compact (at various minimums) is lossless too.
        let mut rng = Rng(0xB0B2_2026_0816_1337);
        for round in 0..400u32 {
            let kind = match rng.below(5) {
                0 => StructuralKind::Json,
                1 => StructuralKind::Csv,
                2 => StructuralKind::Log,
                3 => StructuralKind::Text,
                _ => StructuralKind::Binary,
            };
            let data: Vec<u8> = match kind {
                StructuralKind::Json => gen_json(&mut rng, 0),
                StructuralKind::Binary => {
                    let mut v = vec![0u8; rng.below(3000)];
                    for b in &mut v {
                        *b = rng.byte();
                    }
                    v
                }
                _ => gen_lines(&mut rng),
            };
            let chunks = structural_split(kind, &data);
            let joined = structural_join(kind, &chunks);
            assert_eq!(
                &joined[..],
                &data[..],
                "round {round} kind={kind:?} split+join must be lossless"
            );
            for mc in [1usize, 7, 64, 257, 4096] {
                let comp = structural_split_compact(kind, &data, mc);
                assert_eq!(
                    structural_join(kind, &comp),
                    data,
                    "round {round} kind={kind:?} compact(min={mc}) must be lossless"
                );
            }
        }
    }

    #[test]
    fn edge_inputs_lossless() {
        // empty, unframed JSON, malformed UTF-8, negative depth, whitespace only
        for kind in [
            StructuralKind::Json,
            StructuralKind::Csv,
            StructuralKind::Log,
            StructuralKind::Text,
            StructuralKind::Binary,
        ] {
            let empty: Vec<u8> = vec![];
            assert!(structural_split(kind, &empty).is_empty());
            assert!(structural_join(kind, &[]).is_empty());
        }
        let cases: &[&[u8]] = &[
            b"",                                  // empty
            b"   ",                               // whitespace
            b"{\"a\":1}",                         // an object (not an array)
            b"\"merhaba\"",                       // ilkel
            b"1,2,3",                             // top-level primitives
            b"[]}",                               // malformed: extra closer
            b"[{\"a\":1}",                        // malformed: missing closer
            b"{\"a\":[1,2],\"b\":[3,4]}",         // nested arrays
            b"[[1,2],[3,4]]",                     // an array inside an array
            b"[\n  {\"a\": 1},\n  {\"a\": 2}\n]", // multi-line
            &[0xFF, 0xFE, 0x00, 0x41, 0x22],      // invalid UTF-8
            b"a\r\nb\r\nc",                       // CRLF
            b"\"{\"",                             // a delimiter inside a string
        ];
        for (i, data) in cases.iter().enumerate() {
            for kind in [
                StructuralKind::Json,
                StructuralKind::Csv,
                StructuralKind::Log,
                StructuralKind::Text,
                StructuralKind::Binary,
            ] {
                let chunks = structural_split(kind, data);
                assert_eq!(
                    structural_join(kind, &chunks),
                    *data,
                    "case {i} kind={kind:?} must be lossless"
                );
            }
        }
    }

    #[test]
    fn json_record_boundaries_at_depth1_commas() {
        let json = br#"[{"a":1},{"a":2},{"a":3}]"#;
        let chunks = structural_split(StructuralKind::Json, json);
        assert!(chunks.len() >= 3, "as many pieces as records");
        assert!(
            chunks[0].data.starts_with(b"["),
            "the first piece carries the opening delimiter"
        );
        for c in &chunks[1..] {
            assert!(
                c.data.starts_with(b","),
                "a piece boundary must start with a comma (JSON validity is preserved)"
            );
        }
        assert_eq!(structural_join(StructuralKind::Json, &chunks), json);
    }
}

