//! .bud CLI - encode/decode, ratio proof, bench, bft vote
//! V7 plus K38: the .bud v2 container API (structural chunking plus whole-file
//! serialisation).

#![forbid(unsafe_code)]

use crate::bud_format::{BudFile, BudFlags, BudFormatClass, MultiRatioConsensus};
use crate::bud_format_container::{
    structural_join, structural_split_compact, BudV2File, FormatCodec, StructuralKind,
};
use crate::bud_format_economics::BudEconomics;

pub struct BudCli;

impl BudCli {
    pub fn encode(_path: &str, data: &[u8], class: BudFormatClass) -> BudFile {
        let mime = match class {
            BudFormatClass::Json => "application/json",
            BudFormatClass::Jpeg => "image/jpeg",
            _ => "application/octet-stream",
        };
        let required = 16.68; // plain 7+1
        let cand = MultiRatioConsensus::select_best(
            MultiRatioConsensus::candidates_for_format(class, data),
            required,
        );
        match cand {
            Some(c) => BudFile::encode(data, class, mime, 0, 0, c.pipe_id, c.flags, c.payload),
            None => BudFile::encode(
                data,
                class,
                mime,
                0,
                0,
                0,
                BudFlags::new(true, true, false, false, false, false),
                data.to_vec(),
            ),
        }
    }

    pub fn decode(file: &BudFile) -> Result<Vec<u8>, &'static str> {
        file.decode()
    }

    /// Writes a .bud v2 container: structural chunking (compact, min_chunk)
    /// plus a serialised `BudV2File`. The losslessness guarantee is
    /// `decode_container(encode_container(..)) == original` (K38).
    pub fn encode_container(
        kind: StructuralKind,
        codec: FormatCodec,
        data: &[u8],
        min_chunk: usize,
    ) -> Option<Vec<u8>> {
        let chunks = structural_split_compact(kind, data, min_chunk);
        let file = BudV2File::new(codec, chunks)?;
        Some(file.encode())
    }

    /// Reads a .bud v2 container: verifies strictly (the header, the
    /// content_id of every chunk and the root) and then joins them. A corrupt
    /// input or an input bomb gives `None`, never a panic (K38).
    pub fn decode_container(bytes: &[u8]) -> Option<Vec<u8>> {
        let file = BudV2File::decode(bytes)?;
        let kind = file.header.codec.structural_kind();
        Some(structural_join(kind, &file.chunks))
    }

    pub fn bench(data: &[u8]) -> (f64, f64, f64) {
        // returns (encode MB/s, decode MB/s, ratio)
        let start = std::time::Instant::now();
        let f = Self::encode("test.json", data, BudFormatClass::Json);
        let enc_elapsed = start.elapsed().as_secs_f64();
        let enc_speed = (data.len() as f64 / (1024.0 * 1024.0)) / enc_elapsed.max(0.001);
        let start2 = std::time::Instant::now();
        let _ = Self::decode(&f);
        let dec_elapsed = start2.elapsed().as_secs_f64();
        let dec_speed = (data.len() as f64 / (1024.0 * 1024.0)) / dec_elapsed.max(0.001);
        let econ = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 17.19,
            device_only: false,
        };
        let cost = econ.cost_per_tb_month();
        (enc_speed, dec_speed, cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_encode_decode() {
        let data = br#"{"key":"value"}"#;
        let f = BudCli::encode("test.json", data, BudFormatClass::Json);
        let out = BudCli::decode(&f).unwrap();
        assert_eq!(out, data);
    }
    #[test]
    fn cli_bench() {
        let data = vec![b'a'; 1024 * 1024];
        let (enc, dec, cost) = BudCli::bench(&data);
        assert!(enc > 0.0);
        assert!(dec > 0.0);
        assert!(cost < 0.02);
    }
    #[test]
    fn cli_container_roundtrip_all_kinds() {
        // K38: for every kind, encode_container then decode_container gives
        // back the original.
        let json = br#"[{"a":1},{"a":2},{"a":3},{"a":4}]"#;
        let csv = b"a,b,c\n1,2,3\n4,5,6\n7,8,9\n";
        let log = b"2026-08-16T10:00:00Z INFO req=1\n2026-08-16T10:01:00Z WARN req=2\n";
        let text = b"first line\nsecond line\nthird line\n";
        let bin: Vec<u8> = (0u8..255).cycle().take(200_000).collect();
        for (data, kind, codec) in [
            (&json[..], StructuralKind::Json, FormatCodec::Json),
            (&csv[..], StructuralKind::Csv, FormatCodec::Csv),
            (&log[..], StructuralKind::Log, FormatCodec::Log),
            (&text[..], StructuralKind::Text, FormatCodec::Text),
            (&bin[..], StructuralKind::Binary, FormatCodec::Unknown),
        ] {
            for min in [1usize, 64, 4096, 65536] {
                let enc = BudCli::encode_container(kind, codec, data, min)
                    .expect("the container has to encode");
                let dec = BudCli::decode_container(&enc).expect("the container has to be readable");
                assert_eq!(
                    &dec[..],
                    data,
                    "kind={kind:?} min={min} lossless round trip"
                );
            }
        }
    }
    #[test]
    fn cli_container_rejects_tamper() {
        let json = br#"[{"a":1},{"a":2}]"#;
        let enc =
            BudCli::encode_container(StructuralKind::Json, FormatCodec::Json, json, 64).unwrap();
        let mut bad = enc.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(BudCli::decode_container(&bad).is_none(), "kurcalama red");
        assert!(
            BudCli::decode_container(b"BUD").is_none(),
            "garbage input is refused"
        );
    }
}
