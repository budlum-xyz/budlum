//! The A0 codec register: one frozen row per codec id.
//!
//! A registered id is never removed and its meaning never changes. The row is
//! the meaning: which transform, split rule and entropy coder the id names,
//! what content it applies to, which speed class the reference client must
//! reach on one core, and whether the codec is open.
//!
//! [`CodecState::Open`] means the decoder lives in this crate: every payload a
//! past encoder wrote decodes the same way forever. [`CodecState::Closed`]
//! means the definition is frozen but the decoder is not here. An object that
//! carries a closed id could never produce its content again, so registration
//! refuses it. [`CodecState::Reserved`] is the one id that is never valid.
//!
//! Speed classes are floors measured on the reference client, one core:
//! [`Speed::High`] at least 50 MB/s, [`Speed::Medium`] at least 5 MB/s,
//! [`Speed::Slow`] at least 0.5 MB/s. Rows whose speed is a target rather
//! than a measurement stay closed until they are measured and pass.
//! Convenience: public B.U.D. 3.0 codec surface consumed by upload, replacement, and fuzz harnesses.

use crate::CodecId;

/// The state of a codec id in the register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecState {
    /// The decoder is in this crate and tested.
    Open,
    /// The definition is frozen, the decoder is not available. Refused.
    Closed,
    /// Never valid.
    Reserved,
}

/// The speed class a codec must reach on one core of the reference client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    /// At least 50 MB/s.
    High,
    /// At least 5 MB/s.
    Medium,
    /// At least 0.5 MB/s.
    Slow,
}

/// One frozen row of the register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecEntry {
    /// The codec id.
    pub id: CodecId,
    /// The frozen name of the codec.
    pub name: &'static str,
    /// The content the codec applies to.
    pub applies_to: &'static str,
    /// The speed class. [`None`] only for the reserved id.
    pub speed: Option<Speed>,
    /// Whether the codec is open.
    pub state: CodecState,
}

/// The register, in id order. The rows carry the frozen meaning of the ids
/// 0 through 26; the id 9 is reserved and has no codec.
pub static REGISTER: [CodecEntry; 27] = [
    CodecEntry {
        id: 0,
        name: "raw",
        applies_to: "every content; always a candidate",
        speed: Some(Speed::High),
        state: CodecState::Open,
    },
    CodecEntry {
        id: 1,
        name: "zstd (level 19, long distance matching, fixed 8 MiB window)",
        applies_to: "general content",
        speed: Some(Speed::High),
        state: CodecState::Open,
    },
    CodecEntry {
        id: 2,
        name: "LZMA2 (xz, preset 9e)",
        applies_to: "general content",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 3,
        name: "dictionary zstd",
        applies_to: "objects under 16 KiB, with the class dictionary",
        speed: Some(Speed::High),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 4,
        name: "columnar JSON and zstd (Exact mode)",
        applies_to: "JSON record arrays",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 5,
        name: "lepton_jpeg",
        applies_to: "JPEG, base and progressive",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 6,
        name: "preflate and LZMA2",
        applies_to: "content carrying a DEFLATE stream",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 7,
        name: "lossless audio and header",
        applies_to: "PCM WAV and AIFF",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 8,
        name: "context mixing",
        applies_to: "text, code, records, JSON",
        speed: Some(Speed::Slow),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 9,
        name: "reserved",
        applies_to: "no content",
        speed: None,
        state: CodecState::Reserved,
    },
    CodecEntry {
        id: 10,
        name: "derivation",
        applies_to: "a region of a base content",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 11,
        name: "version delta",
        applies_to: "against the same owner's previous content",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 12,
        name: "LZ and context",
        applies_to: "general content, corpus dictionary",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 13,
        name: "context machine",
        applies_to: "general content, context state",
        speed: Some(Speed::Slow),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 14,
        name: "log field columnar and zstd",
        applies_to: "known log formats: nginx access, syslog",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 15,
        name: "time series: time delta, value xor and zstd",
        applies_to: "(time, value) record arrays, telemetry",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 16,
        name: "append-only log columnar and zstd",
        applies_to: "WAL, ledger, append-mode record streams",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 17,
        name: "pcap field columnar and zstd",
        applies_to: "libpcap capture files",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 18,
        name: "page xor delta and zstd",
        applies_to: "page-structured database files, SQLite",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 19,
        name: "float exponent split: exponent stream Huffman, sign and mantissa zstd",
        applies_to: "BF16 and FP32 model weights",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 20,
        name: "executable section split and zstd",
        applies_to: "PE and ELF",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 21,
        name: "pdf stream split: text LZMA2, streams raw",
        applies_to: "PDF",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 22,
        name: "markdown section stream and zstd",
        applies_to: "markdown and structured text",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 23,
        name: "genome: reference delta, two-bit base code and zstd",
        applies_to: "FASTA and FASTQ",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 24,
        name: "office opc repack and zstd",
        applies_to: "DOCX, XLSX, PPTX",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 25,
        name: "point cloud: grid, full residual and zstd",
        applies_to: "point clouds, lossless mode only",
        speed: Some(Speed::Medium),
        state: CodecState::Closed,
    },
    CodecEntry {
        id: 26,
        name: "lossless image and header",
        applies_to: "images carrying raw pixels: BMP, TIFF",
        speed: Some(Speed::Slow),
        state: CodecState::Closed,
    },
];

/// The largest registered id.
pub const MAX_ID: CodecId = 26;

/// The reserved id. Never valid.
pub const RESERVED_ID: CodecId = 9;

/// Whether `id` is registered and not reserved. Id 9 is reserved and never
/// valid; ids above the register are not registered at all.
#[must_use]
pub const fn is_registered(id: CodecId) -> bool {
    id <= MAX_ID && id != RESERVED_ID
}

/// The row for `id`, if the id is in the register.
#[must_use]
pub fn entry(id: CodecId) -> Option<&'static CodecEntry> {
    REGISTER.iter().find(|row| row.id == id)
}

/// The state of `id`, or [`None`] when the id is not in the register.
#[must_use]
pub fn state_of(id: CodecId) -> Option<CodecState> {
    entry(id).map(|row| row.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_open;

    #[test]
    fn every_id_is_registered_exactly_once() {
        assert_eq!(REGISTER.len(), 27);
        for (index, row) in REGISTER.iter().enumerate() {
            assert_eq!(row.id, index as u16, "row {index} carries another id");
            assert!(!row.name.is_empty());
            assert!(!row.applies_to.is_empty());
        }
    }

    #[test]
    fn names_and_ids_are_unique() {
        for (i, a) in REGISTER.iter().enumerate() {
            for b in REGISTER.iter().skip(i + 1) {
                assert_ne!(a.id, b.id);
                assert_ne!(a.name, b.name);
            }
        }
    }

    #[test]
    fn the_reserved_id_is_never_valid() {
        assert_eq!(state_of(RESERVED_ID), Some(CodecState::Reserved));
        assert!(!is_registered(RESERVED_ID));
        assert!(!is_open(RESERVED_ID));
    }

    #[test]
    fn the_register_matches_the_helper_functions() {
        for id in 0..=MAX_ID {
            let row = entry(id).expect("every id up to the maximum has a row");
            assert_eq!(is_registered(id), row.state != CodecState::Reserved);
            assert_eq!(is_open(id), row.state == CodecState::Open, "id {id}");
        }
        assert!(entry(MAX_ID + 1).is_none());
        assert!(!is_registered(MAX_ID + 1));
    }

    #[test]
    fn every_open_codec_has_a_decoder() {
        for row in REGISTER.iter().filter(|row| row.state == CodecState::Open) {
            assert!(is_open(row.id), "{} is open without a decoder", row.name);
            assert!(row.speed.is_some());
        }
    }
}
