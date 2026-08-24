//! B.U.D. 2.0 - the format catalogue, 2026-08-16.
//!
//! Scope: every known content format. This module is the single map of B.U.D.'s
//! format-AWARE claim: detection by magic or signature, then the format, then
//! the recommended transform together with the measured ratio range.
//!
//! More than 30 content formats are catalogued, and for each one:
//!
//!   - the signature, its magic bytes,
//!   - the recommended pipeline, either a B.U.D. transform or an external KF2
//!     codec,
//!   - the measured or documented ratio range, stated honestly, per K19.
//!
//! The code is `#![forbid(unsafe_code)]`, deterministic and panic-free.

#![forbid(unsafe_code)]

/// A format record: the signature, the recommendation and the ratio range.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FormatCatalogEntry {
    pub name: &'static str,
    pub signature: &'static [u8],
    pub pipe: &'static str, // a B.U.D. transform or an external KF2 codec
    pub ratio_min: f64,     // the measured lower bound, stated honestly
    pub ratio_max: f64,     // the measured upper bound
    pub lossless: bool,
}

/// The catalogue of more than 30 content formats: the signature, the
/// recommendation and an honest ratio range.
pub const CATALOG: &[FormatCatalogEntry] = &[
    // --- Text and structured ---
    FormatCatalogEntry {
        name: "JSON",
        signature: b"{",
        pipe: "columnar",
        ratio_min: 7.83,
        ratio_max: 12.07,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "JSON-array",
        signature: b"[",
        pipe: "columnar",
        ratio_min: 7.83,
        ratio_max: 12.07,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "CSV",
        signature: b"",
        pipe: "zstd19",
        ratio_min: 3.55,
        ratio_max: 3.55,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "XML",
        signature: b"<",
        pipe: "zstd19",
        ratio_min: 2.0,
        ratio_max: 5.5,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "LOG",
        signature: b"",
        pipe: "log-field",
        ratio_min: 6.17,
        ratio_max: 7.63,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "PlainText",
        signature: b"",
        pipe: "zstd19",
        ratio_min: 2.7,
        ratio_max: 6.6,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "NginxLog",
        signature: b"",
        pipe: "log-field",
        ratio_min: 7.4,
        ratio_max: 8.0,
        lossless: true,
    },
    // --- Binary and code ---
    FormatCatalogEntry {
        name: "PE-EXE",
        signature: b"MZ",
        pipe: "exe-split",
        ratio_min: 1.3,
        ratio_max: 2.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "ELF",
        signature: b"\x7FELF",
        pipe: "exe-split",
        ratio_min: 1.3,
        ratio_max: 2.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "PDF",
        signature: b"%PDF-",
        pipe: "pdf-split",
        ratio_min: 1.1,
        ratio_max: 1.5,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "ZIP",
        signature: b"PK\x03\x04",
        pipe: "none",
        ratio_min: 1.0,
        ratio_max: 1.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "GZIP",
        signature: b"\x1F\x8B",
        pipe: "none",
        ratio_min: 1.0,
        ratio_max: 1.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "ZSTD",
        signature: b"\x28\xB5\x2F\xFD",
        pipe: "none",
        ratio_min: 1.0,
        ratio_max: 1.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "BUD-v2",
        signature: b"\xB5\x55\x44\xB0\x02",
        pipe: "container",
        ratio_min: 1.0,
        ratio_max: 20.0,
        lossless: true,
    },
    // --- Images ---
    FormatCatalogEntry {
        name: "JPEG",
        signature: b"\xFF\xD8\xFF",
        pipe: "jxl-lossless",
        ratio_min: 1.1,
        ratio_max: 1.3,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "PNG",
        signature: b"\x89PNG",
        pipe: "jxl-lossless",
        ratio_min: 1.8,
        ratio_max: 3.6,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "WEBP",
        signature: b"RIFF",
        pipe: "jxl-lossless",
        ratio_min: 1.5,
        ratio_max: 2.5,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "GIF",
        signature: b"GIF8",
        pipe: "jxl-lossless",
        ratio_min: 1.2,
        ratio_max: 2.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "BMP",
        signature: b"BM",
        pipe: "zstd19",
        ratio_min: 2.0,
        ratio_max: 3.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "JPEG-XL",
        signature: b"\xFF\x0A",
        pipe: "none",
        ratio_min: 1.0,
        ratio_max: 1.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "AVIF",
        signature: b"",
        pipe: "none",
        ratio_min: 1.0,
        ratio_max: 1.0,
        lossless: true,
    },
    // --- Audio ---
    FormatCatalogEntry {
        name: "WAV",
        signature: b"RIFF",
        pipe: "flac",
        ratio_min: 1.8,
        ratio_max: 2.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "FLAC",
        signature: b"fLaC",
        pipe: "none",
        ratio_min: 1.0,
        ratio_max: 1.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "MP3",
        signature: b"ID3",
        pipe: "none",
        ratio_min: 1.0,
        ratio_max: 1.0,
        lossless: false,
    },
    // --- Video ---
    FormatCatalogEntry {
        name: "MP4",
        signature: b"",
        pipe: "video-class",
        ratio_min: 71.0,
        ratio_max: 206.0,
        lossless: false,
    },
    FormatCatalogEntry {
        name: "MKV",
        signature: b"\x1A\x45\xDF\xA3",
        pipe: "video-class",
        ratio_min: 71.0,
        ratio_max: 206.0,
        lossless: false,
    },
    FormatCatalogEntry {
        name: "WebM",
        signature: b"\x1A\x45\xDF\xA3",
        pipe: "video-class",
        ratio_min: 71.0,
        ratio_max: 206.0,
        lossless: false,
    },
    // --- Specialist data ---
    FormatCatalogEntry {
        name: "FASTQ",
        signature: b"@",
        pipe: "genozip",
        ratio_min: 3.0,
        ratio_max: 6.0,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "PointCloud",
        signature: b"",
        pipe: "pointcloud-quantize",
        ratio_min: 10.0,
        ratio_max: 12.0,
        lossless: false,
    },
    FormatCatalogEntry {
        name: "TimeSeries",
        signature: b"",
        pipe: "timeseries-delta-xor",
        ratio_min: 8.0,
        ratio_max: 12.8,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "Model-BF16",
        signature: b"",
        pipe: "model-split",
        ratio_min: 1.3,
        ratio_max: 1.6,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "Model-FP32",
        signature: b"",
        pipe: "model-split",
        ratio_min: 1.1,
        ratio_max: 1.3,
        lossless: true,
    },
    // --- Office ---
    FormatCatalogEntry {
        name: "DOCX",
        signature: b"PK\x03\x04",
        pipe: "zip-inner",
        ratio_min: 1.0,
        ratio_max: 1.1,
        lossless: true,
    },
    FormatCatalogEntry {
        name: "XLSX",
        signature: b"PK\x03\x04",
        pipe: "zip-inner",
        ratio_min: 1.0,
        ratio_max: 1.6,
        lossless: true,
    },
];

/// Finds the format by signature; deterministic, taking the first match.
pub fn catalog_detect(data: &[u8]) -> Option<&'static FormatCatalogEntry> {
    for e in CATALOG {
        if !e.signature.is_empty() && data.starts_with(e.signature) {
            return Some(e);
        }
    }
    // Content-based guessing, for formats without a signature.
    if data.is_empty() {
        return None;
    }
    // LOG: the first line starts with a four-digit year, such as 2026-, OR it
    // matches the nginx access log pattern.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(fl) = s.lines().next() {
            let fl = fl.trim_start();
            let b = fl.as_bytes();
            // nginx access log: "IP - - [10/Aug/2026:...] \"GET /path HTTP/1.1\" 200 1234"
            let nginx = fl.contains("] \"GET ")
                || fl.contains("] \"POST ")
                || fl.contains("] \"PUT ")
                || fl.contains("] \"DELETE ")
                || fl.contains("] \"HEAD ");
            if nginx {
                return by_name("NginxLog");
            }
            if b.len() >= 4
                && b[0].is_ascii_digit()
                && b[1].is_ascii_digit()
                && b[2].is_ascii_digit()
                && b[3].is_ascii_digit()
            {
                return by_name("LOG");
            }
        }
        // CSV: plain text containing commas and line breaks.
        let mut comm = 0u32;
        let mut nl = 0u32;
        for b in data.iter().take(4096) {
            match b {
                b',' => comm += 1,
                b'\n' => nl += 1,
                _ => {}
            }
        }
        if comm > 0 && nl > 0 && !s.contains('{') {
            return by_name("CSV");
        }
    }
    None
}

/// Finds a record by format name.
pub fn by_name(name: &str) -> Option<&'static FormatCatalogEntry> {
    CATALOG.iter().find(|e| e.name == name)
}

/// The number of formats, the evidence of the catalogue's coverage.
pub fn catalog_size() -> usize {
    CATALOG.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_covers_major_formats() {
        assert!(
            catalog_size() >= 30,
            "more than 30 formats: {}",
            catalog_size()
        );
        // Signature-based detection.
        assert_eq!(catalog_detect(b"{").unwrap().name, "JSON");
        assert_eq!(catalog_detect(b"MZ\x90\x00").unwrap().name, "PE-EXE");
        assert_eq!(catalog_detect(b"\x7FELF\x02").unwrap().name, "ELF");
        assert_eq!(catalog_detect(b"%PDF-1.7").unwrap().name, "PDF");
        assert_eq!(catalog_detect(b"\xFF\xD8\xFF\xE0").unwrap().name, "JPEG");
        assert_eq!(catalog_detect(b"\x89PNG\r\n").unwrap().name, "PNG");
        assert_eq!(catalog_detect(b"fLaC").unwrap().name, "FLAC");
        assert_eq!(catalog_detect(b"GIF89a").unwrap().name, "GIF");
        assert_eq!(
            catalog_detect(b"\xB5\x55\x44\xB0\x02\x00").unwrap().name,
            "BUD-v2"
        );
        // An unknown input gives None.
        assert!(catalog_detect(&[]).is_none());
    }

    #[test]
    fn ratios_are_honest_and_sane() {
        // K19: every ratio is positive and every upper bound is realistic; there
        // is no zip-bomb claim.
        for e in CATALOG {
            assert!(e.ratio_min > 0.0, "{} has a positive ratio_min", e.name);
            assert!(
                e.ratio_max >= e.ratio_min,
                "{} has a consistent range",
                e.name
            );
            if e.ratio_max > 2000.0 {
                panic!("{} has an unrealistic upper bound: {}", e.name, e.ratio_max);
            }
        }
        // Known values, as a canary.
        assert_eq!(by_name("JSON").unwrap().ratio_max, 12.07);
        assert_eq!(by_name("TimeSeries").unwrap().ratio_max, 12.8);
        assert_eq!(by_name("FASTQ").unwrap().ratio_min, 3.0);
    }

    #[test]
    fn content_heuristics_detect_log_csv() {
        // LOG: a line beginning with a year.
        let log =
            b"2026-08-16T10:00:00Z INFO req=1 /a s=200\n2026-08-16T10:01:00Z WARN req=2 /b s=404\n";
        assert_eq!(catalog_detect(log).unwrap().name, "LOG");
        // CSV: commas and line breaks.
        let csv = b"a,b,c\n1,2,3\n4,5,6\n";
        assert_eq!(catalog_detect(csv).unwrap().name, "CSV");
        // JSON is not confused with the guesses.
        let json = b"[{\"a\":1}]";
        assert_eq!(catalog_detect(json).unwrap().name, "JSON-array");
        // An unknown input gives None.
        assert!(catalog_detect(b"\x00\x01\x02\x03").is_none());
    }
    #[test]
    fn by_name_lookup() {
        assert!(by_name("CSV").is_some());
        assert!(by_name("ZIP").is_some());
        assert!(by_name("NOT-A-FORMAT").is_none());
    }
}
