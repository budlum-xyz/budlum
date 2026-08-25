//! Agresif oranlama - her format icin boru hatti, en buyuk oran secimi
//! No number without a measurement - the ratio table comes from
//! corpus/format.json plus our own measurement

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FormatClass {
    Json,
    Csv,
    Text,
    Log,
    Wav,
    Parquet,
    Genomic,
    Xlsx,
    Mp3,
    Mp4,
    Jpeg,
    Png,
    Zip,
    Epub,
    Pptx,
    Pdf,
    Docx,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Pipe {
    pub name: &'static str,
    pub steps: &'static [&'static str], // kabuk soy, CDC16K, delta, zstd dict, xz9 vb
}

#[derive(Debug, Clone)]
pub struct RatioResult {
    pub format: FormatClass,
    pub pipe: Pipe,
    pub ratio: f64, // logical/physical
    pub passes_kf: bool,
}

// The best pipelines, measured (in the manner of model/measure-format.py).
pub const BEST_PIPES: &[(&str, FormatClass, f64)] = &[
    ("CDC16K+zstd+XZ9", FormatClass::Json, 17.191),
    ("duz akis+CDC16K+en iyi", FormatClass::Csv, 15.512),
    ("CDC16K+en iyi", FormatClass::Text, 13.429),
    ("mid/side+delta2+xz9", FormatClass::Wav, 10.936),
    ("CDC16K+en iyi", FormatClass::Parquet, 6.135),
    ("gunzip+2bit+CDC16K", FormatClass::Genomic, 5.781),
    ("zip-ac+CDC16K", FormatClass::Xlsx, 5.236),
    ("CDC16K+en iyi", FormatClass::Mp3, 4.940),
    ("AV1 same res (fidelity)", FormatClass::Mp4, 2.8), // a literature estimate, not measured
    ("JPEG XL lossless", FormatClass::Jpeg, 1.2),
    ("WebP lossless", FormatClass::Png, 1.8),
    ("zip-ac+CDC16K", FormatClass::Zip, 2.605),
];

impl RatioResult {
    pub fn from_best(format: FormatClass) -> Option<Self> {
        for (pipe_name, fmt, ratio) in BEST_PIPES {
            if *fmt == format {
                let passes = *ratio >= 16.68; // plain 7+1 (consistent with price.rs; the KF threshold)
                return Some(RatioResult {
                    format,
                    pipe: Pipe {
                        name: pipe_name,
                        steps: &[],
                    },
                    ratio: *ratio,
                    passes_kf: passes,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_best_passes_old() {
        let r = RatioResult::from_best(FormatClass::Json).unwrap();
        assert!(r.ratio > 16.0);
    }
    #[test]
    fn media_fails_kf_without_social() {
        let r = RatioResult::from_best(FormatClass::Jpeg).unwrap();
        assert!(r.ratio < 5.0);
    }
}
