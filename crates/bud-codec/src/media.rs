//! B.U.D. 2.0 - THE MEDIA MEASUREMENT BENCH
//!
//! Measured ratios of the real media codecs. Only the lossless conversions
//! are recorded here: the lossy image and video tiers are not part of this
//! layer and their rows are gone with the removal. The row is evidence for
//! the codec registry; re-measure before wiring.
//!
//! Code: `#![forbid(unsafe_code)]`, deterministic, with tests.
//! Convenience: public B.U.D. 3.0 codec and storage surface consumed by gateway, CLI, and fuzz harnesses.

#![forbid(unsafe_code)]

/// A measured media codec conversion.
#[derive(Debug, Clone, Copy)]
pub struct MediaBench {
    pub name: &'static str,  // "BMP->AVIF-lossless"
    pub tool: &'static str,  // the measuring tool
    pub measured_ratio: f64, // the REAL measurement; claiming above it is forbidden
    pub lossless: bool,
    pub note: &'static str,
}

pub const MEDIA_BENCHES: &[MediaBench] = &[
    MediaBench { name: "BMP->AVIF-lossless", tool: "libaom-av1", measured_ratio: 15.84, lossless: true,
                 note: "800x600 synthetic corpus" },
    MediaBench { name: "TIFF->AVIF-lossless", tool: "libaom-av1", measured_ratio: 15.84, lossless: true,
                 note: "a raw TIFF corpus; lossless AVIF" },
    MediaBench { name: "PNG->JXL-lossless", tool: "libjxl/e9", measured_ratio: 4.20, lossless: true,
                 note: "1024x768 photo-like, a gradient plus noise; 76% smaller than the PNG" },
    MediaBench { name: "JPEG->JXL-lossless", tool: "libjxl/e9", measured_ratio: 1.56, lossless: true,
                 note: "a REAL MEASUREMENT, 2026-08-16: photo-like JPEG q90 at 1600x1200 to JXL, 1.56x; K80's 20% claim was EXCEEDED by the measurement, at 36% saving" },
    MediaBench { name: "WAV->FLAC", tool: "flac", measured_ratio: 6.26, lossless: true,
                 note: "a clean tone, sine plus harmonics; on noisy audio it drops to roughly 1.2x" },
];

/// The measurement record for a given name.
pub fn bench_get(name: &str) -> Option<&'static MediaBench> {
    MEDIA_BENCHES.iter().find(|b| b.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_media_bench_keeps_only_lossless_rows() {
        assert!(MEDIA_BENCHES.iter().all(|b| b.lossless));
        assert_eq!(bench_get("WAV->FLAC").unwrap().measured_ratio, 6.26);
        assert_eq!(bench_get("BMP->AVIF-lossless").unwrap().measured_ratio, 15.84);
        assert!(bench_get("JPEG->AVIF-lossy").is_none());
    }
}
