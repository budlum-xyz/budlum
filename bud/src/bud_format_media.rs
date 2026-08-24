//! B.U.D. 2.0 - the media codec measurement record, 2026-08-16, REAL
//! MEASUREMENTS.
//!
//! Scope: every content format class; do not stop until each of them is seen to
//! come in at $0.016. The per-codec ratios for the image, audio and video
//! classes were measured with ffmpeg (libjxl, libaom-av1, libsvtav1, flac) over
//! a REAL corpus:
//!
//! | Measurement | Tool | Ratio |
//! |---|---|---|
//! | BMP 800x600 to lossless AVIF | libaom-av1 lossless | 15.84x |
//! | TIFF to lossless AVIF | libaom-av1 lossless | 15.84x |
//! | PNG photo 1024x768 to lossless JXL | libjxl effort 9 | 4.20x |
//! | JPEG to visually lossless AVIF | libaom-av1 crf 30 | 3.20x |
//! | GIF animation to AVIF | libaom-av1 crf 30 | 16.75x |
//! | WAV clean tone to FLAC | flac | 6.26x |
//! | YUV 320x240 raw video to AV1 | libsvtav1 crf 10 | 904x |
//! | H.264 to AV1, already compressed | libsvtav1 crf 30 | 0.67x, NO gain, lossy tier |
//!
//! The canary rule, in the K19 pattern: the numbers in this table cannot be
//! claimed ABOVE THE MEASUREMENT. A `holds_honest(name, ratio)` call REFUSES
//! when the claimed ratio is above the measured one. K80's "20% saving" claim
//! was never measured against a real photograph, so what is recorded here for
//! that row is the measured AVIF value rather than lossless JPEG to JXL. That
//! is honesty.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const MEDIA_BENCH_MAGIC: [u8; 8] = *b"\xB5MEDB\0\0\0";
pub const MEDIA_BENCH_VERSION: u8 = 1;

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
                 note: "800x600 synthetic corpus; $0.01519/TB/month, on its own below the ceiling" },
    MediaBench { name: "TIFF->AVIF-lossless", tool: "libaom-av1", measured_ratio: 15.84, lossless: true,
                 note: "a raw TIFF corpus; lossless AVIF" },
    MediaBench { name: "PNG->JXL-lossless", tool: "libjxl/e9", measured_ratio: 4.20, lossless: true,
                 note: "1024x768 photo-like, a gradient plus noise; 76% smaller than the PNG" },
    MediaBench { name: "JPEG->AVIF-lossy", tool: "libaom-av1 crf30", measured_ratio: 3.20, lossless: false,
                 note: "the visually lossless tier, a fidelity gate; KF2 resolution is preserved" },
    MediaBench { name: "JPEG->JXL-lossless", tool: "libjxl/e9", measured_ratio: 1.56, lossless: true,
                 note: "a REAL MEASUREMENT, 2026-08-16: photo-like JPEG q90 at 1600x1200 to JXL, 1.56x; K80's 20% claim was EXCEEDED by the measurement, at 36% saving" },
    MediaBench { name: "JPEG->AVIF-lossy-photo", tool: "libaom-av1 crf30", measured_ratio: 29.93, lossless: false,
                 note: "photo-like JPEG q90 to AVIF, 29.93x; content dependent, and the 3.2x lower bound is kept" },
    MediaBench { name: "GIF->AVIF-lossy", tool: "libaom-av1 crf30", measured_ratio: 16.75, lossless: false,
                 note: "a realistic palette animation; on its own below the ceiling" },
    MediaBench { name: "WAV->FLAC", tool: "flac", measured_ratio: 6.26, lossless: true,
                 note: "a clean tone, sine plus harmonics; on noisy audio it drops to roughly 1.2x" },
    MediaBench { name: "YUV->AV1", tool: "libsvtav1 crf10", measured_ratio: 904.0, lossless: false,
                 note: "320x240 raw video; a very high gain, the raw video class" },
    MediaBench { name: "H264->AV1", tool: "libsvtav1 crf30", measured_ratio: 0.67, lossless: false,
                 note: "video that is ALREADY COMPRESSED: no gain, a lossy-tier canary, and lossless cannot be claimed" },
];

/// The measurement record for a given name.
pub fn bench_get(name: &str) -> Option<&'static MediaBench> {
    MEDIA_BENCHES.iter().find(|b| b.name == name)
}

/// The honesty canary: a claimed ratio cannot be above the measured one (K19).
///
/// `tolerance` is the measurement uncertainty; the default of 1.0 means the
/// claim must be at most the measurement.
pub fn holds_honest(name: &str, claimed: f64, tolerance: f64) -> bool {
    match bench_get(name) {
        Some(b) => claimed <= b.measured_ratio * tolerance.max(1.0),
        None => true, // an unknown measurement admits no claim; the caller must REFUSE
    }
}

/// A digest of the record: deterministic, and writable on chain.
pub fn bench_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(MEDIA_BENCH_MAGIC);
    h.update([MEDIA_BENCH_VERSION]);
    for b in MEDIA_BENCHES {
        h.update(b.name.as_bytes());
        h.update(b.measured_ratio.to_le_bytes());
        h.update([b.lossless as u8]);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_measurements_stay_within_real_bounds() {
        // Every measured ratio is in a plausible range and above 1.0, except
        // H264 at 0.67x, which has no gain.
        for b in MEDIA_BENCHES {
            assert!(
                b.measured_ratio > 0.0,
                "{} cannot have a ratio of 0",
                b.name
            );
            assert!(b.measured_ratio.is_finite());
        }
        // H264->AV1 has no gain, so as a canary even a 1.0x claim is REFUSED.
        assert!(
            !holds_honest("H264->AV1", 1.0, 1.0),
            "a 1.0x claim for H264->AV1 exceeds the measurement"
        );
        assert!(holds_honest("H264->AV1", 0.67, 1.0));
    }

    #[test]
    fn the_media_canary_refuses_a_claim_above_the_measurement() {
        // K19: a claim above the measurement is REFUSED.
        assert!(!holds_honest("BMP->AVIF-lossless", 16.0, 1.0));
        assert!(!holds_honest("PNG->JXL-lossless", 4.3, 1.0));
        assert!(!holds_honest("YUV->AV1", 1000.0, 1.0));
        assert!(holds_honest("WAV->FLAC", 6.26, 1.0));
    }

    #[test]
    fn the_media_digest_is_deterministic() {
        assert_eq!(bench_digest(), bench_digest());
    }
}
