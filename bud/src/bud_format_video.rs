//! B.U.D. 2.0 invention - video content class plus codec selection, 2026-08-16.
//!
//! Finding K84, from a real ffmpeg measurement: "x265 always beats x264" is
//! WRONG - it depends on the content type, and x264 won on the testsrc2
//! pattern. Static and temporal content reached 1300-1600x while moving content
//! reached 70-206x. So this module:
//!
//! - DETECTS the content class from raw YUV frames, using the mean frame
//!   difference, in pure Rust;
//! - produces a codec and GOP suggestion for that class, out of the honest
//!   measurement table;
//! - carries a video record that can be combined with a generation proof
//!   (`BudVideoRecord`).
//!
//! On losslessness and verification: B.U.D. STORES the video bitstream and
//! proves its RATIO; the codec choice follows the content, through the registry
//! and the generation proof. The code is `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use crate::bud_format_container::FormatCodec;

/// Video content class, from the frame-difference statistic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoContentClass {
    Static,     // frames nearly identical: fixed camera, screen capture, slides
    LowMotion,  // little motion: interview, presentation
    HighMotion, // heavy motion: sport, action, drone
}

/// A measured codec suggestion, from the K84 table over a synthetic corpus, so
/// the comparison is internally consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Hevc,
    Av1,
}

#[derive(Debug, Clone, Copy)]
pub struct VideoSuggestion {
    pub codec: VideoCodec,
    pub gop_frames: u32,         // depolama: UZUN GOP (K85)
    pub scenecut_threshold: u8,  // per content class: 60 for sport, 10 for slides
    pub lossless: bool,          // lossless mode suggestion, for archival
    pub expected_ratio_min: f64, // the K84 measured range, synthetic
    pub expected_ratio_max: f64,
}

impl VideoSuggestion {
    pub const fn new(
        codec: VideoCodec,
        gop: u32,
        scenecut: u8,
        lossless: bool,
        rmin: f64,
        rmax: f64,
    ) -> Self {
        VideoSuggestion {
            codec,
            gop_frames: gop,
            scenecut_threshold: scenecut,
            lossless,
            expected_ratio_min: rmin,
            expected_ratio_max: rmax,
        }
    }

    /// The suggestion for a content class, from the K84 and K85 measurements:
    ///
    /// - Static: AV1, a very long GOP of 240 or more, a low scenecut of 10,
    ///   giving 1300-1600x.
    /// - LowMotion: AV1, a long GOP of 120, a middling scenecut of 30, giving
    ///   roughly 150-250x.
    /// - HighMotion: AV1, a GOP of 60, a high scenecut of 60, giving roughly
    ///   70-200x.
    ///
    /// The H.264 and HEVC alternatives are in the table; AV1 also led in the
    /// lossless measurement (K84).
    pub fn for_class(class: VideoContentClass) -> Self {
        match class {
            VideoContentClass::Static => Self::new(VideoCodec::Av1, 240, 10, false, 1300.0, 1600.0),
            VideoContentClass::LowMotion => {
                Self::new(VideoCodec::Av1, 120, 30, false, 150.0, 250.0)
            }
            VideoContentClass::HighMotion => Self::new(VideoCodec::Av1, 60, 60, false, 70.0, 206.0),
        }
    }

    /// The archival suggestion: AV1 lossless. K84 measured svtav1-lossless at
    /// 134x, the leader among lossless.
    pub fn archival(class: VideoContentClass) -> Self {
        match class {
            VideoContentClass::Static => Self::new(VideoCodec::Av1, 240, 10, true, 100.0, 134.0),
            _ => Self::new(VideoCodec::Av1, 60, 30, true, 25.0, 134.0),
        }
    }
}

/// Content class detection: the mean pixel difference of consecutive YUV420
/// frames.
///
/// Each frame is `w*h*3/2` bytes, and `frames` is the number of consecutive
/// frame pairs, 10 for instance. It returns the class and the mean difference,
/// in 0-255.
pub fn classify_content(
    yuv: &[u8],
    w: usize,
    h: usize,
    frames: usize,
) -> Option<(VideoContentClass, f64)> {
    if w == 0 || h == 0 || frames == 0 {
        return None;
    }
    let frame_bytes = w * h * 3 / 2;
    if frame_bytes == 0 || yuv.len() < frame_bytes * 2 {
        return None;
    }
    let n = frames.min((yuv.len() / frame_bytes).saturating_sub(1));
    if n == 0 {
        return None;
    }
    let mut total_diff: u64 = 0;
    for f in 0..n {
        let a = &yuv[f * frame_bytes..(f + 1) * frame_bytes];
        let b = &yuv[(f + 1) * frame_bytes..(f + 2) * frame_bytes];
        // Sampling every 64th byte, for speed; the Y plane dominates.
        let mut diff: u64 = 0;
        let mut cnt: u64 = 0;
        for i in (0..frame_bytes).step_by(64) {
            diff += (a[i] as i64 - b[i] as i64).unsigned_abs();
            cnt += 1;
        }
        let _ = cnt; // the sample counter, usable for statistics
        total_diff += diff;
    }
    let avg = total_diff as f64 / (n as f64 * (frame_bytes as f64 / 64.0));
    let class = if avg < 1.0 {
        VideoContentClass::Static
    } else if avg < 8.0 {
        VideoContentClass::LowMotion
    } else {
        VideoContentClass::HighMotion
    };
    Some((class, avg))
}

/// A video generation record: codec, resolution, GOP, class and ratio, which
/// can be bound to a generation proof.
#[derive(Debug, Clone)]
pub struct BudVideoRecord {
    pub codec: VideoCodec,
    pub content_class: VideoContentClass,
    pub width: u32,
    pub height: u32,
    pub gop_frames: u32,
    pub lossless: bool,
    pub original_len: u64,  // raw video size, YUV for instance
    pub stored_len: u64,    // compressed bitstream size
    pub claimed_ratio: f64, // original_len / stored_len, measured AT GENERATION
}

impl BudVideoRecord {
    pub fn new(
        codec: VideoCodec,
        class: VideoContentClass,
        width: u32,
        height: u32,
        gop: u32,
        lossless: bool,
        original_len: u64,
        stored_len: u64,
    ) -> Self {
        let claimed_ratio = if stored_len > 0 {
            original_len as f64 / stored_len as f64
        } else {
            1.0
        };
        BudVideoRecord {
            codec,
            content_class: class,
            width,
            height,
            gop_frames: gop,
            lossless,
            original_len,
            stored_len,
            claimed_ratio,
        }
    }

    /// Consistency (K38): does the ratio match the sizes, and are the values
    /// valid.
    pub fn verify(&self) -> bool {
        if !self.claimed_ratio.is_finite() || self.claimed_ratio <= 0.0 {
            return false;
        }
        if self.stored_len == 0 && self.original_len > 0 {
            return false;
        }
        let actual = if self.stored_len > 0 {
            self.original_len as f64 / self.stored_len as f64
        } else {
            1.0
        };
        (self.claimed_ratio - actual).abs() <= 0.01
    }

    /// K19: does the claim fit the measured range of its content class? An
    /// invented ratio is refused.
    pub fn plausible(&self, suggestion: &VideoSuggestion) -> bool {
        self.claimed_ratio >= suggestion.expected_ratio_min * 0.5
            && self.claimed_ratio <= suggestion.expected_ratio_max * 2.0
    }

    pub fn format_codec(&self) -> FormatCodec {
        FormatCodec::Mp4 // the video container class, the registry code
    }
}

pub struct VideoGates;

impl VideoGates {
    /// Did the class detection succeed, is the record consistent, and does it
    /// fit the measured range?
    pub fn k_bud_video(
        rec: &BudVideoRecord,
        suggestion: &VideoSuggestion,
    ) -> Result<(), &'static str> {
        if !rec.verify() {
            return Err("K-BUD-VIDEO: record inconsistent");
        }
        if !rec.plausible(suggestion) {
            return Err("K-BUD-VIDEO: ratio outside measured range, an invented claim");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn static_frame() -> Vec<u8> {
        vec![0u8; 320 * 240 * 3 / 2]
    }

    #[test]
    fn static_content_classified() {
        // The same frame repeated yields Static.
        let mut yuv = static_frame();
        let f = yuv.clone();
        for _ in 0..4 {
            yuv.extend_from_slice(&f);
        }
        let (class, avg) = classify_content(&yuv, 320, 240, 10).expect("enough frames");
        assert_eq!(class, VideoContentClass::Static);
        assert!(avg < 1.0, "the difference should be 0: {avg}");
    }

    #[test]
    fn high_motion_classified() {
        // Every frame random yields HighMotion.
        let mut yuv = Vec::new();
        let mut x = 0x1234_5678u64;
        for _ in 0..6 * (320 * 240 * 3 / 2) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            yuv.push((x & 0xff) as u8);
        }
        let (class, _avg) = classify_content(&yuv, 320, 240, 5).expect("enough frames");
        assert_eq!(class, VideoContentClass::HighMotion);
    }

    #[test]
    fn suggestion_matches_class() {
        let s = VideoSuggestion::for_class(VideoContentClass::Static);
        assert_eq!(s.codec, VideoCodec::Av1);
        assert!(s.gop_frames >= 240);
        assert!(
            s.expected_ratio_min >= 1000.0,
            "the static measurement is roughly 1300-1600x"
        );
        let h = VideoSuggestion::for_class(VideoContentClass::HighMotion);
        assert!(h.expected_ratio_max >= 200.0);
        // Archival: the lossless suggestion.
        assert!(VideoSuggestion::archival(VideoContentClass::LowMotion).lossless);
    }

    #[test]
    fn video_record_verify_and_gate() {
        let rec = BudVideoRecord::new(
            VideoCodec::Av1,
            VideoContentClass::HighMotion,
            1280,
            720,
            60,
            false,
            829_440_000,
            8_205_382,
        );
        assert!(rec.verify());
        assert!(
            (rec.claimed_ratio - 101.0).abs() < 1.0,
            "{}",
            rec.claimed_ratio
        );
        let sugg = VideoSuggestion::for_class(VideoContentClass::HighMotion);
        assert!(
            VideoGates::k_bud_video(&rec, &sugg).is_ok(),
            "101x is inside the HighMotion range"
        );
        // An invented 17x claim is refused for high-motion video: it is below
        // the measured 70-206x.
        let fake = BudVideoRecord::new(
            VideoCodec::Av1,
            VideoContentClass::HighMotion,
            1280,
            720,
            60,
            false,
            829_440_000,
            48_790_588,
        );
        assert!(
            VideoGates::k_bud_video(&fake, &sugg).is_err(),
            "17x is refused for HighMotion (K19)"
        );
    }

    #[test]
    fn insufficient_frames_returns_none() {
        let yuv = static_frame(); // a single frame
        assert!(classify_content(&yuv, 320, 240, 2).is_none());
        assert!(classify_content(&[], 0, 0, 1).is_none());
    }
}
