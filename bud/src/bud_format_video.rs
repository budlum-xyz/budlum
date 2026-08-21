//! B.U.D. 2.0 İcat - Video İçerik-Sınıfı + Codec Seçimi (2026-08-16)
//!
//! K84 bulgusu (GERÇEK ffmpeg ölçümü): "x265 her zaman x264'ten iyidir" YANLIŞ -
//! içerik türüne bağlı (testsrc2 deseninde x264 kazandı). Statik/temporal içerik
//! 1300-1600x oran verirken hareketli 70-206x. Bu modül:
//!   - içerik sınıfını ham YUV karelerinden TESPIT eder (ortalama kare farkı - saf Rust,
//!     ffmpeg gerektirmez),
//!   - içerik sınıfına göre codec + GOP önerisi üretir (dürüst ölçüm tablosundan),
//!   - üretim kanıtı ile birleşebilen video kaydı taşır (BudVideoRecord).
//!
//! Kayıpsızlık/doğrulama: B.U.D. video bitstream'i SAKLAR ve ORANINI kanıtlar; codec
//! seçimi içeriğe göre yapılır (registry + üretim kanıtı). Kod: `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

use crate::bud_format_container::FormatCodec;

/// Video içerik sınıfı (kare-farkı istatistiğinden).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoContentClass {
    Static,    // kareler neredeyse aynı (kamera sabit, ekran kaydı, slideshow)
    LowMotion, // az hareket (röportaj, sunum)
    HighMotion, // çok hareket (spor, aksiyon, drone)
}

/// Ölçülmüş codec önerisi (K84 tablosu, sentetik korpus - içsel tutarlı karşılaştırma).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Hevc,
    Av1,
}

#[derive(Debug, Clone, Copy)]
pub struct VideoSuggestion {
    pub codec: VideoCodec,
    pub gop_frames: u32,      // depolama: UZUN GOP (K85)
    pub scenecut_threshold: u8, // içerik sınıfına göre (spor 60, slideshow 10)
    pub lossless: bool,       // kayıpsız mod önerisi (arşiv için)
    pub expected_ratio_min: f64, // K84 ölçüm aralığı (sentetik)
    pub expected_ratio_max: f64,
}

impl VideoSuggestion {
    pub const fn new(codec: VideoCodec, gop: u32, scenecut: u8, lossless: bool, rmin: f64, rmax: f64) -> Self {
        VideoSuggestion { codec, gop_frames: gop, scenecut_threshold: scenecut, lossless, expected_ratio_min: rmin, expected_ratio_max: rmax }
    }

    /// İçerik sınıfına göre öneri (K84/K85 ölçümleri):
    /// - Static: AV1, çok uzun GOP (240+), düşük scenecut (10) → 1300-1600x
    /// - LowMotion: AV1, uzun GOP (120), orta scenecut (30) → ~150-250x
    /// - HighMotion: AV1, orta GOP (60), yüksek scenecut (60) → ~70-200x
    ///   (H.264/HEVC alternatifleri tabloda; AV1 ölçümde lossless'ta da lider - K84)
    pub fn for_class(class: VideoContentClass) -> Self {
        match class {
            VideoContentClass::Static => Self::new(VideoCodec::Av1, 240, 10, false, 1300.0, 1600.0),
            VideoContentClass::LowMotion => Self::new(VideoCodec::Av1, 120, 30, false, 150.0, 250.0),
            VideoContentClass::HighMotion => Self::new(VideoCodec::Av1, 60, 60, false, 70.0, 206.0),
        }
    }

    /// Arşiv önerisi: AV1 lossless (K84: svtav1-lossless 134x - kayıpsızda lider).
    pub fn archival(class: VideoContentClass) -> Self {
        match class {
            VideoContentClass::Static => Self::new(VideoCodec::Av1, 240, 10, true, 100.0, 134.0),
            _ => Self::new(VideoCodec::Av1, 60, 30, true, 25.0, 134.0),
        }
    }
}

/// İçerik sınıfı tespiti: ardışık karelerin ortalama piksel farkı (YUV420).
/// Her kare `w*h*3/2` bayt; `frames` = ardışık kare çifti sayısı (ör. 10).
/// Dönüş: (sınıf, ortalama fark 0-255).
pub fn classify_content(yuv: &[u8], w: usize, h: usize, frames: usize) -> Option<(VideoContentClass, f64)> {
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
        // örnekleme: her 64. bayt (hız) - Y düzlemi baskın
        let mut diff: u64 = 0;
        let mut cnt: u64 = 0;
        for i in (0..frame_bytes).step_by(64) {
            diff += (a[i] as i64 - b[i] as i64).unsigned_abs();
            cnt += 1;
        }
        let _ = cnt; // örnekleme sayacı (istatistik için kullanılabilir)
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

/// Video üretim kaydı: codec + çözünürlük + GOP + sınıf + oran → üretim kanıtına bağlanabilir.
#[derive(Debug, Clone)]
pub struct BudVideoRecord {
    pub codec: VideoCodec,
    pub content_class: VideoContentClass,
    pub width: u32,
    pub height: u32,
    pub gop_frames: u32,
    pub lossless: bool,
    pub original_len: u64,   // ham video boyutu (ör. YUV)
    pub stored_len: u64,     // sıkıştırılmış bitstream boyutu
    pub claimed_ratio: f64,  // original_len / stored_len (ÜRETİM ANINDA ölçülen)
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
        BudVideoRecord { codec, content_class: class, width, height, gop_frames: gop, lossless, original_len, stored_len, claimed_ratio }
    }

    /// Tutarlılık: oran boyutlarla eşleşiyor mu + değerler geçerli mi (K38).
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

    /// K19: iddia, içerik sınıfının ölçüm aralığına uygun mu? (uydurma oran RED)
    pub fn plausible(&self, suggestion: &VideoSuggestion) -> bool {
        self.claimed_ratio >= suggestion.expected_ratio_min * 0.5
            && self.claimed_ratio <= suggestion.expected_ratio_max * 2.0
    }

    pub fn format_codec(&self) -> FormatCodec {
        FormatCodec::Mp4 // video konteyner sınıfı (registry kodu)
    }
}

pub struct VideoGates;

impl VideoGates {
    /// İçerik sınıfı tespiti başarılı mı + kayıt tutarlı mı + ölçüm aralığına uygun mu?
    pub fn k_bud_video(rec: &BudVideoRecord, suggestion: &VideoSuggestion) -> Result<(), &'static str> {
        if !rec.verify() {
            return Err("K-BUD-VIDEO: record inconsistent");
        }
        if !rec.plausible(suggestion) {
            return Err("K-BUD-VIDEO: ratio outside measured range (uydurma iddia)");
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
        // aynı kare tekrarı → Static
        let mut yuv = static_frame();
        let f = yuv.clone();
        for _ in 0..4 {
            yuv.extend_from_slice(&f);
        }
        let (class, avg) = classify_content(&yuv, 320, 240, 10).expect("yeterli kare");
        assert_eq!(class, VideoContentClass::Static);
        assert!(avg < 1.0, "fark 0 olmalı: {avg}");
    }

    #[test]
    fn high_motion_classified() {
        // her kare rastgele → HighMotion
        let mut yuv = Vec::new();
        let mut x = 0x1234_5678u64;
        for _ in 0..6 * (320 * 240 * 3 / 2) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            yuv.push((x & 0xff) as u8);
        }
        let (class, _avg) = classify_content(&yuv, 320, 240, 5).expect("yeterli");
        assert_eq!(class, VideoContentClass::HighMotion);
    }

    #[test]
    fn suggestion_matches_class() {
        let s = VideoSuggestion::for_class(VideoContentClass::Static);
        assert_eq!(s.codec, VideoCodec::Av1);
        assert!(s.gop_frames >= 240);
        assert!(s.expected_ratio_min >= 1000.0, "statik ölçüm ~1300-1600x");
        let h = VideoSuggestion::for_class(VideoContentClass::HighMotion);
        assert!(h.expected_ratio_max >= 200.0);
        // arşiv: lossless önerisi
        assert!(VideoSuggestion::archival(VideoContentClass::LowMotion).lossless);
    }

    #[test]
    fn video_record_verify_and_gate() {
        let rec = BudVideoRecord::new(VideoCodec::Av1, VideoContentClass::HighMotion, 1280, 720, 60, false, 829_440_000, 8_205_382);
        assert!(rec.verify());
        assert!((rec.claimed_ratio - 101.0).abs() < 1.0, "{}", rec.claimed_ratio);
        let sugg = VideoSuggestion::for_class(VideoContentClass::HighMotion);
        assert!(VideoGates::k_bud_video(&rec, &sugg).is_ok(), "101x HighMotion aralığında");
        // uydurma 17x iddiası yüksek hareketli video için RED (ölçüm 70-206x altı)
        let fake = BudVideoRecord::new(VideoCodec::Av1, VideoContentClass::HighMotion, 1280, 720, 60, false, 829_440_000, 48_790_588);
        assert!(VideoGates::k_bud_video(&fake, &sugg).is_err(), "17x HighMotion RED (K19)");
    }

    #[test]
    fn insufficient_frames_returns_none() {
        let yuv = static_frame(); // tek kare
        assert!(classify_content(&yuv, 320, 240, 2).is_none());
        assert!(classify_content(&[], 0, 0, 1).is_none());
    }
}
