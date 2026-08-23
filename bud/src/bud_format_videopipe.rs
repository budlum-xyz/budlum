//! B.U.D. 2.0 - Video Pipeline Konteyner Entegrasyonu (2026-08-16)
//!
//! Video içerik-sınıfı (bud_format_video) → codec/GOP önerisi → .bud konteyner
//! (BudV2File) → üretim kanıtı (BudProductionRecord) → PACT. Uçtan uca.
//!
//! Akış:
//!   1. Ham YUV'dan içerik sınıfı tespit (kare-farkı - K84 ölçümüne dayalı).
//!   2. Sınıfa göre codec/GOP önerisi (VideoSuggestion - dürüst ölçüm aralığı).
//!   3. Video bitstream'i .bud konteynerine (zstd) gömülür + BudVideoRecord üretilir.
//!   4. Üretim kanıtı: orijinal boyut + saklanan boyut → ölçülen oran (K19).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use crate::bud_format_container::{
    structural_split_compact, BudV2File, FormatCodec, StructuralKind,
};
use crate::bud_format_production::BudProductionRecord;
use crate::bud_format_video::{
    classify_content, BudVideoRecord, VideoContentClass, VideoSuggestion,
};

pub const VIDEO_PIPE_MAGIC: [u8; 8] = *b"\xB5VPIP\0\0\0";
pub const VIDEO_PIPE_VERSION: u8 = 1;

/// Video boru hattı sonucu: konteyner + video kaydı + üretim kanıtı (uçtan uca).
#[derive(Debug, Clone)]
pub struct VideoPipelineResult {
    pub container: Vec<u8>, // .bud konteyner baytları (zstd)
    pub class: VideoContentClass,
    pub suggestion: VideoSuggestion,
    pub video_record: BudVideoRecord,
    pub production_record: BudProductionRecord,
}

/// Video boru hattı: ham YUV + codec çıktısı → .bud konteyner + kanıt zinciri.
/// `video_bytes` = codec çıktısı (H.264/AV1 bitstream); `original_len` = ham YUV boyutu.
pub fn run_video_pipeline(
    yuv_sample: &[u8],
    w: usize,
    h: usize,
    frames: usize,
    video_bytes: &[u8],
    original_len: u64,
    ts_unix: u64,
) -> Option<VideoPipelineResult> {
    // 1) sınıf tespiti (örnek karelerden)
    let (class, _avg) = classify_content(yuv_sample, w, h, frames)?;
    // 2) codec/GOP önerisi (dürüst ölçüm aralığı - K84)
    let suggestion = VideoSuggestion::for_class(class);
    // 3) .bud konteyner: video bitstream'ini yapısal parçala (Binary) + zstd sıkıştır
    let chunks = structural_split_compact(StructuralKind::Binary, video_bytes, 64 * 1024);
    let file = BudV2File::new_zstd(FormatCodec::Mp4, chunks)?;
    let container = file.encode();
    // 4) video kaydı + üretim kanıtı (ölçülen oran - K19)
    let video_record = BudVideoRecord::new(
        suggestion.codec,
        class,
        w as u32,
        h as u32,
        suggestion.gop_frames,
        suggestion.lossless,
        original_len,
        container.len() as u64,
    );
    if !video_record.verify() {
        return None;
    }
    let production_record = BudProductionRecord::new(
        FormatCodec::Mp4,
        "video-pipeline",
        &container,
        original_len,
        ts_unix,
    );
    Some(VideoPipelineResult {
        container,
        class,
        suggestion,
        video_record,
        production_record,
    })
}

/// Boru hattı sonucu → deterministik blob (kayıt zinciri).
impl VideoPipelineResult {
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&VIDEO_PIPE_MAGIC);
        out.push(VIDEO_PIPE_VERSION);
        out.push(match self.class {
            VideoContentClass::Static => 0u8,
            VideoContentClass::LowMotion => 1,
            VideoContentClass::HighMotion => 2,
        });
        out.extend_from_slice(&(self.container.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.container);
        out.extend_from_slice(&self.video_record.claimed_ratio.to_le_bytes());
        out.extend_from_slice(&self.production_record.record_hash());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn static_yuv() -> Vec<u8> {
        // statik kare: aynı çerçeve tekrarı
        let frame = vec![0u8; 160 * 120 * 3 / 2];
        let mut yuv = Vec::new();
        for _ in 0..6 {
            yuv.extend_from_slice(&frame);
        }
        yuv
    }

    #[test]
    fn static_video_pipeline_end_to_end() {
        // statik video → AV1 önerisi + .bud konteyner + kanıt (uçtan uca)
        let yuv = static_yuv();
        let codec_out = b"fake av1 bitstream 1234567890 ".repeat(1000); // codec çıktısı
        let res = run_video_pipeline(&yuv, 160, 120, 5, &codec_out, 1_000_000, 1_768_000_000)
            .expect("boru hattı");
        assert_eq!(res.class, VideoContentClass::Static);
        assert_eq!(
            res.suggestion.codec,
            crate::bud_format_video::VideoCodec::Av1
        );
        assert!(res.suggestion.gop_frames >= 240, "statik uzun GOP");
        // konteyner açılabilir + içeriği orijinal
        let file = BudV2File::decode(&res.container).expect("konteyner");
        assert_eq!(
            file.restore_original().unwrap(),
            codec_out,
            "video bitstream kayıpsız"
        );
        // video kaydı tutarlı + oran ölçüm aralığında
        assert!(res.video_record.verify());
        assert!(res.video_record.claimed_ratio > 1.0);
        // üretim kanıtı tutarlı
        assert!(res.production_record.verify());
        // blob roundtrip
        let blob = res.to_blob();
        assert!(blob.len() > 40);
        assert_eq!(&blob[..8], &VIDEO_PIPE_MAGIC);
    }

    #[test]
    fn high_motion_pipeline() {
        // hareketli video → HighMotion + orta GOP
        let mut yuv = Vec::new();
        let mut x = 0x1234_5678u64;
        for _ in 0..6 * (160 * 120 * 3 / 2) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            yuv.push((x & 0xff) as u8);
        }
        let codec_out = b"av1 high motion stream ".repeat(500);
        let res =
            run_video_pipeline(&yuv, 160, 120, 5, &codec_out, 2_000_000, 100).expect("boru hattı");
        assert_eq!(res.class, VideoContentClass::HighMotion);
        assert!(res.suggestion.gop_frames <= 120, "hareketli kısa GOP");
        assert!(res.video_record.verify());
    }

    #[test]
    fn insufficient_frames_none() {
        // tek kare → sınıf tespiti yok → None
        let yuv = vec![0u8; 160 * 120 * 3 / 2];
        let codec_out = b"x".repeat(100);
        assert!(run_video_pipeline(&yuv, 160, 120, 2, &codec_out, 1000, 1).is_none());
    }
}
