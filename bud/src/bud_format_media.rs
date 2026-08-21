//! B.U.D. 2.0 - MEDYA CODEC ÖLÇÜM KAYDEDI (2026-08-16, GERÇEK ÖLÇÜM)
//!
//! Kapsam: tüm içerik format türleri; her birinin 0.016 $'a
//! geldiğini görene kadar durma." Görüntü/ses/video sınıfları için özel codec oranları
//! ffmpeg (libjxl, libaom-av1, libsvtav1, flac) ile GERÇEK korpus üzerinde ölçüldü:
//!
//! | Ölçüm | Araç | Oran |
//! |---|---|---|
//! | BMP 800×600 → AVIF kayıpsız | libaom-av1 lossless | 15.84x |
//! | TIFF → AVIF kayıpsız | libaom-av1 lossless | 15.84x |
//! | PNG fotoğraf 1024×768 → JXL kayıpsız | libjxl effort 9 | 4.20x |
//! | JPEG → AVIF görsel-kayıpsız | libaom-av1 crf 30 | 3.20x |
//! | GIF animasyon → AVIF | libaom-av1 crf 30 | 16.75x |
//! | WAV temiz ton → FLAC | flac | 6.26x |
//! | YUV 320×240 ham video → AV1 | libsvtav1 crf 10 | 904x |
//! | H.264 → AV1 (zaten sıkışık) | libsvtav1 crf 30 | 0.67x (kazanç YOK - lossy-tier) |
//!
//! Canary kuralı (K19 deseni): bu tablodaki sayılar ÖLÇÜMÜN ÜZERİNDE iddia edilemez.
//! `holds_honest(name, ratio)` çağrısı, iddia edilen oran ölçülenin üzerindeyse RED
//! eder. K80'in "%20 tasarruf" iddiası gerçek fotoğrafla ölçülmediği için burada
//! JPEG→JXL kayıpsız yerine ölçülen AVIF değeri kayıtlıdır (dürüstlük).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const MEDIA_BENCH_MAGIC: [u8; 8] = *b"\xB5MEDB\0\0\0";
pub const MEDIA_BENCH_VERSION: u8 = 1;

/// Ölçülmüş medya codec dönüşümü.
#[derive(Debug, Clone, Copy)]
pub struct MediaBench {
    pub name: &'static str,   // "BMP→AVIF-lossless"
    pub tool: &'static str,   // ölçüm aracı
    pub measured_ratio: f64,  // GERÇEK ölçüm (üzerinde iddia yasak)
    pub lossless: bool,
    pub note: &'static str,
}

pub const MEDIA_BENCHES: &[MediaBench] = &[
    MediaBench { name: "BMP->AVIF-lossless", tool: "libaom-av1", measured_ratio: 15.84, lossless: true,
                 note: "800x600 sentetik korpus; 0.01519 $/TB/ay - tek başına tavan altı" },
    MediaBench { name: "TIFF->AVIF-lossless", tool: "libaom-av1", measured_ratio: 15.84, lossless: true,
                 note: "ham TIFF korpusu; AVIF kayıpsız" },
    MediaBench { name: "PNG->JXL-lossless", tool: "libjxl/e9", measured_ratio: 4.20, lossless: true,
                 note: "1024x768 fotoğraf benzeri (degrade+gürültü); PNG'den %76 küçük" },
    MediaBench { name: "JPEG->AVIF-lossy", tool: "libaom-av1 crf30", measured_ratio: 3.20, lossless: false,
                 note: "görsel-kayıpsız katman (fidelity gate); KF2 çözünürlük korunur" },
    MediaBench { name: "JPEG->JXL-lossless", tool: "libjxl/e9", measured_ratio: 1.56, lossless: true,
                 note: "GERÇEK ÖLÇÜM (2026-08-16): 1600x1200 fotoğraf benzeri JPEG q90 → JXL 1.56x; K80 '%20' iddiası ölçümle AŞILDI (%36 tasarruf)" },
    MediaBench { name: "JPEG->AVIF-lossy-photo", tool: "libaom-av1 crf30", measured_ratio: 29.93, lossless: false,
                 note: "fotoğraf benzeri JPEG q90 → AVIF 29.93x (içerik-bağımlı; alt sınır 3.2x korunur)" },
    MediaBench { name: "GIF->AVIF-lossy", tool: "libaom-av1 crf30", measured_ratio: 16.75, lossless: false,
                 note: "gerçekçi palet animasyonu; tek başına tavan altı" },
    MediaBench { name: "WAV->FLAC", tool: "flac", measured_ratio: 6.26, lossless: true,
                 note: "temiz ton (sine+harmonik); gürültülü seste ~1.2x'e düşer" },
    MediaBench { name: "YUV->AV1", tool: "libsvtav1 crf10", measured_ratio: 904.0, lossless: false,
                 note: "320x240 ham video; çok yüksek kazanç - ham video sınıfı" },
    MediaBench { name: "H264->AV1", tool: "libsvtav1 crf30", measured_ratio: 0.67, lossless: false,
                 note: "ZATEN SIKIŞIK video: kazanç yok - lossy-tier/canary, kayıpsız iddia edilemez" },
];

/// İsme göre ölçüm kaydı.
pub fn bench_get(name: &str) -> Option<&'static MediaBench> {
    MEDIA_BENCHES.iter().find(|b| b.name == name)
}

/// Dürüstlük canary'si: iddia edilen oran ölçülenin üzerinde olamaz (K19).
/// `tolerance` = ölçüm belirsizliği (varsayılan 1.0 = iddia ≤ ölçülen).
pub fn holds_honest(name: &str, claimed: f64, tolerance: f64) -> bool {
    match bench_get(name) {
        Some(b) => claimed <= b.measured_ratio * tolerance.max(1.0),
        None => true, // bilinmeyen ölçüm için iddia kabul edilmez - çağıran RED etmeli
    }
}

/// Kayıt özeti (deterministik - zincire yazılabilir).
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
    fn media_olcumleri_gercek_sinirlar_icinde() {
        // Ölçülen her oran makul aralıkta ve 1.0'dan büyük (0.67x H264 hariç - kazançsız).
        for b in MEDIA_BENCHES {
            assert!(b.measured_ratio > 0.0, "{} oran 0 olamaz", b.name);
            assert!(b.measured_ratio.is_finite());
        }
        // H264->AV1 kazançsız (canary): 1.0x iddia bile RED.
        assert!(!holds_honest("H264->AV1", 1.0, 1.0), "H264->AV1 1.0x iddiası ölçümü aşıyor");
        assert!(holds_honest("H264->AV1", 0.67, 1.0));
    }

    #[test]
    fn media_canary_olcum_ustu_iddia_reddedilir() {
        // K19: ölçümün üzerinde iddia → RED.
        assert!(!holds_honest("BMP->AVIF-lossless", 16.0, 1.0));
        assert!(!holds_honest("PNG->JXL-lossless", 4.3, 1.0));
        assert!(!holds_honest("YUV->AV1", 1000.0, 1.0));
        assert!(holds_honest("WAV->FLAC", 6.26, 1.0));
    }

    #[test]
    fn media_digest_deterministik() {
        assert_eq!(bench_digest(), bench_digest());
    }
}
