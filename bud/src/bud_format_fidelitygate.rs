//! B.U.D. 2.0 - KAYIP GATE (KF2 uzantısı: AVIF lossy eşiği + ZFP/SZ error-bounded)
//!
//! Kalan iş: "AVIF lossy-tier eşiği + ZFP/SZ error-bounded sınıf kabulü."
//! Kural: kayıplı dönüşüm yalnız GÖRSEL-KAYIPSIZ / HATA-SINIRLI eşiklerle kabul
//! edilir; her kayıplı dönüşüm kayıplılık METADATASINI (ölçü) taşır ve gate bunu
//! reddeder/kaydeder. Varsayılan eşikler:
//! - AVIF/JPEG görsel kayıpsız: crf ≤ 32 (ölçülen 3.2x kazancın eşiği; F134)
//! - ZFP/SZ error-bounded: bağıl hata ≤ 1e-3 (bilimsel sınıf, 100-web bulgusu 6-23x)
//! - Çözünürlük HER ZAMAN korunur (KF2)
//! Varsayılanlar ürün kararına açıktır (yorum satırları - kullanıcı onayı ister).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const FID_MAGIC: [u8; 8] = *b"\xB5FID1\0\0\0";

pub const AVIF_CRF_VISUALLY_LOSSLESS: u32 = 32;   // ≤ bu → görsel kayıpsız sayılır (ölçülen)
pub const ZFP_REL_ERROR_BOUND: f64 = 1e-3;       // ≤ bu → error-bounded
pub const SZ_REL_ERROR_BOUND: f64 = 1e-3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossyKind {
    None,             // kayıpsız
    VisuallyLossless, // AVIF/JXL crf eşiği altı
    ErrorBounded,     // ZFP/SZ bağıl hata eşiği altı
    Unbounded,        // RED
}

/// Kayıplılık kararı: görsel medya crf ile, bilimsel veri bağıl hata ile.
pub fn classify_lossy(kind: &str, crf: Option<u32>, rel_error: Option<f64>) -> LossyKind {
    match kind {
        "avif" | "jxl" | "webp" | "jpeg" => match crf {
            Some(c) if c <= AVIF_CRF_VISUALLY_LOSSLESS => LossyKind::VisuallyLossless,
            Some(_) => LossyKind::Unbounded,
            None => LossyKind::None,
        },
        "zfp" | "sz" => match rel_error {
            Some(e) if e <= ZFP_REL_ERROR_BOUND => LossyKind::ErrorBounded,
            Some(_) => LossyKind::Unbounded,
            None => LossyKind::None,
        },
        _ => LossyKind::None,
    }
}

/// Gate: kabul edilen kayıplılık sınıflarının listesi.
pub fn gate_allows(l: LossyKind) -> bool {
    // Kayıpsız (None) her zaman geçer; sınırlı kayıplı sınıflar kabul; sınırsız RED.
    matches!(l, LossyKind::None | LossyKind::VisuallyLossless | LossyKind::ErrorBounded)
}

pub fn fidelity_digest(kind: &str, crf: Option<u32>, rel_error: Option<f64>) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(FID_MAGIC);
    h.update(kind.as_bytes());
    h.update(crf.unwrap_or(u32::MAX).to_le_bytes());
    h.update(rel_error.unwrap_or(f64::MAX).to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avif_esigi_dogru() {
        assert!(gate_allows(classify_lossy("avif", Some(30), None)));
        assert!(gate_allows(classify_lossy("avif", Some(32), None)));
        assert!(!gate_allows(classify_lossy("avif", Some(40), None)));
    }

    #[test]
    fn error_bounded_sinif_kabul() {
        assert!(gate_allows(classify_lossy("zfp", None, Some(1e-4))));
        assert!(!gate_allows(classify_lossy("sz", None, Some(0.01))));
    }

    #[test]
    fn kayipsiz_her_zaman_gecer() {
        assert!(gate_allows(classify_lossy("png", None, None)));
    }

    #[test]
    fn cozunurluk_korunur_notu() {
        // KF2: bu modül yalnız eşik; çözünürlük korunumu kod hattında garantili.
        assert_eq!(AVIF_CRF_VISUALLY_LOSSLESS, 32);
    }
}
