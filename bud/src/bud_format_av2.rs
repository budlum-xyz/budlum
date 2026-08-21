//! B.U.D. 2.0 - AV2 YOLU (2026-08-16 ARAŞTIRMA: AV2 v1.0.0 ÇIKTI)
//!
//! AOMedia AV2 v1.0.0 spec 28 Mayıs 2026, duyuru 9 Haziran 2026: AV1'den ~%30
//! daha iyi, screen/HDR/8K'da ~%40; AVM referans encoder'ı v1.0.0 (yazılım).
//! Donanım decode 2027-2028; yazılım decode ~5x AV1 ağır → arşiv/üretim hattına
//! henüz uygun değil ama video sınıfı yolu HAZIR: codec seçimi içeriğe bağlı
//! (KF2). Bu modül AV2'yi kaydeder + canary: iddia ölçüm üstü olamaz.
//!
//! Video matrisi: YUV→AV1 904x (ölçüldü). AV2 hedefi: AV1'in %70'i bant →
//! ~1290x karşılığı (YUV→AV2). Bu bir HEDEF/plan kaydıdır; gerçek ölçüm AVM
//! encoder'ı üretim kohortunda koşulunca matrise girer (uydurma yok).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const AV2_MAGIC: [u8; 8] = *b"\xB5AV2\0\0\0\0";

/// AV2 kayıt: yayın durumu + iddia + dürüstlük sınırı.
#[derive(Debug, Clone, Copy)]
pub struct Av2Status {
    pub spec_released: bool,       // 2026-05-28
    pub claimed_gain_vs_av1: f64,  // ~0.30 (yayınlanan iddia)
    pub hardware_supported: bool,  // 2027-2028 (bugün yok)
    pub software_decoder: bool,    // AVM ref var, ~5x AV1 ağır
}

pub const AV2_CURRENT: Av2Status = Av2Status {
    spec_released: true,
    claimed_gain_vs_av1: 0.30,
    hardware_supported: false,
    software_decoder: true,
};

/// AV2 bant karşılığı: AV1 oranının %(1-gain)'i kadar → oran çarpanı 1/(1-gain).
pub fn av2_ratio_from_av1(av1_ratio: f64, gain: f64) -> f64 {
    if gain >= 1.0 {
        return av1_ratio;
    }
    av1_ratio / (1.0 - gain)
}

/// Dürüstlük canary'si: AV2 iddiası ölçülmüş/yayınlanmış sınırı aşamaz.
pub fn av2_holds_honest(claimed_ratio: f64, av1_measured: f64, gain: f64) -> bool {
    let theoretical = av2_ratio_from_av1(av1_measured, gain);
    claimed_ratio <= theoretical * 1.05 // %5 tolerans (encoder olgunluğu)
}

pub fn av2_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(AV2_MAGIC);
    h.update([AV2_CURRENT.spec_released as u8]);
    h.update(AV2_CURRENT.claimed_gain_vs_av1.to_le_bytes());
    h.update([AV2_CURRENT.hardware_supported as u8]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn av2_oran_hesabi() {
        // YUV→AV1 904x → AV2 %30 kazanç → ~1291x (teorik)
        let av2 = av2_ratio_from_av1(904.0, 0.30);
        assert!((av2 - 1291.4).abs() < 1.0, "{av2}");
        // %40 kazanç (screen) → ~1506x
        assert!(av2_ratio_from_av1(904.0, 0.40) > av2);
    }

    #[test]
    fn av2_durustluk_canary() {
        let av1_measured = 904.0;
        let gain = 0.30;
        // teorik ~1291 → 1.05 toleransla ~1356 üstü iddia RED
        assert!(av2_holds_honest(1290.0, av1_measured, gain));
        assert!(av2_holds_honest(1355.0, av1_measured, gain));
        assert!(!av2_holds_honest(2000.0, av1_measured, gain), "ölçüm üstü iddia RED");
    }

    #[test]
    fn av2_durum_dogru() {
        // `assert!(SABIT.alan, ...)` clippy::assertions_on_constants tetikler:
        // koşul derleme zamanında bilinir. Niyet "bu alanlar şu değerde
        // KİLİTLİ" olduğundan `assert_eq!` doğru ifade — beklenen değeri
        // açıkça yazar ve alan değişirse hata mesajı ne olduğunu gösterir.
        let durum = AV2_CURRENT;
        assert!(durum.spec_released, "AV2 v1.0.0 2026-05-28 çıktı");
        assert!(
            !durum.hardware_supported,
            "donanım desteği 2027-2028 bekleniyor"
        );
    }

    #[test]
    fn av2_digest_deterministik() {
        assert_eq!(av2_digest(), av2_digest());
    }
}
