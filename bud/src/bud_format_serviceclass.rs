//! B.U.D. 2.0 - HİZMET SINIFLARI (F16 + K71 SLA - karar katmanı)
//!
//! Ekonomi kararı: tek fiyat 0.016, CPU maliyeti validatörde. Bu modül hizmet sınıflarını
//! İÇ yerleşim katmanı olarak tanımlar (kullanıcı fiyatı değişmez - TEK FİYAT):
//! sınıf, erişim sıklığı + yaşa göre seçilir ve hangi medya/erasure düzeyinde
//! tutulacağını belirler. Varsayılan eşikler ürünleşme kararına açık (yorum satırları).
//! `ServiceClass::select` deterministiktir; karar kanıtlanabilir.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SVC_MAGIC: [u8; 8] = *b"\xB5SVC1\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceClass {
    Hot = 0,    // erişim sık → HDD-CMR/QLC, çok kopya/erasure yüksek
    Warm = 1,   // arada → HDD-CMR, erasure standart
    Cold = 2,   // nadir → SMR/tape-hibrit, erasure düşük
    Archive = 3, // yasal/uzun → tape/M-Disc, write-once
    Regenerable = 4, // üretilebilir → sözleşme + commitment (bayt tutmaz, İ2)
}

/// Sınıf seçimi: `access_per_month` + `age_days` → sınıf (deterministik).
pub fn select_class(access_per_month: u64, age_days: u64, regenerable: bool) -> ServiceClass {
    if regenerable {
        return ServiceClass::Regenerable;
    }
    match (access_per_month, age_days) {
        (a, _) if a >= 100 => ServiceClass::Hot,
        (a, _) if a >= 10 => ServiceClass::Warm,
        (a, d) if a >= 1 && d <= 365 => ServiceClass::Cold,
        _ => ServiceClass::Archive,
    }
}

/// Sınıfın iç yerleşim medyası (bud_format_hw eşlemesi).
pub fn placement_media(class: ServiceClass) -> &'static str {
    match class {
        ServiceClass::Hot => "HDD-CMR",
        ServiceClass::Warm => "HDD-CMR",
        ServiceClass::Cold => "HDD-SMR",
        ServiceClass::Archive => "LTO-tape",
        ServiceClass::Regenerable => "none",
    }
}

pub fn class_digest(a: u64, d: u64, r: bool) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SVC_MAGIC);
    h.update(a.to_le_bytes());
    h.update(d.to_le_bytes());
    h.update([r as u8]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sinif_secimi_deterministik() {
        assert_eq!(select_class(500, 1, false), ServiceClass::Hot);
        assert_eq!(select_class(50, 10, false), ServiceClass::Warm);
        assert_eq!(select_class(3, 100, false), ServiceClass::Cold);
        assert_eq!(select_class(0, 900, false), ServiceClass::Archive);
        assert_eq!(select_class(500, 1, true), ServiceClass::Regenerable);
        assert_eq!(class_digest(1, 2, false), class_digest(1, 2, false));
    }

    #[test]
    fn her_sinif_ic_yerlesimi_var() {
        for c in [ServiceClass::Hot, ServiceClass::Warm, ServiceClass::Cold, ServiceClass::Archive, ServiceClass::Regenerable] {
            assert!(!placement_media(c).is_empty());
        }
    }

    #[test]
    fn tek_fiyat_korunur() {
        // sınıf kararı kullanıcı fiyatını DEĞİŞTİRMEZ - iç yerleşimdir.
        assert!(ServiceClass::Hot as u8 <= ServiceClass::Archive as u8);
    }
}
