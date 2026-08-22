//! B.U.D. 2.0 - FİZİKSEL MEDYA KATMANI KAYDI (F303-F330 + SMR/HAMR/Silica)
//!
//! Kalan iş #14: SMR/zoned + HAMR + Silica fiziksel katman evrimi - donanım modeli.
//! Her medya türü: $/TB/ay, dayanıklılık, güç, uygun içerik sınıfı.
//! `tier_for(usd_ceiling)` bir $ bütçesi için en ucuz uygun katmanı seçer
//! (F16 hizmet sınıflarıyla birlikte; tek kullanıcı fiyatı 0.016 korunur,
//! iç maliyet katmanlaması buna göre döner).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const HW_MAGIC: [u8; 8] = *b"\xB5HWR1\0\0\0";

#[derive(Debug, Clone, Copy)]
pub struct MediaTier {
    pub name: &'static str,
    pub usd_per_tb_month: f64,
    pub durability_years: u64,
    pub idle_w_per_tb: f64,
    pub write_once: bool,
    pub note: &'static str,
}

pub const MEDIA_TIERS: &[MediaTier] = &[
    MediaTier {
        name: "HDD-CMR",
        usd_per_tb_month: 0.23342,
        durability_years: 5,
        idle_w_per_tb: 7.0,
        write_once: false,
        note: "price.rs zemini (sıcak/ılık)",
    },
    MediaTier {
        name: "HDD-SMR",
        usd_per_tb_month: 0.175,
        durability_years: 5,
        idle_w_per_tb: 6.0,
        write_once: false,
        note: "F303: $30-45/TB; zoned+append-only soğuk katman",
    },
    MediaTier {
        name: "HAMR",
        usd_per_tb_month: 0.145,
        durability_years: 6,
        idle_w_per_tb: 6.0,
        write_once: false,
        note: "F305: 36-44TB, 2029 $4/TB; yoğunluk",
    },
    MediaTier {
        name: "QLC-SSD",
        usd_per_tb_month: 0.62,
        durability_years: 4,
        idle_w_per_tb: 2.0,
        write_once: false,
        note: "F311: sıcak tier; DWPD 0.1-0.3 soğuk okuma",
    },
    MediaTier {
        name: "LTO-tape",
        usd_per_tb_month: 0.00025,
        durability_years: 30,
        idle_w_per_tb: 0.0,
        write_once: true,
        note: "F3/F307: derin soğuk, 0W idle (tape sınıfı kodlu)",
    },
    MediaTier {
        name: "M-Disc",
        usd_per_tb_month: 0.012,
        durability_years: 1000,
        idle_w_per_tb: 0.0,
        write_once: true,
        note: "optik arşiv; yaz-oku cihazı gerekli",
    },
    MediaTier {
        name: "Silica-glass",
        usd_per_tb_month: 0.01,
        durability_years: 10_000,
        idle_w_per_tb: 0.0,
        write_once: true,
        note: "F256: 7TB/plaka, Azure AI okuma - gelecek ultra-arşiv",
    },
    MediaTier {
        name: "DNA",
        usd_per_tb_month: 800.0,
        durability_years: 1000,
        idle_w_per_tb: 0.0,
        write_once: true,
        note: "F168: $800M/TB - REDDEDİLDİ (ekonomik değil)",
    },
];

pub fn tier_get(name: &str) -> Option<&'static MediaTier> {
    MEDIA_TIERS.iter().find(|t| t.name == name)
}

/// $ bütçesi için en ucuz uygun katman (write-once kısıtı opsiyonel).
pub fn cheapest_tier(usd_ceiling: f64, allow_write_once: bool) -> Option<&'static MediaTier> {
    MEDIA_TIERS
        .iter()
        .filter(|t| t.usd_per_tb_month <= usd_ceiling && (allow_write_once || !t.write_once))
        // `partial_cmp().unwrap()` NaN bir fiyatta panikler. `total_cmp` NaN'i
        // sirali kabul eder ve panik yerine belirlenimli bir siralama verir.
        .min_by(|a, b| a.usd_per_tb_month.total_cmp(&b.usd_per_tb_month))
}

/// 0.016 tek-fiyat hedefi: hangi medya doğrudan tutar?
pub fn media_holds_ceiling(usd: f64, ceiling: f64) -> bool {
    usd <= ceiling
}

pub fn hw_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(HW_MAGIC);
    for t in MEDIA_TIERS {
        h.update(t.name.as_bytes());
        h.update(t.usd_per_tb_month.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tape_0_016_tavaninda() {
        assert!(media_holds_ceiling(
            tier_get("LTO-tape").unwrap().usd_per_tb_month,
            0.016
        ));
        assert!(!media_holds_ceiling(
            tier_get("HDD-CMR").unwrap().usd_per_tb_month,
            0.016
        ));
    }

    #[test]
    fn ucuz_katman_secimi_dogru() {
        // 0.016 bütçe, write-once serbest → tape; yasak → yok
        assert_eq!(cheapest_tier(0.016, true).unwrap().name, "LTO-tape");
        assert!(
            cheapest_tier(0.016, false).is_none()
                || cheapest_tier(0.016, false).unwrap().usd_per_tb_month > 0.016
        );
    }

    #[test]
    fn dna_reddedildi() {
        let dna = tier_get("DNA").unwrap();
        assert!(dna.usd_per_tb_month > 100.0);
    }

    #[test]
    fn hw_digest_deterministik() {
        assert_eq!(hw_digest(), hw_digest());
    }
}
