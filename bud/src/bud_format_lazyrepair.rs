//! B.U.D. 2.0 - TEMBEL ONARIM POLİTİKASI (F34/F102/F295 - lazy recovery)
//!
//! Kalan iş #11a: Lazy recovery. Shard kaybı anında değil, eşik/okuma-talebiyle
//! onarılır → onarım bandı düşer. Bu modül KARAR katmanıdır (MSR kodları GF(2^8)
//! ayrı iş; tasarım notu aşağıda): kayıp sayısı, yaş, okuma talebi ve bant
//! bütçesine göre onarımı ertele/hemen yap.
//! `RepairPolicy::decide` deterministiktir; kanıt kaydı zincire yazılabilir.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const REPAIR_MAGIC: [u8; 8] = *b"\xB5RPR1\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairAction {
    Defer { until_epoch: u64 },
    RepairNow { helpers: usize },
    RebuildFromScratch,
}

/// Tembel onarım kararı.
/// `lost`: kayıp shard sayısı · `tolerated`: kodun tolere ettiği kayıp (f)
/// `age_epochs`: kaybın yaşı · `read_pending`: okuma kuyruğu (talep varsa hemen)
/// `budget_per_epoch`: dönem başına onarım bant kotası.
pub fn decide_repair(
    lost: usize,
    tolerated: usize,
    age_epochs: u64,
    read_pending: bool,
    budget_per_epoch: f64,
) -> Option<RepairAction> {
    if lost == 0 {
        return Some(RepairAction::Defer { until_epoch: 0 }); // kayıp yok
    }
    if lost >= tolerated {
        // tolerans aşıldı → hemen, mümkünse yardımcı düğümlerden
        return Some(RepairAction::RepairNow { helpers: 2 });
    }
    // okuma talebi varsa hemen onar (gecikme kullanıcıya yansımasın)
    if read_pending {
        return Some(RepairAction::RepairNow { helpers: 1 });
    }
    // bütçe yoksa ertele; yaş eşiği aşılırsa onar
    let age_threshold = if budget_per_epoch <= 0.0 {
        0
    } else {
        (1.0 / budget_per_epoch.max(0.001)) as u64
    };
    if age_epochs >= age_threshold.max(2) {
        Some(RepairAction::RepairNow { helpers: 2 })
    } else {
        Some(RepairAction::Defer {
            until_epoch: age_threshold.max(2),
        })
    }
}

pub fn repair_digest(lost: usize, tolerated: usize, age: u64, read: bool, budget: f64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(REPAIR_MAGIC);
    h.update((lost as u32).to_le_bytes());
    h.update((tolerated as u32).to_le_bytes());
    h.update(age.to_le_bytes());
    h.update([read as u8]);
    h.update(budget.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kayip_yoksa_ertelenir() {
        assert!(matches!(
            decide_repair(0, 2, 0, false, 0.5),
            Some(RepairAction::Defer { .. })
        ));
    }

    #[test]
    fn tolerans_asilirsa_hemen_onar() {
        assert!(matches!(
            decide_repair(3, 2, 0, false, 0.5),
            Some(RepairAction::RepairNow { .. })
        ));
    }

    #[test]
    fn okuma_talebi_hemen_onarir() {
        assert!(matches!(
            decide_repair(1, 2, 0, true, 0.5),
            Some(RepairAction::RepairNow { .. })
        ));
    }

    #[test]
    fn butce_yoksa_ertele_buyuk_yasta_onar() {
        // bütçe 0 → eşik 0.max(2)=2; yaş 1 → ertele, yaş 5 → onar
        assert!(matches!(
            decide_repair(1, 2, 1, false, 0.0),
            Some(RepairAction::Defer { .. })
        ));
        assert!(matches!(
            decide_repair(1, 2, 5, false, 0.0),
            Some(RepairAction::RepairNow { .. })
        ));
    }

    #[test]
    fn karar_deterministik() {
        assert_eq!(
            repair_digest(1, 2, 3, true, 0.5),
            repair_digest(1, 2, 3, true, 0.5)
        );
    }
}

// ## MSR kodları - tasarım notu (F41/F293-F297, kodlanmadı - GF(2^8) ayrı iş)
// MSR (minimum-storage regenerating): onarımda TÜM veri yerine α sembol transferi;
// (n,k) için onarım bandı optimum. Mevcut Cauchy MDS (4+2) tek-parça kaybında
// konteynerin 4/6'sını transfer eder; MSR bunu (n-1)·α'ya indirir. Kodlama GF(2^8)
// üzerinde matris çarpımı gerektirir - `bud_format_erasure`'ün GF altyapısına
// `msr_repair_band` hesaplayıcı eklenebilir. Öncelik: düşük (repair bandı zaten
// k-4 LRC ile küçük).
