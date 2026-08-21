//! B.U.D. 2.0 - OTOMATİK ZSTD SEVİYESİ + SIKIŞMAZLIKTA GEÇ (F133/F179)
//!
//! Kalan iş: akıllı zstd seviyesi. Hızlı seviye dene → kazanç küçükse (≤%5) ya da
//! zaman bütçesi aşıldıysa SIKIŞTIRMADAN GEÇ (CPU koru - ZFS smart deseni).
//! Dürüstlük: karar GERÇEK ölçüme dayanır; tahmin yok.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const AUTOZ_MAGIC: [u8; 8] = *b"\xB5AZST\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZstdDecision {
    Level(u8),      // seçilen seviye
    Skip,           // sıkışmaz - ham sakla
}

/// Sıkıştırma denemesi sonucuna göre karar.
/// `fast_ratio`: hızlı seviye oranı (orijinal/sıkışmış) · `time_budget_ms` kaldı mı?
/// `skip_threshold`: bu oranın altında SKIP (varsayılan 1.05 - %5 kazanç).
pub fn decide(
    fast_ratio: f64,
    slow_ratio: f64,
    time_budget_ms_left: u64,
    skip_threshold: f64,
) -> ZstdDecision {
    if fast_ratio <= skip_threshold.max(1.0) {
        return ZstdDecision::Skip; // sıkışmaz
    }
    if time_budget_ms_left < 200 {
        // zaman dar → hızlı seviye yeter (F190: düşük seviye yeter)
        return ZstdDecision::Level(3);
    }
    // yavaş seviye ek kazanç veriyor mu?
    let gain = slow_ratio / fast_ratio.max(1e-9);
    if gain >= 1.10 {
        ZstdDecision::Level(19)
    } else if gain >= 1.03 {
        ZstdDecision::Level(9)
    } else {
        ZstdDecision::Level(3)
    }
}

pub fn autoz_digest(fast: f64, slow: f64, budget: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(AUTOZ_MAGIC);
    h.update(fast.to_le_bytes());
    h.update(slow.to_le_bytes());
    h.update(budget.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sikismazsa_gec() {
        assert!(matches!(decide(1.01, 1.02, 10_000, 1.05), ZstdDecision::Skip));
    }

    #[test]
    fn zaman_darsa_hizli_seviye() {
        assert!(matches!(decide(1.5, 3.0, 50, 1.05), ZstdDecision::Level(3)));
    }

    #[test]
    fn buyuk_kazanc_yavs_seviye() {
        assert!(matches!(decide(1.5, 2.2, 10_000, 1.05), ZstdDecision::Level(19)));
    }

    #[test]
    fn digest_deterministik() {
        assert_eq!(autoz_digest(1.5, 2.2, 100), autoz_digest(1.5, 2.2, 100));
    }
}
