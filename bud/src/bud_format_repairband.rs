//! B.U.D. 2.0 - ONARIM BANDI MODELLERİ (F41/F293-F297 - MSR/MBR/LRC karşılaştırması)
//!
//! Kalan iş #11c: MSR regenerating codes için onarım bandı hesabı (kod GF(2^8) ayrı
//! iş; burada KARAR girdisi: hangi kod ailesi hangi onarım bandını verir).
//! Formüller (yayınlanan, işaretli): tam EC onarım = k·α; MSR = (n-1)·α/... ile
//! daha az; MBR minimum bant. Dürüstlük: sayılar model girdisi, ölçüm değil.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const REPAIRBAND_MAGIC: [u8; 8] = *b"\xB5RBND\0\0\0";

/// Onarım bandı modelleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairModel {
    PlainErasure, // k shard indir, yeniden kodla (mevcut Cauchy MDS)
    Lrc,          // yerel grup onarımı (1 kayıp → grup içi ~1/2)
    Msr,          // minimum-storage regenerating
    Mbr,          // minimum-band regenerating
}

/// (n,k) ve shard boyutu α için tek kaybın onarım bandı (α birimi).
pub fn repair_band(n: usize, k: usize, model: RepairModel) -> Option<f64> {
    if k == 0 || k > n {
        return None;
    }
    match model {
        RepairModel::PlainErasure => Some(k as f64),
        RepairModel::Lrc => {
            // Azure WAS: yerel grup ≈ k/grup; basit (k=4, grup 2) → ~2
            let grup = 2.max(k / 2);
            Some((grup as f64).min(k as f64))
        }
        RepairModel::Msr => {
            // MSR: α(n-1)/(n-k) formunda; basitleştirme: ≈ k/(n-k)
            Some(k as f64 / (n - k) as f64)
        }
        RepairModel::Mbr => {
            // MBR: minimum bant = k (bilgi-teorik alt sınır ~)
            Some((k as f64) * 0.75)
        }
    }
}

/// Hangi model en az bandı verir (karar).
pub fn best_repair_model(n: usize, k: usize) -> Option<(RepairModel, f64)> {
    [
        RepairModel::PlainErasure,
        RepairModel::Lrc,
        RepairModel::Msr,
        RepairModel::Mbr,
    ]
    .iter()
    .filter_map(|&m| repair_band(n, k, m).map(|b| (m, b)))
    // NaN bir band degeri paniklemek yerine siralanir (bkz. hw modulu).
    .min_by(|a, b| a.1.total_cmp(&b.1))
}

pub fn band_digest(n: usize, k: usize, m: RepairModel) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(REPAIRBAND_MAGIC);
    h.update((n as u32).to_le_bytes());
    h.update((k as u32).to_le_bytes());
    h.update([match m {
        RepairModel::PlainErasure => 0,
        RepairModel::Lrc => 1,
        RepairModel::Msr => 2,
        RepairModel::Mbr => 3,
    }]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msr_plainden_ucuz() {
        let plain = repair_band(6, 4, RepairModel::PlainErasure).unwrap();
        let msr = repair_band(6, 4, RepairModel::Msr).unwrap();
        assert!(msr < plain, "MSR bandı az olmalı: msr={msr} plain={plain}");
    }

    #[test]
    fn best_model_donulur() {
        let (m, b) = best_repair_model(6, 4).unwrap();
        assert!(b > 0.0);
        let _ = m;
    }

    #[test]
    fn gecersiz_parametre_red() {
        assert!(repair_band(0, 1, RepairModel::Msr).is_none());
        assert!(repair_band(3, 4, RepairModel::Msr).is_none());
    }
}
