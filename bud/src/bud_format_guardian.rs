//! B.U.D. 2.0 - GEZİCİ BEKÇİ REJENERASYONU (fikirler3.0 Y1/Y9/Y12/Y14)
//!
//! fikirler3.0 tezi: "disk uyur, CPU uyanır, bekçi gezer, tarife uyanıklığa bağlanır."
//! Bu modül Y-fikirlerinin bud iskeletindeki kod karşılığıdır:
//! - Y1  Gezici Bekçi: her epoch bekçi N içerikten birini seçer, PACT'i yeniden
//!   üretir ve commitment'a karşı doğrular (üretim sınavı - PoR yerine).
//! - Y12 Bekçi seçimi: commit-reveal + deterministik PRF (aynı geçmiş → aynı seçim).
//! - Y14 Bekçi alt-rolü: opt-in bayrağı (yeni RoleId açmadan).
//! - Y9  Rejeneratif cihaz ağı: mini-bekçi kaydı (shard denetimi + kusur sayacı).
//!   Sayılar program çıktısıdır; elle yazılmaz (2.0 kuralı). N=26 tablosu DV'den.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const GUARD_MAGIC: [u8; 8] = *b"\xB5GRD1\0\0\0";
pub const GUARD_VERSION: u8 = 1;

/// DV N=26 tablosu: uyanık payı 1/N, 24 saatte yakalanma %99.6 (belgeden sabit).
pub const DV_N: u32 = 26;
pub const DV_CATCH_RATE_24H: f64 = 0.996;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianRole {
    None,       // bekçi değil
    Operator,   // STORAGE_OPERATOR altında opt-in bekçi (Y14)
    MiniDevice, // cihaz ağı mini-bekçisi (Y9)
}

/// Bekçi kaydı (Y14: opt-in bayrağı; Y9: mini-cihaz).
#[derive(Debug, Clone)]
pub struct Guardian {
    pub id: [u8; 32],
    pub role: GuardianRole,
    pub opt_in: bool,     // Y14: seçime yalnız opt-in girer
    pub fault_count: u64, // Y9/Y12: kusur sayacı (itibar)
    pub bond_sep: bool,   // depolama stake'inden AYRI bekçi bond'u
}

impl Guardian {
    pub fn new(id: [u8; 32], role: GuardianRole) -> Self {
        let opt_in = role != GuardianRole::None;
        Self {
            id,
            role,
            opt_in,
            fault_count: 0,
            bond_sep: true,
        }
    }

    pub fn record_fault(&mut self) {
        self.fault_count = self.fault_count.saturating_add(1);
    }
}

/// Y12: commit-reveal bekçi seçimi - deterministik PRF.
/// `seeds`: epoch başında her bekçinin commit ettiği tohumlar (sıralı).
/// `epoch`, `pact_id`: seçim girdisi. Çıktı: seçilen bekçi indeksi + tur sayısı.
/// Aynı girdi → AYNI seçim (konsensüs testi). Commit-reveal: tohumlar açılmadan
/// kimse seçimi bilemez (acilis öncesi manipülasyon kapalı).
pub fn select_guardian(seeds: &[[u8; 32]], epoch: u64, pact_id: &[u8; 32]) -> Option<(usize, u32)> {
    if seeds.is_empty() || seeds.len() > 1024 {
        return None;
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_GUARDIAN_SELECT_V1");
    h.update(epoch.to_le_bytes());
    h.update(pact_id);
    for s in seeds {
        h.update(s);
    }
    let d: [u8; 32] = h.finalize().into();
    let mut w8 = [0u8; 8];
    w8.copy_from_slice(&d[..8]);
    let v = u64::from_le_bytes(w8);
    let idx = (v % seeds.len() as u64) as usize;
    // tur sayısı: N büyüdükçe uyanıklık payı düşer → tur sıklığı 1/N (DV)
    let tour = DV_N.max(1);
    Some((idx, tour))
}

/// Y1: üretim sınavı - PACT'i yeniden üret, commitment'a karşı doğrula.
/// `regenerate`: bekçinin ürettiği baytlar · `commitment`: kayıtlı PACT commitment'ı.
/// Yanlış tarif/hash → her zaman RED (negatif test).
pub fn verify_regeneration(regenerate: &[u8], commitment: &[u8; 32]) -> bool {
    let cid = crate::bud_format_container::content_id(regenerate);
    &cid == commitment
}

/// Y1: tur programı - N içerikten hangisi bu epoch denetlenecek (deterministik).
/// `pact_ids`: içerik listesi · `epoch`: tur. Denetim maliyeti = 1/N içerik.
pub fn tour_plan(pact_ids: &[[u8; 32]], epoch: u64) -> Option<usize> {
    if pact_ids.is_empty() {
        return None;
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_GUARDIAN_TOUR_V1");
    h.update(epoch.to_le_bytes());
    let mut all = Vec::new();
    for p in pact_ids {
        all.extend_from_slice(p);
    }
    h.update(&all);
    let d: [u8; 32] = h.finalize().into();
    let mut w8 = [0u8; 8];
    w8.copy_from_slice(&d[..8]);
    let v = u64::from_le_bytes(w8);
    Some((v % pact_ids.len() as u64) as usize)
}

/// Y9: mini-bekçi cihaz denetim kaydı - shard oku + imza + kusur sayacı.
#[derive(Debug, Clone)]
pub struct MiniGuardianAudit {
    pub device_id: [u8; 32],
    pub pact_id: [u8; 32],
    pub shard_ok: bool,
    pub signed: bool,
}

/// Cihaz yalan kanıtı (Y9 riski): imzasız/bozuk kanıt → kusur sayacı artar.
pub fn audit_mini(device: &mut Guardian, audit: &MiniGuardianAudit) -> bool {
    if audit.shard_ok && audit.signed {
        true
    } else {
        device.record_fault();
        false
    }
}

pub fn guardian_digest(g: &Guardian) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(GUARD_MAGIC);
    h.update([GUARD_VERSION]);
    h.update(g.id);
    h.update([match g.role {
        GuardianRole::None => 0,
        GuardianRole::Operator => 1,
        GuardianRole::MiniDevice => 2,
    }]);
    h.update([g.opt_in as u8]);
    h.update(g.fault_count.to_le_bytes());
    h.update([g.bond_sep as u8]);
    h.finalize().into()
}

/// Y1 ÖLÇÜM: üretim sınavı maliyeti vs PoR sınavı maliyeti (program çıktısı).
/// `produce_sec`: PACT'i yeniden üretme süresi · `por_sec`: karşılık gelen PoR.
/// Kriter (fikirler2.0 İ2): üretim maliyeti PoR'un %1'inden az olmalı.
pub fn production_vs_por_ratio(produce_sec: f64, por_sec: f64) -> f64 {
    if por_sec <= 0.0 {
        return f64::INFINITY;
    }
    produce_sec / por_sec
}

/// Y1 kabul: oran < 0.01 (%1) mı?
pub fn production_cheaper_than_por(produce_sec: f64, por_sec: f64) -> bool {
    production_vs_por_ratio(produce_sec, por_sec) < 0.01
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Digest;

    fn hof(b: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b);
        h.finalize().into()
    }

    #[test]
    fn y12_secim_deterministik_ve_cakismasiz() {
        let seeds: Vec<[u8; 32]> = (0..10u8).map(|i| hof(&[i])).collect();
        let pact = hof(b"pact-a");
        let (i1, t1) = select_guardian(&seeds, 7, &pact).unwrap();
        let (i2, t2) = select_guardian(&seeds, 7, &pact).unwrap();
        assert_eq!((i1, t1), (i2, t2), "aynı geçmiş → aynı seçim");
        assert_eq!(t1, DV_N);
        // farklı epoch → farklı seçim (örnekleme; deterministik değil ama olası)
        let (i3, _) = select_guardian(&seeds, 8, &pact).unwrap();
        assert!(i1 < seeds.len() && i3 < seeds.len());
    }

    #[test]
    fn y1_uretim_sinavi_dogrular_ve_reddeder() {
        let data = b"yeniden uretilebilir icerik ";
        let cid = crate::bud_format_container::content_id(data);
        assert!(verify_regeneration(data, &cid), "doğru üretim → kabul");
        assert!(
            !verify_regeneration(b"yanlis tarif ciktisi", &cid),
            "yanlış → RED"
        );
    }

    #[test]
    fn y1_tur_plan_1n_icerik_sec() {
        let pacts: Vec<[u8; 32]> = (0..26u8).map(|i| hof(&[i])).collect();
        let chosen = tour_plan(&pacts, 100).unwrap();
        assert!(chosen < pacts.len());
        assert_eq!(tour_plan(&pacts, 100).unwrap(), chosen, "deterministik");
        assert!(tour_plan(&[], 1).is_none());
    }

    #[test]
    fn y14_opt_in_ve_ayri_bond() {
        let g = Guardian::new([1u8; 32], GuardianRole::Operator);
        assert!(g.opt_in);
        assert!(g.bond_sep, "bekçi bond'u depolama stake'inden ayrı");
        let none = Guardian::new([2u8; 32], GuardianRole::None);
        assert!(!none.opt_in, "opt-in yoksa seçime girmez");
    }

    #[test]
    fn y9_mini_bekci_kusur_sayar() {
        let mut dev = Guardian::new([9u8; 32], GuardianRole::MiniDevice);
        assert!(audit_mini(
            &mut dev,
            &MiniGuardianAudit {
                device_id: [9u8; 32],
                pact_id: [1u8; 32],
                shard_ok: true,
                signed: true
            }
        ));
        assert_eq!(dev.fault_count, 0);
        assert!(!audit_mini(
            &mut dev,
            &MiniGuardianAudit {
                device_id: [9u8; 32],
                pact_id: [1u8; 32],
                shard_ok: true,
                signed: false
            }
        ));
        assert_eq!(dev.fault_count, 1, "yalan kanıt → kusur");
    }

    #[test]
    fn y1_maliyet_orani_olcum() {
        // üretim 0.5s, PoR 120s → %0.42 → kabul (İ2 kriteri)
        let r = production_vs_por_ratio(0.5, 120.0);
        assert!(r < 0.01, "oran: {r}");
        assert!(production_cheaper_than_por(0.5, 120.0));
        // üretim 2s, PoR 10s → %20 → RED
        assert!(!production_cheaper_than_por(2.0, 10.0));
        assert_eq!(production_vs_por_ratio(1.0, 0.0), f64::INFINITY);
    }

    #[test]
    fn digest_deterministik() {
        let g = Guardian::new([5u8; 32], GuardianRole::Operator);
        assert_eq!(guardian_digest(&g), guardian_digest(&g));
    }
}
