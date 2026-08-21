//! B.U.D. 2.0 - POLLEN-ÜRETİM KÖPRÜSÜ + YÖNETİŞİM-UYUM PAKETİ + BAĞLANTI ENVANTERİ
//! (fikirler3.0 Y7/Y16/Y0)
//!
//! Y7: satın alma ödemesi bir üretim teklifine kilitlenir; grant `Active` olur
//! ancak PACT üretim doğrulaması geçtikten sonra (settlement = üretim kanıtı).
//! Escrow yok - bakiye kilidi (B1 kararı).
//!
//! Y16: her yeni parametre yönetişim desenine girer: constitution whitelist +
//! aktivasyon gecikmeleri (parametre 10 epoch, politika 20, hedefli 5); whitelist'siz
//! parametre ekleyen commit kapiyla RED (mutasyon testi).
//!
//! Y0: V7 tezi ("eksik algoritma değil bağlantı") - bağlantı envanteri: her modülün
//! üretim yolu çağrısı "çağrı var" değil "çağrı doğrulama yapıyor" düzeyinde izlenir.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const GOV_MAGIC: [u8; 8] = *b"\xB5GOV1\0\0\0";

// ============================ Y7: Pollen köprüsü ============================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    Locked,     // ödeme üretim teklifine kilitli
    Active,     // üretim doğrulaması geçti → erişim açık
    Refunded,   // üretim başarısız → bakiye kilidi iadesi
}

#[derive(Debug, Clone)]
pub struct PollenGrant {
    pub buyer: [u8; 32],
    pub pact_id: [u8; 32],
    pub state: GrantState,
    pub payment_locked: u64, // bakiye kilidi (escrow yok)
}

/// Y7: ödeme üretim teklifine kilitlenir; grant Locked başlar.
pub fn lock_payment(buyer: [u8; 32], pact_id: [u8; 32], amount: u64) -> PollenGrant {
    PollenGrant { buyer, pact_id, state: GrantState::Locked, payment_locked: amount }
}

/// Y7: üretim doğrulaması geçerse grant Active olur (okuma açılır).
pub fn activate_after_production(grant: &mut PollenGrant, produced_ok: bool) {
    match (grant.state, produced_ok) {
        (GrantState::Locked, true) => grant.state = GrantState::Active,
        (GrantState::Locked, false) => grant.state = GrantState::Refunded,
        _ => {}
    }
}

/// Y7: kilitli ödeme → okuma reddi; Active → kabul.
pub fn can_read(grant: &PollenGrant) -> bool {
    grant.state == GrantState::Active
}

// ============================ Y16: yönetişim paketi ============================

/// Aktivasyon gecikme sınıfları (belgeden sabit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationClass {
    Parameter = 10, // parametre değişikliği
    Policy = 20,    // politika değişikliği
    Targeted = 5,   // hedefli düzeltme
}

/// Y16: whitelist - yönetişimce oylanabilir parametreler (V7 B4 kapanışı).
pub const PARAM_WHITELIST: &[&str] = &[
    "N_bekci",
    "hedef_enerji_butcesi",
    "tiny_object_threshold",
    "recipe_bounty_orani",
    "fiyat_agirlik_a",
    "fiyat_agirlik_b",
    "fiyat_agirlik_c",
    "validatör_ayrilma_tespiti",
    "sinav_araligi",
];

/// Y16: parametre whitelist'te mi? (whitelist'siz ekleme → kapi RED)
pub fn is_whitelisted(param: &str) -> bool {
    PARAM_WHITELIST.contains(&param)
}

/// Y16: aktivasyon gecikmesi (epoch).
pub fn activation_delay(class: ActivationClass) -> u64 {
    class as u64
}

/// Y16: kapi kuralı - yeni parametre whitelist'te olmalı (mutasyon testi bunu kırar).
pub fn gate_param_added(param: &str) -> bool {
    is_whitelisted(param)
}

// ============================ Y0: bağlantı envanteri ============================

/// Y0: bağlantı durumu - "çağrı doğrulama yapıyor" düzeyi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WiringStatus {
    Wired,   // çağrı var + doğrulama yapıyor
    Unwired, // çağrı yok (V7 B7: 7 modül 4.616 satır)
    Stub,    // çağrı var ama doğrulamasız
}

/// Y0: bağlantı envanteri kaydı (modül adı → durum).
pub fn wiring_inventory(module: &str, call_count: u64, verifies: bool) -> (WiringStatus, bool) {
    let _ = module;
    let status = if call_count == 0 {
        WiringStatus::Unwired
    } else if verifies {
        WiringStatus::Wired
    } else {
        WiringStatus::Stub
    };
    (status, status == WiringStatus::Wired)
}

pub fn gov_digest(g: &PollenGrant) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(GOV_MAGIC);
    h.update(g.buyer);
    h.update(g.pact_id);
    h.update([match g.state {
        GrantState::Locked => 0,
        GrantState::Active => 1,
        GrantState::Refunded => 2,
    }]);
    h.update(g.payment_locked.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn y7_grant_durum_makinesi() {
        let mut g = lock_payment([1u8; 32], [2u8; 32], 1000);
        assert!(!can_read(&g), "kilitliyken okuma RED");
        activate_after_production(&mut g, true);
        assert!(can_read(&g), "üretim doğrulandı → Active");
        let mut g2 = lock_payment([1u8; 32], [2u8; 32], 1000);
        activate_after_production(&mut g2, false);
        assert_eq!(g2.state, GrantState::Refunded, "üretim başarısız → iade");
        assert!(!can_read(&g2));
    }

    #[test]
    fn y16_whitelist_kapisi() {
        assert!(is_whitelisted("N_bekci"));
        assert!(is_whitelisted("tiny_object_threshold"));
        assert!(gate_param_added("recipe_bounty_orani"));
        assert!(!gate_param_added("gizli_parametre"), "whitelist'siz → RED");
        // aktivasyon gecikmeleri
        assert_eq!(activation_delay(ActivationClass::Parameter), 10);
        assert_eq!(activation_delay(ActivationClass::Policy), 20);
        assert_eq!(activation_delay(ActivationClass::Targeted), 5);
    }

    #[test]
    fn y0_baglanti_envanteri() {
        assert_eq!(wiring_inventory("proof_market", 0, false).0, WiringStatus::Unwired);
        assert_eq!(wiring_inventory("provider", 5, true).0, WiringStatus::Wired);
        assert_eq!(wiring_inventory("assignment", 3, false).0, WiringStatus::Stub);
        assert!(wiring_inventory("provider", 5, true).1);
    }

    #[test]
    fn gov_deterministik() {
        let g = lock_payment([1u8; 32], [2u8; 32], 100);
        assert_eq!(gov_digest(&g), gov_digest(&g));
    }
}
