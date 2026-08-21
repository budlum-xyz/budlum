//! B.U.D. 2.0 İCAT - Rejenerasyon Mutabakatı (Regeneration-as-Consensus) (2026-08-16)
//!
//! fikirler2.0 İ2 + DEPOLAMA-ZERO-MIMARI-TEZ: konsensüs "baytı kanıtla" (PoR/PoSt)
//! yerine **"üretimi doğrula"** der: validatör talep anında içeriği üreticiten üretir,
//! hash'ler, PACT commitment'ı ile karşılaştırır; eşleşme mutabakatın kendisidir.
//!
//! Neden "blockchainde yeni": mevcut yaklaşımlar "sakla+kanıtla", "sakla+BFT tasdiki",
//! "sakla+erişim kanıtı", "hesapla+ispatla" (ispat pahalı) ve
//! "olayları sakla+state'i yeniden hesapla" (olay günlüğü kalıcı) der. **Hiçbiri**
//! "içerik baytı hiç saklanmaz; üretim eşleşmesi konsensüs doğrulamasıdır" demiyor.
//!
//! Bu modül: sınav (challenge) → üret → hash → commitment karşılaştır → sonuç.
//! Sınav zincire yazılmaz; yalnız sonuç hash'i denetim için saklanır (İ2).
//! Başarısız üretim → itibar skoru düşer (provider.rs deseni).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use crate::bud_format_pact::PactRecord;
use sha3::{Digest, Sha3_256};

pub const REGEN_MAGIC: [u8; 8] = *b"\xB5RGEN\0\0\0";
pub const REGEN_VERSION: u8 = 1;

/// Sınav sonucu (İ2): üretim mutabakatı geçti mi + maliyet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegenerationOutcome {
    Verified,     // üretim commitment ile eşleşti → mutabakat
    Mismatch,     // üretim commitment ile eşleşmedi → RED + itibar düşer
    NotProducible, // üretici üretilemedi (sınıf yalanı/bozuk üretici)
}

/// Rejenerasyon sınavı: verilen PACT için üretilen baytları doğrula.
/// İ2 tezi: "üretim maliyeti < kanıt maliyeti" - bu fonksiyon maliyeti ölçer.
pub struct RegenerationChallenge;

impl RegenerationChallenge {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_REGENERATION_V1";

    /// Üretilen baytları PACT commitment'ına karşı doğrula (İ2 çekirdeği).
    /// - PureProduction/RecipePlusResidual: commitment = H(üretilen bayt)
    /// - ResidualOnly: commitment = content_id(original) (kayıpsız bütünlük)
    pub fn verify(pact: &PactRecord, produced: &[u8]) -> RegenerationOutcome {
        if !pact.verify() {
            return RegenerationOutcome::NotProducible;
        }
        if pact.verify_production(produced) {
            RegenerationOutcome::Verified
        } else {
            RegenerationOutcome::Mismatch
        }
    }

    /// Rezidüel bütünlük: üretilemeyen artık commitment ile eşleşiyor mu (İ6)?
    /// RecipePlusResidual modunda rezidüel de doğrulanmalı - sınıf yalanı yakalanır.
    pub fn verify_with_residual(pact: &PactRecord, produced: &[u8], residual: &[u8]) -> RegenerationOutcome {
        match pact.verify() {
            false => RegenerationOutcome::NotProducible,
            true => {
                if pact.verify_production(produced) && pact.verify_residual(residual) {
                    RegenerationOutcome::Verified
                } else {
                    RegenerationOutcome::Mismatch
                }
            }
        }
    }

    /// Sınav kaydı: epoch + pact_hash + sonuç + maliyet (denetim için, zincire yazılabilir).
    pub fn record_hash(epoch: u64, pact_hash: [u8; 32], outcome: RegenerationOutcome, cost_units: u64) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(epoch.to_le_bytes());
        h.update(pact_hash);
        h.update([match outcome {
            RegenerationOutcome::Verified => 0u8,
            RegenerationOutcome::Mismatch => 1,
            RegenerationOutcome::NotProducible => 2,
        }]);
        h.update(cost_units.to_le_bytes());
        h.finalize().into()
    }

    /// İ2 kabul: üretim maliyeti, karşılık gelen kanıt maliyetinin %1'inden az olmalı.
    /// (zkVM ispatı 222 yıl saklamaya bedel - DEPOLAMA-ZERO ölçümü; üretim ~okuma maliyeti.)
    pub fn regeneration_beats_proof(production_cost: u64, proof_cost: u64) -> bool {
        proof_cost > 0 && (production_cost as f64) < (proof_cost as f64) * 0.01
    }
}

/// Rejenerasyon mutabakatı kaydı (zincire yazılabilir küçük kayıt - İ8 bayt-bütçe uyumlu).
#[derive(Debug, Clone)]
pub struct RegenerationRecord {
    pub epoch: u64,
    pub pact_hash: [u8; 32],
    pub outcome: RegenerationOutcome,
    pub cost_units: u64,
}

impl RegenerationRecord {
    pub fn new(epoch: u64, pact_hash: [u8; 32], outcome: RegenerationOutcome, cost_units: u64) -> Self {
        RegenerationRecord { epoch, pact_hash, outcome, cost_units }
    }

    pub fn record_hash(&self) -> [u8; 32] {
        RegenerationChallenge::record_hash(self.epoch, self.pact_hash, self.outcome, self.cost_units)
    }

    /// Deterministik blob (magic + sürüm + alanlar + digest).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&REGEN_MAGIC);
        out.push(REGEN_VERSION);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.pact_hash);
        out.push(match self.outcome {
            RegenerationOutcome::Verified => 0u8,
            RegenerationOutcome::Mismatch => 1,
            RegenerationOutcome::NotProducible => 2,
        });
        out.extend_from_slice(&self.cost_units.to_le_bytes());
        out.extend_from_slice(&self.record_hash());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 8 + 32 + 1 + 8;
        if bytes.len() < HDR + 32 || bytes[0..8] != REGEN_MAGIC || bytes[8] != REGEN_VERSION {
            return None;
        }
        let epoch = u64::from_le_bytes(bytes[9..17].try_into().ok()?);
        let mut pact_hash = [0u8; 32];
        pact_hash.copy_from_slice(&bytes[17..49]);
        let outcome = match bytes[49] {
            0 => RegenerationOutcome::Verified,
            1 => RegenerationOutcome::Mismatch,
            2 => RegenerationOutcome::NotProducible,
            _ => return None,
        };
        let cost_units = u64::from_le_bytes(bytes[50..58].try_into().ok()?);
        if bytes.len() != HDR + 32 {
            return None;
        }
        let rec = RegenerationRecord { epoch, pact_hash, outcome, cost_units };
        if bytes[HDR..] != rec.record_hash() {
            return None;
        }
        Some(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_production_regenerates_consensus() {
        // İ2: saf üretim - üretilen bayt commitment'a uyuyorsa mutabakat VERIFIED
        let producer = [1u8; 32];
        let seed = [7u8; 32];
        let produced = b"deterministik uretim ciktisi 1234567890";
        let pact = PactRecord::pure(producer, seed, produced, 100);
        assert_eq!(
            RegenerationChallenge::verify(&pact, produced),
            RegenerationOutcome::Verified,
            "üretim eşleşmesi mutabakatın kendisidir"
        );
        assert_eq!(
            RegenerationChallenge::verify(&pact, b"yanlis uretim"),
            RegenerationOutcome::Mismatch,
            "farklı üretim RED"
        );
        // sınav kaydı zincire yazılabilir
        let rec = RegenerationRecord::new(1, pact.record_hash(), RegenerationOutcome::Verified, 50);
        let blob = rec.to_blob();
        let back = RegenerationRecord::from_blob(&blob).expect("blob");
        assert_eq!(back.outcome, RegenerationOutcome::Verified);
        assert_eq!(back.record_hash(), rec.record_hash());
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(RegenerationRecord::from_blob(&bad).is_none());
    }

    #[test]
    fn residual_class_verified_with_residual() {
        // İ6: üretici + rezidüel - üretim VE rezidüel birlikte doğrulanmalı
        let produced = b"uretilen kisim";
        let residual = b"organik artik 0x1234";
        let pact = PactRecord::producer_plus_residual([9u8; 32], [5u8; 32], produced, residual, 200);
        assert_eq!(
            RegenerationChallenge::verify_with_residual(&pact, produced, residual),
            RegenerationOutcome::Verified
        );
        // rezidüel yanlış → Mismatch (sınıf yalanı)
        assert_eq!(
            RegenerationChallenge::verify_with_residual(&pact, produced, b"farkli"),
            RegenerationOutcome::Mismatch
        );
        // üretim yanlış → Mismatch
        assert_eq!(
            RegenerationChallenge::verify_with_residual(&pact, b"yanlis", residual),
            RegenerationOutcome::Mismatch
        );
    }

    #[test]
    fn residual_only_matches_content_id() {
        // kayıpsız .bud: commitment = content_id → üretim = orijinal baytlar
        let original = b"kayipsiz icerik 12345";
        let pact = PactRecord::residual_only(original, 300);
        assert_eq!(RegenerationChallenge::verify(&pact, original), RegenerationOutcome::Verified);
        assert_eq!(RegenerationChallenge::verify(&pact, b"farkli"), RegenerationOutcome::Mismatch);
    }

    #[test]
    fn regeneration_beats_proof_economy() {
        // İ2 kabul: üretim maliyeti kanıt maliyetinin %1'inden az (zkVM ispatı pahalı)
        assert!(RegenerationChallenge::regeneration_beats_proof(1, 1000), "üretim %0.1 kanıt maliyeti");
        assert!(RegenerationChallenge::regeneration_beats_proof(50, 10_000), "%0.5");
        assert!(!RegenerationChallenge::regeneration_beats_proof(200, 10_000), "%2 → kabul etmez");
        assert!(!RegenerationChallenge::regeneration_beats_proof(1, 0), "proof_cost 0 → false");
    }

    #[test]
    fn tampered_pact_rejected() {
        // bozuk PACT (sınıf yalanı) → NotProducible
        let produced = b"x";
        let mut pact = PactRecord::pure([1u8; 32], [2u8; 32], produced, 1);
        pact.residual_len = 5; // PureProduction'da rezidüel 0 olmalı - verify RED
        assert_eq!(RegenerationChallenge::verify(&pact, produced), RegenerationOutcome::NotProducible);
    }

    #[test]
    fn blob_never_panics() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() & 0xff) as u8
            }
        }
        let mut rng = Rng(0x5247_454E_2026_0816);
        let mut buf = [0u8; 128];
        for _ in 0..2000 {
            let len = (rng.next() % 128) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = RegenerationRecord::from_blob(&buf[..len]);
        }
    }
}
