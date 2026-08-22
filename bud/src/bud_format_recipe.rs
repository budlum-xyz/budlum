//! B.U.D. 2.0 - TARİF MADENCİLİĞİ + TARİF-MAKİNESİ SINIRI (fikirler3.0 Y2/Y15)
//!
//! Y2: Organik (rezidüel) bir PACT için bit-birebir kısa tarif bulan taraf ödül alır
//! (bayt-bütçesi azalır). Bu modül: tarif adayı kaydı + doğrulama + dürüstlük sınırı.
//! DÜRÜSTLÜK: tarif madenciliği zor problemdir (Kolmogorov); ödül boş kalabilir -
//! bu mimariyi bozmaz (sahip-yolu İ12 zaten çalışır). Aday doğrulama maliyeti <
//! rezidüel tasarruf şartı canary ile izlenir.
//!
//! Y15: BudZero aralık makinesi kurulana kadar üretim tarifleri integer-only +
//! checked/saturating ile sınırlıdır; tarif adayı kapısında "aralık-makinesi
//! gerektiren opcode" taraması yapılır (varsa RED).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const RECIPE_MAGIC: [u8; 8] = *b"\xB5RCP1\0\0\0";

/// Y15: aralık-makinesi gerektiren opcode'lar (float/bölme - integer-only yasak).
const FORBIDDEN_OPS: &[&str] = &["fdiv", "fadd", "fmul", "fsqrt", "fpow", "float", "div"];

/// Tarif adayı (Y2): madenci, tarif + tohum + dönüşüm kanıtı yayınlar.
#[derive(Debug, Clone)]
pub struct RecipeCandidate {
    pub miner: [u8; 32],
    pub pact_id: [u8; 32], // hedef PACT (commitment)
    pub recipe: Vec<u8>,   // tarif (opcode listesi - integer-only)
    pub seed: [u8; 32],    // üretim tohumu
}

impl RecipeCandidate {
    /// Y15: tarif integer-only mı? (aralık-makinesi opcode yasak)
    pub fn integer_only(&self) -> bool {
        let txt = String::from_utf8_lossy(&self.recipe).to_lowercase();
        !FORBIDDEN_OPS.iter().any(|op| txt.contains(op))
    }

    /// Y2: aday doğrulama - tarif+tohum ile üretilen baytlar commitment'a eşit mi?
    pub fn verify(&self, produced: &[u8], commitment: &[u8; 32]) -> bool {
        if !self.integer_only() {
            return false; // Y15 sınırı
        }
        let cid = crate::bud_format_container::content_id(produced);
        &cid == commitment
    }
}

/// Ödül: tasarruf edilen bayt-bütçesinin sabit oranı (varsayılan %20, yönetişim).
pub const RECIPE_BOUNTY_RATIO: f64 = 0.20;

/// Bayt-bütçe tasarrufu: eski rezidüel boyut - yeni (tarif+tohum) boyut.
pub fn budget_saving(old_residual: u64, new_recipe_bytes: u64) -> u64 {
    old_residual.saturating_sub(new_recipe_bytes)
}

/// Ödül hesabı: tasarrufun oranı (canary: tasarruf > doğrulama maliyeti şartı).
pub fn bounty(new_residual: u64, old_residual: u64, verify_cost: u64) -> Option<u64> {
    let saving = budget_saving(old_residual, new_residual);
    if saving <= verify_cost {
        return None; // doğrulama maliyeti tasarrufu yerse ödül yok (dürüst)
    }
    Some((saving as f64 * RECIPE_BOUNTY_RATIO).round() as u64)
}

pub fn recipe_digest(c: &RecipeCandidate) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(RECIPE_MAGIC);
    h.update(c.miner);
    h.update(c.pact_id);
    h.update(&c.recipe);
    h.update(c.seed);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn y15_integer_only_sinir() {
        let ok = RecipeCandidate {
            miner: [1u8; 32],
            pact_id: [2u8; 32],
            recipe: b"load add store loop".to_vec(),
            seed: [3u8; 32],
        };
        assert!(ok.integer_only());
        let bad = RecipeCandidate {
            miner: [1u8; 32],
            pact_id: [2u8; 32],
            recipe: b"fdiv load".to_vec(),
            seed: [3u8; 32],
        };
        assert!(!bad.integer_only(), "aralık-makinesi opcode → RED");
    }

    #[test]
    fn y2_aday_dogrulama() {
        let data = b"organik nesne icerigi ";
        let cid = crate::bud_format_container::content_id(data);
        let c = RecipeCandidate {
            miner: [1u8; 32],
            pact_id: cid,
            recipe: b"load store".to_vec(),
            seed: [0u8; 32],
        };
        assert!(c.verify(data, &cid), "doğru üretim → kabul");
        assert!(!c.verify(b"yanlis", &cid), "yanlış → RED");
        // Y15: float tarif her zaman RED (üretim doğru olsa bile)
        let bad = RecipeCandidate {
            miner: [1u8; 32],
            pact_id: cid,
            recipe: b"fmul".to_vec(),
            seed: [0u8; 32],
        };
        assert!(!bad.verify(data, &cid));
    }

    #[test]
    fn y2_odul_durust_sinir() {
        // tasarruf 1000, doğrulama 100 → ödül %20 = 200
        assert_eq!(bounty(0, 1000, 100).unwrap(), 200);
        // doğrulama tasarrufu yerse → None
        assert!(bounty(0, 50, 100).is_none());
        assert!(bounty(500, 400, 0).is_none() || bounty(500, 400, 0) == Some(0));
        // tasarruf yok
    }

    #[test]
    fn digest_deterministik() {
        let c = RecipeCandidate {
            miner: [1u8; 32],
            pact_id: [2u8; 32],
            recipe: b"load".to_vec(),
            seed: [3u8; 32],
        };
        assert_eq!(recipe_digest(&c), recipe_digest(&c));
    }

    #[test]
    fn y15_yasak_opcodelar_kapsar() {
        for op in FORBIDDEN_OPS {
            let c = RecipeCandidate {
                miner: [0u8; 32],
                pact_id: [0u8; 32],
                recipe: op.as_bytes().to_vec(),
                seed: [0u8; 32],
            };
            assert!(!c.integer_only(), "{op} yasak olmalı");
        }
    }
}
