//! D2 (2026-07-22): Privacy-layer note/UTXO model — paralel izole subtree.
//!
//! Account model'e DOKUNMADAN, ayrı bir state alanında yaşar (gizlilik talimatı
//! Bölüm 7 izolasyon kuralı). NFT / B.U.D. / Pollen state'i ile paylaşılmaz.
//!
//! Commitment + nullifier primitifleri (Bölüm 4):
//! - commitment = Poseidon(amount || recipient || blinding) — zincire yalnızca
//!   bu hash yazılır; amount/recipient gizli.
//! - nullifier = Poseidon(secret) — harcanan commitment'ı işaretleyen tek-
//!   kullanımlık değer; hangi commitment'ın harcandığını açıklamadan çifte-
//!   harcamayı önler.
//!
//! Sum-conservation (Σinputs == Σoutputs, homomorfik) opcode/constraint
//! seviyesinde kanıtlanır (D2 opcode 0x22); bu registry yalnızca note
//! yaşam-döngüsünü ve nullifier set'ini tutar.

use crate::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Bir gizli transfer notu. `commitment` amount+recipient+blinding'i bağlar
/// (Poseidon); `nullifier` tek-kullanımlık harcama işaretidir (Poseidon(secret)).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyNote {
    pub commitment: Hash,
    pub nullifier: Hash,
}

/// İzole note registry: account model'e paralel, NFT/B.U.D./Pollen ile state
/// paylaşmaz (Bölüm 7). Canlı (harcanmamış) commitment'lar + harcanmış
/// nullifier set'ini izler.
#[derive(Debug, Clone, Default)]
pub struct NoteRegistry {
    /// Canlı (harcanmamış) note commitment'ları.
    notes: BTreeSet<Hash>,
    /// Harcanmış nullifier'lar — çifte-harcama önleme.
    spent_nullifiers: BTreeSet<Hash>,
}

impl NoteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Yeni oluşturulmuş note commitment'ı ekle. Duplikat commitment veya
    /// halihazırda harcanmış nullifier reddedilir.
    pub fn insert(&mut self, note: &PrivacyNote) -> Result<(), String> {
        if self.notes.contains(&note.commitment) {
            return Err("note commitment already exists".into());
        }
        if self.spent_nullifiers.contains(&note.nullifier) {
            return Err("note nullifier already spent".into());
        }
        self.notes.insert(note.commitment);
        Ok(())
    }

    /// Bir note'u nullifier ile harca: nullifier halihazırda harcanmışsa RED
    /// (çifte-harcama önleme). Commitment canlı set'ten çıkarılır, nullifier
    /// spent set'e eklenir. Harcanan commitment KAMUYA açıklanmaz — çağıran
    /// sum-conservation constraint ile mülkiyeti kanıtlar.
    pub fn spend(&mut self, nullifier: Hash, commitment: Hash) -> Result<(), String> {
        if self.spent_nullifiers.contains(&nullifier) {
            return Err("double-spend: nullifier already spent".into());
        }
        if !self.notes.remove(&commitment) {
            return Err("spend: commitment not found in live note set".into());
        }
        self.spent_nullifiers.insert(nullifier);
        Ok(())
    }

    /// Nullifier halihazırda harcanmış mı (nullifier-check opcode 0x21 için).
    pub fn is_spent(&self, nullifier: Hash) -> bool {
        self.spent_nullifiers.contains(&nullifier)
    }

    /// Commitment canlı (harcanmamış) set'te mi.
    pub fn contains(&self, commitment: Hash) -> bool {
        self.notes.contains(&commitment)
    }

    pub fn live_count(&self) -> usize {
        self.notes.len()
    }

    pub fn spent_count(&self) -> usize {
        self.spent_nullifiers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash {
        let mut x = [0u8; 32];
        x[0] = b;
        x
    }

    #[test]
    fn insert_and_spend_round_trip() {
        let mut r = NoteRegistry::new();
        let note = PrivacyNote {
            commitment: h(1),
            nullifier: h(2),
        };
        r.insert(&note).unwrap();
        assert!(r.contains(h(1)));
        assert!(!r.is_spent(h(2)));
        assert_eq!(r.live_count(), 1);

        r.spend(h(2), h(1)).unwrap();
        assert!(r.is_spent(h(2)));
        assert!(!r.contains(h(1))); // canlı set'ten çıktı
        assert_eq!(r.live_count(), 0);
        assert_eq!(r.spent_count(), 1);
    }

    #[test]
    fn double_spend_rejected() {
        let mut r = NoteRegistry::new();
        r.insert(&PrivacyNote {
            commitment: h(1),
            nullifier: h(2),
        })
        .unwrap();
        r.spend(h(2), h(1)).unwrap();
        // Aynı nullifier tekrar harcama → RED (çifte-harcama).
        let err = r.spend(h(2), h(1)).unwrap_err();
        assert!(err.contains("double-spend"));
    }

    #[test]
    fn duplicate_commitment_rejected() {
        let mut r = NoteRegistry::new();
        r.insert(&PrivacyNote {
            commitment: h(1),
            nullifier: h(2),
        })
        .unwrap();
        // Aynı commitment, farklı nullifier → RED.
        assert!(r
            .insert(&PrivacyNote {
                commitment: h(1),
                nullifier: h(3)
            })
            .is_err());
    }

    #[test]
    fn already_spent_nullifier_on_insert_rejected() {
        let mut r = NoteRegistry::new();
        r.insert(&PrivacyNote {
            commitment: h(1),
            nullifier: h(2),
        })
        .unwrap();
        r.spend(h(2), h(1)).unwrap();
        // Halihazırda harcanmış nullifier ile yeni note → RED.
        assert!(r
            .insert(&PrivacyNote {
                commitment: h(9),
                nullifier: h(2)
            })
            .is_err());
    }

    #[test]
    fn spend_unknown_commitment_rejected() {
        let mut r = NoteRegistry::new();
        let err = r.spend(h(2), h(99)).unwrap_err();
        assert!(err.contains("not found"));
    }
}
