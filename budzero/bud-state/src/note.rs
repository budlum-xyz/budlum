//! Privacy-layer note/UTXO model - paralel izole subtree.
//!
//! Account model'e DOKUNMADAN, ayrı bir state alanında yaşar (gizlilik talimatı
//! Bölüm 7 izolasyon kuralı). NFT / B.U.D. / Pollen state'i ile paylaşılmaz.
//!
//! Commitment + nullifier primitifleri:
//! - commitment = Poseidon(amount || recipient || blinding), zincire yalnızca
//!   Bu hash yazılır; amount/recipient gizli.
//! - nullifier = Poseidon(secret) - harcanan commitment'ı işaretleyen tek-
//!   Kullanımlık değer; hangi commitment'ın harcandığını açıklamadan çifte-
//!   Harcamayı önler.
//!
//! Sum-conservation (Σinputs == Σoutputs, homomorfik) opcode/constraint
//! Seviyesinde kanıtlanır (opcode 0x22); bu registry yalnızca note
//! Yaşam-döngüsünü ve nullifier set'ini tutar.
//!
//! WIRING: unwired - measured. Zincirin harcanmış nullifier kümesi
//! `src/privacy/note_registry.rs` içindeki `L1NoteRegistry`, ve üretimde
//! çalışan o: `AccountState` onu tutuyor, `account.rs:2117` state-root'a
//! karıştırıyor, `snapshot.rs` anlık görüntüye yazıyor. Buradaki
//! `NoteRegistry` aynı kümenin zkVM tarafındaki ikizi ve hiçbir üretim yolu
//! onu kurmuyor: `bud-state`'i yalnız `bud-cli` bağımlılık olarak alıyor ve
//! oradan da sadece `State`, `StateBackend`, `Account` okunuyor.
//!
//! Eksik olan halka bir çağrı değil, bir opcode. Doküman bu tipi
//! "nullifier-check opcode 0x21 için" diye tarif ediyor, ama `bud-vm`'deki
//! `NullifierCheck` bir nullifier'ı yalnızca Poseidon ile TÜRETİP iddia
//! edilenle karşılaştırıyor; harcanmış olup olmadığını hiçbir kümeye
//! sormuyor. Yani VM "bu nullifier bu sırra ait mi" sorusunu cevaplıyor,
//! "bu nullifier daha önce harcandı mı" sorusunu değil. İkinci soruyu bugün
//! yalnız zincir tarafı cevaplıyor.
//!
//! Bu modülün kablolanması opcode'a devlet erişimi vermeyi gerektirir, ki o
//! bir konsensüs yüzeyi kararıdır: VM'nin çifte harcamayı kendi başına
//! reddetmesi, kanıt sisteminin nullifier kümesini de taahhüt etmesi
//! demektir. O karar verilene kadar buradaki tip ölü değil, erken.

use crate::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Bir gizli transfer notu. `commitment` amount+recipient+blinding'i bağlar
/// (Poseidon); `nullifier` tek-kullanımlık harcama işaretidir
/// (Poseidon(secret, DOMAIN_NULLIFIER)).
///
/// VM/AIR tarafı Goldilocks field element (u64) üretir; registry 32-byte Hash
/// Saklar. `hash_from_field` / `field_from_hash` köprüsü little-endian packing
/// Kullanır (üst 24 byte sıfır - domain'ler arası çakışma riski yok çünkü
/// Note subtree izole).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyNote {
    pub commitment: Hash,
    pub nullifier: Hash,
}

// The packing is defined in `budlum-note-packing` and re-exported here, so
// the names this module has always exported keep working while there is only
// one definition left. The wallet computes the nullifier the chain looks up;
// if the two ever packed differently the lookup would miss and the note would
// be spendable twice, which no test inside either crate could see.
pub use budlum_note_packing::{field_from_hash, hash_from_field, is_packed};

impl PrivacyNote {
    /// Construct from VM/AIR field elements (Poseidon outputs).
    #[must_use]
    pub fn from_field_elements(commitment_fe: u64, nullifier_fe: u64) -> Self {
        Self {
            commitment: hash_from_field(commitment_fe),
            nullifier: hash_from_field(nullifier_fe),
        }
    }
}

/// İzole note registry: account model'e paralel, NFT/B.U.D./Pollen ile state
/// Paylaşmaz. Canlı (harcanmamış) commitment'lar + harcanmış
/// Nullifier set'ini izler.
#[derive(Debug, Clone, Default)]
pub struct NoteRegistry {
    /// Canlı (harcanmamış) note commitment'ları.
    notes: BTreeSet<Hash>,
    /// Harcanmış nullifier'lar - çifte-harcama önleme.
    spent_nullifiers: BTreeSet<Hash>,
}

impl NoteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Yeni oluşturulmuş note commitment'ı ekle. Duplikat commitment veya
    /// Halihazırda harcanmış nullifier reddedilir.
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
    /// Spent set'e eklenir. Harcanan commitment KAMUYA açıklanmaz, çağıran
    /// Sum-conservation constraint ile mülkiyeti kanıtlar.
    /// PARTIAL: allowed - the `remove` here *is* the liveness check. It
    /// returns false when the commitment was never live, and that branch has
    /// removed nothing; the branch that removed something cannot then refuse.
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

    #[test]
    fn field_element_packing_roundtrip_and_registry() {
        let commitment_fe = 0xC0FFEEu64;
        let nullifier_fe = 0xBEEFu64;
        let note = PrivacyNote::from_field_elements(commitment_fe, nullifier_fe);
        assert_eq!(field_from_hash(&note.commitment), commitment_fe);
        assert_eq!(field_from_hash(&note.nullifier), nullifier_fe);
        // High bytes must be zero (domain isolation).
        assert!(note.commitment[8..].iter().all(|&b| b == 0));
        let mut r = NoteRegistry::new();
        r.insert(&note).unwrap();
        assert!(r.contains(note.commitment));
        r.spend(note.nullifier, note.commitment).unwrap();
        assert!(r.is_spent(note.nullifier));
    }
}
