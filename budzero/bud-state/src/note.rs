//! Privacy-layer note/UTXO model - paralel izole subtree.
//!
//! It lives in a separate state area without touching the account model, and is
//! not shared with NFT / B.U.D. / Pollen state.
//!
//! Commitment + nullifier primitifleri:
//! - commitment = Poseidon(amount || recipient || blinding); only this hash is
//!   written to the chain; amount/recipient stay secret.
//! - nullifier = Poseidon(secret) - a single use value marking the spent
//!   commitment; it prevents double spending without revealing which
//!   commitment was spent.
//!
//! Sum-conservation (Σinputs == Σoutputs, homomorfik) opcode/constraint
//! level (opcode 0x22); this registry only holds the note lifecycle and the
//! nullifier set.

//!
//! The missing link is not a call but an opcode. The document describes this
//! type as "for the nullifier-check opcode 0x21", but `NullifierCheck` in
//! `bud-vm` only DERIVES a nullifier with Poseidon and compares it against the
//! claimed one; it asks no set whether it has been spent. So the VM answers
//! the question "does this nullifier belong to this secret", not the question
//! "was this nullifier spent before". Today only the chain side answers the
//! second question.
//!
//! Wiring this module requires giving the opcode state access, which is a
//! consensus surface decision: the VM refusing a double spend on its own means
//! the proof system commits to the nullifier set as well. Until that decision
//! is made the type here is not dead but early.

use crate::Hash;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A private transfer note. `commitment` binds amount+recipient+blinding
/// (Poseidon); `nullifier` is the single use spend marker
/// (Poseidon(secret, DOMAIN_NULLIFIER)).
///
/// The VM/AIR side produces a Goldilocks field element (u64); the registry stores a
/// 32 byte Hash. The `hash_from_field` / `field_from_hash` bridge uses little-endian
/// packing (the upper 24 bytes are zero - there is no cross domain collision risk because
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
pub use budlum_note_packing::{
    field_from_hash, hash_from_field, is_packed, note_commitment_v2, note_nullifier_v2, Digest4,
    HashSuiteId, SuiteTaggedCommitment,
};

impl PrivacyNote {
    /// Construct from VM/AIR field elements (Poseidon outputs).
    #[must_use]
    pub fn from_field_elements(commitment_fe: u64, nullifier_fe: u64) -> Self {
        Self {
            commitment: hash_from_field(commitment_fe),
            nullifier: hash_from_field(nullifier_fe),
        }
    }

    /// Construct a V2 256-bit privacy note from suite-tagged Poseidon
    /// commitments, refusing unknown/non-Poseidon suites, all-zero digests,
    /// non-canonical limbs, or 64-bit single-limb truncated digests.
    pub fn from_suite_tagged(
        commitment: &SuiteTaggedCommitment,
        nullifier: &SuiteTaggedCommitment,
    ) -> Result<Self, String> {
        if commitment.suite != HashSuiteId::PoseidonG12V1
            || nullifier.suite != HashSuiteId::PoseidonG12V1
        {
            return Err("V2 privacy note requires PoseidonG12V1 commitments".into());
        }
        let c_d4 = Digest4::from_bytes_checked(&commitment.digest)
            .ok_or_else(|| "V2 commitment contains non-canonical Goldilocks limb".to_string())?;
        if c_d4.is_zero() || c_d4.is_single_limb_truncated() {
            return Err("V2 commitment must be a full non-zero 256-bit Digest4".into());
        }
        let n_d4 = Digest4::from_bytes_checked(&nullifier.digest)
            .ok_or_else(|| "V2 nullifier contains non-canonical Goldilocks limb".to_string())?;
        if n_d4.is_zero() || n_d4.is_single_limb_truncated() {
            return Err("V2 nullifier must be a full non-zero 256-bit Digest4".into());
        }
        if commitment.digest == nullifier.digest {
            return Err("V2 commitment and nullifier must be distinct".into());
        }
        Ok(Self {
            commitment: commitment.digest,
            nullifier: nullifier.digest,
        })
    }

    /// Derive a V2 256-bit privacy note using the single shared
    /// `budlum-note-packing` commitment and nullifier functions.
    pub fn derive_v2(
        amount: u64,
        blinding: [u64; 2],
        recipient: &[u8; 32],
        spend_secret: [u64; 4],
    ) -> Result<Self, String> {
        let commitment = note_commitment_v2(amount, blinding, recipient)
            .ok_or_else(|| "invalid inputs for V2 note commitment".to_string())?;
        let nullifier = note_nullifier_v2(spend_secret, &commitment)
            .ok_or_else(|| "invalid inputs for V2 note nullifier".to_string())?;
        Self::from_suite_tagged(&commitment, &nullifier)
    }
}

/// An isolated note registry: parallel to the account model, it shares no state with
/// NFT/B.U.D./Pollen. Tracks the live (unspent) commitments plus the spent
/// nullifier set.
#[derive(Debug, Clone, Default)]
pub struct NoteRegistry {
    /// The live (unspent) note commitments.
    /// Live commitment -> the nullifier that spends it.
    notes: BTreeMap<Hash, Hash>,
    /// The spent nullifiers - double spend prevention.
    spent_nullifiers: BTreeSet<Hash>,
}

impl NoteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a newly created note commitment. A duplicate commitment or an already
    /// spent nullifier is refused.
    pub fn insert(&mut self, note: &PrivacyNote) -> Result<(), String> {
        if self.notes.contains_key(&note.commitment) {
            return Err("note commitment already exists".into());
        }
        // Two live notes with one nullifier: the first spend would make the
        // second unspendable.
        if self.notes.values().any(|n| n == &note.nullifier) {
            return Err("note nullifier already belongs to a live note".into());
        }
        if self.spent_nullifiers.contains(&note.nullifier) {
            return Err("note nullifier already spent".into());
        }
        self.notes.insert(note.commitment, note.nullifier);
        Ok(())
    }

    /// Spend a note with a nullifier: REFUSED if the nullifier is already spent
    /// (double spend prevention). The commitment leaves the live set, the nullifier
    /// joins the spent set. The spent commitment is NOT revealed publicly; the caller
    /// proves ownership with the sum conservation constraint.
    /// PARTIAL: allowed - the `remove` here *is* the liveness check. It
    /// returns false when the commitment was never live, and that branch has
    /// removed nothing; the branch that removed something cannot then refuse.
    pub fn spend(&mut self, nullifier: Hash, commitment: Hash) -> Result<(), String> {
        if self.spent_nullifiers.contains(&nullifier) {
            return Err("double-spend: nullifier already spent".into());
        }
        match self.notes.get(&commitment) {
            None => return Err("spend: commitment not found in live note set".into()),
            // The nullifier must be the one this note was created with.
            Some(bound) if *bound != nullifier => {
                return Err("spend: nullifier does not belong to this commitment".into())
            }
            Some(_) => {}
        }
        self.notes.remove(&commitment);
        self.spent_nullifiers.insert(nullifier);
        Ok(())
    }

    /// Has the nullifier already been spent (for the nullifier-check opcode 0x21).
    pub fn is_spent(&self, nullifier: Hash) -> bool {
        self.spent_nullifiers.contains(&nullifier)
    }

    /// Is the commitment in the live (unspent) set.
    pub fn contains(&self, commitment: Hash) -> bool {
        self.notes.contains_key(&commitment)
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
        assert!(!r.contains(h(1))); // it left the live set
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
        // Spending with the same nullifier again -> REFUSED (double spend).
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
        // The same commitment, a different nullifier -> REFUSED.
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
        // A new note with an already spent nullifier -> REFUSED.
        assert!(r
            .insert(&PrivacyNote {
                commitment: h(9),
                nullifier: h(2)
            })
            .is_err());
    }

    /// A nullifier cannot spend a commitment it was not created with.
    #[test]
    fn spend_with_a_foreign_nullifier_rejected() {
        let mut r = NoteRegistry::new();
        r.insert(&PrivacyNote {
            commitment: h(1),
            nullifier: h(2),
        })
        .unwrap();
        let err = r.spend(h(7), h(1)).unwrap_err();
        assert!(err.contains("does not belong"));
        assert!(r.contains(h(1)));
        assert!(!r.is_spent(h(7)));
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

    #[test]
    fn note_registry_binds_nullifier_to_commitment() {
        let mut r = NoteRegistry::new();
        let victim = PrivacyNote::from_field_elements(0x1111, 0x2222);
        let attacker = PrivacyNote::from_field_elements(0x3333, 0x4444);
        assert!(r.insert(&victim).is_ok());
        assert!(r.insert(&attacker).is_ok());
        assert!(r.spend(attacker.nullifier, victim.commitment).is_err());
        assert!(!r.is_spent(attacker.nullifier));
        assert!(r.spend(victim.nullifier, victim.commitment).is_ok());
        assert!(r.is_spent(victim.nullifier));
    }

    #[test]
    fn v2_256bit_note_lifecycle_and_fail_closed_refusals() {
        let recipient = [0x42u8; 32];
        let blinding = [101, 202];
        let secret = [7, 8, 9, 10];
        let note = PrivacyNote::derive_v2(500, blinding, &recipient, secret)
            .expect("valid V2 256-bit note");

        // Must match the exact shared `budlum-note-packing` derivation.
        let expected_c = note_commitment_v2(500, blinding, &recipient).unwrap();
        let expected_n = note_nullifier_v2(secret, &expected_c).unwrap();
        assert_eq!(note.commitment, expected_c.digest);
        assert_eq!(note.nullifier, expected_n.digest);

        let mut reg = NoteRegistry::new();
        reg.insert(&note).unwrap();
        assert!(reg.contains(note.commitment));
        reg.spend(note.nullifier, note.commitment).unwrap();
        assert!(reg.is_spent(note.nullifier));
        assert!(reg.spend(note.nullifier, note.commitment).is_err());

        // All-zero, truncated 64-bit, and non-Poseidon suite commitments must fail closed.
        let zero = SuiteTaggedCommitment {
            suite: HashSuiteId::PoseidonG12V1,
            digest: [0u8; 32],
        };
        assert!(PrivacyNote::from_suite_tagged(&zero, &expected_n).is_err());

        let truncated = SuiteTaggedCommitment {
            suite: HashSuiteId::PoseidonG12V1,
            digest: hash_from_field(42),
        };
        assert!(PrivacyNote::from_suite_tagged(&truncated, &expected_n).is_err());

        let wrong_suite = SuiteTaggedCommitment {
            suite: HashSuiteId::Sha3_256V1,
            digest: expected_c.digest,
        };
        assert!(PrivacyNote::from_suite_tagged(&wrong_suite, &expected_n).is_err());
        assert!(PrivacyNote::derive_v2(500, [0, 0], &recipient, secret).is_err());
    }
}
