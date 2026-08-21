//! On-chain note registry: live commitments + spent nullifiers.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// 32-byte commitment or nullifier hash.
///
/// The wallet produces these by packing a Goldilocks field element, and this
/// registry looks them up by equality. Taking the type from the crate that
/// defines the packing is what keeps the two ends describing the same bytes:
/// a private alias here would let the packing rule change on one side while
/// this side kept compiling, and the first symptom would be a nullifier that
/// never matches, so a spent note stays spendable.
pub type NoteHash = budlum_note_packing::NoteHash;

/// Maximum live commitments to prevent unbounded state growth.
/// At 65536 entries × 32 bytes = 2MB - well within node memory limits.
pub const MAX_LIVE_COMMITMENTS: usize = 65_536;

/// Maximum spent nullifiers before fail-closed rejection.
/// At 262144 entries × 32 bytes = 8MB - bounded memory for consensus replay protection.
pub const MAX_SPENT_NULLIFIERS: usize = 262_144;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct L1NoteRegistry {
    live_commitments: BTreeSet<NoteHash>,
    spent_nullifiers: BTreeSet<NoteHash>,
}

impl L1NoteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.live_commitments.is_empty() && self.spent_nullifiers.is_empty()
    }

    pub fn live_count(&self) -> usize {
        self.live_commitments.len()
    }

    pub fn spent_count(&self) -> usize {
        self.spent_nullifiers.len()
    }

    pub fn contains_commitment(&self, c: &NoteHash) -> bool {
        self.live_commitments.contains(c)
    }

    pub fn is_nullifier_spent(&self, n: &NoteHash) -> bool {
        self.spent_nullifiers.contains(n)
    }

    /// Genesis / faucet helper: insert a note without spending (tests + mint path).
    pub fn insert_note(&mut self, commitment: NoteHash) -> Result<(), String> {
        if self.live_commitments.contains(&commitment) {
            return Err("note commitment already live".into());
        }
        if self.spent_nullifiers.contains(&commitment) {
            // Defensive: commitment hash space must not collide with nullifiers in use
        }
        // Bounded live commitment set - fail-closed
        if self.live_commitments.len() >= MAX_LIVE_COMMITMENTS {
            return Err(format!(
                "live commitment set full ({}/{}) - compact or wait for spends",
                self.live_commitments.len(),
                MAX_LIVE_COMMITMENTS
            ));
        }
        self.live_commitments.insert(commitment);
        Ok(())
    }

    /// Apply a private transfer: spend nullifiers (each once) and insert outputs.
    ///
    /// `spent_commitments` are revealed only to the executor as private witness
    /// Linkage for double-spend of the *note* set; nullifiers are the public
    /// Anti-double-spend tags. For v1 submit we require the submitter to also
    /// Pass the commitments being spent (encrypted/TEE path can hide them later).
    pub fn apply_transfer(
        &mut self,
        spent_commitments: &[NoteHash],
        nullifiers: &[NoteHash],
        output_commitments: &[NoteHash],
    ) -> Result<(), String> {
        self.apply_transfer_with_proofs(spent_commitments, nullifiers, output_commitments, &[])
    }

    /// Apply transfer with nullifier derivation proofs.
    /// Each `proof[i]` must satisfy: `nullifier[i] == Poseidon(commitment[i], proof[i])`.
    /// If proofs is empty, falls back to legacy behavior (no binding check).
    pub fn apply_transfer_with_proofs(
        &mut self,
        spent_commitments: &[NoteHash],
        nullifiers: &[NoteHash],
        output_commitments: &[NoteHash],
        nullifier_proofs: &[NoteHash],
    ) -> Result<(), String> {
        if spent_commitments.len() != nullifiers.len() {
            return Err("spent_commitments/nullifiers length mismatch".into());
        }
        if !nullifier_proofs.is_empty() && nullifier_proofs.len() != nullifiers.len() {
            return Err("nullifier_proofs length mismatch".into());
        }
        if spent_commitments.is_empty() {
            return Err("private transfer requires at least one input".into());
        }
        if output_commitments.is_empty() {
            return Err("private transfer requires at least one output".into());
        }

        // Pre-check nullifiers
        for n in nullifiers {
            if self.spent_nullifiers.contains(n) {
                return Err("double-spend: nullifier already spent".into());
            }
        }
        // Pre-check outputs unique + not already live
        let mut seen_out = BTreeSet::new();
        for c in output_commitments {
            if !seen_out.insert(*c) {
                return Err("duplicate output commitment".into());
            }
            if self.live_commitments.contains(c) {
                return Err("output commitment already live".into());
            }
        }
        // Every remaining refusal, decided before a single note moves.
        //
        // These three checks used to live inside the spend loop, after the
        // `remove`. On input two of three, inputs one and two were already out
        // of `live_commitments` when the error returned, and the caller does
        // not roll back: `apply_block_checked` propagates with `?` and leaves
        // the state as it found it. The notes were then neither live nor
        // spent, which is value destroyed by a path that reported failure.
        //
        // A private transfer is all-or-nothing by nature, so the ordering has
        // to say so: refuse while everything is still in place, then move.
        if !nullifier_proofs.is_empty() {
            for (i, (commitment, nullifier)) in
                spent_commitments.iter().zip(nullifiers.iter()).enumerate()
            {
                let proof = &nullifier_proofs[i];
                let expected_nullifier = Self::derive_nullifier(commitment, proof);
                if *nullifier != expected_nullifier {
                    return Err(format!("nullifier derivation proof invalid for input {i}"));
                }
            }
        }
        // Inputs must be live and distinct. The old loop got distinctness for
        // free, because the second `remove` of the same commitment returned
        // false and refused. Checking with `contains` does not, so the
        // duplicate has to be refused explicitly or one note would be spent
        // twice in a single transfer against a single removal.
        let mut seen_in = BTreeSet::new();
        for commitment in spent_commitments {
            if !seen_in.insert(*commitment) {
                return Err("duplicate input commitment".into());
            }
            if !self.live_commitments.contains(commitment) {
                return Err("spend: commitment not in live set".into());
            }
        }
        // Bounded nullifier set - fail-closed. Counted for the whole transfer
        // rather than one input at a time: a transfer that would cross the
        // ceiling partway through must be refused before it starts, not after
        // it has consumed the inputs it had room for.
        if self.spent_nullifiers.len().saturating_add(nullifiers.len()) > MAX_SPENT_NULLIFIERS {
            return Err(format!(
                "spent nullifier set full ({}/{}) - chain must compact before more private transfers",
                self.spent_nullifiers.len(),
                MAX_SPENT_NULLIFIERS
            ));
        }

        // Past every refusal: the transfer now runs to completion.
        for (commitment, nullifier) in spent_commitments.iter().zip(nullifiers.iter()) {
            self.live_commitments.remove(commitment);
            self.spent_nullifiers.insert(*nullifier);
        }
        for c in output_commitments {
            self.live_commitments.insert(*c);
        }
        Ok(())
    }

    pub fn state_root(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"BDLM_L1_NOTE_REGISTRY_V1");
        h.update((self.live_commitments.len() as u64).to_le_bytes());
        for c in &self.live_commitments {
            h.update(c);
        }
        h.update((self.spent_nullifiers.len() as u64).to_le_bytes());
        for n in &self.spent_nullifiers {
            h.update(n);
        }
        h.finalize().into()
    }

    /// Derive nullifier from commitment and proof.
    /// Nullifier = SHA-256("BDLM_NULLIFIER_DERIVE_V1" || commitment || proof)
    pub fn derive_nullifier(commitment: &NoteHash, proof: &NoteHash) -> NoteHash {
        let mut h = Sha256::new();
        h.update(b"BDLM_NULLIFIER_DERIVE_V1");
        h.update(commitment);
        h.update(proof);
        h.finalize().into()
    }

    /// Enforce bounded storage via hard caps.
    /// Spent nullifiers are consensus replay protection, they cannot be deleted
    /// Without breaking double-spend resistance. Instead, MAX_SPENT_NULLIFIERS
    /// Enforces a hard ceiling (fail-closed): once the cap is reached, no new
    /// Private transfers are accepted until the chain performs a state migration
    /// To a non-deleting accumulator design (e.g., Bloom filter + Merkle mountain
    /// Range). This method is retained for API compatibility but pruning is now
    /// Bounded by the MAX_SPENT_NULLIFIERS constant enforced at insertion time.
    pub fn prune_spent_nullifiers(&mut self, _keep_count: usize) {
        // Intentional no-op: nullifiers are bounded by MAX_SPENT_NULLIFIERS
        // Enforced at insertion in apply_transfer_with_proofs. Deleting any
        // Nullifier would break consensus replay protection.
    }

    /// Returns the number of spent nullifiers currently stored.
    pub fn spent_nullifier_count(&self) -> usize {
        self.spent_nullifiers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> NoteHash {
        let mut x = [0u8; 32];
        x[0] = b;
        x
    }

    /// The bytes the wallet packs are the bytes this registry looks up.
    ///
    /// This is the one property the privacy layer cannot check inside any
    /// single crate. The wallet computes a nullifier from a field element and
    /// sends the packed hash; consensus stores that hash and later answers
    /// `is_nullifier_spent` by comparing it. If the two sides ever pack
    /// differently, both keep passing their own tests, because each one packs
    /// and unpacks with its own copy, and a round trip through a copy is
    /// exactly what a divergent copy still does correctly.
    ///
    /// What breaks instead is the lookup between them: the chain never
    /// recorded the hash the wallet is asking about, so a spent note reports
    /// unspent and the double spend it exists to prevent goes through.
    ///
    /// The test spends a note using a hash packed by the shared definition
    /// and then asks the registry about it, which is the crossing point the
    /// unit tests on either side never touch.
    #[test]
    fn a_nullifier_packed_the_way_the_wallet_packs_it_is_found_by_the_registry() {
        let commitment = budlum_note_packing::hash_from_field(0x0102_0304_0506_0708);
        let nullifier = budlum_note_packing::hash_from_field(0xDEAD_BEEF_CAFE_F00D);
        // A zero-output transfer must be rejected.
        let change = budlum_note_packing::hash_from_field(0x1122_3344_5566_7788);

        let mut r = L1NoteRegistry::new();
        r.insert_note(commitment).unwrap();
        assert!(
            r.contains_commitment(&commitment),
            "a commitment packed by the shared rule must be found by the registry"
        );

        r.apply_transfer(&[commitment], &[nullifier], &[change])
            .unwrap();
        assert!(
            r.is_nullifier_spent(&nullifier),
            "the nullifier the wallet would send must be the one the chain stored"
        );
        assert!(
            r.contains_commitment(&change),
            "the output the wallet packed must be the one the chain now holds"
        );

        // And the note cannot be spent twice, which is the guarantee that
        // silently disappears if the two packings drift apart.
        let second = budlum_note_packing::hash_from_field(0x9900_AABB_CCDD_EEFF);
        assert!(r
            .apply_transfer(&[commitment], &[nullifier], &[second])
            .is_err());
    }

    /// A registry hash is a packed hash, not an arbitrary 32 bytes.
    ///
    /// `field_from_hash` reads the low eight bytes and drops the rest, so two
    /// different foreign hashes sharing a low half read back as the same
    /// field element. Nothing in the registry compares field elements, and
    /// Identity here is the full hash.
    #[test]
    fn two_hashes_agreeing_on_the_low_half_are_still_two_notes() {
        let a = budlum_note_packing::hash_from_field(7);
        let mut b = a;
        b[31] = 1;

        assert_eq!(
            budlum_note_packing::field_from_hash(&a),
            budlum_note_packing::field_from_hash(&b),
            "the field elements agree, which is precisely the trap"
        );
        assert!(budlum_note_packing::is_packed(&a));
        assert!(!budlum_note_packing::is_packed(&b));

        let mut r = L1NoteRegistry::new();
        r.insert_note(a).unwrap();
        assert!(
            !r.contains_commitment(&b),
            "the registry must not confuse two notes that share a field element"
        );
        r.insert_note(b)
            .expect("b is a different note and must be insertable");
        assert_eq!(r.live_count(), 2);
    }

    #[test]
    fn insert_spend_roundtrip() {
        let mut r = L1NoteRegistry::new();
        r.insert_note(h(1)).unwrap();
        r.apply_transfer(&[h(1)], &[h(10)], &[h(2)]).unwrap();
        assert!(!r.contains_commitment(&h(1)));
        assert!(r.contains_commitment(&h(2)));
        assert!(r.is_nullifier_spent(&h(10)));
    }

    /// A refused transfer must leave every input exactly where it was.
    ///
    /// The three remaining checks used to sit inside the spend loop, after
    /// `live_commitments.remove`. On input two of three, the first two notes
    /// were already gone when the error returned, and nothing rolls back:
    /// `apply_block_checked` propagates with `?`. The notes ended up neither
    /// live nor spent, which is value destroyed by a path that said it failed.
    #[test]
    fn a_refused_transfer_does_not_consume_the_inputs_it_got_to() {
        let mut r = L1NoteRegistry::new();
        r.insert_note(h(1)).unwrap();
        r.insert_note(h(2)).unwrap();

        // Three inputs, the third of which is not live. The first two are.
        let err = r
            .apply_transfer(&[h(1), h(2), h(3)], &[h(10), h(11), h(12)], &[h(20)])
            .expect_err("an input that is not live must refuse the transfer");
        assert!(err.contains("not in live set"), "got: {err}");

        assert!(
            r.contains_commitment(&h(1)) && r.contains_commitment(&h(2)),
            "the inputs the loop would have reached first must still be live"
        );
        assert!(
            !r.is_nullifier_spent(&h(10)) && !r.is_nullifier_spent(&h(11)),
            "and none of their nullifiers may be recorded as spent"
        );
        assert!(
            !r.contains_commitment(&h(20)),
            "nor may the outputs have been created"
        );

        // And the transfer still works once the inputs are all live, which is
        // what proves the refusal above was about liveness and not a wedge.
        r.insert_note(h(3)).unwrap();
        r.apply_transfer(&[h(1), h(2), h(3)], &[h(10), h(11), h(12)], &[h(20)])
            .expect("all three live now");
        assert!(r.contains_commitment(&h(20)));
    }

    /// The same note twice in one transfer is one removal against two spends.
    ///
    /// The old loop refused this for free: the second `remove` of the same
    /// commitment returned false. Deciding liveness with `contains` does not,
    /// so the duplicate is refused explicitly. Without that check this test is
    /// the one that fails, and it fails by *succeeding* at a double spend.
    #[test]
    fn the_same_input_twice_is_refused() {
        let mut r = L1NoteRegistry::new();
        r.insert_note(h(1)).unwrap();

        let err = r
            .apply_transfer(&[h(1), h(1)], &[h(10), h(11)], &[h(20)])
            .expect_err("one note cannot be spent twice in a single transfer");
        assert!(err.contains("duplicate input"), "got: {err}");
        assert!(
            r.contains_commitment(&h(1)),
            "and the refusal must not have consumed it"
        );
    }

    #[test]
    fn double_spend_rejected() {
        let mut r = L1NoteRegistry::new();
        r.insert_note(h(1)).unwrap();
        r.apply_transfer(&[h(1)], &[h(10)], &[h(2)]).unwrap();
        r.insert_note(h(3)).unwrap();
        assert!(r.apply_transfer(&[h(3)], &[h(10)], &[h(4)]).is_err());
    }

    #[test]
    fn spent_nullifiers_are_never_deleted_by_compatibility_pruning() {
        let mut r = L1NoteRegistry::new();
        r.insert_note(h(1)).unwrap();
        r.apply_transfer(&[h(1)], &[h(10)], &[h(2)]).unwrap();
        r.insert_note(h(3)).unwrap();
        r.apply_transfer(&[h(3)], &[h(11)], &[h(4)]).unwrap();

        let root_before = r.state_root();
        r.prune_spent_nullifiers(1);

        assert_eq!(r.spent_nullifier_count(), 2);
        assert!(r.is_nullifier_spent(&h(10)));
        assert!(r.is_nullifier_spent(&h(11)));
        assert_eq!(r.state_root(), root_before);
    }
}

#[cfg(test)]
mod h3_tests {
    use super::*;

    fn note_hash(b: u8) -> NoteHash {
        let mut x = [0u8; 32];
        x[0] = b;
        x
    }

    #[test]
    fn soft_cap_enforced_on_insert_note() {
        let mut r = L1NoteRegistry::new();
        // Fill up to the cap
        for i in 0..MAX_LIVE_COMMITMENTS {
            let mut h = [0u8; 32];
            // Use byte 1 (not byte 0) to avoid collision with overflow hash
            h[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            r.insert_note(h).unwrap();
        }
        // Next insert must fail-closed (use [0xFF; 32] - guaranteed unique)
        let overflow = [0xFFu8; 32];
        let err = r.insert_note(overflow).unwrap_err();
        assert!(
            err.contains("live commitment set full"),
            "expected cap error, got: {err}"
        );
    }

    #[test]
    fn state_root_deterministic() {
        let mut r = L1NoteRegistry::new();
        r.insert_note(note_hash(1)).unwrap();
        let root1 = r.state_root();
        let root2 = r.state_root();
        assert_eq!(root1, root2, "state_root must be deterministic");
        r.insert_note(note_hash(2)).unwrap();
        let root3 = r.state_root();
        assert_ne!(root1, root3, "state_root must change after mutation");
    }
}
