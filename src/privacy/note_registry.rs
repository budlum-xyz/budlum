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

/// Whether `h` is a hash the note pipeline could have produced: a canonical
/// Goldilocks field element in the low eight bytes, little-endian, and zero
/// above.
///
/// Every legitimate commitment and nullifier has this shape. The wallet packs
/// its Poseidon outputs with `hash_from_field`, and a Poseidon output is below
/// the prime, so a hash of any other shape is either an upstream bug or a
/// submitter probing, and the honest answer to both is a refusal at the
/// transaction boundary, before the registry sees it.
///
/// The registry itself compares whole hashes and would keep two hashes that
/// differ only in a high byte apart. The trouble is the other view of the same
/// set: the zkVM relay speaks field elements (`SpentSet::is_spent(u64)`), and
/// `field_from_hash` drops the high bytes on the way there, so two hashes that
/// agree on the low half read back as one element. With only packed hashes
/// admitted, the two views cannot disagree about what is spent.
#[must_use]
pub fn is_note_hash(h: &NoteHash) -> bool {
    budlum_note_packing::is_packed(h)
        && budlum_note_packing::is_canonical_field(budlum_note_packing::field_from_hash(h))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct L1NoteRegistry {
    live_commitments: BTreeSet<NoteHash>,
    spent_nullifiers: BTreeSet<NoteHash>,
    /// BLG-0058 (P03-F01, decision B): the spent *note* set, bound to the
    /// commitment. A nullifier alone cannot close the loop while proofs are
    /// free inputs: one commitment yields a fresh nullifier per proof, so a
    /// spent commitment could be re-inserted and spent again. The commitment
    /// itself is what dies.
    #[serde(default)]
    spent_commitments: BTreeSet<NoteHash>,
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

    /// BLG-0058: has this *note* been spent already? The chain-internal
    /// filter (decision A) that stops resurrection.
    pub fn is_commitment_spent(&self, c: &NoteHash) -> bool {
        self.spent_commitments.contains(c)
    }

    /// Genesis / faucet helper: insert a note without spending (tests + mint path).
    pub fn insert_note(&mut self, commitment: NoteHash) -> Result<(), String> {
        if self.live_commitments.contains(&commitment) {
            return Err("note commitment already live".into());
        }
        // BLG-0058: a spent note cannot be resurrected. Without this check a
        // PrivacyNoteInsert revived the commitment and a fresh proof minted a
        // fresh nullifier, letting the same note be spent again.
        if self.spent_commitments.contains(&commitment) {
            return Err("note commitment already spent".into());
        }
        if self.spent_nullifiers.contains(&commitment) {
            // Commitment hash space must not collide with nullifiers in use.
            return Err("note commitment collides with a spent nullifier".into());
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

    /// Apply transfer with nullifier derivation proofs.
    /// Each `proof[i]` must satisfy: `nullifier[i] == derive_nullifier(commitment[i], proof[i])`, a domain-separated SHA-256.
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
        // BLG-0058 (decision C): the binding check is not optional. Without
        // proofs the nullifier is a free input and a commitment could be
        // spent once per proof; the legacy no-binding path is gone.
        if nullifier_proofs.len() != nullifiers.len() {
            return Err("nullifier_proofs length mismatch (proofs are mandatory)".into());
        }
        if spent_commitments.is_empty() {
            return Err("private transfer requires at least one input".into());
        }
        if output_commitments.is_empty() {
            return Err("private transfer requires at least one output".into());
        }

        // Pre-check nullifiers
        // The nullifiers of one transfer must also be distinct from each other.
        // The set records a repeated value once, so `[n, n]` would spend two
        // notes and leave a single nullifier behind.
        let mut seen_nullifiers = BTreeSet::new();
        for n in nullifiers {
            if self.spent_nullifiers.contains(n) {
                return Err("double-spend: nullifier already spent".into());
            }
            if !seen_nullifiers.insert(*n) {
                return Err("duplicate nullifier in transfer".into());
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
            if self.spent_nullifiers.contains(c) {
                return Err("output commitment collides with a spent nullifier".into());
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
        for (i, (commitment, nullifier)) in
            spent_commitments.iter().zip(nullifiers.iter()).enumerate()
        {
            let proof = &nullifier_proofs[i];
            let expected_nullifier = Self::derive_nullifier(commitment, proof);
            if *nullifier != expected_nullifier {
                return Err(format!("nullifier derivation proof invalid for input {i}"));
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
            if self.spent_commitments.contains(commitment) {
                return Err("double-spend: commitment already spent".into());
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

        // Bounded live set. Outputs are counted against the same ceiling as
        // `insert_note`: a transfer replaces its inputs with its outputs, so
        // the set grows by the difference. Without this check one input and
        // sixteen outputs add fifteen notes per transfer and walk past
        // MAX_LIVE_COMMITMENTS without any insert_note call.
        let live_after = self
            .live_commitments
            .len()
            .saturating_sub(spent_commitments.len())
            .saturating_add(output_commitments.len());
        if live_after > MAX_LIVE_COMMITMENTS {
            return Err(format!(
                "live commitment set full ({}/{}) - transfer would add {} notes",
                self.live_commitments.len(),
                MAX_LIVE_COMMITMENTS,
                output_commitments
                    .len()
                    .saturating_sub(spent_commitments.len())
            ));
        }

        // Past every refusal: the transfer now runs to completion.
        for (commitment, nullifier) in spent_commitments.iter().zip(nullifiers.iter()) {
            self.live_commitments.remove(commitment);
            self.spent_commitments.insert(*commitment);
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
        // BLG-0058: the spent note set is consensus state and must commit.
        h.update((self.spent_commitments.len() as u64).to_le_bytes());
        for c in &self.spent_commitments {
            h.update(c);
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

        let proof = budlum_note_packing::hash_from_field(0x0FED_CBA9_8765_4321);
        let nullifier = L1NoteRegistry::derive_nullifier(&commitment, &proof);
        r.apply_transfer_with_proofs(&[commitment], &[nullifier], &[change], &[proof])
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
        // silently disappears if the two packings drift apart. BLG-0058: the
        // spent *commitment* is refused even with a fresh proof and a fresh
        // nullifier.
        let second = budlum_note_packing::hash_from_field(0x9900_AABB_CCDD_EEFF);
        let fresh_proof = budlum_note_packing::hash_from_field(0x0123_4567_89AB_CDEF);
        let fresh_nullifier = L1NoteRegistry::derive_nullifier(&commitment, &fresh_proof);
        assert!(r
            .apply_transfer_with_proofs(
                &[commitment],
                &[fresh_nullifier],
                &[second],
                &[fresh_proof]
            )
            .is_err());
        assert!(r.insert_note(commitment).is_err(), "spent note stays dead");
    }

    /// One nullifier cannot cover two inputs of the same transfer.
    #[test]
    fn a_repeated_nullifier_in_one_transfer_is_refused() {
        let a = budlum_note_packing::hash_from_field(11);
        let b = budlum_note_packing::hash_from_field(12);
        let n = budlum_note_packing::hash_from_field(0x8000_0001);
        let out = budlum_note_packing::hash_from_field(0x8100_0001);
        let mut r = L1NoteRegistry::new();
        r.insert_note(a).unwrap();
        r.insert_note(b).unwrap();
        let pa = budlum_note_packing::hash_from_field(31);
        let pb = budlum_note_packing::hash_from_field(32);
        let err = r
            .apply_transfer_with_proofs(&[a, b], &[n, n], &[out], &[pa, pb])
            .unwrap_err();
        assert!(err.contains("duplicate nullifier"));
        assert!(r.contains_commitment(&a) && r.contains_commitment(&b));
        assert_eq!(r.spent_count(), 0);
    }

    /// A commitment equal to a spent nullifier is not a note.
    #[test]
    fn a_commitment_equal_to_a_spent_nullifier_is_refused() {
        let c = budlum_note_packing::hash_from_field(21);
        let out = budlum_note_packing::hash_from_field(0x9100_0001);
        let mut r = L1NoteRegistry::new();
        r.insert_note(c).unwrap();
        let pc = budlum_note_packing::hash_from_field(41);
        let n = L1NoteRegistry::derive_nullifier(&c, &pc);
        r.apply_transfer_with_proofs(&[c], &[n], &[out], &[pc]).unwrap();
        assert!(r.insert_note(n).is_err());
        let spare = budlum_note_packing::hash_from_field(22);
        let ps = budlum_note_packing::hash_from_field(42);
        let next_n = L1NoteRegistry::derive_nullifier(&spare, &ps);
        r.insert_note(spare).unwrap();
        assert!(r
            .apply_transfer_with_proofs(&[spare], &[next_n], &[n], &[ps])
            .is_err());
        assert!(r.contains_commitment(&spare));
    }

    /// A transfer cannot grow the live set past MAX_LIVE_COMMITMENTS.
    #[test]
    fn transfer_outputs_respect_the_live_commitment_cap() {
        let mut r = L1NoteRegistry::new();
        for i in 0..MAX_LIVE_COMMITMENTS {
            r.insert_note(budlum_note_packing::hash_from_field(i as u64 + 1))
                .unwrap();
        }
        let input = budlum_note_packing::hash_from_field(1);
        let pf = budlum_note_packing::hash_from_field(0x7200_0001);
        let nullifier = L1NoteRegistry::derive_nullifier(&input, &pf);
        let outs = [
            budlum_note_packing::hash_from_field(0x7100_0001),
            budlum_note_packing::hash_from_field(0x7100_0002),
        ];
        assert!(r
            .apply_transfer_with_proofs(&[input], &[nullifier], &outs, &[pf])
            .is_err());
        assert_eq!(r.live_count(), MAX_LIVE_COMMITMENTS);
        assert!(r.contains_commitment(&input));
        assert!(!r.is_nullifier_spent(&nullifier));
        // One for one keeps the size and is still allowed.
        r.apply_transfer_with_proofs(&[input], &[nullifier], &outs[..1], &[pf])
            .unwrap();
        assert_eq!(r.live_count(), MAX_LIVE_COMMITMENTS);
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

    /// The boundary check admits exactly the packed, canonical shape.
    #[test]
    fn only_a_packed_canonical_element_is_a_note_hash() {
        let packed = budlum_note_packing::hash_from_field(7);
        assert!(is_note_hash(&packed));

        let mut high_byte = packed;
        high_byte[31] = 1;
        assert!(!is_note_hash(&high_byte), "a high byte set is not packed");

        let too_large = budlum_note_packing::hash_from_field(budlum_note_packing::GOLDILOCKS_P);
        assert!(
            !is_note_hash(&too_large),
            "the prime itself is not a canonical element"
        );
        let largest = budlum_note_packing::hash_from_field(budlum_note_packing::GOLDILOCKS_P - 1);
        assert!(is_note_hash(&largest));
    }

    #[test]
    fn insert_spend_roundtrip() {
        let mut r = L1NoteRegistry::new();
        r.insert_note(h(1)).unwrap();
        let p1 = h(100);
        let n1 = L1NoteRegistry::derive_nullifier(&h(1), &p1);
        r.apply_transfer_with_proofs(&[h(1)], &[n1], &[h(2)], &[p1])
            .unwrap();
        assert!(!r.contains_commitment(&h(1)));
        assert!(r.contains_commitment(&h(2)));
        assert!(r.is_nullifier_spent(&n1));
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
        let (p1, p2, p3) = (h(110), h(111), h(112));
        let (n1, n2, n3) = (
            L1NoteRegistry::derive_nullifier(&h(1), &p1),
            L1NoteRegistry::derive_nullifier(&h(2), &p2),
            L1NoteRegistry::derive_nullifier(&h(3), &p3),
        );
        let err = r
            .apply_transfer_with_proofs(&[h(1), h(2), h(3)], &[n1, n2, n3], &[h(20)], &[p1, p2, p3])
            .expect_err("an input that is not live must refuse the transfer");
        assert!(err.contains("not in live set"), "got: {err}");

        assert!(
            r.contains_commitment(&h(1)) && r.contains_commitment(&h(2)),
            "the inputs the loop would have reached first must still be live"
        );
        assert!(
            !r.is_nullifier_spent(&n1) && !r.is_nullifier_spent(&n2),
            "and none of their nullifiers may be recorded as spent"
        );
        assert!(
            !r.contains_commitment(&h(20)),
            "nor may the outputs have been created"
        );

        // And the transfer still works once the inputs are all live, which is
        // what proves the refusal above was about liveness and not a wedge.
        r.insert_note(h(3)).unwrap();
        r.apply_transfer_with_proofs(&[h(1), h(2), h(3)], &[n1, n2, n3], &[h(20)], &[p1, p2, p3])
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

        let (p1, p2) = (h(110), h(111));
        let (n1, n2) = (
            L1NoteRegistry::derive_nullifier(&h(1), &p1),
            L1NoteRegistry::derive_nullifier(&h(1), &p2),
        );
        let err = r
            .apply_transfer_with_proofs(&[h(1), h(1)], &[n1, n2], &[h(20)], &[p1, p2])
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
        let p1 = h(100);
        let n1 = L1NoteRegistry::derive_nullifier(&h(1), &p1);
        r.apply_transfer_with_proofs(&[h(1)], &[n1], &[h(2)], &[p1])
            .unwrap();
        r.insert_note(h(3)).unwrap();
        assert!(r
            .apply_transfer_with_proofs(&[h(3)], &[n1], &[h(4)], &[p1])
            .is_err());
    }

    #[test]
    fn spent_nullifiers_are_never_deleted_by_compatibility_pruning() {
        let mut r = L1NoteRegistry::new();
        r.insert_note(h(1)).unwrap();
        let p1 = h(100);
        let n1 = L1NoteRegistry::derive_nullifier(&h(1), &p1);
        r.apply_transfer_with_proofs(&[h(1)], &[n1], &[h(2)], &[p1])
            .unwrap();
        r.insert_note(h(3)).unwrap();
        let p2 = h(101);
        let n2 = L1NoteRegistry::derive_nullifier(&h(3), &p2);
        r.apply_transfer_with_proofs(&[h(3)], &[n2], &[h(4)], &[p2])
            .unwrap();

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
