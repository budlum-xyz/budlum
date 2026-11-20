//! Storage PACT binding: generator + residual commitment and the registry root.
//!
//! # Where it is called from
//!
//! `QuantumAccountRegistry::register_with_pacts` compares an account's
//! `pact_root` field against the root of the registry defined here
//! (`src/account_abstraction/registry.rs`). The plain `register` entry point
//! rejects non-zero pact roots, so callers cannot bypass that evidence check.
//! This is an in-memory registry API boundary: no block transaction writes the
//! quantum-account registry and its root is not part of `AccountState` yet.
//!
//! # What is verified
//!
//! A pact's commitment must be the hash of its own payload
//! (`verify_commitment`), and the registry root must be recomputable from the
//! pacts it contains (`verify_root`). Without the second one a root could also
//! match a set that contains no pacts at all. The root commits to the set, not
//! to the delivery order: pacts are stored in canonical id order, and a
//! registry that is not in that order is refused (V3 label).

use sha3::{Digest, Sha3_256};

/// Storage pact entry verified inside [`PactRegistry::verify_root`].
///
/// Convenience: exposed for quantum-account pact-root commitment tests and
/// `PactRegistry` verification in `src/account_abstraction/registry.rs`.
#[derive(Debug, Clone)]
pub(crate) struct Pact {
    pub id: [u8; 32],
    pub recipe_hash: [u8; 32],
    pub seed: [u8; 32],
    pub commitment: [u8; 32],
    pub residual_commitment: [u8; 32],
    pub byte_budget: u64,
    pub mode_flag: u8, // 0=pure production, 1=recipe+residual, 2=residual-only
}

impl Pact {
    /// # Errors
    ///
    /// Returns an error when the byte budget exceeds 128 or the mode flag is
    /// outside the `0..=2` range.
    // Not const: the nightly jobs (udeps, determinism) reject trait calls in
    // const fns with E0658; this fn was reverted from const in c72b911.
    #[cfg(test)]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(
        id: [u8; 32],
        recipe_hash: [u8; 32],
        seed: [u8; 32],
        commitment: [u8; 32],
        residual: [u8; 32],
        budget: u64,
        mode_flag: u8,
    ) -> Result<Self, &'static str> {
        if budget > 128 {
            return Err("storage pact: byte_budget >128");
        }
        if mode_flag > 2 {
            return Err("storage pact: mode_flag >2");
        }
        // The mode and the residual must tell the same story: a pure
        // production pact carries no residual, the other two modes do.
        if (mode_flag == 0) != (residual == [0u8; 32]) {
            return Err("storage pact: mode_flag does not match residual_commitment");
        }
        Ok(Self {
            id,
            recipe_hash,
            seed,
            commitment,
            residual_commitment: residual,
            byte_budget: budget,
            mode_flag,
        })
    }

    /// Validate all structural invariants of a pact (used by both [`Self::new`]
    /// and [`PactRegistry::verify_root`] so directly constructed or deserialized
    /// pacts cannot bypass bounds).
    ///
    /// # Errors
    ///
    /// Returns an error when any field violates the pact invariants.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.byte_budget > 128 {
            return Err("storage pact: byte_budget >128");
        }
        if self.mode_flag > 2 {
            return Err("storage pact: mode_flag >2");
        }
        if (self.mode_flag == 0) != (self.residual_commitment == [0u8; 32]) {
            return Err("storage pact: mode_flag does not match residual_commitment");
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error when the payload exceeds `byte_budget` or does not hash
    /// to the committed value.
    #[cfg(test)]
    pub(crate) fn verify_commitment(&self, payload: &[u8]) -> Result<(), &'static str> {
        self.validate()?;
        let payload_len = u64::try_from(payload.len())
            .map_err(|_| "storage pact: payload exceeds byte_budget")?;
        if payload_len > self.byte_budget {
            return Err("storage pact: payload exceeds byte_budget");
        }
        let mut h = Sha3_256::new();
        h.update(payload);
        let calc: [u8; 32] = h.finalize().into();
        if calc != self.commitment {
            return Err("storage pact: commitment mismatch");
        }
        Ok(())
    }

    #[cfg(test)]
    #[must_use]
    pub fn is_pure_production(&self) -> bool {
        self.mode_flag == 0 && self.residual_commitment == [0u8; 32]
    }
    #[cfg(test)]
    #[must_use]
    // Not const: the nightly jobs (udeps, determinism) reject trait calls in
    // const fns with E0658; this fn was reverted from const in c72b911.
    #[allow(clippy::missing_const_for_fn)]
    pub fn is_residual_only(&self) -> bool {
        self.mode_flag == 2
    }
}

#[derive(Debug, Clone)]
pub struct PactRegistry {
    pub(crate) pacts: Vec<Pact>,
    pub root: [u8; 32],
}

/// Most pacts one registry may hold. The root hashes every pact, so the count bounds that work.
///
/// Convenience: pub so a pact caller can refuse past the same
/// bound the registry enforces in this module.
pub const MAX_PACTS: usize = 1024;

impl Default for PactRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PactRegistry {
    #[must_use]
    // Not const: the nightly jobs (udeps, determinism) reject trait calls in
    // const fns with E0658; this fn was reverted from const in c72b911.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new() -> Self {
        Self {
            pacts: Vec::new(),
            root: [0u8; 32],
        }
    }

    /// # Errors
    ///
    /// Returns an error when the id is already registered or the registry is full.
    #[cfg(test)]
    pub(crate) fn add_pact(&mut self, pact: Pact) -> Result<(), &'static str> {
        if self.pacts.len() >= MAX_PACTS {
            return Err("storage pact: registry is full");
        }
        if self.pacts.iter().any(|existing| existing.id == pact.id) {
            return Err("storage pact: duplicate pact id");
        }
        // The root must describe the set, not the delivery order: insert in
        // id order so `[A, B]` and `[B, A]` cannot commit to different roots.
        let at = self
            .pacts
            .partition_point(|existing| existing.id <= pact.id);
        self.pacts.insert(at, pact);
        self.recompute_root();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn recompute_root(&mut self) {
        self.root = self.computed_root();
    }

    /// Compute the root from the pacts in the registry, without reading the
    /// stored root.
    ///
    /// The empty set commits to zero. `new()` started from a zero root while
    /// the computation returned `H(label)`: a fresh registry could not pass its
    /// own `verify_root`. Zero was chosen out of the two answers because on the
    /// account side a zero `pact_root` already means "no pacts"
    /// (`kq_storage_bound` reads it that way); giving the empty set a separate
    /// label hash would describe one state with two different byte strings.
    #[must_use]
    pub fn computed_root(&self) -> [u8; 32] {
        if self.pacts.is_empty() {
            return [0u8; 32];
        }
        // Every field of every pact is in the preimage. V1 hashed only `id`
        // and `commitment`, so `recipe_hash`, `seed`, `residual_commitment`,
        // `byte_budget` and `mode_flag` could change under a root that still
        // verified; a residual-only pact and a pure-production pact with the
        // same id and commitment were one root. The count in front of the
        // pacts and the fixed width of every field keep the encoding
        // injective.
        //
        // V3 hashes the pacts in canonical id order and refuses an unsorted
        // registry (`verify_root`): under V2 the preimage followed the `Vec`,
        // so one set delivered two ways committed to two roots. The label
        // moves with the rule so a V2 root can never be read as a V3 root.
        let mut h = Sha3_256::new();
        h.update(b"BUDLUM_PACT_REGISTRY_V3");
        h.update((self.pacts.len() as u64).to_le_bytes());
        for p in &self.pacts {
            h.update(p.id);
            h.update(p.recipe_hash);
            h.update(p.seed);
            h.update(p.commitment);
            h.update(p.residual_commitment);
            h.update(p.byte_budget.to_le_bytes());
            h.update([p.mode_flag]);
        }
        h.finalize().into()
    }

    /// # Errors
    ///
    /// Returns an error when any pact violates structural invariants, ids collide,
    /// the pacts are not in canonical id order, capacity is exceeded, or the
    /// recomputed root differs from the stored root.
    pub fn verify_root(&self) -> Result<(), &'static str> {
        if self.pacts.len() > MAX_PACTS {
            return Err("storage pact: registry is full");
        }
        let mut seen_ids = std::collections::BTreeSet::new();
        for pact in &self.pacts {
            pact.validate()?;
            if !seen_ids.insert(pact.id) {
                return Err("storage pact: duplicate pact id");
            }
        }
        // A deserialized or directly constructed registry skips `add_pact`;
        // the root is only order-independent if storage is canonical.
        if !self.pacts.windows(2).all(|w| w[0].id < w[1].id) {
            return Err("storage pact: pacts are not in canonical id order");
        }
        if self.computed_root() != self.root {
            return Err("storage pact: root mismatch");
        }
        Ok(())
    }
}

pub struct PactGates;

impl PactGates {
    /// # Errors
    ///
    /// Returns an error when the pact commitment does not match its payload.
    #[cfg(test)]
    pub(crate) fn kq_storage_pact(pact: &Pact, payload: &[u8]) -> Result<(), &'static str> {
        pact.verify_commitment(payload)
    }
    /// # Errors
    ///
    /// Returns an error when the registry root is stale.
    pub fn kq_pact_registry(registry: &PactRegistry) -> Result<(), &'static str> {
        registry.verify_root()
    }
    /// # Errors
    ///
    /// Returns an error when the storage root is zero while the pact root is
    /// non-zero.
    pub fn kq_storage_bound(
        storage_root: &[u8; 32],
        pact_root: &[u8; 32],
    ) -> Result<(), &'static str> {
        if storage_root == &[0u8; 32] && pact_root != &[0u8; 32] {
            return Err("storage bound: storage_root zero but pact_root non-zero");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pact_commitment_ok() {
        let payload = b"hello";
        let mut h = Sha3_256::new();
        h.update(payload);
        let comm: [u8; 32] = h.finalize().into();
        let pact = Pact::new([1u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 10, 0).unwrap();
        assert!(pact.verify_commitment(payload).is_ok());
        assert!(PactGates::kq_storage_pact(&pact, payload).is_ok());
        assert!(PactGates::kq_storage_pact(&pact, b"tampered").is_err());
        assert!(pact.is_pure_production());
    }
    /// A fresh registry has to agree with its own root.
    ///
    /// `new()` starts from a zero root; if the computation returned anything
    /// else, an empty registry could not pass its own `verify_root`.
    #[test]
    fn an_empty_registry_agrees_with_its_own_root() {
        let reg = PactRegistry::new();
        assert_eq!(reg.computed_root(), [0u8; 32]);
        assert!(reg.verify_root().is_ok());
    }

    /// Adding a pact has to move the root off zero.
    #[test]
    fn adding_a_pact_moves_the_root_off_zero() {
        let mut reg = PactRegistry::new();
        reg.add_pact(
            Pact::new([1u8; 32], [0u8; 32], [0u8; 32], [2u8; 32], [0u8; 32], 10, 0)
                .expect("valid pact"),
        )
        .expect("pact accepted");
        assert_ne!(
            reg.root, [0u8; 32],
            "a non-empty set cannot share a root with the empty set"
        );
        assert!(reg.verify_root().is_ok());
    }

    /// A hand-edited root has to be refused.
    #[test]
    fn a_hand_edited_root_is_refused() {
        let mut reg = PactRegistry::new();
        reg.add_pact(
            Pact::new([1u8; 32], [0u8; 32], [0u8; 32], [2u8; 32], [0u8; 32], 10, 0)
                .expect("valid pact"),
        )
        .expect("pact accepted");
        reg.root = [0xAA; 32];
        assert!(reg.verify_root().is_err());
    }

    /// Every pact field is under the root: an edit to any of the five fields
    /// the V1 root left out is refused by `verify_root`.
    #[test]
    fn every_pact_field_is_bound_by_the_root() {
        let base = || {
            let mut reg = PactRegistry::new();
            reg.add_pact(
                Pact::new([1u8; 32], [3u8; 32], [4u8; 32], [2u8; 32], [5u8; 32], 10, 1)
                    .expect("valid pact"),
            )
            .expect("pact accepted");
            reg
        };
        assert!(base().verify_root().is_ok());
        let edits: [fn(&mut Pact); 5] = [
            |p| p.recipe_hash = [9u8; 32],
            |p| p.seed = [9u8; 32],
            |p| p.residual_commitment = [9u8; 32],
            |p| p.byte_budget = 11,
            |p| p.mode_flag = 2,
        ];
        for edit in edits {
            let mut reg = base();
            edit(&mut reg.pacts[0]);
            assert!(
                reg.verify_root().is_err(),
                "an edited pact field passed under the old root"
            );
        }
    }

    /// The same pact set in either arrival order must commit to one root.
    ///
    /// `add_pact` used to append, and the root hashed the `Vec` in insertion
    /// order: `[A, B]` and `[B, A]` were two different roots for one set, so
    /// an account's `pact_root` depended on delivery order, not on the pacts.
    /// The registry now keeps the pacts in id order, so arrival order cannot
    /// reach the root.
    #[test]
    fn pact_roots_are_order_independent() {
        let make = |id: u8| {
            Pact::new(
                [id; 32],
                [0u8; 32],
                [0u8; 32],
                [id.wrapping_add(10); 32],
                [0u8; 32],
                10,
                0,
            )
            .expect("valid pact")
        };
        let mut forward = PactRegistry::new();
        forward.add_pact(make(1)).expect("first");
        forward.add_pact(make(2)).expect("second");
        let mut backward = PactRegistry::new();
        backward.add_pact(make(2)).expect("first");
        backward.add_pact(make(1)).expect("second");
        assert_eq!(
            forward.computed_root(),
            backward.computed_root(),
            "one pact set must commit to one root regardless of arrival order"
        );
        assert!(forward.verify_root().is_ok());
        assert!(backward.verify_root().is_ok());
        assert_eq!(
            forward.pacts.iter().map(|p| p.id).collect::<Vec<_>>(),
            backward.pacts.iter().map(|p| p.id).collect::<Vec<_>>(),
            "the stored order must be canonical (id order)"
        );
    }

    /// A hand-ordered registry (direct construction) must be refused.
    ///
    /// Canonical storage is what makes the root order-independent; a
    /// deserialized or directly built registry that skips the ordering must
    /// not pass verification.
    #[test]
    fn a_non_canonical_pact_order_is_refused() {
        let make = |id: u8| {
            Pact::new(
                [id; 32],
                [0u8; 32],
                [0u8; 32],
                [id.wrapping_add(10); 32],
                [0u8; 32],
                10,
                0,
            )
            .expect("valid pact")
        };
        let mut unsorted = PactRegistry {
            pacts: vec![make(2), make(1)],
            root: [0u8; 32],
        };
        unsorted.recompute_root();
        assert!(
            unsorted.verify_root().is_err(),
            "a registry whose pacts are not in canonical id order must be refused"
        );
    }

    #[test]
    fn a_pact_id_cannot_be_added_twice() {
        let mut reg = PactRegistry::new();
        let make = || Pact::new([1u8; 32], [0u8; 32], [0u8; 32], [2u8; 32], [0u8; 32], 10, 0);
        reg.add_pact(make().expect("valid pact"))
            .expect("first add");
        let root = reg.root;
        assert!(reg.add_pact(make().expect("valid pact")).is_err());
        assert_eq!(reg.root, root);
        assert_eq!(reg.pacts.len(), 1);
    }

    #[test]
    fn registry_root() {
        let mut reg = PactRegistry::new();
        let payload = b"data";
        let mut h = Sha3_256::new();
        h.update(payload);
        let comm: [u8; 32] = h.finalize().into();
        let pact = Pact::new([1u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 10, 0).unwrap();
        reg.add_pact(pact).expect("pact accepted");
        assert!(reg.verify_root().is_ok());
    }

    #[test]
    fn pact_mode_must_match_the_residual_commitment() {
        let z = [0u8; 32];
        let r = [9u8; 32];
        assert!(Pact::new([1u8; 32], z, z, z, r, 10, 0).is_err());
        assert!(Pact::new([1u8; 32], z, z, z, z, 10, 1).is_err());
        assert!(Pact::new([1u8; 32], z, z, z, z, 10, 2).is_err());
        assert!(Pact::new([1u8; 32], z, z, z, z, 10, 0).is_ok());
        assert!(Pact::new([1u8; 32], z, z, z, r, 10, 1).is_ok());
        assert!(Pact::new([1u8; 32], z, z, z, r, 10, 2).is_ok());
    }

    #[test]
    fn verify_root_and_verify_commitment_enforce_pact_invariants_against_direct_construction() {
        let payload = b"over-budget-payload";
        let mut h = Sha3_256::new();
        h.update(payload);
        let comm: [u8; 32] = h.finalize().into();
        let pact = Pact::new([1u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 4, 0).unwrap();
        assert!(
            pact.verify_commitment(payload).is_err(),
            "payload larger than declared byte_budget must be refused"
        );

        // Direct struct literal with forged mode_flag / budget / duplicate ids + matching root:
        let mut forged_mode = PactRegistry {
            pacts: vec![Pact {
                id: [2u8; 32],
                recipe_hash: [0u8; 32],
                seed: [0u8; 32],
                commitment: comm,
                residual_commitment: [9u8; 32], // contradicts mode_flag 0
                byte_budget: 10,
                mode_flag: 0,
            }],
            root: [0u8; 32],
        };
        forged_mode.recompute_root();
        assert!(
            forged_mode.verify_root().is_err(),
            "verify_root must refuse malformed pact even when root matches"
        );

        let valid = Pact::new([3u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 32, 0).unwrap();
        let mut dup = PactRegistry {
            pacts: vec![valid.clone(), valid],
            root: [0u8; 32],
        };
        dup.recompute_root();
        assert!(
            dup.verify_root().is_err(),
            "verify_root must refuse duplicate pact ids"
        );
    }
}
