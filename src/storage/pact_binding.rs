//! Storage PACT binding: recipe + residual commitment and the registry root.
//!
//! # Where it is called from
//!
//! `QuantumAccountRegistry::register_with_pacts` compares an account's
//! `pact_root` field against the root of the registry defined here
//! (`src/account_abstraction/registry.rs`). For a long time it did not: an
//! account carried a `pact_root`, but nothing checked that the root named a
//! real set of pacts, so the field was a claim rather than a binding.
//!
//! # What is verified
//!
//! A pact's commitment must be the hash of its own payload
//! (`verify_commitment`), and the registry root must be recomputable from the
//! pacts it contains (`verify_root`). Without the second one a root could also
//! match a set that contains no pacts at all.

use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub struct Pact {
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
            return Err("KQ-STORAGE-PACT: byte_budget >128");
        }
        if mode_flag > 2 {
            return Err("KQ-STORAGE-PACT: mode_flag >2");
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

    /// # Errors
    ///
    /// Returns an error when the payload does not hash to the committed value.
    pub fn verify_commitment(&self, payload: &[u8]) -> Result<(), &'static str> {
        let mut h = Sha3_256::new();
        h.update(payload);
        let calc: [u8; 32] = h.finalize().into();
        if calc != self.commitment {
            return Err("KQ-STORAGE-PACT: commitment mismatch");
        }
        Ok(())
    }

    #[must_use]
    pub fn is_pure_production(&self) -> bool {
        self.mode_flag == 0 && self.residual_commitment == [0u8; 32]
    }
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
    pub pacts: Vec<Pact>,
    pub root: [u8; 32],
}

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

    pub fn add_pact(&mut self, pact: Pact) {
        self.pacts.push(pact);
        self.recompute_root();
    }

    pub fn recompute_root(&mut self) {
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
        let mut h = Sha3_256::new();
        h.update(b"BUDLUM_PACT_REGISTRY_V1");
        for p in &self.pacts {
            h.update(p.id);
            h.update(p.commitment);
        }
        h.finalize().into()
    }

    /// # Errors
    ///
    /// Returns an error when the recomputed root does not match the stored
    /// root.
    pub fn verify_root(&self) -> Result<(), &'static str> {
        if self.computed_root() != self.root {
            return Err("KQ-STORAGE-PACT: root mismatch");
        }
        Ok(())
    }
}

pub struct PactGates;

impl PactGates {
    /// # Errors
    ///
    /// Returns an error when the pact commitment does not match its payload.
    pub fn kq_storage_pact(pact: &Pact, payload: &[u8]) -> Result<(), &'static str> {
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
            return Err("KQ-STORAGE-BOUND: storage_root zero but pact_root non-zero");
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
        );
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
        );
        reg.root = [0xAA; 32];
        assert!(reg.verify_root().is_err());
    }

    #[test]
    fn registry_root() {
        let mut reg = PactRegistry::new();
        let payload = b"data";
        let mut h = Sha3_256::new();
        h.update(payload);
        let comm: [u8; 32] = h.finalize().into();
        let pact = Pact::new([1u8; 32], [0u8; 32], [0u8; 32], comm, [0u8; 32], 10, 0).unwrap();
        reg.add_pact(pact);
        assert!(reg.verify_root().is_ok());
    }
}
