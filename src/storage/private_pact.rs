//! WIRING: unwired - E5 private-pact seed opening waits for the pact execution path.
//!
//! `verify_seed_opening` refuses a seed/blinding pair whose commitment does
//! not match the pact, but no production path executes private pacts yet:
//! the cleartext seed never enters the chain, so there is nothing to open.
//! The guard moves the day an execution path takes a seed opening as input;
//! this declaration leaves with it. Keeping the guard visible (instead of
//! deleting it) pins the commitment scheme `BDLM_PACT_PRIVATE_SEED_V1` that
//! the state root already binds.

use sha3::{Digest, Sha3_256};

use crate::storage::pact_binding::hasher_init;

/// E5: Private PACT with ZK-Seed Commitment.
///
/// Blinds the recipe seed via a cryptographic commitment `Sha3_256(b"BDLM_PACT_PRIVATE_SEED_V1" || seed || blinding)`,
/// preventing cleartext leakage of proprietary AI/data generation recipes while keeping
/// state root bindings verifiable.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PrivatePact {
    pub id: [u8; 32],
    pub recipe_hash: [u8; 32],
    pub seed_commitment: [u8; 32],
    pub output_commitment: [u8; 32],
    pub byte_budget: u64,
}

impl PrivatePact {
    /// # Errors
    ///
    /// A `KQ-STORAGE-PACT` finding when `byte_budget` exceeds 128.
    pub const fn new(
        id: [u8; 32],
        recipe_hash: [u8; 32],
        seed_commitment: [u8; 32],
        output_commitment: [u8; 32],
        byte_budget: u64,
    ) -> Result<Self, &'static str> {
        if byte_budget > 128 {
            return Err("KQ-STORAGE-PACT: byte_budget >128");
        }
        Ok(Self {
            id,
            recipe_hash,
            seed_commitment,
            output_commitment,
            byte_budget,
        })
    }

    /// Compute seed commitment from cleartext seed and blinding factor.
    #[must_use]
    fn compute_seed_commitment(seed: &[u8; 32], blinding: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        hasher_init(&mut h, b"BDLM_PACT_PRIVATE_SEED_V1");
        h.update(seed);
        h.update(blinding);
        h.finalize().into()
    }

    /// Verify an opening of the private seed.
    #[must_use]
    fn verify_seed_opening(&self, seed: &[u8; 32], blinding: &[u8; 32]) -> bool {
        Self::compute_seed_commitment(seed, blinding) == self.seed_commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_pact_seed_commitment_and_opening() {
        let seed = [0x11u8; 32];
        let blinding = [0x22u8; 32];
        let comm = PrivatePact::compute_seed_commitment(&seed, &blinding);

        let pact = PrivatePact::new([0x01; 32], [0x02; 32], comm, [0x03; 32], 64).unwrap();

        assert!(pact.verify_seed_opening(&seed, &blinding));
        assert!(!pact.verify_seed_opening(&[0x99; 32], &blinding));
    }
}
