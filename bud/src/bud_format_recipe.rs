//! B.U.D. 2.0 - RECIPE MINING AND THE RECIPE MACHINE BOUND; ideas 3.0 items Y2
//! and Y15.
//!
//! Y2: whoever finds a bit-exact short recipe for an organic, residual PACT
//! earns a bounty, because the byte budget falls. This module holds the recipe
//! candidate record, its verification and the honesty bound.
//!
//! HONESTY: recipe mining is a hard problem, in the Kolmogorov sense, and the
//! bounty may go unclaimed. That does not break the architecture, since the
//! owner path, I12, already works. The requirement that candidate verification
//! cost stay below the residual saving is watched by a canary.
//!
//! Y15: until the BudZero interval machine is built, production recipes are
//! bounded to integer-only arithmetic with checked and saturating operations.
//! The candidate gate scans for opcodes that would require the interval
//! machine, and REFUSES the candidate if it finds any.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const RECIPE_MAGIC: [u8; 8] = *b"\xB5RCP1\0\0\0";

/// Y15: the opcodes that would require the interval machine, meaning floating
/// point and division; under integer-only they are forbidden.
const FORBIDDEN_OPS: &[&str] = &["fdiv", "fadd", "fmul", "fsqrt", "fpow", "float", "div"];

/// A recipe candidate (Y2): the miner publishes the recipe, the seed and the
/// proof of the transformation.
#[derive(Debug, Clone)]
pub struct RecipeCandidate {
    pub miner: [u8; 32],
    pub pact_id: [u8; 32], // the target PACT, by commitment
    pub recipe: Vec<u8>,   // the recipe, an opcode list, integer-only
    pub seed: [u8; 32],    // the production seed
}

impl RecipeCandidate {
    /// Y15: is the recipe integer-only? Interval machine opcodes are forbidden.
    pub fn integer_only(&self) -> bool {
        let txt = String::from_utf8_lossy(&self.recipe).to_lowercase();
        !FORBIDDEN_OPS.iter().any(|op| txt.contains(op))
    }

    /// Y2: candidate verification. Do the bytes produced from the recipe and the
    /// seed equal the commitment?
    pub fn verify(&self, produced: &[u8], commitment: &[u8; 32]) -> bool {
        if !self.integer_only() {
            return false; // the Y15 bound
        }
        let cid = crate::bud_format_container::content_id(produced);
        &cid == commitment
    }
}

/// The bounty: a fixed share of the byte budget saved; the default is 20
/// percent, and governance can change it.
pub const RECIPE_BOUNTY_RATIO: f64 = 0.20;

/// The byte budget saving: the old residual size minus the new size of the
/// recipe plus seed.
pub fn budget_saving(old_residual: u64, new_recipe_bytes: u64) -> u64 {
    old_residual.saturating_sub(new_recipe_bytes)
}

/// The bounty calculation, a share of the saving. The canary requires the
/// saving to exceed the verification cost.
pub fn bounty(new_residual: u64, old_residual: u64, verify_cost: u64) -> Option<u64> {
    let saving = budget_saving(old_residual, new_residual);
    if saving <= verify_cost {
        return None; // if verification eats the saving there is no bounty; that is honest
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
    fn y15_integer_only_bound() {
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
        assert!(!bad.integer_only(), "an interval machine opcode is refused");
    }

    #[test]
    fn y2_candidate_verification() {
        let data = b"organic object content ";
        let cid = crate::bud_format_container::content_id(data);
        let c = RecipeCandidate {
            miner: [1u8; 32],
            pact_id: cid,
            recipe: b"load store".to_vec(),
            seed: [0u8; 32],
        };
        assert!(c.verify(data, &cid), "correct production is accepted");
        assert!(!c.verify(b"wrong", &cid), "wrong production is refused");
        // Y15: a floating point recipe is always refused, even when the
        // production is correct.
        let bad = RecipeCandidate {
            miner: [1u8; 32],
            pact_id: cid,
            recipe: b"fmul".to_vec(),
            seed: [0u8; 32],
        };
        assert!(!bad.verify(data, &cid));
    }

    #[test]
    fn y2_bounty_honesty_bound() {
        // A saving of 1000 against a verification cost of 100 gives a 20 percent
        // bounty of 200.
        assert_eq!(bounty(0, 1000, 100).unwrap(), 200);
        // If verification eats the saving, there is no bounty.
        assert!(bounty(0, 50, 100).is_none());
        assert!(bounty(500, 400, 0).is_none() || bounty(500, 400, 0) == Some(0));
        // No saving at all.
    }

    #[test]
    fn the_digest_is_deterministic() {
        let c = RecipeCandidate {
            miner: [1u8; 32],
            pact_id: [2u8; 32],
            recipe: b"load".to_vec(),
            seed: [3u8; 32],
        };
        assert_eq!(recipe_digest(&c), recipe_digest(&c));
    }

    #[test]
    fn y15_covers_every_forbidden_opcode() {
        for op in FORBIDDEN_OPS {
            let c = RecipeCandidate {
                miner: [0u8; 32],
                pact_id: [0u8; 32],
                recipe: op.as_bytes().to_vec(),
                seed: [0u8; 32],
            };
            assert!(!c.integer_only(), "{op} must be forbidden");
        }
    }
}
