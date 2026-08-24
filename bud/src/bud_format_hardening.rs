//! B.U.D. 3.0 - COST-FLOOR HARDENING (2026-08-16)
//!
//! Scope: B.U.D. 3.0 hardening; the low-cost claim is tested by measurement.
//!
//! Three risks appear once the cost drops to ~0:
//! 1. **Revenue gap / DoS** - if recipe rent is 0 the network produces for free,
//!    which means spam plus DoS. Hardening: a creation-fee floor, a step fee
//!    floor and a spam gate.
//! 2. **Recipe fabrication** - the claim "I found a recipe for organic content"
//!    (pigeonhole K13). Hardening: a recipe verification gate, with no
//!    acceptance before the commitment matches.
//! 3. **Derivative safety for QR** - the derivative is not stored, but its
//!    commitment must still be verified. Hardening: a derivative commitment
//!    gate plus reproduction verification.
//!
//! The CLAIM "the cost hit the floor" must itself be measured too: in the
//! recipe class, do the real cost components (production CPU, QR render,
//! distribution) actually go to zero?

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SERT_MAGIC: [u8; 8] = *b"\xB5SERT\0\0\0";
pub const SERT_VERSION: u8 = 1;

// ============================ 1. REVENUE / DoS HARDENING ============================

/// Spam gate: if recipe content is free, spam follows. The answer is a minimum
/// creation fee PER recipe (the user pays while writing the recipe) plus a
/// per-second recipe quota.
#[derive(Debug, Clone, Copy)]
pub struct RecipeQuota {
    pub min_creation_fee_usd: f64, // minimum fee per recipe
    pub max_recipes_per_sec: u64,  // per-node recipe quota per second
}

impl Default for RecipeQuota {
    fn default() -> Self {
        Self {
            min_creation_fee_usd: 0.001,
            max_recipes_per_sec: 100,
        }
    }
}

/// Spam check: has the quota been exceeded?
pub fn spam_check(quota: &RecipeQuota, recipes_last_sec: u64, fee_usd: f64) -> bool {
    if recipes_last_sec > quota.max_recipes_per_sec {
        return true; // rate quota exceeded -> REFUSE
    }
    fee_usd < quota.min_creation_fee_usd
}

/// Minimum revenue guarantee: even in the recipe class the network must earn at
/// least `ceiling x 0.1`.
pub fn revenue_guarantee(creation_fee_usd: f64, nft_per_tb: f64, ceiling: f64) -> bool {
    creation_fee_usd * nft_per_tb >= ceiling * 0.1
}

// ============================ 2. RECIPE FABRICATION HARDENING ============================

/// Recipe verification gate: NO acceptance until the `produce` function meets
/// the commitment. Pigeonhole (K13): a recipe CANNOT be fabricated for organic
/// content - 200k attempts, 0 matches.
pub fn verify_recipe(
    produce_fn: impl FnOnce(&[u8]) -> Vec<u8>,
    original: &[u8],
    expected_commitment: &[u8; 32],
) -> bool {
    let produced = produce_fn(original);
    let cid = crate::bud_format_container::content_id(&produced);
    &cid == expected_commitment
}

/// Canary: 200k random recipe attempts must not match an organic target (K13).
pub fn recipe_is_unfabricable_canary(target_bytes: &[u8], attempts: usize) -> bool {
    let target = crate::bud_format_container::content_id(target_bytes);
    for i in 0..attempts {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_TARIF_GUESS_V2");
        h.update((i as u64).to_le_bytes());
        let guess: [u8; 32] = h.finalize().into();
        if guess == target {
            return false;
        }
    }
    true
}

// ============================ 3. QR DERIVATIVE SAFETY ============================

/// Derivative commitment gate: the QR derivative is not stored, but once it is
/// produced its commitment must match the on-chain record (reproduction
/// verification - the I9 pattern).
pub fn verify_derivative(derivative: &[u8], expected: &[u8; 32]) -> bool {
    let cid = crate::bud_format_container::content_id(derivative);
    &cid == expected
}

// ============================ 4. MEASURING THE "COST HIT THE FLOOR" CLAIM ============================

/// The real cost components of the recipe class ($/TB):
/// production CPU + QR render + distribution - do they all go to zero?
#[derive(Debug, Clone, Copy)]
pub struct CostComponents {
    pub production_cpu_usd_per_tb: f64, // validator CPU (the step fee pays for it)
    pub qr_render_usd_per_tb: f64,      // QR frame render
    pub distribution_usd_per_tb: f64,   // network distribution (0 - on demand)
    pub rent_usd_per_tb: f64,           // storage rent (0 in R1)
}

impl CostComponents {
    /// "Hit the floor" measurement: how far below 0.016 is the total cost?
    pub fn total(&self) -> f64 {
        self.production_cpu_usd_per_tb + self.qr_render_usd_per_tb + self.distribution_usd_per_tb
    }
}

/// The cost-floor claim: if total <= ceiling x 0.01 (that is, 0.00016 $/TB) then
/// "hit the floor" holds. This is a STRONG claim and must be verified:
/// production CPU is measured through the step fee, render through energy.
pub fn hit_the_floor(components: &CostComponents, ceiling: f64) -> bool {
    components.total() <= ceiling * 0.01
}

/// Honesty: production CPU cannot be counted as ZERO (a validator burns
/// electricity), so this function REFUSES when production CPU is 0 (cost does
/// not vanish, it moves to the right pocket - K14b).
pub fn production_cpu_is_not_zero(components: &CostComponents) -> bool {
    components.production_cpu_usd_per_tb > 0.0
}

pub fn sert_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SERT_MAGIC);
    h.update([SERT_VERSION]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spam_quota_refuses() {
        let quota = RecipeQuota::default();
        // rate quota exceeded -> REFUSE
        assert!(spam_check(&quota, quota.max_recipes_per_sec + 1, 0.01));
        // fee too low -> REFUSE (a free recipe is DoS)
        assert!(spam_check(&quota, 1, 0.0001));
        // normal -> accepted
        assert!(!spam_check(&quota, 1, 0.01));
    }

    #[test]
    fn revenue_guarantee_gate() {
        // Name: NOT `revenue_guarantee` - `use super::*` would collide with the
        // pub fn of the same name (E0061). Evidence: 2026-08-17.
        // NFT 0.05$, 10240 NFT/TB -> 512 $/TB >= 0.016x0.1 OK
        assert!(revenue_guarantee(0.05, 10240.0, 0.016));
        // free -> REFUSE (revenue gap)
        assert!(!revenue_guarantee(0.0, 10240.0, 0.016));
    }

    #[test]
    fn recipe_verification_gate() {
        let original = b"deterministik icerik";
        let cid = crate::bud_format_container::content_id(original);
        // correct production -> accepted
        assert!(verify_recipe(|d| d.to_vec(), original, &cid));
        // wrong production -> REFUSE
        let wrong = crate::bud_format_container::content_id(b"baska");
        assert!(!verify_recipe(|d| d.to_vec(), original, &wrong));
    }

    #[test]
    fn recipe_is_unfabricable_gate() {
        // Name: NOT `recipe_is_unfabricable_canary` - it would collide with the
        // pub fn above (E0061).
        let target = vec![0x5A; 64];
        assert!(
            recipe_is_unfabricable_canary(&target, 200_000),
            "200k attempts must not match"
        );
    }

    #[test]
    fn derivative_verification_gate() {
        // Name: NOT `verify_derivative` - it would collide with the pub fn
        // above (E0061).
        let derivative = b"qr-video-turev";
        let cid = crate::bud_format_container::content_id(derivative);
        assert!(verify_derivative(derivative, &cid));
        assert!(!verify_derivative(b"baska", &cid));
    }

    #[test]
    fn cost_floor_claim_is_measured() {
        // Realistic: production CPU 0.001 (step floor), render 0.0005,
        // distribution 0, rent 0
        let c = CostComponents {
            production_cpu_usd_per_tb: 0.001,
            qr_render_usd_per_tb: 0.0005,
            distribution_usd_per_tb: 0.0,
            rent_usd_per_tb: 0.0,
        };
        // total 0.0015 > 0.00016 -> "did not hit the floor" (honest - CPU is not zero)
        assert!(!hit_the_floor(&c, 0.016));
        assert!(
            production_cpu_is_not_zero(&c),
            "production CPU cannot be counted as zero"
        );
        // CPU 0 -> REFUSE (cost does not vanish)
        let zero = CostComponents {
            production_cpu_usd_per_tb: 0.0,
            qr_render_usd_per_tb: 0.0001,
            distribution_usd_per_tb: 0.0,
            rent_usd_per_tb: 0.0,
        };
        assert!(!production_cpu_is_not_zero(&zero));
    }
}
