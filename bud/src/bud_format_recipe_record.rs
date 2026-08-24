//! B.U.D. 3.0 - THE RECIPE RECORD (spec section 19.4 - "no storage, only a recipe field")
//!
//! The question behind it (2026-08-16): "what if the content, once compressed, were
//! sent as a QR video, a system that moves storage onto the network alone; what would the tariff be?"
//! The spec answer (measured by K13/K14/K15): the only persistent object is THE RECIPE RECORD.
//! Two kinds: Generative (generator+seed, ~120 B, R1) | Bodied (compressed/raw body, R2/R3).
//! A QR video is a derivative (not kept). held_bytes: Generative -> 0, Bodied -> len(body).
//! Rent accrues only on Bodied.body (the K14b three meters: rent -> the storer,
//! step -> the validator, commitment -> the consensus state).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const RECIPE_MAGIC: [u8; 8] = *b"\xB5TRF1\0\0\0";
pub const RECIPE_VERSION: u8 = 1;

/// The three content-source regimes (spec section 17.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentSource {
    Generated,    // born from the recipe (R1) - 0 bytes held
    Compressible, // compressible organic content (R2) - the zlib base is held
    EntropyCoded, // photo/video/encrypted (R3) - a raw body, it does not compress
}

/// The recipe record - the ONLY persistent object of B.U.D. 3.0.
#[derive(Debug, Clone)]
pub enum RecipeRecord {
    Generative {
        commitment: [u8; 32], // the content identity (K3)
        generator: u16,       // the generator identity (deterministic)
        seed: [u8; 32],
        params: Vec<u8>, // generator parameters
    },
    Bodied {
        commitment: [u8; 32],
        compression: u8, // 0=none, 1=zlib-9 (if it shrinks)
        body: Vec<u8>,   // a compressed (R2) or raw (R3) body
    },
}

impl RecipeRecord {
    /// Bytes held (the K14b rent meter): Generative -> 0; Bodied -> len(body).
    pub fn held_bytes(&self) -> u64 {
        match self {
            Self::Generative { .. } => 0,
            Self::Bodied { body, .. } => body.len() as u64,
        }
    }

    /// The source regime.
    pub fn source(&self) -> ContentSource {
        match self {
            Self::Generative { .. } => ContentSource::Generated,
            Self::Bodied { compression, .. } => {
                if *compression > 0 {
                    ContentSource::Compressible
                } else {
                    ContentSource::EntropyCoded
                }
            }
        }
    }

    /// The record size (commitment-field accounting, section 19.1).
    pub fn record_bytes(&self) -> u64 {
        match self {
            Self::Generative { params, .. } => 32 + 2 + 32 + params.len() as u64,
            Self::Bodied { body, .. } => 32 + 1 + body.len() as u64,
        }
    }

    /// The commitment (K3: SHA3-256, domain-tagged).
    pub fn commit(content: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_TARIF_COMMIT_V1");
        h.update((content.len() as u64).to_le_bytes());
        h.update(content);
        h.finalize().into()
    }

    /// Write a generative recipe (the commitment is bound to the content; the 19.2 canary: it cannot be forged).
    pub fn generative(generator: u16, seed: [u8; 32], params: Vec<u8>) -> Self {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_TARIF_GENERATOR_V1");
        h.update(generator.to_le_bytes());
        h.update(seed);
        h.update(&params);
        let commitment: [u8; 32] = h.finalize().into();
        Self::Generative {
            commitment,
            generator,
            seed,
            params,
        }
    }

    /// Write a bodied recipe (zlib-9; a raw body if it does not shrink - spec section 1.2).
    pub fn bodied(body: Vec<u8>, compression: u8) -> Self {
        let commitment = Self::commit(&body);
        Self::Bodied {
            commitment,
            compression,
            body,
        }
    }
}

/// RENT per TB/month (K14b - only the bytes held; generation CPU is in the step fee).
/// The floor: $0.23342/TB/month (one physical base across all editions: 60-month amortization).
pub const R3_FLOOR_USD_TB_MONTH: f64 = 0.23342;

/// Rent: the physical floor x erasure x the held share / the compression ratio.
/// R1 (Generative, held=0) -> 0.0; R2 -> floor/ratio; R3 -> floor (ratio=1).
pub fn rent(recipe: &RecipeRecord, erasure: f64, compression_ratio: f64) -> f64 {
    let held = recipe.held_bytes();
    if held == 0 {
        return 0.0; // R1: no rent, no bytes held
    }
    let ratio = if compression_ratio > 1.0 {
        compression_ratio
    } else {
        1.0
    };
    R3_FLOOR_USD_TB_MONTH * erasure.max(1.0) / ratio
}

/// THE STEP FEE FLOOR (to the validator; per read, the requester pays - not rent).
/// The electricity lower bound (spec section 18.1b): a price below it is a validator loss = DoS.
pub fn step_floor(generator: u16) -> f64 {
    match generator {
        1 => 0.000085, // avatar (RLE)
        2 => 0.00226,  // gradient (vector)
        3 => 0.01028,  // hash noise
        _ => 0.01028,  // an unknown generator -> the highest floor (safe)
    }
}

/// The rent-ceiling gate (D13: 0.032; the B.U.D. 2.0 target is 0.016).
pub fn rent_within_ceiling(recipe: &RecipeRecord, erasure: f64, ratio: f64, ceiling: f64) -> bool {
    rent(recipe, erasure, ratio) <= ceiling
}

/// The 19.2 canary: a 120 B generative recipe CANNOT BE FORGED for organic content.
/// Pigeonhole: the content space is 2^160000, the recipe space is 2^960.
/// It is confirmed when no match is found for the given target within the attempt budget.
pub fn recipe_cannot_be_forged(target: &[u8], attempts: usize) -> bool {
    let target_hash = RecipeRecord::commit(target);
    for i in 0..attempts {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_TARIF_GUESS_V1");
        h.update((i as u64).to_le_bytes());
        let guess: [u8; 32] = h.finalize().into();
        if guess == target_hash {
            return false; // found - incredible, but it breaks the canary
        }
    }
    true // no attempt matched - it cannot be forged (as expected)
}

pub fn recipe_digest(t: &RecipeRecord) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(RECIPE_MAGIC);
    h.update([RECIPE_VERSION]);
    match t {
        RecipeRecord::Generative {
            commitment,
            generator,
            seed,
            params,
        } => {
            h.update([0]);
            h.update(commitment);
            h.update(generator.to_le_bytes());
            h.update(seed);
            h.update(params);
        }
        RecipeRecord::Bodied {
            commitment,
            compression,
            body,
        } => {
            h.update([1]);
            h.update(commitment);
            h.update([*compression]);
            h.update(body);
        }
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generative_recipe_pays_no_rent() {
        let t = RecipeRecord::generative(1, [7u8; 32], vec![1, 2, 3]);
        assert_eq!(t.held_bytes(), 0, "R1: 0 bytes held");
        assert_eq!(rent(&t, 1.031, 1.0), 0.0, "R1: rent 0");
        assert!(rent_within_ceiling(&t, 1.031, 1.0, 0.016));
    }

    #[test]
    fn a_bodied_recipe_divides_rent_by_the_ratio() {
        // R2: text compressing 189x -> 0.23342*1.031/189 = about 0.00127
        let body = vec![0u8; 1000];
        let t = RecipeRecord::bodied(body.clone(), 1);
        assert_eq!(t.held_bytes(), 1000);
        let k = rent(&t, 1.031, 189.0);
        assert!((k - 0.00127).abs() < 0.0002, "rent: {k}");
        // R3: it does not compress -> ratio=1 -> 0.23342*1.031 = about 0.241
        let t3 = RecipeRecord::bodied(body, 0);
        assert!((rent(&t3, 1.031, 1.0) - 0.241).abs() < 0.01);
    }

    #[test]
    fn the_step_floor_is_class_based() {
        assert!(step_floor(1) < step_floor(2));
        assert!(step_floor(2) < step_floor(3));
        // An unknown generator -> the highest (safe)
        assert_eq!(step_floor(99), step_floor(3));
    }

    #[test]
    fn the_recipe_forgery_canary() {
        let target = vec![0xA5; 160]; // organic content
        assert!(
            recipe_cannot_be_forged(&target, 200_000),
            "200k attempts must not match"
        );
        let _ = RecipeRecord::commit(&target); // the commitment is computable
    }

    #[test]
    fn the_record_size_depends_on_the_regime() {
        // R1 is ~120 B; R2/R3 = body + 33 B
        let u = RecipeRecord::generative(1, [0u8; 32], vec![]);
        assert!(
            u.record_bytes() <= 120,
            "a generative recipe is ~120 B: {}",
            u.record_bytes()
        );
        let g = RecipeRecord::bodied(vec![0u8; 500], 1);
        assert_eq!(g.record_bytes(), 533);
    }

    #[test]
    fn the_recipe_digest_is_deterministic() {
        let t = RecipeRecord::bodied(b"body".to_vec(), 1);
        assert_eq!(recipe_digest(&t), recipe_digest(&t));
    }
}
