//! A B.U.D. 2.0 INVENTION: the regeneration block, the blockchain power plant,
//! 2026-08-16.
//!
//! The synthesis of I2 and K89: every epoch produces a REGENERATION BLOCK, made
//! of the epoch, the selected PACT exams, which are the regeneration consensus,
//! the segment ledger root, the byte budget (I8) and the previous block hash,
//! all hashed into the block hash that forms the chain.
//!
//! Verification: any node can recompute the block, because it is deterministic.
//! If the PACT exams passed under "verify the production", the regeneration
//! consensus, the block is valid.
//!
//! The block carries NO content BYTES, only commitments and exam results. That
//! is the I2 thesis.
//!
//! The code is `#![forbid(unsafe_code)]`, deterministic and panic-free.

#![forbid(unsafe_code)]

use crate::bud_format_pact::PactRecord;
use crate::bud_format_regeneration::{RegenerationChallenge, RegenerationOutcome};
use sha3::{Digest, Sha3_256};

pub const BLOCK_MAGIC: [u8; 8] = *b"\xB5REGNB\0\0";
pub const BLOCK_VERSION: u8 = 1;
pub const MAX_PACTS_PER_BLOCK: usize = 10_000;

/// A single PACT exam record inside the block: the commitment and the exam
/// result, with NO bytes, per I2.
#[derive(Debug, Clone)]
pub struct PactChallengeInBlock {
    pub pact_hash: [u8; 32], // the hash of the PACT record
    pub outcome: RegenerationOutcome,
    pub cost_units: u64, // the production cost, the I2 economics
}

/// A regeneration block, one link of the chain.
#[derive(Debug, Clone)]
pub struct RegenerationBlock {
    pub epoch: u64,
    pub prev_hash: [u8; 32],
    pub pact_challenges: Vec<PactChallengeInBlock>,
    pub segment_root: [u8; 32], // the ledger root (K89)
    pub byte_budget: u64,       // I8: the ceiling on the network's total physical load
    pub ts_unix: u64,
    pub hash: [u8; 32], // the chain anchor, deterministic
}

impl RegenerationBlock {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_REGENBLOCK_V1";

    pub fn new(
        epoch: u64,
        prev_hash: [u8; 32],
        challenges: Vec<PactChallengeInBlock>,
        segment_root: [u8; 32],
        byte_budget: u64,
        ts_unix: u64,
    ) -> Option<Self> {
        if challenges.len() > MAX_PACTS_PER_BLOCK {
            return None;
        }
        let mut b = RegenerationBlock {
            epoch,
            prev_hash,
            pact_challenges: challenges,
            segment_root,
            byte_budget,
            ts_unix,
            hash: [0u8; 32],
        };
        b.hash = b.compute_hash();
        Some(b)
    }

    /// The domain-tagged chain hash; it is deterministic, so every node produces
    /// the same result.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(self.epoch.to_le_bytes());
        h.update(self.prev_hash);
        for c in &self.pact_challenges {
            h.update(c.pact_hash);
            h.update([match c.outcome {
                RegenerationOutcome::Verified => 0u8,
                RegenerationOutcome::Mismatch => 1,
                RegenerationOutcome::NotProducible => 2,
            }]);
            h.update(c.cost_units.to_le_bytes());
        }
        h.update(self.segment_root);
        h.update(self.byte_budget.to_le_bytes());
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }

    /// Block verification: the hash chain plus whether every exam is VERIFIED.
    /// That is I2, the production consensus.
    pub fn verify(&self) -> bool {
        self.hash == self.compute_hash()
            && self
                .pact_challenges
                .iter()
                .all(|c| c.outcome == RegenerationOutcome::Verified)
    }

    /// VERIFY the regeneration exam before adding it to the block; that is the
    /// core of I2.
    ///
    /// `produced` is the bytes generated from the recipe, and it is compared
    /// against the PACT commitment.
    pub fn add_challenge(
        pact: &PactRecord,
        produced: &[u8],
        cost_units: u64,
    ) -> Option<PactChallengeInBlock> {
        let outcome = RegenerationChallenge::verify(pact, produced);
        Some(PactChallengeInBlock {
            pact_hash: pact.record_hash(),
            outcome,
            cost_units,
        })
    }

    /// The regeneration economics, the I2 premise: the total production cost in
    /// the block must be far below the corresponding proof cost, whether proof of
    /// replication or zero knowledge.
    pub fn total_production_cost(&self) -> u64 {
        self.pact_challenges.iter().map(|c| c.cost_units).sum()
    }

    /// The deterministic blob: magic, version, the fields and a digest.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&BLOCK_MAGIC);
        out.push(BLOCK_VERSION);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(&(self.pact_challenges.len() as u32).to_le_bytes());
        for c in &self.pact_challenges {
            out.extend_from_slice(&c.pact_hash);
            out.push(match c.outcome {
                RegenerationOutcome::Verified => 0u8,
                RegenerationOutcome::Mismatch => 1,
                RegenerationOutcome::NotProducible => 2,
            });
            out.extend_from_slice(&c.cost_units.to_le_bytes());
        }
        out.extend_from_slice(&self.segment_root);
        out.extend_from_slice(&self.byte_budget.to_le_bytes());
        out.extend_from_slice(&self.ts_unix.to_le_bytes());
        out.extend_from_slice(&self.hash);
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 8 + 32 + 4;
        if bytes.len() < HDR + 32 + 32 + 8 + 8 + 32
            || bytes[0..8] != BLOCK_MAGIC
            || bytes[8] != BLOCK_VERSION
        {
            return None;
        }
        let epoch = u64::from_le_bytes(bytes[9..17].try_into().ok()?);
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&bytes[17..49]);
        let count = u32::from_le_bytes(bytes[49..53].try_into().ok()?) as usize;
        if count > MAX_PACTS_PER_BLOCK {
            return None;
        }
        let mut pos = HDR;
        let mut challenges = Vec::with_capacity(count);
        for _ in 0..count {
            if bytes.len() < pos + 32 + 1 + 8 {
                return None;
            }
            let mut pact_hash = [0u8; 32];
            pact_hash.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            let outcome = match bytes[pos] {
                0 => RegenerationOutcome::Verified,
                1 => RegenerationOutcome::Mismatch,
                2 => RegenerationOutcome::NotProducible,
                _ => return None,
            };
            pos += 1;
            let cost_units = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
            pos += 8;
            challenges.push(PactChallengeInBlock {
                pact_hash,
                outcome,
                cost_units,
            });
        }
        if bytes.len() < pos + 32 + 8 + 8 + 32 {
            return None;
        }
        let mut segment_root = [0u8; 32];
        segment_root.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let byte_budget = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let ts_unix = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        if pos != bytes.len() {
            return None;
        }
        let b = RegenerationBlock {
            epoch,
            prev_hash,
            pact_challenges: challenges,
            segment_root,
            byte_budget,
            ts_unix,
            hash,
        };
        if b.hash != b.compute_hash() {
            return None; // tampering
        }
        Some(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pact() -> (PactRecord, Vec<u8>) {
        let produced = b"deterministic production output 1234567890";
        let pact = PactRecord::pure([1u8; 32], [7u8; 32], produced, 100);
        (pact, produced.to_vec())
    }

    #[test]
    fn block_roundtrip_and_verify() {
        let (pact, produced) = sample_pact();
        let ch = RegenerationBlock::add_challenge(&pact, &produced, 50).expect("challenge");
        assert_eq!(ch.outcome, RegenerationOutcome::Verified);
        let block =
            RegenerationBlock::new(1, [0u8; 32], vec![ch], [9u8; 32], 1_000_000, 1_768_000_000)
                .expect("the block");
        assert!(
            block.verify(),
            "the block is valid, since every exam is VERIFIED"
        );
        // blob roundtrip
        let blob = block.to_blob();
        let back = RegenerationBlock::from_blob(&blob).expect("blob");
        assert_eq!(back.hash, block.hash);
        assert!(back.verify());
        // Tampering is refused.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(RegenerationBlock::from_blob(&bad).is_none());
        // A surplus byte is refused.
        let mut extra = blob.clone();
        extra.push(0x00);
        assert!(RegenerationBlock::from_blob(&extra).is_none());
    }

    #[test]
    fn block_rejects_mismatch_challenge() {
        // If an exam is a Mismatch, the block is INVALID; I2 requires the
        // production consensus.
        let (pact, _) = sample_pact();
        let ch =
            RegenerationBlock::add_challenge(&pact, b"wrong production", 50).expect("challenge");
        assert_eq!(ch.outcome, RegenerationOutcome::Mismatch);
        let block =
            RegenerationBlock::new(2, [1u8; 32], vec![ch], [0u8; 32], 100, 10).expect("the block");
        assert!(
            !block.verify(),
            "a Mismatch exam makes the block REFUSE, per I2"
        );
    }

    #[test]
    fn chain_links_prev_hash() {
        // The chain: block N's prev_hash must be block N-1's hash.
        let (pact, produced) = sample_pact();
        let ch = RegenerationBlock::add_challenge(&pact, &produced, 10).unwrap();
        let b0 = RegenerationBlock::new(0, [0u8; 32], vec![ch.clone()], [1u8; 32], 100, 1).unwrap();
        let b1 = RegenerationBlock::new(1, b0.hash, vec![ch], [2u8; 32], 100, 2).unwrap();
        assert_eq!(b1.prev_hash, b0.hash, "the chain link");
        assert!(b1.verify());
        // Link b1 to the WRONG hash for b0 and the hash differs, deterministically.
        let b1_bad = RegenerationBlock::new(1, [9u8; 32], vec![], [2u8; 32], 100, 2).unwrap();
        assert_ne!(b1_bad.hash, b1.hash);
    }

    #[test]
    fn production_cost_accumulates() {
        let (pact, produced) = sample_pact();
        let chs: Vec<PactChallengeInBlock> = (0..10)
            .map(|i| RegenerationBlock::add_challenge(&pact, &produced, i as u64 + 1).unwrap())
            .collect();
        let block = RegenerationBlock::new(3, [0u8; 32], chs, [0u8; 32], 100, 3).unwrap();
        assert_eq!(block.total_production_cost(), 55);
        // An empty exam list still gives a valid block, with a budget of zero.
        let empty = RegenerationBlock::new(4, block.hash, vec![], [0u8; 32], 0, 4).unwrap();
        assert!(empty.verify());
        // Exceeding MAX_PACTS gives None.
        let too_many = vec![
            PactChallengeInBlock {
                pact_hash: [0u8; 32],
                outcome: RegenerationOutcome::Verified,
                cost_units: 1
            };
            MAX_PACTS_PER_BLOCK + 1
        ];
        assert!(RegenerationBlock::new(5, [0u8; 32], too_many, [0u8; 32], 0, 5).is_none());
    }

    #[test]
    fn blob_never_panics() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() & 0xff) as u8
            }
        }
        let mut rng = Rng(0x424C_4F43_4B20_2608);
        let mut buf = vec![0u8; 256];
        for _ in 0..2000 {
            let len = (rng.next() % 256) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = RegenerationBlock::from_blob(&buf[..len]);
        }
    }
}
