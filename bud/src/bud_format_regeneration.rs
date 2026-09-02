//! B.U.D. 2.0 INVENTION - Regeneration-as-Consensus (2026-08-16)
//!
//! ideas2.0 I2 + the STORAGE-ZERO ARCHITECTURE THESIS: instead of "prove the
//! byte" (PoR/PoSt), consensus says **"verify the production"**: on demand the
//! validator produces the content from the producer, hashes it, and compares it
//! with the PACT commitment; the match is consensus itself.
//!
//! Why this is "new on a blockchain": existing approaches say "store+prove",
//! "store+BFT attestation", "store+proof of access", "compute+prove" (proving is
//! expensive) and "store events+recompute state" (the event log is permanent).
//! **None of them** says "the content byte is never stored; a production match
//! is the consensus verification".
//!
//! This module: a challenge -> produce -> hash -> compare with the commitment ->
//! a result. The challenge is not written on chain; only the result hash is kept
//! for audit (I2). A failed production lowers the reputation score (the
//! provider.rs pattern).
//!
//! Code: `#![forbid(unsafe_code)]`, deterministic, panic free.

#![forbid(unsafe_code)]

use crate::bud_format_pact::PactRecord;
use sha3::{Digest, Sha3_256};

pub const REGEN_MAGIC: [u8; 8] = *b"\xB5RGEN\0\0\0";
pub const REGEN_VERSION: u8 = 1;

/// The challenge result (I2): did the production consensus pass, and at what cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegenerationOutcome {
    Verified,      // the production matched the commitment -> consensus
    Mismatch,      // the production did not match the commitment -> REFUSED, reputation drops
    NotProducible, // the producer could not produce (a class lie or a broken producer)
}

/// The regeneration challenge: verify the produced bytes against the given
/// PACT. The I2 thesis is "the cost of producing is below the cost of proving" -
/// this function measures that cost.
pub struct RegenerationChallenge;

impl RegenerationChallenge {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_REGENERATION_V1";

    /// Verify the produced bytes against the PACT commitment (the core of I2).
    /// - PureProduction/RecipePlusResidual: commitment = H(produced bytes)
    /// - ResidualOnly: commitment = content_id(original) (lossless integrity)
    pub fn verify(pact: &PactRecord, produced: &[u8]) -> RegenerationOutcome {
        if !pact.verify() {
            return RegenerationOutcome::NotProducible;
        }
        if pact.verify_production(produced) {
            RegenerationOutcome::Verified
        } else {
            RegenerationOutcome::Mismatch
        }
    }

    /// Residual integrity: does the remainder that cannot be produced match the
    /// commitment (I6)? In RecipePlusResidual mode the residual must be verified
    /// too - a class lie is caught this way.
    pub fn verify_with_residual(
        pact: &PactRecord,
        produced: &[u8],
        residual: &[u8],
    ) -> RegenerationOutcome {
        match pact.verify() {
            false => RegenerationOutcome::NotProducible,
            true => {
                if pact.verify_production(produced) && pact.verify_residual(residual) {
                    RegenerationOutcome::Verified
                } else {
                    RegenerationOutcome::Mismatch
                }
            }
        }
    }

    /// The challenge record: epoch + pact_hash + result + cost (for audit, writable on chain).
    pub fn record_hash(
        epoch: u64,
        pact_hash: [u8; 32],
        outcome: RegenerationOutcome,
        cost_units: u64,
    ) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(epoch.to_le_bytes());
        h.update(pact_hash);
        h.update([match outcome {
            RegenerationOutcome::Verified => 0u8,
            RegenerationOutcome::Mismatch => 1,
            RegenerationOutcome::NotProducible => 2,
        }]);
        h.update(cost_units.to_le_bytes());
        h.finalize().into()
    }

    /// The I2 acceptance rule: the cost of producing must be below 1 percent of
    /// the corresponding proving cost. (A zkVM proof is worth 222 years of
    /// storage - the STORAGE-ZERO measurement; producing costs about as much as
    /// reading.)
    pub fn regeneration_beats_proof(production_cost: u64, proof_cost: u64) -> bool {
        proof_cost > 0 && (production_cost as f64) < (proof_cost as f64) * 0.01
    }
}

/// The regeneration consensus record (a small on-chain record - within the I8 byte budget).
#[derive(Debug, Clone)]
pub struct RegenerationRecord {
    pub epoch: u64,
    pub pact_hash: [u8; 32],
    pub outcome: RegenerationOutcome,
    pub cost_units: u64,
}

impl RegenerationRecord {
    pub fn new(
        epoch: u64,
        pact_hash: [u8; 32],
        outcome: RegenerationOutcome,
        cost_units: u64,
    ) -> Self {
        RegenerationRecord {
            epoch,
            pact_hash,
            outcome,
            cost_units,
        }
    }

    pub fn record_hash(&self) -> [u8; 32] {
        RegenerationChallenge::record_hash(
            self.epoch,
            self.pact_hash,
            self.outcome,
            self.cost_units,
        )
    }

    /// A deterministic blob (magic + version + fields + digest).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&REGEN_MAGIC);
        out.push(REGEN_VERSION);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.pact_hash);
        out.push(match self.outcome {
            RegenerationOutcome::Verified => 0u8,
            RegenerationOutcome::Mismatch => 1,
            RegenerationOutcome::NotProducible => 2,
        });
        out.extend_from_slice(&self.cost_units.to_le_bytes());
        out.extend_from_slice(&self.record_hash());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 8 + 32 + 1 + 8;
        if bytes.len() < HDR + 32 || bytes[0..8] != REGEN_MAGIC || bytes[8] != REGEN_VERSION {
            return None;
        }
        let epoch = u64::from_le_bytes(bytes[9..17].try_into().ok()?);
        let mut pact_hash = [0u8; 32];
        pact_hash.copy_from_slice(&bytes[17..49]);
        let outcome = match bytes[49] {
            0 => RegenerationOutcome::Verified,
            1 => RegenerationOutcome::Mismatch,
            2 => RegenerationOutcome::NotProducible,
            _ => return None,
        };
        let cost_units = u64::from_le_bytes(bytes[50..58].try_into().ok()?);
        if bytes.len() != HDR + 32 {
            return None;
        }
        let rec = RegenerationRecord {
            epoch,
            pact_hash,
            outcome,
            cost_units,
        };
        if bytes[HDR..] != rec.record_hash() {
            return None;
        }
        Some(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_production_regenerates_consensus() {
        // I2: pure production - if the produced byte matches the commitment, consensus is VERIFIED
        let producer = [1u8; 32];
        let seed = [7u8; 32];
        let produced = b"deterministic production output 1234567890";
        let pact = PactRecord::pure(producer, seed, produced, 100);
        assert_eq!(
            RegenerationChallenge::verify(&pact, produced),
            RegenerationOutcome::Verified,
            "a production match is consensus itself"
        );
        assert_eq!(
            RegenerationChallenge::verify(&pact, b"wrong production"),
            RegenerationOutcome::Mismatch,
            "a different production is REFUSED"
        );
        // the challenge record can be written on chain
        let rec = RegenerationRecord::new(1, pact.record_hash(), RegenerationOutcome::Verified, 50);
        let blob = rec.to_blob();
        let back = RegenerationRecord::from_blob(&blob).expect("blob");
        assert_eq!(back.outcome, RegenerationOutcome::Verified);
        assert_eq!(back.record_hash(), rec.record_hash());
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(RegenerationRecord::from_blob(&bad).is_none());
    }

    #[test]
    fn residual_class_verified_with_residual() {
        // I6: producer + residual - the production AND the residual must be verified together
        let produced = b"the produced part";
        let residual = b"organic remainder 0x1234";
        let pact =
            PactRecord::producer_plus_residual([9u8; 32], [5u8; 32], produced, residual, 200);
        assert_eq!(
            RegenerationChallenge::verify_with_residual(&pact, produced, residual),
            RegenerationOutcome::Verified
        );
        // a wrong residual -> Mismatch (a class lie)
        assert_eq!(
            RegenerationChallenge::verify_with_residual(&pact, produced, b"different"),
            RegenerationOutcome::Mismatch
        );
        // a wrong production -> Mismatch
        assert_eq!(
            RegenerationChallenge::verify_with_residual(&pact, b"wrong", residual),
            RegenerationOutcome::Mismatch
        );
    }

    #[test]
    fn residual_only_matches_content_id() {
        // a lossless .bud: commitment = content_id -> production = the original bytes
        let original = b"lossless content 12345";
        let pact = PactRecord::residual_only(original, 300);
        assert_eq!(
            RegenerationChallenge::verify(&pact, original),
            RegenerationOutcome::Verified
        );
        assert_eq!(
            RegenerationChallenge::verify(&pact, b"different"),
            RegenerationOutcome::Mismatch
        );
    }

    #[test]
    fn regeneration_beats_proof_economy() {
        // The I2 rule: producing costs below 1 percent of proving (a zkVM proof is expensive)
        assert!(
            RegenerationChallenge::regeneration_beats_proof(1, 1000),
            "producing is 0.1 percent of the proving cost"
        );
        assert!(
            RegenerationChallenge::regeneration_beats_proof(50, 10_000),
            "%0.5"
        );
        assert!(
            !RegenerationChallenge::regeneration_beats_proof(200, 10_000),
            "%2 → kabul etmez"
        );
        assert!(
            !RegenerationChallenge::regeneration_beats_proof(1, 0),
            "proof_cost 0 → false"
        );
    }

    #[test]
    fn tampered_pact_rejected() {
        // a corrupt PACT (a class lie) -> NotProducible
        let produced = b"x";
        let mut pact = PactRecord::pure([1u8; 32], [2u8; 32], produced, 1);
        pact.residual_len = 5; // in PureProduction the residual must be 0 - verify REFUSES
        assert_eq!(
            RegenerationChallenge::verify(&pact, produced),
            RegenerationOutcome::NotProducible
        );
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
        let mut rng = Rng(0x5247_454E_2026_0816);
        let mut buf = [0u8; 128];
        for _ in 0..2000 {
            let len = (rng.next() % 128) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = RegenerationRecord::from_blob(&buf[..len]);
        }
    }
}
