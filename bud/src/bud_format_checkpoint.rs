//! B.U.D. 2.0 invention - direction 2: the checkpoint consensus state machine
//! (2026-08-16).
//!
//! Research: inspiration 2 D (a durable state machine plus checkpoint
//! conformance), S.123 (decentralised agent coordination) and K53/K67 (the
//! SEC 17a-4 audit trail: a hash chain plus a timestamp, an identity and a
//! cryptographic proof). B.U.D.'s multi-format multi-ratio consensus is carried
//! by a durable checkpoint: the chosen ratio and signature of every format is
//! stored in the checkpoint and restored on restart, and a corrupted chain is
//! REFUSED.
//!
//! This module is not a skeleton but a working core: a hash-chained checkpoint
//! plus its verification.

#![forbid(unsafe_code)]

use crate::bud_format_container::FormatCodec;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub epoch: u64,
    pub codec: FormatCodec,
    pub expert: String,
    pub pipe: String,
    pub ratio: f64,
    pub content_root: [u8; 32],
    pub prev_hash: [u8; 32], // the chain: the hash of the previous checkpoint (all zero = genesis)
    pub hash: [u8; 32],      // anchored hash: the cryptographic proof at record time (SEC 17a-4)
}

impl Checkpoint {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_CHECKPOINT_V1";

    pub fn new(
        epoch: u64,
        codec: FormatCodec,
        expert: &str,
        pipe: &str,
        ratio: f64,
        content_root: [u8; 32],
        prev_hash: [u8; 32],
    ) -> Self {
        let mut cp = Checkpoint {
            epoch,
            codec,
            expert: expert.to_string(),
            pipe: pipe.to_string(),
            ratio,
            content_root,
            prev_hash,
            hash: [0u8; 32],
        };
        cp.hash = cp.compute_hash();
        cp
    }

    /// Domain-etiketli kriptografik hash (K3 deseni).
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update(self.epoch.to_le_bytes());
        h.update((self.codec as u16).to_le_bytes());
        h.update((self.expert.len() as u64).to_le_bytes());
        h.update(self.expert.as_bytes());
        h.update((self.pipe.len() as u64).to_le_bytes());
        h.update(self.pipe.as_bytes());
        h.update(self.ratio.to_le_bytes());
        h.update(self.content_root);
        h.update(self.prev_hash);
        h.finalize().into()
    }

    /// Anchored chain verification: the stored hash of every checkpoint has to
    /// equal the recomputed one (the record is intact), and `prev_hash` has to
    /// be the hash of the one before it (the chain is unbroken). The genesis
    /// `prev_hash` is `[0;32]`.
    pub fn verify_chain(checkpoints: &[Checkpoint]) -> bool {
        for (i, cp) in checkpoints.iter().enumerate() {
            if cp.hash != cp.compute_hash() {
                return false; // the record is corrupt (a ratio or field changed)
            }
            if i == 0 {
                if cp.prev_hash != [0u8; 32] {
                    return false; // genesis has to be the head of the chain
                }
            } else {
                let prev = &checkpoints[i - 1];
                if cp.prev_hash != prev.hash {
                    return false; // the chain is broken
                }
            }
        }
        true
    }

    /// The latest, authoritative checkpoint - restored on restart.
    pub fn latest(checkpoints: &[Checkpoint]) -> Option<&Checkpoint> {
        checkpoints.last()
    }

    /// The ratio ceiling check (KF): is the chosen ratio plausible, meaning
    /// neither a zip bomb nor zero.
    pub fn ratio_plausible(&self, min: f64, max: f64) -> bool {
        self.ratio >= min && self.ratio <= max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bud_format_container::content_id;

    fn root(seed: u8) -> [u8; 32] {
        content_id(&[seed; 32])
    }

    #[test]
    fn chain_verifies_and_restores_latest() {
        let c1 = Checkpoint::new(
            1,
            FormatCodec::Json,
            "json-expert",
            "zstd19",
            7.83,
            root(1),
            [0u8; 32],
        );
        let h1 = c1.compute_hash();
        let c2 = Checkpoint::new(
            2,
            FormatCodec::Log,
            "log-expert",
            "zstd19",
            6.17,
            root(2),
            h1,
        );
        let chain = vec![c1, c2];
        assert!(Checkpoint::verify_chain(&chain), "a valid chain");
        let latest = Checkpoint::latest(&chain).unwrap();
        assert_eq!(latest.epoch, 2);
        assert!(latest.ratio_plausible(1.0, 100.0));
    }

    #[test]
    fn broken_chain_rejected() {
        let c1 = Checkpoint::new(
            1,
            FormatCodec::Json,
            "json-expert",
            "zstd19",
            7.83,
            root(1),
            [0u8; 32],
        );
        let c2 = Checkpoint::new(
            2,
            FormatCodec::Log,
            "log-expert",
            "zstd19",
            6.17,
            root(2),
            [0xAA; 32],
        );
        assert!(
            !Checkpoint::verify_chain(&[c1, c2]),
            "prev hash uymayan zincir RED"
        );
    }

    #[test]
    fn genesis_must_be_zero_prev() {
        let c1 = Checkpoint::new(
            1,
            FormatCodec::Json,
            "json-expert",
            "zstd19",
            7.83,
            root(1),
            [0x01; 32],
        );
        assert!(
            !Checkpoint::verify_chain(&[c1]),
            "the genesis prev has to be zero"
        );
    }

    #[test]
    fn tampered_ratio_breaks_chain() {
        let c1 = Checkpoint::new(
            1,
            FormatCodec::Json,
            "json-expert",
            "zstd19",
            7.83,
            root(1),
            [0u8; 32],
        );
        let h1 = c1.compute_hash();
        let mut c2 = Checkpoint::new(
            2,
            FormatCodec::Log,
            "log-expert",
            "zstd19",
            6.17,
            root(2),
            h1,
        );
        assert!(Checkpoint::verify_chain(&[c1.clone(), c2.clone()]));
        c2.ratio = 13750.0; // tampered with, so the record is corrupt
        assert!(
            !Checkpoint::verify_chain(&[c1, c2]),
            "when the ratio changes the chain is REFUSED"
        );
    }
}
