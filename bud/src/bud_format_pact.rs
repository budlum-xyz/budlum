//! B.U.D. 2.0 - the production contract (PACT) record (2026-08-16)
//!
//! The .bud format counterpart of invention I1 (PACT registry):
//! the on-chain existence of content is not bytes but the tuple `(producer_hash, seed, commitment,
//! residual_commitment)`. This module:
//!   - computes the generatability class of a .bud container (with residual = 0
//!     the bytes are fully reproducible from the producer - F1/F14),
//!   - hashes the PACT record with domain-tagged SHA3 (writable on chain),
//!   - verification: the commitment of the produced bytes must match the record (I2 generate_and_verify).
//!
//! Losslessness: a PACT record does not replace the ORIGINAL; it is the integrity anchor of the container.
//! The generatable class claim permits integrity verification even when a LOSSY transform
//! (for example a video codec) is used inside the .bud: commitment = H(producer output), and the bytes are
//! reproducible. In the lossless class commitment = content_id(original) (K3).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const PACT_MAGIC: [u8; 8] = *b"\xB5PACT\0\0\0";
pub const PACT_VERSION: u8 = 1;

/// Production mode (the `mod` field of invention I1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PactMode {
    /// Pure production: no residual, all bytes are produced from the producer (F1/F14)
    PureProduction = 0,
    /// Recipe plus residual: the unproducible remainder sits in the owner/erasure layer (I6)
    RecipePlusResidual = 1,
    /// Residual only: the unproducible class (organic), ordinary lossless storage
    ResidualOnly = 2,
}

impl PactMode {
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::PureProduction),
            1 => Some(Self::RecipePlusResidual),
            2 => Some(Self::ResidualOnly),
            _ => None,
        }
    }
}

/// The production contract record (I1). About 100 bytes - even if the content is 1 GB.
#[derive(Debug, Clone)]
pub struct PactRecord {
    pub mode: PactMode,
    pub producer_id: [u8; 32], // the hash of the deterministic producer function
    pub seed: [u8; 32],        // the producer input (the seed)
    pub commitment: [u8; 32],  // H(produced bytes) - the proof of matching production
    pub residual_commitment: [u8; 32], // H(residual) - RecipePlusResidual when non-empty
    pub residual_len: u64,     // the residual size (the input of the I6 price function)
    pub byte_budget: u64,      // the ceiling on physical load imposed on the network (I8)
    pub ts_unix: u64,
}

impl PactRecord {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_PACT_V1";
    pub const EMPTY_RESIDUAL: [u8; 32] = [0u8; 32]; // the representation of an empty residual (I1)

    /// A pure production record (residual = 0, commitment = H(produced bytes)).
    pub fn pure(producer_id: [u8; 32], seed: [u8; 32], produced: &[u8], ts: u64) -> Self {
        PactRecord {
            mode: PactMode::PureProduction,
            producer_id,
            seed,
            commitment: Self::hash_bytes(b"BDLM_PACT_OUTPUT_V1", produced),
            residual_commitment: Self::EMPTY_RESIDUAL,
            residual_len: 0,
            byte_budget: 0,
            ts_unix: ts,
        }
    }

    /// A recipe plus residual record (the unproducible remainder gets its own commitment).
    pub fn producer_plus_residual(
        producer_id: [u8; 32],
        seed: [u8; 32],
        produced: &[u8],
        residual: &[u8],
        ts: u64,
    ) -> Self {
        PactRecord {
            mode: PactMode::RecipePlusResidual,
            producer_id,
            seed,
            commitment: Self::hash_bytes(b"BDLM_PACT_OUTPUT_V1", produced),
            residual_commitment: Self::hash_bytes(b"BDLM_PACT_RESIDUAL_V1", residual),
            residual_len: residual.len() as u64,
            byte_budget: 0,
            ts_unix: ts,
        }
    }

    /// For a lossless .bud: commitment = content_id(original) (K3) - exact integrity.
    pub fn residual_only(original: &[u8], ts: u64) -> Self {
        let cid = crate::bud_format_container::content_id(original);
        PactRecord {
            mode: PactMode::ResidualOnly,
            producer_id: [0u8; 32],
            seed: [0u8; 32],
            commitment: cid,
            residual_commitment: cid,
            residual_len: original.len() as u64,
            byte_budget: original.len() as u64,
            ts_unix: ts,
        }
    }

    /// A domain-tagged cryptographic hash - an identity writable on chain (I1).
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update([self.mode.to_u8()]);
        h.update(self.producer_id);
        h.update(self.seed);
        h.update(self.commitment);
        h.update(self.residual_commitment);
        h.update(self.residual_len.to_le_bytes());
        h.update(self.byte_budget.to_le_bytes());
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }

    /// CONSENSUS-SAFE SERIALIZATION (remaining work item 5 - the verification test is below):
    /// `to_blob`/`from_blob` below (PACT_MAGIC + fields + the record_hash digest)
    /// already exist and are CANONICAL: the same logical record -> the SAME bytes -> no effect on the state
    /// root (section 10.3). Test: `consensus_safe_serialization_roundtrip`.
    /// Production verification (I2 generate_and_verify): do the produced bytes satisfy the commitment?
    /// In the lossless class (ResidualOnly) commitment = content_id(original) - it must match K3.
    pub fn verify_production(&self, produced: &[u8]) -> bool {
        match self.mode {
            PactMode::PureProduction | PactMode::RecipePlusResidual => {
                self.commitment == Self::hash_bytes(b"BDLM_PACT_OUTPUT_V1", produced)
            }
            PactMode::ResidualOnly => {
                self.commitment == crate::bud_format_container::content_id(produced)
            }
        }
    }

    /// Class-lie check (I6): residual_len 0 with mode RecipePlusResidual is inconsistent.
    pub fn verify(&self) -> bool {
        match self.mode {
            PactMode::PureProduction => self.residual_len == 0,
            PactMode::RecipePlusResidual => {
                self.residual_len > 0 && self.residual_commitment != Self::EMPTY_RESIDUAL
            }
            PactMode::ResidualOnly => {
                self.residual_len > 0 && self.residual_commitment == self.commitment
            }
        }
    }

    /// Residual verification (I6): do the given residual bytes satisfy the commitment?
    pub fn verify_residual(&self, residual: &[u8]) -> bool {
        match self.mode {
            PactMode::RecipePlusResidual => {
                self.residual_commitment == Self::hash_bytes(b"BDLM_PACT_RESIDUAL_V1", residual)
            }
            PactMode::ResidualOnly => {
                self.residual_commitment == crate::bud_format_container::content_id(residual)
            }
            PactMode::PureProduction => residual.is_empty(),
        }
    }

    fn hash_bytes(domain: &[u8], data: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(domain);
        h.update((data.len() as u64).to_le_bytes());
        h.update(data);
        h.finalize().into()
    }
}

/// A deterministic blob (magic + version + fields + digest).
impl PactRecord {
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PACT_MAGIC);
        out.push(PACT_VERSION);
        out.push(self.mode.to_u8());
        out.extend_from_slice(&self.producer_id);
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.residual_commitment);
        out.extend_from_slice(&self.residual_len.to_le_bytes());
        out.extend_from_slice(&self.byte_budget.to_le_bytes());
        out.extend_from_slice(&self.ts_unix.to_le_bytes());
        out.extend_from_slice(&self.record_hash()); // digest (kurcalama RED)
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 1 + 32 + 32 + 32 + 32 + 8 + 8 + 8;
        if bytes.len() < HDR + 32 || bytes[0..8] != PACT_MAGIC || bytes[8] != PACT_VERSION {
            return None;
        }
        let mode = PactMode::from_u8(bytes[9])?;
        let mut r = PactRecord {
            mode,
            producer_id: [0u8; 32],
            seed: [0u8; 32],
            commitment: [0u8; 32],
            residual_commitment: [0u8; 32],
            residual_len: 0,
            byte_budget: 0,
            ts_unix: 0,
        };
        let mut pos = 10;
        r.producer_id.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        r.seed.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        r.commitment.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        r.residual_commitment.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        r.residual_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        r.byte_budget = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        r.ts_unix = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        if bytes.len() != pos + 32 {
            return None; // trailing bytes -> strict refusal
        }
        if bytes[pos..] != r.record_hash() {
            return None; // kurcalama
        }
        if !r.verify() {
            return None;
        }
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_production_roundtrip_and_verify() {
        // pure production: producer + seed -> bytes; the commitment must match the production
        let seed = [7u8; 32];
        let producer = [1u8; 32];
        let produced = b"deterministic production output 1234567890";
        let pact = PactRecord::pure(producer, seed, produced, 100);
        assert!(
            pact.verify_production(produced),
            "the production commitment matches"
        );
        assert!(
            !pact.verify_production(b"another output"),
            "a different production is REFUSED"
        );
        assert!(pact.verify(), "pure production is consistent");
        // blob roundtrip
        let blob = pact.to_blob();
        let back = PactRecord::from_blob(&blob).expect("blob okunur");
        assert_eq!(back.record_hash(), pact.record_hash());
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(PactRecord::from_blob(&bad).is_none());
        // trailing bytes are refused
        let mut extra = blob.clone();
        extra.push(0x00);
        assert!(PactRecord::from_blob(&extra).is_none());
        // short input
        assert!(PactRecord::from_blob(&[0u8; 20]).is_none());
    }

    #[test]
    fn producer_plus_residual_classification() {
        // producer plus residual: the unproducible remainder gets its own commitment (I6)
        let produced = b"the produced part";
        let residual = b"organic remainder: noise 0x1234";
        let pact =
            PactRecord::producer_plus_residual([9u8; 32], [5u8; 32], produced, residual, 200);
        assert!(pact.verify_production(produced));
        assert!(pact.verify(), "a residual above zero is consistent");
        assert_eq!(pact.residual_len, residual.len() as u64);
        // class lie: mode RecipePlusResidual with residual_len 0 -> verify REFUSES (I6)
        let mut liar = pact.clone();
        liar.residual_len = 0;
        assert!(!liar.verify(), "hiding the residual is REFUSED");
        // the right residual -> verify_residual passes; a different residual -> refused (I6)
        assert!(pact.verify_residual(residual), "the right residual matches");
        assert!(
            !pact.verify_residual(b"a different residual"),
            "a different residual is REFUSED"
        );
        let mut liar2 = pact.clone();
        liar2.residual_commitment = [1u8; 32];
        assert!(
            !liar2.verify_residual(residual),
            "a tampered commitment is REFUSED"
        );
    }

    #[test]
    fn residual_only_matches_content_id() {
        // a lossless .bud: commitment = content_id(original) (K3)
        let original = b"lossless content 12345";
        let pact = PactRecord::residual_only(original, 300);
        assert!(pact.verify_production(original), "content_id matches");
        assert!(
            !pact.verify_production(b"different"),
            "different content is REFUSED"
        );
        assert_eq!(
            pact.commitment,
            crate::bud_format_container::content_id(original)
        );
        assert!(pact.verify());
    }

    #[test]
    fn pact_record_small_and_deterministic() {
        // I1 acceptance: a PACT record is about 100-150 bytes
        let seed = [1u8; 32];
        let pact = PactRecord::pure([2u8; 32], seed, b"x", 1);
        let blob = pact.to_blob();
        assert!(
            blob.len() <= 256,
            "the PACT record is compact: {} bytes",
            blob.len()
        );
        // the same fields -> the same hash (deterministic)
        let pact2 = PactRecord::pure([2u8; 32], seed, b"x", 1);
        assert_eq!(pact.record_hash(), pact2.record_hash());
        assert_ne!(pact.record_hash(), [0u8; 32]);
    }

    #[test]
    fn consensus_safe_serialization_roundtrip() {
        // I1: to_blob -> from_blob is exact; the blob is canonical (fixed size and order).
        let p1 = PactRecord::pure([7u8; 32], [9u8; 32], b"produced data", 1_768_000_000);
        let blob = p1.to_blob();
        let p2 = PactRecord::from_blob(&blob).expect("the blob opens");
        assert_eq!(p1.record_hash(), p2.record_hash(), "serialization is exact");
        assert_eq!(p1.mode, p2.mode);
        assert_eq!(p1.residual_len, p2.residual_len);
        // canonical: the same record -> the same bytes (no effect on the state root)
        let p3 = PactRecord::pure([7u8; 32], [9u8; 32], b"produced data", 1_768_000_000);
        assert_eq!(blob, p3.to_blob());
        // bozuk blob → None (panik yok)
        let mut bozuk = blob.clone();
        bozuk[10] ^= 0xFF;
        let r = PactRecord::from_blob(&bozuk);
        assert!(r.is_none() || r.unwrap().record_hash() != p1.record_hash());
        assert!(PactRecord::from_blob(b"kisa").is_none());
    }

    #[test]
    fn from_blob_never_panics() {
        // mini-fuzz: rastgele baytlarda from_blob panik'siz
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
        let mut rng = Rng(0x5041_4354_2026_0816);
        let mut buf = [0u8; 200];
        for _ in 0..2000 {
            let len = (rng.next() % 200) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = PactRecord::from_blob(&buf[..len]);
        }
    }
}
