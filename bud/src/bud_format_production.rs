//! A B.U.D. 2.0 invention: the production ratio proof, `BudProductionRecord`,
//! 2026-08-16.
//!
//! "Making the compression ratio claim verifiable on the blockchain": every
//! `.bud` container can carry a production record AT THE MOMENT OF PRODUCTION,
//! holding the real measured ratio, the pipeline identity, the original and
//! stored sizes, and the `content_root` anchor. The record is hashed with a
//! domain-tagged SHA3 (K3) and can be written into the checkpoint chain.
//!
//! Verification, on chain: anyone can recompute `record_hash`, and `verify`
//! checks ratio consistency, that `claimed_ratio` is approximately
//! `original_len / stored_len`. The K19 gate: an unmeasured, inflated ratio
//! claim, such as 17.19x against a real 7.83x, is REFUSED. A production proof
//! is valid only when it comes from REAL production.
//!
//! The code is `#![forbid(unsafe_code)]`, deterministic and tested.

#![forbid(unsafe_code)]

use crate::bud_format_container::FormatCodec;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub struct BudProductionRecord {
    pub format_codec: FormatCodec,
    pub pipe: &'static str, // "structural+zstd19", "json-columnar-exact", ...
    pub original_len: u64,
    pub stored_len: u64,
    pub payload_root: [u8; 32], // content_id(original), the K3 anchor
    pub ts_unix: u64,
    pub claimed_ratio: f64, // the ratio MEASURED during production, not invented
}

impl BudProductionRecord {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_PRODUCTION_V1";
    pub const RATIO_TOLERANCE: f64 = 0.01;

    pub fn new(
        format_codec: FormatCodec,
        pipe: &'static str,
        original: &[u8],
        stored_len: u64,
        ts_unix: u64,
    ) -> Self {
        let root = crate::bud_format_container::content_id(original);
        let claimed_ratio = if stored_len > 0 {
            original.len() as f64 / stored_len as f64
        } else {
            1.0
        };
        BudProductionRecord {
            format_codec,
            pipe,
            original_len: original.len() as u64,
            stored_len,
            payload_root: root,
            ts_unix,
            claimed_ratio,
        }
    }

    /// The domain-tagged cryptographic hash, in the K3 pattern; an identity
    /// writable on chain.
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((self.format_codec as u16).to_le_bytes());
        h.update((self.pipe.len() as u64).to_le_bytes());
        h.update(self.pipe.as_bytes());
        h.update(self.original_len.to_le_bytes());
        h.update(self.stored_len.to_le_bytes());
        h.update(self.payload_root);
        h.update(self.ts_unix.to_le_bytes());
        h.update(self.claimed_ratio.to_le_bytes());
        h.finalize().into()
    }

    /// Consistency: does the ratio claim match the sizes, and are the values
    /// valid (K38)?
    pub fn verify(&self) -> bool {
        if !self.claimed_ratio.is_finite() || self.claimed_ratio <= 0.0 {
            return false;
        }
        if self.stored_len == 0 && self.original_len > 0 {
            return false;
        }
        let actual = if self.stored_len > 0 {
            self.original_len as f64 / self.stored_len as f64
        } else {
            1.0
        };
        (self.claimed_ratio - actual).abs() <= Self::RATIO_TOLERANCE
    }

    /// The deterministic blob, for the chain or segment record.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.format_codec as u16).to_le_bytes());
        out.extend_from_slice(&(self.pipe.len() as u32).to_le_bytes());
        out.extend_from_slice(self.pipe.as_bytes());
        out.extend_from_slice(&self.original_len.to_le_bytes());
        out.extend_from_slice(&self.stored_len.to_le_bytes());
        out.extend_from_slice(&self.payload_root);
        out.extend_from_slice(&self.ts_unix.to_le_bytes());
        out.extend_from_slice(&self.claimed_ratio.to_le_bytes());
        out.extend_from_slice(&self.record_hash());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 + 4 + 32 + 8 + 8 + 8 + 32 {
            return None;
        }
        let mut pos = 0usize;
        let format_codec = crate::bud_format_container::FormatCodec::from_u16(u16::from_le_bytes(
            bytes[0..2].try_into().ok()?,
        ));
        pos += 2;
        let pipe_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if bytes.len() < pos + pipe_len {
            return None;
        }
        let pipe = std::str::from_utf8(&bytes[pos..pos + pipe_len])
            .ok()?
            .to_string();
        pos += pipe_len;
        if bytes.len() < pos + 8 + 8 + 32 + 8 + 8 + 32 {
            return None;
        }
        let original_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let stored_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let mut payload_root = [0u8; 32];
        payload_root.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let ts_unix = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let claimed_ratio = f64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        if bytes.len() != pos + 32 {
            return None;
        }
        let rec = BudProductionRecord {
            format_codec,
            pipe: Box::leak(pipe.into_boxed_str()),
            original_len,
            stored_len,
            payload_root,
            ts_unix,
            claimed_ratio,
        };
        if bytes[pos..] != rec.record_hash() {
            return None;
        }
        Some(rec)
    }

    /// The K19 gate: a claim cannot exceed `max_multiple` times the value in the
    /// measurement table. Unmeasured exaggeration, an invented ratio, is REFUSED.
    pub fn plausible_against(&self, measured: f64, max_multiple: f64) -> bool {
        if !measured.is_finite() || measured <= 0.0 {
            return false;
        }
        self.claimed_ratio <= measured * max_multiple
    }
}

pub struct ProductionGates;

impl ProductionGates {
    /// Is the record consistent and plausible against the measured ratio (K19)?
    pub fn k_bud_production(rec: &BudProductionRecord, measured: f64) -> Result<(), &'static str> {
        if !rec.verify() {
            return Err("K-BUD-PRODUCTION: record inconsistent (ratio != len ratio)");
        }
        if !rec.plausible_against(measured, 1.5) {
            return Err("K-BUD-PRODUCTION: ratio > measured*1.5, an invented claim");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_record_verify_and_hash() {
        let data = br#"[{"u":"u1","v":1},{"u":"u1","v":2}]"#;
        let rec = BudProductionRecord::new(FormatCodec::Json, "json-columnar-exact", data, 120, 42);
        assert!(rec.verify(), "the production record is consistent");
        assert!((rec.claimed_ratio - data.len() as f64 / 120.0).abs() < 0.01);
        assert_ne!(rec.record_hash(), [0u8; 32], "the hash is not empty");
        // The same fields give the same hash, deterministically.
        let rec2 =
            BudProductionRecord::new(FormatCodec::Json, "json-columnar-exact", data, 120, 42);
        assert_eq!(rec.record_hash(), rec2.record_hash());
        // A different size gives a different hash.
        let rec3 =
            BudProductionRecord::new(FormatCodec::Json, "json-columnar-exact", data, 121, 42);
        assert_ne!(rec.record_hash(), rec3.record_hash());
    }

    #[test]
    fn production_ratio_gate_rejects_fake() {
        // K19: a claim of 17.19x against a measured 7.83x is REFUSED, as invented.
        let data = b"x".repeat(1000);
        let rec = BudProductionRecord::new(FormatCodec::Json, "structural+zstd19", &data, 58, 1);
        // 1000/58 is 17.24x, above 1.5 times the measured JSON figure of 7.83x, so
        // it is REFUSED.
        assert!(
            ProductionGates::k_bud_production(&rec, 7.83).is_err(),
            "a 17x claim is refused"
        );
        // 8.0x is consistent with the measurement and passes.
        let rec2 = BudProductionRecord::new(FormatCodec::Json, "structural+zstd19", &data, 125, 1);
        assert!(
            ProductionGates::k_bud_production(&rec2, 7.83).is_ok(),
            "an 8.0x claim passes"
        );
    }

    #[test]
    fn production_verify_detects_tamper() {
        let data = br#"{"a":1}"#;
        let rec = BudProductionRecord::new(FormatCodec::Json, "json-columnar-exact", data, 50, 7);
        assert!(rec.verify());
        // Inflate the ratio by hand and verify refuses.
        let mut bad = rec.clone();
        bad.claimed_ratio = 999.0;
        assert!(!bad.verify(), "a ratio inconsistency is refused");
        // A stored length of zero with content present is refused.
        let mut bad2 = rec.clone();
        bad2.stored_len = 0;
        bad2.claimed_ratio = 1.0;
        assert!(!bad2.verify(), "a zero stored length is refused");
    }
}
