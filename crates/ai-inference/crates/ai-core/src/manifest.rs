//! The manifest of a LoRA or SFT output.
//!
//! The output is matched against the on-chain `register_ai_model` record
//! through the digest of this manifest. The adapter dtype stays in the type
//! system as BF16 or FP16 (there is no FP4, because of the router-collapse
//! risk; see research section 1.5).

use crate::model::{placeholder_digest, Hash32, ModelId};

/// Adapter precision. FP4 is deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterDtype {
    Bf16,
    Fp16,
}

/// The training output manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoRaManifest {
    pub base_model: ModelId,
    /// The SHA-256 of the adapter. Mandatory in production (fail-closed).
    pub adapter_sha256: Option<String>,
    pub rank: u16,
    pub alpha: u16,
    pub dtype: AdapterDtype,
    /// The content_id list of the datasets used in training.
    pub dataset_refs: Vec<Hash32>,
    /// The training framework the run used, recorded as the operator named it.
    pub framework: String,
    /// ISO-8601 tarih.
    pub trained_at: String,
}

/// A length as 8 little-endian bytes.
fn len_prefix(len: usize) -> [u8; 8] {
    u64::try_from(len).unwrap_or(u64::MAX).to_le_bytes()
}

/// Appends a length-prefixed field.
fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&len_prefix(bytes.len()));
    buf.extend_from_slice(bytes);
}

impl LoRaManifest {
    #[must_use]
    pub fn new(base_model: ModelId, rank: u16, alpha: u16) -> Self {
        Self {
            base_model,
            adapter_sha256: None,
            rank,
            alpha,
            dtype: AdapterDtype::Bf16,
            dataset_refs: Vec::new(),
            framework: String::new(),
            trained_at: String::new(),
        }
    }

    /// The manifest digest (a placeholder; in production a SHA-256 goes here).
    ///
    /// Every field is bound. Each variable-length field carries a length
    /// prefix, so two different manifests cannot give the same input bytes.
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.base_model.0);
        match &self.adapter_sha256 {
            Some(h) => {
                buf.push(1);
                push_field(&mut buf, h.as_bytes());
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&self.rank.to_le_bytes());
        buf.extend_from_slice(&self.alpha.to_le_bytes());
        buf.push(match self.dtype {
            AdapterDtype::Bf16 => 1,
            AdapterDtype::Fp16 => 2,
        });
        buf.extend_from_slice(&len_prefix(self.dataset_refs.len()));
        for r in &self.dataset_refs {
            buf.extend_from_slice(r);
        }
        push_field(&mut buf, self.framework.as_bytes());
        push_field(&mut buf, self.trained_at.as_bytes());
        placeholder_digest(&buf)
    }

    /// Production acceptance: an output is not locked in without an adapter
    /// hash and a date.
    #[must_use]
    pub fn is_production_ready(&self) -> bool {
        self.adapter_sha256.is_some() && !self.trained_at.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_changes_with_dataset_refs() {
        let m = LoRaManifest::new(ModelId([2; 32]), 16, 32);
        let d1 = m.digest();

        let mut m2 = m.clone();
        m2.dataset_refs.push([3; 32]);
        assert_ne!(d1, m2.digest());
    }

    /// The digest binds the adapter hash, the dtype, the framework and the date.
    #[test]
    fn digest_binds_every_field() {
        let m = LoRaManifest::new(ModelId([2; 32]), 16, 32);
        let base = m.digest();

        let mut a = m.clone();
        a.adapter_sha256 = Some("ab".repeat(32));
        assert_ne!(base, a.digest());
        let mut a2 = a.clone();
        a2.adapter_sha256 = Some("cd".repeat(32));
        assert_ne!(a.digest(), a2.digest());

        let mut d = m.clone();
        d.dtype = AdapterDtype::Fp16;
        assert_ne!(base, d.digest());

        let mut f = m.clone();
        f.framework = "trainer".to_string();
        assert_ne!(base, f.digest());

        let mut t = m.clone();
        t.trained_at = "2026-01-01".to_string();
        assert_ne!(base, t.digest());
    }

    /// An all-zero dataset ref is not the same as no ref.
    #[test]
    fn zero_dataset_ref_differs_from_none() {
        let m = LoRaManifest::new(ModelId([2; 32]), 16, 32);
        let mut z = m.clone();
        z.dataset_refs.push([0; 32]);
        assert_ne!(m.digest(), z.digest());
    }

    #[test]
    fn default_dtype_is_bf16_not_fp4() {
        let m = LoRaManifest::new(ModelId([2; 32]), 16, 32);
        assert_eq!(m.dtype, AdapterDtype::Bf16);
        // FP4 does not exist in this enum; the line below does not compile:
        // let _ = AdapterDtype::Fp4;
    }
}
