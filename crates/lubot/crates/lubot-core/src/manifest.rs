//! LoRA/SFT çıktısının manifesti.
//!
//! Çıktı, zincir üstü `register_lubot_model` kaydıyla bu manifest'in
//! digest'i üzerinden eşleşir. Adaptör dtype'ı BF16/FP16 olarak tip
//! sisteminde kalır (FP4 yoktur - router-collapse riski, araştırma §1.5).

use crate::model::{placeholder_digest, Hash32, ModelId};

/// Adaptör hassasiyeti. FP4 bilinçli olarak yoktur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterDtype {
    Bf16,
    Fp16,
}

/// Eğitim çıktısı manifesti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoRaManifest {
    pub base_model: ModelId,
    /// Adaptörün SHA-256'sı. Üretimde zorunlu (fail-closed).
    pub adapter_sha256: Option<String>,
    pub rank: u16,
    pub alpha: u16,
    pub dtype: AdapterDtype,
    /// Eğitimde kullanılan veri setlerinin content_id listesi.
    pub dataset_refs: Vec<Hash32>,
    /// Eğitim çerçevesi (ör. "llama-factory", "axolotl").
    pub framework: String,
    /// ISO-8601 tarih.
    pub trained_at: String,
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

    /// Manifest digest'i (yer tutucu; üretimde SHA-256 girer).
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.base_model.0);
        buf.extend_from_slice(&self.rank.to_le_bytes());
        buf.extend_from_slice(&self.alpha.to_le_bytes());
        for r in &self.dataset_refs {
            buf.extend_from_slice(r);
        }
        placeholder_digest(&buf)
    }

    /// Üretim kabulü: adaptör hash'i ve tarih olmadan çıktı kilitlenmez.
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

    #[test]
    fn default_dtype_is_bf16_not_fp4() {
        let m = LoRaManifest::new(ModelId([2; 32]), 16, 32);
        assert_eq!(m.dtype, AdapterDtype::Bf16);
        // FP4 bu enum'da yoktur; aşağıdaki satır derlenmez:
        // let _ = AdapterDtype::Fp4;
    }
}
