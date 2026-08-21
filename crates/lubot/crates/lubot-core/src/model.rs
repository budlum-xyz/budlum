//! Model kimliği ve kayıt tipleri.
//!
//! `ModelId`, budlum/main'deki `AiModelId(model_hash)` ile birebir aynı
//! biçimdir: 32 bayt model hash'i. Off-chain checkpoint ile on-chain kayıt
//! aynı digest'ten türetilir; eşleşme çapraz testle sabitlenir.

use crate::tier::ModelTier;

/// 32 bayt hash.
pub type Hash32 = [u8; 32];

/// Zincir üstü `AiModelId` ile aynı biçim (budlum/main `src/ai/types.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModelId(pub Hash32);

/// Taban modelin lisansı. İnce ayar çıktısının atıf yükümlülükleri buna göre
/// kurulur (bkz. `NOTICE.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelLicense {
    /// DeepSeek V4 ağırlıkları: standart MIT.
    Mit,
    /// Apache-2.0 (NOTICE taşıma yükümlülüğü).
    Apache20,
    /// Diğer; metin saklanır ve kayıt öncesi gözden geçirme zorunludur.
    Other(String),
}

/// İnce ayarın başladığı checkpoint türü.
///
/// DeepSeek V4'te Base modeller yayınlandı; bu fark SFT zeminini değiştirir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FineTuneSource {
    /// Sıfırdan SFT için uygun base checkpoint.
    BaseModel,
    /// Yalnız instruct checkpoint var; LoRA bunun üzerine kurulur.
    InstructModel,
}

/// Off-chain checkpoint kaydı. Ağırlıklar repo'ya girmez; hash + kaynak izlenir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSpec {
    pub model_id: ModelId,
    /// Ör. `deepseek-ai/DeepSeek-V4-Flash-Base`
    pub base_repo: String,
    pub revision: Option<String>,
    /// Checkpoint SHA-256'sı. Üretimde zorunlu; iskelette `None` kalabilir
    /// ama `None` iken kayıt fail-closed reddedilir (bkz. lubot-data::verify).
    pub sha256: Option<String>,
    pub license: ModelLicense,
    pub fine_tune_source: FineTuneSource,
    /// Bu checkpoint'in desteklediği Lubot kademesi (`light` / `normal`).
    pub tier: ModelTier,
}

impl ModelSpec {
    /// Yeni kayıt. `sha256` boşken bu kayıt yalnızca taslaktır.
    #[must_use]
    pub fn new(
        model_id: ModelId,
        base_repo: impl Into<String>,
        license: ModelLicense,
        fine_tune_source: FineTuneSource,
        tier: ModelTier,
    ) -> Self {
        Self {
            model_id,
            base_repo: base_repo.into(),
            revision: None,
            sha256: None,
            license,
            fine_tune_source,
            tier,
        }
    }

    /// SHA-256'sız kayıt üretim kabulüne uygun değildir.
    #[must_use]
    pub fn is_production_ready(&self) -> bool {
        self.sha256.is_some()
    }
}

/// Yer tutucu digest: gerçek SHA-256 (ring/sha2) üretim fazında girer.
/// Bu fonksiyon güvenlik amacı taşımaz; yalnızca iskelet testlerinde kullanılır.
#[must_use]
pub fn placeholder_digest(bytes: &[u8]) -> Hash32 {
    let mut out = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        out[i % 32] = out[i % 32].wrapping_add(*b);
        out[(i * 7 + 3) % 32] ^= b.rotate_left((i % 8) as u32);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_id_mirrors_32_byte_hash() {
        let id = ModelId([7; 32]);
        assert_eq!(id.0.len(), 32);
    }

    #[test]
    fn spec_without_sha256_is_not_production_ready() {
        let spec = ModelSpec::new(
            ModelId([1; 32]),
            "deepseek-ai/DeepSeek-V4-Flash-Base",
            ModelLicense::Mit,
            FineTuneSource::BaseModel,
            crate::tier::ModelTier::Light,
        );
        assert!(!spec.is_production_ready());
        let mut ready = spec;
        ready.sha256 = Some("ab".repeat(32));
        assert!(ready.is_production_ready());
    }

    #[test]
    fn flash_base_maps_to_light_tier() {
        let spec = ModelSpec::new(
            ModelId([1; 32]),
            "deepseek-ai/DeepSeek-V4-Flash-Base",
            ModelLicense::Mit,
            FineTuneSource::BaseModel,
            crate::tier::ModelTier::Light,
        );
        assert_eq!(spec.tier, crate::tier::ModelTier::Light);
    }

    #[test]
    fn placeholder_digest_is_deterministic() {
        assert_eq!(placeholder_digest(b"lubot"), placeholder_digest(b"lubot"));
        assert_ne!(placeholder_digest(b"lubot"), placeholder_digest(b"lobot"));
    }
}
