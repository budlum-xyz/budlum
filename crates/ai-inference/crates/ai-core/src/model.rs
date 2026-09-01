//! Model identity and registration types.
//!
//! `ModelId` has exactly the same shape as `AiModelId(model_hash)` in
//! budlum/main: a 32-byte model hash. The off-chain checkpoint and the
//! on-chain registration are derived from the same digest, and the match is
//! pinned by a cross test.

use crate::tier::ModelTier;

/// A 32-byte hash.
pub type Hash32 = [u8; 32];

/// The same shape as the on-chain `AiModelId` (budlum/main
/// `src/ai/types.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModelId(pub Hash32);

/// The base model's licence. The attribution obligations of the fine-tuned
/// output are built on it (see `NOTICE.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelLicense {
    /// DeepSeek V4 weights: standard MIT.
    Mit,
    /// Apache-2.0 (carries a NOTICE obligation).
    Apache20,
    /// Anything else; the text is stored and a review before registration is
    /// mandatory.
    Other(String),
}

/// The kind of checkpoint the fine-tuning started from.
///
/// DeepSeek V4 published Base models, and that difference changes the ground
/// SFT stands on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FineTuneSource {
    /// A base checkpoint suitable for SFT from scratch.
    BaseModel,
    /// Only an instruct checkpoint exists; LoRA is built on top of it.
    InstructModel,
}

/// The off-chain checkpoint record. The weights do not enter the repo; the
/// hash and the source are tracked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSpec {
    pub model_id: ModelId,
    /// For example `deepseek-ai/DeepSeek-V4-Flash-Base`.
    pub base_repo: String,
    pub revision: Option<String>,
    /// The checkpoint SHA-256. Mandatory in production; it may stay `None` in
    /// the skeleton, but while it is `None` the record is refused fail-closed
    /// (see ai-data::verify).
    pub sha256: Option<String>,
    pub license: ModelLicense,
    pub fine_tune_source: FineTuneSource,
    /// The AI inference layer tier this checkpoint supports (`light` / `normal`).
    pub tier: ModelTier,
}

impl ModelSpec {
    /// A new record. While `sha256` is empty the record is only a draft.
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

    /// A record without a SHA-256 is not fit for production admission.
    #[must_use]
    pub fn is_production_ready(&self) -> bool {
        self.sha256.is_some()
    }
}

/// A placeholder digest: the real SHA-256 (ring/sha2) arrives in the
/// production phase. This function carries no security purpose; it is only
/// used in the skeleton tests.
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
        assert_eq!(placeholder_digest(b"ai_inference"), placeholder_digest(b"ai_inference"));
        assert_ne!(placeholder_digest(b"ai_inference"), placeholder_digest(b"lobot"));
    }
}
