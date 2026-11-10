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
/// output are built on it; the licence of those weights travels with the weights, not with this repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelLicense {
    /// Base weights published under a permissive licence.
    Mit,
    /// Apache-2.0 (carries a NOTICE obligation).
    Apache20,
    /// Anything else; the text is stored and a review before registration is
    /// mandatory.
    Other(String),
}

/// The kind of checkpoint the fine-tuning started from.
///
/// Some upstreams publish Base models next to instruct ones, and that difference changes the ground
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
    /// For example `<operator-org>/<base-checkpoint>`; the value is configuration, not a constant of this layer.
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

/// The digest the output lock and the manifest use: SHA-256 over a domain tag
/// and the bytes. The earlier skeleton mixed bytes with add and xor, so zero
/// bytes contributed nothing and collisions were constructible (P34-F07).
#[must_use]
pub fn placeholder_digest(bytes: &[u8]) -> Hash32 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"BDLM_AI_CORE_DIGEST_V1");
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    h.finalize().into()
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
            "example-org/base-checkpoint-light",
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
    fn light_base_maps_to_light_tier() {
        let spec = ModelSpec::new(
            ModelId([1; 32]),
            "example-org/base-checkpoint-light",
            ModelLicense::Mit,
            FineTuneSource::BaseModel,
            crate::tier::ModelTier::Light,
        );
        assert_eq!(spec.tier, crate::tier::ModelTier::Light);
    }

    /// P34-F07: zero bytes must change the digest.
    #[test]
    fn digest_distinguishes_zero_padding() {
        assert_ne!(placeholder_digest(&[]), placeholder_digest(&[0u8; 32]));
        assert_ne!(
            placeholder_digest(&[0u8; 32]),
            placeholder_digest(&[0u8; 33])
        );
    }

    #[test]
    fn placeholder_digest_is_deterministic() {
        assert_eq!(
            placeholder_digest(b"ai_inference"),
            placeholder_digest(b"ai_inference")
        );
        assert_ne!(
            placeholder_digest(b"ai_inference"),
            placeholder_digest(b"lobot")
        );
    }
}
