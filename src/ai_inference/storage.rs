//! B.U.D. storage + AI dataset entegrasyonu.
//!
//! Binds AI-dataset metadata to a StorageDeal - a training corpus or an
//! inference cache. This completes the storage side of the closed-circuit
//! principle: the AI inference layer only reads data from B.U.D. storage that is labelled as an
//! AI dataset.

use crate::domain::storage_deal::StorageDeal;

use super::{AiDatasetKind, AiDatasetMetadata};

/// A B.U.D. StorageDeal labelled as an AI dataset.
#[derive(Clone, Debug)]
pub struct AiDatasetStorageDeal {
    /// Temel storage deal (B.U.D. depolama).
    pub deal: StorageDeal,
    /// The AI dataset metadata: kind, model target and sample count.
    pub ai_metadata: AiDatasetMetadata,
}

impl AiDatasetStorageDeal {
    /// Binds AI metadata to a StorageDeal.
    #[must_use]
    pub fn new(deal: StorageDeal, ai_metadata: AiDatasetMetadata) -> Self {
        Self { deal, ai_metadata }
    }

    /// Is this a training corpus?
    #[must_use]
    pub fn is_training_corpus(&self) -> bool {
        self.ai_metadata.kind == AiDatasetKind::TrainingCorpus
    }

    /// Is this an inference cache?
    #[must_use]
    pub fn is_inference_cache(&self) -> bool {
        self.ai_metadata.kind == AiDatasetKind::InferenceCache
    }
}
