//! Görev A — B.U.D. storage + AI dataset entegrasyonu.
//!
//! Bir StorageDeal'a AI-dataset metadata'sı bağlar (eğitim corpus / çıkarım önbelleği).
//! Bu, kapalı-devre prensibinin depolama tarafını tamamlar: Lubot yalnızca
//! AI-dataset olarak etiketlenmiş B.U.D. depolamasındaki veriyi okur.

use crate::domain::storage_deal::StorageDeal;

use super::{AiDatasetKind, AiDatasetMetadata};

/// AI dataset olarak etiketlenmiş bir B.U.D. StorageDeal.
#[derive(Clone, Debug)]
pub struct AiDatasetStorageDeal {
    /// Temel storage deal (B.U.D. depolama).
    pub deal: StorageDeal,
    /// AI dataset metadata (tür + model target + örnek sayısı).
    pub ai_metadata: AiDatasetMetadata,
}

impl AiDatasetStorageDeal {
    /// Bir StorageDeal'a AI metadata bağla.
    #[must_use]
    pub fn new(deal: StorageDeal, ai_metadata: AiDatasetMetadata) -> Self {
        Self { deal, ai_metadata }
    }

    /// Eğitim corpus'u mu?
    #[must_use]
    pub fn is_training_corpus(&self) -> bool {
        self.ai_metadata.kind == AiDatasetKind::TrainingCorpus
    }

    /// Çıkarım önbelleği mi?
    #[must_use]
    pub fn is_inference_cache(&self) -> bool {
        self.ai_metadata.kind == AiDatasetKind::InferenceCache
    }
}
