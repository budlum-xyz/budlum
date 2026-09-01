//! AI dataset types - the same shape as `AiDatasetKind` /
//! `AiDatasetMetadata` in budlum/main `src/ai_inference/mod.rs` (mirror types).
//!
//! The permission rules are not copied here; they are queried from the chain
//! state (K3).

use crate::model::Hash32;

/// The dataset kind. Identical to `AiDatasetKind` in budlum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetKind {
    /// A training corpus (the SFT/CPT input).
    TrainingCorpus,
    /// An inference cache (closed-circuit inference responses).
    InferenceCache,
}

/// AI dataset metadata bound to a B.U.D. StorageDeal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetMetadata {
    pub kind: DatasetKind,
    /// Which model it targets (budlum: `model_target`).
    pub model_target: Option<Hash32>,
    pub sample_count: u64,
}

impl DatasetMetadata {
    /// The training corpus label.
    #[must_use]
    pub fn training(model_target: Hash32, sample_count: u64) -> Self {
        Self {
            kind: DatasetKind::TrainingCorpus,
            model_target: Some(model_target),
            sample_count,
        }
    }

    /// The inference cache label.
    #[must_use]
    pub fn inference_cache(model_target: Hash32) -> Self {
        Self {
            kind: DatasetKind::InferenceCache,
            model_target: Some(model_target),
            sample_count: 0,
        }
    }

    /// Validate the metadata before it labels a B.U.D. StorageDeal.
    ///
    /// A dataset label is a claim in the closed circuit: it is what tells the
    /// chain "this StorageDeal is safe for the AI inference layer to read as a training corpus".
    /// A label that does not hold together is not a harmless decoration - it is
    /// the thing an operator would lean on to justify reading data that should
    /// not have been labelled. Two conditions are checked:
    ///
    /// * a training corpus must have more than zero samples. A corpus with
    ///   zero samples trains nothing; labelling it is a claim with nothing
    ///   under it.
    /// * the dataset must name the model it targets. `DatasetMetadata` is a
    ///   mirrored type and its fields are public, so the builder methods
    ///   (`training` / `inference_cache`) always set the target but a hand-built
    ///   `None` is possible. A dataset that does not say which model it feeds
    ///   is a label the chain cannot bind to anything.
    ///
    /// # Errors
    ///
    /// [`DatasetError::EmptyTrainingCorpus`] or
    /// [`DatasetError::MissingModelTarget`].
    pub fn validate(&self) -> Result<(), DatasetError> {
        if self.model_target.is_none() {
            return Err(DatasetError::MissingModelTarget);
        }
        if self.kind == DatasetKind::TrainingCorpus && self.sample_count == 0 {
            return Err(DatasetError::EmptyTrainingCorpus);
        }
        Ok(())
    }
}

/// Dataset metadata validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatasetError {
    /// A training corpus with zero samples trains nothing.
    EmptyTrainingCorpus,
    /// A dataset that does not name the model it targets.
    MissingModelTarget,
}

/// The closed-circuit source kinds: the only three channels the AI inference layer can read.
///
/// - `PollenGrant`  - an authorised read through a Pollen `AccessGrant` /
///   `TrainingDataGrant`
/// - `StorageDeal`  - content labelled as an AI dataset in B.U.D. storage
/// - `SocialRef`    - in-network content coming over the SocialFi bridge
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    PollenGrant,
    StorageDeal,
    SocialRef,
}

/// The closed-circuit reference of a data source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    pub kind: SourceKind,
    pub content_id: Hash32,
    /// The number of epochs left on a Pollen training grant (matching the
    /// budlum `TrainingDataGrant` epoch limit).
    pub grant_epochs_remaining: Option<u64>,
}

impl SourceRef {
    #[must_use]
    pub fn storage_deal(content_id: Hash32) -> Self {
        Self {
            kind: SourceKind::StorageDeal,
            content_id,
            grant_epochs_remaining: None,
        }
    }

    #[must_use]
    pub fn pollen_grant(content_id: Hash32, epochs_remaining: u64) -> Self {
        Self {
            kind: SourceKind::PollenGrant,
            content_id,
            grant_epochs_remaining: Some(epochs_remaining),
        }
    }

    #[must_use]
    pub fn social(content_id: Hash32) -> Self {
        Self {
            kind: SourceKind::SocialRef,
            content_id,
            grant_epochs_remaining: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_kind_matches_budlum_semantics() {
        let t = DatasetMetadata::training([9; 32], 1000);
        assert_eq!(t.kind, DatasetKind::TrainingCorpus);
        assert_eq!(t.sample_count, 1000);

        let i = DatasetMetadata::inference_cache([9; 32]);
        assert_eq!(i.kind, DatasetKind::InferenceCache);
    }

    /// The builder methods produce valid metadata.
    #[test]
    fn builder_metadata_is_valid() {
        assert!(DatasetMetadata::training([9; 32], 1000).validate().is_ok());
        assert!(DatasetMetadata::inference_cache([9; 32]).validate().is_ok());
    }

    /// A training corpus that names no samples is refused - the label is a
    /// claim with nothing under it.
    #[test]
    fn an_empty_training_corpus_is_refused() {
        let mut bad = DatasetMetadata::training([9; 32], 1000);
        bad.sample_count = 0;
        assert_eq!(bad.validate(), Err(DatasetError::EmptyTrainingCorpus));
    }

    /// A dataset that does not name its target model is refused.
    #[test]
    fn a_dataset_without_a_target_model_is_refused() {
        let mut bad = DatasetMetadata::training([9; 32], 10);
        bad.model_target = None;
        assert_eq!(bad.validate(), Err(DatasetError::MissingModelTarget));
    }

    /// An inference cache may name no samples (it is not measured as a
    /// count) and still be valid, so the empty training-corpus rule does not
    /// overreach.
    #[test]
    fn an_inference_cache_may_have_zero_samples() {
        let cache = DatasetMetadata::inference_cache([9; 32]);
        assert_eq!(cache.sample_count, 0);
        assert!(cache.validate().is_ok());
    }

    #[test]
    fn only_grant_carries_epochs() {
        let deal = SourceRef::storage_deal([1; 32]);
        assert!(deal.grant_epochs_remaining.is_none());

        let grant = SourceRef::pollen_grant([1; 32], 3);
        assert_eq!(grant.grant_epochs_remaining, Some(3));
    }
}
