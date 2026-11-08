//! AI dataset types - the same shape as `AiDatasetKind` /
//! `AiDatasetMetadata` in budlum/main `src/ai_inference/mod.rs` (mirror types).
//!
//! The permission rules are not copied here; they are queried from the chain
//! state.

use crate::model::Hash32;

/// The dataset kind. Identical to `AiDatasetKind` in budlum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetKind {
    /// A training corpus (the SFT/CPT input).
    TrainingCorpus,
    /// An inference cache (closed-circuit inference responses).
    InferenceCache,
}

/// AI dataset metadata bound to a B.U.D. `StorageDeal`.
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

    /// Validate the metadata before it labels a B.U.D. `StorageDeal`.
    ///
    /// A dataset label is a claim in the closed circuit: it is what tells the
    /// chain "this `StorageDeal` is safe for AI inference layer to read as a training corpus".
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
        if matches!(self.model_target, None | Some([0u8; 32])) {
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

/// The closed-circuit source kinds: the only three channels AI inference layer can read.
///
/// - `DataMarketGrant`  - an authorised read through a DataMarket `AccessGrant` /
///   `TrainingDataGrant`
/// - `StorageDeal`  - content labelled as an AI dataset in B.U.D. storage
/// - `SocialRef`    - in-network content coming over the `SocialFi` bridge
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    DataMarketGrant,
    StorageDeal,
    SocialRef,
}

/// The closed-circuit reference of a data source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    pub kind: SourceKind,
    pub content_id: Hash32,
    /// DataMarket's on-chain data-asset identity. It is distinct from `content_id`:
    /// the grant is issued to the asset, while the bytes are checked against
    /// the content digest. `None` for `StorageDeal` and `SocialRef`.
    pub asset_id: Option<Hash32>,
    /// The exact on-chain DataMarket grant authorising this input.
    ///
    /// `None` for `StorageDeal` and `SocialRef` sources. A DataMarket source without
    /// this identifier cannot be authorised: asking whether *some* grant for
    /// this asset is active does not prove the grant named by the input is.
    pub grant_id: Option<Hash32>,
    /// The number of epochs left on a DataMarket training grant (matching the
    /// budlum `TrainingDataGrant` epoch limit). This is a local shape check;
    /// the chain query remains authoritative for current activity.
    pub grant_epochs_remaining: Option<u64>,
}

impl SourceRef {
    #[must_use]
    pub fn storage_deal(content_id: Hash32) -> Self {
        Self {
            kind: SourceKind::StorageDeal,
            content_id,
            asset_id: None,
            grant_id: None,
            grant_epochs_remaining: None,
        }
    }

    /// Construct a DataMarket source with separate asset, grant, and content identities.
    #[must_use]
    pub fn data_market_grant(
        asset_id: Hash32,
        grant_id: Hash32,
        content_id: Hash32,
        epochs_remaining: u64,
    ) -> Self {
        Self {
            kind: SourceKind::DataMarketGrant,
            content_id,
            asset_id: Some(asset_id),
            grant_id: Some(grant_id),
            grant_epochs_remaining: Some(epochs_remaining),
        }
    }

    #[must_use]
    pub fn social(content_id: Hash32) -> Self {
        Self {
            kind: SourceKind::SocialRef,
            content_id,
            asset_id: None,
            grant_id: None,
            grant_epochs_remaining: None,
        }
    }

    /// Validate source identity and the grant fields' relationship to its kind.
    ///
    /// The epoch count is only a structural hint. An access decision must also
    /// query the chain with this exact `(grant_id, asset_id, content_id, consumer)` tuple.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError`] for zero identities, missing/expired DataMarket
    /// grant data, or grant fields attached to a non-DataMarket source.
    pub fn validate(&self) -> Result<(), SourceError> {
        if self.content_id == [0u8; 32] {
            return Err(SourceError::ZeroContentId);
        }
        match self.kind {
            SourceKind::DataMarketGrant => {
                let Some(asset_id) = self.asset_id else {
                    return Err(SourceError::MissingAssetId);
                };
                if asset_id == [0u8; 32] {
                    return Err(SourceError::ZeroAssetId);
                }
                let Some(grant_id) = self.grant_id else {
                    return Err(SourceError::MissingGrantId);
                };
                if grant_id == [0u8; 32] {
                    return Err(SourceError::ZeroGrantId);
                }
                match self.grant_epochs_remaining {
                    Some(epochs) if epochs > 0 => Ok(()),
                    _ => Err(SourceError::ExpiredOrMissingGrant),
                }
            }
            SourceKind::StorageDeal | SourceKind::SocialRef => {
                if self.asset_id.is_some() {
                    return Err(SourceError::UnexpectedAssetId);
                }
                if self.grant_id.is_some() {
                    return Err(SourceError::UnexpectedGrantId);
                }
                if self.grant_epochs_remaining.is_some() {
                    return Err(SourceError::UnexpectedGrantEpochs);
                }
                Ok(())
            }
        }
    }
}

/// Errors from validating a closed-circuit data source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    /// All-zero `content_id` does not identify content.
    ZeroContentId,
    /// A DataMarket source did not name its data asset.
    MissingAssetId,
    /// All-zero `asset_id` does not identify a data asset.
    ZeroAssetId,
    /// A non-DataMarket source carried a DataMarket asset ID.
    UnexpectedAssetId,
    /// A DataMarket source did not name its exact grant.
    MissingGrantId,
    /// All-zero `grant_id` does not identify an on-chain grant.
    ZeroGrantId,
    /// A DataMarket grant is absent, expired, or has no remaining-epoch hint.
    ExpiredOrMissingGrant,
    /// A non-DataMarket source carried a DataMarket grant ID.
    UnexpectedGrantId,
    /// A non-DataMarket source carried DataMarket grant epochs.
    UnexpectedGrantEpochs,
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
        assert!(deal.asset_id.is_none());
        assert!(deal.grant_id.is_none());
        assert!(deal.grant_epochs_remaining.is_none());
        assert!(deal.validate().is_ok());

        let grant = SourceRef::data_market_grant([3; 32], [2; 32], [1; 32], 3);
        assert_eq!(grant.asset_id, Some([3; 32]));
        assert_eq!(grant.grant_id, Some([2; 32]));
        assert_eq!(grant.grant_epochs_remaining, Some(3));
        assert!(grant.validate().is_ok());
    }

    #[test]
    fn zero_model_target_and_storage_content_id_are_refused() {
        let mut bad = DatasetMetadata::training([4; 32], 10);
        bad.model_target = Some([0u8; 32]);
        assert_eq!(bad.validate(), Err(DatasetError::MissingModelTarget));

        assert_eq!(
            SourceRef::storage_deal([0u8; 32]).validate(),
            Err(SourceError::ZeroContentId)
        );
    }

    #[test]
    fn source_identity_and_grant_shape_are_validated() {
        let mut source = SourceRef::data_market_grant([3; 32], [2; 32], [1; 32], 3);
        source.asset_id = None;
        assert_eq!(source.validate(), Err(SourceError::MissingAssetId));

        source.asset_id = Some([0; 32]);
        assert_eq!(source.validate(), Err(SourceError::ZeroAssetId));

        source.asset_id = Some([3; 32]);
        source.grant_id = None;
        assert_eq!(source.validate(), Err(SourceError::MissingGrantId));

        source.grant_id = Some([0; 32]);
        assert_eq!(source.validate(), Err(SourceError::ZeroGrantId));

        source.grant_id = Some([2; 32]);
        source.grant_epochs_remaining = Some(0);
        assert_eq!(source.validate(), Err(SourceError::ExpiredOrMissingGrant));

        let mut non_grant = SourceRef::storage_deal([1; 32]);
        non_grant.asset_id = Some([3; 32]);
        assert_eq!(non_grant.validate(), Err(SourceError::UnexpectedAssetId));

        non_grant.asset_id = None;
        non_grant.grant_id = Some([2; 32]);
        assert_eq!(non_grant.validate(), Err(SourceError::UnexpectedGrantId));

        non_grant.grant_id = None;
        non_grant.grant_epochs_remaining = Some(1);
        assert_eq!(
            non_grant.validate(),
            Err(SourceError::UnexpectedGrantEpochs)
        );
        assert_eq!(
            SourceRef::social([0; 32]).validate(),
            Err(SourceError::ZeroContentId)
        );
    }
}
