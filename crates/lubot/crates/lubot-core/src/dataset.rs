//! AI dataset types - the same shape as `AiDatasetKind` /
//! `AiDatasetMetadata` in budlum/main `src/lubot/mod.rs` (mirror types).
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
}

/// The closed-circuit source kinds: the only three channels Lubot can read.
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

    #[test]
    fn only_grant_carries_epochs() {
        let deal = SourceRef::storage_deal([1; 32]);
        assert!(deal.grant_epochs_remaining.is_none());

        let grant = SourceRef::pollen_grant([1; 32], 3);
        assert_eq!(grant.grant_epochs_remaining, Some(3));
    }
}
