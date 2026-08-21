//! AI-dataset tipleri - budlum/main `src/lubot/mod.rs` içindeki
//! `AiDatasetKind` / `AiDatasetMetadata` ile aynı biçim (ayna tipler).
//!
//! İzin kuralları burada kopyalanmaz; zincir durumundan sorgulanır (K3).

use crate::model::Hash32;

/// Veri seti türü. budlum'daki `AiDatasetKind` ile birebir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatasetKind {
    /// Eğitim corpus'u (SFT/CPT girdisi).
    TrainingCorpus,
    /// Çıkarım önbelleği (kapalı-devre çıkarım yanıtları).
    InferenceCache,
}

/// B.U.D. StorageDeal'a bağlanan AI-dataset metadata'sı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetMetadata {
    pub kind: DatasetKind,
    /// Hangi modele hedeflendiği (budlum: `model_target`).
    pub model_target: Option<Hash32>,
    pub sample_count: u64,
}

impl DatasetMetadata {
    /// Eğitim corpus'u etiketi.
    #[must_use]
    pub fn training(model_target: Hash32, sample_count: u64) -> Self {
        Self {
            kind: DatasetKind::TrainingCorpus,
            model_target: Some(model_target),
            sample_count,
        }
    }

    /// Çıkarım önbelleği etiketi.
    #[must_use]
    pub fn inference_cache(model_target: Hash32) -> Self {
        Self {
            kind: DatasetKind::InferenceCache,
            model_target: Some(model_target),
            sample_count: 0,
        }
    }
}

/// Kapalı-devre kaynak türleri: Lubot'un okuyabildiği tek üç kanal.
///
/// - `PollenGrant`  - Pollen `AccessGrant` / `TrainingDataGrant` ile yetkili okuma
/// - `StorageDeal`  - B.U.D. depolamasında AI-dataset etiketli içerik
/// - `SocialRef`    - SocialFi köprüsünden gelen ağ içi içerik
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    PollenGrant,
    StorageDeal,
    SocialRef,
}

/// Bir veri kaynağının kapalı-devre referansı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    pub kind: SourceKind,
    pub content_id: Hash32,
    /// Pollen eğitim grant'lerinde kalan epoch sayısı (budlum
    /// `TrainingDataGrant` epoch limitine karşılık).
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
