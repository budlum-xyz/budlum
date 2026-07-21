//! # Lubot — Merkeziyetsiz Yapay Zeka Katmanı (Faz A: gerçek budlum-core wiring)
//!
//! Kapalı-devre, doğrulanabilir AI katmanı. Bu modül Lubot'u **gerçek**
//! budlum-core primitive'lerine bağlar (mock yok):
//! - **Operator compute-bond** = `AiRegistry` verifier stake (AI-layer-first kararı).
//! - **Kapalı-devre veri** = gerçek `Pollen` `AccessGrant` doğrulaması.
//! - **Sertleştirme tipleri:** training-data grant (Pollen), AI-dataset metadata
//!   (B.U.D. storage), social-data ref (SocialFi ↔ Lubot).
//!
//! Operator rolü: AI katmanı verifier stake'ine bağlı (PoS validator'dan bağımsız,
//! composable). Verifier-registry'de `LUBOT_OPERATOR` (RoleId(8)) mapping'i,
//! budlum-core verifier-registry bağımlılığı eklendikten sonra devreye girer.

use crate::ai::AiRegistry;
use crate::core::address::Address;
use crate::pollen::data_rights::{AccessGrant, AccessGrantStatus};

// ============================================================
// Operator (validator hardening: ayrı compute-bond rolü)
// ============================================================

/// Lubot operator'ü kaydet: compute-bond = AiRegistry verifier stake.
/// PoS validator'dan bağımsız; aynı aktör beide olabilir (composable).
pub fn register_operator(
    registry: &mut AiRegistry,
    operator: &Address,
    bond: u64,
) -> Result<u64, String> {
    registry.lock_verifier_stake(operator, bond)
}

/// Operator compute-bond miktarı (0 = bondsuz).
#[must_use]
pub fn operator_bond(registry: &AiRegistry, operator: &Address) -> u64 {
    registry.verifier_stake(operator)
}

/// Operator Lubot trafiği alabilir mi (bond > 0)?
#[must_use]
pub fn operator_eligible(registry: &AiRegistry, operator: &Address) -> bool {
    registry.is_staked_verifier(operator)
}

// ============================================================
// Pollen hardening: kapalı-devre inference grant doğrulaması
// ============================================================

/// Kapalı-devre: bir `AccessGrant` Lubot çıkarımı için geçerli mi?
/// (grantee eşleşmesi + active + süresi dolmamış + read kotası var).
pub fn validate_inference_grant(
    grant: &AccessGrant,
    consumer: &Address,
    now_block: u64,
) -> Result<(), String> {
    if grant.grantee != *consumer {
        return Err("Lubot: grant not issued to this consumer".into());
    }
    if grant.status != AccessGrantStatus::Active {
        return Err("Lubot: grant not active".into());
    }
    if now_block > grant.expires_at_block {
        return Err("Lubot: grant expired".into());
    }
    if grant.reads_used >= grant.max_reads {
        return Err("Lubot: grant read quota exhausted".into());
    }
    Ok(())
}

// ============================================================
// Pollen hardening: training-data grant (yeni — bulk eğitim okuma)
// ============================================================

/// Eğitim için bulk veri erişim yetkisi (epoch-sınırlı). Pollen inference
/// grant'ından farklı: eğitim bir corpus'u tekrar-tekrar (epoch) okur.
#[derive(Clone, Debug)]
pub struct TrainingDataGrant {
    pub asset_id_bytes: [u8; 32],
    pub owner: Address,
    pub grantee: Address,
    pub issued_at_block: u64,
    pub expires_at_block: u64,
    pub max_epochs: u32,
    pub epochs_used: u32,
}

impl TrainingDataGrant {
    /// Bir eğitim epoch'u tüket (fail-closed: sınır dolunca hata).
    pub fn consume_epoch(&mut self) -> Result<(), String> {
        if self.epochs_used >= self.max_epochs {
            return Err("Lubot: training-data grant epochs exhausted".into());
        }
        self.epochs_used += 1;
        Ok(())
    }

    /// Hâlâ geçerli mi (süre + epoch)?
    #[must_use]
    pub fn is_valid(&self, now_block: u64) -> bool {
        now_block <= self.expires_at_block && self.epochs_used < self.max_epochs
    }
}

// ============================================================
// B.U.D. hardening: AI-dataset metadata (StorageDeal için ek)
// ============================================================

/// AI dataset türü.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AiDatasetKind {
    /// Çıkarım önbelleği (sık sorgu yanıtları).
    #[default]
    InferenceCache,
    /// Eğitim corpus'u.
    TrainingCorpus,
}

/// Bir `StorageDeal`'a eklenecek AI-dataset metadata'sı (B.U.D. hardening).
#[derive(Clone, Debug, Default)]
pub struct AiDatasetMetadata {
    pub kind: AiDatasetKind,
    pub model_target: Option<[u8; 32]>,
    pub sample_count: u64,
}

impl AiDatasetMetadata {
    /// Eğitim corpus metadata'sı üret.
    #[must_use]
    pub fn training(model_target: [u8; 32], sample_count: u64) -> Self {
        Self {
            kind: AiDatasetKind::TrainingCorpus,
            model_target: Some(model_target),
            sample_count,
        }
    }

    /// Çıkarım önbelleği metadata'sı üret.
    #[must_use]
    pub fn inference_cache(model_target: [u8; 32]) -> Self {
        Self {
            kind: AiDatasetKind::InferenceCache,
            model_target: Some(model_target),
            sample_count: 0,
        }
    }
}

// ============================================================
// SocialFi hardening: sosyal içerik = Lubot veri kaynağı
// ============================================================

/// SocialFi NFT içeriğinden Lubot veri referansı (Pollen grant bekler).
/// Kapalı-devre: Lubot sosyal içeriği yalnızca Pollen grant ile okur.
#[derive(Clone, Debug)]
pub struct SocialDataRef {
    pub nft_id: u64,
    pub content_id_bytes: [u8; 32],
    pub owner: Address,
}

impl SocialDataRef {
    /// Sosyal NFT içeriğinden Lubot veri referansı üret.
    #[must_use]
    pub fn from_social(nft_id: u64, content_id_bytes: [u8; 32], owner: Address) -> Self {
        Self {
            nft_id,
            content_id_bytes,
            owner,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    #[test]
    fn training_data_grant_exhausts_at_max_epochs() {
        let mut g = TrainingDataGrant {
            asset_id_bytes: [1; 32],
            owner: addr(2),
            grantee: addr(3),
            issued_at_block: 0,
            expires_at_block: 1000,
            max_epochs: 2,
            epochs_used: 0,
        };
        assert!(g.consume_epoch().is_ok());
        assert!(g.consume_epoch().is_ok());
        assert!(g.consume_epoch().is_err(), "third epoch must be rejected");
        assert!(!g.is_valid(0), "exhausted grant not valid");
    }

    #[test]
    fn ai_dataset_metadata_builders() {
        let t = AiDatasetMetadata::training([9; 32], 1000);
        assert_eq!(t.kind, AiDatasetKind::TrainingCorpus);
        assert_eq!(t.sample_count, 1000);
        let i = AiDatasetMetadata::inference_cache([9; 32]);
        assert_eq!(i.kind, AiDatasetKind::InferenceCache);
        assert_eq!(i.sample_count, 0);
    }

    #[test]
    fn social_data_ref_from_social() {
        let s = SocialDataRef::from_social(42, [7; 32], addr(1));
        assert_eq!(s.nft_id, 42);
        assert_eq!(s.owner, addr(1));
    }
}
