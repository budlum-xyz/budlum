//! # Lubot - Merkeziyetsiz Yapay Zeka Katmanı (: gerçek budlum-core wiring)
//!
//! Kapalı-devre AI katmanı. Bu modül Lubot'u gerçek budlum-core
//! Primitive'lerine bağlar (mock yok):
//!
//! **Kapsam sınırı:** buradaki "doğrulanabilir" erişim ve bond kontrollerini
//! Anlatır, çıkarımın kriptografik doğrulamasını değil. Zincir üzerindeki
//! Çıkarım kanıtı bugün doğrulanmıyor; işlem yolu `require_execution_proof`
//! İsteyen modelleri fail-closed reddeder. Ayrıntı: `docs/AI_VERIFICATION_STATUS.md`.
//!
//! - **Operator compute-bond** = `AiRegistry` verifier stake (AI-layer-first kararı).
//! - **Kapalı-devre veri** = gerçek `Pollen` `AccessGrant` doğrulaması.
//! - **Sertleştirme tipleri:** training-data grant (Pollen), AI-dataset metadata
//!   (B.U.D. storage), social-data ref (SocialFi ↔ Lubot).
//!
//! Operator rolü: AI katmanı verifier stake'ine bağlı (PoS validator'dan bağımsız,
//! Composable). Verifier-registry'de `LUBOT_OPERATOR` (RoleId(8)) mapping'i,
//! Budlum-core verifier-registry bağımlılığı eklendikten sonra devreye girer.

use crate::ai::AiRegistry;
use crate::core::address::Address;
use crate::pollen::data_rights::{AccessGrant, AccessGrantStatus};

pub mod effort;
pub mod executor;
pub mod inference;
pub mod metrics;
pub mod query;
pub mod social;
pub mod storage;
pub mod verify;

// Operator (validator hardening: ayrı compute-bond rolü)

/// Smallest compute-bond a Lubot operator may register with.
///
/// `lock_verifier_stake` only rejects a zero bond, so without a floor a single
/// actor could register many addresses at one unit each and fill
/// `agreement_threshold` alone - the threshold counts addresses, not stake.
/// The floor makes that attack cost `threshold × MIN_OPERATOR_BOND` instead of
/// `threshold × 1`.
///
/// The value is a protocol parameter, not a market price: it is the point below
/// which a bond stops being skin in the game. Governance can raise it.
pub const MIN_OPERATOR_BOND: u64 = 1_000;

/// The floor has to be stricter than the zero-check `lock_verifier_stake`
/// already performs, otherwise it adds nothing. Checked at compile time, so a
/// future edit that weakens it fails the build rather than a test run.
const _: () = assert!(
    MIN_OPERATOR_BOND > 1,
    "MIN_OPERATOR_BOND must exceed the zero-check it replaces"
);

/// Lubot operator'ü kaydet: compute-bond = AiRegistry verifier stake.
/// PoS validator'dan bağımsız; aynı aktör beide olabilir (composable).
///
/// Bonds below [`MIN_OPERATOR_BOND`] are rejected rather than accepted at face
/// value, so Sybil registration has a floor cost.
pub fn register_operator(
    registry: &mut AiRegistry,
    operator: &Address,
    bond: u64,
) -> Result<u64, String> {
    if bond < MIN_OPERATOR_BOND {
        return Err(format!(
            "Lubot: compute-bond {bond} is below the minimum {MIN_OPERATOR_BOND}"
        ));
    }
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

// Pollen hardening: kapalı-devre inference grant doğrulaması

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

// Pollen hardening: training-data grant (yeni - bulk eğitim okuma)

/// Eğitim için bulk veri erişim yetkisi (epoch-sınırlı). Pollen inference
/// Grant'ından farklı: eğitim bir corpus'u tekrar-tekrar (epoch) okur.
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

// B.U.D. hardening: AI-dataset metadata (StorageDeal için ek)

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

// SocialFi hardening: sosyal içerik = Lubot veri kaynağı

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

// Pollen grant runtime construction (kapalı-devre tam)

/// Bir Lubot çıkarımı için kapalı-devre Pollen AccessGrant inşa et.
///
/// Veri sahibi, Lubot operator'üne (grantee) sınırlı okuma yetkisi verir.
/// `owner_signature` SENTINEL'dır (gerçek imza imzalama adımı ayrı).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_lubot_inference_grant(
    asset_id: crate::pollen::AssetId,
    owner: Address,
    grantee: Address,
    price_paid: u64,
    issued_at_block: u64,
    expires_at_block: u64,
    max_reads: u32,
    purpose_hash: [u8; 32],
) -> AccessGrant {
    AccessGrant::new_unsigned(
        asset_id,
        owner,
        grantee,
        grantee, // payer = grantee (operator öder)
        price_paid,
        issued_at_block,
        expires_at_block,
        max_reads,
        purpose_hash,
    )
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
    /// E2E: model kaydı + operator bond + lubot transaction build → tx_type doğru.
    #[test]
    fn lubot_e2e_model_bond_tx_integration() {
        use crate::ai::AiRegistry;
        use crate::core::transaction::TransactionType;

        let mut registry = AiRegistry::new();
        let owner = Address([1; 32]);
        let operator = Address([2; 32]);
        let model_hash = [9u8; 32];

        // Model kaydet.
        let model_id = super::inference::register_lubot_model(&mut registry, owner, model_hash)
            .expect("model register");

        // Operator bond.
        let bond = super::register_operator(&mut registry, &operator, MIN_OPERATOR_BOND)
            .expect("operator bond");
        assert_eq!(bond, MIN_OPERATOR_BOND);
        assert!(super::operator_eligible(&registry, &operator));

        // Lubot transaction inşa et.
        let tx = super::executor::build_lubot_transaction(
            owner,
            operator,
            model_id,
            b"lubot-e2e-input".to_vec(),
            10,
            100,
            0,
            45262,
            1,
            1000,
        )
        .expect("build tx");

        // Transaction type doğru.
        assert!(
            matches!(tx.tx_type, TransactionType::AiInferenceRequest(_)),
            "tx must be AiInferenceRequest"
        );
    }

    /// A bond below the floor is refused, so filling `agreement_threshold`
    /// with throwaway addresses costs real stake.
    #[test]
    fn compute_bond_below_the_floor_is_rejected() {
        let mut registry = AiRegistry::new();
        let operator = Address([7u8; 32]);
        assert!(
            super::register_operator(&mut registry, &operator, MIN_OPERATOR_BOND - 1).is_err(),
            "a bond one unit under the floor must be refused"
        );
        assert!(
            super::register_operator(&mut registry, &operator, 1).is_err(),
            "a one-unit bond must be refused"
        );
        assert!(
            super::register_operator(&mut registry, &operator, MIN_OPERATOR_BOND).is_ok(),
            "the floor itself must be accepted"
        );
    }
}
