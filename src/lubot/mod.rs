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
// What a model may read, and in what form. Reading only: Lubot does not
// generate images or video. Written as a plain comment rather than `///`:
// a doc comment here makes rustdoc resolve the module's own `//!` header in
// this file's scope instead of the module's, and an intra-doc link to a type
// defined next door then fails to resolve.
pub mod perception;
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

/// Executor giriş kapısı: bir çıkarım isteği, okuma beyanı ve modelin
/// kayıtlı modaliteleri açısından kabul edilebilir mi?
///
/// Fail-closed denetimler, sırayla:
/// 1. Beyan yoksa red - ne okuduğunu söylemeyen istek, metin modele
///    görüntü vermenin yoludur (V3 öncesi istekler).
/// 2. Model bu modaliteyi kayıtta beyan etmemişse red. Kayıtlı olmayan
///    model boş küme varsayılır (`ModalitySet::none`): her şey reddedilir.
/// 3. Beyan kendi tavanlarına uymuyorsa red (`check_admissible`).
/// 4. `input_ref` bir Pollen referansı taşıyorsa, beyandaki varlıkla aynı
///    varlığı göstermeli - A varlığı için izin alıp B'yi okumak kapanır.
///
/// İzin KURALLARI burada kopyalanmaz: Pollen denetimi executor'un
/// `validate_ai_read_ref` çağrısında zaten yapılır; bu kapı yalnızca
/// okumanın NE olduğunu (modalite + varlık tutarlılığı) denetler.
///
/// # Errors
///
/// İstek perception beyanı taşımıyorsa veya model kaydı yoksa hata döner.
pub fn admit_inference_request(
    registry: &crate::ai::AiRegistry,
    req: &crate::ai::types::AiInferenceRequest,
) -> Result<(), String> {
    let perception = req
        .perception
        .clone()
        .ok_or_else(|| "çıkarım isteği perception beyanı taşımalı (V3)".to_string())?;
    let modalities = registry
        .models
        .get(&req.model_id)
        .map_or(crate::lubot::perception::ModalitySet::none(), |m| {
            m.modalities
        });
    if !modalities.declares_modality(perception.kind) {
        return Err(format!(
            "model {} {:?} modalitesini beyan etmemiş",
            req.model_id.to_hex(),
            perception.kind
        ));
    }
    perception
        .check_admissible(modalities)
        .map_err(|e| e.to_string())?;
    if let Ok(Some(data_ref)) =
        crate::pollen::data_rights::AiDataInputRef::decode(req.input_ref.as_slice())
    {
        if data_ref.asset_id != perception.asset_id {
            return Err("perception beyanı ile input_ref farklı varlıkları gösteriyor".to_string());
        }
    }
    // Kanonik commitment denetimi: input_commitment, input_ref'in kanonik
    // ön imajı olmalı. Aksi halde aynı içerik, keyfi farklı commitment'lar
    // altında ayrı istek kimlikleri üretir ve operatör işini ücretsiz
    // çoğaltır (dedup/replay korumasının dayandığı değişmez).
    if req.input_commitment
        != crate::ai::types::canonical_input_commitment(req.input_ref.as_slice())
    {
        return Err("input_commitment kanonik ön imajla eşleşmiyor".to_string());
    }
    Ok(())
}

// Pollen hardening: kapalı-devre inference grant doğrulaması

/// Is an `AccessGrant` usable for a Lubot inference right now?
///
/// Delegates to [`AccessGrant::is_active_for`], which is the same predicate
/// the production read path uses through
/// `MarketplaceRegistry::validate_ai_read_ref`. It did not always: this
/// function used to re-implement the four conditions itself, and while it was
/// doing so nothing called it. A second copy of a permission rule is worse
/// than no copy, because the two drift and it stops being obvious which one
/// decides. The copy here was already the weaker of the two, since it never
/// checked that the grant belonged to the asset's owner.
///
/// What stays here is the Lubot-facing wording of the refusal. An operator
/// told "grant not active" by the AI layer should not have to work out which
/// of Pollen's internal conditions it tripped.
///
/// # Errors
///
/// A message naming the condition that failed.
pub fn validate_inference_grant(
    grant: &AccessGrant,
    consumer: &Address,
    now_block: u64,
) -> Result<(), String> {
    if grant.is_active_for(consumer, now_block) {
        return Ok(());
    }
    // The predicate above is the authority on whether the grant is usable.
    // These branches only decide which sentence to return, so a refusal
    // cannot disagree with it: they are read after the single yes/no, never
    // instead of it.
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
    // `is_active_for` refused for a reason this function does not enumerate.
    // Refusing anyway is the only fail-closed answer: the alternative is to
    // return Ok for a grant the authority just rejected.
    Err("Lubot: grant refused by Pollen".into())
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
/// F-12: the production AI read path (`validate_ai_read_ref`) is
/// requester-bound. `grantee` must be the inference requester, not the
/// operator. The operator executes the job; it is not the account that
/// holds the data grant. `payer` is the same requester: they are the
/// party that paid for the read.
///
/// `owner_signature` is SENTINEL here (signing is a separate step).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_lubot_inference_grant(
    asset_id: crate::pollen::AssetId,
    owner: Address,
    requester: Address,
    price_paid: u64,
    issued_at_block: u64,
    expires_at_block: u64,
    max_reads: u32,
    purpose_hash: [u8; 32],
) -> AccessGrant {
    AccessGrant::new_unsigned(
        asset_id,
        owner,
        requester,
        requester,
        price_paid,
        issued_at_block,
        expires_at_block,
        max_reads,
        purpose_hash,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ai::types::AiModelId;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    fn inference_grant(max_reads: u32, expires: u64) -> AccessGrant {
        build_lubot_inference_grant(
            crate::pollen::AssetId([1; 32]),
            addr(2),
            addr(3),
            100,
            0,
            expires,
            max_reads,
            [0; 32],
        )
    }

    // --- the single permission rule, and the wording around it -----------

    #[test]
    fn lubot_agrees_with_pollen_on_every_grant_state() {
        // The point of delegating: the two must never disagree. If this
        // module ever answers differently from the predicate the production
        // read path uses, one of them is deciding something the other does
        // not know about, and which one applies depends on which door the
        // request came through.
        let mut cases = vec![
            inference_grant(3, 1000),
            inference_grant(0, 1000), // no reads left
            inference_grant(3, 0),    // already expired
        ];
        let mut revoked = inference_grant(3, 1000);
        revoked.status = AccessGrantStatus::Revoked;
        cases.push(revoked);
        let mut used_up = inference_grant(1, 1000);
        used_up.record_read().unwrap();
        cases.push(used_up);

        for (i, grant) in cases.iter().enumerate() {
            for now in [0u64, 1, 500, 1001] {
                for consumer in [addr(3), addr(9)] {
                    let pollen = grant.is_active_for(&consumer, now);
                    let lubot = validate_inference_grant(grant, &consumer, now).is_ok();
                    assert_eq!(
                        pollen, lubot,
                        "case {i} at block {now}: Pollen says {pollen}, Lubot says {lubot}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_refusal_names_the_condition_that_failed() {
        // Delegation must not cost the operator the reason. "Refused" alone
        // leaves them guessing whether to buy a new grant, wait, or give up.
        let expired = inference_grant(3, 10);
        let err = validate_inference_grant(&expired, &addr(3), 11).unwrap_err();
        assert!(err.contains("expired"), "got: {err}");

        let exhausted = inference_grant(0, 1000);
        let err = validate_inference_grant(&exhausted, &addr(3), 1).unwrap_err();
        assert!(err.contains("quota"), "got: {err}");

        let stranger = inference_grant(3, 1000);
        let err = validate_inference_grant(&stranger, &addr(9), 1).unwrap_err();
        assert!(err.contains("consumer"), "got: {err}");
    }

    #[test]
    fn a_grant_at_its_last_block_is_still_usable() {
        // `is_active_for` uses `<=`, so the expiry block itself is inside the
        // window. The old copy here used `>` on the other side of the
        // comparison and agreed by accident; pinning it means a future edit
        // to either side shows up as a failure rather than a silent
        // off-by-one on the last block of every grant.
        let g = inference_grant(3, 10);
        assert!(validate_inference_grant(&g, &addr(3), 10).is_ok());
        assert!(validate_inference_grant(&g, &addr(3), 11).is_err());
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
        let grant = AccessGrant::new_unsigned(
            crate::pollen::AssetId([9; 32]),
            Address([8; 32]),
            owner,
            owner,
            0,
            1,
            10_000,
            100,
            [0; 32],
        );
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
            &grant,
            None,
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

    // --- admit_inference_request kapı testleri (V3) ---

    fn text_perception() -> crate::lubot::perception::PerceptionRequest {
        crate::lubot::perception::PerceptionRequest {
            asset_id: crate::pollen::AssetId([1; 32]),
            content_id: crate::storage::content_id::ContentId([2; 32]),
            kind: crate::lubot::perception::PerceptionKind::Text,
            declared_units: 100,
        }
    }

    fn text_request(
        model_id: AiModelId,
        perception: Option<crate::lubot::perception::PerceptionRequest>,
    ) -> crate::ai::types::AiInferenceRequest {
        crate::ai::types::AiInferenceRequest {
            request_id: crate::ai::types::AiRequestId([0; 32]),
            requester: Address([2; 32]),
            model_id,
            input_commitment: crate::ai::types::canonical_input_commitment(&[]),
            input_ref: crate::ai::types::BoundedBytes::empty(),
            max_fee: 10,
            callback: None,
            submitted_at_block: 1,
            deadline_block: 100,
            effort: crate::lubot::effort::EffortTier::default(),
            perception,
        }
    }

    #[test]
    fn admit_rejects_request_without_declaration() {
        let mut registry = AiRegistry::new();
        let model_id =
            super::inference::register_lubot_model(&mut registry, Address([1; 32]), [9u8; 32])
                .unwrap();
        let req = text_request(model_id, None);
        assert!(super::admit_inference_request(&registry, &req).is_err());
    }

    #[test]
    fn admit_rejects_modality_model_did_not_declare() {
        let mut registry = AiRegistry::new();
        let model_id =
            super::inference::register_lubot_model(&mut registry, Address([1; 32]), [9u8; 32])
                .unwrap();
        let mut p = text_perception();
        p.kind = crate::lubot::perception::PerceptionKind::Image;
        let req = text_request(model_id, Some(p));
        assert!(super::admit_inference_request(&registry, &req).is_err());
    }

    #[test]
    fn admit_accepts_declared_text_read() {
        let mut registry = AiRegistry::new();
        let model_id =
            super::inference::register_lubot_model(&mut registry, Address([1; 32]), [9u8; 32])
                .unwrap();
        let req = text_request(model_id, Some(text_perception()));
        assert!(super::admit_inference_request(&registry, &req).is_ok());
    }

    #[test]
    fn admit_rejects_asset_mismatch_between_ref_and_declaration() {
        let mut registry = AiRegistry::new();
        let model_id =
            super::inference::register_lubot_model(&mut registry, Address([1; 32]), [9u8; 32])
                .unwrap();
        // input_ref varlık A'yı işaret ediyor; beyan varlık B'yi.
        let data_ref = crate::pollen::data_rights::AiDataInputRef {
            asset_id: crate::pollen::AssetId([7; 32]),
            grant_id: crate::pollen::AssetId([8; 32]),
        };
        let mut req = text_request(model_id, Some(text_perception()));
        req.input_ref = crate::ai::types::BoundedBytes::try_new(data_ref.encode()).unwrap();
        assert!(super::admit_inference_request(&registry, &req).is_err());
    }

    #[test]
    fn admit_rejects_non_canonical_input_commitment() {
        let mut registry = AiRegistry::new();
        let model_id =
            super::inference::register_lubot_model(&mut registry, Address([1; 32]), [9u8; 32])
                .unwrap();
        // Kanonik commitment ile geçer.
        let mut req = text_request(model_id, Some(text_perception()));
        assert!(super::admit_inference_request(&registry, &req).is_ok());
        // Aynı içerik, keyfi commitment → red (istek çoğaltma değişmezi).
        req.input_commitment = [1; 32];
        assert!(super::admit_inference_request(&registry, &req).is_err());
    }

    #[test]
    fn model_spec_rejects_poisoned_execution_dims() {
        use crate::ai::types::AiModelSpec;

        let owner = Address([1; 32]);
        let mut base = AiModelSpec {
            model_id: AiModelId([9u8; 32]),
            model_hash: [9u8; 32],
            owner,
            min_verifier_count: 1,
            agreement_threshold: 1,
            max_input_ref_bytes: 1024,
            max_output_ref_bytes: 1024,
            request_deadline_blocks: 1000,
            result_deadline_blocks: 1000,
            version: 1,
            active: true,
            require_execution_proof: false,
            execution_program_hash: None,
            execution_class: 0,
            execution_dims: None,
            execution_weights_digest: None,
            modalities: crate::lubot::perception::ModalitySet::text_only(),
        };

        // 0 boyutlu katman red.
        let mut bad = base.clone();
        bad.execution_dims = Some(vec![0, 4]);
        assert!(bad.validate().is_err(), "0 boyutlu katman kabul edilmemeli");

        // Tek katman red.
        let mut bad = base.clone();
        bad.execution_dims = Some(vec![8]);
        assert!(bad.validate().is_err(), "tek katman kabul edilmemeli");

        // 33 katman red.
        let mut bad = base.clone();
        bad.execution_dims = Some(vec![4; 33]);
        assert!(bad.validate().is_err(), "33 katman kabul edilmemeli");

        // Geçerli şekil kabul.
        base.execution_dims = Some(vec![8, 4, 4]);
        assert!(base.validate().is_ok(), "geçerli dims kabul edilmeli");
    }
}
