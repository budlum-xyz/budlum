//! # AI inference layer - the decentralized AI layer (real budlum-core wiring)
//!
//! A closed-loop AI layer. This module binds the AI inference layer to real budlum-core
//! primitives (no mocks):
//!
//! **Scope boundary:** verifiable here refers to the access and bond checks,
//! not to cryptographic verification of the inference. On-chain inference
//! proof is not verified today; the transaction path refuses models that request
//! `require_execution_proof` fail-closed. Details: `docs/AI_VERIFICATION_STATUS.md`.
//!
//! - **Operator compute bond** = `AiRegistry` verifier stake (the AI-layer-first decision).
//! - **Closed-loop data** = real `Pollen` `AccessGrant` verification.
//! - **Hardening types:** training-data grant (Pollen), AI-dataset metadata
//!   (B.U.D. storage), social-data ref (SocialFi ↔ the AI inference layer).
//!
//! The operator role is bound to the AI-layer verifier stake (independent of the PoS validator,
//! Composable). Verifier-registry'de `AI_INFERENCE_OPERATOR` (RoleId(8)) mapping'i,
//! and comes into play once the budlum-core verifier-registry dependency is added.

use crate::ai::AiRegistry;
use crate::core::address::Address;
use crate::pollen::data_rights::{AccessGrant, AccessGrantStatus};

pub mod effort;
pub mod executor;
pub mod inference;
pub mod metrics;
// What a model may read, and in what form. Reading only: the AI inference layer does not
// generate images or video. Written as a plain comment rather than `///`:
// a doc comment here makes rustdoc resolve the module's own `//!` header in
// this file's scope instead of the module's, and an intra-doc link to a type
// defined next door then fails to resolve.
pub mod perception;
pub mod query;
pub mod social;
pub mod storage;
pub mod verify;

// Operator (validator hardening: a separate compute-bond role)

/// Smallest compute-bond a the AI inference layer operator may register with.
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

/// Register a the AI inference layer operator: the compute bond is the AiRegistry verifier stake.
/// Independent of the PoS validator; the same actor may be both (composable).
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
            "the AI inference layer: compute-bond {bond} is below the minimum {MIN_OPERATOR_BOND}"
        ));
    }
    registry.lock_verifier_stake(operator, bond)
}

/// The operator compute-bond amount (0 = unbonded).
#[must_use]
pub fn operator_bond(registry: &AiRegistry, operator: &Address) -> u64 {
    registry.verifier_stake(operator)
}

/// Whether the operator may take the AI inference layer traffic (bond > 0).
#[must_use]
pub fn operator_eligible(registry: &AiRegistry, operator: &Address) -> bool {
    registry.is_staked_verifier(operator)
}

/// The executor entry gate: is an inference request admissible with respect to its read
/// declaration and the model's registered modalities?
///
/// Fail-closed checks, in order:
/// 1. No declaration means refusal - a request that does not say what it reads is the way to feed
///    an image to a text model (pre-V3 requests).
/// 2. Refusal if the model did not declare this modality at registration. An unregistered
///    model defaults to the empty set (`ModalitySet::none`): everything is refused.
/// 3. Refusal if the declaration violates its own ceilings (`check_admissible`).
/// 4. If `input_ref` carries a Pollen reference it must point at the same asset as the
///    declaration - taking a grant for asset A and reading B is closed off.
///
/// The grant RULES are not duplicated here: the Pollen check already happens in the executor's
/// `validate_ai_read_ref` call; this gate only checks WHAT the read is
/// (modality + asset consistency).
///
/// # Errors
///
/// Errors if the request carries no perception declaration or the model is not registered.
pub fn admit_inference_request(
    registry: &crate::ai::AiRegistry,
    req: &crate::ai::types::AiInferenceRequest,
) -> Result<(), String> {
    let perception = req.perception.clone().ok_or_else(|| {
        "an inference request must carry a perception declaration (V3)".to_string()
    })?;
    let modalities = registry
        .models
        .get(&req.model_id)
        .map_or(crate::ai_inference::perception::ModalitySet::none(), |m| {
            m.modalities
        });
    if !modalities.declares_modality(perception.kind) {
        return Err(format!(
            "model {} did not declare the {:?} modality",
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
            return Err(
                "the perception declaration and input_ref point at different assets".to_string(),
            );
        }
    }
    // Canonical commitment check: input_commitment must be the canonical preimage of
    // input_ref. Otherwise the same content produces distinct request ids under arbitrary
    // commitments and an attacker multiplies operator work for free
    // (the invariant dedup/replay protection rests on).
    if req.input_commitment
        != crate::ai::types::canonical_input_commitment(req.input_ref.as_slice())
    {
        return Err("input_commitment does not match the canonical preimage".to_string());
    }
    Ok(())
}

// Pollen hardening: closed-loop inference grant verification

/// Is an `AccessGrant` usable for a the AI inference layer inference right now?
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
/// What stays here is the the AI inference layer-facing wording of the refusal. An operator
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
        return Err("the AI inference layer: grant not issued to this consumer".into());
    }
    if grant.status != AccessGrantStatus::Active {
        return Err("the AI inference layer: grant not active".into());
    }
    if now_block > grant.expires_at_block {
        return Err("the AI inference layer: grant expired".into());
    }
    if grant.reads_used >= grant.max_reads {
        return Err("the AI inference layer: grant read quota exhausted".into());
    }
    // `is_active_for` refused for a reason this function does not enumerate.
    // Refusing anyway is the only fail-closed answer: the alternative is to
    // return Ok for a grant the authority just rejected.
    Err("the AI inference layer: grant refused by Pollen".into())
}

// Pollen hardening: training-data grant (new - bulk training reads)

/// Bulk data access authority for training (epoch bounded). Different from a Pollen
/// inference grant: training reads a corpus over and over (epochs).
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
    /// Consume one training epoch (fail-closed: errors once the limit is reached).
    pub fn consume_epoch(&mut self) -> Result<(), String> {
        if self.epochs_used >= self.max_epochs {
            return Err("the AI inference layer: training-data grant epochs exhausted".into());
        }
        self.epochs_used += 1;
        Ok(())
    }

    /// Whether it is still valid (time + epochs).
    #[must_use]
    pub fn is_valid(&self, now_block: u64) -> bool {
        now_block <= self.expires_at_block && self.epochs_used < self.max_epochs
    }
}

// B.U.D. hardening: AI-dataset metadata (an addition for StorageDeal)

/// AI dataset type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AiDatasetKind {
    /// Inference cache (answers to frequent queries).
    #[default]
    InferenceCache,
    /// Training corpus.
    TrainingCorpus,
}

/// AI-dataset metadata to attach to a `StorageDeal` (B.U.D. hardening).
#[derive(Clone, Debug, Default)]
pub struct AiDatasetMetadata {
    pub kind: AiDatasetKind,
    pub model_target: Option<[u8; 32]>,
    pub sample_count: u64,
}

impl AiDatasetMetadata {
    /// Produce training corpus metadata.
    #[must_use]
    pub fn training(model_target: [u8; 32], sample_count: u64) -> Self {
        Self {
            kind: AiDatasetKind::TrainingCorpus,
            model_target: Some(model_target),
            sample_count,
        }
    }

    /// Produce inference cache metadata.
    #[must_use]
    pub fn inference_cache(model_target: [u8; 32]) -> Self {
        Self {
            kind: AiDatasetKind::InferenceCache,
            model_target: Some(model_target),
            sample_count: 0,
        }
    }
}

// SocialFi hardening: social content as a the AI inference layer data source

/// A the AI inference layer data reference from SocialFi NFT content (expects a Pollen grant).
/// Closed loop: the AI inference layer reads social content only with a Pollen grant.
#[derive(Clone, Debug)]
pub struct SocialDataRef {
    pub nft_id: u64,
    pub content_id_bytes: [u8; 32],
    pub owner: Address,
}

impl SocialDataRef {
    /// Produce a the AI inference layer data reference from social NFT content.
    #[must_use]
    pub fn from_social(nft_id: u64, content_id_bytes: [u8; 32], owner: Address) -> Self {
        Self {
            nft_id,
            content_id_bytes,
            owner,
        }
    }
}

// Pollen grant runtime construction (the closed loop complete)

/// Build a closed-loop Pollen AccessGrant for a the AI inference layer inference.
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
pub fn build_ai_inference_inference_grant(
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
mod tests {
    use super::*;
    use crate::ai::types::AiModelId;

    fn addr(b: u8) -> Address {
        Address([b; 32])
    }

    fn inference_grant(max_reads: u32, expires: u64) -> AccessGrant {
        build_ai_inference_inference_grant(
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
    fn ai_inference_agrees_with_pollen_on_every_grant_state() {
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
                    let ai_inference = validate_inference_grant(grant, &consumer, now).is_ok();
                    assert_eq!(
                        pollen, ai_inference,
                        "case {i} at block {now}: Pollen says {pollen}, the AI inference layer says {ai_inference}"
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
    /// E2E: model registration + operator bond + ai_inference transaction build -> the tx_type is correct.
    #[test]
    fn ai_inference_e2e_model_bond_tx_integration() {
        use crate::ai::AiRegistry;
        use crate::core::transaction::TransactionType;

        let mut registry = AiRegistry::new();
        let owner = Address([1; 32]);
        let operator = Address([2; 32]);
        let model_hash = [9u8; 32];

        // Model kaydet.
        let model_id =
            super::inference::register_ai_inference_model(&mut registry, owner, model_hash)
                .expect("model register");

        // Operator bond.
        let bond = super::register_operator(&mut registry, &operator, MIN_OPERATOR_BOND)
            .expect("operator bond");
        assert_eq!(bond, MIN_OPERATOR_BOND);
        assert!(super::operator_eligible(&registry, &operator));

        // Build the the AI inference layer transaction.
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
        let tx = super::executor::build_ai_inference_transaction(
            owner,
            operator,
            model_id,
            b"ai_inference-e2e-input".to_vec(),
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

        // The transaction type is correct.
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

    // --- admit_inference_request gate tests (V3) ---

    fn text_perception() -> crate::ai_inference::perception::PerceptionRequest {
        crate::ai_inference::perception::PerceptionRequest {
            asset_id: crate::pollen::AssetId([1; 32]),
            content_id: crate::storage::content_id::ContentId([2; 32]),
            kind: crate::ai_inference::perception::PerceptionKind::Text,
            declared_units: 100,
        }
    }

    fn text_request(
        model_id: AiModelId,
        perception: Option<crate::ai_inference::perception::PerceptionRequest>,
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
            effort: crate::ai_inference::effort::EffortTier::default(),
            perception,
        }
    }

    #[test]
    fn admit_rejects_request_without_declaration() {
        let mut registry = AiRegistry::new();
        let model_id = super::inference::register_ai_inference_model(
            &mut registry,
            Address([1; 32]),
            [9u8; 32],
        )
        .unwrap();
        let req = text_request(model_id, None);
        assert!(super::admit_inference_request(&registry, &req).is_err());
    }

    #[test]
    fn admit_rejects_modality_model_did_not_declare() {
        let mut registry = AiRegistry::new();
        let model_id = super::inference::register_ai_inference_model(
            &mut registry,
            Address([1; 32]),
            [9u8; 32],
        )
        .unwrap();
        let mut p = text_perception();
        p.kind = crate::ai_inference::perception::PerceptionKind::Image;
        let req = text_request(model_id, Some(p));
        assert!(super::admit_inference_request(&registry, &req).is_err());
    }

    #[test]
    fn admit_accepts_declared_text_read() {
        let mut registry = AiRegistry::new();
        let model_id = super::inference::register_ai_inference_model(
            &mut registry,
            Address([1; 32]),
            [9u8; 32],
        )
        .unwrap();
        let req = text_request(model_id, Some(text_perception()));
        assert!(super::admit_inference_request(&registry, &req).is_ok());
    }

    #[test]
    fn admit_rejects_asset_mismatch_between_ref_and_declaration() {
        let mut registry = AiRegistry::new();
        let model_id = super::inference::register_ai_inference_model(
            &mut registry,
            Address([1; 32]),
            [9u8; 32],
        )
        .unwrap();
        // input_ref points at asset A; the declaration at asset B.
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
        let model_id = super::inference::register_ai_inference_model(
            &mut registry,
            Address([1; 32]),
            [9u8; 32],
        )
        .unwrap();
        // Passes with the canonical commitment.
        let mut req = text_request(model_id, Some(text_perception()));
        assert!(super::admit_inference_request(&registry, &req).is_ok());
        // The same content with an arbitrary commitment -> refused (the request multiplication invariant).
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
            modalities: crate::ai_inference::perception::ModalitySet::text_only(),
        };

        // A zero-sized layer is refused.
        let mut bad = base.clone();
        bad.execution_dims = Some(vec![0, 4]);
        assert!(
            bad.validate().is_err(),
            "a zero-sized layer must not be accepted"
        );

        // A single layer is refused.
        let mut bad = base.clone();
        bad.execution_dims = Some(vec![8]);
        assert!(
            bad.validate().is_err(),
            "a single layer must not be accepted"
        );

        // 33 layers are refused.
        let mut bad = base.clone();
        bad.execution_dims = Some(vec![4; 33]);
        assert!(bad.validate().is_err(), "33 layers must not be accepted");

        // A valid shape is accepted.
        base.execution_dims = Some(vec![8, 4, 4]);
        assert!(base.validate().is_ok(), "valid dims must be accepted");
    }
}
