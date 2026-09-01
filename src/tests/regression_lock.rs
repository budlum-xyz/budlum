//! Regression lock tests - CI-breaking security seals.
//!
//! These tests prevent security bugs found and fixed in the past from being
//! silently reverted. If any of them breaks in CI it means the
//! corresponding fix has been broken; it may only be removed by a deliberate
//! decision (and by updating this file).
//!
//! ## Regresyon #1: ZK finality fail-open
//!
//! The generic trait `verify_finality` method of ZkFinalityAdapter used to be able to
//! finalize without a ProofClaimRegistry lookup (fail-open).
//! Fixed: the trait method always returns `Rejected`,
//! and real verification happens only through `verify_finality_with_claim`
//! together with the ProofClaimRegistry.
//!
//! ## Regresyon #2: Relayer escrow silent-failure
//!
//! When an escrowed AiAgentPayment is released, the payment must be removed from the
//! registry and the recipient credited. If release/reclaim
//! fails silently (the payment disappears without a balance change),
//! funds are lost. The test verifies that release/reclaim really removes the
//! payment, and that the non-escrowed path credits the recipient immediately.
//!

// ─── Regresyon #1: ZK finality fail-open ─────────────────────────────────

#[cfg(test)]
mod zk_finality_fail_open_regression {
    use crate::domain::finality_adapter::{
        DomainFinalityAdapter, FinalityProof, FinalityStatus, ZkFinalityAdapter,
    };
    use crate::domain::plugin::default_domain;
    use crate::domain::types::{ConsensusKind, DomainCommitment, Hash32};

    /// ZK domain + commitment helper functions.
    fn zk_domain() -> crate::domain::types::ConsensusDomain {
        default_domain(42, ConsensusKind::Zk, 45262, "zk-proof-verification", 0)
    }

    fn zk_commitment(state_root: Hash32) -> DomainCommitment {
        DomainCommitment {
            domain_id: 42,
            domain_height: 10,
            domain_block_hash: [1u8; 32],
            parent_domain_block_hash: [0u8; 32],
            state_root,
            tx_root: [3u8; 32],
            event_root: [4u8; 32],
            finality_proof_hash: [5u8; 32],
            consensus_kind: ConsensusKind::Zk,
            validator_set_hash: [6u8; 32],
            timestamp_ms: 123,
            sequence: 0,
            producer: None,
            state_updates: std::collections::BTreeMap::new(),
        }
    }

    /// REGRESSION LOCK: `ZkFinalityAdapter::verify_finality`
    /// (the generic trait entry point) must NEVER return `Finalized`.
    ///
    /// This method used to be able to finalize without a ProofClaimRegistry
    /// lookup: a second, registry-independent verification path (fail-open).
    /// If someone accidentally "fixes" this method into returning `Finalized`,
    /// this test breaks.
    ///
    /// Intended behaviour: always `Rejected` - ZK finality can only be resolved
    /// through `verify_finality_with_claim`.
    #[test]
    fn zk_trait_verify_finality_never_finalizes() {
        let adapter = ZkFinalityAdapter;
        let domain = zk_domain();
        let commitment = zk_commitment([0xAAu8; 32]);
        let proof = FinalityProof::Zk {
            domain_id: 42,
            target_height: 10,
            final_state_root: [0xAAu8; 32],
        };

        let result = adapter
            .verify_finality(&domain, &commitment, &proof)
            .expect("verify_finality should return Ok, not Err");

        assert!(
            matches!(result, FinalityStatus::Rejected(_)),
            "ZkFinalityAdapter::verify_finality must NEVER return Finalized or Pending. \
             Got: {:?}. This is a regression - ZK finality must only \
             resolve via verify_finality_with_claim with ProofClaimRegistry.",
            result
        );
    }

    /// REGRESSION LOCK: `verify_finality_with_claim` must NEVER return `Finalized`
    /// when accepted_claim_root=None (no claim in the registry).
    ///
    /// This is one manifestation of the "missing binding" defect found in the
    /// audit - with no claim there must be no finalization.
    #[test]
    fn zk_verify_with_claim_rejects_missing_claim() {
        let adapter = ZkFinalityAdapter;
        let domain = zk_domain();
        let commitment = zk_commitment([0xAAu8; 32]);
        let proof = FinalityProof::Zk {
            domain_id: 42,
            target_height: 10,
            final_state_root: [0xAAu8; 32],
        };

        let result = adapter
            .verify_finality_with_claim(&domain, &commitment, &proof, None)
            .expect("verify_finality_with_claim should return Ok");

        assert!(
            matches!(result, FinalityStatus::Rejected(_)),
            "ZK finality with no accepted claim must be Rejected, got: {:?}",
            result
        );
    }

    /// REGRESSION LOCK: `verify_finality_with_claim` must NEVER return `Finalized`
    /// when the claim root does not match the commitment state root.
    ///
    /// Audit: "binding the proof to the accepted claim" + "binding
    /// the claim to THIS commitment" - if either fails there must be no
    /// finalization.
    #[test]
    fn zk_verify_with_claim_rejects_root_mismatch() {
        let adapter = ZkFinalityAdapter;
        let domain = zk_domain();
        let commitment = zk_commitment([0xBBu8; 32]); // commitment state root ≠ claim root
        let proof = FinalityProof::Zk {
            domain_id: 42,
            target_height: 10,
            final_state_root: [0xAAu8; 32], // claim root
        };

        // Claim root ≠ commitment state root → Rejected
        let result = adapter
            .verify_finality_with_claim(
                &domain,
                &commitment,
                &proof,
                Some([0xAAu8; 32]), // accepted claim root matches proof but NOT commitment
            )
            .expect("verify_finality_with_claim should return Ok");

        assert!(
            matches!(result, FinalityStatus::Rejected(_)),
            "ZK finality with claim/commitment root mismatch must be Rejected, got: {:?}",
            result
        );
    }

    /// REGRESSION LOCK: `verify_finality_with_claim` must NEVER return `Finalized` proof'un
    /// when the claim root does not match the proof's final_state_root.
    #[test]
    fn zk_verify_with_claim_rejects_proof_claim_mismatch() {
        let adapter = ZkFinalityAdapter;
        let domain = zk_domain();
        let commitment = zk_commitment([0xAAu8; 32]); // commitment state root = 0xAA
        let proof = FinalityProof::Zk {
            domain_id: 42,
            target_height: 10,
            final_state_root: [0xBBu8; 32], // proof root ≠ claim root
        };

        let result = adapter
            .verify_finality_with_claim(
                &domain,
                &commitment,
                &proof,
                Some([0xAAu8; 32]), // accepted claim root ≠ proof's final_state_root
            )
            .expect("verify_finality_with_claim should return Ok");

        assert!(
            matches!(result, FinalityStatus::Rejected(_)),
            "ZK finality with proof/claim root mismatch must be Rejected, got: {:?}",
            result
        );
    }

    /// REGRESSION LOCK: `Finalized` must be returned only when ALL bindings match
    /// (claim root = proof root = commitment state root).
    #[test]
    fn zk_verify_with_claim_finalizes_only_when_all_roots_match() {
        let adapter = ZkFinalityAdapter;
        let domain = zk_domain();
        let shared_root: Hash32 = [0xCCu8; 32];
        let commitment = zk_commitment(shared_root);
        let proof = FinalityProof::Zk {
            domain_id: 42,
            target_height: 10,
            final_state_root: shared_root,
        };

        let result = adapter
            .verify_finality_with_claim(&domain, &commitment, &proof, Some(shared_root))
            .expect("verify_finality_with_claim should return Ok");

        assert_eq!(
            result,
            FinalityStatus::Finalized,
            "ZK finality must finalize when all three roots match (claim=proof=commitment)"
        );
    }

    /// REGRESSION LOCK: `verify_finality_with_claim` must NEVER return `Finalized`
    /// on a domain_id or height mismatch.
    #[test]
    fn zk_verify_with_claim_rejects_domain_or_height_mismatch() {
        let adapter = ZkFinalityAdapter;
        let domain = zk_domain(); // domain_id=42
        let commitment = zk_commitment([0xAAu8; 32]); // domain_id=42, height=10

        // Wrong domain_id
        let proof_wrong_domain = FinalityProof::Zk {
            domain_id: 99,
            target_height: 10,
            final_state_root: [0xAAu8; 32],
        };
        let result = adapter
            .verify_finality_with_claim(
                &domain,
                &commitment,
                &proof_wrong_domain,
                Some([0xAAu8; 32]),
            )
            .expect("should return Ok");
        assert!(
            matches!(result, FinalityStatus::Rejected(_)),
            "ZK finality with wrong domain_id must be Rejected, got: {:?}",
            result
        );

        // Wrong height
        let proof_wrong_height = FinalityProof::Zk {
            domain_id: 42,
            target_height: 999,
            final_state_root: [0xAAu8; 32],
        };
        let result = adapter
            .verify_finality_with_claim(
                &domain,
                &commitment,
                &proof_wrong_height,
                Some([0xAAu8; 32]),
            )
            .expect("should return Ok");
        assert!(
            matches!(result, FinalityStatus::Rejected(_)),
            "ZK finality with wrong height must be Rejected, got: {:?}",
            result
        );
    }
}

// ─── Regresyon #2: Relayer escrow silent-failure ──────────────────────────

#[cfg(test)]
mod relayer_escrow_silent_failure_regression {
    use crate::ai::registry::AiRegistry;
    use crate::ai::types::{
        AiAgentPayment, AiInferenceRequest, AiInferenceResult, AiModelId, AiModelSpec, AiRequestId,
        BoundedBytes,
    };
    use crate::core::address::Address;

    /// Helper: a basic AI registry + model setup.
    fn setup_registry_with_model(
        min_verifier_count: u32,
        agreement_threshold: u32,
    ) -> (AiRegistry, AiModelId, Address) {
        let mut registry = AiRegistry::new();
        let owner =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let model_id = AiModelId::of(&owner, &[1u8; 32], 1);
        registry
            .register_model(AiModelSpec {
                model_id,
                model_hash: [1u8; 32],
                owner,
                min_verifier_count,
                agreement_threshold,
                max_input_ref_bytes: 1024,
                max_output_ref_bytes: 2048,
                request_deadline_blocks: 100,
                result_deadline_blocks: 50,
                version: 1,
                active: true,
                require_execution_proof: false,
                execution_program_hash: None,
                execution_class: 0,
                execution_dims: None,
                execution_weights_digest: None,
                modalities: crate::ai_inference::perception::ModalitySet::text_only(),
            })
            .unwrap();
        (registry, model_id, owner)
    }

    /// Build an inference request and record it in the registry.
    fn submit_request(
        registry: &mut AiRegistry,
        model_id: AiModelId,
        requester: Address,
        current_block: u64,
        deadline_block: u64,
    ) -> AiRequestId {
        let mut req = AiInferenceRequest {
            request_id: AiRequestId::default(),
            requester,
            model_id,
            input_commitment: [2u8; 32],
            input_ref: BoundedBytes::try_new(b"test".to_vec()).unwrap(),
            max_fee: 500,
            callback: None,
            submitted_at_block: current_block,
            deadline_block,
            effort: crate::ai_inference::effort::EffortTier::default(),
            perception: None,
        };
        req.request_id = req.calculate_id();
        registry.submit_request(req, current_block).unwrap()
    }

    /// Submit a result from a verifier.
    /// (Verifier stake is mandatory after Strix #359; the helper stakes
    /// automatically.)
    fn submit_result(
        registry: &mut AiRegistry,
        request_id: AiRequestId,
        verifier: Address,
        output_commitment: [u8; 32],
        result_nonce: u64,
        current_block: u64,
    ) {
        if registry.verifier_stake(&verifier) < crate::ai::registry::MIN_VERIFIER_STAKE {
            let _ =
                registry.lock_verifier_stake(&verifier, crate::ai::registry::MIN_VERIFIER_STAKE);
        }
        registry
            .submit_result(
                AiInferenceResult {
                    request_id,
                    verifier,
                    output_commitment,
                    output_ref: BoundedBytes::try_new(b"response".to_vec()).unwrap(),
                    result_nonce,
                    signature: vec![1],
                    submitted_at_block: current_block,
                },
                current_block,
            )
            .unwrap();
    }

    /// REGRESSION LOCK: when an escrowed payment is released the payment MUST BE
    /// REMOVED from the registry. If `release_agent_payment` fails silently
    /// (the payment stays but no balance is credited),
    /// funds stay frozen.
    ///
    /// This test verifies that release really removes the payment.
    /// If someone breaks the release code the payment stays in the registry and
    /// the test assertion (`get_agent_payment` -> `None`) fails.
    #[test]
    fn escrowed_payment_release_removes_payment_from_registry() {
        let (mut registry, model_id, _owner) = setup_registry_with_model(2, 2);
        let requester =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000080")
                .unwrap();
        let verifier =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000010")
                .unwrap();
        let verifier2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let current_block = 100u64;

        // Build request + result + outcome
        let request_id = submit_request(
            &mut registry,
            model_id,
            requester,
            current_block,
            current_block + 100,
        );

        // Two verifiers submit the same output_commitment -> finalization
        submit_result(
            &mut registry,
            request_id,
            verifier,
            [0x11u8; 32],
            1,
            current_block + 10,
        );
        submit_result(
            &mut registry,
            request_id,
            verifier2,
            [0x11u8; 32],
            2,
            current_block + 11,
        );

        // Build an escrowed payment
        let payment = AiAgentPayment {
            payment_id: [0xFEu8; 32],
            from_agent: requester,
            to_agent: verifier,
            amount: 250,
            request_id: Some(request_id),
            require_proof: false,
            submitted_at_block: current_block + 20,
            expiry_block: current_block + 200,
        };
        registry
            .submit_agent_payment(payment, current_block + 20)
            .unwrap();

        // Payment registry'de var
        assert!(
            registry.get_agent_payment(&[0xFEu8; 32]).is_some(),
            "escrowed payment must exist before release"
        );

        // Release
        let released_to = registry
            .release_agent_payment(&[0xFEu8; 32], current_block + 30)
            .expect("release must succeed");
        assert_eq!(released_to, verifier);

        // REGRESSION LOCK: the payment must NO LONGER be in the registry
        assert!(
            registry.get_agent_payment(&[0xFEu8; 32]).is_none(),
            "REGRESSION: after an escrowed payment release the payment is still in the registry! \
             This means release did not remove the payment (silent failure) - \
             the payment stays frozen without the recipient being credited."
        );
    }

    /// REGRESSION LOCK: when an escrowed payment expires
    /// Reclaim edilebilmeli ve payment registry'den KALDIRILMALIDIR.
    ///
    /// If reclaim fails silently the expired payment
    /// stays in the registry and the sender cannot recover the funds.
    #[test]
    fn escrowed_payment_reclaim_removes_expired_payment_from_registry() {
        let (mut registry, model_id, _owner) = setup_registry_with_model(2, 2);
        let requester =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000081")
                .unwrap();
        let verifier =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000010")
                .unwrap();
        let current_block = 100u64;

        let request_id = submit_request(
            &mut registry,
            model_id,
            requester,
            current_block,
            current_block + 100,
        );

        // Escrowed payment (short expiry)
        let payment = AiAgentPayment {
            payment_id: [0xFDu8; 32],
            from_agent: requester,
            to_agent: verifier,
            amount: 300,
            request_id: Some(request_id),
            require_proof: false,
            submitted_at_block: current_block,
            expiry_block: current_block + 50, // expires after 50 blocks
        };
        registry
            .submit_agent_payment(payment, current_block)
            .unwrap();

        // Not expired yet -> reclaim must be refused
        let reclaim_before =
            registry.reclaim_agent_payment(&[0xFDu8; 32], &requester, current_block + 30);
        assert!(reclaim_before.is_err(), "reclaim before expiry must fail");
        assert!(
            registry.get_agent_payment(&[0xFDu8; 32]).is_some(),
            "payment must still exist before expiry"
        );

        // Reclaim after expiry
        let reclaimed_amount = registry
            .reclaim_agent_payment(&[0xFDu8; 32], &requester, current_block + 51)
            .expect("reclaim after expiry must succeed");
        assert_eq!(reclaimed_amount, 300);

        // REGRESSION LOCK: the payment must NO LONGER be in the registry
        assert!(
            registry.get_agent_payment(&[0xFDu8; 32]).is_none(),
            "REGRESSION: after reclaiming an expired payment it is still in the registry! \
             This means reclaim did not remove the payment (silent failure) - \
             the payment stays frozen without the sender recovering the funds."
        );
    }

    /// REGRESSION LOCK: a non-escrowed payment (request_id=None) can never be
    /// released; that path is already resolved in the executor via immediate
    /// credit. Release must not be called, because there is no escrow.
    #[test]
    fn non_escrowed_payment_cannot_be_released() {
        let (mut registry, _model_id, _owner) = setup_registry_with_model(2, 2);
        let sender =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000082")
                .unwrap();
        let recipient =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000083")
                .unwrap();

        // Non-escrowed payment (request_id = None)
        let payment = AiAgentPayment {
            payment_id: [0xFCu8; 32],
            from_agent: sender,
            to_agent: recipient,
            amount: 100,
            request_id: None, // Non-escrowed!
            require_proof: false,
            submitted_at_block: 100,
            expiry_block: 200,
        };
        registry.submit_agent_payment(payment, 100).unwrap();

        // If release is attempted -> it must error (no escrow)
        let result = registry.release_agent_payment(&[0xFCu8; 32], 110);
        assert!(
            result.is_err(),
            "REGRESYON: non-escrowed payment release edilmemeli! \
             This payment must be credited immediately in the executor and must not enter the release path. \
             Release erroring out preserves the fact that the executor's non-escrowed path works \
             correctly (the recipient is credited immediately)."
        );
    }

    /// REGRESSION LOCK: reclaim may only be performed by the sender (from_agent).
    /// Any other address attempting reclaim -> error.
    #[test]
    fn escrowed_payment_reclaim_only_by_original_sender() {
        let (mut registry, model_id, _owner) = setup_registry_with_model(2, 2);
        let requester =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000084")
                .unwrap();
        let verifier =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000010")
                .unwrap();
        let current_block = 100u64;

        let request_id = submit_request(
            &mut registry,
            model_id,
            requester,
            current_block,
            current_block + 100,
        );

        let payment = AiAgentPayment {
            payment_id: [0xFBu8; 32],
            from_agent: requester,
            to_agent: verifier,
            amount: 400,
            request_id: Some(request_id),
            require_proof: false,
            submitted_at_block: current_block,
            expiry_block: current_block + 50,
        };
        registry
            .submit_agent_payment(payment, current_block)
            .unwrap();

        // The recipient (to_agent) cannot reclaim
        let result = registry.reclaim_agent_payment(&[0xFBu8; 32], &verifier, current_block + 51);
        assert!(
            result.is_err(),
            "REGRESSION: the recipient (to_agent) must not be able to reclaim the payment! \
             Only the sender (from_agent) may hold reclaim authority."
        );

        // The payment is still in the registry (reclaim failed)
        assert!(
            registry.get_agent_payment(&[0xFBu8; 32]).is_some(),
            "failed reclaim must not remove the payment"
        );
    }

    /// REGRESSION LOCK: release must be refused once the payment has expired.
    /// An expired payment can only be recovered through reclaim.
    #[test]
    fn escrowed_payment_release_rejected_after_expiry() {
        let (mut registry, model_id, _owner) = setup_registry_with_model(2, 2);
        let requester =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000085")
                .unwrap();
        let verifier =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000010")
                .unwrap();
        let current_block = 100u64;

        let request_id = submit_request(
            &mut registry,
            model_id,
            requester,
            current_block,
            current_block + 100,
        );

        let payment = AiAgentPayment {
            payment_id: [0xFAu8; 32],
            from_agent: requester,
            to_agent: verifier,
            amount: 200,
            request_id: Some(request_id),
            require_proof: false,
            submitted_at_block: current_block,
            expiry_block: current_block + 50,
        };
        registry
            .submit_agent_payment(payment, current_block)
            .unwrap();

        // Release attempted after expiry -> must be refused
        let result = registry.release_agent_payment(&[0xFAu8; 32], current_block + 51);
        assert!(
            result.is_err(),
            "REGRESYON: expired payment release edilmemeli! \
             An expired payment can only be recovered through reclaim. \
             Accepting release would send the funds to the recipient and \
             leave the sender unable to recover them."
        );

        // The payment is still in the registry (release failed)
        assert!(
            registry.get_agent_payment(&[0xFAu8; 32]).is_some(),
            "failed release must not remove the payment"
        );
    }

    /// REGRESSION LOCK: double release must be prevented. Because the first release removes
    /// the payment, a second release must error with payment not found.
    #[test]
    fn escrowed_payment_double_release_prevented() {
        let (mut registry, model_id, _owner) = setup_registry_with_model(2, 2);
        let requester =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000086")
                .unwrap();
        let verifier =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000010")
                .unwrap();
        let verifier2 =
            Address::from_hex("0000000000000000000000000000000000000000000000000000000000000011")
                .unwrap();
        let current_block = 100u64;

        let request_id = submit_request(
            &mut registry,
            model_id,
            requester,
            current_block,
            current_block + 100,
        );

        // Two verifiers, same output -> finalization
        submit_result(
            &mut registry,
            request_id,
            verifier,
            [0x11u8; 32],
            1,
            current_block + 10,
        );
        submit_result(
            &mut registry,
            request_id,
            verifier2,
            [0x11u8; 32],
            2,
            current_block + 11,
        );

        let payment = AiAgentPayment {
            payment_id: [0xF9u8; 32],
            from_agent: requester,
            to_agent: verifier,
            amount: 150,
            // Must link the REAL finalized request_id (not a placeholder).
            // Placeholder [0xCD;32] has no outcome → release fails pre-condition.
            request_id: Some(request_id),
            require_proof: false,
            submitted_at_block: current_block + 20,
            expiry_block: current_block + 200,
        };
        registry
            .submit_agent_payment(payment, current_block + 20)
            .unwrap();

        // The first release succeeds
        registry
            .release_agent_payment(&[0xF9u8; 32], current_block + 30)
            .expect("first release must succeed");

        // Second release -> the payment is gone
        let result = registry.release_agent_payment(&[0xF9u8; 32], current_block + 31);
        assert!(
            result.is_err(),
            "REGRESSION: double release must be prevented! After the first release removes \
             the payment the second release must error. Otherwise \
             the recipient could claim the same payment twice."
        );
    }
}
