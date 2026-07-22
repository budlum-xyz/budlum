//! Regresyon kilidi testleri — CI kırıcı güvenlik mühürleri.
//!
//! Bu testler, geçmişte tespit edilen ve düzeltilen güvenlik bug'larının
//! yanlışlıkla geri alınmasını önler. Herhangi birinin CI'da kırılması,
//! ilgili düzeltmenin bozulduğu anlamına gelir — yalnızca bilinçli bir
//! kararla (ve bu dosyanın güncellenmesiyle) kaldırılabilir.
//!
//! ## Regresyon #1: ZK finality fail-open (Task 0.358)
//!
//! ZkFinalityAdapter'ın generic trait `verify_finality` metodu eskiden
//! ProofClaimRegistry lookup'ı olmadan finalize edebiliyordu (fail-open).
//! Task 0.358'de düzeltildi: trait metodu her zaman `Rejected` döner,
//! gerçek doğrulama yalnızca `verify_finality_with_claim` üzerinden
//! ProofClaimRegistry ile yapılır.
//!
//! ## Regresyon #2: Relayer escrow silent-failure (P5 ADIM11)
//!
//! Escrowed AiAgentPayment release edildiğinde, registry'den payment
//! kaldırılmalı ve alıcıya balance credit yapılmalı. Eğer release/reclaim
//! sessizce başarısız olursa (balance değişimi olmadan payment kaybolursa),
//! fonlar kaybedilir. Test, release/reclaim'in payment'ı gerçekten
//! kaldırdığını ve non-escrowed path'in recipient'ı anında credit ettiğini
//! doğrular.

// ─── Regresyon #1: ZK finality fail-open ─────────────────────────────────

#[cfg(test)]
mod zk_finality_fail_open_regression {
    use crate::domain::finality_adapter::{
        DomainFinalityAdapter, FinalityProof, FinalityStatus, ZkFinalityAdapter,
    };
    use crate::domain::plugin::default_domain;
    use crate::domain::types::{ConsensusKind, DomainCommitment, Hash32};

    /// ZK domain + commitment yardımcı fonksiyonları.
    fn zk_domain() -> crate::domain::types::ConsensusDomain {
        default_domain(42, ConsensusKind::Zk, 1337, "zk-proof-verification", 0)
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

    /// REGRESYON KİLİDİ (Task 0.358): `ZkFinalityAdapter::verify_finality`
    /// (generic trait entry point) ASLA `Finalized` dönmemelidir.
    ///
    /// Bu metod eskiden ProofClaimRegistry lookup'ı olmadan finalize
    /// edebiliyordu — bu, ikinci bir registry-bağımsız doğrulama yoluydu
    /// (fail-open). Birisi yanlışlıkla bu metodu "düzeltip" `Finalized`
    /// dönmeye başlarsa, bu test kırılır.
    ///
    /// İstenen davranış: her zaman `Rejected` — ZK finality yalnızca
    /// `verify_finality_with_claim` üzerinden çözülebilir.
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
             Got: {:?}. This is a Task 0.358 regression — ZK finality must only \
             resolve via verify_finality_with_claim with ProofClaimRegistry.",
            result
        );
    }

    /// REGRESYON KİLİDİ: `verify_finality_with_claim` accepted_claim_root=None
    /// (registry'de claim yok) durumunda ASLA `Finalized` dönmemelidir.
    ///
    /// Bu, Task 0.08 audit'inde bulunan "missing binding" hatasının bir
    /// tezahürü — claim yoksa finalize olmamalı.
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

    /// REGRESYON KİLİDİ: `verify_finality_with_claim` claim root ile
    /// commitment state root eşleşmediğinde ASLA `Finalized` dönmemelidir.
    ///
    /// Task 0.08 audit: "binding the proof to the accepted claim" + "binding
    /// the claim to THIS commitment" — ikisi de başarısız olursa finalize
    /// olmamalı.
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

    /// REGRESYON KİLİDİ: `verify_finality_with_claim` claim root ile proof'un
    /// final_state_root eşleşmediğinde ASLA `Finalized` dönmemelidir.
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

    /// REGRESYON KİLİDİ: Yalnızca TÜM binding'ler eşleştiğinde (claim root
    /// = proof root = commitment state root) `Finalized` dönmelidir.
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

    /// REGRESYON KİLİDİ: `verify_finality_with_claim` domain_id veya height
    /// uyuşmazlığında ASLA `Finalized` dönmemelidir.
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

    /// Yardımcı: temel bir AI registry + model kurulumu.
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
            })
            .unwrap();
        (registry, model_id, owner)
    }

    /// Bir inference request oluştur ve registry'ye kaydet.
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
        };
        req.request_id = req.calculate_id();
        registry.submit_request(req, current_block).unwrap()
    }

    /// Bir verifier'dan result submit et.
    fn submit_result(
        registry: &mut AiRegistry,
        request_id: AiRequestId,
        verifier: Address,
        output_commitment: [u8; 32],
        result_nonce: u64,
        current_block: u64,
    ) {
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

    /// REGRESYON KİLİDİ (P5 ADIM11): Escrowed payment release edildiğinde,
    /// payment registry'den KALDIRILMALIDIR. Eğer `release_agent_payment`
    /// sessizce başarısız olursa (payment kalır ama balance credit yapılmaz),
    /// fonlar donmuş kalır.
    ///
    /// Bu test, release'in payment'ı gerçekten kaldırdığını doğrular.
    /// Eğer birisi release kodunu kırarsa, payment registry'de kalır ve
    /// test assertion'ı (`get_agent_payment` → `None`) başarısız olur.
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

        // Request + result + outcome oluştur
        let request_id = submit_request(
            &mut registry,
            model_id,
            requester.clone(),
            current_block,
            current_block + 100,
        );

        // İki verifier aynı output_commitment ile submit → finalization
        submit_result(
            &mut registry,
            request_id.clone(),
            verifier.clone(),
            [0x11u8; 32],
            1,
            current_block + 10,
        );
        submit_result(
            &mut registry,
            request_id.clone(),
            verifier2.clone(),
            [0x11u8; 32],
            2,
            current_block + 11,
        );

        // Escrowed payment oluştur
        let payment = AiAgentPayment {
            payment_id: [0xFEu8; 32],
            from_agent: requester.clone(),
            to_agent: verifier.clone(),
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

        // REGRESYON KİLİDİ: Payment artık registry'de OLMAMALI
        assert!(
            registry.get_agent_payment(&[0xFEu8; 32]).is_none(),
            "REGRESYON: escrowed payment release sonrası payment hâlâ registry'de! \
             Bu, release'in payment'ı kaldırmadığı (silent-failure) anlamına gelir — \
             fonlar alıcıya credit edilmeden payment donmuş kalır."
        );
    }

    /// REGRESYON KİLİDİ (P5 ADIM11): Escrowed payment expire olduğunda
    /// reclaim edilebilmeli ve payment registry'den KALDIRILMALIDIR.
    ///
    /// Eğer reclaim sessizce başarısız olursa, süresi dolmuş payment
    /// registry'de kalır ve gönderen fonlarını geri alamaz.
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
            requester.clone(),
            current_block,
            current_block + 100,
        );

        // Escrowed payment (kısa expiry)
        let payment = AiAgentPayment {
            payment_id: [0xFDu8; 32],
            from_agent: requester.clone(),
            to_agent: verifier,
            amount: 300,
            request_id: Some(request_id),
            require_proof: false,
            submitted_at_block: current_block,
            expiry_block: current_block + 50, // 50 block sonra expire
        };
        registry
            .submit_agent_payment(payment, current_block)
            .unwrap();

        // Henüz expire olmadı → reclaim reddedilmeli
        let reclaim_before =
            registry.reclaim_agent_payment(&[0xFDu8; 32], &requester, current_block + 30);
        assert!(reclaim_before.is_err(), "reclaim before expiry must fail");
        assert!(
            registry.get_agent_payment(&[0xFDu8; 32]).is_some(),
            "payment must still exist before expiry"
        );

        // Expire sonrası reclaim
        let reclaimed_amount = registry
            .reclaim_agent_payment(&[0xFDu8; 32], &requester, current_block + 51)
            .expect("reclaim after expiry must succeed");
        assert_eq!(reclaimed_amount, 300);

        // REGRESYON KİLİDİ: Payment artık registry'de OLMAMALI
        assert!(
            registry.get_agent_payment(&[0xFDu8; 32]).is_none(),
            "REGRESYON: expired payment reclaim sonrası payment hâlâ registry'de! \
             Bu, reclaim'in payment'ı kaldırmadığı (silent-failure) anlamına gelir — \
             gönderen fonlarını geri alamadan payment donmuş kalır."
        );
    }

    /// REGRESYON KİLİDİ: Non-escrowed payment (request_id=None) asla release
    /// edilemez — bu path zaten "immediate credit" ile executor'da çözülür.
    /// Release çağrılmamalı, çünkü escrow yok.
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

        // Release denenirse → hata vermeli (escrow yok)
        let result = registry.release_agent_payment(&[0xFCu8; 32], 110);
        assert!(
            result.is_err(),
            "REGRESYON: non-escrowed payment release edilmemeli! \
             Bu payment executor'da anında credit edilmeli, release path'ine girmemeli. \
             Release'in hata vermesi, executor'ın non-escrowed path'inin doğru \
             çalıştığını (recipient anında credit alır) korur."
        );
    }

    /// REGRESYON KİLİDİ: Reclaim yalnızca gönderen (from_agent) tarafından
    /// yapılabilir. Başka bir adres reclaim ederse → hata.
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
            requester.clone(),
            current_block,
            current_block + 100,
        );

        let payment = AiAgentPayment {
            payment_id: [0xFBu8; 32],
            from_agent: requester.clone(),
            to_agent: verifier.clone(),
            amount: 400,
            request_id: Some(request_id),
            require_proof: false,
            submitted_at_block: current_block,
            expiry_block: current_block + 50,
        };
        registry
            .submit_agent_payment(payment, current_block)
            .unwrap();

        // Alıcı (to_agent) reclaim edemez
        let result = registry.reclaim_agent_payment(&[0xFBu8; 32], &verifier, current_block + 51);
        assert!(
            result.is_err(),
            "REGRESYON: alıcı (to_agent) payment'ı reclaim edememeli! \
             Yalnızca gönderen (from_agent) reclaim yetkisine sahip olmalı."
        );

        // Payment hâlâ registry'de (reclaim başarısız oldu)
        assert!(
            registry.get_agent_payment(&[0xFBu8; 32]).is_some(),
            "failed reclaim must not remove the payment"
        );
    }

    /// REGRESYON KİLİDİ: Release, ödeme süresi dolmuşsa (expired) reddedilmeli.
    /// Expired payment ancak reclaim ile geri alınabilir.
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
            requester.clone(),
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

        // Expire sonrası release denenir → reddedilmeli
        let result = registry.release_agent_payment(&[0xFAu8; 32], current_block + 51);
        assert!(
            result.is_err(),
            "REGRESYON: expired payment release edilmemeli! \
             Expired payment sadece reclaim ile geri alınabilir. \
             Release'in kabul edilmesi, fonların alıcıya gitmesine ve \
             gönderenin geri alamamasına yol açar."
        );

        // Payment hâlâ registry'de (release başarısız)
        assert!(
            registry.get_agent_payment(&[0xFAu8; 32]).is_some(),
            "failed release must not remove the payment"
        );
    }

    /// REGRESYON KİLİDİ: Çift release önlenmeli. İlk release payment'ı
    /// kaldırdığı için, ikinci release bulunamayan payment hatası vermeli.
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
            requester.clone(),
            current_block,
            current_block + 100,
        );

        // İki verifier aynı output → finalization
        submit_result(
            &mut registry,
            request_id.clone(),
            verifier.clone(),
            [0x11u8; 32],
            1,
            current_block + 10,
        );
        submit_result(
            &mut registry,
            request_id.clone(),
            verifier2,
            [0x11u8; 32],
            2,
            current_block + 11,
        );

        let payment = AiAgentPayment {
            payment_id: [0xF9u8; 32],
            from_agent: requester,
            to_agent: verifier.clone(),
            amount: 150,
            // Must link the REAL finalized request_id (not a placeholder).
            // Placeholder [0xCD;32] has no outcome → release fails pre-condition.
            request_id: Some(request_id.clone()),
            require_proof: false,
            submitted_at_block: current_block + 20,
            expiry_block: current_block + 200,
        };
        registry
            .submit_agent_payment(payment, current_block + 20)
            .unwrap();

        // İlk release başarılı
        registry
            .release_agent_payment(&[0xF9u8; 32], current_block + 30)
            .expect("first release must succeed");

        // İkinci release → payment artık yok
        let result = registry.release_agent_payment(&[0xF9u8; 32], current_block + 31);
        assert!(
            result.is_err(),
            "REGRESYON: çift release önlenmeli! İlk release payment'ı \
             kaldırdıktan sonra ikinci release bir hata vermeli. Aksi halde \
             alıcı aynı ödemeyi iki kez talep edebilir."
        );
    }
}
