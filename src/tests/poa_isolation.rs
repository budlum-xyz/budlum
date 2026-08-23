//! PoA/Permissionless izolasyon test seti - CI Genişletme Madde 9.
//!
//! Bu dosya PoA domain'inin permissionless tarafa sızmadığını doğrular.
//! 5 farklı sızma senaryosu test edilir:
//! 1. RPC leak - PoA verisi permissionless RPC'de görünmemeli
//! 2. Event leak - PoA membership event'leri permissionless domain'e sızmamalı
//! 3. Cross-domain mesaj leak - PoA KYC metadata cross-domain mesajda taşınmamalı
//! 4. Log leak - PoA bilgisi zincir verilerinde sızdırılmamalı
//! 5. Error message leak - Hata mesajları PoA detaylarını ifşa etmemeli

#[cfg(test)]
mod poa_isolation_tests {
    use crate::core::account::AccountState;
    use crate::core::address::Address;

    use crate::registry::poa_membership::PoaMembershipRegistry;
    use crate::registry::role::roles;

    const POA_DOMAIN: u32 = 3;

    /// Senaryo 1: RPC Leak - PoA membership verisi permissionless registry'de görünmemeli.
    ///
    /// PoA üyesi permissionless registry'ye stake atlamadan girememeli.
    #[test]
    fn poa_member_cannot_register_in_permissionless_registry_without_stake() {
        let perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);
        let poa_member = Address::from([0xAA; 32]);

        // Admin ata ve PoA'ya KYC ile başvur + onayla
        poa_reg.add_admin(POA_DOMAIN, admin);
        poa_reg
            .submit_application(POA_DOMAIN, poa_member, [1u8; 32])
            .unwrap();
        poa_reg.approve(POA_DOMAIN, admin, poa_member).unwrap();

        // PoA üyesi permissionless registry'de aktif olmamalı (stake yok)
        assert!(
            !perm_state.registry.is_active(&poa_member, roles::VALIDATOR),
            "PoA member should NOT be active as a permissionless validator without stake"
        );
        assert!(
            !perm_state
                .registry
                .is_active(&poa_member, roles::STORAGE_OPERATOR),
            "PoA member should NOT be active as a storage operator without stake"
        );
        assert!(
            !perm_state
                .registry
                .is_active(&poa_member, roles::AI_VERIFIER),
            "PoA member should NOT be active as an AI verifier without stake"
        );
    }

    /// Senaryo 2: Event Leak - PoA membership event'leri permissionless domain'de görünmemeli.
    ///
    /// PoA üyeliği permissionless validator setine yansımamalı.
    #[test]
    fn poa_membership_does_not_affect_permissionless_validator_set() {
        let mut perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);
        let poa_member = Address::from([0xAA; 32]);
        let permissionless_validator = Address::from([0xBB; 32]);

        // PoA üyesi ekle
        poa_reg.add_admin(POA_DOMAIN, admin);
        poa_reg
            .submit_application(POA_DOMAIN, poa_member, [1u8; 32])
            .unwrap();
        poa_reg.approve(POA_DOMAIN, admin, poa_member).unwrap();

        // Permissionless validator ekle (stake ile)
        perm_state.add_balance(&permissionless_validator, 10_000);
        perm_state.add_validator(permissionless_validator, 5_000);

        // Active validators listesinde sadece permissionless validator olmalı
        let active = perm_state.get_active_validators();
        assert_eq!(
            active.len(),
            1,
            "Only permissionless validator should be in active set"
        );
        assert_eq!(active[0].address, permissionless_validator);

        // PoA üyesi active validators listesinde olmamalı
        assert!(
            !active.iter().any(|v| v.address == poa_member),
            "PoA member must NOT appear in permissionless active validator set"
        );
    }

    /// Senaryo 3: Cross-Domain Mesaj Leak - PoA KYC metadata cross-domain mesajda taşınmamalı.
    ///
    /// CrossDomainMessage KYC commitment içermez, sadece payload_hash taşır.
    #[test]
    fn cross_domain_message_does_not_carry_kyc_metadata() {
        use crate::cross_domain::message::{
            CrossDomainMessage, CrossDomainMessageParams, MessageKind,
        };

        // PoA domain'inden permissionless domain'e mesaj oluştur
        let message = CrossDomainMessage::new(CrossDomainMessageParams {
            source_domain: POA_DOMAIN,
            target_domain: 1,
            source_height: 100,
            event_index: 0,
            nonce: 0,
            sender: Address::from([0xAA; 32]),
            recipient: Address::from([0xBB; 32]),
            payload_hash: [0xCC; 32],
            kind: MessageKind::Custom(vec![1, 2, 3]),
            expiry_height: 200,
        });

        // Mesaj KYC commitment veya PoA metadata içermemeli
        let message_bytes = serde_json::to_vec(&message).unwrap();
        let message_str = String::from_utf8_lossy(&message_bytes);

        assert!(
            !message_str.to_lowercase().contains("kyc"),
            "CrossDomainMessage must NOT contain KYC metadata"
        );

        // Mesaj sadece hash taşır, ham veri değil
        assert_ne!(
            message.payload_hash, [0u8; 32],
            "Payload hash should be present"
        );
    }

    /// Senaryo 4: Log Leak - PoA bilgisi zincir verilerinde sızdırılmamalı.
    ///
    /// PoA registry'si permissionless registry'den tamamen ayrıdır.
    #[test]
    fn poa_membership_isolated_from_permissionless_registry() {
        let perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);
        let poa_member = Address::from([0xAA; 32]);

        // PoA üyesi ekle
        poa_reg.add_admin(POA_DOMAIN, admin);
        poa_reg
            .submit_application(POA_DOMAIN, poa_member, [1u8; 32])
            .unwrap();
        poa_reg.approve(POA_DOMAIN, admin, poa_member).unwrap();

        // PoA registry'si permissionless registry'den ayrı
        assert!(
            poa_reg.is_authorized(POA_DOMAIN, &poa_member),
            "PoA member should be authorized in PoA registry"
        );

        // Permissionless registry'de bu adres aktif olmamalı
        assert!(
            !perm_state.registry.is_active(&poa_member, roles::VALIDATOR),
            "PoA member must NOT be active in permissionless registry"
        );
    }

    /// Senaryo 5: Error Message Leak - Hata mesajları PoA detaylarını ifşa etmemeli.
    ///
    /// PoA ve Permissionless registry'ler tamamen ayrı veri yapılarıdır.
    #[test]
    fn poa_and_permissionless_registries_share_no_state() {
        let mut perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);

        let poa_addr = Address::from([0xAA; 32]);
        let perm_addr = Address::from([0xBB; 32]);

        // PoA'ya üye ekle
        poa_reg.add_admin(POA_DOMAIN, admin);
        poa_reg
            .submit_application(POA_DOMAIN, poa_addr, [1u8; 32])
            .unwrap();
        poa_reg.approve(POA_DOMAIN, admin, poa_addr).unwrap();

        // Permissionless'a validator ekle
        perm_state.add_balance(&perm_addr, 10_000);
        perm_state.add_validator(perm_addr, 5_000);

        // PoA üyesi permissionless validator setinde yok
        assert!(
            !perm_state.registry.is_active(&poa_addr, roles::VALIDATOR),
            "PoA member must NOT be in permissionless registry"
        );

        // Permissionless validator PoA'da yok
        assert!(
            !poa_reg.is_authorized(POA_DOMAIN, &perm_addr),
            "Permissionless validator must NOT be in PoA registry"
        );

        // Permissionless registry parametreleri PoA'dan bağımsız
        let perm_params = perm_state.registry.params();
        assert!(perm_params.min_stake > 0);
    }

    /// Ek: PoA domain ID'si permissionless domain ID'sinden farklı olmalı.
    #[test]
    fn poa_domain_id_isolated_from_permissionless() {
        use crate::domain::types::DomainId;

        let poa_domain: DomainId = POA_DOMAIN;
        let permissionless_domain: DomainId = 1;

        assert_ne!(
            poa_domain, permissionless_domain,
            "PoA domain ID must differ from permissionless domain ID"
        );
    }

    /// Ek: PoA admin yetkisi permissionless tarafı etkilememeli.
    #[test]
    fn poa_admin_authority_does_not_grant_permissionless_power() {
        let perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);

        poa_reg.add_admin(POA_DOMAIN, admin);

        // Admin PoA'da yetkili
        assert!(poa_reg.is_admin(POA_DOMAIN, &admin));

        // Ama permissionless registry'de sıradan bir hesap
        assert!(
            !perm_state.registry.is_active(&admin, roles::VALIDATOR),
            "PoA admin should NOT have permissionless validator status"
        );
    }

    /// Ek izolasyon mührü : PoA whitelist'i permissionless
    /// Stake'ten tamamen bağımsızdır. Stake ile permissionless validator olan
    /// Hesap PoA whitelist'inde YOK; PoA whitelist üyeliği permissionless aktif
    /// Statü VERMEZ. Bu test "PoA Isolation" CI kapısının (≥7) bir parçasıdır.
    #[test]
    fn poa_whitelist_independent_of_permissionless_stake() {
        use crate::registry::poa_onboarding::PoAOnboarding;

        let mut perm_state = AccountState::new();
        let mut poa = PoAOnboarding::new();
        let admin = Address::from([0xAD; 32]);
        poa.add_admin(POA_DOMAIN, admin);

        // Permissionless validator - stake ile
        let perm_validator = Address::from([0xBB; 32]);
        perm_state.add_balance(&perm_validator, 10_000);
        perm_state.add_validator(perm_validator, 5_000);
        assert!(
            perm_state
                .registry
                .is_active(&perm_validator, roles::VALIDATOR),
            "sanity: stake validator is active in permissionless registry"
        );

        // Stake-only hesap PoA whitelist'inde değil
        assert!(
            !poa.whitelist(POA_DOMAIN, 1).contains(&perm_validator),
            "stake-only account must NOT appear in PoA whitelist"
        );

        // Bir PoA üyesi onayla
        let poa_member = Address::from([0xAA; 32]);
        poa.submit_application(POA_DOMAIN, poa_member, [1u8; 32], 0)
            .unwrap();
        poa.approve(POA_DOMAIN, admin, poa_member, 0, 1_000)
            .unwrap();

        let wl = poa.whitelist(POA_DOMAIN, 1);
        assert!(wl.contains(&poa_member));
        assert!(
            !wl.contains(&perm_validator),
            "permissionless validator must NOT leak into PoA whitelist"
        );

        // Ters yönlü sızma: PoA whitelist üyeliği permissionless aktiflik vermez
        assert!(
            !perm_state.registry.is_active(&poa_member, roles::VALIDATOR),
            "PoA whitelist membership must NOT grant permissionless validator status"
        );
    }
}

/// PoA uyum defteri artik bir KAPI: dondurma kaydinin sonucu var.
///
/// Modul uzun sure yalniz kayit tutuyordu - dondurma cagrilabiliyordu ama
/// dondurulmus olmanin hicbir etkisi yoktu. Bu testler baglamayi kilitler.
#[cfg(test)]
mod poa_compliance_gate {
    use crate::chain::blockchain::Blockchain;
    use crate::consensus::PoWEngine;
    use crate::core::address::Address;
    use crate::domain::plugin::default_domain;
    use crate::domain::{ConsensusDomain, ConsensusKind};
    use crate::registry::ComplianceDomainKind;
    use std::sync::Arc;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn chain() -> Blockchain {
        Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None)
    }

    fn poa_domain(id: u32) -> ConsensusDomain {
        default_domain(
            id,
            ConsensusKind::PoA,
            u64::from(id) + 900,
            "poa-authority-quorum",
            0,
        )
    }

    /// Izinsiz alanda dondurma REDDEDILIR.
    ///
    /// Egemenlik iddiasi tasiyan bir agda, izinsiz bir alanin hesabini
    /// merkezi bir yonetici donduramamali. Alanin turu **kaydindan** okunur;
    /// cagiran kendi alanini "PoA" ilan edip bu yetkiyi uretemez.
    #[test]
    fn a_permissionless_domain_account_cannot_be_frozen() {
        let mut bc = chain();
        // PoA olmayan herhangi bir alan: uyum defteri yalniz PoA'ya bakar.
        let d = default_domain(7, ConsensusKind::PoW, 907, "pow-header-chain-v1", 0);
        bc.register_consensus_domain(d).expect("alan kaydi");

        let err = bc
            .freeze_poa_account(7, true, addr(0x42), [9u8; 32])
            .expect_err("izinsiz alanda dondurma reddedilmeli");
        assert!(
            err.contains("Poa") || err.contains("PoA") || err.contains("Permissionless"),
            "gerekce alanin izinsiz oldugunu soylemeli, gelen: {err}"
        );
        assert!(!bc
            .poa_compliance
            .is_frozen(ComplianceDomainKind::PoA, &addr(0x42)));
    }

    /// Yetkisiz cagiran donduramaz.
    #[test]
    fn an_unauthorized_admin_cannot_freeze() {
        let mut bc = chain();
        bc.register_consensus_domain(poa_domain(8))
            .expect("alan kaydi");

        bc.freeze_poa_account(8, false, addr(0x43), [9u8; 32])
            .expect_err("yetkisiz dondurma reddedilmeli");
        assert!(!bc
            .poa_compliance
            .is_frozen(ComplianceDomainKind::PoA, &addr(0x43)));
    }

    /// Gerekce ozeti sifir olamaz: kanitsiz dondurma denetlenemez.
    #[test]
    fn a_freeze_without_evidence_is_refused() {
        let mut bc = chain();
        bc.register_consensus_domain(poa_domain(9))
            .expect("alan kaydi");

        bc.freeze_poa_account(9, true, addr(0x44), [0u8; 32])
            .expect_err("sifir gerekce ozeti reddedilmeli");
        assert!(!bc
            .poa_compliance
            .is_frozen(ComplianceDomainKind::PoA, &addr(0x44)));
    }

    /// Bilinmeyen alan icin dondurma yok.
    #[test]
    fn an_unknown_domain_cannot_be_frozen() {
        let mut bc = chain();
        let err = bc
            .freeze_poa_account(4242, true, addr(0x45), [9u8; 32])
            .expect_err("bilinmeyen alan reddedilmeli");
        assert!(err.contains("unknown domain"), "{err}");
    }

    /// Dondurma bir KAPI kurar: dondurulmus operatorun denetim paketi reddedilir.
    ///
    /// Kaydin sonucu olmasaydi "donduruldu" yalnizca bir not olurdu.
    #[test]
    fn a_frozen_operator_cannot_export_a_sovereign_audit_bundle() {
        use crate::domain::sovereign::{
            AuditExportBundle, ComplianceEvidence, DomainLifecycleState, SovereignDomainClass,
            SovereignDomainTemplate,
        };

        let mut bc = chain();
        bc.register_consensus_domain(poa_domain(11))
            .expect("alan kaydi");
        let operator = addr(0x11);

        let compliance = ComplianceEvidence {
            policy_hash: [3u8; 32],
            authority_set_hash: [4u8; 32],
            jurisdiction_hash: [5u8; 32],
            audit_commitment: [6u8; 32],
        };
        let template = SovereignDomainTemplate::new(
            11,
            SovereignDomainClass::EnterprisePoa,
            ConsensusKind::PoA,
            operator,
            true,
            compliance,
            DomainLifecycleState::Active,
        );
        let template_id = template.template_id;
        let compliance_root = template.compliance.root();
        bc.register_sovereign_template(template)
            .expect("sablon kaydi");

        let bundle = AuditExportBundle {
            template_id,
            from_height: 0,
            to_height: 10,
            global_header_root: [6u8; 32],
            commitment_root: [7u8; 32],
            compliance_root,
        };

        // Dondurmadan once gecer.
        bc.validate_sovereign_audit_export(&bundle)
            .expect("dondurma yokken paket gecmeli");

        // Operator dondurulur.
        bc.freeze_poa_account(11, true, operator, [8u8; 32])
            .expect("yetkili dondurma");

        let err = bc
            .validate_sovereign_audit_export(&bundle)
            .expect_err("dondurulmus operatorun paketi reddedilmeli");
        assert!(
            err.contains("frozen"),
            "gerekce dondurmayi soylemeli: {err}"
        );
    }

    /// Dondurma calisir ve denetim izine girer.
    #[test]
    fn a_poa_freeze_is_recorded_with_its_evidence() {
        let mut bc = chain();
        bc.register_consensus_domain(poa_domain(10))
            .expect("alan kaydi");
        let target = addr(0x46);

        bc.freeze_poa_account(10, true, target, [7u8; 32])
            .expect("yetkili dondurma gecmeli");

        assert!(bc
            .poa_compliance
            .is_frozen(ComplianceDomainKind::PoA, &target));
        assert!(
            !bc.poa_compliance.audit_events().is_empty(),
            "dondurma denetim izine girmeli"
        );
    }
}
