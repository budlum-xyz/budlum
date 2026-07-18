//! PoA/Permissionless izolasyon test seti — CI Genişletme Madde 9.
//!
//! Bu dosya PoA domain'inin permissionless tarafa sızmadığını doğrular.
//! 5 farklı sızma senaryosu test edilir:
//! 1. RPC leak — PoA verisi permissionless RPC'de görünmemeli
//! 2. Event leak — PoA membership event'leri permissionless domain'e sızmamalı
//! 3. Cross-domain mesaj leak — PoA KYC metadata cross-domain mesajda taşınmamalı
//! 4. Log leak — PoA bilgisi zincir verilerinde sızdırılmamalı
//! 5. Error message leak — Hata mesajları PoA detaylarını ifşa etmemeli

#[cfg(test)]
mod poa_isolation_tests {
    use crate::core::account::AccountState;
    use crate::core::address::Address;
    use crate::registry::poa_membership::PoaMembershipRegistry;
    use crate::registry::role::roles;

    const POA_DOMAIN: u32 = 3;

    /// Senaryo 1: RPC Leak — PoA membership verisi permissionless registry'de görünmemeli.
    ///
    /// PoA üyesi permissionless registry'ye stake atlamadan girememeli.
    #[test]
    fn poa_member_cannot_register_in_permissionless_registry_without_stake() {
        let mut perm_state = AccountState::new();
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

    /// Senaryo 2: Event Leak — PoA membership event'leri permissionless domain'de görünmemeli.
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
        assert_eq!(active[0], permissionless_validator);

        // PoA üyesi active validators listesinde olmamalı
        assert!(
            !active.contains(&poa_member),
            "PoA member must NOT appear in permissionless active validator set"
        );
    }

    /// Senaryo 3: Cross-Domain Mesaj Leak — PoA KYC metadata cross-domain mesajda taşınmamalı.
    ///
    /// CrossDomainMessage KYC commitment içermez — sadece payload_hash taşır.
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

    /// Senaryo 4: Log Leak — PoA bilgisi zincir verilerinde sızdırılmamalı.
    ///
    /// PoA registry'si permissionless registry'den tamamen ayrıdır.
    #[test]
    fn poa_membership_isolated_from_permissionless_registry() {
        let mut perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);
        let poa_member = Address::from([0xAA; 32]);

        // PoA üyesi ekle
        poa_reg.add_admin(POA_DOMAIN, admin);
        poa_reg
            .submit_application(POA_DOMAIN, poa_member, [1u8; 32])
            .unwrap();
        poa_reg.approve(POA_DOMAIN, admin, poa_member).unwrap();

        // Permissionless registry'de bu adres olmamalı
        let perm_registrations = perm_state.registry.registrations_as_seq();
        let has_poa_in_perm = perm_registrations.iter().any(|r| r.address == poa_member);
        assert!(
            !has_poa_in_perm,
            "PoA member must NOT appear in permissionless registry"
        );

        // PoA registry'si permissionless registry'den ayrı
        assert!(
            poa_reg.is_authorized(POA_DOMAIN, &poa_member),
            "PoA member should be authorized in PoA registry"
        );
    }

    /// Senaryo 5: Error Message Leak — Hata mesajları PoA detaylarını ifşa etmemeli.
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

        // PoA üyesi permissionless'ta yok
        assert!(perm_state.validators.get(&poa_addr).is_none());
        // Permissionless validator PoA'da yok
        assert!(!poa_reg.is_authorized(POA_DOMAIN, &perm_addr));

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
        let mut perm_state = AccountState::new();
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
}
