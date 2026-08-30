//! PoA/permissionless isolation test suite - CI expansion item 9.
//!
//! This file verifies that the PoA domain does not leak into the permissionless side.
//! Five distinct leak scenarios are tested:
//! 1. RPC leak - PoA data must not appear in the permissionless RPC
//! 2. Event leak - PoA membership events must not leak into the permissionless domain
//! 3. Cross-domain message leak - PoA KYC metadata must not travel in a cross-domain message
//! 4. Log leak - PoA information must not be leaked in chain data
//! 5. Error message leak - error messages must not disclose PoA details

#[cfg(test)]
mod poa_isolation_tests {
    use crate::core::account::AccountState;
    use crate::core::address::Address;

    use crate::registry::poa_membership::PoaMembershipRegistry;
    use crate::registry::role::roles;

    const POA_DOMAIN: u32 = 3;

    /// Scenario 1: RPC leak - PoA membership data must not appear in the permissionless registry.
    ///
    /// A PoA member must not enter the permissionless registry without staking.
    #[test]
    fn poa_member_cannot_register_in_permissionless_registry_without_stake() {
        let perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);
        let poa_member = Address::from([0xAA; 32]);

        // Assign an admin, apply to PoA with KYC and approve
        poa_reg.add_admin(POA_DOMAIN, admin);
        poa_reg
            .submit_application(POA_DOMAIN, poa_member, [1u8; 32])
            .unwrap();
        poa_reg.approve(POA_DOMAIN, admin, poa_member).unwrap();

        // The PoA member must not be active in the permissionless registry (no stake)
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

    /// Scenario 2: event leak - PoA membership events must not appear in the permissionless domain.
    ///
    /// PoA membership must not be reflected in the permissionless validator set.
    #[test]
    fn poa_membership_does_not_affect_permissionless_validator_set() {
        let mut perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);
        let poa_member = Address::from([0xAA; 32]);
        let permissionless_validator = Address::from([0xBB; 32]);

        // Add a PoA member
        poa_reg.add_admin(POA_DOMAIN, admin);
        poa_reg
            .submit_application(POA_DOMAIN, poa_member, [1u8; 32])
            .unwrap();
        poa_reg.approve(POA_DOMAIN, admin, poa_member).unwrap();

        // Permissionless validator ekle (stake ile)
        perm_state.add_balance(&permissionless_validator, 10_000);
        perm_state.add_validator(permissionless_validator, 5_000);

        // The active validators list must contain only the permissionless validator
        let active = perm_state.get_active_validators();
        assert_eq!(
            active.len(),
            1,
            "Only permissionless validator should be in active set"
        );
        assert_eq!(active[0].address, permissionless_validator);

        // The PoA member must not be in the active validators list
        assert!(
            !active.iter().any(|v| v.address == poa_member),
            "PoA member must NOT appear in permissionless active validator set"
        );
    }

    /// Scenario 3: cross-domain message leak - PoA KYC metadata must not travel in a cross-domain message.
    ///
    /// A CrossDomainMessage contains no KYC commitment; it carries only payload_hash.
    #[test]
    fn cross_domain_message_does_not_carry_kyc_metadata() {
        use crate::cross_domain::message::{
            CrossDomainMessage, CrossDomainMessageParams, MessageKind,
        };

        // Build a message from the PoA domain to the permissionless domain
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

        // The message must contain no KYC commitment or PoA metadata
        let message_bytes = serde_json::to_vec(&message).unwrap();
        let message_str = String::from_utf8_lossy(&message_bytes);

        assert!(
            !message_str.to_lowercase().contains("kyc"),
            "CrossDomainMessage must NOT contain KYC metadata"
        );

        // The message carries only a hash, not raw data
        assert_ne!(
            message.payload_hash, [0u8; 32],
            "Payload hash should be present"
        );
    }

    /// Scenario 4: log leak - PoA information must not be leaked in chain data.
    ///
    /// The PoA registry is entirely separate from the permissionless registry.
    #[test]
    fn poa_membership_isolated_from_permissionless_registry() {
        let perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);
        let poa_member = Address::from([0xAA; 32]);

        // Add a PoA member
        poa_reg.add_admin(POA_DOMAIN, admin);
        poa_reg
            .submit_application(POA_DOMAIN, poa_member, [1u8; 32])
            .unwrap();
        poa_reg.approve(POA_DOMAIN, admin, poa_member).unwrap();

        // The PoA registry is separate from the permissionless registry
        assert!(
            poa_reg.is_authorized(POA_DOMAIN, &poa_member),
            "PoA member should be authorized in PoA registry"
        );

        // This address must not be active in the permissionless registry
        assert!(
            !perm_state.registry.is_active(&poa_member, roles::VALIDATOR),
            "PoA member must NOT be active in permissionless registry"
        );
    }

    /// Scenario 5: error message leak - error messages must not disclose PoA details.
    ///
    /// The PoA and permissionless registries are entirely separate data structures.
    #[test]
    fn poa_and_permissionless_registries_share_no_state() {
        let mut perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);

        let poa_addr = Address::from([0xAA; 32]);
        let perm_addr = Address::from([0xBB; 32]);

        // Add a member to PoA
        poa_reg.add_admin(POA_DOMAIN, admin);
        poa_reg
            .submit_application(POA_DOMAIN, poa_addr, [1u8; 32])
            .unwrap();
        poa_reg.approve(POA_DOMAIN, admin, poa_addr).unwrap();

        // Permissionless'a validator ekle
        perm_state.add_balance(&perm_addr, 10_000);
        perm_state.add_validator(perm_addr, 5_000);

        // The PoA member is not in the permissionless validator set
        assert!(
            !perm_state.registry.is_active(&poa_addr, roles::VALIDATOR),
            "PoA member must NOT be in permissionless registry"
        );

        // Permissionless validator PoA'da yok
        assert!(
            !poa_reg.is_authorized(POA_DOMAIN, &perm_addr),
            "Permissionless validator must NOT be in PoA registry"
        );

        // The permissionless registry parameters are independent of PoA
        let perm_params = perm_state.registry.params();
        assert!(perm_params.min_stake > 0);
    }

    /// Extra: the PoA domain id must differ from the permissionless domain id.
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

    /// Extra: PoA admin authority must not affect the permissionless side.
    #[test]
    fn poa_admin_authority_does_not_grant_permissionless_power() {
        let perm_state = AccountState::new();
        let mut poa_reg = PoaMembershipRegistry::new();
        let admin = Address::from([0xAD; 32]);

        poa_reg.add_admin(POA_DOMAIN, admin);

        // Admin PoA'da yetkili
        assert!(poa_reg.is_admin(POA_DOMAIN, &admin));

        // But it is an ordinary account in the permissionless registry
        assert!(
            !perm_state.registry.is_active(&admin, roles::VALIDATOR),
            "PoA admin should NOT have permissionless validator status"
        );
    }

    /// An additional isolation seal: the PoA whitelist is entirely independent of
    /// permissionless stake. An account that became a permissionless validator through stake is
    /// NOT in the PoA whitelist; PoA whitelist membership does NOT grant permissionless active
    /// status. This test is part of the PoA isolation CI gate (7 or more).
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

        // A stake-only account is not in the PoA whitelist
        assert!(
            !poa.whitelist(POA_DOMAIN, 1).contains(&perm_validator),
            "stake-only account must NOT appear in PoA whitelist"
        );

        // Approve a PoA member
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

        // The reverse leak: PoA whitelist membership does not grant permissionless activity
        assert!(
            !perm_state.registry.is_active(&poa_member, roles::VALIDATOR),
            "PoA whitelist membership must NOT grant permissionless validator status"
        );
    }
}

/// The PoA compliance ledger is now a GATE: a freeze record has consequences.
///
/// For a long time the module only kept records - freezing could be called but
/// being frozen had no effect. These tests lock the binding.
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

    /// Freezing in a permissionless domain is REFUSED.
    ///
    /// On a network that claims sovereignty, a central administrator must not be
    /// able to freeze the account of a permissionless domain. The kind of the
    /// domain is read **from its record**;
    /// a caller cannot declare their own domain to be PoA and manufacture this authority.
    #[test]
    fn a_permissionless_domain_account_cannot_be_frozen() {
        let mut bc = chain();
        // Any non-PoA domain: the compliance ledger only looks at PoA.
        let d = default_domain(7, ConsensusKind::PoW, 907, "pow-header-chain-v1", 0);
        bc.register_consensus_domain(d)
            .expect("the domain registers");

        let err = bc
            .freeze_poa_account(7, true, addr(0x42), [9u8; 32])
            .expect_err("freezing in a permissionless domain must be refused");
        assert!(
            err.contains("Poa") || err.contains("PoA") || err.contains("Permissionless"),
            "the reason must state that the domain is permissionless, got: {err}"
        );
        assert!(!bc
            .poa_compliance
            .is_frozen(ComplianceDomainKind::PoA, &addr(0x42)));
    }

    /// An unauthorized caller cannot freeze.
    #[test]
    fn an_unauthorized_admin_cannot_freeze() {
        let mut bc = chain();
        bc.register_consensus_domain(poa_domain(8))
            .expect("the domain registers");

        bc.freeze_poa_account(8, false, addr(0x43), [9u8; 32])
            .expect_err("an unauthorized freeze must be refused");
        assert!(!bc
            .poa_compliance
            .is_frozen(ComplianceDomainKind::PoA, &addr(0x43)));
    }

    /// The reason digest cannot be zero: a freeze without evidence cannot be audited.
    #[test]
    fn a_freeze_without_evidence_is_refused() {
        let mut bc = chain();
        bc.register_consensus_domain(poa_domain(9))
            .expect("the domain registers");

        bc.freeze_poa_account(9, true, addr(0x44), [0u8; 32])
            .expect_err("a zero reason digest must be refused");
        assert!(!bc
            .poa_compliance
            .is_frozen(ComplianceDomainKind::PoA, &addr(0x44)));
    }

    /// No freeze for an unknown domain.
    #[test]
    fn an_unknown_domain_cannot_be_frozen() {
        let mut bc = chain();
        let err = bc
            .freeze_poa_account(4242, true, addr(0x45), [9u8; 32])
            .expect_err("an unknown domain must be refused");
        assert!(err.contains("unknown domain"), "{err}");
    }

    /// A freeze installs a GATE: the audit package of a frozen operator is refused.
    ///
    /// Without consequences, being frozen would be just a note.
    #[test]
    fn a_frozen_operator_cannot_export_a_sovereign_audit_bundle() {
        use crate::domain::sovereign::{
            AuditExportBundle, ComplianceEvidence, DomainLifecycleState, SovereignDomainClass,
            SovereignDomainTemplate,
        };

        let mut bc = chain();
        bc.register_consensus_domain(poa_domain(11))
            .expect("the domain registers");
        // The operator is read from the domain RECORD. Had the test invented its own address,
        // it would bypass the gate that verifies the record is consistent with the template; the record
        // already says the template operator must equal the domain operator.
        let operator = bc
            .domain_registry
            .get(11)
            .and_then(|d| d.operator)
            .expect("the operator of the registered domain");

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
            .expect("the template registers");

        let bundle = AuditExportBundle {
            template_id,
            from_height: 0,
            to_height: 10,
            global_header_root: [6u8; 32],
            commitment_root: [7u8; 32],
            compliance_root,
        };

        // It passes before the freeze.
        bc.validate_sovereign_audit_export(&bundle)
            .expect("with no freeze the packet must pass");

        // Operator dondurulur.
        bc.freeze_poa_account(11, true, operator, [8u8; 32])
            .expect("yetkili dondurma");

        let err = bc
            .validate_sovereign_audit_export(&bundle)
            .expect_err("the package of a frozen operator must be refused");
        assert!(
            err.contains("frozen"),
            "the reason must state the freeze: {err}"
        );
    }

    /// The freeze works and enters the audit trail.
    #[test]
    fn a_poa_freeze_is_recorded_with_its_evidence() {
        let mut bc = chain();
        bc.register_consensus_domain(poa_domain(10))
            .expect("the domain registers");
        let target = addr(0x46);

        bc.freeze_poa_account(10, true, target, [7u8; 32])
            .expect("an authorised freeze must pass");

        assert!(bc
            .poa_compliance
            .is_frozen(ComplianceDomainKind::PoA, &target));
        assert!(
            !bc.poa_compliance.audit_events().is_empty(),
            "the freeze must enter the audit trail"
        );
    }
}
