//! The PoA participant onboarding test matrix.
//!
//! It covers the full lifecycle of the
//! [`crate::registry::poa_onboarding::PoAOnboarding`] module, the whitelist
//! requirement, the KYC expiry behaviour
//! Ve karar denetim (audit) izini kapsar.
//!
//! These tests are NOT part of the `cargo test --lib poa_isolation` gate,
//! because their names do not contain `poa_isolation`; they run in the general
//! lib test suite. The isolation seal was added to the eighth test in
//! `src/tests/poa_isolation.rs`.

#[cfg(test)]
mod tests {
    use crate::core::address::Address;

    use crate::registry::poa_onboarding::{OnboardingDecision, PoAOnboarding, DEFAULT_KYC_HORIZON};

    const DOMAIN: u32 = 3;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn kyc(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// A helper: it returns an onboarding set up with one admin and a single
    /// approved membership.
    fn onboarded(admin: Address, member: Address, horizon: u64) -> PoAOnboarding {
        let mut poa = PoAOnboarding::new();
        poa.add_admin(DOMAIN, admin);
        poa.submit_application(DOMAIN, member, kyc(1), 0).unwrap();
        poa.approve(DOMAIN, admin, member, 0, horizon).unwrap();
        poa
    }

    /// 1. The full lifecycle: application (NOT authorized), approval (on the
    ///    whitelist), revocation (off the whitelist). The decision audit trail
    ///    carries 3 events.
    #[test]
    fn full_onboarding_lifecycle_and_audit() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let mut poa = PoAOnboarding::new();
        poa.add_admin(DOMAIN, admin);

        // The application: not authorized yet.
        poa.submit_application(DOMAIN, member, kyc(1), 10).unwrap();
        assert!(!poa.whitelist(DOMAIN, 10).contains(&member));

        // Approval: the member is on the whitelist
        poa.approve(DOMAIN, admin, member, 20, 1_000).unwrap();
        assert!(poa.whitelist(DOMAIN, 20).contains(&member));

        // Revocation: off the whitelist.
        poa.revoke(DOMAIN, admin, member, 30, "offboarding")
            .unwrap();
        assert!(!poa.whitelist(DOMAIN, 30).contains(&member));

        // The audit trail: Submitted, Approved and Revoked, in order.
        let log = poa.audit_log();
        assert_eq!(log.len(), 3);
        assert!(matches!(
            log[0].decision,
            OnboardingDecision::Submitted { .. }
        ));
        assert!(matches!(
            log[1].decision,
            OnboardingDecision::Approved { .. }
        ));
        assert!(matches!(
            log[2].decision,
            OnboardingDecision::Revoked { .. }
        ));
        assert_eq!(log[0].actor, member); // the candidate who applied
        assert_eq!(log[1].actor, admin);
        assert_eq!(log[2].actor, admin);
    }

    /// 2. The whitelist contains only Approved members; Pending, Rejected and
    ///    Revoked are excluded.
    #[test]
    fn whitelist_excludes_pending_rejected_revoked() {
        let admin = addr(0xAD);
        let mut poa = PoAOnboarding::new();
        poa.add_admin(DOMAIN, admin);

        let pending = addr(1);
        let rejected = addr(2);
        let revoked = addr(3);

        poa.submit_application(DOMAIN, pending, kyc(1), 0).unwrap();

        poa.submit_application(DOMAIN, rejected, kyc(2), 0).unwrap();
        poa.reject(DOMAIN, admin, rejected, 0, "bad dossier")
            .unwrap();

        poa.submit_application(DOMAIN, revoked, kyc(3), 0).unwrap();
        poa.approve(DOMAIN, admin, revoked, 0, 1_000).unwrap();
        poa.revoke(DOMAIN, admin, revoked, 0, "compliance").unwrap();

        let wl = poa.whitelist(DOMAIN, 0);
        assert!(wl.is_empty(), "no Approved member ⇒ empty whitelist");
        assert!(!wl.contains(&pending));
        assert!(!wl.contains(&rejected));
        assert!(!wl.contains(&revoked));
    }

    /// 3. KYC expiry: once the horizon passes, the member drops off the
    ///    whitelist and a KycExpired event is added to the audit trail once.
    #[test]
    fn kyc_expiry_drops_member_from_whitelist() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let mut poa = onboarded(admin, member, 100);

        // Horizon=100 → blok 100'de hâlâ yetkili (now_block > expiry reddeder)
        assert!(poa.whitelist(DOMAIN, 100).contains(&member));
        // It expired at block 101 and dropped off.
        assert!(!poa.whitelist(DOMAIN, 101).contains(&member));

        // The expiry was written into the audit trail once.
        let expired_count = poa
            .audit_log()
            .iter()
            .filter(|e| matches!(e.decision, OnboardingDecision::KycExpired { .. }))
            .count();
        assert_eq!(expired_count, 1, "expiry should be logged exactly once");

        // The underlying registry state is still Approved: the administrative
        // state did not change.
        assert!(poa.registry().is_authorized(DOMAIN, &member));
    }

    /// 4. Renewing the KYC after expiry puts the member back on the whitelist.
    #[test]
    fn renew_kyc_restores_membership() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let mut poa = onboarded(admin, member, 100);

        assert!(poa.whitelist(DOMAIN, 100).contains(&member));
        assert!(!poa.whitelist(DOMAIN, 101).contains(&member));

        // A fresh KYC gives a new horizon.
        poa.renew_kyc(DOMAIN, admin, member, kyc(2), 200, 100)
            .unwrap();
        assert!(poa.whitelist(DOMAIN, 250).contains(&member));
        assert!(!poa.whitelist(DOMAIN, 301).contains(&member));

        // The RenewedKyc audit event is present.
        let renewed = poa
            .audit_log()
            .iter()
            .any(|e| matches!(e.decision, OnboardingDecision::RenewedKyc { .. }));
        assert!(renewed);
    }

    /// 5. The consensus-style requirement gate: if contains is false the
    ///    operation is refused.
    #[test]
    fn whitelist_enforcement_gate_rejects_unauthorized() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let impostor = addr(0xCC);
        let mut poa = onboarded(admin, member, 1_000);

        let wl = poa.whitelist(DOMAIN, 5);

        // The gate: a whitelisted member may act, an unpermitted one may not.
        fn consensus_gate(
            wl: &crate::registry::poa_onboarding::PoAWhitelist,
            who: &Address,
        ) -> Result<(), &'static str> {
            if wl.contains(who) {
                Ok(())
            } else {
                Err("account not authorized to produce blocks in PoA domain")
            }
        }

        assert!(consensus_gate(&wl, &member).is_ok());
        assert!(consensus_gate(&wl, &impostor).is_err());
        assert!(
            consensus_gate(&wl, &admin).is_err(),
            "admin authority ≠ block production authority"
        );
    }

    /// 6. The audit trail is append-only and ordered by block, and every event
    ///    carries its own fields.
    #[test]
    fn audit_trail_is_append_only_and_ordered() {
        let admin = addr(0xAD);
        let a = addr(1);
        let b = addr(2);
        let mut poa = PoAOnboarding::new();
        poa.add_admin(DOMAIN, admin);

        poa.submit_application(DOMAIN, a, kyc(1), 1).unwrap();
        poa.submit_application(DOMAIN, b, kyc(2), 2).unwrap();
        poa.approve(DOMAIN, admin, a, 3, 500).unwrap();
        poa.reject(DOMAIN, admin, b, 4, "no").unwrap();

        let log = poa.audit_log();
        assert_eq!(log.len(), 4);
        // The block numbers increase monotonically.
        let blocks: Vec<u64> = log.iter().map(|e| e.at_block).collect();
        assert_eq!(blocks, vec![1, 2, 3, 4]);
        // The domain is the same in every event.
        assert!(log.iter().all(|e| e.domain == DOMAIN));
    }

    /// 7. Every onboarding action by an unauthorized (non-admin) caller has to
    ///    return an error AND add nothing to the audit trail.
    #[test]
    fn non_admin_actions_fail_and_leave_no_audit_trace() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let nobody = addr(0x99);
        let mut poa = PoAOnboarding::new();
        poa.add_admin(DOMAIN, admin);
        poa.submit_application(DOMAIN, member, kyc(1), 0).unwrap();

        let baseline = poa.audit_log().len();

        // Nobody approve edemez
        assert!(poa.approve(DOMAIN, nobody, member, 0, 100).is_err());
        assert!(poa.reject(DOMAIN, nobody, member, 0, "x").is_err());
        assert!(poa.revoke(DOMAIN, nobody, member, 0, "y").is_err());

        // No audit event was added.
        assert_eq!(poa.audit_log().len(), baseline);
        // Hâlâ yetkisiz
        assert!(!poa.whitelist(DOMAIN, 0).contains(&member));
    }

    /// 8. The default horizon is finite, so an open-ended approval cannot break
    ///    the re-KYC discipline. We confirm the in-module test once more here.
    #[test]
    fn default_horizon_is_finite_and_positive() {
        const _: () = assert!(DEFAULT_KYC_HORIZON > 0 && DEFAULT_KYC_HORIZON < u64::MAX);
    }
}
