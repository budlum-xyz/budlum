//! PoA katılımcı onboarding test matrisi — Phase 11.3 Görev 4.
//!
//! [`crate::registry::poa_onboarding::PoaOnboarding`] modülünün tam yaşam
//! döngüsünü, whitelist zorunluluğunu, KYC son kullanma (expiry) davranışını
//! ve karar denetim (audit) izini kapsar.
//!
//! Bu testler `cargo test --lib poa_isolation` kapısının parçası DEĞİLDİR
//! (adları `poa_isolation` içermiyor); genel lib test takımında çalışır.
//! İzolasyon "mührü" `src/tests/poa_isolation.rs` içindeki 8. teste eklenmiştir.

#[cfg(test)]
mod poa_onboarding_matrix {
    use crate::core::address::Address;
    use crate::registry::poa_onboarding::{OnboardingDecision, PoAOnboarding, DEFAULT_KYC_HORIZON};

    const DOMAIN: u32 = 3;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn kyc(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Mutlak yardım: bir admin + tek üyelik onayı kurulmuş onboarding döndürür.
    fn onboarded(admin: Address, member: Address, horizon: u64) -> PoAOnboarding {
        let mut poa = PoAOnboarding::new();
        poa.add_admin(DOMAIN, admin);
        poa.submit_application(DOMAIN, member, kyc(1), 0).unwrap();
        poa.approve(DOMAIN, admin, member, 0, horizon).unwrap();
        poa
    }

    /// 1. Tam yaşam döngüsü: başvuru (yetki YOK) → onay (whitelist'te) → iptal
    ///    (whitelist'ten düştü). Karar audit izi 3 olay içerir.
    #[test]
    fn full_onboarding_lifecycle_and_audit() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let mut poa = PoAOnboarding::new();
        poa.add_admin(DOMAIN, admin);

        // Başvuru: henüz yetkili değil
        poa.submit_application(DOMAIN, member, kyc(1), 10).unwrap();
        assert!(!poa.whitelist(DOMAIN, 10).contains(&member));

        // Onay: whitelist'e girdi
        poa.approve(DOMAIN, admin, member, 20, 1_000).unwrap();
        assert!(poa.whitelist(DOMAIN, 20).contains(&member));

        // İptal: whitelist'ten çıktı
        poa.revoke(DOMAIN, admin, member, 30, "offboarding")
            .unwrap();
        assert!(!poa.whitelist(DOMAIN, 30).contains(&member));

        // Audit izi: Submitted + Approved + Revoked (sıralı)
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
        assert_eq!(log[0].actor, member); // başvuruyu yapan aday
        assert_eq!(log[1].actor, admin);
        assert_eq!(log[2].actor, admin);
    }

    /// 2. Whitelist yalnızca Approved üyeleri içerir; Pending/Rejected/Revoked
    ///    hariç tutulur.
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

    /// 3. KYC son kullanma: horizon geçince üye whitelist'ten düşer ve audit
    ///    izine bir kez KycExpired olayı eklenir.
    #[test]
    fn kyc_expiry_drops_member_from_whitelist() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let mut poa = onboarded(admin, member, 100);

        // horizon=100 → blok 100'de hâlâ yetkili (now_block > expiry reddeder)
        assert!(poa.whitelist(DOMAIN, 100).contains(&member));
        // blok 101'de süresi doldu → düştü
        assert!(!poa.whitelist(DOMAIN, 101).contains(&member));

        // Expiry audit izine bir kez işlendi
        let expired_count = poa
            .audit_log()
            .iter()
            .filter(|e| matches!(e.decision, OnboardingDecision::KycExpired { .. }))
            .count();
        assert_eq!(expired_count, 1, "expiry should be logged exactly once");

        // Alt katman registry durumu hâlâ Approved (idari durum değişmedi)
        assert!(poa.registry().is_authorized(DOMAIN, &member));
    }

    /// 4. Süre dolduktan sonra KYC yenileme whitelist'e geri koyar.
    #[test]
    fn renew_kyc_restores_membership() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let mut poa = onboarded(admin, member, 100);

        assert!(poa.whitelist(DOMAIN, 100).contains(&member));
        assert!(!poa.whitelist(DOMAIN, 101).contains(&member));

        // Yeniden KYC → yeni horizon
        poa.renew_kyc(DOMAIN, admin, member, kyc(2), 200, 100)
            .unwrap();
        assert!(poa.whitelist(DOMAIN, 250).contains(&member));
        assert!(!poa.whitelist(DOMAIN, 301).contains(&member));

        // RenewedKyc audit olayı var
        let renewed = poa
            .audit_log()
            .iter()
            .any(|e| matches!(e.decision, OnboardingDecision::RenewedKyc { .. }));
        assert!(renewed);
    }

    /// 5. Konsensus-tarzı zorunluluk kapısı: contains() yanlışsa işlem reddedilir.
    #[test]
    fn whitelist_enforcement_gate_rejects_unauthorized() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let impostor = addr(0xCC);
        let mut poa = onboarded(admin, member, 1_000);

        let wl = poa.whitelist(DOMAIN, 5);

        // Kapı: whiteliste üye işlem yapabilir, izinsiz olamaz
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

    /// 6. Audit izi ekle-only ve blok sıralı; her olay kendi alanlarını taşır.
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
        // Blok numaraları monotop artan
        let blocks: Vec<u64> = log.iter().map(|e| e.at_block).collect();
        assert_eq!(blocks, vec![1, 2, 3, 4]);
        // Alan/domain her olayda aynı
        assert!(log.iter().all(|e| e.domain == DOMAIN));
    }

    /// 7. Yetkisiz (admin olmayan) bir çağrı yapan tüm onboarding eylemleri
    ///    hata döndürmeli VE audit izine hiçbir şey eklememeli.
    #[test]
    fn non_admin_actions_fail_and_leave_no_audit_trace() {
        let admin = addr(0xAD);
        let member = addr(0xAA);
        let nobody = addr(0x99);
        let mut poa = PoaOnboarding::new();
        poa.add_admin(DOMAIN, admin);
        poa.submit_application(DOMAIN, member, kyc(1), 0).unwrap();

        let baseline = poa.audit_log().len();

        // nobody approve edemez
        assert!(poa.approve(DOMAIN, nobody, member, 0, 100).is_err());
        assert!(poa.reject(DOMAIN, nobody, member, 0, "x").is_err());
        assert!(poa.revoke(DOMAIN, nobody, member, 0, "y").is_err());

        // Hiçbir audit olayı eklenmedi
        assert_eq!(poa.audit_log().len(), baseline);
        // Hâlâ yetkisiz
        assert!(!poa.whitelist(DOMAIN, 0).contains(&member));
    }

    /// 8. Varsayılan horizon sonludur — açık-sonlu onay re-KYC disiplinini
    ///    bozmaz (modül içi testi burada bir kez daha teyit ediyoruz).
    #[test]
    fn default_horizon_is_finite_and_positive() {
        assert!(DEFAULT_KYC_HORIZON > 0 && DEFAULT_KYC_HORIZON < u64::MAX);
    }
}
