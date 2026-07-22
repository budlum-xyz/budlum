//! Task 11.3 Task 3: Slashing test matrisi.
//!
//! Ayrı ayrı test senaryoları: double-sign, downtime/liveness, invalid
//! attestation. Verifier Registry üstünde, her slashing koşulu için
//! pozitif (slash tetiklenir) ve negatif (honest validator slash'lanmaz).

#[cfg(test)]
mod tests {
    use crate::core::address::Address;
    use crate::registry::evidence::{ProofProvenance, SlashingProof, SlashingReport};
    use crate::registry::params::RegistryParams;
    use crate::registry::permissionless::PermissionlessRegistry;
    use crate::registry::roles;

    fn setup_registry() -> PermissionlessRegistry {
        PermissionlessRegistry::with_params(RegistryParams::default())
    }

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    // ─── Double-Sign Slashing ───

    #[test]
    fn double_sign_slashes_validator_and_jails() {
        let mut reg = setup_registry();
        let val = addr(0x42);

        reg.register(val, roles::VALIDATOR, 10_000, 0)
            .expect("register must succeed");

        let report = SlashingReport::consensus_double_sign(
            val,
            100, // height
            "hash_aaa".to_string(),
            "hash_bbb".to_string(), // different → equivocation
            vec![0xAA; 64],
            vec![0xBB; 64],
            Some(addr(0x01)), // reporter
        );

        let result = reg.slash_from_report(&report);
        assert!(result.is_ok(), "double-sign must trigger slash");

        let slash_result = result.unwrap();
        assert!(slash_result.is_some(), "slash must produce a record");

        assert!(
            !reg.is_active(&val, roles::VALIDATOR),
            "double-signed validator must NOT be active"
        );
        assert_eq!(
            reg.slashing_history().len(),
            1,
            "slashing history must have 1 entry"
        );
    }

    #[test]
    fn honest_validator_not_slashed() {
        let mut reg = setup_registry();
        let honest = addr(0x50);

        reg.register(honest, roles::VALIDATOR, 10_000, 0)
            .expect("register must succeed");

        assert_eq!(
            reg.slashing_history().len(),
            0,
            "honest validator must have empty slashing history"
        );
        assert!(
            reg.is_active(&honest, roles::VALIDATOR),
            "honest validator must remain active"
        );
    }

    // ─── Liveness / Downtime Slashing ───

    #[test]
    fn liveness_fault_processed() {
        let mut reg = setup_registry();
        let val = addr(0x44);

        reg.register(val, roles::VALIDATOR, 10_000, 0)
            .expect("register must succeed");

        let report = SlashingReport::new(
            val,
            roles::VALIDATOR,
            SlashingProof::Liveness {
                window_start_epoch: 0,
                window_end_epoch: 100,
                missed: 50,
                expected: 100,
            },
            ProofProvenance::ConsensusVerified,
            Some(addr(0x01)),
        );

        let result = reg.slash_from_report(&report);
        assert!(result.is_ok(), "liveness fault must be processed");
    }

    // ─── Invalid Signature Spam ───

    #[test]
    fn invalid_signature_spam_processed() {
        let mut reg = setup_registry();
        let val = addr(0x55);

        reg.register(val, roles::VALIDATOR, 10_000, 0)
            .expect("register must succeed");

        let report = SlashingReport::new(
            val,
            roles::VALIDATOR,
            SlashingProof::InvalidSignatureSpam {
                epoch: 42,
                count: 25,
                threshold: 20,
            },
            ProofProvenance::ConsensusVerified,
            Some(addr(0x01)),
        );

        let result = reg.slash_from_report(&report);
        assert!(result.is_ok(), "invalid sig spam must be processed");
    }

    // ─── Unverified Reports ───

    #[test]
    fn unverified_report_does_not_slash() {
        let mut reg = setup_registry();
        let val = addr(0x60);

        reg.register(val, roles::VALIDATOR, 10_000, 0)
            .expect("register must succeed");

        let report = SlashingReport::new(
            val,
            roles::VALIDATOR,
            SlashingProof::DoubleSign {
                height: 100,
                block_hash_1: "aaa".to_string(),
                block_hash_2: "bbb".to_string(),
                signature_1: vec![0xAA; 64],
                signature_2: vec![0xBB; 64],
            },
            ProofProvenance::Unverified,
            Some(addr(0x01)),
        );

        let result = reg.slash_from_report(&report);

        // Unverified → must NOT slash (security).
        // The result may be Ok(None) or Err, but validator must remain active.
        let _ = result;
        assert!(
            reg.is_active(&val, roles::VALIDATOR),
            "unverified report must NOT slash validator"
        );
    }

    // ─── Slashing History ───

    #[test]
    fn slashing_history_accumulates() {
        let mut reg = setup_registry();
        let val1 = addr(0x70);
        let val2 = addr(0x71);

        reg.register(val1, roles::VALIDATOR, 10_000, 0).unwrap();
        reg.register(val2, roles::VALIDATOR, 10_000, 0).unwrap();

        let r1 = SlashingReport::consensus_double_sign(
            val1,
            100,
            "aaa".to_string(),
            "bbb".to_string(),
            vec![0xAA; 64],
            vec![0xBB; 64],
            Some(addr(0x01)),
        );
        let _ = reg.slash_from_report(&r1);

        let r2 = SlashingReport::consensus_double_sign(
            val2,
            200,
            "ccc".to_string(),
            "ddd".to_string(),
            vec![0xCC; 64],
            vec![0xDD; 64],
            Some(addr(0x01)),
        );
        let _ = reg.slash_from_report(&r2);

        assert_eq!(
            reg.slashing_history().len(),
            2,
            "two slash events must produce 2 history entries"
        );
    }

    #[test]
    fn slashing_history_for_specific_validator() {
        let mut reg = setup_registry();
        let val = addr(0x80);

        reg.register(val, roles::VALIDATOR, 10_000, 0).unwrap();

        let report = SlashingReport::consensus_double_sign(
            val,
            100,
            "aaa".to_string(),
            "bbb".to_string(),
            vec![0xAA; 64],
            vec![0xBB; 64],
            Some(addr(0x01)),
        );
        let _ = reg.slash_from_report(&report);

        let history = reg.slashing_history_for(&val);
        assert_eq!(
            history.len(),
            1,
            "slashing history for this validator must have 1 entry"
        );
    }

    // ─── Dedup: Same Evidence Not Slashed Twice ───

    #[test]
    fn same_evidence_not_slashed_twice() {
        let mut reg = setup_registry();
        let val = addr(0x90);

        reg.register(val, roles::VALIDATOR, 10_000, 0).unwrap();

        let report = SlashingReport::consensus_double_sign(
            val,
            100,
            "aaa".to_string(),
            "bbb".to_string(),
            vec![0xAA; 64],
            vec![0xBB; 64],
            Some(addr(0x01)),
        );

        let r1 = reg.slash_from_report(&report);
        assert!(r1.is_ok());

        // Same evidence again → no-op (already jailed).
        let r2 = reg.slash_from_report(&report);
        let _ = r2;

        assert_eq!(
            reg.slashing_history().len(),
            1,
            "same evidence must not produce duplicate slashing entry"
        );
    }
}
