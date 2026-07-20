//! Hardening Protocol H5–H7 (+ H8 prep) regression locks (ARENA3).
//! Marker: REGRESSION — do not delete without replacing coverage.

#[cfg(test)]
mod tests {
    use crate::chain::snapshot::{
        SnapshotAuthError, SnapshotTrustPolicy, StateSnapshotV2, StateSnapshotV2Params,
        CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION, MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION,
    };
    use crate::core::account::AccountState;
    use crate::core::chain_config::Network;
    use crate::network::protocol::{MessageError, NetworkMessage, MAX_MESSAGE_SIZE};
    use crate::rpc::server::RpcSecurityConfig;
    use ed25519_dalek::SigningKey;
    use std::path::Path;

    /// H5.3: production default requires RPC auth.
    #[test]
    fn h5_3_rpc_auth_required_by_default() {
        let cfg = RpcSecurityConfig::default();
        assert!(
            cfg.auth_required,
            "secure default must require auth (operator_default is explicit opt-out)"
        );
        let op = RpcSecurityConfig::operator_default();
        assert!(!op.auth_required);
        assert!(Network::Mainnet.security_config().rpc_auth_required);
    }

    /// H5.5: oversized network frames rejected before parse work balloons.
    #[test]
    fn h5_5_max_message_size_rejected() {
        let oversized = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let err = NetworkMessage::from_bytes_validated(&oversized).unwrap_err();
        match err {
            MessageError::TooLarge(n) => assert_eq!(n, MAX_MESSAGE_SIZE + 1),
            other => panic!("expected TooLarge, got {other:?}"),
        }
        let tiny = NetworkMessage::from_bytes_validated(&[0u8; 4]);
        if let Err(MessageError::TooLarge(_)) = tiny {
            panic!("tiny frame must not hit size gate");
        }
    }

    /// H5.1 companion: eclipse /24 bound still enforced at PeerManager.
    #[test]
    fn h5_1_eclipse_bound_still_active() {
        use crate::network::peer_manager::PeerManager;
        let mut pm = PeerManager::new();
        assert_eq!(pm.max_peers_per_subnet(), 4);
        let s = [198, 51, 100];
        for _ in 0..4 {
            let peer = libp2p::identity::Keypair::generate_ed25519()
                .public()
                .to_peer_id();
            assert!(pm.can_admit_subnet(Some(s)));
            pm.note_connected(peer, Some(s));
        }
        assert!(!pm.can_admit_subnet(Some(s)));
    }

    /// H5.6: multinode smoke script + workflow wired (structural).
    #[test]
    fn h5_6_multinode_smoke_artifacts_present() {
        assert!(Path::new("scripts/devnet-multinode-smoke.sh").is_file());
        let wf = include_str!("../../.github/workflows/docker-smoke.yml");
        assert!(
            wf.contains("devnet-multinode-smoke") && wf.contains("devnet-multinode-smoke.sh"),
            "docker-smoke must run 4-node multinode job"
        );
    }

    fn sample_snapshot() -> StateSnapshotV2 {
        let st = AccountState::new();
        StateSnapshotV2::from_state(
            &st,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "b".into(),
                genesis_hash: "g".into(),
                chain_id: 1337,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        )
    }

    /// H6.3 GAP-1: RequireSigned fails closed without signature.
    #[test]
    fn h6_3_require_signed_fails_without_signature() {
        let mut snap = sample_snapshot();
        snap.trust_policy = SnapshotTrustPolicy::RequireSigned;
        // from_state already filled snapshot_hash via private calculate_hash.
        let err = snap.verify_authentic(None).unwrap_err();
        assert!(
            matches!(
                err,
                SnapshotAuthError::MissingSigner | SnapshotAuthError::MissingSignature
            ),
            "got {err:?}"
        );
    }

    /// H6.3: signed manifest verifies under trust list; wrong key rejected.
    #[test]
    fn h6_3_signed_manifest_verifies_and_rejects_untrusted() {
        let mut snap = sample_snapshot();
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let vk = ed25519_dalek::VerifyingKey::from(&signing_key);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(vk.as_bytes());
        snap.sign_manifest(&signing_key, pk);
        // verify_authentic uses calculate_digest() for sig; snapshot_hash from from_state.
        assert!(snap.verify_authentic(Some(&[pk])).is_ok());
        assert_eq!(
            snap.verify_authentic(Some(&[[99u8; 32]])).unwrap_err(),
            SnapshotAuthError::SignerNotTrusted
        );
    }

    /// H6.4: migration_report rejects ancient / future schemas; accepts current.
    #[test]
    fn h6_4_migration_report_bounds() {
        let mut snap = sample_snapshot();
        assert_eq!(snap.schema_version, CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION);
        assert!(snap.migration_report().is_ok());

        snap.schema_version = MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION.saturating_sub(1);
        assert!(snap.migration_report().is_err());

        snap.schema_version = CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION + 10;
        assert!(snap.migration_report().is_err());
    }

    /// H6.1: genesis determinism workflow present.
    #[test]
    fn h6_1_determinism_workflow_present() {
        let wf = include_str!("../../.github/workflows/determinism.yml");
        assert!(
            wf.contains("Genesis") || wf.contains("genesis") || wf.contains("determinism"),
            "determinism workflow must exist for H6.1"
        );
        assert!(Path::new("config/mainnet-genesis.json").is_file());
        assert!(Path::new("docs/operations/GENESIS_FLIP_CHECKLIST.md").is_file());
    }

    /// H7.1–H7.3: supply-chain gate files present.
    #[test]
    fn h7_supply_chain_gate_files_present() {
        assert!(Path::new("deny.toml").is_file());
        assert!(Path::new(".gitleaks.toml").is_file());
        assert!(Path::new(".github/coverage-baseline.txt").is_file());
        let ci = include_str!("../../.github/workflows/ci.yml");
        assert!(ci.contains("gitleaks") || ci.contains("secret-scan"));
        assert!(ci.contains("deny") || ci.contains("cargo-deny") || ci.contains("Cargo Deny"));
        assert!(ci.contains("coverage") || ci.contains("llvm-cov"));
    }

    /// H7.5: coverage baseline is a finite ratchet value.
    #[test]
    fn h7_5_coverage_baseline_is_numeric_ratchet() {
        let raw = include_str!("../../.github/coverage-baseline.txt").trim();
        let v: f64 = raw.parse().expect("baseline must parse as f64");
        assert!((50.0..=100.0).contains(&v), "baseline out of range: {v}");
    }

    /// H8 prep: SECURITY.md links bounty; runbook + audit checklist exist.
    #[test]
    fn h8_ops_and_bounty_docs_present() {
        let sec = include_str!("../../SECURITY.md");
        assert!(
            sec.contains("BUG_BOUNTY") || sec.contains("bug bounty") || sec.contains("Bug Bounty"),
            "SECURITY.md must reference bounty program"
        );
        assert!(Path::new("docs/BUG_BOUNTY.md").is_file());
        assert!(Path::new("docs/operations/PRODUCTION_RUNBOOK.md").is_file());
        assert!(Path::new("docs/AUDIT_CHECKLIST.md").is_file());
        assert!(Path::new("docs/operations/VALIDATOR_ONBOARDING.md").is_file());
    }
}
