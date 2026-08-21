//! Hardening Protocol H5 to H7 (+ H8 prep) regression locks.
//! Marker: REGRESSION - do not delete without replacing coverage.

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

    /// Production default requires RPC auth.
    #[test]
    fn rpc_auth_required_by_default() {
        let cfg = RpcSecurityConfig::default();
        assert!(
            cfg.auth_required,
            "secure default must require auth (operator_default is explicit opt-out)"
        );
        let op = RpcSecurityConfig::operator_default();
        assert!(!op.auth_required);
        assert!(Network::Mainnet.security_config().rpc_auth_required);
    }

    /// Oversized network frames rejected before parse work balloons.
    #[test]
    fn max_message_size_rejected() {
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

    /// Eclipse /24 bound still enforced at PeerManager.
    #[test]
    fn eclipse_bound_still_active() {
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

    /// Multinode smoke script + workflow wired (structural).
    #[test]
    fn multinode_smoke_artifacts_present() {
        assert!(Path::new("ops/scripts/devnet-multinode-smoke.sh").is_file());
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
                chain_id: 45262,
                finalized_height: 0,
                finalized_hash: "f".into(),
                finality_certificates: vec![],
            },
        )
    }

    /// H6.3: RequireSigned fails closed without signature.
    #[test]
    fn require_signed_fails_without_signature() {
        let mut snap = sample_snapshot();
        snap.trust_policy = SnapshotTrustPolicy::RequireSigned;
        // trust_policy is hashed into the digest, so from_state's hash is
        // stale the moment the policy moves. Re-sign the manifest with a
        // throwaway key would also work; here the point is the missing
        // signature, so the fixture is made consistent instead.
        snap.reseal_after_manual_edit();
        let err = snap.verify_authentic(None).unwrap_err();
        assert!(
            matches!(
                err,
                SnapshotAuthError::MissingSigner | SnapshotAuthError::MissingSignature
            ),
            "got {err:?}"
        );
    }

    /// Signed manifest verifies under trust list; wrong key rejected.
    #[test]
    fn signed_manifest_verifies_and_rejects_untrusted() {
        let mut snap = sample_snapshot();
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let vk = ed25519_dalek::VerifyingKey::from(&signing_key);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(vk.as_bytes());
        snap.sign_manifest(&signing_key, pk);
        // Verify_authentic uses calculate_digest for sig; snapshot_hash from from_state.
        assert!(snap.verify_authentic(Some(&[pk])).is_ok());
        assert_eq!(
            snap.verify_authentic(Some(&[[99u8; 32]])).unwrap_err(),
            SnapshotAuthError::SignerNotTrusted
        );
    }

    /// Migration_report rejects ancient / future schemas; accepts current.
    #[test]
    fn migration_report_bounds() {
        let mut snap = sample_snapshot();
        assert_eq!(snap.schema_version, CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION);
        assert!(snap.migration_report().is_ok());

        snap.schema_version = MIN_SUPPORTED_STATE_SNAPSHOT_SCHEMA_VERSION.saturating_sub(1);
        assert!(snap.migration_report().is_err());

        snap.schema_version = CURRENT_STATE_SNAPSHOT_SCHEMA_VERSION + 10;
        assert!(snap.migration_report().is_err());
    }

    /// Genesis determinism workflow present.
    #[test]
    fn determinism_workflow_present() {
        let wf = include_str!("../../.github/workflows/determinism.yml");
        assert!(
            wf.contains("Genesis") || wf.contains("genesis") || wf.contains("determinism"),
            "determinism workflow must exist for H6.1"
        );
        assert!(Path::new("config/mainnet-genesis.json").is_file());
    }

    /// Supply-chain policies exist *and* CI still points at them.
    ///
    /// The paths matter as a pair: a policy file that no workflow names is
    /// decoration, and a workflow flag pointing at a missing file fails only
    /// at runtime. Both directions are checked so moving a config without
    /// updating its caller (or the reverse) fails here instead of silently
    /// disabling a gate.
    #[test]
    fn supply_chain_policies_are_wired_into_ci() {
        for path in [
            ".quality/deny.toml",
            ".quality/typos.toml",
            ".quality/grype.yaml",
            ".quality/osv-scanner.toml",
            ".gitleaks.toml",
            ".github/coverage-baseline.txt",
        ] {
            assert!(Path::new(path).is_file(), "missing policy file: {path}");
        }

        let ci = include_str!("../../.github/workflows/ci.yml");
        assert!(
            ci.contains(".gitleaks.toml"),
            "CI must name the gitleaks config"
        );
        assert!(
            ci.contains(".quality/deny.toml"),
            "CI must name the relocated cargo-deny config"
        );
        assert!(ci.contains("coverage") || ci.contains("llvm-cov"));

        // Each scanner workflow has to pass its own relocated config; without
        // the flag the tool would silently fall back to built-in defaults and
        // every reasoned exception in these files would stop applying.
        for (wf, cfg) in [
            (
                include_str!("../../.github/workflows/typos.yml"),
                ".quality/typos.toml",
            ),
            (
                include_str!("../../.github/workflows/grype.yml"),
                ".quality/grype.yaml",
            ),
            (
                include_str!("../../.github/workflows/osv-scanner.yml"),
                ".quality/osv-scanner.toml",
            ),
        ] {
            assert!(
                wf.contains(&format!("--config {cfg}")) || wf.contains(&format!("--config={cfg}")),
                "workflow does not pass {cfg} explicitly"
            );
        }
    }

    /// Coverage baseline is a finite ratchet value.
    #[test]
    fn coverage_baseline_is_numeric_ratchet() {
        let raw = include_str!("../../.github/coverage-baseline.txt").trim();
        let v: f64 = raw.parse().expect("baseline must parse as f64");
        assert!((50.0..=100.0).contains(&v), "baseline out of range: {v}");
    }

    /// SECURITY.md tells a reporter where to send a vulnerability.
    ///
    /// This is the one document with an operational contract: if it stops
    /// Naming a disclosure route, reports go nowhere.
    #[test]
    fn security_policy_states_a_disclosure_route() {
        let sec = include_str!("../../docs/SECURITY.md");
        let lower = sec.to_lowercase();
        assert!(
            lower.contains("security@") || lower.contains("advisor") || lower.contains("report"),
            "SECURITY.md must state how to report a vulnerability"
        );
    }
}
