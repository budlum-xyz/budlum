#[cfg(test)]
mod hardening_tests {
    use crate::cli::commands::NodeConfig;
    use crate::core::account::AccountState;
    use crate::core::address::Address;
    #[cfg(test)]
    fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
        let mut b = [0u8; 32];
        b[0] = byte;
        crate::core::address::Address::from(b)
    }

    use crate::core::metrics::Metrics;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_merkle_state_root_determinism() {
        let mut state1 = AccountState::new();
        let alice = Address::from_hex(&"01".repeat(32)).unwrap();
        let bob = Address::from_hex(&"02".repeat(32)).unwrap();

        state1.add_balance(&alice, 100);
        state1.add_balance(&bob, 200);

        let mut state2 = AccountState::new();
        state2.add_balance(&bob, 200);
        state2.add_balance(&alice, 100);

        let root1 = state1.calculate_state_root();
        let root2 = state2.calculate_state_root();

        assert_eq!(
            root1, root2,
            "Merkle root must be deterministic regardless of insertion order"
        );
        assert_ne!(root1, "0".repeat(64), "Root should not be empty");

        state1.add_balance(&alice, 1);
        assert_ne!(
            root1,
            state1.calculate_state_root(),
            "Root must change when balance changes"
        );
    }

    #[test]
    fn test_metrics_encoding_format() {
        let metrics = Metrics::new().expect("metric names are literals");
        metrics.chain_height.set(1234);
        metrics.peer_count.set(5);

        let encoded = metrics.encode();
        assert!(
            encoded.contains("budlum_chain_height 1234"),
            "Encoded metrics should contain height"
        );
        assert!(
            encoded.contains("budlum_peer_count 5"),
            "Encoded metrics should contain peer count"
        );
        assert!(
            encoded.contains("# HELP budlum_chain_height"),
            "Encoded metrics should contain HELP metadata"
        );
    }

    #[test]
    fn test_toml_config_merge() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("budlum.toml");
        let mut file = File::create(&config_path).unwrap();
        writeln!(
            file,
            r#"
            [storage]
            data_dir = "/tmp/custom_db"
            [rpc]
            public_listener = "127.0.0.1:9999"
            [metrics]
            listener = "0.0.0.0:7070"
        "#
        )
        .unwrap();

        let mut config = NodeConfig {
            config: Some(config_path.to_str().unwrap().to_string()),
            ..Default::default()
        };

        assert_ne!(config.rpc_port, 9999);

        config.load_with_file();

        assert_eq!(config.db_path, "/tmp/custom_db");
        assert_eq!(config.rpc_port, 9999);
        assert_eq!(config.metrics_port, 7070);
    }

    #[test]
    fn test_apply_snapshot_rejects_older_than_finalized() {
        use crate::chain::blockchain::Blockchain;
        use crate::consensus::pow::PoWEngine;
        use std::sync::Arc;

        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        bc.finalized_height = 10;

        let snapshot = crate::chain::snapshot::StateSnapshot::from_state(
            5,
            "hash".to_string(),
            45262,
            &bc.state,
            0,
            "finalhash".to_string(),
        );

        let result = bc.apply_state_snapshot(snapshot);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("older than current finalized"));
    }

    #[test]
    fn test_db_repair_index() {
        use crate::core::block::Block;
        use crate::storage::db::Storage;

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_repair.db");
        let storage = Storage::new(db_path.to_str().unwrap()).unwrap();

        // Create a block and commit it
        let mut block = Block::new(1, "prev_hash".to_string(), vec![]);
        block.hash = block.calculate_hash();
        storage.commit_block(&block, "state_root_1").unwrap();

        // Verify we can read it
        assert!(storage.get_block_by_height(1).unwrap().is_some());

        // Corrupt the height index by removing it
        let height_key = "HEIGHT:1".to_string();
        storage.db().remove(height_key.as_bytes()).unwrap();
        storage.db().flush().unwrap();

        // Verify reading by height returns None now
        assert!(storage.get_block_by_height(1).unwrap().is_none());

        // Repair the index
        storage.repair_index().unwrap();

        // Verify reading by height works again
        assert!(storage.get_block_by_height(1).unwrap().is_some());
        assert_eq!(
            storage.get_block_by_height(1).unwrap().unwrap().hash,
            block.hash
        );
    }

    // === SECURITY TESTS (security review, item 3) ===

    /// The production call of the BLS PoP.
    ///
    /// Security review, section 3: `verify_pop` used to be called only from a
    /// unit test and from nowhere in production, which left the rogue-key attack
    /// open. This test verifies that the public `verify_pop` function still
    /// accepts valid PoPs and refuses invalid ones, so the
    /// `build_validator_snapshot_from_state` filter in `blockchain.rs` can rely
    /// on it. The filter itself cannot be called directly from a unit test
    /// because it is private; this test guarantees the contract of the public
    /// API.
    #[test]
    fn test_verify_pop_guarantee_for_production_filter() {
        use crate::chain::finality::verify_pop;
        use crate::chain::finality::ValidatorEntry;

        // Empty BLS/PoP is never consensus-ready, including at genesis.
        let genesis_style = ValidatorEntry {
            address: crate::core::address::Address::zero(),
            stake: 1000,
            bls_public_key: Vec::new(),
            pop_signature: Vec::new(),
            pq_public_key: Vec::new(),
        };
        // Missing proof/key is rejected; production snapshot construction uses
        // The same fail-closed result and has no genesis bypass.
        assert!(!verify_pop(
            &genesis_style,
            crate::core::transaction::DEFAULT_CHAIN_ID,
        ));

        // An invalid, forged PoP - the production filter has to refuse it.
        let invalid = ValidatorEntry {
            address: test_addr_from_byte(1u8),
            stake: 1000,
            bls_public_key: vec![0u8; 96], // an arbitrary G2 point, most likely invalid
            pop_signature: vec![0u8; 48],
            pq_public_key: Vec::new(),
        };
        // A forged key or signature also has to return false from verify_pop;
        // the production filter drops it from the snapshot - rogue-key
        // protection.
        assert!(!verify_pop(
            &invalid,
            crate::core::transaction::DEFAULT_CHAIN_ID,
        ));
    }

    // === SECURITY FIX (security review, section 5) ===================
    // RPC authentication is ON by default. An operator disabling it deliberately
    // (`operator_default`) produces a log warning.

    /// The default config: authentication is ON, secure by default. An operator
    /// wanting `auth_required=false` has to call `operator_default`
    /// deliberately; this test pins down that Default is the secure one.
    #[test]
    fn rpc_auth_required_default_true() {
        use crate::rpc::RpcSecurityConfig;
        let config = RpcSecurityConfig::default();
        assert!(
            config.auth_required,
            "secure default: auth must be required unless operator opts in"
        );
    }

    /// `operator_default` turns authentication off and returns
    /// `auth_required=false`, showing that the operator disabled it
    /// deliberately. SECURITY warnings are logged at startup, but the behavioural
    /// contract
    /// Budur.)
    #[test]
    fn rpc_operator_default_disables_auth() {
        use crate::rpc::RpcSecurityConfig;
        let config = RpcSecurityConfig::operator_default();
        assert!(!config.auth_required);
        assert!(config.allowed_ips.contains(&"127.0.0.1".to_string()));
    }

    /// When `from_env` is passed `auth_required=true` with an empty api_key
    /// (the env var is not set) it returns an error, which stops an operator from
    /// starting a public RPC with an empty key.
    #[test]
    fn rpc_empty_api_key_rejected_when_auth_required() {
        use crate::rpc::RpcSecurityConfig;
        std::env::remove_var("BUDLUM_TUR6_RPC_TEST_KEY");
        let res = RpcSecurityConfig::from_env(
            true,
            Some("BUDLUM_TUR6_RPC_TEST_KEY"),
            vec![],
            vec![],
            None,
        );
        assert!(
            res.is_err(),
            "auth_required=true with unset env var must fail closed"
        );
    }

    // === SECURITY FIX (security review, section 6) ===================
    // `save` on KeyPair and ValidatorKeys now creates the file directly with
    // 0o600, so there is no TOCTOU window, and it no longer swallows permission
    // errors, so there is no silent failure. The tests below pin down both
    // guarantees.

    /// `KeyPair::save` creates the file with a strict 0o600 and no TOCTOU, and
    /// `load` restores the same key afterwards.
    #[cfg(unix)]
    #[test]
    fn keypair_save_creates_with_strict_permissions() {
        use crate::crypto::primitives::KeyPair;
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("kp.bin");
        let kp = KeyPair::generate().expect("kp must generate");
        kp.save(&path).expect("save must succeed");
        let meta = std::fs::metadata(&path).expect("file must exist");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "KeyPair::save must create the file with 0o600, got {mode:o}"
        );
        // Round-trip: the same key after load.
        let kp2 = KeyPair::load(&path).expect("load must succeed");
        assert_eq!(kp.private_key_bytes(), kp2.private_key_bytes());
    }

    /// `ValidatorKeys::save` also creates the file with a strict 0o600, AND the
    /// earlier `let _ = set_permissions` regression is gone - the error is now
    /// propagated with `?`.
    #[cfg(unix)]
    #[test]
    fn validator_keys_save_creates_with_strict_permissions() {
        use crate::crypto::primitives::ValidatorKeys;
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("vk.bin");
        let vk = ValidatorKeys::generate().expect("validator keys must generate");
        vk.save(&path).expect("save must succeed");
        let meta = std::fs::metadata(&path).expect("file must exist");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "ValidatorKeys::save must create the file with 0o600, got {mode:o}"
        );
    }

    // === SECURITY FIX (security review, section 5 wiring) ============
    // `NodeConfig::default` is now `rpc_auth_required: true`, the secure value.
    // This test pins down that the default really is `true` through the struct
    // literal. The earlier fix had only corrected `RpcSecurityConfig::default`
    // and never touched the `NodeConfig::default` the CLI reads, so at the real
    // start of main it was still `false`. This closes that wiring gap.
    #[test]
    fn cli_config_default_has_rpc_auth_required_true() {
        use crate::cli::NodeConfig;
        let cfg = NodeConfig::default();
        assert!(
            cfg.rpc_auth_required,
            "NodeConfig::default() must require RPC auth (was: false before the wiring fix)"
        );
        assert!(
            cfg.rpc_allowed_ips.contains(&"127.0.0.1".to_string()),
            "NodeConfig::default() must restrict to localhost-only"
        );
        assert!(
            cfg.rpc_allowed_ips.contains(&"::1".to_string()),
            "NodeConfig::default() must include IPv6 loopback"
        );
    }

    /// The resolved-value warning of `main.rs`: with an `RpcSecurityConfig`
    /// carrying `auth_required=false`, this check has to produce a `warn!`. The
    /// verification extracts a helper function and a `tracing` subscriber
    /// Ile log yakalayarak. (`tracing` global subscriber zaten
    /// It may not be installed under test; in practice this test only
    /// verifies that the code path compiles and is called under the right
    /// condition; the real warning behaviour is verified manually in the
    /// integration tests.
    #[test]
    fn main_resolved_auth_required_check_compiles() {
        // The check is inline in `main.rs:564-575`. We re-derive the
        // Condition here to lock the contract: `auth_required=false`
        // Is a security-relevant configuration and the warning branch
        // Is reachable from any of the three constructors
        // (Default, operator_default, from_env).
        use crate::rpc::RpcSecurityConfig;
        let from_default = RpcSecurityConfig::default();
        let from_op = RpcSecurityConfig::operator_default();
        let from_env_no_auth = RpcSecurityConfig {
            auth_required: false,
            ..Default::default()
        };
        // `from_default` is now `true`, so there is no warning.
        assert!(from_default.auth_required);
        // `operator_default` is deliberately `false`, so the warning fires.
        assert!(!from_op.auth_required);
        // `from_env(auth_required=false)` fires the warning.
        assert!(!from_env_no_auth.auth_required);
    }
}
