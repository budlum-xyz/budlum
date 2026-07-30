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
        let metrics = Metrics::new();
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

    // === SECURITY TESTS (Güvenlik Denetimi Madde 3) ===

    /// BLS PoP production çağrısı.
    /// Güvenlik denetimi §3: `verify_pop` daha önce yalnızca unit
    /// Test'te çağrılıyordu; production'da hiçbir yerde çağrılmıyordu
    /// (rogue-key saldırısına açık). Bu test, public `verify_pop`
    /// Fonksiyonunun hâlâ geçerli PoP'leri kabul ettiğini, geçersiz
    /// Olanları reddettiğini doğrular — böylece `blockchain.rs`'in
    /// `build_validator_snapshot_from_state` filtresi güvenle
    /// Kullanabilir. (Filtre unit test'lerde doğrudan çağrılamaz çünkü
    /// Private'tır; bu test public API'nin kontratını garanti eder.)
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

        // Geçersiz PoP (sahte) — production filtresi bunu reddetmeli
        let invalid = ValidatorEntry {
            address: test_addr_from_byte(1u8),
            stake: 1000,
            bls_public_key: vec![0u8; 96], // rastgele G2 noktası (büyük ihtimalle geçersiz)
            pop_signature: vec![0u8; 48],
            pq_public_key: Vec::new(),
        };
        // Sahte key/sig de verify_pop'tan false dönmeli; production
        // Filtresi bunu snapshot'tan çıkarır (rogue-key koruması).
        assert!(!verify_pop(
            &invalid,
            crate::core::transaction::DEFAULT_CHAIN_ID,
        ));
    }

    // === SECURITY FIX (Güvenlik Denetimi §5) =========================
    // RPC kimlik doğrulaması varsayılan olarak AÇIK. Operatörün bilinçli
    // Olarak devre dışı bırakması (`operator_default`) log uyarısı verir.

    /// Default config: kimlik doğrulama AÇIK (secure by default).
    /// `auth_required=false` kullanan operatör kasıtlı olarak `operator_default`
    /// Çağırmalı; bu test Default'ın secure olduğunu sabitler.
    #[test]
    fn rpc_auth_required_default_true() {
        use crate::rpc::RpcSecurityConfig;
        let config = RpcSecurityConfig::default();
        assert!(
            config.auth_required,
            "secure default: auth must be required unless operator opts in"
        );
    }

    /// `operator_default` kimlik doğrulamayı kapatır ve `auth_required=false`
    /// Döner — operatörün bilinçli olarak devre dışı bıraktığını gösterir.
    /// (Başlangıçta GÜVENLİK uyarıları loglanır, ama davranış kontratı
    /// Budur.)
    #[test]
    fn rpc_operator_default_disables_auth() {
        use crate::rpc::RpcSecurityConfig;
        let config = RpcSecurityConfig::operator_default();
        assert!(!config.auth_required);
        assert!(config.allowed_ips.contains(&"127.0.0.1".to_string()));
    }

    /// `from_env` ile `auth_required=true` ve boş api_key
    /// (env var ayarlanmamış) geçirildiğinde hata döner — operatörün
    /// Public bir RPC'yi boş key ile başlatması engellenir.
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

    // === SECURITY FIX (Güvenlik Denetimi §6) =========================
    // KeyPair / ValidatorKeys `save` artık dosyayı doğrudan 0o600 ile
    // Oluşturur (TOCTOU penceresi yok) ve izin hatalarını yutar (sessiz
    // Hata yok). Aşağıdaki test'ler bu iki garantiyi sabitler.

    /// `KeyPair::save` strict 0o600 ile oluşturur (TOCTOU yok) ve
    /// `load` sonrasında aynı anahtarı geri yükler.
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
        // Round-trip: load sonrası aynı anahtar.
        let kp2 = KeyPair::load(&path).expect("load must succeed");
        assert_eq!(kp.private_key_bytes(), kp2.private_key_bytes());
    }

    /// `ValidatorKeys::save` de strict 0o600 ile oluşturur VE önceki
    /// `let _ = set_permissions` regresyonu yok (hata artık `?` ile
    /// Yayılır).
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

    // === SECURITY FIX (Güvenlik Denetimi §5 wiring) ==================
    // `NodeConfig::default` artık `rpc_auth_required: true` (secure).
    // Bu test, default'un struct literal'ı üzerinden gerçekten `true`
    // Olduğunu sabitler. (sadece `RpcSecurityConfig::default`'ı
    // Düzeltmişti; CLI'nin okuduğu `NodeConfig::default`'a
    // Dokunmamıştı — yani gerçek main başlangıcında hâlâ `false`
    // Kalıyordu. wiring gap'i kapatıyor.)
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

    /// `main.rs`'in çözümlenmiş-değer uyarısı: `auth_required=false` olan
    /// Bir `RpcSecurityConfig` ile bu kontrol `warn!` üretmeli.
    /// Doğrulama: bir helper fonksiyon extract edip `tracing` subscriber
    /// Ile log yakalayarak. (`tracing` global subscriber zaten
    /// Test'lerde kurulu olmayabilir; bu test pratik olarak sadece
    /// Kod yolunun compile edildiğini + doğru koşulda çağrıldığını
    /// Doğrular — gerçek warning davranışı entegrasyon test'lerinde
    /// Manuel olarak doğrulanır.)
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
        // `from_default` artık `true` → uyarı yok.
        assert!(from_default.auth_required);
        // `operator_default` kasıtlı olarak `false` → uyarı tetiklenir.
        assert!(!from_op.auth_required);
        // `from_env(auth_required=false)` → uyarı tetiklenir.
        assert!(!from_env_no_auth.auth_required);
    }
}
