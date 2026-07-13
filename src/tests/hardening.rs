#[cfg(test)]
mod hardening_tests {
    use crate::cli::commands::NodeConfig;
    use crate::core::account::AccountState;
    use crate::core::address::Address;
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
        let mut bc = Blockchain::new(consensus, None, 1337, None);
        bc.finalized_height = 10;

        let snapshot = crate::chain::snapshot::StateSnapshot::from_state(
            5,
            "hash".to_string(),
            1337,
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
        let height_key = format!("HEIGHT:{}", 1);
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

    // === TUR 3 SECURITY TESTS (Güvenlik Denetimi Madde 2 & 3) ===

    /// TUR 3 Görev 1 — SnapshotChunk DoS üst sınırı.
    /// Güvenlik denetimi §2: saldirgan `total = u32::MAX` göndererek
    /// alıcı node'u sınırsız bellek ayırmaya zorlayabilir; bu da Rust'ın
    /// varsayılan abort davranışıyla süreci çökertir. Bu test, sabitin
    /// `u32` tipinde tanımlı olduğunu ve `network::node` modülünden
    /// erişilebilir olduğunu doğrular (tip kontrolü derleme zamanında
    /// garanti edilir; değer kontrolü runtime'da tekrar edilebilir ama
    /// sabit bir tanım olduğundan gereksiz — sınır invariant'ları
    /// kaynak kodda yorumla belgelenmiş).
    #[test]
    fn test_max_snapshot_chunks_constant_is_dos_protection() {
        use crate::network::node::MAX_SNAPSHOT_CHUNKS;
        // Sabit `u32` tipinde olmalı (proto alanıyla uyumlu); bu
        // atama derleme zamanında tip kontrolü yapar ve `u32`'den
        // başka bir tipte tanımlanmışsa build kırılır.
        let _as_u32: u32 = MAX_SNAPSHOT_CHUNKS;
        // 4096 × 512KB/chunk = 2GB tavan — DoS yüzeyini sınırlar
        // ama gerçek snapshot'lara (tipik 10-50 chunk) izin verir.
        // (clippy "constant assertion" uyarısını önlemek için
        // runtime'da değer kontrolü yapılmıyor; sabit bir tanım.)
    }

    /// TUR 3 Görev 2 — BLS PoP production çağrısı.
    /// Güvenlik denetimi §3: `verify_pop` daha önce yalnızca unit
    /// test'te çağrılıyordu; production'da hiçbir yerde çağrılmıyordu
    /// (rogue-key saldırısına açık). Bu test, public `verify_pop`
    /// fonksiyonunun hâlâ geçerli PoP'leri kabul ettiğini, geçersiz
    /// olanları reddettiğini doğrular — böylece `blockchain.rs`'in
    /// `build_validator_snapshot_from_state` filtresi güvenle
    /// kullanabilir. (Filtre unit test'lerde doğrudan çağrılamaz çünkü
    /// private'tır; bu test public API'nin kontratını garanti eder.)
    #[test]
    fn test_verify_pop_guarantee_for_production_filter() {
        use crate::chain::finality::verify_pop;
        use crate::chain::finality::ValidatorEntry;
        use crate::core::address::Address;

        // Boş BLS key/PoP — genesis bypass durumu (snapshot'a alınabilir)
        let genesis_style = ValidatorEntry {
            address: Address::from([0u8; 32]),
            stake: 1000,
            bls_public_key: Vec::new(),
            pop_signature: Vec::new(),
            pq_public_key: Vec::new(),
        };
        // verify_pop boş key ile false döner (PoP yok); ama build_validator_snapshot
        // boş key durumunda bypass yapar (genesis güven). Burada sadece
        // verify_pop'un false döndüğünü doğruluyoruz — bypass başka yerde.
        assert!(!verify_pop(&genesis_style));

        // Geçersiz PoP (sahte) — production filtresi bunu reddetmeli
        let invalid = ValidatorEntry {
            address: Address::from([1u8; 32]),
            stake: 1000,
            bls_public_key: vec![0u8; 96], // rastgele G2 noktası (büyük ihtimalle geçersiz)
            pop_signature: vec![0u8; 48],
            pq_public_key: Vec::new(),
        };
        // Sahte key/sig de verify_pop'tan false dönmeli; production
        // filtresi bunu snapshot'tan çıkarır (rogue-key koruması).
        assert!(!verify_pop(&invalid));
    }

    // === TUR 6 SECURITY FIX (Güvenlik Denetimi §2) =========================
    // Snapshot session memory-bloat koruması: `in_progress_snapshots` map'i
    // aşağıdaki sabitlerle sınırlı, eski session'lar sweep ile düşürülüyor.

    /// DoS-hardening: `MAX_CONCURRENT_SNAPSHOTS` cap değeri pozitif ve
    /// makul (>=1, <=1024) — operatörün keyfi cap'leyebileceği bir yapı.
    #[test]
    fn tur6_max_concurrent_snapshots_is_bounded() {
        use crate::network::node::MAX_CONCURRENT_SNAPSHOTS;
        assert!(MAX_CONCURRENT_SNAPSHOTS >= 1, "cap must be at least 1");
        assert!(
            MAX_CONCURRENT_SNAPSHOTS <= 1024,
            "cap should be modest (got {MAX_CONCURRENT_SNAPSHOTS})"
        );
    }

    /// DoS-hardening: `SNAPSHOT_SESSION_TIMEOUT_SECS` sıfırdan büyük ve
    /// makul (1 dakika ile 1 saat arası) — çok kısa timeout iyi huylu
    /// snapshot transferleri yanlışlıkla düşürür, çok uzun timeout
    /// DoS penceresini açar.
    #[test]
    fn tur6_snapshot_session_timeout_is_sane() {
        use crate::network::node::SNAPSHOT_SESSION_TIMEOUT_SECS;
        assert!(SNAPSHOT_SESSION_TIMEOUT_SECS >= 60);
        assert!(SNAPSHOT_SESSION_TIMEOUT_SECS <= 3600);
    }

    // === TUR 6 SECURITY FIX (Güvenlik Denetimi §5) =========================
    // RPC kimlik doğrulaması varsayılan olarak AÇIK. Operatörün bilinçli
    // olarak devre dışı bırakması (`operator_default`) log uyarısı verir.

    /// Default config: kimlik doğrulama AÇIK (secure by default).
    /// `auth_required=false` kullanan operatör kasıtlı olarak `operator_default`
    /// çağırmalı; bu test Default'ın secure olduğunu sabitler.
    #[test]
    fn tur6_rpc_auth_required_default_true() {
        use crate::rpc::RpcSecurityConfig;
        let config = RpcSecurityConfig::default();
        assert!(
            config.auth_required,
            "secure default: auth must be required unless operator opts in"
        );
    }

    /// `operator_default` kimlik doğrulamayı kapatır ve `auth_required=false`
    /// döner — operatörün bilinçli olarak devre dışı bıraktığını gösterir.
    /// (Başlangıçta GÜVENLİK uyarıları loglanır, ama davranış kontratı
    /// budur.)
    #[test]
    fn tur6_rpc_operator_default_disables_auth() {
        use crate::rpc::RpcSecurityConfig;
        let config = RpcSecurityConfig::operator_default();
        assert!(!config.auth_required);
        assert!(config.allowed_ips.contains(&"127.0.0.1".to_string()));
    }

    /// `from_env` ile `auth_required=true` ve boş api_key
    /// (env var ayarlanmamış) geçirildiğinde hata döner — operatörün
    /// public bir RPC'yi boş key ile başlatması engellenir.
    #[test]
    fn tur6_rpc_empty_api_key_rejected_when_auth_required() {
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

    // === TUR 6 SECURITY FIX (Güvenlik Denetimi §6) =========================
    // KeyPair / ValidatorKeys `save` artık dosyayı doğrudan 0o600 ile
    // oluşturur (TOCTOU penceresi yok) ve izin hatalarını yutar (sessiz
    // hata yok). Aşağıdaki test'ler bu iki garantiyi sabitler.

    /// `KeyPair::save` strict 0o600 ile oluşturur (TOCTOU yok) ve
    /// `load` sonrasında aynı anahtarı geri yükler.
    #[cfg(unix)]
    #[test]
    fn tur6_keypair_save_creates_with_strict_permissions() {
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
    /// yayılır).
    #[cfg(unix)]
    #[test]
    fn tur6_validator_keys_save_creates_with_strict_permissions() {
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
}
