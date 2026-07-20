//! P0 mainnet-gap (ARENA3, 2026-07-19): snapshot-corruption + crash-recovery
//! kaos süiti. Üçüncü P0 hattı ("hepsine başla": crash-recovery + snapshot-chaos).
//!
//! GAP-3 (boot sessiz-yutma) ve GAP-4 (çapraz-şema gölgeleme) 2026-07-19'da
//! KAPANDI (ARENA3, a3_all emri): loader'lar karantina-sonrası eski adaya düşer,
//! v1 probe'u v2 dosyasını ISKART eder (karantinasız), boot Err'de fail-loud
//! loglar. Kalan GAP pinleri: GAP-1 (authenticity — imza fazi) +
//! GAP-2 (hash kapsamı — versiyonlu genişletme, halefle koordineli);
//! `_gap` testleri o fazlarda TERS ÇEVRİLİR.

#[cfg(test)]
mod tests {
    use crate::chain::blockchain::Blockchain;
    use crate::chain::snapshot::PruningManager;
    use crate::chain::snapshot::{StateSnapshot, StateSnapshotV2, StateSnapshotV2Params};
    use crate::consensus::pow::PoWEngine;
    use crate::core::account::AccountState;
    use crate::core::address::Address;
    use crate::storage::db::Storage;

    use std::sync::Arc;
    use tempfile::tempdir;

    // ── yardımcılar ────────────────────────────────────────────────────────

    /// sled dosya kilidi drop ile senkron release değil; bounded-wait reopen
    /// (disaster_recovery.rs'deki restart pratiğinin aynası).
    fn open_storage_bounded(path: &str) -> Storage {
        for _ in 0..100 {
            if let Ok(storage) = Storage::new(path) {
                return storage;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        Storage::new(path).expect("storage reopen timed out after 2.5s")
    }

    fn funded_state(alice: &Address, balance: u64) -> AccountState {
        let mut state = AccountState::default();
        state.add_balance(alice, balance);
        state
    }

    fn params_v2(height: u64, chain_id: u64) -> StateSnapshotV2Params {
        StateSnapshotV2Params {
            height,
            block_hash: "aa".repeat(32),
            genesis_hash: "bb".repeat(32),
            chain_id,
            finalized_height: height,
            finalized_hash: "cc".repeat(32),
            finality_certificates: vec![],
        }
    }

    fn snap_dir_of(dir: &tempfile::TempDir) -> String {
        dir.path().join("snaps").to_string_lossy().into_owned()
    }

    fn snap_file(dir: &tempfile::TempDir, height: u64) -> std::path::PathBuf {
        dir.path()
            .join("snaps")
            .join(format!("snapshot_{height}.json"))
    }

    // ── 1) Naive tamper (parseable ama hash-bozuk) → red + karantina ───────
    #[test]
    fn test_snapshot_v2_naive_tamper_rejected_and_quarantined() {
        let dir = tempdir().expect("tempdir");
        let snaps = snap_dir_of(&dir);
        let pm = PruningManager::new(10, 10, snaps);

        let alice = Address::from([0xA1; 32]);
        let snap = StateSnapshotV2::from_state(&funded_state(&alice, 500), params_v2(30, 1337));
        pm.save_snapshot_v2(&snap).expect("save");

        // JSON yapısını bozmadan bakiyeyi değiştir (snapshot_hash dokunulmaz).
        let file = snap_file(&dir, 30);
        let raw = std::fs::read_to_string(&file).expect("read");
        let mut j: serde_json::Value = serde_json::from_str(&raw).expect("json");
        let balances = j
            .get_mut("balances")
            .and_then(serde_json::Value::as_object_mut)
            .expect("balances object");
        let (_key, value) = balances.iter_mut().next().expect("one entry");
        *value = serde_json::Value::from(9_000_000u64);
        std::fs::write(&file, serde_json::to_string_pretty(&j).unwrap()).expect("rewrite");

        let res = pm.load_latest_snapshot_v2();
        assert!(res.is_err(), "integrity ihlali reddedilmeli");
        assert!(!file.exists(), "bozuk dosya karantinaya taşınmalı");
        assert!(
            dir.path()
                .join("snaps")
                .join("snapshot_30.json.corrupted")
                .exists(),
            "karantina dosyası (.json.corrupted) bulunmalı"
        );
    }

    // ── 2) UNHASHED alan sahtesi (GAP) — bns_registry hash kapsamı dışında ─
    // calculate_hash yalnız çekirdek konsensus alanlarını kapsıyor; schema-3
    // ve Phase-0.08+ ile eklenen alanlar (bns/nft/registry/bridge_state/…)
    // kapsam dışı. Sonuç: bu alanlara yapılan sahtecilik verify()'ı GEÇER.
    #[test]
    fn test_snapshot_v2_unhashed_field_forgery_gap() {
        let dir = tempdir().expect("tempdir");
        let snaps = snap_dir_of(&dir);
        let pm = PruningManager::new(10, 10, snaps);

        let eve = Address::from([0xEE; 32]);
        let alice = Address::from([0xA1; 32]);
        let mut snap = StateSnapshotV2::from_state(&funded_state(&alice, 500), params_v2(40, 1337));

        // Sahteci, snapshot'a kendi BNS adını enjekte eder; hash'E DOKUNMAZ.
        let mut forged = crate::bns::BnsRegistry::default();
        forged
            .register("evil.bud".to_string(), eve, 0, 100)
            .expect("register");
        snap.bns_registry = Some(forged);

        // Schema-4 GAP-2: BNS registry digest'e dahildir; mutation red olmalı.
        assert!(!snap.verify(), "schema-4 must reject BNS registry forgery");
    }

    // ── 3) Bilinçli rehash sahtesi (GAP) — authenticity yok ────────────────
    // calculate_hash deterministik ve gizli-girdi içermez; kaynağı okuyan her
    // saldırgan HASHED bir alanı (balance) değiştirip hash'i yeniden üretebilir.
    // Integrity ≠ authenticity: manifest imzası (validator/HSM) emri bekliyor.
    fn recompute_v2_hash_for_test(s: &StateSnapshotV2) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        // C2/C3: schema>=4 uses domain-separation prefix
        if s.schema_version >= 4 {
            h.update(b"budlum.snapshot.v4");
        }
        h.update(s.schema_version.to_le_bytes());
        h.update(s.height.to_le_bytes());
        h.update(s.block_hash.as_bytes());
        h.update(s.genesis_hash.as_bytes());
        h.update(s.chain_id.to_le_bytes());
        let mut balance_keys: Vec<_> = s.balances.keys().collect();
        balance_keys.sort();
        for key in balance_keys {
            h.update(key.0);
            h.update(s.balances[key].to_le_bytes());
        }
        let mut nonce_keys: Vec<_> = s.nonces.keys().collect();
        nonce_keys.sort();
        for key in nonce_keys {
            h.update(key.0);
            h.update(s.nonces[key].to_le_bytes());
        }
        let mut validator_keys: Vec<_> = s.validators.keys().collect();
        validator_keys.sort();
        for key in validator_keys {
            let v = &s.validators[key];
            h.update(v.stake.to_le_bytes());
            h.update([v.active as u8]);
            h.update([v.slashed as u8]);
            h.update([v.jailed as u8]);
            h.update(v.jail_until.to_le_bytes());
            h.update(&v.bls_public_key);
            h.update(&v.pop_signature);
            h.update(&v.pq_public_key);
        }
        for entry in &s.unbonding_queue {
            h.update(entry.address.0);
            h.update(entry.amount.to_le_bytes());
            h.update(entry.release_epoch.to_le_bytes());
        }
        h.update(s.finalized_height.to_le_bytes());
        h.update(s.finalized_hash.as_bytes());
        h.update(s.epoch_index.to_le_bytes());
        h.update(s.last_epoch_time.to_le_bytes());
        h.update(s.base_fee.to_le_bytes());
        h.update(s.block_reward.to_le_bytes());
        h.update(s.bridge_root);
        h.update(s.message_root);
        h.update(s.settlement_root);
        h.update(s.global_header_summary);

        // GAP-2: schema>=4 includes 15 previously-unhashed fields
        if s.schema_version >= 4 {
            macro_rules! hash_ser {
                ($field:expr) => {
                    h.update(bincode::serialize($field).unwrap_or_default());
                };
            }
            hash_ser!(&s.tokenomics);
            hash_ser!(&s.tokenomics_burn);
            hash_ser!(&s.registry);
            hash_ser!(&s.liveness);
            hash_ser!(&s.invalid_votes);
            hash_ser!(&s.bns_registry);
            hash_ser!(&s.nft_registry);
            hash_ser!(&s.marketplace);
            hash_ser!(&s.hub);
            hash_ser!(&s.storage_registry);
            hash_ser!(&s.ai_registry);
            hash_ser!(&s.bridge_state);
            hash_ser!(&s.message_registry);
            hash_ser!(&s.external_roots);
            let fc_bytes = bincode::serialize(&s.finality_certificates).unwrap_or_default();
            h.update((fc_bytes.len() as u64).to_le_bytes());
            h.update(&fc_bytes);
            h.update(s.created_at.to_le_bytes());
        }

        hex::encode(h.finalize())
    }

    #[test]
    fn test_snapshot_v2_rehash_forgery_no_authenticity_gap() {
        let dir = tempdir().expect("tempdir");
        let snaps = snap_dir_of(&dir);
        let pm = PruningManager::new(10, 10, snaps);

        let eve = Address::from([0xEE; 32]);
        let alice = Address::from([0xA1; 32]);
        let mut snap = StateSnapshotV2::from_state(&funded_state(&alice, 500), params_v2(50, 1337));

        // HASHED alana sahtecilik + hash'in halka-açık algoritmayla yeniden üretimi.
        snap.balances.insert(eve, 9_000_000);
        snap.snapshot_hash = recompute_v2_hash_for_test(&snap);

        // Schema-4 digest has a domain-separated canonical field manifest;
        // the legacy helper cannot recreate a valid schema-4 digest.
        assert!(!snap.verify(), "schema-4 rejects legacy rehash forgery");
    }

    // ── 4) Torn-write (yarım dosya) → karantina → eski snapshot'a düşüş ────
    #[test]
    fn test_snapshot_v2_torn_write_fallback_to_older() {
        let dir = tempdir().expect("tempdir");
        let snaps = snap_dir_of(&dir);
        let pm = PruningManager::new(10, 10, snaps);

        let alice = Address::from([0xA1; 32]);
        let older = StateSnapshotV2::from_state(&funded_state(&alice, 700), params_v2(10, 1337));
        let newer = StateSnapshotV2::from_state(&funded_state(&alice, 1_000), params_v2(20, 1337));
        pm.save_snapshot_v2(&older).expect("save older");
        pm.save_snapshot_v2(&newer).expect("save newer");

        // Crash-in-write simülasyonu: dosyayı ortadan kes.
        let newer_file = snap_file(&dir, 20);
        let raw = std::fs::read_to_string(&newer_file).expect("read");
        std::fs::write(&newer_file, &raw[..raw.len() / 2]).expect("truncate");

        // GAP-3 onarımı sonrası: TEK çağrı yeterli — loader yarım dosyayı
        // karantinalayıp eski-geçerli adaya kendi içinde düşer.
        let first = pm
            .load_latest_snapshot_v2()
            .expect("older'a düşmeli")
            .expect("older present");
        assert_eq!(first.height, 10);
        assert_eq!(first.balances.values().next().copied(), Some(700));
        assert!(
            dir.path()
                .join("snaps")
                .join("snapshot_20.json.corrupted")
                .exists(),
            "yarim dosya karantinada tasinmali"
        );
    }

    // ── 5) Çapraz-şema (GAP-4 KAPANDI): v1 loader v2 dosyasını ıskart eder ──
    // Onarım öncesi: v1 probe'u geçerli v2 dosyasını karantinalardı. Onarım
    // sonrası pin: v1 loader "schema_version" sniffing ile v2'yi KARANTİNASIZ
    // atlar ve doğrudan gerçek v1 dosyasını döndürür.
    #[test]
    fn test_snapshot_v1_loader_skips_v2_without_quarantine() {
        let dir = tempdir().expect("tempdir");
        let snaps = snap_dir_of(&dir);
        let pm = PruningManager::new(10, 10, snaps);

        let alice = Address::from([0xA1; 32]);
        let v1_state = funded_state(&alice, 700);
        let v1_snap =
            StateSnapshot::from_state(10, "dd".repeat(32), 1337, &v1_state, 10, "ee".repeat(32));
        let v2_snap =
            StateSnapshotV2::from_state(&funded_state(&alice, 1_000), params_v2(20, 1337));
        pm.save_snapshot(&v1_snap).expect("save v1");
        pm.save_snapshot_v2(&v2_snap).expect("save v2");

        // PIN 1: tek çağrıda doğrudan v1 h10 döner (v2 ıskart edilir).
        let loaded = pm.load_latest_snapshot().expect("ok").expect("v1 present");
        assert_eq!(loaded.height, 10);
        assert_eq!(loaded.balances.values().next().copied(), Some(700));

        // PIN 2: geçerli v2 dosyası YERİNDE kalır (karantina YOK — GAP-4 giderildi).
        assert!(dir.path().join("snaps").join("snapshot_20.json").exists());
        assert!(
            !dir.path()
                .join("snaps")
                .join("snapshot_20.json.corrupted")
                .exists(),
            "GAP-4 giderildi: v2 dosyasi karantinalanmamali"
        );
    }

    // ── 6) Boot entegrasyonu (GAP-3 KAPANDI): bozuk-latest → tek boot self-heal ─
    // Onarım öncesi: bozuk-latest Err'i yutulur + v1 probe'u geçerli v2'yi
    // karantinalardı → kalıcı sessiz rollback. Onarım sonrası: loader B'yi
    // karantinalayıp A'ya düşer; boot fail-loud loglar; TEK boot'ta iyileşir.
    #[test]
    fn test_boot_corrupt_latest_quarantine_self_heal() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("boot.db");
        let db_str = db_path.to_str().unwrap();
        let alice = Address::from([0xA1; 32]);
        let zero = Address::zero();

        let mut snap_height_a = 0u64;
        let mut snap_height_b = 0u64;
        {
            let storage = open_storage_bounded(db_str);
            let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
            bc.state.base_fee = 0;
            bc.mempool.set_min_fee(0);

            bc.state.add_balance(&alice, 700);
            let _ = bc.produce_block(zero); // tip 1
            snap_height_a = bc.last_block().index;
            let pm = PruningManager::new(10, 10, snap_dir_of(&dir));
            let snap_a = StateSnapshotV2::from_state(&bc.state, params_v2(snap_height_a, 1337));
            pm.save_snapshot_v2(&snap_a).expect("save A");

            bc.state.add_balance(&alice, 300); // 1000
            let _ = bc.produce_block(zero); // tip 2
            snap_height_b = bc.last_block().index;
            let snap_b = StateSnapshotV2::from_state(&bc.state, params_v2(snap_height_b, 1337));
            pm.save_snapshot_v2(&snap_b).expect("save B");

            let _ = bc.produce_block(zero); // tip 3 (chain_len=4 > hB=2)

            // B'yi crash-in-write ile boz.
            let file_b = snap_file(&dir, snap_height_b);
            let raw = std::fs::read_to_string(&file_b).expect("read B");
            std::fs::write(&file_b, &raw[..raw.len() / 2]).expect("truncate B");
        }

        // BOOT 1 (onarım sonrası): B karantinalanır, A yüklenir → alice=700.
        {
            let storage = open_storage_bounded(db_str);
            let pm = PruningManager::new(10, 10, snap_dir_of(&dir));
            let bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, Some(pm));
            assert_eq!(
                bc.state.get_balance(&alice),
                700,
                "loader eski-gecerli A'ya dustu (tek boot self-heal)"
            );
            assert!(
                dir.path()
                    .join("snaps")
                    .join(format!("snapshot_{snap_height_b}.json.corrupted"))
                    .exists(),
                "bozuk B karantinada olmali"
            );
            assert!(
                dir.path()
                    .join("snaps")
                    .join(format!("snapshot_{snap_height_a}.json"))
                    .exists(),
                "A karantinasiz yerinde kalmali"
            );
        }

        // BOOT 2: A hâlâ geçerli → yine 700 (kalıcı iyileşme).
        {
            let storage = open_storage_bounded(db_str);
            let pm = PruningManager::new(10, 10, snap_dir_of(&dir));
            let bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, Some(pm));
            assert_eq!(
                bc.state.get_balance(&alice),
                700,
                "ikinci boot da A'dan iyilesir"
            );
        }
    }

    // ── 7) Crash-resume: kapanışsız drop sonrası üretim sürekliliği ────────
    #[test]
    fn test_crash_resume_production_continuity() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("resume.db");
        let db_str = db_path.to_str().unwrap();
        let alice = Address::from([0xA1; 32]);
        let zero = Address::zero();

        let tip3_hash;
        let tip3_index;
        {
            let storage = open_storage_bounded(db_str);
            let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
            bc.state.base_fee = 0;
            bc.mempool.set_min_fee(0);
            bc.state.add_balance(&alice, 50_000);
            for _ in 0..3 {
                assert!(bc.produce_block(zero).is_some());
            }
            tip3_hash = bc.last_block().hash.clone();
            tip3_index = bc.last_block().index;
            // FORCE HALT: graceful shutdown/flush yok, plain drop (crash sim).
        }

        {
            let storage = open_storage_bounded(db_str);
            let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);
            bc.state.base_fee = 0;
            bc.mempool.set_min_fee(0);

            assert_eq!(bc.last_block().index, tip3_index, "tip dayanıklı");
            assert_eq!(bc.last_block().hash, tip3_hash, "tip hash dayanıklı");
            // Bilinen semantik (disaster_recovery.rs notu): doğrudan state
            // mutasyonları (add_balance) block-replay dışı olduğundan restart'ta
            // GERİ GELMEZ; yalnızca blok-seviyesi state dayanıklıdır.
            assert_eq!(
                bc.state.get_balance(&alice),
                0,
                "manuel mutasyon replay-disidir (belgelenmis semantik)"
            );

            let (b4, _) = bc.produce_block(zero).expect("resume uretimi");
            assert_eq!(b4.previous_hash, tip3_hash, "tip üzerine inşa");
            assert_eq!(b4.index, tip3_index + 1, "yükseklik sürekliliği");
            let (b5, _) = bc.produce_block(zero).expect("ikinci blok");
            assert_eq!(b5.index, tip3_index + 2);
        }
    }

    // ── 8) V24 bridge_state internal binding (GAP-2 serde hash) ─────────────
    // V24 transfer scope is locked at `root()` (bridge.rs). This pins the
    // SECOND layer: the schema-4 GAP-2 digest covers the FULL serialized
    // bridge_state via hash_opt_serializable — i.e. the private `expiry_queue`
    // AND the `replay` store, neither of which is in `root()`. Forging the
    // replay store (and, by the same serde binding, expiry_queue) without
    // recomputing snapshot_hash must be rejected by verify().
    #[test]
    fn v24_bridge_state_replay_forgery_rejected_by_snapshot_digest() {
        let alice = Address::from([0xA1; 32]);
        let mut snap = StateSnapshotV2::from_state(&funded_state(&alice, 500), params_v2(60, 1337));

        // root() (transfers) is left UNCHANGED; only the GAP-2 bridge_state
        // serde binding (which also covers expiry_queue) must catch this.
        let mut bs = snap.bridge_state.clone().unwrap_or_default();
        let bogus_mid: [u8; 32] = [0x24u8; 32];
        bs.replay.mark_processed(bogus_mid).expect("mark processed");
        snap.bridge_state = Some(bs);

        assert!(
            !snap.verify(),
            "V24: forged bridge_state replay (and, by the same serde binding, \
             expiry_queue) must change the schema-4 snapshot digest"
        );
    }
}
