//! P0 mainnet-gap (2026-07-19): snapshot-corruption + crash-recovery
//! chaos suite. The third P0 line ("start on all of them": crash recovery and
//! snapshot chaos).
//!
//! The silent boot swallow and the cross-schema shadowing were CLOSED on
//! 2026-07-19: the loaders fall back to the older candidate after quarantining,
//! the v1 probe DISCARDS a v2 file without quarantining it, and boot logs
//! fail-loud on an Err. The remaining GAP pins are authenticity (the signature
//! task) and hash coverage (a versioned extension, coordinated with its
//! successor); the `_gap` tests are INVERTED when those tasks land.

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

    // -- helpers ------------------------------------------------------------

    /// The sled file lock is not released synchronously on drop, so this is a
    /// bounded-wait reopen - a mirror of the restart practice in
    /// disaster_recovery.rs.
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

    // ── 1) Naive tamper (parseable but hash-broken) → refused + quarantined ──
    #[test]
    fn test_snapshot_v2_naive_tamper_rejected_and_quarantined() {
        let dir = tempdir().expect("tempdir");
        let snaps = snap_dir_of(&dir);
        let pm = PruningManager::new(10, 10, snaps);

        let alice = Address::from([0xA1; 32]);
        let snap = StateSnapshotV2::from_state(&funded_state(&alice, 500), params_v2(30, 45262));
        pm.save_snapshot_v2(&snap).expect("save");

        // Change the balance without breaking the JSON structure; snapshot_hash
        // is left untouched.
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
        assert!(res.is_err(), "an integrity violation has to be refused");
        assert!(
            !file.exists(),
            "the corrupt file has to be moved to quarantine"
        );
        assert!(
            dir.path()
                .join("snaps")
                .join("snapshot_30.json.corrupted")
                .exists(),
            "the quarantine file (.json.corrupted) has to be present"
        );
    }

    // -- 2) Forging an UNHASHED field (GAP): bns_registry is outside the hash --
    // calculate_hash covers only the core consensus fields; schema-3
    // and the fields added with Task-0.08+ (bns/nft/registry/bridge_state/…)
    // are out of scope. The consequence: forgery in those fields PASSES verify.
    #[test]
    fn test_snapshot_v2_unhashed_field_forgery_gap() {
        let dir = tempdir().expect("tempdir");
        let snaps = snap_dir_of(&dir);
        let _pm = PruningManager::new(10, 10, snaps);

        let eve = Address::from([0xEE; 32]);
        let alice = Address::from([0xA1; 32]);
        let mut snap =
            StateSnapshotV2::from_state(&funded_state(&alice, 500), params_v2(40, 45262));

        // The forger injects their own BNS name into the snapshot and DOES NOT
        // TOUCH the hash.
        let mut forged = crate::bns::BnsRegistry::default();
        forged
            .register("evil.bud".to_string(), eve, 0, 100)
            .expect("register");
        snap.bns_registry = Some(forged);

        // Schema-4: the BNS registry is part of the digest, so the mutation has
        // to be refused.
        assert!(!snap.verify(), "schema-4 must reject BNS registry forgery");
    }

    // -- 3) A deliberate rehash forgery (GAP): there is no authenticity --------
    // calculate_hash is deterministic and takes no secret input, so any attacker
    // who reads the source can change a HASHED field (a balance) and recompute
    // the hash. Integrity is not authenticity: the manifest signature (a
    // validator or HSM) is waiting on its own task.
    fn recompute_v2_hash_for_test(s: &StateSnapshotV2) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        // Schema>=4 uses domain-separation prefix
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

        // Schema>=4 includes 15 previously-unhashed fields
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
            hash_ser!(&s.budlumxyz);
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
        let _pm = PruningManager::new(10, 10, snaps);

        let eve = Address::from([0xEE; 32]);
        let alice = Address::from([0xA1; 32]);
        let mut snap =
            StateSnapshotV2::from_state(&funded_state(&alice, 500), params_v2(50, 45262));

        // Forgery in a HASHED field, plus recomputing the hash with the public
        // algorithm.
        snap.balances.insert(eve, 9_000_000);
        snap.snapshot_hash = recompute_v2_hash_for_test(&snap);

        // Schema-4 digest has a domain-separated canonical field manifest;
        // The legacy helper cannot recreate a valid schema-4 digest.
        assert!(!snap.verify(), "schema-4 rejects legacy rehash forgery");
    }

    // -- 4) A torn write (a half file): quarantine, then fall back to the older snapshot --
    #[test]
    fn test_snapshot_v2_torn_write_fallback_to_older() {
        let dir = tempdir().expect("tempdir");
        let snaps = snap_dir_of(&dir);
        let pm = PruningManager::new(10, 10, snaps);

        let alice = Address::from([0xA1; 32]);
        let older = StateSnapshotV2::from_state(&funded_state(&alice, 700), params_v2(10, 45262));
        let newer = StateSnapshotV2::from_state(&funded_state(&alice, 1_000), params_v2(20, 45262));
        pm.save_snapshot_v2(&older).expect("save older");
        pm.save_snapshot_v2(&newer).expect("save newer");

        // Simulate a crash during the write by cutting the file in half.
        let newer_file = snap_file(&dir, 20);
        let raw = std::fs::read_to_string(&newer_file).expect("read");
        std::fs::write(&newer_file, &raw[..raw.len() / 2]).expect("truncate");

        // After the fix a SINGLE call is enough: the loader quarantines the half
        // file and falls back to the older valid candidate on its own.
        let first = pm
            .load_latest_snapshot_v2()
            .expect("it has to fall back to the older one")
            .expect("older present");
        assert_eq!(first.height, 10);
        assert_eq!(first.balances.values().next().copied(), Some(700));
        assert!(
            dir.path()
                .join("snaps")
                .join("snapshot_20.json.corrupted")
                .exists(),
            "a half-written file must be moved to quarantine"
        );
    }

    // -- 5) Cross-schema (CLOSED): the v1 loader discards a v2 file ----------
    // Before the fix the v1 probe quarantined a valid v2 file. The pin after the
    // fix: the v1 loader sniffs "schema_version", skips the v2 file WITHOUT
    // quarantining it, and returns the real v1 file directly.
    #[test]
    fn test_snapshot_v1_loader_skips_v2_without_quarantine() {
        let dir = tempdir().expect("tempdir");
        let snaps = snap_dir_of(&dir);
        let pm = PruningManager::new(10, 10, snaps);

        let alice = Address::from([0xA1; 32]);
        let v1_state = funded_state(&alice, 700);
        let v1_snap =
            StateSnapshot::from_state(10, "dd".repeat(32), 45262, &v1_state, 10, "ee".repeat(32));
        let v2_snap =
            StateSnapshotV2::from_state(&funded_state(&alice, 1_000), params_v2(20, 45262));
        pm.save_snapshot(&v1_snap).expect("save v1");
        pm.save_snapshot_v2(&v2_snap).expect("save v2");

        // PIN 1: a single call returns v1 h10 directly, discarding the v2 file.
        let loaded = pm.load_latest_snapshot().expect("ok").expect("v1 present");
        assert_eq!(loaded.height, 10);
        assert_eq!(loaded.balances.values().next().copied(), Some(700));

        // PIN 2: the valid v2 file stays IN PLACE - no quarantine, which was the fix.
        assert!(dir.path().join("snaps").join("snapshot_20.json").exists());
        assert!(
            !dir.path()
                .join("snaps")
                .join("snapshot_20.json.corrupted")
                .exists(),
            "GAP-4 was fixed: the v2 file must not be quarantined"
        );
    }

    // -- 6) Boot integration (CLOSED): a corrupt latest self-heals in one boot --
    // Before the fix the Err from the corrupt latest was swallowed and the v1
    // probe quarantined the valid v2, which meant a permanent silent rollback.
    // After the fix the loader quarantines B and falls back to A, boot logs
    // fail-loud, and it recovers in a SINGLE boot.
    #[test]
    fn test_boot_corrupt_latest_quarantine_self_heal() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("boot.db");
        let db_str = db_path.to_str().unwrap();
        let alice = Address::from([0xA1; 32]);
        let zero = Address::zero();

        let snap_height_a;
        let snap_height_b;
        {
            let storage = open_storage_bounded(db_str);
            let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
            bc.state.base_fee = 0;
            bc.mempool.set_min_fee(0);

            bc.state.add_balance(&alice, 700);
            let _ = bc.produce_block(zero); // tip 1
            snap_height_a = bc.last_block().index;
            let pm = PruningManager::new(10, 10, snap_dir_of(&dir));
            let snap_a = StateSnapshotV2::from_state(&bc.state, params_v2(snap_height_a, 45262));
            pm.save_snapshot_v2(&snap_a).expect("save A");

            bc.state.add_balance(&alice, 300); // 1000
            let _ = bc.produce_block(zero); // tip 2
            snap_height_b = bc.last_block().index;
            let snap_b = StateSnapshotV2::from_state(&bc.state, params_v2(snap_height_b, 45262));
            pm.save_snapshot_v2(&snap_b).expect("save B");

            let _ = bc.produce_block(zero); // tip 3 (chain_len=4 > hB=2)

            // Break B with a crash-in-write.
            let file_b = snap_file(&dir, snap_height_b);
            let raw = std::fs::read_to_string(&file_b).expect("read B");
            std::fs::write(&file_b, &raw[..raw.len() / 2]).expect("truncate B");
        }

        // BOOT 1 (after the fix): B is quarantined and A is loaded, so alice=700.
        {
            let storage = open_storage_bounded(db_str);
            let pm = PruningManager::new(10, 10, snap_dir_of(&dir));
            let bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, Some(pm));
            assert_eq!(
                bc.state.get_balance(&alice),
                700,
                "the loader fell back to the older valid A - a single-boot self-heal"
            );
            assert!(
                dir.path()
                    .join("snaps")
                    .join(format!("snapshot_{snap_height_b}.json.corrupted"))
                    .exists(),
                "the corrupt B has to be in quarantine"
            );
            assert!(
                dir.path()
                    .join("snaps")
                    .join(format!("snapshot_{snap_height_a}.json"))
                    .exists(),
                "A must stay in place, unquarantined"
            );
        }

        // BOOT 2: A is still valid, so 700 again - the recovery is permanent.
        {
            let storage = open_storage_bounded(db_str);
            let pm = PruningManager::new(10, 10, snap_dir_of(&dir));
            let bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, Some(pm));
            assert_eq!(
                bc.state.get_balance(&alice),
                700,
                "the second boot also recovers from A"
            );
        }
    }

    // -- 7) Crash resume: production continuity after a drop with no shutdown --
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
            let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
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
            let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 45262, None);
            bc.state.base_fee = 0;
            bc.mempool.set_min_fee(0);

            assert_eq!(bc.last_block().index, tip3_index, "the tip is durable");
            assert_eq!(bc.last_block().hash, tip3_hash, "the tip hash is durable");
            // Known semantics (see the note in disaster_recovery.rs): direct state
            // mutations such as add_balance sit outside block replay, so they DO
            // NOT come back on restart; only block-level state is durable.
            assert_eq!(
                bc.state.get_balance(&alice),
                0,
                "a manual mutation is outside replay (documented semantics)"
            );

            let (b4, _) = bc.produce_block(zero).expect("production on resume");
            assert_eq!(b4.previous_hash, tip3_hash, "it builds on the tip");
            assert_eq!(b4.index, tip3_index + 1, "height continuity");
            let (b5, _) = bc.produce_block(zero).expect("second block");
            assert_eq!(b5.index, tip3_index + 2);
        }
    }

    // ── 8) bridge_state internal binding (serde hash) ─────────────
    // Transfer scope is locked at `root` (bridge.rs). This pins the
    // SECOND layer: the schema-4 digest covers the FULL serialized
    // Bridge_state via hash_opt_serializable - i.e. the private `expiry_queue`
    // AND the `replay` store, neither of which is in `root`. Forging the
    // Replay store (and, by the same serde binding, expiry_queue) without
    // Recomputing snapshot_hash must be rejected by verify.
    #[test]
    fn bridge_state_replay_forgery_rejected_by_snapshot_digest() {
        let alice = Address::from([0xA1; 32]);
        let mut snap =
            StateSnapshotV2::from_state(&funded_state(&alice, 500), params_v2(60, 45262));

        // Root (transfers) is left UNCHANGED; only bridge_state
        // Serde binding (which also covers expiry_queue) must catch this.
        let mut bs = snap.bridge_state.clone().unwrap_or_default();
        let bogus_mid: [u8; 32] = [0x24u8; 32];
        bs.replay
            .mark_processed_at(bogus_mid, 0)
            .expect("mark processed");
        snap.bridge_state = Some(bs);

        assert!(
            !snap.verify(),
            "forged bridge_state replay (and, by the same serde binding, \
             expiry_queue) must change the schema-4 snapshot digest"
        );
    }
}
