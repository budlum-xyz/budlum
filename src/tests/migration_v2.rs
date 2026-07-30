//! Migration/upgrade path testi — CI Genişletme Madde 3.
//!
//! Eski format snapshot'tan yeni formata migration veri bozmadan çalışmalı.

#[cfg(test)]
mod migration_tests {
    use crate::chain::snapshot::*;
    use crate::core::account::AccountState;
    use crate::core::address::Address;

    /// Schema-2 snapshot migration: report doğrudan snapshot üzerinde kontrol edilir
    /// (from_bytes schema_version'ı yükseltir, bu yüzden report from_bytes ÖNCEsi alınır).
    #[test]
    fn schema2_migration_preserves_data() {
        let mut state = AccountState::new();
        let alice = Address::from([0xAA; 32]);
        let bob = Address::from([0xBB; 32]);
        state.add_balance(&alice, 5000);
        state.add_balance(&bob, 3000);
        state.add_validator(alice, 2000);

        let snapshot = StateSnapshotV2::from_state(
            &state,
            StateSnapshotV2Params {
                height: 100,
                block_hash: "test_block_hash".into(),
                genesis_hash: "test_genesis_hash".into(),
                chain_id: 45262,
                finalized_height: 90,
                finalized_hash: "finalized_hash".into(),
                finality_certificates: vec![],
            },
        );

        // Schema-2'ye düşür
        let mut old = snapshot.clone();
        old.schema_version = 2;

        // From_bytes ÖNCESİ migration report kontrol
        let report = old.migration_report().unwrap();
        assert!(report.migrated, "Schema-2 should trigger migration");
        assert_eq!(report.original_schema_version, 2);
        assert_eq!(report.target_schema_version, 4);

        // From_bytes ile yükle (schema otomatik yükseltilir)
        let bytes = serde_json::to_vec(&old).unwrap();
        let restored = StateSnapshotV2::from_bytes(&bytes).unwrap();

        // Veri korunmalı
        assert_eq!(restored.balances.get(&alice), Some(&5000));
        assert_eq!(restored.balances.get(&bob), Some(&3000));
        assert!(restored.validators.contains_key(&alice));
        assert_eq!(restored.height, 100);
        assert_eq!(restored.chain_id, 45262);
        assert_eq!(restored.schema_version, 4);
    }

    /// Desteklenmeyen schema reddedilmeli.
    #[test]
    fn unsupported_schema_rejected() {
        let state = AccountState::new();
        let snapshot = StateSnapshotV2::from_state(
            &state,
            StateSnapshotV2Params {
                height: 1,
                block_hash: "h".into(),
                genesis_hash: "g".into(),
                chain_id: 1,
                finalized_height: 0,
                finalized_hash: "".into(),
                finality_certificates: vec![],
            },
        );

        let mut bad = snapshot.clone();
        bad.schema_version = 1;
        assert!(StateSnapshotV2::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err());

        let mut future = snapshot;
        future.schema_version = 99;
        assert!(StateSnapshotV2::from_bytes(&serde_json::to_vec(&future).unwrap()).is_err());
    }

    /// Mevcut schema doğrudan yüklenmeli.
    #[test]
    fn current_schema_loads_directly() {
        let state = AccountState::new();
        let snapshot = StateSnapshotV2::from_state(
            &state,
            StateSnapshotV2Params {
                height: 50,
                block_hash: "hash".into(),
                genesis_hash: "genesis".into(),
                chain_id: 42,
                finalized_height: 40,
                finalized_hash: "final".into(),
                finality_certificates: vec![],
            },
        );
        let bytes = snapshot.to_bytes();
        let restored = StateSnapshotV2::from_bytes(&bytes).unwrap();
        assert_eq!(restored.schema_version, 4);
        assert_eq!(restored.height, 50);
    }
}
