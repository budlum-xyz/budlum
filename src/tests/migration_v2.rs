//! The migration and upgrade path test - CI expansion, item 3.
//!
//! Migrating a snapshot from the old format to the new one has to work without
//! corrupting any data.

#[cfg(test)]
mod migration_tests {
    use crate::chain::snapshot::*;
    use crate::core::account::AccountState;
    use crate::core::address::Address;

    /// Schema-2 snapshot migration: the report is checked directly on the
    /// snapshot, because `from_bytes` raises the schema_version, so the report is
    /// taken BEFORE `from_bytes`.
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

        // Drop it down to schema-2.
        let mut old = snapshot.clone();
        old.schema_version = 2;

        // Check the migration report BEFORE from_bytes.
        let report = old.migration_report().unwrap();
        assert!(report.migrated, "Schema-2 should trigger migration");
        assert_eq!(report.original_schema_version, 2);
        assert_eq!(report.target_schema_version, 4);

        // Load it with from_bytes; the schema is raised automatically.
        let bytes = serde_json::to_vec(&old).unwrap();
        let restored = StateSnapshotV2::from_bytes(&bytes).unwrap();

        // The data has to be preserved.
        assert_eq!(restored.balances.get(&alice), Some(&5000));
        assert_eq!(restored.balances.get(&bob), Some(&3000));
        assert!(restored.validators.contains_key(&alice));
        assert_eq!(restored.height, 100);
        assert_eq!(restored.chain_id, 45262);
        assert_eq!(restored.schema_version, 4);
    }

    /// An unsupported schema has to be refused.
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

    /// The current schema has to load directly.
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
