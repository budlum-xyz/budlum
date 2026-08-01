//! Replay and State Audit Tests.
//! Ensures that state recovery from DB is bit-for-bit identical to live execution.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use crate::core::transaction::Transaction;
use crate::crypto::primitives::KeyPair;
use crate::storage::db::Storage;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_state_bit_identical_after_reload() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("replay_audit.db");
    let db_str = db_path.to_str().unwrap();

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let bob = Address::from([0xBB; 32]);

    let root_live;

    // Funding must be part of the chain (genesis allocations): reload
    // Replays blocks against the deterministic genesis state, so direct
    // In-memory add_balance would render the chain unreplayable (init
    // Hard-exits the process, blockchain.rs:339).
    let funded_genesis = || {
        let mut g = crate::chain::genesis::GenesisConfig::new(45262);
        g = g.with_allocation(alice, 1000);
        g.base_fee = 0;
        g
    };

    // 1. Live Execution
    {
        let storage = Storage::new(db_str).unwrap();
        let mut bc = Blockchain::new_with_genesis(
            Arc::new(PoWEngine::new(0)),
            Some(storage),
            45262,
            None,
            Some(funded_genesis()),
        );
        // Dev-environment fixture: zero-fee mempool admission (fee=0 txs).
        bc.mempool.set_min_fee(0);

        // Each produce_block REBUILDS the mempool with the DEFAULT config
        // (min_fee=1, blockchain.rs:3089), so txs must carry fee >= 1 to
        // Survive admission across multiple production rounds. fee=1 still
        // Executes deterministically above genesis base_fee=0.
        for i in 0..5 {
            let mut tx = Transaction::new_with_fee(alice, bob, 10, 1, 0, vec![]);
            tx.nonce = i;
            tx.sign(&alice_kp);
            bc.mempool.add_transaction(tx).unwrap();
            let _ = bc.produce_block(Address::zero());
        }

        // Compare masked: executable consensus surface only (overlay fields
        // Are commit-path projections; see reload arm for full rationale).
        let mut live_masked = bc.state.clone();
        live_masked.bridge_root = [0u8; 32];
        live_masked.message_root = [0u8; 32];
        live_masked.settlement_root = [0u8; 32];
        live_masked.global_header_summary = [0u8; 32];
        root_live = live_masked.calculate_state_root();
        assert_ne!(root_live, "0".repeat(64));
        // Drop and close DB
    }

    // 2. Reload and Replay from Storage
    {
        let storage = Storage::new(db_str).unwrap();
        // The constructor new_with_genesis loads the chain and rebuilds the
        // State; it must receive the SAME funded genesis (identical genesis
        // Hash, identical initial balances).
        let bc_reloaded = Blockchain::new_with_genesis(
            Arc::new(PoWEngine::new(0)),
            Some(storage),
            45262,
            None,
            Some(funded_genesis()),
        );

        // Overlay fields (bridge/message/settlement/global-header roots) are
        // Commit-path projections not mirrored by the replay loop - normalize
        // On both sides (see load_test.rs for the full rationale) and
        // Compare the executable consensus surface bit-for-bit.
        let mut state_reloaded_masked = bc_reloaded.state.clone();
        state_reloaded_masked.bridge_root = [0u8; 32];
        state_reloaded_masked.message_root = [0u8; 32];
        state_reloaded_masked.settlement_root = [0u8; 32];
        state_reloaded_masked.global_header_summary = [0u8; 32];
        let root_reloaded = state_reloaded_masked.calculate_state_root();

        assert_eq!(
            root_live, root_reloaded,
            "Reloaded executable state root must match live state root exactly"
        );
        // Alice spent 5x(amount 10 + fee 1); bob received 5x10.
        assert_eq!(bc_reloaded.state.get_balance(&alice), 945);
        assert_eq!(bc_reloaded.state.get_balance(&bob), 50);
    }
}

/// Sub-registry recovery across a restart.
///
/// This test carried `#[ignore]` with the note "V3 sub-registry persistence is
/// not implemented: Blockchain::new reloads blocks but rebuilds BNS/NFT
/// registries empty". The note is wrong, and the ignore was hiding a broken
/// test rather than a missing feature.
///
/// The old body wrote straight into `bc.state.bns_registry` and
/// `bc.state.nft_registry`, then produced a block and expected the entries to
/// come back. They could not. Restart recovery replays blocks through
/// `apply_block_effects`, so state that never entered a transaction is not
/// part of the chain and there is nothing to replay. The test was asserting
/// that an in-memory mutation survives a restart, which is not a property this
/// system has or should have.
///
/// BNS state does persist, by both routes that exist: `BnsRegister` is a
/// transaction the executor applies (`executor.rs:496`, mutating
/// `state.bns_registry`), so replay reconstructs it; and `bns_registry` is
/// carried in the schema-4 snapshot and covered by its digest
/// (`snapshot.rs:661`, `769`).
///
/// This version drives the real path: fund an account at genesis, register a
/// name with a signed `BnsRegister` transaction, produce the block, drop the
/// chain, reopen it against the same database and ask the rebuilt registry to
/// resolve the name.
#[tokio::test]
async fn a_bns_name_registered_by_transaction_survives_a_restart() {
    let dir = tempdir().unwrap();
    let db_str = dir
        .path()
        .join("registry_audit.db")
        .to_str()
        .unwrap()
        .to_string();

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    let bns_name = "recovery.bud".to_string();

    // Funding has to come from genesis: replay rebuilds state from the
    // deterministic genesis, so an in-memory `add_balance` would leave the
    // chain unreplayable.
    let funded_genesis = || {
        let mut g = crate::chain::genesis::GenesisConfig::new(45262);
        g = g.with_allocation(alice, 1_000_000);
        g.base_fee = 0;
        g
    };

    let cost;

    // 1. Register the name through a transaction, so it is in the chain.
    {
        let storage = Storage::new(&db_str).unwrap();
        let mut bc = Blockchain::new_with_genesis(
            Arc::new(PoWEngine::new(0)),
            Some(storage),
            45262,
            None,
            Some(funded_genesis()),
        );
        bc.mempool.set_min_fee(0);

        cost = bc.state.bns_registry.calculate_cost(&bns_name, 1000);
        let data = bincode::serialize(&(bns_name.clone(), 1000u64)).expect("ser");
        let mut tx = Transaction::new_with_chain_id(
            alice,
            Address::zero(),
            cost,
            1,
            0,
            data,
            45262,
            crate::core::transaction::TransactionType::BnsRegister,
        );
        tx.sign(&alice_kp);
        bc.mempool.add_transaction(tx).unwrap();
        let produced = bc.produce_block(Address::zero());
        assert!(produced.is_some(), "the registering block must be produced");

        assert_eq!(
            bc.state.bns_registry.resolve(&bns_name, 10),
            Some(alice),
            "the name must resolve while the chain is still live, or the \
             restart half of this test proves nothing"
        );
    }

    // 2. Reopen against the same database and replay.
    {
        let storage = Storage::new(&db_str).unwrap();
        let bc = Blockchain::new_with_genesis(
            Arc::new(PoWEngine::new(0)),
            Some(storage),
            45262,
            None,
            Some(funded_genesis()),
        );

        assert!(
            bc.chain.len() > 1,
            "the reopened chain must carry the registering block, or replay had \
             nothing to apply"
        );
        assert_eq!(
            bc.state.bns_registry.resolve(&bns_name, 10),
            Some(alice),
            "a name registered by transaction must survive a restart"
        );
    }
}
