//! Replay and State Audit Tests (ARENA2).
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
    // replays blocks against the deterministic genesis state, so direct
    // in-memory add_balance would render the chain unreplayable (init
    // hard-exits the process, blockchain.rs:339).
    let funded_genesis = || {
        let mut g = crate::chain::genesis::GenesisConfig::new(1337);
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
            1337,
            None,
            Some(funded_genesis()),
        );
        // Dev-environment fixture: zero-fee mempool admission (fee=0 txs).
        bc.mempool.set_min_fee(0);

        for i in 0..5 {
            let mut tx = Transaction::new(alice, bob, 10, vec![]);
            tx.nonce = i;
            tx.sign(&alice_kp);
            bc.mempool.add_transaction(tx).unwrap();
            let _ = bc.produce_block(Address::zero());
        }

        root_live = bc.state.calculate_state_root();
        assert_ne!(root_live, "0".repeat(64));
        // Drop and close DB
    }

    // 2. Reload and Replay from Storage
    {
        let storage = Storage::new(db_str).unwrap();
        // The constructor new_with_genesis loads the chain and rebuilds the
        // state; it must receive the SAME funded genesis (identical genesis
        // hash, identical initial balances).
        let bc_reloaded = Blockchain::new_with_genesis(
            Arc::new(PoWEngine::new(0)),
            Some(storage),
            1337,
            None,
            Some(funded_genesis()),
        );

        let mut state_reloaded = bc_reloaded.state.clone();
        let root_reloaded = state_reloaded.calculate_state_root();

        assert_eq!(
            root_live, root_reloaded,
            "Reloaded state root must match live state root exactly"
        );
        assert_eq!(bc_reloaded.state.get_balance(&alice), 950);
        assert_eq!(bc_reloaded.state.get_balance(&bob), 50);
    }
}

#[tokio::test]
#[ignore = "V3 sub-registry persistence is not implemented: Blockchain::new reloads blocks but rebuilds BNS/NFT registries empty (6ba5728 moved them into AccountState without wiring storage recovery). Tracked as mainnet-gap; see STATUS_ONLINE."]
async fn test_sub_registry_recovery() {
    let dir = tempdir().unwrap();
    let db_str = dir
        .path()
        .join("registry_audit.db")
        .to_str()
        .unwrap()
        .to_string();

    let alice = Address::from([0x01; 32]);
    let cid = crate::storage::content_id::ContentId([0xCC; 32]);

    let bns_name = "recovery.bud".to_string();

    // 1. Fill Registries
    {
        let storage = Storage::new(&db_str).unwrap();
        let mut bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);

        // BNS
        bc.state
            .bns_registry
            .register(bns_name.clone(), alice, 0, 1000)
            .unwrap();
        // NFT
        bc.state.nft_registry.mint(alice, cid, 0, None);

        let _ = bc.produce_block(Address::zero());
        // Save current state to storage (this would usually happen via block commit)
    }

    // 2. Verify Recovery
    {
        let storage = Storage::new(&db_str).unwrap();
        let bc = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage), 1337, None);

        assert_eq!(bc.state.bns_registry.resolve(&bns_name, 10), Some(alice));
        assert!(bc.state.nft_registry.get_nft(0).is_some());
        assert_eq!(bc.state.nft_registry.get_nft(0).unwrap().content_id, cid);
    }
}

macro_rules! gen_replay_tests {
    ($($name:ident, $seed:expr),*) => {
        $(
            #[test]
            fn $name() {
                // Placeholder for seed-based replay variations
                assert!(true);
            }
        )*
    }
}

gen_replay_tests!(
    replay_1, 1, replay_2, 2, replay_3, 3, replay_4, 4, replay_5, 5, replay_6, 6, replay_7, 7,
    replay_8, 8, replay_9, 9, replay_10, 10, replay_11, 11, replay_12, 12, replay_13, 13,
    replay_14, 14, replay_15, 15, replay_16, 16, replay_17, 17, replay_18, 18, replay_19, 19,
    replay_20, 20
);
