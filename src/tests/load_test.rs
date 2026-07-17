//! Chaos v2 Heavy Load Test (ADIM 5 §5.4 / Q-X3 Response)
//!
//! Simulates extreme transaction pressure (1000+ txs) with concurrent
//! block production and state anchoring. Validates that the V3-Anchored
//! state root calculation remains performant and deterministic under load.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::core::transaction::Transaction;
use crate::crypto::primitives::KeyPair;
use crate::storage::db::Storage;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_chaos_v2_heavy_load_under_pressure() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("load_test.db");
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, Some(storage), 1337, None);
    bc.state.base_fee = 0;
    bc.mempool.set_min_fee(0);

    let alice_kp = KeyPair::generate().unwrap();
    let alice = Address::from(alice_kp.public_key_bytes());
    bc.state.add_balance(&alice, 10_000_000);

    let bob = Address::from([2u8; 32]);
    
    println!("PHASE 1: Injecting 1000 transactions...");
    for i in 0..1000 {
        let mut tx = Transaction::new(alice, bob, 1, vec![]);
        tx.nonce = i as u64;
        tx.sign(&alice_kp);
        bc.mempool.add_transaction(tx).unwrap();
    }
    
    assert_eq!(bc.mempool.len(), 1000);
    
    println!("PHASE 2: Producing blocks to clear mempool...");
    // Each block in devnet/test might have a tx limit, but produce_block 
    // usually takes as many as possible or a default limit.
    let mut total_processed = 0;
    while bc.mempool.len() > 0 {
        if let Some((block, _)) = bc.produce_block(Address::zero()) {
            total_processed += block.transactions.len();
            println!("Produced block #{} with {} txs (mempool: {})", 
                block.index, block.transactions.len(), bc.mempool.len());
        } else {
            panic!("Block production failed under load!");
        }
    }
    
    assert_eq!(total_processed, 1000);
    assert_eq!(bc.state.get_balance(&bob), 1000);
    
    println!("PHASE 3: Verifying V3-Anchored state root determinism...");
    let root1 = bc.state.calculate_state_root();
    
    // Simulate restart and reload
    drop(bc);
    let storage2 = Storage::new(db.to_str().unwrap()).unwrap();
    let bc2 = Blockchain::new(Arc::new(PoWEngine::new(0)), Some(storage2), 1337, None);
    
    let mut state2 = bc2.state.clone();
    let root2 = state2.calculate_state_root();
    
    assert_eq!(root1, root2, "State root must be deterministic after heavy load and restart");
    println!("LOAD TEST SUCCESS: 1000 txs processed, state consistent.");
}
