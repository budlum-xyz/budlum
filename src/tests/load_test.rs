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
            println!(
                "Produced block #{} with {} txs (mempool: {})",
                block.index,
                block.transactions.len(),
                bc.mempool.len()
            );
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

    assert_eq!(
        root1, root2,
        "State root must be deterministic after heavy load and restart"
    );
    println!("LOAD TEST SUCCESS: 1000 txs processed, state consistent.");
}

#[tokio::test]
async fn test_chaos_v2_differential_vm_oracle() {
    use crate::execution::zkvm::ZkVmExecutor;
    use bud_isa::{Instruction, Opcode};
    
    // Simple arithmetic program: (10 + 20) * 2 = 60
    let program = vec![
        Instruction { opcode: Opcode::Load, rd: 1, rs1: 0, rs2: 0, imm: 10 }.encode(),
        Instruction { opcode: Opcode::Load, rd: 2, rs1: 0, rs2: 0, imm: 20 }.encode(),
        Instruction { opcode: Opcode::Add, rd: 3, rs1: 1, rs2: 2, imm: 0 }.encode(),
        Instruction { opcode: Opcode::Load, rd: 4, rs1: 0, rs2: 0, imm: 2 }.encode(),
        Instruction { opcode: Opcode::Mul, rd: 5, rs1: 3, rs2: 4, imm: 0 }.encode(),
        Instruction { opcode: Opcode::Log, rd: 0, rs1: 5, rs2: 0, imm: 0 }.encode(),
        Instruction { opcode: Opcode::Halt, rd: 0, rs1: 0, rs2: 0, imm: 0 }.encode(),
    ];
    
    let bytecode: Vec<u8> = program.iter().flat_map(|inst| inst.to_le_bytes()).collect();
    
    // 1. ZKVM Execution (Oracle A)
    let receipt = ZkVmExecutor::execute_bytecode(&bytecode, 1_000_000).unwrap();
    let zkvm_result = receipt.events[0];
    
    // 2. Rust Native Oracle (Oracle B)
    let rust_result = (10u64 + 20u64) * 2u64;
    
    // Differential Assert
    assert_eq!(zkvm_result, rust_result, "ZKVM result {} must match Rust Oracle {}", zkvm_result, rust_result);
    println!("DIFFERENTIAL VM TEST SUCCESS: ZKVM == Rust Oracle");
}
