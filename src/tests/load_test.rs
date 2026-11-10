//! Chaos v2 Heavy Load Test (Q-X3 Response)
//!
//! Simulates extreme transaction pressure (1000+ txs) with concurrent
//! Block production and state anchoring. Validates that the V3-Anchored
//! State root calculation remains performant and deterministic under load.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
#[cfg(test)]
fn test_addr_from_byte(byte: u8) -> crate::core::address::Address {
    let mut b = [0u8; 32];
    b[0] = byte;
    crate::core::address::Address::from(b)
}

use crate::core::transaction::Transaction;
use crate::crypto::primitives::KeyPair;
use crate::storage::db::Storage;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_chaos_v2_heavy_load_under_pressure() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("load_test.db");
    let bob = test_addr_from_byte(2u8);

    // Mempool enforces a per-sender DoS cap (config.max_per_sender = 100),
    // So the 1000-tx workload is distributed across 10 funded senders,
    // Each exactly at the cap. Funding MUST go through genesis allocations:
    // Reload replays blocks from the deterministic genesis state, and direct
    // In-memory state mutations are not part of the chain (replaying block
    // #1 against an unfunded account fails inside apply_block_effects and
    // The init path hard-exits the process - blockchain.rs:339).
    let senders: Vec<KeyPair> = (0..10).map(|_| KeyPair::generate().unwrap()).collect();
    let funded_genesis = || {
        let mut g = crate::chain::genesis::GenesisConfig::new(45262);
        for kp in &senders {
            g = g.with_allocation(Address::from(kp.public_key_bytes()), 100_000);
        }
        g.base_fee = 0;
        g
    };
    let storage = Storage::new(db.to_str().unwrap()).unwrap();
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new_with_genesis(
        consensus,
        Some(storage),
        45262,
        None,
        Some(funded_genesis()),
    );
    bc.mempool.set_min_fee(0);

    println!("Phase: Injecting 1000 transactions (10 senders x 100)...");
    for kp in &senders {
        let from = Address::from(kp.public_key_bytes());
        for i in 0..100 {
            let mut tx = Transaction::new(from, bob, 1, vec![]);
            tx.nonce = i as u64;
            tx.sign(kp);
            bc.mempool.add_transaction(tx).unwrap();
        }
    }

    assert_eq!(bc.mempool.len(), 1000);

    println!("Phase: Producing blocks to clear mempool...");
    // Each block in devnet/test might have a tx limit, but produce_block
    // Usually takes as many as possible or a default limit.
    let mut total_processed = 0;
    while !bc.mempool.is_empty() {
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

    println!("Phase: Verifying V3-Anchored state root determinism...");
    // Snapshot the live state before the restart; the map-level diff is
    // The diagnostic layer for any replay divergence.
    let mut live_state = bc.state.clone();
    let live_accounts = bc.state.accounts.clone();

    // Simulate restart and reload (same funded genesis => same genesis hash,
    // Same funded accounts; replay reproduces the exact live state root).
    drop(bc);
    let storage2 = Storage::new(db.to_str().unwrap()).unwrap();
    let bc2 = Blockchain::new_with_genesis(
        Arc::new(PoWEngine::new(0)),
        Some(storage2),
        45262,
        None,
        Some(funded_genesis()),
    );

    let mut state2 = bc2.state.clone();

    // The state root is a pure function of (pubkey, balance, nonce) over the
    // Accounts map - diagnose at map level first so any replay divergence
    // Pinpoints the offending accounts instead of an opaque hash.
    assert_eq!(
        live_accounts.len(),
        bc2.state.accounts.len(),
        "account count must survive replay"
    );
    let mismatches: Vec<_> = live_accounts
        .iter()
        .filter(|(k, a)| match bc2.state.accounts.get(*k) {
            Some(b) => b.balance != a.balance || b.nonce != a.nonce,
            None => true,
        })
        .collect();
    if !mismatches.is_empty() {
        for (k, a) in mismatches.iter().take(3) {
            let rb = bc2.state.accounts.get(*k).map(|b| (b.balance, b.nonce));
            eprintln!(
                "REPLAY MISMATCH {:?}: live=(bal {}, nonce {}) replayed={:?}",
                k, a.balance, a.nonce, rb
            );
        }
        panic!("{} accounts differ after replay", mismatches.len());
    }

    // The full root, overlay fields included, must be identical after a
    // restart. Masking the bridge, message, settlement and header summary
    // roots on both sides would hide a fork after restart.
    assert_eq!(
        live_state.calculate_state_root(),
        state2.calculate_state_root(),
        "the full state root must be bit-identical after heavy load and restart"
    );
    println!("LOAD TEST SUCCESS: 1000 txs processed, state consistent.");
}

#[tokio::test]
async fn test_chaos_v2_differential_vm_oracle() {
    use crate::execution::zkvm::ZkVmExecutor;
    use bud_isa::{Instruction, Opcode};

    fn inst(opcode: Opcode, rd: u8, rs1: u8, rs2: u8, imm: i32) -> u64 {
        Instruction {
            opcode,
            rd,
            rs1,
            rs2,
            imm,
        }
        .encode()
    }

    // Deterministic inputs below 2^20, so every native result stays far from
    // the field modulus and the native oracle needs no reduction.
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % (1 << 20)) as i32
    };
    let mut inputs: Vec<(i32, i32)> = vec![(0, 0), (1, 0), (0, 1), (1, 1), ((1 << 20) - 1, 1)];
    for _ in 0..27 {
        inputs.push((next(), next()));
    }

    for (a, b) in inputs {
        let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
        let cases = [
            (Opcode::Add, a, b, a as u64 + b as u64),
            (Opcode::Sub, hi, lo, hi as u64 - lo as u64),
            (Opcode::Mul, a, b, a as u64 * b as u64),
        ];
        for (op, x, y, native) in cases {
            let program = [
                inst(Opcode::Load, 1, 0, 0, x),
                inst(Opcode::Load, 2, 0, 0, y),
                inst(op, 3, 1, 2, 0),
                inst(Opcode::Log, 0, 3, 0, 0),
                inst(Opcode::Halt, 0, 0, 0, 0),
            ];
            let bytecode: Vec<u8> = program.iter().flat_map(|i| i.to_le_bytes()).collect();
            let receipt = ZkVmExecutor::execute_bytecode(
                &bytecode,
                1_000_000,
                crate::execution::zkvm::TxContext::default(),
            )
            .unwrap();
            assert_eq!(
                receipt.events[0], native,
                "ZKVM {op:?}({x}, {y}) must match the native result {native}"
            );
        }
    }
}
