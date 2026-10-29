//! Expanded Consensus and Chain tests.

use crate::chain::blockchain::Blockchain;
use crate::consensus::poa::{PoAConfig, PoAEngine};
use crate::consensus::pow::PoWEngine;
use crate::consensus::ConsensusEngine;
use crate::core::address::Address;

use crate::core::block::Block;
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

#[test]
fn test_pow_engine_zero_difficulty() {
    // Difficulty 0 should accept any nonce
    let engine = PoWEngine::new(0);
    let mut block = Block::new(1, "prev".to_string(), vec![]);
    block.nonce = 0;
    assert!(engine
        .validate_block(&block, &[], &crate::core::account::AccountState::new())
        .is_ok());
}

#[test]
fn test_poa_engine_empty_authorities() {
    let config = PoAConfig::default(); // empty
    let engine = PoAEngine::new(config, None);
    let mut block = Block::new(1, "prev".to_string(), vec![]);
    block.producer = Some(addr(1));
    // Should fail because addr(1) is not an authority
    assert!(engine
        .validate_block(&block, &[], &crate::core::account::AccountState::new())
        .is_err());
}

#[test]
fn test_blockchain_invalid_previous_hash() {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);
    let mut block = Block::new(1, "WRONG_HASH".to_string(), vec![]);
    block.chain_id = 45262;
    // Should fail at blockchain level before consensus
    assert!(bc.validate_and_add_block(block).map(|_| ()).is_err());
}

#[test]
fn test_blockchain_future_timestamp_buffer() {
    use crate::consensus::ConsensusEngine;
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus.clone(), None, 45262, None);
    let mut block = Block::new(1, bc.chain[0].hash.clone(), vec![]);
    block.chain_id = 45262;
    // One hour ahead of the real clock. The devnet genesis is dated 0, so a
    // block dated from genesis would be in the past and never reach the
    // drift gate.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    block.timestamp = now_ms + 3600 * 1000;
    // The gate itself names the reason.
    let reason = consensus
        .validate_timestamp(&block, Some(&bc.chain[0]))
        .unwrap_err();
    assert!(
        reason.0.contains("too far in the future"),
        "wrong reason: {}",
        reason.0
    );
    // And the chain refuses the block.
    let res = bc.validate_and_add_block(block).map(|_| ());
    assert!(
        res.is_err(),
        "future-timestamp block must be rejected (timestamp drift protection)"
    );
}

macro_rules! gen_pow_difficulty_tests {
    ($($name:ident, $diff:expr),*) => {
        $(
            #[test]
            fn $name() {
                let engine = PoWEngine::new($diff);
                assert_eq!(
                    engine.info(),
                    format!(
                        "PoW (difficulty: {}, binary target: {} leading zero bits)",
                        $diff,
                        $diff * 4
                    )
                );
            }
        )*
    }
}

gen_pow_difficulty_tests!(
    pow_diff_1, 1, pow_diff_2, 2, pow_diff_3, 3, pow_diff_4, 4, pow_diff_5, 5
);

// Meaningful variations of chain tests
#[test]
fn chain_boundary_index_zero() {
    let consensus = Arc::new(PoWEngine::new(0));
    let bc = Blockchain::new(consensus, None, 45262, None);
    assert_eq!(bc.chain[0].index, 0);
}

#[test]
fn chain_genesis_balance_check() {
    let consensus = Arc::new(PoWEngine::new(0));
    let bc = Blockchain::new(consensus, None, 45262, None);
    // Devnet default allocation
    assert!(bc.state.get_balance(&Address::from([0x01; 32])) >= 1_000_000_000);
}

// The forty copies of one block-production test are one loop over
// the producer addresses. Same assertions per address, no macro stamp-out.
#[test]
fn block_production_works_across_producer_addresses() {
    for idx in 1u8..=40 {
        let consensus = Arc::new(PoWEngine::new(0));
        let mut bc = Blockchain::new(consensus, None, 45262, None);
        let p = addr(idx);
        let res = bc.produce_block(p);
        assert!(res.is_some(), "production must succeed for producer {idx}");
        assert_eq!(bc.chain.len(), 2);
    }
}
