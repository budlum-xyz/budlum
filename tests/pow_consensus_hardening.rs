//! Regression tests for PoW contiguous block height validation and verified
//! proof-of-work enforcement in fork-choice comparisons.

use budlum_core::consensus::pow::PoWEngine;
use budlum_core::consensus::ConsensusEngine;
use budlum_core::core::account::AccountState;
use budlum_core::core::block::Block;

#[test]
fn pow_validate_block_refuses_height_skip_and_fork_choice_refuses_unmined_candidate() {
    let engine = PoWEngine::new(2);
    let state = AccountState::new();

    let mut genesis = Block::new_with_chain_id(0, "0".repeat(64), Vec::new(), 45_262);
    genesis.timestamp = 1_000;
    genesis.hash = genesis.calculate_hash();

    let mut b1 = Block::new_with_chain_id(1, genesis.hash.clone(), Vec::new(), 45_262);
    b1.timestamp = 2_000;
    engine.prepare_block(&mut b1, &state).expect("mine b1");
    let honest_chain = vec![genesis.clone(), b1.clone()];
    assert!(engine
        .validate_block(&b1, std::slice::from_ref(&genesis), &state)
        .is_ok());

    // 1. Mined block jumping from height 1 directly to height 500 must be refused!
    let mut skipped = Block::new_with_chain_id(500, b1.hash.clone(), Vec::new(), 45_262);
    skipped.timestamp = 3_000;
    engine
        .prepare_block(&mut skipped, &state)
        .expect("mine skipped");
    assert!(
        engine
            .validate_block(&skipped, &honest_chain, &state)
            .is_err(),
        "PoW block skipping from height 1 to 500 must be refused by validate_block"
    );

    // 2. Unmined candidate chain of 5 blocks (0 PoW work performed!) must NEVER beat honest mined chain!
    let mut fake_chain = vec![genesis];
    for h in 1..=4u64 {
        let prev = fake_chain.last().expect("prev").hash.clone();
        let mut unmined = Block::new_with_chain_id(h, prev, Vec::new(), 45_262);
        unmined.timestamp = 1_000 + u128::from(h) * 1_000;
        // Force a non-zero leading nibble by tweaking nonce if needed so meets_difficulty(2) is false
        unmined.hash = unmined.calculate_hash();
        while unmined.hash.starts_with("00") {
            unmined.nonce += 1;
            unmined.hash = unmined.calculate_hash();
        }
        fake_chain.push(unmined);
    }
    assert!(
        !engine.is_better_chain(&honest_chain, &fake_chain),
        "unmined zero-work PoW chain must never beat an honestly mined PoW chain in is_better_chain"
    );
}
