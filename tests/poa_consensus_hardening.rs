//! Regression tests for PoAEngine fork-choice signature, linkage, and VRF-free
//! chain verification.

use budlum_core::consensus::poa::{PoAConfig, PoAEngine};
use budlum_core::consensus::{ConsensusEngine, MIN_BLOCK_INTERVAL_MS};
use budlum_core::core::account::{AccountState, Validator};
use budlum_core::core::address::Address;
use budlum_core::core::block::Block;
use budlum_core::crypto::primitives::KeyPair;

#[test]
fn poa_fork_choice_refuses_unsigned_unlinked_or_unauthorized_candidate_chain() {
    let auth_kp = KeyPair::generate().expect("Ed25519 keygen");
    let auth_addr = Address::from(auth_kp.public_key_bytes());

    let mut state = AccountState::new();
    let mut val = Validator::new(auth_addr, 1_000);
    val.active = true;
    state.validators.insert(auth_addr, val);

    let engine = PoAEngine::with_config(PoAConfig::default(), vec![auth_addr], Some(auth_kp));

    let mut genesis = Block::new_with_chain_id(0, "0".repeat(64), Vec::new(), 45_262);
    genesis.timestamp = 10_000;
    genesis.hash = genesis.calculate_hash();

    let mut b1 = Block::new_with_chain_id(1, genesis.hash.clone(), Vec::new(), 45_262);
    b1.timestamp = genesis.timestamp + MIN_BLOCK_INTERVAL_MS;
    engine
        .prepare_block_with_chain(&mut b1, &state, std::slice::from_ref(&genesis))
        .expect("authority signs b1");
    engine
        .validate_block(&b1, std::slice::from_ref(&genesis), &state)
        .expect("b1 validates");
    let honest_chain = vec![genesis.clone(), b1];

    // Attack: 4-block unsigned candidate chain with valid hashes & links but NO authority signatures!
    let mut unsigned_chain = vec![genesis];
    for h in 1..=3u64 {
        let prev = unsigned_chain.last().expect("prev").clone();
        let mut fake = Block::new_with_chain_id(h, prev.hash, Vec::new(), 45_262);
        fake.timestamp = prev.timestamp + MIN_BLOCK_INTERVAL_MS;
        fake.hash = fake.calculate_hash();
        unsigned_chain.push(fake);
    }

    assert!(
        engine.fork_choice_score(&honest_chain) > 0,
        "honest signed PoA chain must score > 0"
    );
    assert_eq!(
        engine.fork_choice_score(&unsigned_chain),
        0,
        "unsigned PoA candidate chain must score 0, not chain.len()"
    );
    assert!(
        !engine.is_better_chain(&honest_chain, &unsigned_chain),
        "unsigned PoA candidate chain must never beat an authority-signed PoA chain"
    );
}
