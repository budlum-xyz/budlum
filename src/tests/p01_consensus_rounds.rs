//! P01 consensus-round behaviour (BLG-0006/0007/0009/0017/0029) and the P01
//! negative-validation batch (BLG-0028).
//!
//! The round rule is shared by PoS and PoA: the block nonce carries the
//! leader round, the round is capped at [`MAX_LEADER_ROUNDS`], and a round
//! `r > 0` must sit at least `MIN_BLOCK_INTERVAL_MS + r * ROUND_TIMEOUT_MS`
//! after its parent. These tests pin the pieces the older suite never
//! exercised: the round binding in the seed and threshold, the cap and floor
//! refusals, checkpoint parking until quorum finality, and the missing
//! negative cases named by P01-F19.

use crate::consensus::poa::{PoAConfig, PoAEngine};
use crate::consensus::pos::{PoSConfig, PoSEngine};
use crate::consensus::pow::{PoWConfig, PoWEngine};
use crate::consensus::ConsensusEngine;
use crate::consensus::{MAX_LEADER_ROUNDS, MIN_BLOCK_INTERVAL_MS, ROUND_TIMEOUT_MS};
use crate::core::account::{AccountState, Validator};
use crate::core::address::Address;
use crate::core::block::Block;
use crate::crypto::primitives::ValidatorKeys;

/// A state holding exactly one fully consensus-ready validator (real VRF,
/// BLS + PoP and PQ keys), so validation reaches the round logic instead of
/// failing at the key checks.
fn ready_validator_state(keys: &ValidatorKeys) -> (AccountState, Address) {
    let address = Address::from(keys.sig_key.public_key_bytes());
    let mut state = AccountState::new();
    state.add_validator(address, 2_000);
    let bls = keys.bls_key.as_ref().expect("fixture has BLS keys");
    let pop = bls.generate_pop(crate::core::transaction::DEFAULT_CHAIN_ID, &address);
    if let Some(validator) = state.get_validator_mut(&address) {
        validator.vrf_public_key = keys.vrf_key.public.to_bytes().to_vec();
        validator.bls_public_key = bls.public_key.clone();
        validator.pop_signature = pop;
        validator.pq_public_key = keys
            .pq_key
            .as_ref()
            .expect("fixture has PQ keys")
            .public_key_bytes()
            .to_vec();
        validator.active = true;
    }
    (state, address)
}

/// A one-validator state with only what leader selection needs (PoA).
fn poa_state_with(addresses: &[Address]) -> AccountState {
    let mut state = AccountState::new();
    for address in addresses {
        state
            .validators
            .insert(*address, Validator::new(*address, 1_000));
        state.validators.get_mut(address).unwrap().active = true;
    }
    state
}

#[test]
fn pos_seed_binds_the_round() {
    let engine = PoSEngine::new(PoSConfig::default(), None);
    let chain = vec![Block::genesis()];
    let chain_id = crate::core::transaction::DEFAULT_CHAIN_ID;
    let round0 = engine
        .calculate_seed_with_chain(chain_id, 0, 1, 0, &chain)
        .unwrap();
    let round1 = engine
        .calculate_seed_with_chain(chain_id, 0, 1, 1, &chain)
        .unwrap();
    let round1_again = engine
        .calculate_seed_with_chain(chain_id, 0, 1, 1, &chain)
        .unwrap();
    assert_ne!(
        round0, round1,
        "the round must re-roll the leader seed (P01-F01)"
    );
    assert_eq!(round1, round1_again, "the seed must stay deterministic");
}

#[test]
fn pos_vrf_threshold_widens_with_the_round() {
    let engine = PoSEngine::new(PoSConfig::default(), None);
    let base = engine.calculate_vrf_threshold_for_round(1_000, 4_000, 0);
    let round1 = engine.calculate_vrf_threshold_for_round(1_000, 4_000, 1);
    let round_cap = engine.calculate_vrf_threshold_for_round(1_000, 4_000, MAX_LEADER_ROUNDS);
    assert_eq!(
        round1,
        base.saturating_mul(2),
        "round 1 must double the threshold (P01-F01)"
    );
    assert_eq!(
        round_cap,
        base.saturating_mul(MAX_LEADER_ROUNDS + 1),
        "the cap round must price at (cap + 1)x"
    );
}

#[test]
fn pos_validate_rejects_round_above_the_cap() {
    let keys = ValidatorKeys::generate().unwrap();
    let (state, address) = ready_validator_state(&keys);
    let engine = PoSEngine::new(PoSConfig::default(), None);
    let parent = Block::genesis();

    let mut block = Block::new(1, parent.hash.clone(), vec![]);
    block.slot = block.index;
    block.producer = Some(address);
    block.nonce = MAX_LEADER_ROUNDS + 1;
    block.validator_set_hash = state
        .consensus_validator_set_hash(block.chain_id)
        .expect("fixture keys are consensus-ready");
    block.sign(&keys.sig_key);

    let error = engine
        .validate_block(&block, &[parent], &state)
        .expect_err("a round above the cap must be refused");
    assert!(
        error.0.contains("exceeds the cap"),
        "the refusal must name the cap, got: {error:?}"
    );
}

#[test]
fn pos_validate_rejects_a_premature_round_timestamp() {
    let keys = ValidatorKeys::generate().unwrap();
    let (state, address) = ready_validator_state(&keys);
    let engine = PoSEngine::new(PoSConfig::default(), None);
    let mut parent = Block::genesis();
    parent.timestamp = 1_000_000;
    parent.hash = parent.calculate_hash();

    // Round 2 prices at parent + 1s + 2x3s. One second after the parent is
    // far too early (P01-F20).
    let mut block = Block::new(1, parent.hash.clone(), vec![]);
    block.slot = block.index;
    block.timestamp = parent.timestamp + MIN_BLOCK_INTERVAL_MS;
    block.producer = Some(address);
    block.nonce = 2;
    block.validator_set_hash = state
        .consensus_validator_set_hash(block.chain_id)
        .expect("fixture keys are consensus-ready");
    block.sign(&keys.sig_key);

    let error = engine
        .validate_block(&block, &[parent], &state)
        .expect_err("a premature round must be refused");
    assert!(
        error.0.contains("claimed too early"),
        "the refusal must name the timing floor, got: {error:?}"
    );
}

#[test]
fn pos_round_floor_matches_the_pricing_formula() {
    // The floor is part of consensus now: parent + MIN_BLOCK_INTERVAL_MS +
    // round * ROUND_TIMEOUT_MS. Pin the constants so a silent change cannot
    // reprice every round.
    assert_eq!(MIN_BLOCK_INTERVAL_MS, 1_000);
    assert_eq!(ROUND_TIMEOUT_MS, 3_000);
    assert_eq!(MAX_LEADER_ROUNDS, 16);
}

#[test]
fn pos_checkpoint_parks_until_finalized() {
    let engine = PoSEngine::new(PoSConfig::default(), None);
    let chain_id = crate::core::transaction::DEFAULT_CHAIN_ID;
    let epoch_length = crate::core::chain_config::epoch_len_for_chain_id(chain_id);

    // A chain across two epoch boundaries (indices epoch_length and
    // 2 * epoch_length) recorded the way the commit path does.
    let producer_keys = crate::crypto::primitives::KeyPair::generate().unwrap();
    let producer = Address::from(producer_keys.public_key_bytes());
    let mut chain = vec![Block::genesis()];
    for i in 1..=(2 * epoch_length) {
        let previous = chain.last().unwrap().hash.clone();
        let mut block = Block::new(i, previous, vec![]);
        block.slot = block.index;
        block.producer = Some(producer);
        chain.push(block);
    }
    let first_boundary = chain[epoch_length as usize].clone();
    let second_boundary = chain[(2 * epoch_length) as usize].clone();

    engine
        .record_block(&first_boundary, None)
        .expect("recording the boundary block must succeed");
    assert!(
        engine.get_checkpoints().unwrap().is_empty(),
        "the boundary checkpoint must stay parked until quorum finality (P01-F04)"
    );

    // A finalised height whose chain does not hold the block must drop it,
    // not promote it.
    engine.note_finalized_height(first_boundary.index, &chain[..1], None);
    assert!(
        engine.get_checkpoints().unwrap().is_empty(),
        "a checkpoint on a losing fork must be dropped, not promoted"
    );

    // The next boundary, finalised against the chain that holds it, is
    // promoted - and only it.
    engine
        .record_block(&second_boundary, None)
        .expect("recording the boundary block must succeed");
    engine.note_finalized_height(second_boundary.index, &chain, None);
    let checkpoints = engine.get_checkpoints().unwrap();
    assert_eq!(checkpoints.len(), 1, "only the finalised checkpoint is promoted");
    assert_eq!(checkpoints[0].block_index, second_boundary.index);
    assert_eq!(checkpoints[0].block_hash, second_boundary.hash);
}

#[test]
fn poa_leader_round_changes_the_expected_proposer() {
    let mut addresses = Vec::new();
    for i in 1..=4u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        addresses.push(Address::from(bytes));
    }
    let state = poa_state_with(&addresses);
    let engine = PoAEngine::new(PoAConfig::default(), None);
    let active = state.get_active_validators();
    let entropy = [7u8; 32];

    // Over a run of slots the round must actually re-roll someone: if the
    // round term did nothing, every (slot, round) pair would name the same
    // leader (P01-F02).
    let mut changed = false;
    for slot in 0..32u64 {
        let round0 = engine
            .expected_proposer_with_entropy(slot, &active, &entropy, 0)
            .expect("active set is non-empty");
        for round in 1..=MAX_LEADER_ROUNDS {
            let later = engine
                .expected_proposer_with_entropy(slot, &active, &entropy, round)
                .expect("active set is non-empty");
            if later.address != round0.address {
                changed = true;
                break;
            }
        }
        if changed {
            break;
        }
    }
    assert!(
        changed,
        "no slot saw a leader change across rounds - the round term is not bound (P01-F02)"
    );
}

#[test]
fn pow_mining_budget_aborts_and_reports() {
    // Difficulty 32 is 2^128 work: only the budget can end this search.
    let engine = PoWEngine::with_config(PoWConfig {
        difficulty: 32,
        mine_time_budget_ms: 0,
        ..Default::default()
    });
    let mut block = Block::new(1, "0".repeat(64), vec![]);
    block.hash = block.calculate_hash();
    let error = engine
        .prepare_block(&mut block, &AccountState::new())
        .expect_err("an exhausted mining budget must abort the attempt");
    assert!(
        error.0.contains("mining budget exhausted"),
        "the refusal must name the budget, got: {error:?}"
    );
}

#[test]
fn pos_validate_rejects_wrong_validator_set_hash() {
    let keys = ValidatorKeys::generate().unwrap();
    let (state, address) = ready_validator_state(&keys);
    let engine = PoSEngine::new(PoSConfig::default(), None);
    let parent = Block::genesis();

    let mut block = Block::new(1, parent.hash.clone(), vec![]);
    block.slot = block.index;
    block.producer = Some(address);
    block.validator_set_hash = "deadbeef".repeat(8);
    block.sign(&keys.sig_key);

    let error = engine
        .validate_block(&block, &[parent], &state)
        .expect_err("a wrong validator set hash must be refused");
    assert!(
        error.0.contains("Validator set hash mismatch"),
        "got: {error:?}"
    );
}

#[test]
fn pos_validate_rejects_unknown_producer() {
    let keys = ValidatorKeys::generate().unwrap();
    let (state, _address) = ready_validator_state(&keys);
    let engine = PoSEngine::new(PoSConfig::default(), None);
    let parent = Block::genesis();

    let stranger = crate::crypto::primitives::KeyPair::generate().unwrap();
    let mut block = Block::new(1, parent.hash.clone(), vec![]);
    block.slot = block.index;
    block.producer = Some(Address::from(stranger.public_key_bytes()));
    block.validator_set_hash = state
        .consensus_validator_set_hash(block.chain_id)
        .expect("fixture keys are consensus-ready");
    block.sign(&stranger);

    let error = engine
        .validate_block(&block, &[parent], &state)
        .expect_err("an unknown producer must be refused");
    assert!(
        error.0.contains("Unknown block producer"),
        "got: {error:?}"
    );
}

#[test]
fn pos_validate_rejects_invalid_slashing_evidence() {
    let keys = ValidatorKeys::generate().unwrap();
    let (state, address) = ready_validator_state(&keys);
    let engine = PoSEngine::new(PoSConfig::default(), None);
    let parent = Block::genesis();

    let mut block = Block::new(1, parent.hash.clone(), vec![]);
    block.slot = block.index;
    block.producer = Some(address);
    block.validator_set_hash = state
        .consensus_validator_set_hash(block.chain_id)
        .expect("fixture keys are consensus-ready");
    // A real VRF so validation reaches the evidence checks behind it.
    let seed = engine
        .calculate_seed_with_chain(block.chain_id, block.epoch, block.slot, 0, &[parent.clone()])
        .expect("seed derivation succeeds");
    let (vrf_io, vrf_proof, _) = keys
        .vrf_key
        .vrf_sign(schnorrkel::context::signing_context(b"BUDLUM_VRF").bytes(&seed));
    block.vrf_output = vrf_io.to_preout().to_bytes().to_vec();
    block.vrf_proof = vrf_proof.to_bytes().to_vec();
    // Evidence over two different heights is structurally invalid.
    use crate::consensus::pos::SlashingEvidence;
    use crate::core::block::BlockHeader;
    let mut header1 = BlockHeader::from_block(&parent);
    header1.index = 5;
    let mut header2 = BlockHeader::from_block(&parent);
    header2.index = 6;
    block.slashing_evidence = Some(vec![SlashingEvidence::new(
        header1,
        header2,
        vec![0u8; 64],
        vec![1u8; 64],
    )]);
    block.sign(&keys.sig_key);

    let error = engine
        .validate_block(&block, &[parent], &state)
        .expect_err("invalid slashing evidence must be refused");
    assert!(
        error.0.contains("Invalid slashing evidence"),
        "got: {error:?}"
    );
}

#[test]
fn poa_validate_rejects_the_wrong_leader() {
    let alice = crate::crypto::primitives::KeyPair::generate().unwrap();
    let bob = crate::crypto::primitives::KeyPair::generate().unwrap();
    let alice_address = Address::from(alice.public_key_bytes());
    let bob_address = Address::from(bob.public_key_bytes());
    let state = poa_state_with(&[alice_address, bob_address]);
    let engine = PoAEngine::new(PoAConfig::default(), None);

    let mut parent = Block::genesis();
    parent.timestamp = 1_000_000;
    parent.hash = parent.calculate_hash();
    let active = state.get_active_validators();
    let entropy = crate::consensus::poa::leader_entropy(&parent.hash);
    let expected = engine
        .expected_proposer_with_entropy(1, &active, &entropy, 0)
        .expect("active set is non-empty");

    // Sign with whichever key is NOT the expected leader.
    let (wrong_key, wrong_address) = if expected.address == alice_address {
        (bob, bob_address)
    } else {
        (alice, alice_address)
    };
    let mut block = Block::new(1, parent.hash.clone(), vec![]);
    block.timestamp = parent.timestamp + MIN_BLOCK_INTERVAL_MS;
    block.producer = Some(wrong_address);
    block.nonce = 0;
    block.sign(&wrong_key);

    let error = engine
        .validate_block(&block, &[parent], &state)
        .expect_err("a block from the wrong leader must be refused");
    assert!(
        error.0.contains("expected proposer") || error.0.contains("leader"),
        "the refusal must name the leader rule, got: {error:?}"
    );
}

#[test]
fn pos_preview_binds_the_nonce_to_the_round() {
    let keys = ValidatorKeys::generate().unwrap();
    let (mut state, address) = ready_validator_state(&keys);
    state.add_balance(&address, 1);
    let engine = PoSEngine::new(
        PoSConfig {
            min_stake: 1,
            ..Default::default()
        },
        None,
    );
    let mut parent = Block::genesis();
    parent.timestamp = 1_000_000;
    parent.hash = parent.calculate_hash();

    let mut block = Block::new(1, parent.hash.clone(), vec![]);
    block.timestamp = parent.timestamp + MIN_BLOCK_INTERVAL_MS;
    block.producer = Some(address);
    let result = engine.preview_block_with_chain(&mut block, &state, &[parent.clone()]);
    if result.is_ok() {
        assert!(
            block.nonce <= MAX_LEADER_ROUNDS,
            "preview must never claim a round above the cap (P01-F10), got {}",
            block.nonce
        );
    }
}
