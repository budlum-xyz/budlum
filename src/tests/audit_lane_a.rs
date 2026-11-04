//! Lane A live-verification regression tests (WP-01 to WP-04).
//!
//! Only "previously fixed" findings live here: each test is green and stays
//! permanent (directive section 14.1 rule 7). Repro tests for findings that are
//! still open live on the `audit/repro-a` branch and do not merge.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use std::sync::Arc;

/// Source of a production file with its `#[cfg(test)]` tail cut off, so a
/// source-scan assertion never matches a test fixture.
fn production_part(src: &str) -> &str {
    src.split("#[cfg(test)]").next().unwrap_or(src)
}

/// BLG-001: a slot whose round-0 election is empty must be able to re-roll.
/// The round is part of the VRF seed (a fresh draw per round), and the round
/// ladder is priced by the parent's timestamp and capped.
#[test]
fn audit_lane_a_blg_001_leader_round_rerolls_seed_and_ladder_is_capped() {
    use crate::consensus::pos::{PoSConfig, PoSEngine};
    use crate::consensus::{
        affordable_leader_round, MAX_LEADER_ROUNDS, MIN_BLOCK_INTERVAL_MS, ROUND_TIMEOUT_MS,
    };
    use crate::core::block::Block;

    let engine = PoSEngine::new(PoSConfig::default(), None);
    let chain = vec![Block::genesis()];
    let chain_id = crate::core::transaction::DEFAULT_CHAIN_ID;
    let r0 = engine
        .calculate_seed_with_chain(chain_id, 0, 1, 0, &chain)
        .unwrap();
    let r1 = engine
        .calculate_seed_with_chain(chain_id, 0, 1, 1, &chain)
        .unwrap();
    assert_ne!(r0, r1, "round must change the seed so an empty slot re-rolls");
    assert!(
        engine
            .calculate_seed_with_chain(chain_id, 0, 1, MAX_LEADER_ROUNDS + 1, &chain)
            .is_err(),
        "rounds above the cap are refused"
    );

    let parent = 1_000_000u128;
    assert_eq!(affordable_leader_round(parent, parent), 0);
    assert_eq!(
        affordable_leader_round(parent, parent + MIN_BLOCK_INTERVAL_MS + ROUND_TIMEOUT_MS),
        1
    );
    assert_eq!(
        affordable_leader_round(parent, parent + 10_000_000_000),
        MAX_LEADER_ROUNDS
    );
    // A parent stamped in the future pins the ladder at round 0, not a panic.
    assert_eq!(affordable_leader_round(parent + 50_000, parent), 0);
}

/// BLG-017: a peer-controlled hash string in a vote log line must never be
/// cut at a byte offset (a multi-byte character on the cut would panic and
/// abort a release node). Source-level lock: the in-file behavioural test is
/// `network::node::tests::log_prefix_survives_multibyte_input`.
#[test]
fn audit_lane_a_blg_017_no_utf8_byte_slice_of_peer_strings_in_vote_handlers() {
    let node = production_part(include_str!("../network/node.rs"));
    assert!(node.contains("fn log_prefix(s: &str, max_chars: usize)"));
    assert!(
        node.matches("log_prefix(&checkpoint_hash, 16)").count() >= 3,
        "Prevote, Precommit and FinalityCert handlers log through log_prefix"
    );
    for forbidden in ["checkpoint_hash[..", "voter_id[..", "&block.hash[.."] {
        assert!(
            !node.contains(forbidden),
            "byte slice `{forbidden}` of a peer string found in network/node.rs"
        );
    }
}

/// BLG-019: `TransactionType::StateUpdate` no longer writes any account
/// nonce. Every sender is refused with `state_update_retired` before any
/// state is touched (commitment nonce writes belong to the settlement door).
#[test]
fn audit_lane_a_blg_019_state_update_is_retired_for_every_sender() {
    use crate::core::transaction::{Transaction, TransactionType};
    let mut node = Blockchain::new(Arc::new(PoWEngine::new(0)), None, 45262, None);
    let attacker = Address::from([0xAD; 32]);
    let victim = Address::from([0xB0; 32]);
    node.state.add_balance(&attacker, 1_000_000);
    node.state.add_balance(&victim, 500);
    let tx = Transaction::new_with_chain_id(
        attacker,
        Address::zero(),
        0,
        1,
        node.state.get_nonce(&attacker),
        Vec::new(),
        45262,
        TransactionType::StateUpdate {
            domain_id: 1,
            domain_height: 1,
            state_updates: vec![(victim, u64::MAX - 1001)],
        },
    );
    let err = crate::execution::executor::Executor::apply_transaction_checked(&mut node.state, &tx)
        .expect_err("StateUpdate must be refused");
    assert_eq!(err.code(), "state_update_retired");
    assert_eq!(node.state.get_nonce(&victim), 0, "victim nonce untouched");
}

/// BLG-020: the block producer executes every candidate transaction against a
/// disposable copy and publishes it only on success, so a transaction that
/// fails halfway cannot leave partial writes in the selection prefix.
/// Source-level lock (the failing-halfway fixture needs a bespoke executor
/// arm); the residual `Executor` has no nonce or signature check of its own is
/// recorded in the lane file.
#[test]
fn audit_lane_a_blg_020_producer_executes_on_a_disposable_candidate_state() {
    let src = production_part(include_str!("../chain/blockchain.rs"));
    let start = src
        .find("fn collect_block_transactions(")
        .expect("collect_block_transactions exists");
    let body = &src[start..start + 9000.min(src.len() - start)];
    let clone_at = body
        .find("let mut candidate_state = temp_state.clone();")
        .expect("candidate copy");
    let apply_at = body
        .find("Executor::apply_transaction_checked(&mut candidate_state, tx)")
        .expect("apply on the candidate, not on temp_state");
    let publish_at = body
        .find("temp_state = candidate_state;")
        .expect("publish only after success");
    assert!(clone_at < apply_at && apply_at < publish_at);
    assert!(
        !body.contains("Executor::apply_transaction_checked(&mut temp_state"),
        "the producer must never execute straight on the selection prefix"
    );
}

/// BLG-021: a bond adds to an existing role stake (no override), and the
/// out-of-block RPC doors that wrote the registry on one node are refused.
#[test]
fn audit_lane_a_blg_021_role_bond_is_additive_and_rpc_doors_are_refused() {
    use crate::core::account::AccountState;
    use crate::registry::role::roles;
    let mut state = AccountState::new();
    let who = Address::from([0x21; 32]);
    state.add_balance(&who, 10_000_000);
    let min = state.registry.params().min_stake;
    state.bond_relayer(&who, min).unwrap();
    state.bond_relayer(&who, 7).unwrap();
    assert_eq!(
        state.registry.get(&who, roles::RELAYER).unwrap().stake,
        min + 7,
        "a second bond must add to the stake, not replace it"
    );
    assert_eq!(state.get_balance(&who), 10_000_000 - min - 7);

    let rpc = production_part(include_str!("../rpc/server.rs"));
    assert!(rpc.contains("Out-of-block relayer bonding is refused"));
    assert!(rpc.contains("Out-of-block prover bonding is refused"));
    assert!(rpc.contains("Out-of-block role unbonding is refused"));
}
