//! the global header is a consensus object.
//!
//! The transition of every finality checkpoint block builds the header from
//! the state at the end of that block, and the state root commits its hash.
//! Four nodes that apply the same blocks therefore hold the same header
//! sequence and the same state roots, and a node that restarts rebuilds the
//! sequence by replaying its stored blocks.

use crate::chain::blockchain::Blockchain;
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;
use crate::storage::db::Storage;
use std::sync::Arc;

const CHAIN_ID: u64 = 45262;

fn node(storage: Option<Storage>) -> Blockchain {
    Blockchain::new(Arc::new(PoWEngine::new(0)), storage, CHAIN_ID, None)
}

fn header_hashes(chain: &Blockchain) -> Vec<[u8; 32]> {
    chain
        .state
        .settlement
        .global_headers
        .iter()
        .map(crate::settlement::GlobalBlockHeader::calculate_hash_bytes)
        .collect()
}

/// Produce `blocks` blocks on `producer` and import each into `followers`.
fn run(producer: &mut Blockchain, followers: &mut [Blockchain], blocks: usize) {
    for _ in 0..blocks {
        let (block, _) = producer
            .produce_block(Address::from([0x11; 32]))
            .expect("a block is produced");
        for follower in followers.iter_mut() {
            follower
                .validate_and_add_block(block.clone())
                .expect("a follower imports the producer's block");
        }
    }
}

#[test]
fn four_nodes_build_the_same_global_header_sequence() {
    let interval = crate::core::chain_config::finality_checkpoint_interval_for_chain_id(CHAIN_ID);
    let blocks = usize::try_from(interval.saturating_mul(3)).expect("a small interval");
    let mut producer = node(None);
    let mut followers = vec![node(None), node(None), node(None)];
    run(&mut producer, &mut followers, blocks);

    let expected = header_hashes(&producer);
    assert!(
        expected.len() >= 3,
        "three checkpoints passed, so three headers were built, got {}",
        expected.len()
    );
    let summary = producer.state.global_header_summary;
    assert_eq!(Some(&summary), expected.last());
    for follower in &followers {
        assert_eq!(header_hashes(follower), expected);
        assert_eq!(follower.state.global_header_summary, summary);
        assert_eq!(
            follower.last_block().state_root,
            producer.last_block().state_root
        );
    }

    // Each header names the checkpoint it was built at and links to the one
    // before it.
    let headers: Vec<_> = producer.state.settlement.global_headers.iter().collect();
    for pair in headers.windows(2) {
        if let [previous, next] = pair {
            assert_eq!(next.previous_global_hash, previous.calculate_hash_bytes());
            assert_eq!(next.global_height, previous.global_height.saturating_add(1));
            assert_eq!(next.checkpoint_height % interval, 0);
        }
    }
}

#[test]
fn a_restart_rebuilds_the_same_global_header_sequence() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("global_header_sequence.db");
    let path = path.to_str().expect("a utf-8 path");
    let interval = crate::core::chain_config::finality_checkpoint_interval_for_chain_id(CHAIN_ID);
    let blocks = usize::try_from(interval.saturating_mul(2)).expect("a small interval");

    let (expected, root) = {
        let mut producer = node(Some(Storage::new(path).expect("the store opens")));
        run(&mut producer, &mut [], blocks);
        (
            header_hashes(&producer),
            producer.last_block().state_root.clone(),
        )
    };
    assert!(!expected.is_empty());

    let restarted = node(Some(Storage::new(path).expect("the store reopens")));
    assert_eq!(header_hashes(&restarted), expected);
    assert_eq!(restarted.last_block().state_root, root);
}

#[test]
fn state_window_is_authoritative_for_header_reads_and_previews() {
    let interval = crate::core::chain_config::finality_checkpoint_interval_for_chain_id(CHAIN_ID);
    let blocks = usize::try_from(interval).expect("a small interval");
    let mut chain = node(None);
    run(&mut chain, &mut [], blocks);

    let committed = chain
        .state
        .settlement
        .global_headers
        .latest()
        .cloned()
        .expect("one checkpoint header");

    // A snapshot can restore the consensus window before the node-local
    // archive has been rebuilt. Reads must use the state-rooted copy, not an
    // absent or stale local archive.
    chain.global_headers.clear();
    assert_eq!(
        chain.global_header(committed.global_height),
        Some(committed.clone())
    );

    let preview = chain.build_global_header(None);
    assert_eq!(
        preview.global_height,
        committed.global_height.saturating_add(1)
    );
    assert_eq!(
        preview.previous_global_hash,
        committed.calculate_hash_bytes()
    );
}
