//! Regression tests for witness-retention genesis/zero-window/inverted-tip
//! guards and sparse state-trie zero-root refusal.

use budlum_core::persistence::state_trie::MerkleProof;
use budlum_core::persistence::witness_retention::{may_prune, NodeKind};

#[test]
fn witness_retention_never_prunes_genesis_zero_window_or_inverted_finality() {
    // Genesis block (height 0) witness must never be pruned.
    assert!(
        !may_prune(NodeKind::Normal, 0, 1_000, 2_000, 64),
        "genesis witness at height 0 must never be pruned"
    );
    // Zero retention window must fail closed instead of deleting at tip.
    assert!(
        !may_prune(NodeKind::Normal, 100, 100, 100, 0),
        "retention_blocks == 0 must not prune finalized tip witness"
    );
    // Corrupted state where finalized_height > tip_height must fail closed.
    assert!(
        !may_prune(NodeKind::Normal, 100, 500, 200, 10),
        "finalized_height > tip_height is inconsistent and must refuse pruning"
    );
}

#[test]
fn state_trie_merkle_proof_refuses_all_zero_expected_root() {
    let fake_proof = MerkleProof {
        address: [0u8; 32],
        siblings: vec![[0u8; 32]; 256],
        directions: vec![false; 256],
        leaf_hash: [0u8; 32],
    };
    assert!(
        !fake_proof.verify(&[0u8; 32]),
        "all-zero [0u8; 32] expected_root is never a domain-prefixed trie root"
    );
}
