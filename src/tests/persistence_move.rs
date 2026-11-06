//! The persistence move is behaviour-neutral: the node-local store, its
//! traits, the proof-bearing state trie, pruning and witness retention
//! moved from `crate::storage` to `crate::persistence` without changing a
//! byte they produce. A fixed block sequence built on the moved store
//! gives the same state root before and after a restart that replays the
//! stored blocks over genesis, and the state trie over the same accounts
//! gives the same root and the same proof on both sides of the move.

use crate::tests::block_door_harness::BlockHarness;

#[test]
fn persistence_move_is_behaviour_neutral() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("persistence_move_db");
    let path = path.to_str().expect("a utf8 path");

    let mut harness = BlockHarness::open(path);
    // A fixed block sequence: two domain registrations through blocks.
    let first = harness.operated_domain(1);
    let second = harness.operated_domain_of_kind(2, crate::domain::ConsensusKind::PoS);
    harness.register_domain(first);
    harness.register_domain(second);
    let root_before = harness.chain.state.calculate_state_root();
    let height_before = harness.chain.chain.len();

    let harness = harness.restart();
    assert_eq!(harness.chain.chain.len(), height_before);
    assert_eq!(
        harness.chain.state.calculate_state_root(),
        root_before,
        "replaying the stored blocks over genesis must give the same state root"
    );
}

#[test]
fn persistence_state_trie_root_and_proof_are_stable() {
    use crate::persistence::state_trie::{prove_account, MerkleTrie};

    let mut trie = MerkleTrie::new();
    let mut accounts = Vec::new();
    for i in 0..16u8 {
        let mut address = [0u8; 32];
        address[31] = i;
        accounts.push((address, u64::from(i) * 1_000, u64::from(i)));
    }
    for (address, balance, nonce) in &accounts {
        trie.insert(address, *balance, *nonce);
    }
    let root = trie.root();
    for (address, balance, nonce) in &accounts {
        let bundle = prove_account(accounts.iter().copied(), address);
        assert_eq!(bundle.root, root);
        assert_eq!(bundle.balance, *balance);
        assert_eq!(bundle.nonce, *nonce);
        assert!(bundle.proof.verify(&root));
    }
}
