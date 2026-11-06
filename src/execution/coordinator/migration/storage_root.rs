//! Reconstructs an Ethereum storage trie from a complete set of proven slots.
//!
//! Individual inclusion proofs do not prove completeness. Finalization therefore
//! rebuilds the secure trie from every imported slot and requires its root to
//! equal the account proof's `storageRoot`. A partial import cannot finalize.

use std::collections::BTreeMap;

use crate::cross_domain::evm::mpt;
use crate::cross_domain::evm::rlp::{self, Item};

/// Computes the canonical storage root from `(slot, value)` pairs.
///
/// Ethereum hashes each 32-byte slot before inserting it into the trie. A zero
/// value is deletion and has no leaf. Every nonzero value is the RLP encoding
/// of its minimal big-endian byte string.
#[must_use]
pub fn compute_storage_root(storage: &BTreeMap<[u8; 32], [u8; 32]>) -> [u8; 32] {
    let entries: BTreeMap<[u8; 32], Vec<u8>> = storage
        .iter()
        .filter(|(_, value)| **value != [0u8; 32])
        .map(|(slot, value)| {
            (
                mpt::keccak256(slot),
                rlp::encode(&Item::String(minimal_word(value))),
            )
        })
        .collect();
    if entries.is_empty() {
        return mpt::keccak256(&rlp::encode(&Item::String(Vec::new())));
    }
    let entries: Vec<TrieEntry> = entries
        .into_iter()
        .map(|(key, value)| TrieEntry {
            path: mpt::to_nibbles(&key),
            value,
        })
        .collect();
    let root = build_node(&entries, 0);
    mpt::keccak256(&rlp::encode(&root))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrieEntry {
    path: Vec<u8>,
    value: Vec<u8>,
}

/// Builds one node from entries sorted by their complete 64-nibble paths.
fn build_node(entries: &[TrieEntry], depth: usize) -> Item {
    debug_assert!(!entries.is_empty());
    debug_assert!(entries.windows(2).all(|pair| pair[0].path < pair[1].path));
    if entries.len() == 1 {
        return leaf(&entries[0].path[depth..], entries[0].value.clone());
    }

    let shared = shared_prefix_len(entries, depth);
    if shared > depth {
        let child = build_node(entries, shared);
        return Item::List(vec![
            Item::String(mpt::hp_encode(&entries[0].path[depth..shared], false)),
            node_reference(child),
        ]);
    }

    let mut children: Vec<Option<Item>> = (0..16).map(|_| None).collect();
    let mut start = 0usize;
    while start < entries.len() {
        let nibble = entries[start].path[depth];
        let mut end = start + 1;
        while end < entries.len() && entries[end].path[depth] == nibble {
            end += 1;
        }
        children[usize::from(nibble)] = Some(build_node(&entries[start..end], depth + 1));
        start = end;
    }
    let mut fields: Vec<Item> = children
        .into_iter()
        .map(|child| child.map_or_else(|| Item::String(Vec::new()), node_reference))
        .collect();
    // Fixed-width hashed keys cannot terminate at a branch with two entries.
    fields.push(Item::String(Vec::new()));
    Item::List(fields)
}

fn shared_prefix_len(entries: &[TrieEntry], depth: usize) -> usize {
    let first = &entries[0].path;
    let last = &entries[entries.len() - 1].path;
    let limit = first.len().min(last.len());
    (depth..limit)
        .take_while(|index| first[*index] == last[*index])
        .last()
        .map_or(depth, |index| index + 1)
}

fn leaf(path: &[u8], value: Vec<u8>) -> Item {
    Item::List(vec![
        Item::String(mpt::hp_encode(path, true)),
        Item::String(value),
    ])
}

/// A child shorter than 32 encoded bytes is inline; otherwise it is hashed.
fn node_reference(node: Item) -> Item {
    let encoded = rlp::encode(&node);
    if encoded.len() < 32 {
        node
    } else {
        Item::String(mpt::keccak256(&encoded).to_vec())
    }
}

fn minimal_word(value: &[u8; 32]) -> Vec<u8> {
    let first = value.iter().position(|byte| *byte != 0).unwrap_or(32);
    value[first..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(last: u8) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[31] = last;
        value
    }

    fn manual_leaf(slot: &[u8; 32], value: [u8; 32]) -> Vec<u8> {
        let path = mpt::hp_encode(&mpt::to_nibbles(&mpt::keccak256(slot)), true);
        rlp::encode(&Item::List(vec![
            Item::String(path),
            Item::String(rlp::encode(&Item::String(minimal_word(&value)))),
        ]))
    }

    #[test]
    fn empty_storage_has_the_canonical_empty_trie_root() {
        assert_eq!(
            hex::encode(compute_storage_root(&BTreeMap::new())),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn one_slot_matches_an_independently_built_leaf_and_zero_is_absent() {
        let slot = [0x42u8; 32];
        let leaf = manual_leaf(&slot, value(7));
        let storage = BTreeMap::from([(slot, value(7))]);
        assert_eq!(compute_storage_root(&storage), mpt::keccak256(&leaf));
        assert_eq!(
            compute_storage_root(&BTreeMap::from([(slot, [0u8; 32])])),
            compute_storage_root(&BTreeMap::new())
        );
    }

    #[test]
    fn extension_and_inline_branch_encoding_match_a_manual_trie() {
        let entries = vec![
            TrieEntry {
                path: vec![0, 1],
                value: vec![1],
            },
            TrieEntry {
                path: vec![0, 2],
                value: vec![2],
            },
        ];
        let first_leaf = leaf(&[], vec![1]);
        let second_leaf = leaf(&[], vec![2]);
        let mut fields: Vec<Item> = (0..16)
            .map(|index| match index {
                1 => first_leaf.clone(),
                2 => second_leaf.clone(),
                _ => Item::String(Vec::new()),
            })
            .collect();
        fields.push(Item::String(Vec::new()));
        let branch = Item::List(fields);
        let extension = Item::List(vec![
            Item::String(mpt::hp_encode(&[0], false)),
            Item::String(mpt::keccak256(&rlp::encode(&branch)).to_vec()),
        ]);
        assert_eq!(
            mpt::keccak256(&rlp::encode(&build_node(&entries, 0))),
            mpt::keccak256(&rlp::encode(&extension))
        );
    }

    #[test]
    fn adding_a_slot_changes_the_root_and_omitting_it_cannot_reproduce_it() {
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        let complete = BTreeMap::from([(first, value(1)), (second, value(2))]);
        let partial = BTreeMap::from([(first, value(1))]);
        // Independently generated with py-trie's HexaryTrie.
        assert_eq!(
            hex::encode(compute_storage_root(&complete)),
            "4c78f36c95677bfff06e5e4c367c53fbf230c81dcba95e905bf90ce13f64ebbe"
        );
        assert_eq!(
            hex::encode(compute_storage_root(&partial)),
            "39898e1d5b8c286eaaa0efd7e4c24d8002e57cc86895895f250cfb1eb7d2b0d4"
        );
    }
}
