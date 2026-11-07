//! Reconstructs an Ethereum storage trie from a complete set of proven slots.
//!
//! Individual inclusion proofs do not prove completeness. Finalization rebuilds
//! the secure Merkle-Patricia trie from every imported slot and requires its root
//! to equal the proven `storageRoot`.

use crate::cross_domain::evm::mpt;
use crate::cross_domain::evm::rlp::{self, Item};
use std::collections::BTreeMap;

/// Computes the canonical Ethereum storage root from `(slot, value)` pairs.
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

fn build_node(entries: &[TrieEntry], depth: usize) -> Item {
    if let [single] = entries {
        let suffix = single.path.get(depth..).unwrap_or(&[]);
        return leaf(suffix, single.value.clone());
    }
    let Some(head) = entries.first() else {
        return Item::String(Vec::new());
    };

    let shared = shared_prefix_len(entries, depth);
    if shared > depth {
        let child = build_node(entries, shared);
        let seg = head.path.get(depth..shared).unwrap_or(&[]);
        return Item::List(vec![
            Item::String(mpt::hp_encode(seg, false)),
            node_reference(child),
        ]);
    }

    let mut children: Vec<Option<Item>> = (0..16).map(|_| None).collect();
    let mut rest = entries;
    while let Some(first_entry) = rest.first() {
        let Some(&nibble) = first_entry.path.get(depth) else {
            break;
        };
        let group_len = rest.partition_point(|e| e.path.get(depth) == Some(&nibble));
        let (group, tail) = rest.split_at(group_len.max(1));
        if let Some(slot) = children.get_mut(usize::from(nibble)) {
            *slot = Some(build_node(group, depth + 1));
        }
        rest = tail;
    }

    let mut fields: Vec<Item> = children
        .into_iter()
        .map(|child| child.map_or_else(|| Item::String(Vec::new()), node_reference))
        .collect();
    fields.push(Item::String(Vec::new()));
    Item::List(fields)
}

fn shared_prefix_len(entries: &[TrieEntry], depth: usize) -> usize {
    let (Some(first), Some(last)) = (entries.first(), entries.last()) else {
        return depth;
    };
    let a = first.path.get(depth..).unwrap_or(&[]);
    let b = last.path.get(depth..).unwrap_or(&[]);
    let matched = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
    depth + matched
}

fn leaf(path: &[u8], value: Vec<u8>) -> Item {
    Item::List(vec![
        Item::String(mpt::hp_encode(path, true)),
        Item::String(value),
    ])
}

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
    value.get(first..).unwrap_or(&[]).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(last: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = last;
        out
    }

    #[test]
    fn empty_and_populated_storage_roots_are_deterministic() {
        let empty = compute_storage_root(&BTreeMap::new());
        assert_eq!(
            hex::encode(empty),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
        let mut map = BTreeMap::new();
        map.insert([0x01u8; 32], value(7));
        map.insert([0x02u8; 32], value(9));
        let r1 = compute_storage_root(&map);
        map.insert([0x03u8; 32], [0u8; 32]);
        let r2 = compute_storage_root(&map);
        assert_eq!(r1, r2);
    }
    fn manual_leaf(slot: &[u8; 32], value: [u8; 32]) -> Vec<u8> {
        let path = mpt::hp_encode(&mpt::to_nibbles(&mpt::keccak256(slot)), true);
        rlp::encode(&Item::List(vec![
            Item::String(path),
            Item::String(rlp::encode(&Item::String(minimal_word(&value)))),
        ]))
    }

    #[test]
    fn one_slot_matches_an_independently_built_leaf() {
        let slot = [0x42u8; 32];
        let leaf = manual_leaf(&slot, value(7));
        assert_eq!(
            compute_storage_root(&BTreeMap::from([(slot, value(7))])),
            mpt::keccak256(&leaf)
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
        let mut fields: Vec<Item> = (0..16)
            .map(|index| match index {
                1 => leaf(&[], vec![1]),
                2 => leaf(&[], vec![2]),
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
    fn complete_and_partial_storage_have_distinct_independent_roots() {
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        let complete = BTreeMap::from([(first, value(1)), (second, value(2))]);
        let partial = BTreeMap::from([(first, value(1))]);
        // Independently generated with an external HexaryTrie implementation.
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
