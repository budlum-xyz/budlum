//! Reconstructs an Ethereum storage trie from a complete set of proven slots.
//!
//! Individual inclusion proofs do not prove completeness. Finalization rebuilds
//! the secure Merkle-Patricia trie from every imported slot and requires its root
//! to equal the proven `storageRoot`.
//! Convenience: public Ethereum secure MPT storage-root reconstructor (WP-34).

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
}
