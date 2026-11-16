//! The sparse Merkle tree the name registry commits to.
//!
//! A name lives at the 256-bit path `SHA-256("BDLM_BNS_KEY_V1" || name)`.
//! The tree is the usual sparse tree over that key space with one
//! compression: a subtree that holds exactly one name is that name's leaf
//! node, and an empty subtree is the zero digest. So the shape depends only
//! on the set of names, never on the order they arrived in, a write touches
//! the nodes on one path, and a proof is as long as the path is deep.
//!
//! - leaf node: `SHA-256("BDLM_BNS_SMT_LEAF_V1" || key || value)`
//! - inner node: `SHA-256("BDLM_BNS_SMT_NODE_V1" || left || right)`
//! - empty subtree: `[0; 32]`
//!
//! A proof for a key is the list of sibling digests from the terminal node
//! up to the root. The terminal node is the leaf of that key (inclusion), an
//! empty subtree (absence), or the leaf of another key that shares the path
//! so far (absence: the slot is taken by a different name).

use sha2::{Digest, Sha256};

/// The digest of an empty subtree.
const EMPTY: [u8; 32] = [0u8; 32];

/// The deepest a path can go: one level per key bit.
const MAX_DEPTH: usize = 256;

/// The path of `name` in the tree.
#[must_use]
pub fn key_of(name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_KEY_V1");
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

/// The digest of the leaf node that binds `value` to `key`.
fn leaf_node(slot: &[u8; 32], record_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_SMT_LEAF_V1");
    hasher.update(slot);
    hasher.update(record_digest);
    hasher.finalize().into()
}

/// The digest of an inner node.
fn inner_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"BDLM_BNS_SMT_NODE_V1");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Bit `depth` of `key`, most significant bit first. `true` is the right child.
fn bit(key: &[u8; 32], depth: usize) -> bool {
    key.get(depth / 8)
        .is_some_and(|byte| (byte >> (7 - (depth % 8))) & 1 == 1)
}

/// What a path ends in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// The leaf of the queried key, with its value.
    Leaf([u8; 32]),
    /// An empty subtree.
    Empty,
    /// The leaf of another key: `(key, value)`.
    Other([u8; 32], [u8; 32]),
}

/// A path from a terminal node up to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub terminal: Terminal,
    /// Sibling digests, ordered from the terminal node up to the root.
    pub siblings: Vec<[u8; 32]>,
}

/// Fold a path for `key` up to the root it implies.
///
/// `terminal` is the digest of the node the path ends in. Returns `None` for
/// a path deeper than the key is long.
fn fold(key: &[u8; 32], terminal: [u8; 32], siblings: &[[u8; 32]]) -> Option<[u8; 32]> {
    if siblings.len() > MAX_DEPTH {
        return None;
    }
    let mut acc = terminal;
    let mut depth = siblings.len();
    for sibling in siblings {
        depth = depth.checked_sub(1)?;
        acc = if bit(key, depth) {
            inner_node(sibling, &acc)
        } else {
            inner_node(&acc, sibling)
        };
    }
    Some(acc)
}

/// Whether `a` and `b` agree on their first `depth` bits.
fn share_prefix(a: &[u8; 32], b: &[u8; 32], depth: usize) -> bool {
    (0..depth.min(MAX_DEPTH)).all(|d| bit(a, d) == bit(b, d))
}

/// The root a path for `key` implies, or why the path proves nothing.
///
/// # Errors
///
/// A path that is too deep, or an occupied slot that is the queried key
/// itself or does not lie on the queried path.
pub fn root_of_path(key: &[u8; 32], path: &Path) -> Result<[u8; 32], String> {
    let terminal = match path.terminal {
        Terminal::Leaf(value) => leaf_node(key, &value),
        Terminal::Empty => EMPTY,
        Terminal::Other(other, value) => {
            if other == *key {
                return Err("the occupied slot holds the queried name itself".into());
            }
            if !share_prefix(key, &other, path.siblings.len()) {
                return Err("the occupied slot does not lie on the queried path".into());
            }
            leaf_node(&other, &value)
        }
    };
    fold(key, terminal, &path.siblings).ok_or_else(|| "the path is deeper than the key".to_string())
}

#[derive(Debug, Clone)]
enum Node {
    Leaf {
        key: [u8; 32],
        value: [u8; 32],
        hash: [u8; 32],
    },
    Inner {
        left: Option<Box<Node>>,
        right: Option<Box<Node>>,
        hash: [u8; 32],
    },
}

impl Node {
    const fn hash(&self) -> [u8; 32] {
        match self {
            Self::Leaf { hash, .. } | Self::Inner { hash, .. } => *hash,
        }
    }

    fn leaf(key: [u8; 32], value: [u8; 32]) -> Box<Self> {
        Box::new(Self::Leaf {
            key,
            value,
            hash: leaf_node(&key, &value),
        })
    }

    fn inner(left: Option<Box<Self>>, right: Option<Box<Self>>) -> Box<Self> {
        let hash = inner_node(&hash_of(left.as_deref()), &hash_of(right.as_deref()));
        Box::new(Self::Inner { left, right, hash })
    }
}

fn hash_of(node: Option<&Node>) -> [u8; 32] {
    node.map_or(EMPTY, Node::hash)
}

/// Put `(key, value)` into the subtree rooted at `depth`.
fn insert_at(node: Option<Box<Node>>, key: [u8; 32], value: [u8; 32], depth: usize) -> Box<Node> {
    match node.map(|boxed| *boxed) {
        None => Node::leaf(key, value),
        Some(Node::Leaf {
            key: held,
            value: held_value,
            ..
        }) => {
            if held == key || depth >= MAX_DEPTH {
                return Node::leaf(key, value);
            }
            // Two names now share this subtree. The one that was here goes
            // one level down on its own side, then the new one is added.
            let moved = Some(Node::leaf(held, held_value));
            let split = if bit(&held, depth) {
                Node::inner(None, moved)
            } else {
                Node::inner(moved, None)
            };
            insert_at(Some(split), key, value, depth)
        }
        Some(Node::Inner { left, right, .. }) => {
            if bit(&key, depth) {
                let right = insert_at(right, key, value, depth.saturating_add(1));
                Node::inner(left, Some(right))
            } else {
                let left = insert_at(left, key, value, depth.saturating_add(1));
                Node::inner(Some(left), right)
            }
        }
    }
}

/// Take `key` out of the subtree rooted at `depth`. The flag says whether a
/// leaf was removed.
fn remove_at(node: Option<Box<Node>>, key: &[u8; 32], depth: usize) -> (Option<Box<Node>>, bool) {
    match node.map(|boxed| *boxed) {
        None => (None, false),
        Some(Node::Leaf {
            key: held,
            value,
            hash,
        }) => {
            if held == *key {
                (None, true)
            } else {
                (
                    Some(Box::new(Node::Leaf {
                        key: held,
                        value,
                        hash,
                    })),
                    false,
                )
            }
        }
        Some(Node::Inner { left, right, .. }) => {
            let (left, right, removed) = if bit(key, depth) {
                let (right, removed) = remove_at(right, key, depth.saturating_add(1));
                (left, right, removed)
            } else {
                let (left, removed) = remove_at(left, key, depth.saturating_add(1));
                (left, right, removed)
            };
            // A subtree left with one name is that name's leaf again, and
            // an empty one is nothing: the shape follows the set of names.
            let collapsed = match (left, right) {
                (None, None) => None,
                (Some(only), None) if matches!(*only, Node::Leaf { .. }) => Some(only),
                (None, Some(only)) if matches!(*only, Node::Leaf { .. }) => Some(only),
                (left, right) => Some(Node::inner(left, right)),
            };
            (collapsed, removed)
        }
    }
}

/// The sparse tree over a set of `(key, value)` pairs.
#[derive(Debug, Clone, Default)]
pub struct Tree {
    root: Option<Box<Node>>,
    len: usize,
}

impl Tree {
    /// The digest the tree commits to. An empty tree is 32 zero bytes.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        hash_of(self.root.as_deref())
    }

    /// How many keys the tree holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the tree holds no key.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Set the value of `key`, re-hashing the nodes on its path only.
    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) {
        let fresh = matches!(
            self.prove(&key).terminal,
            Terminal::Empty | Terminal::Other(..)
        );
        self.root = Some(insert_at(self.root.take(), key, value, 0));
        if fresh {
            self.len = self.len.saturating_add(1);
        }
    }

    /// Remove `key`. Removing a key the tree does not hold changes nothing.
    pub fn remove(&mut self, key: &[u8; 32]) {
        let (root, removed) = remove_at(self.root.take(), key, 0);
        self.root = root;
        if removed {
            self.len = self.len.saturating_sub(1);
        }
    }

    /// The path of `key`: to its leaf when the tree holds it, otherwise to
    /// the empty slot or the other leaf that stands where it would be.
    #[must_use]
    pub fn prove(&self, key: &[u8; 32]) -> Path {
        let mut siblings = Vec::new();
        let mut node = self.root.as_deref();
        let mut depth = 0usize;
        let terminal = loop {
            match node {
                None => break Terminal::Empty,
                Some(Node::Leaf {
                    key: held, value, ..
                }) => {
                    break if held == key {
                        Terminal::Leaf(*value)
                    } else {
                        Terminal::Other(*held, *value)
                    };
                }
                Some(Node::Inner { left, right, .. }) => {
                    let (next, other) = if bit(key, depth) {
                        (right, left)
                    } else {
                        (left, right)
                    };
                    siblings.push(hash_of(other.as_deref()));
                    node = next.as_deref();
                    depth = depth.saturating_add(1);
                }
            }
        };
        siblings.reverse();
        Path { terminal, siblings }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn names(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("name{i}.bud")).collect()
    }

    /// The root by the definition, with no tree: empty is zero, one name is
    /// its leaf, anything else is the hash of the two halves.
    fn reference_root(items: &[([u8; 32], [u8; 32])], depth: usize) -> [u8; 32] {
        match items {
            [] => EMPTY,
            [(key, value)] => leaf_node(key, value),
            _ => {
                let (right, left): (Vec<_>, Vec<_>) =
                    items.iter().partition(|(key, _)| bit(key, depth));
                inner_node(
                    &reference_root(&left, depth + 1),
                    &reference_root(&right, depth + 1),
                )
            }
        }
    }

    #[test]
    fn an_empty_tree_has_the_empty_root_and_proves_every_name_absent() {
        let tree = Tree::default();
        assert_eq!(tree.root(), EMPTY);
        assert!(tree.is_empty());
        let key = key_of("ayaz.bud");
        let path = tree.prove(&key);
        assert_eq!(path.terminal, Terminal::Empty);
        assert!(path.siblings.is_empty());
        assert_eq!(root_of_path(&key, &path), Ok(EMPTY));
    }

    #[test]
    fn the_root_does_not_depend_on_the_order_of_writes_or_on_removed_names() {
        let all = names(40);
        let items: Vec<([u8; 32], [u8; 32])> = all
            .iter()
            .enumerate()
            .map(|(i, name)| (key_of(name), value(u8::try_from(i).unwrap())))
            .collect();
        let expected = reference_root(&items, 0);

        let mut forward = Tree::default();
        for (key, val) in &items {
            forward.insert(*key, *val);
        }
        let mut backward = Tree::default();
        for (key, val) in items.iter().rev() {
            backward.insert(*key, *val);
        }
        assert_eq!(forward.root(), expected);
        assert_eq!(backward.root(), expected);
        assert_eq!(forward.len(), 40);

        // Names that came and went leave no trace, and a rewrite of a value
        // ends where a fresh tree with that value ends.
        let mut churned = Tree::default();
        for i in 0..20u8 {
            churned.insert(key_of(&format!("gone{i}.bud")), value(i));
        }
        for (key, _) in &items {
            churned.insert(*key, value(0xEE));
        }
        for (key, val) in &items {
            churned.insert(*key, *val);
        }
        for i in 0..20u8 {
            churned.remove(&key_of(&format!("gone{i}.bud")));
        }
        churned.remove(&key_of("never.bud"));
        assert_eq!(churned.root(), expected);
        assert_eq!(churned.len(), 40);

        // Removing everything gives the empty tree back.
        for (key, _) in &items {
            churned.remove(key);
        }
        assert_eq!(churned.root(), EMPTY);
        assert!(churned.is_empty());
    }

    #[test]
    fn every_held_name_proves_inclusion_and_every_other_name_proves_absence() {
        let mut tree = Tree::default();
        let held = names(24);
        for (i, name) in held.iter().enumerate() {
            tree.insert(key_of(name), value(u8::try_from(i).unwrap()));
        }
        let root = tree.root();
        for (i, name) in held.iter().enumerate() {
            let key = key_of(name);
            let path = tree.prove(&key);
            assert_eq!(
                path.terminal,
                Terminal::Leaf(value(u8::try_from(i).unwrap()))
            );
            assert_eq!(root_of_path(&key, &path), Ok(root));
        }
        let mut empty_slots = 0;
        let mut occupied_slots = 0;
        for i in 0..200 {
            let key = key_of(&format!("free{i}.bud"));
            let path = tree.prove(&key);
            match path.terminal {
                Terminal::Empty => empty_slots += 1,
                Terminal::Other(..) => occupied_slots += 1,
                Terminal::Leaf(_) => panic!("a name the tree does not hold proved inclusion"),
            }
            assert_eq!(root_of_path(&key, &path), Ok(root));
        }
        assert!(empty_slots > 0 && occupied_slots > 0);
    }

    #[test]
    fn a_path_with_one_byte_changed_does_not_reach_the_root() {
        let mut tree = Tree::default();
        for (i, name) in names(16).iter().enumerate() {
            tree.insert(key_of(name), value(u8::try_from(i).unwrap()));
        }
        let root = tree.root();
        let key = key_of("name3.bud");
        let path = tree.prove(&key);
        assert!(path.siblings.len() >= 2);
        assert_eq!(root_of_path(&key, &path), Ok(root));

        for i in 0..path.siblings.len() {
            let mut bent = path.clone();
            bent.siblings[i][7] ^= 1;
            assert_ne!(root_of_path(&key, &bent), Ok(root));
        }
        let mut other_value = path.clone();
        other_value.terminal = Terminal::Leaf(value(0x77));
        assert_ne!(root_of_path(&key, &other_value), Ok(root));
        let mut shorter = path.clone();
        shorter.siblings.pop();
        assert_ne!(root_of_path(&key, &shorter), Ok(root));
        // The path of one name is not a path of another.
        assert_ne!(root_of_path(&key_of("name4.bud"), &path), Ok(root));
        // A held name cannot be shown as an empty slot.
        let mut hidden = path;
        hidden.terminal = Terminal::Empty;
        assert_ne!(root_of_path(&key, &hidden), Ok(root));
        assert!(fold(&key, EMPTY, &vec![EMPTY; MAX_DEPTH + 1]).is_none());
    }

    #[test]
    fn an_occupied_slot_off_the_queried_path_is_refused() {
        let mut tree = Tree::default();
        for (i, name) in names(16).iter().enumerate() {
            tree.insert(key_of(name), value(u8::try_from(i).unwrap()));
        }
        let key = key_of("name5.bud");
        let own = tree.prove(&key);
        // The name's own leaf, relabelled as "another name holds the slot".
        let relabelled = Path {
            terminal: Terminal::Other(key, value(5)),
            siblings: own.siblings.clone(),
        };
        assert!(root_of_path(&key, &relabelled).is_err());
        // A leaf from a different branch of the tree does not stand in the
        // queried slot, whatever siblings come with it.
        let stranger = (0..16)
            .map(|i| key_of(&format!("name{i}.bud")))
            .find(|other| !share_prefix(&key, other, own.siblings.len()))
            .unwrap();
        let misplaced = Path {
            terminal: Terminal::Other(stranger, value(1)),
            siblings: own.siblings,
        };
        assert!(root_of_path(&key, &misplaced).is_err());
    }
}
