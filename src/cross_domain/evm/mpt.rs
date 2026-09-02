//! In-tree Merkle-Patricia Trie (MPT) **verifier** - Ethereum Yellow Paper
//! Appendix D.
//!
//! **Verify only** (RFC Q1 = relayer_produces): proof generation lives in the relayer binary;
//! Budlum only verifies `(proof_nodes, root, key) -> value`.
//! Deterministic and network free - critical for consensus safety.
//!
//! # MPT node types (after RLP decoding)
//!
//! - **Null**: the empty string `""` -> empty trie / missing child.
//! - **Leaf**: `[hp_encoded_path, value]` - path terminator flag=1.
//! - **Extension**: `[hp_encoded_path, child_ref]` - terminator flag=0.
//! - **Branch**: `[c0, c1, ..., c15, value]` - 17 elements (16 children + optional value).
//!
//! `child_ref` is either a 32-byte keccak256 hash (looked up in node_map) or an inline
//! RLP-encoded node (32 bytes or fewer, the small-node optimization).
//!
//! # Security
//!
//! - Node hash = `keccak256(rlp(node))`. The root is the hash of the root node.
//! - A missing node, a broken path or a wrong root -> `Err` (the proof is invalid).
//! - `keccak256` comes from the `sha3` crate (already present; NO new dependency).

use crate::cross_domain::evm::rlp::{self, Item, RlpError};
use sha3::{Digest, Keccak256};

/// Hard bound on trie descent.
///
/// A path is `keccak256(key)` expanded to nibbles, so an honest proof
/// descends at most 64 levels and each step consumes at least one nibble.
/// Extension nodes are the exception: a hex-prefix path can decode to an
/// *empty* nibble list (`hp_decode(&[0x00])`), and `nibbles.starts_with(&[])`
/// is always true, so `remaining` comes back the same length it went in.
///
/// Two such nodes pointing at each other never terminate. Measured against
/// the unbounded version:
///
/// ```text
/// A -> B, B -> A, both empty-path extensions
/// fatal runtime error: stack overflow, aborting
/// ```
///
/// The proof bytes come from a bridge relayer, so that is a remote abort of
/// the node process, not a local misuse. The depth is generous, twice the
/// longest honest descent - because the goal is to stop non-termination, not
/// to second-guess a legitimate trie.
pub const MAX_WALK_DEPTH: usize = 128;
use std::collections::HashMap;

/// MPT verification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MptError {
    /// The key is not in the trie (null child / empty value slot).
    KeyNotFound,
    /// A node is missing from the proof (the referenced hash is not in node_map).
    MissingNode,
    /// Node RLP decode error.
    Rlp(RlpError),
    /// Invalid node structure (unknown list length and similar).
    InvalidNode,
    /// Invalid hex-prefix encoding.
    InvalidHpEncoding,
    /// Invalid node reference (neither a 32-byte hash nor inline RLP).
    InvalidNodeRef,
    /// The path does not match (leaf/extension path mismatch).
    PathMismatch,
    /// Trie descent exceeded [`MAX_WALK_DEPTH`].
    ///
    /// Reached when a proof's nodes do not make progress, an empty-path
    /// extension leaves the remaining nibbles unchanged, so a cycle among
    /// such nodes would otherwise recurse until the stack is exhausted.
    NestingTooDeep,
}

impl std::fmt::Display for MptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MptError::KeyNotFound => write!(f, "mpt: key not found in trie"),
            MptError::MissingNode => write!(f, "mpt: missing node in proof"),
            MptError::Rlp(e) => write!(f, "mpt: rlp decode error: {e}"),
            MptError::InvalidNode => write!(f, "mpt: invalid node structure"),
            MptError::InvalidHpEncoding => write!(f, "mpt: invalid hex-prefix encoding"),
            MptError::InvalidNodeRef => write!(f, "mpt: invalid node reference"),
            MptError::PathMismatch => write!(f, "mpt: path does not match"),
            MptError::NestingTooDeep => {
                write!(f, "mpt: trie descent exceeded {MAX_WALK_DEPTH} levels")
            }
        }
    }
}

impl std::error::Error for MptError {}

impl From<RlpError> for MptError {
    fn from(e: RlpError) -> Self {
        MptError::Rlp(e)
    }
}

/// Keccak-256 digest (32 bytes).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The empty trie root = `keccak256(rlp(""))` = `keccak256(0x80)`.
/// A canonical constant in Ethereum; every empty trie has this root.
/// The value is CI proved (keccak256(0x80) could not be computed locally; the CI test
/// `empty_trie_root_constant_correct` is the authority).
pub const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Expands a 32-byte hash into 64 nibbles (the MPT path is the nibbles of keccak256(key)).
pub fn to_nibbles(hash: &[u8; 32]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(64);
    for &b in hash {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    nibbles
}

/// Hex-prefix encode (Yellow Paper Appendix D \mathrm{compact} fonksiyonu).
///
/// `is_leaf=true` -> the terminator flag; `nibbles` may have odd or even length.
pub fn hp_encode(nibbles: &[u8], is_leaf: bool) -> Vec<u8> {
    let flag = if is_leaf { 2u8 } else { 0u8 };
    let odd = nibbles.len() % 2 == 1;
    let prefix_nibble = flag + if odd { 1 } else { 0 };
    let mut out = Vec::new();
    if odd {
        // The first path nibble is packed into the same byte as the prefix.
        out.push((prefix_nibble << 4) | nibbles[0]);
        for pair in nibbles[1..].chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    } else {
        out.push(prefix_nibble << 4);
        for pair in nibbles.chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    }
    out
}

/// Hex-prefix decode → (is_leaf, path_nibbles).
pub fn hp_decode(bytes: &[u8]) -> Result<(bool, Vec<u8>), MptError> {
    if bytes.is_empty() {
        return Err(MptError::InvalidHpEncoding);
    }
    let first = bytes[0];
    let flag_byte = first >> 4;
    if flag_byte > 3 {
        return Err(MptError::InvalidHpEncoding); // only 0/1/2/3 are valid
    }
    let is_leaf = (flag_byte & 0b10) != 0;
    let odd = (flag_byte & 0b01) != 0;

    let mut nibbles = Vec::new();
    if odd {
        nibbles.push(first & 0x0f);
    }
    for &b in &bytes[1..] {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    Ok((is_leaf, nibbles))
}

/// Verifies an MPT proof and returns the value for the key.
///
/// - `proof_nodes`: RLP-encoded node bytes (a hash -> bytes map is built).
/// - `root`: the expected root hash (`keccak256(rlp(root_node))`).
/// - `key`: the raw key bytes (the path is the nibbles of `keccak256(key)`).
///
/// On success -> the value bytes (leaf value or branch value slot, raw).
/// On failure -> the proof is invalid (MissingNode/PathMismatch/KeyNotFound and so on).
pub fn verify(proof_nodes: &[Vec<u8>], root: &[u8; 32], key: &[u8]) -> Result<Vec<u8>, MptError> {
    // Node map: hash → RLP bytes (relayer proof'tan).
    let mut node_map: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    for node_bytes in proof_nodes {
        node_map.insert(keccak256(node_bytes), node_bytes.clone());
    }

    // Resolve the root node.
    let root_bytes = node_map.get(root).ok_or(MptError::MissingNode)?;
    let root_item = rlp::decode(root_bytes)?;
    let path = to_nibbles(&keccak256(key));

    walk(&root_item, &path, &node_map, 0)
}

/// Recursive trie walk. `nibbles` holds the remaining path nibbles.
fn walk(
    node: &Item,
    nibbles: &[u8],
    node_map: &HashMap<[u8; 32], Vec<u8>>,
    depth: usize,
) -> Result<Vec<u8>, MptError> {
    if depth > MAX_WALK_DEPTH {
        return Err(MptError::NestingTooDeep);
    }
    match node {
        // A null node -> empty/missing.
        Item::String(b) if b.is_empty() => Err(MptError::KeyNotFound),

        // A two-element list: leaf or extension.
        Item::List(items) if items.len() == 2 => {
            let path_bytes = rlp::as_bytes(&items[0])?;
            let (is_leaf, node_path) = hp_decode(path_bytes)?;
            if !nibbles.starts_with(&node_path) {
                return Err(MptError::PathMismatch);
            }
            let remaining = &nibbles[node_path.len()..];
            if is_leaf {
                // Leaf: the whole path must be consumed -> returns the value.
                if !remaining.is_empty() {
                    return Err(MptError::PathMismatch);
                }
                return Ok(rlp::as_bytes(&items[1])?.to_vec());
            }
            // Extension: resolve the child reference and continue.
            let child = resolve_ref(&items[1], node_map)?;
            walk(&child, remaining, node_map, depth + 1)
        }

        // 17-eleman liste: branch.
        Item::List(items) if items.len() == 17 => {
            if nibbles.is_empty() {
                // The whole path is consumed -> the branch value slot (index 16).
                let value_slot = &items[16];
                return match value_slot {
                    Item::String(b) if b.is_empty() => Err(MptError::KeyNotFound),
                    _ => Ok(rlp::as_bytes(value_slot)?.to_vec()),
                };
            }
            let nibble = nibbles[0] as usize;
            let child = resolve_ref(&items[nibble], node_map)?;
            walk(&child, &nibbles[1..], node_map, depth + 1)
        }

        _ => Err(MptError::InvalidNode),
    }
}

/// Resolves a node reference: a 32-byte hash (node_map lookup) or an inline RLP node.
fn resolve_ref(item: &Item, node_map: &HashMap<[u8; 32], Vec<u8>>) -> Result<Item, MptError> {
    match item {
        Item::String(b) if b.is_empty() => Err(MptError::KeyNotFound),
        Item::String(b) if b.len() == 32 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(b);
            let node_bytes = node_map.get(&hash).ok_or(MptError::MissingNode)?;
            rlp::decode(node_bytes).map_err(MptError::from)
        }
        Item::String(b) => {
            // An inline node (RLP of 32 bytes or fewer) - decode and handle in place.
            rlp::decode(b).map_err(MptError::from)
        }
        Item::List(_) => {
            // A nested decoded inline node (the branch child is a list directly).
            Ok(item.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::evm::rlp::{decode as rlp_decode, encode as rlp_encode};

    /// Test helper: produces leaf node RLP bytes (a test trie builder).
    fn leaf_node_bytes(nibbles: &[u8], value: &[u8]) -> Vec<u8> {
        let node = Item::List(vec![
            Item::String(hp_encode(nibbles, true)),
            Item::String(value.to_vec()),
        ]);
        rlp_encode(&node)
    }

    /// Test helper: extension node RLP bytes.
    fn extension_node_bytes(nibbles: &[u8], child_hash: &[u8; 32]) -> Vec<u8> {
        let node = Item::List(vec![
            Item::String(hp_encode(nibbles, false)),
            Item::String(child_hash.to_vec()),
        ]);
        rlp_encode(&node)
    }

    /// Test helper: branch node RLP bytes (16 children + value).
    fn branch_node_bytes(children: [Option<Vec<u8>>; 16], value: Option<Vec<u8>>) -> Vec<u8> {
        let mut items: Vec<Item> = children
            .iter()
            .map(|c| match c {
                Some(b) => Item::String(b.clone()),
                None => Item::String(vec![]),
            })
            .collect();
        items.push(match value {
            Some(v) => Item::String(v),
            None => Item::String(vec![]),
        });
        rlp_encode(&Item::List(items))
    }

    // ---- Hex-prefix KAT ----

    #[test]
    fn hp_encode_decode_leaf_even() {
        let nibbles = vec![1, 2, 3, 4];
        let enc = hp_encode(&nibbles, true);
        assert_eq!(enc, vec![0x20, 0x12, 0x34]); // leaf+even → 0x20, then 1234
        let (is_leaf, decoded) = hp_decode(&enc).unwrap();
        assert!(is_leaf);
        assert_eq!(decoded, nibbles);
    }

    #[test]
    fn hp_encode_decode_leaf_odd() {
        let nibbles = vec![1, 2, 3];
        let enc = hp_encode(&nibbles, true);
        assert_eq!(enc, vec![0x31, 0x23]); // leaf+odd → 0x31, first nibble 1 packed, then 23
        let (is_leaf, decoded) = hp_decode(&enc).unwrap();
        assert!(is_leaf);
        assert_eq!(decoded, nibbles);
    }

    #[test]
    fn hp_encode_decode_extension_even() {
        let nibbles = vec![0xa, 0xb, 0xc, 0xd];
        let enc = hp_encode(&nibbles, false);
        assert_eq!(enc, vec![0x00, 0xab, 0xcd]);
        let (is_leaf, decoded) = hp_decode(&enc).unwrap();
        assert!(!is_leaf);
        assert_eq!(decoded, nibbles);
    }

    #[test]
    fn hp_decode_invalid_flag_rejected() {
        // Flag_byte = 4 (>3) → InvalidHpEncoding
        assert_eq!(hp_decode(&[0x40]).unwrap_err(), MptError::InvalidHpEncoding);
    }

    // ---- keccak256 + EMPTY_TRIE_ROOT verification ----

    #[test]
    fn empty_trie_root_constant_correct() {
        // rlp("") = 0x80; keccak256(0x80) = EMPTY_TRIE_ROOT
        let computed = keccak256(&[0x80]);
        assert_eq!(computed, EMPTY_TRIE_ROOT);
    }

    // ---- verify: tek-leaf trie ----

    #[test]
    fn verify_single_leaf_hit() {
        // A single-entry trie: key -> value (one leaf node is the root).
        let key = b"hello";
        let value = b"world";
        let nibbles = to_nibbles(&keccak256(key));
        let node_bytes = leaf_node_bytes(&nibbles, value);
        let root = keccak256(&node_bytes);

        let result = verify(std::slice::from_ref(&node_bytes), &root, key).unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn verify_single_leaf_wrong_key_misses() {
        let key = b"hello";
        let value = b"world";
        let nibbles = to_nibbles(&keccak256(key));
        let node_bytes = leaf_node_bytes(&nibbles, value);
        let root = keccak256(&node_bytes);

        // A different key -> a path mismatch (the leaf path nibbles differ).
        let err = verify(&[node_bytes], &root, b"different").unwrap_err();
        assert_eq!(err, MptError::PathMismatch);
    }

    // ---- verify: leaf + extension + branch (multiple nodes) ----

    #[test]
    fn verify_two_keys_share_branch() {
        // The first nibbles of the two keys differ -> a branch root with a leaf per child.
        // keccak256("a") and keccak256("b") should differ in their first nibble (very likely).
        let key_a = b"a";
        let val_a = b"alpha";
        let key_b = b"b";
        let val_b = b"beta";

        let nib_a = to_nibbles(&keccak256(key_a));
        let nib_b = to_nibbles(&keccak256(key_b));
        assert_ne!(
            nib_a[0], nib_b[0],
            "test precondition: distinct first nibble"
        );

        let leaf_a_bytes = leaf_node_bytes(&nib_a[1..], val_a);
        let leaf_b_bytes = leaf_node_bytes(&nib_b[1..], val_b);
        let hash_a = keccak256(&leaf_a_bytes);
        let hash_b = keccak256(&leaf_b_bytes);

        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[nib_a[0] as usize] = Some(hash_a.to_vec());
        children[nib_b[0] as usize] = Some(hash_b.to_vec());

        // The absent-key check happens BEFORE the children are moved (branch_node_bytes
        // takes ownership). Is the first-nibble slot of the c key occupied?
        let absent = b"c";
        let nib_c = to_nibbles(&keccak256(absent));
        let absent_slot_empty = children[nib_c[0] as usize].is_none();

        let branch_bytes = branch_node_bytes(children, None);
        let root = keccak256(&branch_bytes);

        let proof = vec![branch_bytes, leaf_a_bytes, leaf_b_bytes];

        assert_eq!(verify(&proof, &root, key_a).unwrap(), val_a);
        assert_eq!(verify(&proof, &root, key_b).unwrap(), val_b);

        // Absent key → KeyNotFound (null child branch slot).
        if absent_slot_empty {
            assert_eq!(
                verify(&proof, &root, absent).unwrap_err(),
                MptError::KeyNotFound
            );
        }
    }

    // ---- verify: extension node (shared prefix) ----

    #[test]
    fn verify_extension_path() {
        // A test with synthetic nibbles so the two keys share a prefix:
        // Root = extension([0,1,2,3] → branch); branch child'lar leaf.
        // Instead of a real key we test the nibble walk directly through hp_encode.
        let shared = vec![0u8, 1, 2, 3];
        // The 4th child of the branch is a leaf (path = [] -> the branch value).
        let leaf_nibbles: Vec<u8> = vec![9, 9, 9, 9]; // into the 9th child of the branch
        let leaf_bytes = leaf_node_bytes(&leaf_nibbles, b"leaf-val");
        let leaf_hash = keccak256(&leaf_bytes);

        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[9] = Some(leaf_hash.to_vec());
        let branch_bytes = branch_node_bytes(children, None);
        let branch_hash = keccak256(&branch_bytes);

        let ext_bytes = extension_node_bytes(&shared, &branch_hash);
        let root = keccak256(&ext_bytes);

        // Path = shared + [9] + leaf_nibbles; key = nibbles_to_bytes(shared+[9]+leaf)
        let full_path: Vec<u8> = shared
            .iter()
            .cloned()
            .chain(std::iter::once(9))
            .chain(leaf_nibbles.iter().cloned())
            .collect();
        // Key bytes (each nibble pair of the path is a byte); exactly 64 nibbles is not
        // required because verify uses keccak256(key); here we call walk instead of verify
        // in order to test the walk directly.
        let mut node_map: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        node_map.insert(keccak256(&ext_bytes), ext_bytes.clone());
        node_map.insert(keccak256(&branch_bytes), branch_bytes.clone());
        node_map.insert(keccak256(&leaf_bytes), leaf_bytes.clone());

        let root_item = rlp_decode(&ext_bytes).unwrap();
        let result = walk(&root_item, &full_path, &node_map, 0).unwrap();
        assert_eq!(result, b"leaf-val");

        // A wrong path (not a shared prefix) -> PathMismatch
        let bad_path = vec![5u8, 6, 7, 8];
        assert_eq!(
            walk(&root_item, &bad_path, &node_map, 0).unwrap_err(),
            MptError::PathMismatch
        );

        // Root hash verification
        assert_eq!(keccak256(&ext_bytes), root);
    }

    // ---- negatif: missing node ----

    #[test]
    fn verify_missing_node_rejected() {
        // Skip a node of the proof → MissingNode.
        let key = b"hello";
        let value = b"world";
        let nibbles = to_nibbles(&keccak256(key));
        let node_bytes = leaf_node_bytes(&nibbles, value);
        let root = keccak256(&node_bytes);

        // An empty proof -> the root node is not in the map.
        let err = verify(&[], &root, key).unwrap_err();
        assert_eq!(err, MptError::MissingNode);
    }

    #[test]
    fn verify_wrong_root_rejected() {
        let key = b"hello";
        let value = b"world";
        let nibbles = to_nibbles(&keccak256(key));
        let node_bytes = leaf_node_bytes(&nibbles, value);
        let real_root = keccak256(&node_bytes);
        let wrong_root = [0xffu8; 32];

        let err = verify(&[node_bytes], &wrong_root, key).unwrap_err();
        assert_eq!(err, MptError::MissingNode); // wrong root → lookup miss
        let _ = real_root; // (the real root was verified in the previous test)
    }

    #[test]
    fn verify_empty_trie_root_key_not_found() {
        // Root = EMPTY_TRIE_ROOT but the proof carries the rlp("") node.
        let empty_node = vec![0x80]; // rlp("") = 0x80
        let err = verify(&[empty_node], &EMPTY_TRIE_ROOT, b"any").unwrap_err();
        assert_eq!(err, MptError::KeyNotFound);
    }

    // ---- inline node support ----

    #[test]
    fn verify_inline_branch_child() {
        // The branch child is an inline leaf rather than a hash (RLP of 32 bytes or fewer). Real
        // Ethereum leaves with a 64-nibble path are never inline; here we test the inline
        // mechanism with a synthetic short path (the walk + resolve_ref path).
        // Path = 2 nibbles [0xa, 0xb], value = 1 byte -> a small leaf.
        let inline_leaf = leaf_node_bytes(&[0xa, 0xb], b"v");
        assert!(inline_leaf.len() <= 32, "precondition: inline-able");

        // Branch'in 5. child slot'una inline leaf koy; path = [5, 0xa, 0xb].
        let mut children: [Option<Vec<u8>>; 16] = Default::default();
        children[5] = Some(inline_leaf.clone());
        let branch_bytes = branch_node_bytes(children, None);
        let root = keccak256(&branch_bytes);

        // verify turns keccak256(key) into the path - we test through walk directly
        // because the path from a key is keccak256(key) and would not match the synthetic path.
        let mut node_map: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        node_map.insert(keccak256(&branch_bytes), branch_bytes.clone());

        let root_item = rlp_decode(&branch_bytes).unwrap();
        let path = vec![5u8, 0xa, 0xb];
        let result = walk(&root_item, &path, &node_map, 0).unwrap();
        assert_eq!(result, b"v");

        // Root hash verification
        assert_eq!(keccak256(&branch_bytes), root);
    }

    // ---- fuzz-like: random node bytes -> an error (not a panic) ----

    #[test]
    fn garbage_proof_does_not_panic() {
        let garbage_sets: Vec<Vec<Vec<u8>>> = vec![
            vec![vec![0x00]],
            vec![vec![0xff; 100]],
            vec![vec![0xc0]],             // empty list
            vec![vec![0xc1, 0x80]],       // 1-elem list (invalid node)
            vec![vec![0xd2, 0x80, 0x80]], // 2-elem list but value empty
        ];
        let root = [0x42u8; 32];
        for proof in &garbage_sets {
            // The result must be Err (MissingNode / InvalidNode / Rlp), not a panic.
            let _ = verify(proof, &root, b"key");
        }
        // MissingNode is expected because the root hashes are not in the proof; what matters
        // is that there is no panic (DoS safety).
    }
}

#[cfg(test)]
mod depth_bound_locks {
    use super::*;
    use crate::cross_domain::evm::rlp::encode as rlp_encode;

    /// A cycle of empty-path extension nodes must be refused, not recursed.
    ///
    /// `hp_decode(&[0x00])` yields an empty nibble list, and
    /// `nibbles.starts_with(&[])` is always true, so an extension node with an
    /// empty path hands `walk` the same `remaining` it received. Two such
    /// nodes referring to each other never make progress. Measured against the
    /// unbounded version:
    ///
    /// ```text
    /// A -> B, B -> A, both empty-path extensions
    /// fatal runtime error: stack overflow, aborting
    /// ```
    ///
    /// The proof bytes arrive from a bridge relayer, so this was a remote
    /// abort of the node process.
    #[test]
    fn a_cycle_of_empty_path_extensions_is_refused() {
        let a_ref = [0xAAu8; 32];
        let b_ref = [0xBBu8; 32];

        let node_a = Item::List(vec![
            Item::String(hp_encode(&[], false)),
            Item::String(b_ref.to_vec()),
        ]);
        let node_b = Item::List(vec![
            Item::String(hp_encode(&[], false)),
            Item::String(a_ref.to_vec()),
        ]);
        let bytes_a = rlp_encode(&node_a);
        let bytes_b = rlp_encode(&node_b);

        let mut map = std::collections::HashMap::new();
        map.insert(a_ref, bytes_a.clone());
        map.insert(b_ref, bytes_b.clone());

        let path = to_nibbles(&[0x11u8; 32]);
        let root_item = rlp::decode(&bytes_a).expect("node A decodes");

        assert_eq!(
            walk(&root_item, &path, &map, 0),
            Err(MptError::NestingTooDeep),
            "a non-progressing cycle must terminate with an error"
        );
    }

    /// The bound has to clear the deepest descent a real trie can produce.
    ///
    /// Comparing two constants would be folded away at compile time (clippy
    /// calls it a constant assertion, correctly), so this builds an actual
    /// branch chain 64 levels deep, the maximum a keccak256 path allows,
    /// and checks it resolves. Lowering `MAX_WALK_DEPTH` below the honest
    /// maximum would make this fail with `NestingTooDeep`.
    #[test]
    fn a_maximum_depth_honest_descent_still_resolves() {
        let key = b"deep";
        let path = to_nibbles(&keccak256(key));
        assert_eq!(path.len(), 64, "keccak256 expands to 64 nibbles");
        let value = b"found";

        // Build bottom-up: a leaf consuming nothing, then 64 branch nodes each
        // consuming one nibble of the path.
        let mut node_map: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let leaf = Item::List(vec![
            Item::String(hp_encode(&[], true)),
            Item::String(value.to_vec()),
        ]);
        let mut current_bytes = rlp_encode(&leaf);
        let mut current_hash = keccak256(&current_bytes);
        node_map.insert(current_hash, current_bytes.clone());

        for level in (0..64).rev() {
            let nibble = path[level] as usize;
            let mut children: Vec<Item> = (0..17).map(|_| Item::String(Vec::new())).collect();
            children[nibble] = Item::String(current_hash.to_vec());
            let branch = Item::List(children);
            current_bytes = rlp_encode(&branch);
            current_hash = keccak256(&current_bytes);
            node_map.insert(current_hash, current_bytes.clone());
        }

        let nodes: Vec<Vec<u8>> = node_map.values().cloned().collect();
        assert_eq!(
            verify(&nodes, &current_hash, key),
            Ok(value.to_vec()),
            "a 64-level descent is honest and must not hit the depth bound"
        );
    }

    /// An existing round-trip must still work - the bound is a ceiling, not a
    /// behaviour change.
    #[test]
    fn a_normal_leaf_lookup_still_resolves() {
        let key = b"balance";
        let value = b"42";
        let path = to_nibbles(&keccak256(key));

        let leaf = Item::List(vec![
            Item::String(hp_encode(&path, true)),
            Item::String(value.to_vec()),
        ]);
        let leaf_bytes = rlp_encode(&leaf);
        let root = keccak256(&leaf_bytes);

        assert_eq!(
            verify(&[leaf_bytes], &root, key),
            Ok(value.to_vec()),
            "a single-leaf trie must still verify"
        );
    }
}
