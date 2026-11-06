use crate::core::hash::hash_fields_bytes;
use crate::domain::types::Hash32;

/// Tagged node hash: the settlement binding of the shared tree primitive's
/// binary combine. The tag cannot collide with a leaf domain or the
/// promotion tag, so a node digest is never mistaken for either.
pub(crate) fn merkle_node_hash(left: &[u8; 32], right: &[u8; 32]) -> Hash32 {
    hash_fields_bytes(&[b"BDLM_MERKLE_NODE_V1", left, right])
}

/// Tagged promotion hash: the settlement binding of the shared tree
/// primitive's unary combine. An unpaired tail is promoted under its own
/// domain tag rather than paired with itself. The self-pairing made the odd
/// tail contribute exactly what a duplicated leaf would, so the root of
/// [a, b, c] equalled the root of [a, b, c, c]: two different commitments,
/// one digest. The promotion tag cannot collide with a node tag, so a
/// promoted digest is never mistaken for a paired one.
pub(crate) fn merkle_odd_promote_hash(node: &[u8; 32]) -> Hash32 {
    hash_fields_bytes(&[b"BDLM_MERKLE_ODD_PROMOTE_V1", node])
}

/// The settlement Merkle root: the one shared tree shape
/// (`consensus::merkle_tree`) under this module's tagged binding, so the
/// settlement, event and QC trees cannot drift apart on tree shape again.
pub fn merkle_root(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return hash_fields_bytes(&[b"BDLM_EMPTY_MERKLE_ROOT_V1"]);
    }
    crate::consensus::merkle_tree::merkle_root(leaves, merkle_node_hash, merkle_odd_promote_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_deterministic() {
        let a = hash_fields_bytes(&[b"a"]);
        let b = hash_fields_bytes(&[b"b"]);
        assert_eq!(merkle_root(&[a, b]), merkle_root(&[a, b]));
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
    }

    /// The ambiguity this root must not have: duplicating the odd tail
    /// leaf produced the same digest as the three-leaf tree, because the
    /// self-paired tail and a real fourth leaf hashed identically. The
    /// promoted tail must differ from a paired one.
    #[test]
    fn an_odd_tail_never_mimics_a_duplicated_leaf() {
        let a = hash_fields_bytes(&[b"a"]);
        let b = hash_fields_bytes(&[b"b"]);
        let c = hash_fields_bytes(&[b"c"]);
        assert_ne!(
            merkle_root(&[a, b, c]),
            merkle_root(&[a, b, c, c]),
            "the three-leaf and duplicated-tail trees must not share a root"
        );
        let d = hash_fields_bytes(&[b"d"]);
        assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c, d]));
        assert_ne!(
            merkle_root(&[c]),
            merkle_root(&[c, c]),
            "a lone leaf and a self-paired pair must not share a root"
        );
    }
}
