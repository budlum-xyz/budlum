//! When a witness may be deleted.
//!
//! An archive node keeps every witness and proof. A normal node prunes by the Pul-Lite rule:
//! a witness goes only after its block is final and the retention period has passed, never
//! before. The decision is a pure function of heights so the storage layer, the sync server
//! and the tests all read one rule; the storage separation itself (witness rows apart from block
//! bodies) builds on it.

/// The retention period of a normal node, in blocks, after finality. One day at the shortest
/// accepted block interval of one second. Provisional until the propagation measurement
/// and the witness size measurement fix it; it is a parameter of
/// [`may_prune`], not a consensus value.
pub const DEFAULT_RETENTION_BLOCKS: u64 = 86_400;

/// The retention role of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Stores all witnesses and proofs, forever.
    Archive,
    /// Prunes witnesses by the Pul-Lite rule.
    Normal,
}

/// Whether the witness of the block at `witness_height` may be deleted now.
///
/// `finalized_height` is the highest final block and `tip_height` the head. A witness above the
/// finalized height is never pruned, and a finalized one stays until it is at least
/// `retention_blocks` behind the tip.
#[must_use]
pub fn may_prune(
    kind: NodeKind,
    witness_height: u64,
    finalized_height: u64,
    tip_height: u64,
    retention_blocks: u64,
) -> bool {
    match kind {
        NodeKind::Archive => false,
        NodeKind::Normal => {
            witness_height <= finalized_height
                && witness_height <= tip_height
                && tip_height - witness_height >= retention_blocks
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_node_never_prunes() {
        assert!(!may_prune(NodeKind::Archive, 1, 1_000_000, 2_000_000, 0));
    }

    #[test]
    fn a_witness_above_finality_is_kept() {
        assert!(!may_prune(NodeKind::Normal, 101, 100, 1_000_000, 10));
    }

    #[test]
    fn a_finalized_witness_waits_for_the_retention_period() {
        assert!(!may_prune(NodeKind::Normal, 100, 100, 100 + 9, 10));
        assert!(may_prune(NodeKind::Normal, 100, 100, 100 + 10, 10));
    }

    #[test]
    fn a_tip_below_the_witness_height_does_not_underflow() {
        assert!(!may_prune(NodeKind::Normal, 100, 100, 50, 10));
        assert!(!may_prune(NodeKind::Normal, 100, 100, 50, 0));
    }
}
