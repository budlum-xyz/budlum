//! In-memory share store. The durable backend is chosen in `DB_CHOICE.md`.
//!
//! WIRING: [`crate::duty::MobileCore`] is the only caller.

use crate::custody::{symbol_leaf, symbol_root, Audit, CustodyProof, ProofContext, prove};
use crate::error::CoreError;
use crate::quota::fits;
use std::collections::BTreeMap;

/// Identifier of a stored share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShareId(pub u64);

/// One custody share held on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareRecord {
    /// Local id.
    pub id: ShareId,
    /// Object key.
    pub object: [u8; 32],
    /// Segment index.
    pub segment: u64,
    /// Encoding symbol id.
    pub esi: u32,
    /// Position in the symbol root.
    pub position: u64,
    /// Symbol bytes.
    pub symbol: Vec<u8>,
    /// `(esi, symbol_leaf)` pairs of the segment, in ESI order.
    pub placed: Vec<(u32, [u8; 32])>,
}

impl ShareRecord {
    /// Stored size of this share.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.symbol.len() as u64
    }

    /// Proof context for this share's segment.
    #[must_use]
    pub fn proof_context(&self) -> ProofContext {
        ProofContext {
            symbol_root: symbol_root(&self.placed),
            symbol_count: self.placed.len() as u64,
            sub_blocks: crate::custody::sub_block_count(self.symbol.len()),
        }
    }
}

/// Assigned share the network asks this validator to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedShare {
    /// Object key.
    pub object: [u8; 32],
    /// Segment index.
    pub segment: u64,
    /// Encoding symbol id.
    pub esi: u32,
    /// Position in the symbol root.
    pub position: u64,
    /// Symbol bytes.
    pub symbol: Vec<u8>,
    /// `(esi, symbol_leaf)` pairs of the segment, in ESI order.
    pub placed: Vec<(u32, [u8; 32])>,
}

/// The shares this core holds.
#[derive(Debug, Default)]
pub struct ShareStore {
    next_id: u64,
    shares: BTreeMap<u64, ShareRecord>,
}

impl ShareStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes currently stored.
    #[must_use]
    pub fn stored_bytes(&self) -> u64 {
        self.shares.values().map(ShareRecord::size).sum()
    }

    /// Number of shares.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Whether the store holds no shares.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// Accept a share if it fits in `quota`.
    ///
    /// # Errors
    ///
    /// [`CoreError`] when the share would exceed the quota, or when the
    /// placed leaf does not match the symbol.
    pub fn accept(
        &mut self,
        assigned: AssignedShare,
        quota: u64,
    ) -> Result<ShareRecord, CoreError> {
        let incoming = assigned.symbol.len() as u64;
        if !fits(self.stored_bytes(), incoming, quota) {
            return Err(CoreError::new(
                "mobile_quota_exceeded",
                "accepting this share would exceed the custody quota",
            ));
        }
        // The position used by audit proofs must identify this exact ESI and
        // leaf, not merely some matching entry elsewhere in the placement.
        // Strict ordering also rules out ambiguous duplicate ESIs.
        if assigned.placed.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(CoreError::new(
                "mobile_share_placement_order",
                "the placement must contain unique ESIs in ascending order",
            ));
        }
        let expected = usize::try_from(assigned.position)
            .ok()
            .and_then(|position| assigned.placed.get(position));
        if expected != Some(&(assigned.esi, symbol_leaf(&assigned.symbol))) {
            return Err(CoreError::new(
                "mobile_share_leaf_mismatch",
                "the assigned position, ESI and symbol must match the placed leaf",
            ));
        }
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let record = ShareRecord {
            id: ShareId(id),
            object: assigned.object,
            segment: assigned.segment,
            esi: assigned.esi,
            position: assigned.position,
            symbol: assigned.symbol,
            placed: assigned.placed,
        };
        self.shares.insert(id, record.clone());
        Ok(record)
    }

    /// The share at `id`.
    #[must_use]
    pub fn get(&self, id: ShareId) -> Option<&ShareRecord> {
        self.shares.get(&id.0)
    }

    /// Drop `id` and return the bytes it occupied.
    pub fn release(&mut self, id: ShareId) -> Option<u64> {
        self.shares.remove(&id.0).map(|r| r.size())
    }

    /// Id of the largest share, if any.
    #[must_use]
    pub fn largest_id(&self) -> Option<ShareId> {
        self.shares
            .values()
            .max_by_key(|s| s.size())
            .map(|s| s.id)
    }

    /// The share that matches `audit`, if any.
    #[must_use]
    pub fn matching_audit(&self, object: &[u8; 32], audit: &Audit) -> Option<&ShareRecord> {
        self.shares.values().find(|s| {
            &s.object == object && s.segment == audit.segment && s.position == audit.position
        })
    }

    /// Answer an audit for an object and a share this store holds.
    ///
    /// # Errors
    ///
    /// [`CoreError`] when no share matches, or the proof cannot be built.
    pub fn answer(&self, object: &[u8; 32], audit: &Audit) -> Result<CustodyProof, CoreError> {
        let share = self.matching_audit(object, audit).ok_or_else(|| {
            CoreError::new(
                "mobile_audit_unknown_share",
                "no stored share matches this audit",
            )
        })?;
        let position = usize::try_from(share.position).map_err(|_| {
            CoreError::new("mobile_audit_position", "the share position does not fit")
        })?;
        let sub = usize::try_from(audit.sub_block).map_err(|_| {
            CoreError::new(
                "mobile_audit_sub_block",
                "the sub-block index does not fit",
            )
        })?;
        prove(share.segment, &share.placed, position, &share.symbol, sub).ok_or_else(|| {
            CoreError::new(
                "mobile_audit_proof_failed",
                "the stored symbol cannot prove this sub-block",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_share_id_exhaustion_does_not_overwrite_a_record() {
        let symbol = vec![1; 64];
        let mut store = ShareStore::new();
        store.next_id = u64::MAX;
        let assigned = AssignedShare {
            object: [1; 32],
            segment: 0,
            esi: 0,
            position: 0,
            placed: vec![(0, symbol_leaf(&symbol))],
            symbol,
        };
        assert!(store.accept(assigned, 1_000).is_err());
        assert!(store.is_empty());
        assert_eq!(store.next_id, u64::MAX);
    }
}
