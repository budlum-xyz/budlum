//! In-memory share store. The durable backend is chosen in `DB_CHOICE.md`.
//!
//! WIRING: [`crate::duty::MobileCore`] is the only caller.

use crate::custody::{prove, symbol_leaf, symbol_root, Audit, CustodyProof, ProofContext};
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

/// Bytes retained per `(u32, [u8; 32])` placement entry (`4 + 32`).
pub const PLACED_ENTRY_BYTES: u64 = 36;
/// Upper bound on retained placement entries per share (matches RFC 6330 ceiling + repair margin).
pub const MAX_PLACED_ENTRIES: usize = 65_536;
/// Upper bound on symbol payload size in bytes (matches RFC 6330 maximum symbol length).
pub const MAX_SYMBOL_BYTES: usize = 65_536;

/// Retained size in bytes of a symbol plus its placement vector.
#[must_use]
pub fn share_retained_bytes(symbol_len: usize, placed_len: usize) -> u64 {
    let symbol_u64 = u64::try_from(symbol_len).unwrap_or(u64::MAX);
    let placed_u64 = u64::try_from(placed_len).unwrap_or(u64::MAX);
    symbol_u64.saturating_add(placed_u64.saturating_mul(PLACED_ENTRY_BYTES))
}

/// Saturating accumulation of per-share retained byte counts.
#[must_use]
fn sum_retained_bytes<I: Iterator<Item = u64>>(sizes: I) -> u64 {
    sizes.fold(0u64, u64::saturating_add)
}

impl ShareRecord {
    /// Stored size of this share (symbol bytes plus retained placement vector).
    #[must_use]
    pub fn size(&self) -> u64 {
        share_retained_bytes(self.symbol.len(), self.placed.len())
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

    /// Bytes currently stored, saturating at `u64::MAX` rather than wrapping or panicking.
    #[must_use]
    pub fn stored_bytes(&self) -> u64 {
        sum_retained_bytes(self.shares.values().map(ShareRecord::size))
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
    /// placed leaf does not match the symbol, the assignment conflicts with
    /// an already stored symbol, or the local id space is exhausted.
    pub fn accept(
        &mut self,
        assigned: AssignedShare,
        quota: u64,
    ) -> Result<ShareRecord, CoreError> {
        if assigned.object == [0u8; 32] {
            return Err(CoreError::new(
                "mobile_zero_object",
                "a custody share cannot reference the all-zero object key",
            ));
        }
        if assigned.symbol.is_empty() {
            return Err(CoreError::new(
                "mobile_empty_symbol",
                "a custody symbol must be at least one byte",
            ));
        }
        if assigned.symbol.len() > MAX_SYMBOL_BYTES {
            return Err(CoreError::new(
                "mobile_symbol_too_large",
                "a custody symbol exceeds the maximum symbol size bound",
            ));
        }
        if assigned.placed.len() > MAX_PLACED_ENTRIES {
            return Err(CoreError::new(
                "mobile_placement_too_large",
                "share placement exceeds maximum retained entry bound",
            ));
        }
        let incoming = share_retained_bytes(assigned.symbol.len(), assigned.placed.len());
        if !fits(self.stored_bytes(), incoming, quota) {
            return Err(CoreError::new(
                "mobile_quota_exceeded",
                "accepting this share would exceed the custody quota",
            ));
        }
        // The position used by audit proofs must identify this exact ESI and
        // leaf, not merely some matching entry elsewhere in the placement.
        // Strict ordering also rules out ambiguous duplicate ESIs.
        if assigned
            .placed
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
        {
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
        if self.shares.values().any(|share| {
            share.object == assigned.object
                && share.segment == assigned.segment
                && (share.position == assigned.position || share.esi == assigned.esi)
        }) {
            return Err(CoreError::new(
                "mobile_share_already_stored",
                "this object's segment already has a symbol at that position or ESI",
            ));
        }
        // Two shares of the same (object, segment) under overlapping ESI ranges
        // belong to the same symbol root and must agree on every placed leaf;
        // repair placements cover strictly higher, disjoint ESI ranges.
        if let (Some(&(new_first, _)), Some(&(new_last, _))) =
            (assigned.placed.first(), assigned.placed.last())
        {
            let conflicts = self.shares.values().any(|share| {
                if share.object != assigned.object || share.segment != assigned.segment {
                    return false;
                }
                let Some(&(old_first, _)) = share.placed.first() else {
                    return false;
                };
                let Some(&(old_last, _)) = share.placed.last() else {
                    return false;
                };
                let overlaps = old_first <= new_last && new_first <= old_last;
                overlaps && share.placed != assigned.placed
            });
            if conflicts {
                return Err(CoreError::new(
                    "mobile_share_placement_conflict",
                    "conflicting placement root for overlapping ESI range in segment",
                ));
            }
        }
        let id = self.next_id;
        let next_id = id.checked_add(1).ok_or_else(|| {
            CoreError::new(
                "mobile_share_id_exhausted",
                "the local share identifier space is exhausted",
            )
        })?;
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
        self.next_id = next_id;
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
        self.shares.values().max_by_key(|s| s.size()).map(|s| s.id)
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
            CoreError::new("mobile_audit_sub_block", "the sub-block index does not fit")
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
    fn mobile_share_id_exhaustion_does_not_overwrite_a_record() -> Result<(), CoreError> {
        let symbol = vec![1; 64];
        let mut store = ShareStore::new();
        let mut assigned = AssignedShare {
            object: [1; 32],
            segment: 0,
            esi: 0,
            position: 0,
            placed: vec![(0, symbol_leaf(&symbol))],
            symbol,
        };
        let original = store.accept(assigned.clone(), 1_000)?;
        store.next_id = u64::MAX;
        assigned.object = [2; 32];
        assert_eq!(
            store.accept(assigned, 1_000).err().map(|e| e.code),
            Some("mobile_share_id_exhausted")
        );
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(original.id), Some(&original));
        assert_eq!(store.next_id, u64::MAX);
        Ok(())
    }

    #[test]
    fn mobile_store_counts_placed_bytes_against_quota_and_caps_entries() {
        let mut store = ShareStore::new();
        let symbol = vec![1u8];
        let mut placed: Vec<(u32, [u8; 32])> = (0..100u32).map(|i| (i, [7; 32])).collect();
        placed[0] = (0, symbol_leaf(&symbol));
        // 1-byte symbol + 100 placement entries = 1 + 3600 = 3601 bytes.
        let assigned = AssignedShare {
            object: [9; 32],
            segment: 0,
            esi: 0,
            position: 0,
            placed,
            symbol,
        };
        assert_eq!(
            store.accept(assigned.clone(), 1_000).err().map(|e| e.code),
            Some("mobile_quota_exceeded")
        );
        let stored = store.accept(assigned, 4_000).unwrap();
        assert_eq!(stored.size(), 1 + 100 * PLACED_ENTRY_BYTES);
        assert_eq!(store.stored_bytes(), 1 + 100 * PLACED_ENTRY_BYTES);
    }

    #[test]
    fn mobile_stored_bytes_saturates_without_overflow() {
        let mut store = ShareStore::new();
        assert_eq!(
            share_retained_bytes(usize::MAX, usize::MAX),
            u64::MAX,
            "share_retained_bytes must saturate at u64::MAX"
        );
        // Directly verify saturating summation across inputs whose exact sum overflows u64.
        assert_eq!(
            sum_retained_bytes([u64::MAX - 10, 25, u64::MAX].into_iter()),
            u64::MAX
        );
        assert_eq!(sum_retained_bytes([120, 340, 40].into_iter()), 500);

        // An empty symbol must be refused so it cannot masquerade as a 64-byte
        // zero-padded symbol while accounting zero symbol bytes.
        let empty = AssignedShare {
            object: [5; 32],
            segment: 0,
            esi: 0,
            position: 0,
            placed: vec![(0, symbol_leaf(&[]))],
            symbol: Vec::new(),
        };
        assert_eq!(
            store.accept(empty, 4_096).err().map(|e| e.code),
            Some("mobile_empty_symbol")
        );

        // A symbol above RFC 6330's 65_536-byte ceiling must be refused even
        // when the quota itself is larger.
        let oversized_bytes = vec![0xAB; MAX_SYMBOL_BYTES + 1];
        let oversized = AssignedShare {
            object: [6; 32],
            segment: 0,
            esi: 0,
            position: 0,
            placed: vec![(0, symbol_leaf(&oversized_bytes))],
            symbol: oversized_bytes,
        };
        assert_eq!(
            store.accept(oversized, u64::MAX).err().map(|e| e.code),
            Some("mobile_symbol_too_large")
        );

        // All-zero object key must be rejected.
        let zero_obj = AssignedShare {
            object: [0; 32],
            segment: 0,
            esi: 0,
            position: 0,
            placed: vec![(0, symbol_leaf(b"ok"))],
            symbol: b"ok".to_vec(),
        };
        assert_eq!(
            store.accept(zero_obj, 4_096).err().map(|e| e.code),
            Some("mobile_zero_object")
        );

        // Overlapping ESI range with mutated placement root must be rejected, while
        // a disjoint higher-ESI repair root on the same (object, segment) is accepted.
        let s0 = b"sym0".to_vec();
        let s1 = b"sym1".to_vec();
        let honest_placed = vec![(0, symbol_leaf(&s0)), (1, symbol_leaf(&s1))];
        store
            .accept(
                AssignedShare {
                    object: [9; 32],
                    segment: 0,
                    esi: 0,
                    position: 0,
                    placed: honest_placed,
                    symbol: s0,
                },
                4_096,
            )
            .unwrap();
        let conflicting_placed = vec![(0, [0xEE; 32]), (1, symbol_leaf(&s1))];
        assert_eq!(
            store
                .accept(
                    AssignedShare {
                        object: [9; 32],
                        segment: 0,
                        esi: 1,
                        position: 1,
                        placed: conflicting_placed,
                        symbol: s1,
                    },
                    4_096,
                )
                .err()
                .map(|e| e.code),
            Some("mobile_share_placement_conflict")
        );
        let rep0 = b"rep0".to_vec();
        let rep1 = b"rep1".to_vec();
        store
            .accept(
                AssignedShare {
                    object: [9; 32],
                    segment: 0,
                    esi: 11,
                    position: 1,
                    placed: vec![(10, symbol_leaf(&rep0)), (11, symbol_leaf(&rep1))],
                    symbol: rep1,
                },
                4_096,
            )
            .unwrap();
    }
}
