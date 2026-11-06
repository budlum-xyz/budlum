//! Aggregation Volume for sub-symbol B.U.D. 3.0 objects (Section 6.12, WP-21 item 4).
//! exposed for upload small-object packing, gateway reads, and compaction sweeps.
//!
//! Per Section 6.12:
//! 1. Objects smaller than a single symbol (`< symbol_size`, 2,911 bytes in P0)
//!    are neither placed alone nor kept as full replicas.
//! 2. Small objects pack into an [`AggregationVolume`] (default 4 MiB,
//!    `DEFAULT_VOLUME_BYTES`) that is segmented, Fountain-coded, and placed like
//!    a single segment.
//! 3. Each small object retains its own BOF-1 [`ObjectKey`] commitment and is
//!    located inside the volume by `(offset, len)` plus a Merkle inclusion proof
//!    under `BDLM_BUD3_VOLUME_V1`.
//! 4. A volume never mixes visibilities or owners: it is either [`VolumeScope::Public`]
//!    or [`VolumeScope::SealedOwner`].
//! 5. When an entry's reference count drops to zero it is evicted from active
//!    entries and the volume is marked for re-encoding within at most 7 days
//!    (`VOLUME_REENCODE_MAX_SECS`).

use super::bof1::Object;
use super::limits::Profile;
use super::registry::{Address, ObjectKey};
use super::segment::commit_object;
use crate::core::hash::hash_fields_bytes;

/// Domain tag for Aggregation Volume leaf/node/root Merkle commitments.
pub const VOLUME_TAG: &[u8] = b"BDLM_BUD3_VOLUME_V1";

/// Default Aggregation Volume capacity in bytes (4 MiB, TESTNET-DEFAULT Section 6.12.6).
pub const DEFAULT_VOLUME_BYTES: usize = 4 * 1024 * 1024;

/// Maximum re-encoding delay after an entry's refcount reaches zero (7 days, Section 6.12.5).
pub const VOLUME_REENCODE_MAX_SECS: u64 = 7 * 86_400;

/// Visibility and ownership isolation boundary of an [`AggregationVolume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeScope {
    /// Public small objects only (`!Flags::SEALED`).
    Public,
    /// Sealed small objects belonging to a single owner (`Flags::SEALED`).
    SealedOwner(Address),
}

/// Metadata and byte location of one small object packed inside a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeEntry {
    /// Standalone BOF-1 commitment of the small object (never altered by packing).
    pub object: ObjectKey,
    /// Byte offset inside the volume buffer.
    pub offset: u64,
    /// Encoded BOF-1 byte length of the small object.
    pub len: u64,
    /// Whether this entry is still live (`false` once refcount hits 0).
    pub active: bool,
}

/// Merkle inclusion proof locating one [`VolumeEntry`] under a volume's root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInclusionProof {
    /// Leaf index in the volume's entry list.
    pub index: u64,
    /// Total leaves in the volume Merkle tree.
    pub leaf_count: u64,
    /// Byte offset in the packed volume payload.
    pub offset: u64,
    /// Byte length of the encoded BOF-1 object.
    pub len: u64,
    /// Sibling hashes (`None` when an odd node moved up unchanged).
    pub path: Vec<Option<[u8; 32]>>,
}

/// Errors packing or reading an [`AggregationVolume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeError {
    /// Object is at least one full symbol (`>= symbol_size`) and does not belong in a small-object volume.
    NotSmallObject,
    /// Mixing public and sealed objects (or different owners) in one volume is forbidden.
    ScopeMismatch,
    /// Volume has insufficient remaining space under `max_bytes`.
    VolumeFull,
    /// Duplicate object commitment in the same volume.
    DuplicateEntry,
    /// Requested object is not active in this volume.
    UnknownEntry,
    /// Object commitment failed to compute.
    CommitmentFailed,
}

fn entry_leaf_hash(index: u64, entry: &VolumeEntry, bytes: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[
        VOLUME_TAG,
        &[0x00],
        &index.to_le_bytes(),
        &entry.object,
        &entry.offset.to_le_bytes(),
        &entry.len.to_le_bytes(),
        bytes,
    ])
}

fn volume_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[VOLUME_TAG, &[0x01], left, right])
}

fn volume_root_hash(count: u64, top: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[VOLUME_TAG, &[0x02], &count.to_le_bytes(), top])
}

/// Whether an encoded BOF-1 object of `object_len` bytes belongs in an
/// [`AggregationVolume`] (`object_len < profile.symbol_size`).
#[must_use]
pub const fn qualifies_for_volume(object_len: u64, profile: &Profile) -> bool {
    object_len < profile.symbol_size as u64
}

/// Packed small-object container encoded and placed as B.U.D. 3.0 segments.
#[derive(Debug, Clone)]
pub struct AggregationVolume {
    scope: VolumeScope,
    profile: Profile,
    max_bytes: usize,
    data: Vec<u8>,
    entries: Vec<VolumeEntry>,
    reencode_due_by_sec: Option<u64>,
}

impl AggregationVolume {
    /// Create a fresh empty [`AggregationVolume`] for `scope` and `profile`.
    #[must_use]
    pub fn new(scope: VolumeScope, profile: Profile, max_bytes: usize) -> Self {
        Self {
            scope,
            profile,
            max_bytes: max_bytes.max(usize::from(profile.symbol_size)),
            data: Vec::new(),
            entries: Vec::new(),
            reencode_due_by_sec: None,
        }
    }

    /// Visibility/owner scope of this volume.
    #[must_use]
    pub const fn scope(&self) -> VolumeScope {
        self.scope
    }

    /// Packed volume bytes ready for segment encoding and placement.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Deadline timestamp (`now_sec + 7 days`) by which evicted entries must be
    /// compacted via [`Self::reencode_compact`], if any eviction occurred.
    #[must_use]
    pub const fn reencode_due_by_sec(&self) -> Option<u64> {
        self.reencode_due_by_sec
    }

    /// Append a small BOF-1 `object` owned by `owner` (ignored for public scope).
    ///
    /// # Errors
    ///
    /// [`VolumeError`] if `object` is `>= symbol_size`, violates `scope`,
    /// duplicates an existing entry, or exceeds `max_bytes`.
    pub fn insert(
        &mut self,
        object: &Object,
        owner: Option<Address>,
    ) -> Result<VolumeEntry, VolumeError> {
        match (self.scope, object.header.is_sealed(), owner) {
            (VolumeScope::Public, false, _) => {}
            (VolumeScope::SealedOwner(expected), true, Some(actual)) if expected == actual => {}
            _ => return Err(VolumeError::ScopeMismatch),
        }
        let encoded = object.encode();
        if !qualifies_for_volume(encoded.len() as u64, &self.profile) {
            return Err(VolumeError::NotSmallObject);
        }
        if self.data.len().saturating_add(encoded.len()) > self.max_bytes {
            return Err(VolumeError::VolumeFull);
        }
        let commitment =
            commit_object(&encoded, &self.profile).ok_or(VolumeError::CommitmentFailed)?;
        if self.entries.iter().any(|e| e.active && e.object == commitment) {
            return Err(VolumeError::DuplicateEntry);
        }
        let entry = VolumeEntry {
            object: commitment,
            offset: self.data.len() as u64,
            len: encoded.len() as u64,
            active: true,
        };
        self.data.extend_from_slice(&encoded);
        self.entries.push(entry);
        Ok(entry)
    }

    /// Evict `object` when its reference count hits zero and schedule volume
    /// compaction within `VOLUME_REENCODE_MAX_SECS` (7 days).
    ///
    /// # Errors
    ///
    /// [`VolumeError::UnknownEntry`] if `object` is not active in this volume.
    pub fn evict(&mut self, object: &ObjectKey, now_sec: u64) -> Result<(), VolumeError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.object == *object)
            .ok_or(VolumeError::UnknownEntry)?;
        entry.active = false;
        let due = now_sec.saturating_add(VOLUME_REENCODE_MAX_SECS);
        self.reencode_due_by_sec = Some(self.reencode_due_by_sec.map_or(due, |cur| cur.min(due)));
        Ok(())
    }

    /// Compact out evicted entries and produce a clean [`AggregationVolume`]
    /// preserving every active object's standalone commitment.
    #[must_use]
    pub fn reencode_compact(&self) -> Self {
        let mut next_data = Vec::with_capacity(self.data.len());
        let mut next_entries = Vec::new();
        for e in self.entries.iter().filter(|e| e.active) {
            let Ok(start) = usize::try_from(e.offset) else {
                continue;
            };
            let Ok(len) = usize::try_from(e.len) else {
                continue;
            };
            let Some(end) = start.checked_add(len) else {
                continue;
            };
            let Some(slice) = self.data.get(start..end) else {
                continue;
            };
            let new_offset = next_data.len() as u64;
            next_data.extend_from_slice(slice);
            next_entries.push(VolumeEntry {
                object: e.object,
                offset: new_offset,
                len: e.len,
                active: true,
            });
        }
        Self {
            scope: self.scope,
            profile: self.profile,
            max_bytes: self.max_bytes,
            data: next_data,
            entries: next_entries,
            reencode_due_by_sec: None,
        }
    }

    fn active_leaves(&self) -> Vec<(VolumeEntry, &[u8], [u8; 32])> {
        let mut out = Vec::new();
        for e in self.entries.iter().filter(|e| e.active) {
            let Ok(start) = usize::try_from(e.offset) else {
                continue;
            };
            let Ok(len) = usize::try_from(e.len) else {
                continue;
            };
            let Some(end) = start.checked_add(len) else {
                continue;
            };
            let Some(slice) = self.data.get(start..end) else {
                continue;
            };
            let idx = out.len() as u64;
            let leaf = entry_leaf_hash(idx, e, slice);
            out.push((*e, slice, leaf));
        }
        out
    }

    /// Merkle root over all active entries in this volume.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self.active_leaves().into_iter().map(|(_, _, h)| h).collect();
        let count = leaves.len() as u64;
        let mut level = leaves;
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [l, r] => volume_node_hash(l, r),
                    [one] => *one,
                    _ => [0u8; 32],
                })
                .collect();
        }
        let top = level.first().copied().unwrap_or([0u8; 32]);
        volume_root_hash(count, &top)
    }

    /// Extract the encoded BOF-1 bytes and Merkle inclusion proof of `object`.
    ///
    /// # Errors
    ///
    /// [`VolumeError::UnknownEntry`] if `object` is not active in this volume.
    pub fn get_with_proof(
        &self,
        object: &ObjectKey,
    ) -> Result<(Vec<u8>, VolumeInclusionProof), VolumeError> {
        let active = self.active_leaves();
        let want_idx = active
            .iter()
            .position(|(e, _, _)| e.object == *object)
            .ok_or(VolumeError::UnknownEntry)?;
        let (entry, slice, _) = *active.get(want_idx).ok_or(VolumeError::UnknownEntry)?;
        let count = active.len() as u64;
        let mut level: Vec<[u8; 32]> = active.into_iter().map(|(_, _, h)| h).collect();
        let mut pos = want_idx;
        let mut path = Vec::new();
        while level.len() > 1 {
            let sibling = if pos.is_multiple_of(2) { pos + 1 } else { pos - 1 };
            path.push(level.get(sibling).copied());
            pos /= 2;
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [l, r] => volume_node_hash(l, r),
                    [one] => *one,
                    _ => [0u8; 32],
                })
                .collect();
        }
        Ok((
            slice.to_vec(),
            VolumeInclusionProof {
                index: want_idx as u64,
                leaf_count: count,
                offset: entry.offset,
                len: entry.len,
                path,
            },
        ))
    }

    /// Retrieve `object` along with its [`VolumeInclusionProof`] and self-verify
    /// the Merkle proof against [`Self::root`] before returning.
    /// Convenience: exposed for gateway and client small-object reads.
    pub fn get_verified(
        &self,
        object: &ObjectKey,
    ) -> Result<(Vec<u8>, VolumeInclusionProof), VolumeError> {
        let (bytes, proof) = self.get_with_proof(object)?;
        let root = self.root();
        if !verify_volume_inclusion(&root, object, &bytes, &proof) {
            return Err(VolumeError::UnknownEntry);
        }
        Ok((bytes, proof))
    }
}

/// Verify a [`VolumeInclusionProof`] for `object` and `encoded_bytes` against `volume_root`.
#[must_use]
pub fn verify_volume_inclusion(
    volume_root: &[u8; 32],
    object: &ObjectKey,
    encoded_bytes: &[u8],
    proof: &VolumeInclusionProof,
) -> bool {
    if proof.leaf_count == 0 || proof.index >= proof.leaf_count || encoded_bytes.len() as u64 != proof.len {
        return false;
    }
    let entry = VolumeEntry {
        object: *object,
        offset: proof.offset,
        len: proof.len,
        active: true,
    };
    let mut cur = entry_leaf_hash(proof.index, &entry, encoded_bytes);
    let mut idx = proof.index;
    let mut width = proof.leaf_count;
    for step in &proof.path {
        if width <= 1 {
            return false;
        }
        match step {
            Some(sib) => {
                cur = if idx.is_multiple_of(2) {
                    volume_node_hash(&cur, sib)
                } else {
                    volume_node_hash(sib, &cur)
                };
            }
            None => {
                if !idx.is_multiple_of(2) || idx + 1 != width {
                    return false;
                }
            }
        }
        idx /= 2;
        width = width.div_ceil(2);
    }
    width == 1 && volume_root_hash(proof.leaf_count, &cur) == *volume_root
}

#[cfg(test)]
mod tests {
    use super::super::keys::derive_object_content_key;
    use super::super::seal::seal_object;
    use super::*;

    #[test]
    fn bud3_aggregation_volume() {
        let mut vol = AggregationVolume::new(VolumeScope::Public, Profile::P0, DEFAULT_VOLUME_BYTES);
        let o1 = Object::raw_public(b"tiny object one");
        let o2 = Object::raw_public(b"tiny object two");
        let o3 = Object::raw_public(b"tiny object three");

        let e1 = vol.insert(&o1, None).unwrap();
        let e2 = vol.insert(&o2, None).unwrap();
        let e3 = vol.insert(&o3, None).unwrap();

        // Sealed object cannot enter a public volume (Section 6.12.4).
        let sealed = seal_object(
            b"secret",
            &derive_object_content_key(&[9; 32], 1),
            [1; 24],
        )
        .unwrap();
        assert_eq!(
            vol.insert(&sealed, Some([1; 32])),
            Err(VolumeError::ScopeMismatch)
        );

        let root = vol.root();
        for e in [e1, e2, e3] {
            let (bytes, proof) = vol.get_with_proof(&e.object).unwrap();
            assert!(verify_volume_inclusion(&root, &e.object, &bytes, &proof));
        }

        // Evicting o2 schedules 7-day compaction while preserving o1 and o3 commitments!
        vol.evict(&e2.object, 1_000).unwrap();
        assert_eq!(vol.reencode_due_by_sec(), Some(1_000 + VOLUME_REENCODE_MAX_SECS));
        assert_eq!(vol.get_with_proof(&e2.object), Err(VolumeError::UnknownEntry));

        let compacted = vol.reencode_compact();
        assert!(compacted.reencode_due_by_sec().is_none());
        let new_root = compacted.root();
        let (b1, p1) = compacted.get_with_proof(&e1.object).unwrap();
        let (b3, p3) = compacted.get_with_proof(&e3.object).unwrap();
        assert!(verify_volume_inclusion(&new_root, &e1.object, &b1, &p1));
        assert!(verify_volume_inclusion(&new_root, &e3.object, &b3, &p3));
    }
}
