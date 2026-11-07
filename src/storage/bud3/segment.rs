//! Segmentation and the object commitment.
//!
//! The object bytes are cut into segments of `k_max x symbol_size` bytes; the
//! last segment is shorter. Each segment is one RFC 6330 source block and is
//! coded on its own, so no per-object source-block ceiling applies. All
//! lengths and offsets are `u64`, so an object above 4 GiB has no truncation
//! point.
//!
//! * Segment digest: `SHA-256` over the length-prefixed fields
//!   `BDLM_BUD3_SEGMENT_V1`, the segment index (`u64` little-endian) and the
//!   segment bytes.
//! * Object commitment: a binary Merkle tree over the segment digests. A node
//!   is `SHA-256(len-prefixed BDLM_BUD3_OBJECT_V1, 0x01, left, right)`; an odd
//!   node moves up unchanged (it is never paired with itself). The commitment
//!   is the length-prefixed hash of the tag, `0x00`, the segment count and the
//!   tree root, so two objects with a different segment count never share a
//!   commitment.
//!
//! Segment digests are not written in the object: they are computed from it.
//! Convenience: public B.U.D. 3.0 segment domain tags and tree builders.

use super::limits::Profile;
use crate::core::hash::hash_fields_bytes;

/// The segment digest tag.
pub const SEGMENT_TAG: &[u8] = b"BDLM_BUD3_SEGMENT_V1";
/// The object commitment tag.
pub const OBJECT_TAG: &[u8] = b"BDLM_BUD3_OBJECT_V1";

/// The 32-byte object commitment.
pub type ObjectCommitment = [u8; 32];

/// The segment layout of one object under one profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segmentation {
    object_len: u64,
    segment_bytes: u64,
    symbol_size: u64,
}

impl Segmentation {
    /// The layout of an object of `object_len` bytes. `None` for an invalid
    /// profile.
    #[must_use]
    pub const fn new(object_len: u64, profile: &Profile) -> Option<Self> {
        if !profile.is_valid() {
            return None;
        }
        Some(Self {
            object_len,
            segment_bytes: profile.segment_bytes(),
            symbol_size: profile.symbol_size as u64,
        })
    }

    /// The object length.
    #[must_use]
    pub const fn object_len(&self) -> u64 {
        self.object_len
    }

    /// The number of segments; an empty object still has one (empty) segment.
    #[must_use]
    pub const fn count(&self) -> u64 {
        if self.object_len == 0 {
            1
        } else {
            self.object_len.div_ceil(self.segment_bytes)
        }
    }

    /// Byte offset of segment `index` in the object.
    #[must_use]
    pub const fn offset(&self, index: u64) -> Option<u64> {
        if index >= self.count() {
            return None;
        }
        Some(index * self.segment_bytes)
    }

    /// Length of segment `index` in bytes.
    #[must_use]
    pub const fn len(&self, index: u64) -> Option<u64> {
        let Some(offset) = self.offset(index) else {
            return None;
        };
        let rest = self.object_len - offset;
        Some(if rest < self.segment_bytes {
            rest
        } else {
            self.segment_bytes
        })
    }

    /// Source symbols of segment `index` (`k`). At least one, so an empty
    /// segment still codes to a padded symbol.
    #[must_use]
    pub const fn source_symbols(&self, index: u64) -> Option<u64> {
        let Some(len) = self.len(index) else {
            return None;
        };
        let k = len.div_ceil(self.symbol_size);
        Some(if k == 0 { 1 } else { k })
    }

    /// Total source symbols of the object (the frame count of the logical
    /// path without repair).
    #[must_use]
    pub const fn total_source_symbols(&self) -> u64 {
        if self.object_len == 0 {
            1
        } else {
            self.object_len.div_ceil(self.symbol_size)
        }
    }
}

/// The digest of segment `index` with bytes `bytes`.
#[must_use]
pub fn segment_digest(index: u64, bytes: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[SEGMENT_TAG, &index.to_le_bytes(), bytes])
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[OBJECT_TAG, &[0x01], left, right])
}

/// The object commitment over the segment digests, in segment order.
#[must_use]
pub fn object_commitment(digests: &[[u8; 32]]) -> ObjectCommitment {
    let mut level: Vec<[u8; 32]> = digests.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => node(l, r),
                [one] => *one,
                _ => [0u8; 32],
            })
            .collect();
    }
    let root = level.first().copied().unwrap_or([0u8; 32]);
    hash_fields_bytes(&[
        OBJECT_TAG,
        &[0x00],
        &(digests.len() as u64).to_le_bytes(),
        &root,
    ])
}

/// The commitment of an object held in memory.
#[must_use]
pub fn commit_object(object: &[u8], profile: &Profile) -> Option<ObjectCommitment> {
    let seg = Segmentation::new(object.len() as u64, profile)?;
    let mut digests = Vec::new();
    for index in 0..seg.count() {
        let start = usize::try_from(seg.offset(index)?).ok()?;
        let len = usize::try_from(seg.len(index)?).ok()?;
        let bytes = object.get(start..start.checked_add(len)?)?;
        digests.push(segment_digest(index, bytes));
    }
    Some(object_commitment(&digests))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 16,
        fps: 10,
        k_max: 4,
    };

    #[test]
    fn segment_offsets_are_u64() {
        let p = Profile::P0;
        // Sixteen GiB plus one byte: well past u32 and the 256-block ceiling.
        let len = 16 * super::super::limits::GIB + 1;
        let s = Segmentation::new(len, &p).unwrap();
        let n = s.count();
        assert!(n > 256, "no per-object source block ceiling: {n}");
        let last = n - 1;
        assert!(s.offset(last).unwrap() > u64::from(u32::MAX));
        let total: u64 = (0..n).map(|i| s.len(i).unwrap()).sum();
        assert_eq!(total, len);
        assert_eq!(s.len(last), Some(len - last * p.segment_bytes()));
        assert_eq!(s.offset(n), None);
    }

    #[test]
    fn small_layout() {
        let s = Segmentation::new(100, &SMALL).unwrap();
        // 64-byte segments: 64 + 36.
        assert_eq!(s.count(), 2);
        assert_eq!((s.len(0), s.len(1)), (Some(64), Some(36)));
        assert_eq!(
            (s.source_symbols(0), s.source_symbols(1)),
            (Some(4), Some(3))
        );
        assert_eq!(s.total_source_symbols(), 7);
        let empty = Segmentation::new(0, &SMALL).unwrap();
        assert_eq!((empty.count(), empty.source_symbols(0)), (1, Some(1)));
    }

    #[test]
    fn segment_digest_binds_index_and_bytes() {
        assert_ne!(segment_digest(0, b"x"), segment_digest(1, b"x"));
        assert_ne!(segment_digest(0, b"x"), segment_digest(0, b"y"));
    }

    #[test]
    fn commitment_binds_order_count_and_content() {
        let a = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let b = [[2u8; 32], [1u8; 32], [3u8; 32]];
        assert_ne!(object_commitment(&a), object_commitment(&b));
        // An odd node is not paired with itself: [x, y, z] != [x, y, z, z].
        let dup = [[1u8; 32], [2u8; 32], [3u8; 32], [3u8; 32]];
        assert_ne!(object_commitment(&a), object_commitment(&dup));
        // One segment: the commitment is not the bare digest.
        assert_ne!(object_commitment(&[[9u8; 32]]), [9u8; 32]);
        let obj: Vec<u8> = (0..200u8).collect();
        let c1 = commit_object(&obj, &SMALL).unwrap();
        let mut tampered = obj.clone();
        tampered[150] ^= 1;
        assert_ne!(c1, commit_object(&tampered, &SMALL).unwrap());
    }
}
