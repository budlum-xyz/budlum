//! Aggregation volumes: small objects share one placed segment.
//!
//! An object whose bytes fit inside one symbol is not placed on its own and is
//! not kept as a full copy. Small objects are joined in an aggregation volume,
//! and the volume is coded and placed exactly like one segment. Every member is
//! found by its offset and a Merkle proof; the object commitment of the member
//! does not change.
//!
//! * Member leaf: `SHA-256` over the length-prefixed fields
//!   `BDLM_BUD3_VOLUME_V1`, `0x00`, the member index (`u64` little-endian),
//!   the offset (`u64`), the length (`u64`), the content-id kind byte, the
//!   content-id digest, the content length and the object commitment.
//! * Volume root: a binary Merkle tree over the member leaves. An odd node
//!   moves up unchanged, and the root binds the member count, so two volumes
//!   with a different member count never share a root.
//! * Volume id: `SHA-256` over `BDLM_BUD3_VOLUME_V1`, `0x03`, the visibility
//!   tag, the owner, the volume length and the volume bytes. A view checks it,
//!   so bytes that arrive from holders are refused unless they are the bytes
//!   the chain recorded.
//!
//! Only objects of one visibility share a volume: a public volume, or the
//! sealed volume of one owner. A deletion takes the member out of the table and
//! zeroes its slot. For sealed content that zeroing is the crypto shredding and
//! it is effective at once; for public content the volume is recoded within
//! [`RECODE_DEADLINE_SECS`].
//!
//! WIRING: unwired - [`super::pipeline`] builds and views a volume for the
//! upload and view paths. The delete path of `bud3::delete` and the reference
//! counter (WP-22) call [`AggregationVolume::remove`],
//! [`AggregationVolume::needs_recode`] and [`AggregationVolume::compact`] once
//! that door lands.

use super::content_id::{ContentId, ContentIdKind};
use super::registry::Address;
use crate::core::hash::hash_fields_bytes;

/// The domain tag of every volume hash.
pub const VOLUME_TAG: &[u8] = b"BDLM_BUD3_VOLUME_V1";
/// TESTNET-DEFAULT volume length: 4 MiB (section 6.12 item 6).
pub const DEFAULT_VOLUME_BYTES: u64 = 4 * 1024 * 1024;
/// A public volume with a freed slot is recoded within seven days.
pub const RECODE_DEADLINE_SECS: u64 = 7 * 24 * 60 * 60;
/// The most members one volume may carry. The proof walk is bounded by it.
pub const MAX_MEMBERS: usize = 1 << 16;
/// The longest Merkle path a proof may carry.
pub const MAX_PATH: usize = 32;

/// One step of a member path: the sibling, or `None` where the node had no
/// sibling and moved up unchanged.
pub type PathStep = Option<[u8; 32]>;

/// What a volume may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Public content only.
    Public,
    /// Sealed content of one owner only.
    Sealed(Address),
}

impl Visibility {
    /// The tag and the owner the volume id binds.
    #[must_use]
    fn tag(&self) -> (&'static [u8], [u8; 32]) {
        match self {
            Self::Public => (b"public", [0u8; 32]),
            Self::Sealed(owner) => (b"sealed", *owner),
        }
    }

    /// Whether the volume carries sealed content.
    #[must_use]
    /// WIRING: exercised by the WP-21 volume session and deletion sweep.
    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }

    /// The owner of a sealed volume.
    #[must_use]
    /// WIRING: exercised by the WP-21 volume session and deletion sweep.
    pub fn owner(&self) -> Option<Address> {
        match self {
            Self::Public => None,
            Self::Sealed(owner) => Some(*owner),
        }
    }
}

/// One small object inside a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeMember {
    /// The content id of the member. Its kind must match the volume.
    pub content_id: ContentId,
    /// Byte offset of the member inside the volume.
    pub offset: u64,
    /// Member length in bytes.
    pub len: u64,
    /// The object commitment of the member. It does not change when the member
    /// joins a volume.
    pub commitment: [u8; 32],
}

impl VolumeMember {
    /// The leaf of this member at `index` in the volume.
    #[must_use]
    fn leaf(&self, index: u64) -> [u8; 32] {
        let kind = match self.content_id.kind {
            ContentIdKind::Public => 0u8,
            ContentIdKind::Sealed => 1u8,
        };
        hash_fields_bytes(&[
            VOLUME_TAG,
            &[0x00],
            &index.to_le_bytes(),
            &self.offset.to_le_bytes(),
            &self.len.to_le_bytes(),
            &[kind],
            &self.content_id.digest,
            &self.content_id.len.to_le_bytes(),
            &self.commitment,
        ])
    }
}

/// A slot freed by a deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Freed {
    /// Offset of the freed slot.
    pub offset: u64,
    /// Length of the freed slot.
    pub len: u64,
    /// Unix seconds of the deletion.
    pub at: u64,
    /// Whether the volume is sealed. A sealed slot is shredded at once and
    /// needs no recode.
    pub sealed: bool,
}

/// The result of taking a member out of a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Removal {
    /// The member that left.
    pub member: VolumeMember,
    /// Whether the volume is sealed.
    pub sealed: bool,
    /// The time the deletion is effective, when it is immediate.
    pub effective_at: Option<u64>,
}

/// Why a volume refused a member or a view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeError {
    /// The capacity is zero, so no member would ever be admitted.
    EmptyCapacity,
    /// The batch has no object, so there is nothing to place.
    EmptyVolume,
    /// The object is not smaller than one symbol, so it is placed on its own.
    NotSmall {
        /// Object length.
        len: u64,
        /// Symbol size of the profile.
        symbol_size: u64,
    },
    /// The volume has no room left.
    Capacity {
        /// Member length.
        len: u64,
        /// Free bytes before the member.
        free: u64,
        /// Volume capacity.
        capacity: u64,
    },
    /// A sealed object was offered to a public volume, or the reverse.
    MixedVisibility,
    /// The content id is already a member.
    DuplicateMember,
    /// The member table is full.
    TooManyMembers {
        /// Members now.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// The content id is not a member.
    UnknownMember,
    /// An offset or a length does not fit a `u64`.
    OffsetOverflow,
    /// The member table does not tile the volume bytes, or a hole is not zero.
    LayoutMismatch,
    /// A length differs from the recorded one.
    LengthMismatch {
        /// Recorded length.
        want: u64,
        /// Recovered length.
        got: u64,
    },
    /// The recovered bytes are not the bytes the chain recorded.
    IdMismatch,
    /// The member table does not match the recorded root.
    RootMismatch,
    /// The member path does not lead to the recorded root.
    ProofMismatch,
}

/// A placed aggregation volume.
#[derive(Debug, Clone)]
pub struct AggregationVolume {
    visibility: Visibility,
    capacity: u64,
    bytes: Vec<u8>,
    members: Vec<VolumeMember>,
    freed: Vec<Freed>,
    root: [u8; 32],
    volume_id: [u8; 32],
}

impl AggregationVolume {
    /// An empty volume of one visibility.
    ///
    /// # Errors
    ///
    /// [`VolumeError::EmptyCapacity`] for a zero capacity.
    pub fn new(visibility: Visibility, capacity: u64) -> Result<Self, VolumeError> {
        if capacity == 0 {
            return Err(VolumeError::EmptyCapacity);
        }
        let mut volume = Self {
            visibility,
            capacity,
            bytes: Vec::new(),
            members: Vec::new(),
            freed: Vec::new(),
            root: root_of(&[]),
            volume_id: [0u8; 32],
        };
        volume.volume_id = volume_id_of(&volume.visibility, &[]);
        Ok(volume)
    }

    /// The visibility.
    #[must_use]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// The capacity in bytes.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }

    /// The volume bytes: the members in insertion order, with freed slots
    /// zeroed.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The volume length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Whether the volume has no member.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Free bytes before the capacity.
    #[must_use]
    pub fn free(&self) -> u64 {
        self.capacity.saturating_sub(self.len())
    }

    /// The member table.
    #[must_use]
    pub fn members(&self) -> &[VolumeMember] {
        &self.members
    }

    /// The freed slots.
    #[must_use]
    pub fn freed(&self) -> &[Freed] {
        &self.freed
    }

    /// The member root.
    #[must_use]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The volume id.
    #[must_use]
    pub const fn volume_id(&self) -> [u8; 32] {
        self.volume_id
    }

    /// The member with this content id.
    #[must_use]
    pub fn member(&self, content_id: &ContentId) -> Option<&VolumeMember> {
        self.members.iter().find(|m| m.content_id == *content_id)
    }

    /// Join one object. The object must be smaller than one symbol, must match
    /// the volume visibility and must not already be a member.
    ///
    /// # Errors
    ///
    /// [`VolumeError`] for a large object, a full volume, a repeated content
    /// id, a visibility mismatch or an offset that does not fit.
    pub fn push(
        &mut self,
        content_id: &ContentId,
        commitment: [u8; 32],
        bytes: &[u8],
        symbol_size: u32,
    ) -> Result<VolumeMember, VolumeError> {
        let len = bytes.len() as u64;
        let symbol_size = u64::from(symbol_size);
        if symbol_size == 0 || len >= symbol_size {
            return Err(VolumeError::NotSmall { len, symbol_size });
        }
        if self.members.len() >= MAX_MEMBERS {
            return Err(VolumeError::TooManyMembers {
                count: self.members.len(),
                max: MAX_MEMBERS,
            });
        }
        if self.member(content_id).is_some() {
            return Err(VolumeError::DuplicateMember);
        }
        let visible = match self.visibility {
            Visibility::Public => content_id.kind == ContentIdKind::Public,
            Visibility::Sealed(_) => content_id.kind == ContentIdKind::Sealed,
        };
        if !visible {
            return Err(VolumeError::MixedVisibility);
        }
        let offset = self.len();
        let end = offset.checked_add(len).ok_or(VolumeError::OffsetOverflow)?;
        if end > self.capacity {
            return Err(VolumeError::Capacity {
                len,
                free: self.free(),
                capacity: self.capacity,
            });
        }
        self.bytes.extend_from_slice(bytes);
        let member = VolumeMember {
            content_id: *content_id,
            offset,
            len,
            commitment,
        };
        self.members.push(member);
        self.rehash();
        Ok(member)
    }

    /// The Merkle path of one member, if it is a member.
    ///
    /// WIRING: the reveal path of WP-21 hands this path to a viewer with the
    /// member, so the viewer checks the member against the root it holds.
    #[must_use]
    pub fn member_proof(&self, content_id: &ContentId) -> Option<Vec<PathStep>> {
        let index = self
            .members
            .iter()
            .position(|m| m.content_id == *content_id)?;
        Some(proof_for(&self.members, index))
    }

    /// Take a member out. Its slot is zeroed, the table is rebuilt and the
    /// volume id follows the bytes.
    ///
    /// WIRING: the `SocialDelete` and reference-counter door of WP-22 calls
    /// this when the last reference to a member is burned.
    ///
    /// # Errors
    ///
    /// [`VolumeError::UnknownMember`] when the content id is not a member.
    pub fn remove(&mut self, content_id: &ContentId, now: u64) -> Result<Removal, VolumeError> {
        let index = self
            .members
            .iter()
            .position(|m| m.content_id == *content_id)
            .ok_or(VolumeError::UnknownMember)?;
        let member = self.members[index];
        let start = usize::try_from(member.offset).map_err(|_| VolumeError::OffsetOverflow)?;
        let len = usize::try_from(member.len).map_err(|_| VolumeError::OffsetOverflow)?;
        let end = start.checked_add(len).ok_or(VolumeError::OffsetOverflow)?;
        let slot = self
            .bytes
            .get_mut(start..end)
            .ok_or(VolumeError::OffsetOverflow)?;
        slot.fill(0);
        self.members.remove(index);
        let sealed = self.visibility.is_sealed();
        self.freed.push(Freed {
            offset: member.offset,
            len: member.len,
            at: now,
            sealed,
        });
        self.rehash();
        Ok(Removal {
            member,
            sealed,
            effective_at: if sealed { Some(now) } else { None },
        })
    }

    /// Whether a freed public slot has waited out [`RECODE_DEADLINE_SECS`].
    ///
    /// WIRING: the maintenance pass of WP-21 calls this before it recodes a
    /// volume, and the delete door of WP-22 records the deadline beside it.
    #[must_use]
    pub fn needs_recode(&self, now: u64) -> bool {
        self.freed
            .iter()
            .any(|f| !f.sealed && now.saturating_sub(f.at) >= RECODE_DEADLINE_SECS)
    }

    /// Recode the volume: the members move together and the holes leave.
    ///
    /// WIRING: the maintenance pass of WP-21 calls this when
    /// [`AggregationVolume::needs_recode`] says the deadline has passed.
    ///
    /// # Errors
    ///
    /// [`VolumeError::OffsetOverflow`] for a slot outside the bytes.
    pub fn compact(&mut self) -> Result<(), VolumeError> {
        let mut bytes = Vec::with_capacity(self.bytes.len());
        let mut members = Vec::with_capacity(self.members.len());
        for member in &self.members {
            let start = usize::try_from(member.offset).map_err(|_| VolumeError::OffsetOverflow)?;
            let len = usize::try_from(member.len).map_err(|_| VolumeError::OffsetOverflow)?;
            let end = start.checked_add(len).ok_or(VolumeError::OffsetOverflow)?;
            let slot = self
                .bytes
                .get(start..end)
                .ok_or(VolumeError::OffsetOverflow)?;
            let offset = bytes.len() as u64;
            bytes.extend_from_slice(slot);
            members.push(VolumeMember {
                offset,
                ..*member
            });
        }
        self.bytes = bytes;
        self.members = members;
        self.freed.clear();
        self.rehash();
        Ok(())
    }

    fn rehash(&mut self) {
        self.root = root_of(&self.members);
        self.volume_id = volume_id_of(&self.visibility, &self.bytes);
    }
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_fields_bytes(&[VOLUME_TAG, &[0x01], left, right])
}

fn root_hash(root: &[u8; 32], count: u64) -> [u8; 32] {
    hash_fields_bytes(&[VOLUME_TAG, &[0x02], &count.to_le_bytes(), root])
}

/// The root of a member table. An empty table has its own root.
#[must_use]
pub fn root_of(members: &[VolumeMember]) -> [u8; 32] {
    if members.is_empty() {
        return hash_fields_bytes(&[VOLUME_TAG, &[0x05]]);
    }
    let mut level: Vec<[u8; 32]> = members
        .iter()
        .enumerate()
        .map(|(index, member)| member.leaf(index as u64))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            match level.get(i + 1) {
                Some(right) => next.push(node_hash(&level[i], right)),
                None => next.push(level[i]),
            }
            i += 2;
        }
        level = next;
    }
    root_hash(&level[0], members.len() as u64)
}

/// The id of a volume with these bytes and this visibility.
#[must_use]
pub fn volume_id_of(visibility: &Visibility, bytes: &[u8]) -> [u8; 32] {
    let (tag, owner) = visibility.tag();
    hash_fields_bytes(&[
        VOLUME_TAG,
        &[0x03],
        tag,
        &owner,
        &(bytes.len() as u64).to_le_bytes(),
        bytes,
    ])
}

/// The Merkle path of the member at `index`.
#[must_use]
pub fn proof_for(members: &[VolumeMember], index: usize) -> Vec<PathStep> {
    let mut level: Vec<[u8; 32]> = members
        .iter()
        .enumerate()
        .map(|(i, member)| member.leaf(i as u64))
        .collect();
    let mut pos = index;
    let mut path = Vec::new();
    while level.len() > 1 {
        let sibling = if pos % 2 == 0 {
            level.get(pos + 1).copied()
        } else {
            level.get(pos - 1).copied()
        };
        path.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            match level.get(i + 1) {
                Some(right) => next.push(node_hash(&level[i], right)),
                None => next.push(level[i]),
            }
            i += 2;
        }
        level = next;
        pos /= 2;
    }
    path
}

/// Check a member path against a recorded root and member count.
#[must_use]
pub fn verify_member(
    root: &[u8; 32],
    count: u64,
    index: u64,
    member: &VolumeMember,
    path: &[PathStep],
) -> bool {
    if index >= count || path.len() > MAX_PATH {
        return false;
    }
    let mut hash = member.leaf(index);
    let mut pos = index;
    for step in path {
        match step {
            Some(sibling) => {
                hash = if pos % 2 == 0 {
                    node_hash(&hash, sibling)
                } else {
                    node_hash(sibling, &hash)
                };
            }
            None => {
                if pos % 2 == 1 {
                    return false;
                }
            }
        }
        pos /= 2;
    }
    pos == 0 && root_hash(&hash, count) == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::content_id::ContentKey;

    const SYMBOL: u32 = 128;

    fn public(bytes: &[u8]) -> ContentId {
        ContentId::public(bytes)
    }

    fn sealed(bytes: &[u8]) -> ContentId {
        ContentId::sealed(&ContentKey([7u8; 32]), bytes)
    }

    fn commitment(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn bud3_volume_members_are_smaller_than_one_symbol() {
        let mut volume = AggregationVolume::new(Visibility::Public, 1024).unwrap();
        let id = public(b"x");
        // Exactly one symbol is placed on its own, so the volume refuses it.
        let big = vec![1u8; SYMBOL as usize];
        assert_eq!(
            volume.push(&id, commitment(1), &big, SYMBOL),
            Err(VolumeError::NotSmall {
                len: u64::from(SYMBOL),
                symbol_size: u64::from(SYMBOL),
            })
        );
        let small = vec![1u8; SYMBOL as usize - 1];
        assert!(volume.push(&id, commitment(1), &small, SYMBOL).is_ok());
        assert_eq!(volume.members().len(), 1);
    }

    #[test]
    fn bud3_volume_refuses_mixed_visibility_and_duplicates() {
        let mut volume = AggregationVolume::new(Visibility::Public, 4096).unwrap();
        let public_id = public(b"public member");
        assert!(volume.push(&public_id, commitment(1), b"public member", SYMBOL).is_ok());
        // A sealed member never shares a public volume.
        let sealed_id = sealed(b"sealed member");
        assert_eq!(
            volume.push(&sealed_id, commitment(2), b"sealed member", SYMBOL),
            Err(VolumeError::MixedVisibility)
        );
        // The same content id joins once.
        assert_eq!(
            volume.push(&public_id, commitment(1), b"public member", SYMBOL),
            Err(VolumeError::DuplicateMember)
        );
        // A sealed volume refuses a public member.
        let mut sealed_volume =
            AggregationVolume::new(Visibility::Sealed([0u8; 32]), 4096).unwrap();
        assert_eq!(
            sealed_volume.push(&public_id, commitment(1), b"public member", SYMBOL),
            Err(VolumeError::MixedVisibility)
        );
        assert!(sealed_volume
            .push(&sealed_id, commitment(2), b"sealed member", SYMBOL)
            .is_ok());
    }

    #[test]
    fn bud3_volume_root_binds_every_member_field() {
        let mut volume = AggregationVolume::new(Visibility::Public, 4096).unwrap();
        let a = public(b"a");
        let b = public(b"b");
        volume.push(&a, commitment(1), b"a", SYMBOL).unwrap();
        let one = volume.root();
        volume.push(&b, commitment(2), b"b", SYMBOL).unwrap();
        let two = volume.root();
        assert_ne!(one, two, "the count and the members are bound");

        let mut changed = volume.members().to_vec();
        changed[0].commitment = commitment(9);
        assert_ne!(root_of(&changed), two, "the commitment is bound");

        let mut changed = volume.members().to_vec();
        changed[1].offset += 1;
        assert_ne!(root_of(&changed), two, "the offset is bound");

        let mut order = volume.members().to_vec();
        order.swap(0, 1);
        assert_ne!(root_of(&order), two, "the position is bound");
    }

    #[test]
    fn bud3_volume_proof_finds_each_member() {
        let mut volume = AggregationVolume::new(Visibility::Public, 4096).unwrap();
        let ids: Vec<ContentId> = (0u8..5).map(|i| public(&[i])).collect();
        for (i, id) in ids.iter().enumerate() {
            volume
                .push(id, commitment(i as u8), &[i as u8], SYMBOL)
                .unwrap();
        }
        let count = volume.members().len() as u64;
        for (i, id) in ids.iter().enumerate() {
            let member = *volume.member(id).unwrap();
            let path = volume.member_proof(id).unwrap();
            assert!(verify_member(volume.root(), count, i as u64, &member, &path));
            // The same path never finds a member at another position.
            assert!(!verify_member(volume.root(), count, i as u64 + 1, &member, &path));
            // A member with another commitment fails under the same path.
            let mut forged = member;
            forged.commitment = commitment(200);
            assert!(!verify_member(volume.root(), count, i as u64, &forged, &path));
        }
        assert!(volume.member_proof(&public(b"absent")).is_none());
    }

    #[test]
    fn bud3_volume_delete_zeroes_the_bytes() {
        let mut volume = AggregationVolume::new(Visibility::Public, 4096).unwrap();
        let a = public(b"one");
        let b = public(b"two");
        volume.push(&a, commitment(1), b"one", SYMBOL).unwrap();
        volume.push(&b, commitment(2), b"two", SYMBOL).unwrap();
        let before = volume.volume_id();
        let removal = volume.remove(&a, 1_000).unwrap();
        assert_eq!(removal.member.content_id, a);
        assert!(!removal.sealed);
        assert_eq!(removal.effective_at, None);
        let bytes = volume.bytes();
        assert_eq!(&bytes[..3], &[0u8, 0, 0], "the slot is zeroed at once");
        assert_eq!(&bytes[3..], b"two");
        assert_ne!(volume.volume_id(), before, "the id follows the bytes");
        assert_eq!(volume.members().len(), 1);
        assert_eq!(volume.remove(&a, 1_000), Err(VolumeError::UnknownMember));

        // Seven days after the deletion the public volume needs a recode.
        assert!(!volume.needs_recode(1_000 + RECODE_DEADLINE_SECS - 1));
        assert!(volume.needs_recode(1_000 + RECODE_DEADLINE_SECS));

        volume.compact().unwrap();
        assert_eq!(volume.bytes(), b"two");
        assert_eq!(volume.members()[0].offset, 0);
        assert!(!volume.needs_recode(1_000 + RECODE_DEADLINE_SECS));
        assert!(!volume.is_empty());
    }

    #[test]
    fn bud3_volume_sealed_deletion_is_immediate() {
        let owner = [0u8; 32];
        let mut volume = AggregationVolume::new(Visibility::Sealed(owner), 4096).unwrap();
        let a = sealed(b"secret one");
        let b = sealed(b"secret two");
        volume.push(&a, commitment(1), b"secret one", SYMBOL).unwrap();
        volume.push(&b, commitment(2), b"secret two", SYMBOL).unwrap();
        let removal = volume.remove(&a, 7).unwrap();
        assert!(removal.sealed);
        assert_eq!(removal.effective_at, Some(7), "crypto shredding is immediate");
        assert_eq!(&volume.bytes()[..10], &[0u8; 10]);
        // A sealed volume never waits for a recode.
        assert!(!volume.needs_recode(7 + RECODE_DEADLINE_SECS * 10));
        assert_eq!(volume.visibility().owner(), Some(owner));
    }

    #[test]
    fn bud3_volume_capacity_is_the_genesis_length() {
        let small = AggregationVolume::new(Visibility::Public, 8).unwrap();
        assert_eq!(small.capacity(), 8);
        assert_eq!(small.free(), 8);
        let mut volume = small;
        volume.push(&public(b"a"), commitment(1), b"12345", SYMBOL).unwrap();
        assert_eq!(volume.free(), 3);
        assert_eq!(
            volume.push(&public(b"b"), commitment(2), b"1234", SYMBOL),
            Err(VolumeError::Capacity {
                len: 4,
                free: 3,
                capacity: 8
            })
        );
        assert!(matches!(
            AggregationVolume::new(Visibility::Public, 0),
            Err(VolumeError::EmptyCapacity)
        ));
        assert_eq!(DEFAULT_VOLUME_BYTES, 4 * 1024 * 1024);
    }

    #[test]
    fn bud3_volume_id_binds_visibility_and_owner() {
        let bytes = b"members";
        let public = volume_id_of(&Visibility::Public, bytes);
        let other = volume_id_of(&Visibility::Public, b"memberz");
        assert_ne!(public, other);
        let one = volume_id_of(&Visibility::Sealed([0u8; 32]), bytes);
        let two = volume_id_of(&Visibility::Sealed([1u8; 32]), bytes);
        assert_ne!(public, one, "a sealed id never equals a public id");
        assert_ne!(one, two, "the owner is bound");
    }
}
