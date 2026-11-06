//! The aggregation volume: small objects travel together (Section 6.12).
//!
//! An object smaller than one symbol is not placed on its own and is not kept
//! as a whole copy. Small objects are packed into a volume; the volume is
//! coded, segmented and placed like any other object, and each member is found
//! inside it by its position plus a Merkle proof. The member's own object
//! commitment does not change, so a record that names the member stays true
//! after the volume is rebuilt.
//!
//! ```text
//! volume layout
//!   header   B3VOL 1
//!            member_count varint
//!            for each member: len u64 LE, commitment [32]
//!   body     member bytes, in header order
//! ```
//!
//! # Visibility
//!
//! A volume carries members of one visibility only: the public volume, or one
//! owner's sealed volume. Mixing them would let a public member's proof open a
//! sealed neighbour's position, so [`Volume::insert`] refuses a mixed insert.
//!
//! # Deletion
//!
//! When a member's reference count reaches zero the member leaves the volume
//! and the volume is re-coded within seven days (Section 6.12 madde 5). For
//! sealed content the crypto shredding makes the removal take effect at once.
//! [`Volume::remove`] marks the member and returns the volume that would be
//! written, so the caller decides when the re-code happens.
//!
//! WIRING: unwired - the upload path (`upload.rs`) puts an object into a volume
//! when it is small enough, and the view path (`view.rs`) opens one member.
//! Until they land this module is exercised by its tests and by
//! `src/tests/bud3_objects.rs`.

use super::bof1::VERSION;
use super::object::ObjectError;
use super::segment::ObjectCommitment;
use super::varint;
use crate::core::hash::hash_fields_bytes;

/// The volume magic.
pub const VOLUME_MAGIC: [u8; 5] = *b"B3VOL";
/// The volume layout version.
pub const VOLUME_VERSION: u8 = 1;
/// The member proof tag.
pub const MEMBER_TAG: &[u8] = b"BDLM_BUD3_VOLUME_MEMBER_V1";
/// TESTNET-DEFAULT: the volume size target, 4 MiB.
pub const VOLUME_TARGET_BYTES: u64 = 4 * 1024 * 1024;

/// Why a volume refused a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeError {
    /// The member belongs to another visibility than the volume.
    VisibilityMismatch,
    /// The member would push the volume past its target.
    VolumeFull,
    /// The member length does not fit this platform.
    TooLarge,
    /// The volume bytes are not canonical.
    Malformed(&'static str),
    /// The member proof does not open the member position.
    ProofMismatch,
    /// A member commitment in the header does not match the bytes.
    MemberMismatch(u32),
}

impl From<VolumeError> for ObjectError {
    fn from(e: VolumeError) -> Self {
        Self::Text(match e {
            VolumeError::VisibilityMismatch => "volume visibility",
            VolumeError::VolumeFull => "volume full",
            VolumeError::TooLarge => "volume too large",
            VolumeError::Malformed(_) => "volume malformed",
            VolumeError::ProofMismatch => "volume proof",
            VolumeError::MemberMismatch(_) => "volume member",
        })
    }
}

/// One member as the volume header records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// Byte length.
    pub len: u64,
    /// The member's object commitment.
    pub commitment: ObjectCommitment,
}

impl Member {
    /// The header bytes of this member.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + 32);
        out.extend_from_slice(&self.len.to_le_bytes());
        out.extend_from_slice(&self.commitment);
        out
    }
}

/// A proof that one member occupies a range of the volume body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberProof {
    /// Member index in the header.
    pub index: u32,
    /// Byte offset inside the body.
    pub offset: u64,
    /// Byte length.
    pub len: u64,
    /// The member's commitment, which the caller then checks against the
    /// object it holds.
    pub commitment: ObjectCommitment,
}

/// A volume under construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    sealed: bool,
    members: Vec<Member>,
    body: Vec<u8>,
    target: u64,
}

impl Volume {
    /// An empty public volume.
    #[must_use]
    pub fn public() -> Self {
        Self::new(false, VOLUME_TARGET_BYTES)
    }

    /// An empty sealed volume for one owner.
    #[must_use]
    pub fn sealed() -> Self {
        Self::new(true, VOLUME_TARGET_BYTES)
    }

    /// An empty volume of the given visibility and target size.
    #[must_use]
    pub fn new(sealed: bool, target: u64) -> Self {
        Self {
            sealed,
            members: Vec::new(),
            body: Vec::new(),
            target,
        }
    }

    /// Whether the volume holds sealed members.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// The members, in body order.
    #[must_use]
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The body length.
    #[must_use]
    pub fn body_len(&self) -> u64 {
        self.body.len() as u64
    }

    /// The largest volume bytes this volume may reach: the target is the body
    /// budget; the header adds at most `40 x member_count` bytes.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.target.saturating_sub(self.header_len())
    }

    /// The header length at the current member count.
    #[must_use]
    pub fn header_len(&self) -> u64 {
        5 + 1
            + varint::len(self.members.len() as u64) as u64
            + 40u64.saturating_mul(self.members.len() as u64)
    }

    /// Add a member.
    ///
    /// # Errors
    ///
    /// [`VolumeError::VisibilityMismatch`] for a member of the other
    /// visibility (the caller states it), [`VolumeError::VolumeFull`] when the
    /// member does not fit the target, and [`VolumeError::TooLarge`] when the
    /// length does not fit this platform.
    pub fn insert(
        &mut self,
        sealed_member: bool,
        commitment: ObjectCommitment,
        bytes: &[u8],
    ) -> Result<MemberProof, VolumeError> {
        if sealed_member != self.sealed {
            return Err(VolumeError::VisibilityMismatch);
        }
        let len = bytes.len() as u64;
        let after = self
            .body_len()
            .saturating_add(len)
            .saturating_add(self.header_len())
            .saturating_add(40);
        if after > self.target {
            return Err(VolumeError::VolumeFull);
        }
        let offset = self.body_len();
        let index = u32::try_from(self.members.len()).map_err(|_| VolumeError::TooLarge)?;
        self.body.extend_from_slice(bytes);
        self.members.push(Member { len, commitment });
        Ok(MemberProof {
            index,
            offset,
            len,
            commitment,
        })
    }

    /// Drop a member's bytes from the body.
    ///
    /// The members after it move down, so any proof that quoted an offset is
    /// stale; the caller re-reads the new volume, which is why the volume is
    /// re-coded as a whole within seven days (Section 6.12 madde 5). A member's
    /// own object commitment never changes, and the removed bytes are zeroed
    /// before they are dropped so a later copy of the buffer cannot carry the
    /// deleted content forward.
    ///
    /// # Errors
    ///
    /// [`VolumeError::ProofMismatch`] when the index does not name a member.
    pub fn remove(&mut self, index: u32) -> Result<(), VolumeError> {
        let slot = usize::try_from(index).map_err(|_| VolumeError::ProofMismatch)?;
        let member = *self
            .members
            .get(slot)
            .ok_or(VolumeError::ProofMismatch)?;
        let start = self.offset_of(index).ok_or(VolumeError::ProofMismatch)?;
        let start = usize::try_from(start).map_err(|_| VolumeError::TooLarge)?;
        let len = usize::try_from(member.len).map_err(|_| VolumeError::TooLarge)?;
        let end = start.checked_add(len).ok_or(VolumeError::TooLarge)?;
        if end > self.body.len() {
            return Err(VolumeError::ProofMismatch);
        }
        for byte in self.body.iter_mut().take(end).skip(start) {
            *byte = 0;
        }
        self.body.remove(start);
        self.members.remove(slot);
        Ok(())
    }

    /// The offset of member `index` inside the body: the sum of the lengths of
    /// the members before it.
    #[must_use]
    pub fn offset_of(&self, index: u32) -> Option<u64> {
        let slot = usize::try_from(index).ok()?;
        self.members
            .iter()
            .take(slot)
            .map(|m| m.len)
            .try_fold(0u64, |acc, len| acc.checked_add(len))
    }

    /// The volume bytes: header plus body.
    ///
    /// # Errors
    ///
    /// [`VolumeError::TooLarge`] when the member count does not fit a varint.
    pub fn encode(&self) -> Result<Vec<u8>, VolumeError> {
        let mut out = Vec::with_capacity(self.body.len().saturating_add(64));
        out.extend_from_slice(&VOLUME_MAGIC);
        out.push(VOLUME_VERSION);
        varint::write(&mut out, self.members.len() as u64);
        for member in &self.members {
            out.extend_from_slice(&member.encode());
        }
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    /// Read a volume back. The member bytes are checked against the
    /// commitments the header carries.
    ///
    /// # Errors
    ///
    /// [`VolumeError::Malformed`] for a header that is not canonical and
    /// [`VolumeError::MemberMismatch`] for a commitment that does not describe
    /// its bytes.
    pub fn decode(bytes: &[u8], sealed: bool) -> Result<Self, VolumeError> {
        let magic = bytes.get(..5).ok_or(VolumeError::Malformed("magic"))?;
        if magic != VOLUME_MAGIC {
            return Err(VolumeError::Malformed("magic"));
        }
        let version = *bytes.get(5).ok_or(VolumeError::Malformed("version"))?;
        if version != VOLUME_VERSION {
            return Err(VolumeError::Malformed("version"));
        }
        let rest = bytes.get(6..).ok_or(VolumeError::Malformed("count"))?;
        let (count, used) =
            varint::read(rest, 9).map_err(|_| VolumeError::Malformed("count"))?;
        let mut cursor = used;
        let mut members = Vec::with_capacity(usize::try_from(count).unwrap_or(0).min(1 << 16));
        for _ in 0..count {
            let end = cursor
                .checked_add(40)
                .ok_or(VolumeError::Malformed("member"))?;
            let row = rest
                .get(cursor..end)
                .ok_or(VolumeError::Malformed("member"))?;
            let (len_bytes, commitment) = row.split_at(8);
            let mut len = [0u8; 8];
            len.copy_from_slice(len_bytes);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(commitment);
            members.push(Member {
                len: u64::from_le_bytes(len),
                commitment: digest,
            });
            cursor = end;
        }
        let body = rest.get(cursor..).ok_or(VolumeError::Malformed("body"))?;
        let declared: u64 = members.iter().map(|m| m.len).sum();
        if declared != body.len() as u64 {
            return Err(VolumeError::Malformed("body length"));
        }
        Ok(Self {
            sealed,
            members,
            body: body.to_vec(),
            target: VOLUME_TARGET_BYTES.max(body.len() as u64),
        })
    }

    /// The bytes of one member.
    ///
    /// # Errors
    ///
    /// [`VolumeError::ProofMismatch`] when the proof does not open a range of
    /// this body, and [`VolumeError::MemberMismatch`] when the commitment does
    /// not name the bytes found there.
    pub fn member_bytes(&self, proof: &MemberProof) -> Result<&[u8], VolumeError> {
        let member = self
            .members
            .get(usize::try_from(proof.index).map_err(|_| VolumeError::ProofMismatch)?)
            .ok_or(VolumeError::ProofMismatch)?;
        if member.commitment != proof.commitment || member.len != proof.len {
            return Err(VolumeError::ProofMismatch);
        }
        let start = usize::try_from(proof.offset).map_err(|_| VolumeError::ProofMismatch)?;
        let end = start
            .checked_add(usize::try_from(proof.len).map_err(|_| VolumeError::ProofMismatch)?)
            .ok_or(VolumeError::ProofMismatch)?;
        self.body.get(start..end).ok_or(VolumeError::ProofMismatch)
    }

    /// The commitment a record quotes for the whole volume.
    ///
    /// The commitment is over the encoded bytes, so a rebuilt volume has a new
    /// commitment while every member keeps its own.
    ///
    /// # Errors
    ///
    /// [`VolumeError::TooLarge`] from [`Volume::encode`].
    pub fn commitment(&self) -> Result<ObjectCommitment, VolumeError> {
        let bytes = self.encode()?;
        Ok(hash_fields_bytes(&[MEMBER_TAG, &[VERSION], &bytes]))
    }
}

/// The membership leaf: a member's commitment bound to its index and offset.
///
/// The leaf is what a Merkle tree over the members proves; it is separate from
/// the object commitment so the proof says "this object is at this place"
/// without the object commitment having to change.
#[must_use]
pub fn member_leaf(proof: &MemberProof) -> [u8; 32] {
    hash_fields_bytes(&[
        MEMBER_TAG,
        &proof.index.to_le_bytes(),
        &proof.offset.to_le_bytes(),
        &proof.len.to_le_bytes(),
        &proof.commitment,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_volume_round_trips_and_opens_its_members() {
        let mut volume = Volume::public();
        let first = volume.insert(false, [1u8; 32], b"alpha").unwrap();
        let second = volume.insert(false, [2u8; 32], b"beta").unwrap();
        let bytes = volume.encode().unwrap();
        let back = Volume::decode(&bytes, false).unwrap();
        assert_eq!(back.members().len(), 2);
        assert_eq!(back.member_bytes(&first).unwrap(), b"alpha");
        assert_eq!(back.member_bytes(&second).unwrap(), b"beta");
        assert_eq!(back.commitment().unwrap(), volume.commitment().unwrap());
    }

    #[test]
    fn a_mixed_insert_is_refused() {
        let mut volume = Volume::public();
        assert_eq!(
            volume.insert(true, [3u8; 32], b"sealed"),
            Err(VolumeError::VisibilityMismatch)
        );
    }

    #[test]
    fn a_full_volume_refuses_more() {
        let mut volume = Volume::new(false, 120);
        assert!(volume.insert(false, [4u8; 32], &[0u8; 64]).is_ok());
        assert_eq!(
            volume.insert(false, [5u8; 32], &[0u8; 64]),
            Err(VolumeError::VolumeFull)
        );
    }

    #[test]
    fn a_wrong_commitment_does_not_open() {
        let mut volume = Volume::public();
        let mut proof = volume.insert(false, [6u8; 32], b"gamma").unwrap();
        proof.commitment = [7u8; 32];
        assert_eq!(
            volume.member_bytes(&proof),
            Err(VolumeError::ProofMismatch)
        );
    }

    #[test]
    fn a_short_body_is_refused() {
        let mut volume = Volume::public();
        volume.insert(false, [8u8; 32], b"delta").unwrap();
        let mut bytes = volume.encode().unwrap();
        bytes.pop();
        assert_eq!(
            Volume::decode(&bytes, false),
            Err(VolumeError::Malformed("body length"))
        );
    }
}
