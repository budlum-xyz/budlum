//! B.U.D. 3.0 video commitment over logical frames.
//! exposed for upload commitment binding and client-side frame verification.
//!
//! Per Section 6.15:
//! 1. Each segment folds its ordered logical frame digests via [`fold_frame_digests`].
//! 2. Segment results chain sequentially into one 32-byte video commitment.
//! 3. The video commitment is never stored inside a BOF-1 object; it is derived
//!    deterministically from `(Object, Profile)`.
//! 4. PNG, BDLV, and H.264 presentation bytes never enter the video commitment.

use super::bof1::Object;
use super::frame::{frames_for_object_bytes, Bud3Frame, FrameWireError};
use super::limits::Profile;
use crate::core::hash::hash_fields_bytes;

/// Domain-separation tag for per-segment logical frame folding.
pub const BUD3_VIDEO_SEG_TAG: &[u8] = b"BDLM_BUD3_VIDEO_SEG_V1";

/// Domain-separation tag for chaining segment video digests into the stream commitment.
pub const BUD3_VIDEO_TAG: &[u8] = b"BDLM_BUD3_VIDEO_V1";

/// Fold the ordered logical frame digests of `segment` into one segment digest.
#[must_use]
pub fn fold_frame_digests(segment: u64, frame_digests: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = hash_fields_bytes(&[
        BUD3_VIDEO_SEG_TAG,
        b"init",
        &segment.to_le_bytes(),
        &(frame_digests.len() as u64).to_le_bytes(),
    ]);
    for (idx, digest) in frame_digests.iter().enumerate() {
        acc = hash_fields_bytes(&[
            BUD3_VIDEO_SEG_TAG,
            &acc,
            &(idx as u64).to_le_bytes(),
            digest,
        ]);
    }
    acc
}

/// Chain ordered per-segment folded digests into one 32-byte video commitment.
#[must_use]
pub fn chain_segment_video_digests(segment_digests: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = hash_fields_bytes(&[
        BUD3_VIDEO_TAG,
        b"init",
        &(segment_digests.len() as u64).to_le_bytes(),
    ]);
    for (seg, digest) in segment_digests.iter().enumerate() {
        acc = hash_fields_bytes(&[BUD3_VIDEO_TAG, &acc, &(seg as u64).to_le_bytes(), digest]);
    }
    acc
}

/// Compute the video commitment over an ordered slice of [`Bud3Frame`]s.
///
/// # Errors
///
/// Returns [`FrameWireError::BadGeometry`] if `frames` is empty or segment
/// indices are not contiguous starting at `0`.
pub fn video_commitment_from_frames(frames: &[Bud3Frame]) -> Result<[u8; 32], FrameWireError> {
    if frames.is_empty() {
        return Err(FrameWireError::BadGeometry);
    }
    let mut segment_digests: Vec<[u8; 32]> = Vec::new();
    let mut cur_seg = 0u64;
    let mut cur_digests: Vec<[u8; 32]> = Vec::new();

    for frame in frames {
        if frame.segment == cur_seg {
            cur_digests.push(frame.digest());
        } else if frame.segment == cur_seg.saturating_add(1) && !cur_digests.is_empty() {
            segment_digests.push(fold_frame_digests(cur_seg, &cur_digests));
            cur_digests.clear();
            cur_seg = frame.segment;
            cur_digests.push(frame.digest());
        } else {
            return Err(FrameWireError::BadGeometry);
        }
    }
    if cur_digests.is_empty() {
        return Err(FrameWireError::BadGeometry);
    }
    segment_digests.push(fold_frame_digests(cur_seg, &cur_digests));
    Ok(chain_segment_video_digests(&segment_digests))
}

/// Convenience: derive the canonical video commitment directly from `object`
/// and `profile` (with `repair_per_segment` derived repair frames per segment).
///
/// # Errors
///
/// Returns [`FrameWireError`] if `profile` cannot frame `object`.
pub fn video_commitment(
    object: &Object,
    profile: &Profile,
    repair_per_segment: u32,
) -> Result<[u8; 32], FrameWireError> {
    let frames = frames_for_object_bytes(&object.encode(), profile, repair_per_segment)?;
    video_commitment_from_frames(&frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn video_commitment_is_deterministic_and_sensitive_to_every_frame() {
        let obj = Object::raw_public(&b"logical frame commitment".repeat(200));
        let c1 = video_commitment(&obj, &Profile::P0, 2).unwrap();
        let c2 = video_commitment(&obj, &Profile::P0, 2).unwrap();
        assert_eq!(c1, c2);

        let other = Object::raw_public(&b"logical frame commitmenu".repeat(200));
        assert_ne!(c1, video_commitment(&other, &Profile::P0, 2).unwrap());
    }
}
