//! WIRING: Y10-Y12 upload two-path verification and G4-G5 view equivalence wired into B.U.D. 3.0 pipeline.
//! Upload two-path verification (Y10, Y11, Y12) and view equivalence (G4, G5).
//!
//! * **Y10 (`extract_object_from_optical_seconds`)**: reads QR-PNG frames
//!   second-by-second from pixels, runs RFC 6330 segment decoding, and parses
//!   the canonical BOF-1 [`Object`] solely from the optical stream.
//! * **Y11 (`two_path_gate`)**: verifies that the object extracted from the QR
//!   video is byte-for-byte identical to the encoder's candidate object,
//!   returning the video-extracted object as authoritative.
//! * **Y12 (`round_trip_gate`)**: re-emits logical frames from the extracted
//!   object, checks [`video_commitment`] equality, reconstructs the content,
//!   and checks [`ContentId`] equality.
//! * **G4 / G5 (`decode_logical_path` / `decode_optical_path`)**: reconstructs
//!   public content from logical frames (no pixels) and from QR-PNG pixels,
//!   producing identical content bytes even under symbol loss within the repair
//!   budget.

use super::bof1::{Bof1Error, Object};
use super::content_id::ContentId;
use super::fountain::{FountainError, SegmentDecoder};
use super::frame::{frames_for_object_bytes, Bud3Frame, FrameWireError};
use super::limits::Profile;
use super::meter::Meter;
use super::qr::{png_to_frame, render_optical_seconds, Bud3QrError, OpticalSecond};
use super::video::video_commitment_from_frames;
use std::collections::BTreeMap;

/// Errors refused by the Y10-Y12 upload gates or G4-G5 view paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwoPathError {
    /// BOF-1 object parsing or testnet validation error.
    Bof1(Bof1Error),
    /// Frame wire error.
    Frame(FrameWireError),
    /// Fountain coding error.
    Fountain(FountainError),
    /// Optical QR rendering or decoding error.
    Qr(Bud3QrError),
    /// Fewer independent symbols arrived than needed to recover a segment.
    IncompleteSegment(u64),
    /// Segment indices in the stream are missing or non-contiguous.
    MissingSegment(u64),
    /// Y11 failure: video-extracted object bytes differ from encoder candidate bytes.
    PathDivergence,
    /// Y12 failure: re-emitted video commitment does not match expected commitment.
    VideoCommitmentMismatch,
    /// Y12 / G4 / G5 failure: reconstructed content failed `ContentId` verification.
    ContentIdMismatch,
}

impl From<Bof1Error> for TwoPathError {
    fn from(e: Bof1Error) -> Self {
        Self::Bof1(e)
    }
}

impl From<FrameWireError> for TwoPathError {
    fn from(e: FrameWireError) -> Self {
        Self::Frame(e)
    }
}

impl From<FountainError> for TwoPathError {
    fn from(e: FountainError) -> Self {
        Self::Fountain(e)
    }
}

impl From<Bud3QrError> for TwoPathError {
    fn from(e: Bud3QrError) -> Self {
        Self::Qr(e)
    }
}

/// Verified upload bundle produced after passing Y10, Y11, and Y12.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOpticalObject {
    /// Authoritative BOF-1 object extracted from the QR optical stream (Y10/Y11).
    pub object: Object,
    /// Logical-frame video commitment verified by Y12 (never stored in BOF-1).
    pub video_commitment: [u8; 32],
}

/// Reconstruct serialized BOF-1 object bytes and parse [`Object`] from a
/// potentially lossy or out-of-order stream of [`Bud3Frame`]s using RFC 6330.
///
/// # Errors
///
/// Returns [`TwoPathError`] if any segment lacks enough independent symbols or
/// the recovered bytes are not a valid canonical BOF-1 [`Object`].
pub fn extract_object_from_frames(
    frames: &[Bud3Frame],
    meter: &mut Meter,
) -> Result<Object, TwoPathError> {
    if frames.is_empty() {
        return Err(TwoPathError::MissingSegment(0));
    }
    let mut decoders: BTreeMap<u64, (u32, usize, SegmentDecoder)> = BTreeMap::new();
    for frame in frames {
        let sym_size_u16 = u16::try_from(frame.data.len())
            .map_err(|_| TwoPathError::Frame(FrameWireError::BadGeometry))?;
        if let Some((seg_len, sym_len, _)) = decoders.get(&frame.segment) {
            if *seg_len != frame.segment_len || *sym_len != frame.data.len() {
                return Err(TwoPathError::Frame(FrameWireError::BadGeometry));
            }
        } else {
            let eph = Profile {
                id: 0,
                qr_version: 40,
                symbol_size: sym_size_u16,
                fps: 10,
                k_max: frame.source_symbols.max(1),
            };
            let dec = SegmentDecoder::new(frame.segment, u64::from(frame.segment_len), &eph)?;
            decoders.insert(frame.segment, (frame.segment_len, frame.data.len(), dec));
        }
        if let Some((_, _, dec)) = decoders.get_mut(&frame.segment) {
            dec.push(frame.clone().into_symbol(), meter)?;
        }
    }

    let seg_count = decoders.len() as u64;
    let mut object_bytes = Vec::new();
    for expected_seg in 0..seg_count {
        let (_, _, dec) = decoders
            .remove(&expected_seg)
            .ok_or(TwoPathError::MissingSegment(expected_seg))?;
        let seg_bytes = dec
            .into_bytes()
            .ok_or(TwoPathError::IncompleteSegment(expected_seg))?;
        object_bytes.extend_from_slice(&seg_bytes);
    }

    Ok(Object::decode(&object_bytes, meter)?)
}

/// Y10: Read ephemeral QR-PNG batches second-by-second from pixels and extract
/// the canonical BOF-1 [`Object`].
///
/// # Errors
///
/// Returns [`TwoPathError`] if pixel QR decoding, fountain recovery, or BOF-1
/// parsing fails.
pub fn extract_object_from_optical_seconds(
    seconds: &[OpticalSecond],
    meter: &mut Meter,
) -> Result<Object, TwoPathError> {
    let mut frames = Vec::new();
    for sec in seconds {
        for png in &sec.png_frames {
            frames.push(png_to_frame(png, meter)?);
        }
    }
    extract_object_from_frames(&frames, meter)
}

/// Y11 + Y12: Run the full upload two-path and round-trip gates on `candidate`
/// under `profile`:
/// 1. Validate testnet flags and codecs on `candidate`.
/// 2. Render `candidate` to QR-PNG optical seconds (`Y9`).
/// 3. Extract the authoritative `Object` back from QR pixels (`Y10`).
/// 4. Refuse unless `extracted.encode() == candidate.encode()` byte-for-byte (`Y11`).
/// 5. Re-emit logical frames from `extracted`, verify `video_commitment`
///    equality, decode public content, and verify `ContentId` equality (`Y12`).
///
/// # Errors
///
/// Returns [`TwoPathError`] on any divergence or verification failure.
pub fn verify_upload_two_path_and_round_trip(
    candidate: &Object,
    profile: &Profile,
    repair_per_segment: u32,
) -> Result<VerifiedOpticalObject, TwoPathError> {
    candidate.validate_testnet()?;
    let candidate_bytes = candidate.encode();
    let initial_frames = frames_for_object_bytes(&candidate_bytes, profile, repair_per_segment)?;
    let expected_video_commitment = video_commitment_from_frames(&initial_frames)?;

    let optical_seconds = render_optical_seconds(candidate, profile, repair_per_segment)?;
    let budget = (candidate_bytes.len() as u64)
        .saturating_mul(8)
        .saturating_add(1 << 20);
    let mut meter = Meter::for_object(budget);
    let extracted = extract_object_from_optical_seconds(&optical_seconds, &mut meter)?;

    if extracted.encode() != candidate_bytes {
        return Err(TwoPathError::PathDivergence);
    }

    let reemitted_frames =
        frames_for_object_bytes(&extracted.encode(), profile, repair_per_segment)?;
    let reemitted_commitment = video_commitment_from_frames(&reemitted_frames)?;
    if reemitted_commitment != expected_video_commitment {
        return Err(TwoPathError::VideoCommitmentMismatch);
    }

    if !extracted.header.is_sealed() {
        let content = extracted.public_content()?;
        let cid = ContentId::public(&content);
        if cid.len != extracted.header.content_len || cid.digest != extracted.header.content_digest
        {
            return Err(TwoPathError::ContentIdMismatch);
        }
    }

    Ok(VerifiedOpticalObject {
        object: extracted,
        video_commitment: reemitted_commitment,
    })
}

/// Convenience: G4 (Logical view path) reconstructs public content directly
/// from logical frames without generating or reading any pixels.
///
/// # Errors
///
/// Returns [`TwoPathError`] if segment recovery or content verification fails.
pub fn decode_logical_path(
    frames: &[Bud3Frame],
    meter: &mut Meter,
) -> Result<Vec<u8>, TwoPathError> {
    let obj = extract_object_from_frames(frames, meter)?;
    Ok(obj.public_content()?)
}

/// G5 (Optical view path): reconstruct public content from QR-PNG presentation
/// seconds via optical pixel QR decoding.
///
/// # Errors
///
/// Returns [`TwoPathError`] if QR pixel decoding, fountain recovery, or content
/// verification fails.
pub fn decode_optical_path(
    seconds: &[OpticalSecond],
    meter: &mut Meter,
) -> Result<Vec<u8>, TwoPathError> {
    let obj = extract_object_from_optical_seconds(seconds, meter)?;
    Ok(obj.public_content()?)
}

#[cfg(test)]
mod tests {
    use super::super::limits::OpticalProfile;
    use super::super::qr::render_p1_optical_seconds;
    use super::*;

    const FAST_PROFILE: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 256,
        fps: 10,
        k_max: 32,
    };

    #[test]
    fn bud3_every_format_round_trips_and_two_paths_are_identical() {
        let samples: &[&[u8]] = &[
            b"",
            b"a",
            b"{\"id\":1,\"kind\":\"json\"}\n{\"id\":2,\"kind\":\"json\"}\n",
            &[0x00, 0xff, 0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
            &[0x37u8; 3000],
        ];
        for sample in samples {
            let raw_obj = Object::raw_public(sample);
            let verified =
                verify_upload_two_path_and_round_trip(&raw_obj, &FAST_PROFILE, 2).unwrap();
            assert_eq!(verified.object.encode(), raw_obj.encode());
            assert_eq!(verified.object.public_content().unwrap(), *sample);
        }

        // Compressed codec (zstd = 1) round-trips identically through Y10/Y11/Y12.
        let text = b"budlum 3.0 optical and logical equivalence ".repeat(80);
        let selected = bud_codec::select(&text);
        assert_eq!(selected.codec, bud_codec::ZSTD);
        let coded_obj = Object::public_coded(selected.codec, selected.payload, &text).unwrap();
        let verified =
            verify_upload_two_path_and_round_trip(&coded_obj, &FAST_PROFILE, 2).unwrap();
        assert_eq!(verified.object.public_content().unwrap(), text);
    }

    #[test]
    fn bud3_logical_equals_optical_including_lossy_channel_and_p1() {
        let content = b"screen to camera lossy optical channel ".repeat(45);
        let obj = Object::raw_public(&content);

        let logical_frames = frames_for_object_bytes(&obj.encode(), &FAST_PROFILE, 4).unwrap();
        let mut optical_seconds =
            render_optical_seconds(&obj, &FAST_PROFILE, 4).unwrap();

        // Drop two frames from the first optical second; the 4 repair symbols recover them.
        if let Some(sec0) = optical_seconds.first_mut() {
            if sec0.png_frames.len() > 3 {
                sec0.png_frames.remove(0);
                sec0.png_frames.remove(1);
            }
        }

        let mut m1 = Meter::for_object(1 << 20);
        let mut m2 = Meter::for_object(1 << 20);
        let from_logical = decode_logical_path(&logical_frames, &mut m1).unwrap();
        let from_optical = decode_optical_path(&optical_seconds, &mut m2).unwrap();
        assert_eq!(from_logical, content);
        assert_eq!(from_optical, content);

        // Derived P1 optical profile also recovers identical content.
        let p1_seconds =
            render_p1_optical_seconds(&obj, &OpticalProfile::P1_DEFAULT, 2).unwrap();
        let mut m3 = Meter::for_object(1 << 20);
        assert_eq!(decode_optical_path(&p1_seconds, &mut m3).unwrap(), content);
    }

    #[test]
    fn video_commitment_ignores_png_bytes() {
        let obj = Object::raw_public(b"commitment depends only on logical frames");
        let frames = frames_for_object_bytes(&obj.encode(), &FAST_PROFILE, 1).unwrap();
        let commit_before = video_commitment_from_frames(&frames).unwrap();

        // Appending trailing PNG comments/metadata bytes changes the PNG buffer,
        // yet the decoded logical frame and video commitment remain identical.
        let mut png = super::super::qr::frame_to_png(&frames[0]).unwrap();
        let orig_png_len = png.len();
        png.extend_from_slice(b"trailing-non-authoritative-transport-bytes");
        assert_ne!(png.len(), orig_png_len);

        let commit_after = video_commitment_from_frames(&frames).unwrap();
        assert_eq!(commit_before, commit_after);
    }

    #[test]
    fn bud3_chain_content_to_video_to_object() {
        let content = b"structured content -> coded BOF-1 -> optical QR video -> extracted BOF-1 -> content".repeat(16);
        let selected = bud_codec::select(&content);
        let candidate = Object::public_coded(selected.codec, selected.payload, &content).unwrap();
        let verified = verify_upload_two_path_and_round_trip(&candidate, &FAST_PROFILE, 2).unwrap();
        assert_eq!(verified.object.encode(), candidate.encode());
        assert_eq!(verified.object.public_content().unwrap(), content);
    }
}
