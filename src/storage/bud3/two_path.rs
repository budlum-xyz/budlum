//! Upload two-path verification (Y10, Y11, Y12) and view equivalence (G4, G5).
//! exposed for upload optical round-trip gate and viewer equivalence checks.
//!
//! * **Y10 (`extract_object_from_optical_seconds`)**: reads QR-PNG frames
//!   second-by-second from pixels, runs RFC 6330 segment decoding, and parses
//!   the canonical BOF-1 [`Object`] solely from the optical stream.
//! * **Y11 (`two_path_gate`)**: verifies that the object extracted from the QR
//!   video is byte-for-byte identical to the encoder's candidate object,
//!   returning the video-extracted object as authoritative.
//! * **Y12 (`round_trip_gate`)**: re-emits logical frames from the extracted
//!   object, checks `video_commitment` equality, reconstructs the content,
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
/// Groups frames per segment by `(segment_len, symbol_len, source_symbols)` and
/// prioritizes majority geometry so a single rogue/corrupted frame with spoofed
/// dimensions cannot hijack or DoS the segment decoder.
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
    const MAX_STREAM_SEGMENTS: usize = 1024;
    type GeomKey = (u32, usize, u32);
    let mut by_segment: BTreeMap<u64, BTreeMap<GeomKey, Vec<&Bud3Frame>>> = BTreeMap::new();
    for frame in frames {
        let _ = u16::try_from(frame.data.len())
            .map_err(|_| TwoPathError::Frame(FrameWireError::BadGeometry))?;
        if !by_segment.contains_key(&frame.segment) && by_segment.len() >= MAX_STREAM_SEGMENTS {
            return Err(TwoPathError::Frame(FrameWireError::BadGeometry));
        }
        by_segment
            .entry(frame.segment)
            .or_default()
            .entry((frame.segment_len, frame.data.len(), frame.source_symbols))
            .or_default()
            .push(frame);
    }

    let seg_count = u64::try_from(by_segment.len())
        .map_err(|_| TwoPathError::Frame(FrameWireError::BadGeometry))?;
    let mut object_bytes = Vec::new();
    for expected_seg in 0..seg_count {
        let geom_map = by_segment
            .remove(&expected_seg)
            .ok_or(TwoPathError::MissingSegment(expected_seg))?;
        let multi_geom = geom_map.len() > 1;
        let mut candidates: Vec<(GeomKey, Vec<&Bud3Frame>)> = geom_map.into_iter().collect();
        // Try the geometry with the highest frame count first so outlier rogue
        // frames cannot preempt an honest majority stream.
        candidates.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));

        let mut recovered: Option<Vec<u8>> = None;
        for ((seg_len, sym_len, source_symbols), group) in candidates.into_iter().take(4) {
            if source_symbols == 0 || source_symbols > Profile::P0.k_max {
                if multi_geom {
                    continue;
                }
                return Err(TwoPathError::Frame(FrameWireError::BadGeometry));
            }
            let sym_size_u16 = u16::try_from(sym_len)
                .map_err(|_| TwoPathError::Frame(FrameWireError::BadGeometry))?;
            let eph = Profile {
                id: 0,
                qr_version: 40,
                symbol_size: sym_size_u16,
                fps: 10,
                k_max: source_symbols,
            };
            // A decoder reserves both the padded segment buffer and the per-symbol
            // slot table (~24 bytes per source symbol) regardless of how tiny the
            // arriving frame payload is: charge the meter up front so a stream of
            // 27-byte frames across distinct segments cannot bypass memory limits.
            let decoder_overhead = eph
                .segment_bytes()
                .saturating_add(u64::from(eph.k_max).saturating_mul(24));
            meter
                .charge_bytes(decoder_overhead)
                .map_err(|e| TwoPathError::Frame(FrameWireError::Budget(e)))?;
            let mut dec = match SegmentDecoder::new(expected_seg, u64::from(seg_len), &eph) {
                Ok(d) => d,
                Err(_) if multi_geom => continue,
                Err(e) => return Err(TwoPathError::Fountain(e)),
            };
            let mut push_ok = true;
            for frame in group {
                if !dec.is_done() {
                    if let Err(e) = dec.push((*frame).clone().into_symbol(), meter) {
                        if multi_geom {
                            push_ok = false;
                            break;
                        }
                        return Err(TwoPathError::Fountain(e));
                    }
                }
            }
            if !push_ok {
                continue;
            }
            if let Some(seg_bytes) = dec.into_bytes() {
                recovered = Some(seg_bytes);
                break;
            }
        }

        let seg_bytes = recovered.ok_or(if multi_geom {
            TwoPathError::Frame(FrameWireError::BadGeometry)
        } else {
            TwoPathError::IncompleteSegment(expected_seg)
        })?;
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
        let verified = verify_upload_two_path_and_round_trip(&coded_obj, &FAST_PROFILE, 2).unwrap();
        assert_eq!(verified.object.public_content().unwrap(), text);
    }

    #[test]
    fn bud3_logical_equals_optical_including_lossy_channel_and_p1() {
        let content = b"screen to camera lossy optical channel ".repeat(45);
        let obj = Object::raw_public(&content);

        let logical_frames = frames_for_object_bytes(&obj.encode(), &FAST_PROFILE, 4).unwrap();
        let mut optical_seconds = render_optical_seconds(&obj, &FAST_PROFILE, 4).unwrap();

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
        let p1_seconds = render_p1_optical_seconds(&obj, &OpticalProfile::P1_DEFAULT, 2).unwrap();
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
    fn frame_wire_rejects_excessive_source_symbols_and_two_path_charges_decoder_buffer() {
        use super::super::frame::{Bud3Frame, FrameWireError, BUD3_FRAME_MAGIC};
        use super::super::limits::RFC6330_MAX_SOURCE_SYMBOLS;

        // Craft a wire frame claiming source_symbols = RFC6330_MAX_SOURCE_SYMBOLS + 1.
        let mut raw = Vec::with_capacity(27);
        raw.extend_from_slice(&BUD3_FRAME_MAGIC);
        raw.push(0); // profile 0
        raw.push(0); // source kind
        raw.extend_from_slice(&0u64.to_le_bytes()); // segment 0
        raw.extend_from_slice(&64u32.to_le_bytes()); // segment_len
        raw.extend_from_slice(&0u32.to_le_bytes()); // esi
        raw.extend_from_slice(&(RFC6330_MAX_SOURCE_SYMBOLS + 1).to_le_bytes());
        raw.push(0xAA);
        let mut wire_meter = Meter::for_object(1 << 20);
        assert_eq!(
            Bud3Frame::decode_wire(&raw, &mut wire_meter),
            Err(FrameWireError::BadGeometry)
        );

        // Distinct-segment frames, each naming the largest permitted source
        // count (`k_max` symbols of 2048 bytes, about 8 MB per decoder). Under
        // a 1 MB meter the first decoder allocation hits the meter cap.
        let k = Profile::P0.k_max;
        let mut bogus_frames = Vec::new();
        for seg in 0..4u64 {
            let mut f = Vec::with_capacity(26 + 2048);
            f.extend_from_slice(&BUD3_FRAME_MAGIC);
            f.push(0);
            f.push(0);
            f.extend_from_slice(&seg.to_le_bytes());
            f.extend_from_slice(&(k * 2048).to_le_bytes());
            f.extend_from_slice(&0u32.to_le_bytes());
            f.extend_from_slice(&k.to_le_bytes());
            f.extend_from_slice(&vec![0x55u8; 2048]);
            bogus_frames.push(Bud3Frame::decode_wire(&f, &mut wire_meter).unwrap());
        }
        let mut meter = Meter::for_object(1 << 20);
        let err = extract_object_from_frames(&bogus_frames, &mut meter).unwrap_err();
        assert!(
            matches!(err, TwoPathError::Frame(FrameWireError::Budget(_))),
            "expected meter budget error, got {err:?}"
        );

        // A frame naming more source symbols than the profile allows is
        // refused before any decoder is sized from it.
        let mut over = bogus_frames.swap_remove(0);
        over.source_symbols = k + 1;
        let mut meter = Meter::for_object(1 << 30);
        assert!(matches!(
            extract_object_from_frames(&[over], &mut meter),
            Err(TwoPathError::Frame(FrameWireError::BadGeometry))
        ));
    }

    #[test]
    fn extract_object_from_frames_survives_poisoned_leading_frame_geometry() {
        use super::super::fountain::SymbolKind;
        use super::super::frame::Bud3Frame;

        let content = b"majority honest frames defeat one leading rogue frame".repeat(12);
        let obj = Object::raw_public(&content);
        let honest_frames = frames_for_object_bytes(&obj.encode(), &FAST_PROFILE, 3).unwrap();
        let rogue = Bud3Frame {
            kind: SymbolKind::Source,
            segment: 0,
            segment_len: honest_frames[0].segment_len.saturating_add(19),
            esi: 0,
            source_symbols: 99,
            data: vec![0xAA; 19],
        };
        let mut mixed = vec![rogue];
        mixed.extend(honest_frames);

        let mut meter = Meter::for_object(4 << 20);
        let recovered = extract_object_from_frames(&mixed, &mut meter).unwrap();
        assert_eq!(recovered.public_content().unwrap(), content);
    }
}
