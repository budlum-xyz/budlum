//! The optical path: logical frames to QR symbols, and back (Section 6.4 Y9 to
//! Y12, Section 6.5 G4 and G5).
//!
//! Two paths lead from the same object bytes to the same content:
//!
//! * **Logical (G4, the default).** The symbols travel as bytes. The viewer
//!   decodes them on the device.
//! * **Optical (G5, optional).** The symbols are rendered as QR symbols on one
//!   screen and read back with a camera on another device. A frame lost on the
//!   way is repaired by the fountain code, not by a retransmission.
//!
//! A frame is self-describing: it carries the segment and the ESI it belongs
//! to, so a viewer that joins in the middle of a stream can decode without a
//! handshake. The frame header is fixed size and the payload after it is the
//! symbol itself:
//!
//! ```text
//! magic[3]        = "B3F"
//! version u8      = 1
//! esi u32 LE
//! segment u64 LE
//! data[...]       = exactly the symbol bytes
//! ```
//!
//! # What is not committed
//!
//! PNG bytes, an H.264 stream and a picture of a screen are all presentations
//! of the frames. None of them reaches an identity or a record: the video
//! commitment is computed from the logical frames ([`super::object`]), so two
//! rasters of the same frames with different sizes commit to the same value
//! (Section 6.15, BLG-214).
//!
//! WIRING: unwired - the upload session (`upload.rs`) runs the two-path gate
//! (Y11) before it registers an object, and the view session runs the optical
//! path (G5). Until they land this module is exercised by its own tests and by
//! `src/tests/bud3_objects.rs`.

use super::fountain::Symbol;
use super::limits::Profile;
use super::object::{encode_symbols, object_from_symbols, ObjectError};
use super::segment::Segmentation;
use crate::storage::qr_matrix::QrMatrix;
use crate::storage::qr_png::matrix_to_png;
use crate::storage::qr_video::png_to_optical_frame;

/// The frame magic.
pub const FRAME_MAGIC: [u8; 3] = *b"B3F";
/// The frame version.
pub const FRAME_VERSION: u8 = 1;
/// Bytes before the symbol: magic, version, ESI and segment.
pub const FRAME_HEADER_LEN: usize = 3 + 1 + 4 + 8;
/// The largest frame one QR symbol carries: the whole QR payload is the frame
/// header plus the symbol.
pub const MAX_FRAME_LEN: usize = crate::storage::qr_matrix::MAX_QR_PAYLOAD;
/// The largest symbol a frame can carry.
pub const MAX_SYMBOL_IN_FRAME: usize = MAX_FRAME_LEN - FRAME_HEADER_LEN;
/// The PNG signature, so a reader refuses a non-raster before it unpacks one.
pub const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Why a frame or a video path was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The frame is shorter than its own header.
    Truncated,
    /// Not `B3F`.
    BadMagic,
    /// Not version 1.
    BadVersion(u8),
    /// The symbol is empty or larger than one QR symbol can carry.
    BadPayloadLen(usize),
    /// The frame's symbol is not `symbol_size` bytes, so the readers of the
    /// frame cannot agree on where it ends.
    WrongSymbolSize {
        /// The profile's symbol size.
        want: usize,
        /// The bytes found after the frame header.
        got: usize,
    },
    /// The QR encoder refused the frame.
    Qr(crate::storage::qr_matrix::QrMatrixError),
    /// The PNG raster could not be produced.
    Png(crate::storage::qr_png::QrPngError),
    /// A raster did not decode to a frame.
    Decode(String),
    /// The two paths produced different object bytes (Y11).
    TwoPathMismatch,
    /// A symbol could not be coded or decoded.
    Object(ObjectError),
}

impl From<ObjectError> for FrameError {
    fn from(e: ObjectError) -> Self {
        Self::Object(e)
    }
}

impl From<super::fountain::FountainError> for FrameError {
    fn from(e: super::fountain::FountainError) -> Self {
        Self::Object(ObjectError::Fountain(e))
    }
}

impl From<crate::storage::qr_matrix::QrMatrixError> for FrameError {
    fn from(e: crate::storage::qr_matrix::QrMatrixError) -> Self {
        Self::Qr(e)
    }
}

impl From<crate::storage::qr_png::QrPngError> for FrameError {
    fn from(e: crate::storage::qr_png::QrPngError) -> Self {
        Self::Png(e)
    }
}

/// Write one symbol as an optical frame.
///
/// # Errors
///
/// [`FrameError::BadPayloadLen`] when the symbol is empty or larger than one
/// QR symbol can carry together with its frame header.
pub fn frame_for_symbol(symbol: &Symbol) -> Result<Vec<u8>, FrameError> {
    let len = symbol.data.len();
    if len == 0 || len > MAX_SYMBOL_IN_FRAME {
        return Err(FrameError::BadPayloadLen(len));
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + len);
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.extend_from_slice(&symbol.esi.to_le_bytes());
    out.extend_from_slice(&symbol.segment.to_le_bytes());
    out.extend_from_slice(&symbol.data);
    Ok(out)
}

/// Read one optical frame back into a symbol.
///
/// The frame does not carry its symbol length, so the reader takes everything
/// after the header as the symbol. A caller that has a profile should use
/// [`symbol_from_frame_sized`], which checks the length as well.
///
/// # Errors
///
/// [`FrameError`] for a frame that is not canonical: wrong magic or version, a
/// truncated header, an empty symbol or a frame longer than one QR symbol.
pub fn symbol_from_frame(frame: &[u8]) -> Result<Symbol, FrameError> {
    let magic = frame.get(..3).ok_or(FrameError::Truncated)?;
    if magic != FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    let version = *frame.get(3).ok_or(FrameError::Truncated)?;
    if version != FRAME_VERSION {
        return Err(FrameError::BadVersion(version));
    }
    let esi_bytes = frame.get(4..8).ok_or(FrameError::Truncated)?;
    let mut esi = [0u8; 4];
    esi.copy_from_slice(esi_bytes);
    let segment_bytes = frame.get(8..FRAME_HEADER_LEN).ok_or(FrameError::Truncated)?;
    let mut segment = [0u8; 8];
    segment.copy_from_slice(segment_bytes);
    let data = frame.get(FRAME_HEADER_LEN..).ok_or(FrameError::Truncated)?;
    if data.is_empty() {
        return Err(FrameError::BadPayloadLen(0));
    }
    if data.len() > MAX_SYMBOL_IN_FRAME {
        return Err(FrameError::BadPayloadLen(data.len()));
    }
    Ok(Symbol {
        segment: u64::from_le_bytes(segment),
        esi: u32::from_le_bytes(esi),
        data: data.to_vec(),
    })
}

/// Read a frame back into the symbol it presents, refusing a symbol whose
/// length is not the profile's symbol size.
///
/// The frame reader alone cannot check this, because the frame carries no
/// length. Inside a session a frame whose symbol is short would silently
/// become a smaller symbol at the same ESI, which the decoder would then
/// either reject or accept with different bytes, so the length comes from the
/// profile and a mismatch is a malformed frame.
///
/// # Errors
///
/// Every [`symbol_from_frame`] error, plus [`FrameError::WrongSymbolSize`].
pub fn symbol_from_frame_sized(frame: &[u8], profile: &Profile) -> Result<Symbol, FrameError> {
    let symbol = symbol_from_frame(frame)?;
    let want = usize::from(profile.symbol_size);
    if symbol.data.len() != want {
        return Err(FrameError::WrongSymbolSize {
            want,
            got: symbol.data.len(),
        });
    }
    Ok(symbol)
}

/// Render one frame as a deterministic QR PNG.
///
/// # Errors
///
/// [`FrameError::Qr`] or [`FrameError::Png`] when the symbol cannot be
/// presented; a payload that does not fit one symbol was already refused by
/// [`frame_for_symbol`].
pub fn frame_to_png(frame: &[u8]) -> Result<Vec<u8>, FrameError> {
    let matrix = QrMatrix::encode(frame)?;
    Ok(matrix_to_png(&matrix)?)
}

/// Whether the bytes start with the PNG signature.
#[must_use]
pub fn is_png(bytes: &[u8]) -> bool {
    bytes.starts_with(&PNG_MAGIC)
}

/// Read a QR PNG back into the frame it presents.
///
/// # Errors
///
/// [`FrameError::Decode`] when a raster holds no readable symbol. A caller
/// reading a video skips such a raster rather than ending the session.
pub fn png_to_frame(png: &[u8]) -> Result<Vec<u8>, FrameError> {
    if !is_png(png) {
        return Err(FrameError::Decode(String::from("not a png")));
    }
    png_to_optical_frame(png).map_err(|e| FrameError::Decode(e.to_string()))
}

/// The frames of one object: one frame per coded symbol, grouped by segment.
///
/// # Errors
///
/// [`ObjectError`] for a profile that does not segment or a segment that
/// cannot be coded, and [`FrameError::BadPayloadLen`] when a symbol does not
/// fit one presentation frame.
pub fn frames_for_object(
    object: &[u8],
    profile: &Profile,
    symbols_per_segment: u32,
) -> Result<Vec<Symbol>, FrameError> {
    let segments = encode_symbols(object, profile, symbols_per_segment)?;
    let mut out = Vec::new();
    for group in segments {
        for symbol in group {
            // Validate the presentation length once, here, so the caller learns
            // about it before it renders anything.
            let _ = frame_for_symbol(&symbol)?;
            out.push(symbol);
        }
    }
    Ok(out)
}

/// Render the frames of an object as QR PNGs, in frame order.
///
/// # Errors
///
/// Every [`frames_for_object`] error, plus [`FrameError::Qr`] and
/// [`FrameError::Png`] when a frame cannot be presented.
pub fn optical_video(
    object: &[u8],
    profile: &Profile,
    symbols_per_segment: u32,
) -> Result<Vec<Vec<u8>>, FrameError> {
    let symbols = frames_for_object(object, profile, symbols_per_segment)?;
    let mut out = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        out.push(frame_to_png(&frame_for_symbol(&symbol)?)?);
    }
    Ok(out)
}

/// Write the object bytes back from QR PNGs (Y10).
///
/// Symbols may arrive out of order or repaired, and the fountain code needs
/// any `k` of them per segment. A raster that does not parse is skipped,
/// because one unreadable picture on a screen must not end a view.
///
/// # Errors
///
/// [`ObjectError`] when a segment does not reach `k` symbols.
pub fn object_from_optical(
    pngs: &[Vec<u8>],
    profile: &Profile,
    object_len: u64,
) -> Result<Vec<u8>, ObjectError> {
    // An unreadable raster is skipped, but every readable frame must present a
    // symbol of the profile's size: a short symbol is a malformed frame, not a
    // smaller one, so it is dropped rather than decoded.
    let mut symbols = Vec::with_capacity(pngs.len());
    for png in pngs {
        let Ok(frame) = png_to_frame(png) else {
            continue;
        };
        let Ok(symbol) = symbol_from_frame_sized(&frame, profile) else {
            continue;
        };
        symbols.push(symbol);
    }
    object_from_symbols(&symbols, profile, object_len)
}

/// Y11, the two-path gate: the object written from the optical path equals the
/// object the encoder wrote.
///
/// # Errors
///
/// [`FrameError::TwoPathMismatch`] when the bytes differ. A difference is not a
/// tolerance to widen: the two paths are the same object by definition, and an
/// upload that disagrees with itself is refused.
pub fn two_paths_identical(
    object: &[u8],
    profile: &Profile,
    symbols_per_segment: u32,
) -> Result<(), FrameError> {
    let pngs = optical_video(object, profile, symbols_per_segment)?;
    let from_optical = object_from_optical(&pngs, profile, object.len() as u64)?;
    if from_optical != object {
        return Err(FrameError::TwoPathMismatch);
    }
    Ok(())
}

/// Y12, the round-trip gate: an object cut into segments keeps its length and
/// its source symbol count.
///
/// # Errors
///
/// [`FrameError::Object`] for a profile that does not segment.
pub fn round_trip_shape(object: &[u8], profile: &Profile) -> Result<(u64, u64), FrameError> {
    let seg = Segmentation::new(object.len() as u64, profile).ok_or(ObjectError::BadProfile)?;
    Ok((seg.count(), seg.total_source_symbols()))
}

/// The number of frames a viewer must collect to decode one segment: `k + 2`,
/// the source symbols plus the two the loss rule asks for (Section 6.5 G3).
///
/// # Errors
///
/// [`FrameError::Object`] for a profile that does not segment, or a segment
/// that does not exist in the object.
pub fn symbols_to_collect(
    profile: &Profile,
    object_len: u64,
    segment: u64,
) -> Result<u32, FrameError> {
    let seg = Segmentation::new(object_len, profile).ok_or(ObjectError::BadProfile)?;
    let k = seg
        .source_symbols(segment)
        .ok_or(ObjectError::SegmentMissing(segment))?;
    u32::try_from(k)
        .ok()
        .and_then(|k| k.checked_add(2))
        .ok_or(FrameError::Object(ObjectError::TooLarge))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::bud3::bof1::Object;

    const SMALL: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 64,
        fps: 4,
        k_max: 8,
    };

    #[test]
    fn a_frame_round_trips_through_its_symbol() {
        let symbol = Symbol {
            segment: 3,
            esi: 17,
            data: vec![1, 2, 3, 4],
        };
        let frame = frame_for_symbol(&symbol).unwrap();
        assert_eq!(symbol_from_frame(&frame).unwrap(), symbol);
    }

    #[test]
    fn a_short_symbol_is_refused_by_the_sized_reader() {
        let frame = frame_for_symbol(&Symbol {
            segment: 0,
            esi: 0,
            data: vec![9; 4],
        })
        .unwrap();
        assert_eq!(
            symbol_from_frame_sized(&frame, &SMALL),
            Err(FrameError::WrongSymbolSize { want: 64, got: 4 })
        );
    }

    #[test]
    fn a_frame_too_large_for_one_qr_symbol_is_refused() {
        let symbol = Symbol {
            segment: 0,
            esi: 0,
            data: vec![0u8; MAX_SYMBOL_IN_FRAME + 1],
        };
        assert!(matches!(
            frame_for_symbol(&symbol),
            Err(FrameError::BadPayloadLen(_))
        ));
    }

    #[test]
    fn a_frame_past_k_is_a_repair_frame() {
        // One segment of 8 source symbols; ESI 8 is the first repair symbol.
        let seg = Segmentation::new(8 * u64::from(SMALL.symbol_size), &SMALL).unwrap();
        assert_eq!(seg.source_symbols(0), Some(8));
        let source = Symbol {
            segment: 0,
            esi: 7,
            data: vec![1u8; 64],
        };
        let repair = Symbol {
            segment: 0,
            esi: 8,
            data: vec![2u8; 64],
        };
        let k = seg.source_symbols(source.segment).unwrap_or(0);
        assert!(u64::from(source.esi) < k);
        assert!(u64::from(repair.esi) >= k);
        let frame = frame_for_symbol(&repair).unwrap();
        assert_eq!(symbol_from_frame_sized(&frame, &SMALL).unwrap().esi, 8);
    }

    #[test]
    fn the_two_paths_agree_on_a_small_object() {
        let profile = Profile {
            symbol_size: 2911,
            ..SMALL
        };
        let object = Object::raw_public(b"two paths, one object").encode();
        two_paths_identical(&object, &profile, 4).unwrap();
    }
}
