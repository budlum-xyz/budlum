//! Ephemeral ISO QR optical presentation for B.U.D. 3.0 frames.
//! exposed for upload pixel round-trip verification and P1 optical transfer.
//!
//! Renders [`Bud3Frame`] wire payloads into deterministic ISO/IEC 18004 QR
//! matrices (byte mode, error-correction level L, deterministic mask order
//! `0..=7`) and PNG rasters, and reads PNG pixels back through the optical QR
//! detector (`png_to_optical_frame`) into verified [`Bud3Frame`]s.
//!
//! QR matrices and PNG rasters are strictly transient presentation artifacts:
//! their bytes never enter [`super::ContentId`], [`super::object_commitment`],
//! [`super::video::video_commitment`], or [`super::registry::Bud3Registry`].

use super::bof1::Object;
use super::frame::{frames_for_object_bytes, Bud3Frame, FrameWireError};
use super::limits::{OpticalProfile, Profile};
use super::meter::Meter;
use crate::storage::qr_matrix::{QrMatrix, QrMatrixError, THREE_QR_EC};
use crate::storage::qr_png::{frame_to_qr_png, QrPngError};
use crate::storage::qr_video::{png_to_optical_frame, QrVideoError};

/// One second of ephemeral QR-PNG optical presentation frames (`fps` frames max).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpticalSecond {
    /// Zero-based playback second (`frame_ordinal / fps`).
    pub second: u64,
    /// Ordered deterministic PNG rasters emitted during `second`.
    pub png_frames: Vec<Vec<u8>>,
}

/// Errors during ephemeral QR rendering or optical PNG decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bud3QrError {
    /// Logical frame wire error.
    Frame(FrameWireError),
    /// QR matrix build error.
    Matrix(QrMatrixError),
    /// PNG rasterization error.
    Png(QrPngError),
    /// Optical QR decode error.
    OpticalDecode(QrVideoError),
    /// Invalid P1 optical profile envelope.
    InvalidOpticalProfile,
}

impl From<FrameWireError> for Bud3QrError {
    fn from(e: FrameWireError) -> Self {
        Self::Frame(e)
    }
}

impl From<QrMatrixError> for Bud3QrError {
    fn from(e: QrMatrixError) -> Self {
        Self::Matrix(e)
    }
}

impl From<QrPngError> for Bud3QrError {
    fn from(e: QrPngError) -> Self {
        Self::Png(e)
    }
}

impl From<QrVideoError> for Bud3QrError {
    fn from(e: QrVideoError) -> Self {
        Self::OpticalDecode(e)
    }
}

/// Convenience: build the deterministic ISO QR matrix (byte mode, ECC L,
/// deterministic mask `0..=7`) for one [`Bud3Frame`].
///
/// # Errors
///
/// Returns [`Bud3QrError`] if the encoded frame wire exceeds QR v40 ECC-L capacity.
pub fn frame_to_matrix(frame: &Bud3Frame) -> Result<QrMatrix, Bud3QrError> {
    let wire = frame.encode_wire();
    Ok(QrMatrix::encode_with_ec(&wire, THREE_QR_EC)?)
}

/// Render one [`Bud3Frame`] into a deterministic grayscale PNG image.
///
/// # Errors
///
/// Returns [`Bud3QrError`] if QR encoding or PNG rasterization fails.
pub fn frame_to_png(frame: &Bud3Frame) -> Result<Vec<u8>, Bud3QrError> {
    let wire = frame.encode_wire();
    Ok(frame_to_qr_png(&wire)?)
}

/// Decode a PNG image optically (greyscale raster -> QR finder/grid detection ->
/// wire bytes -> bounded [`Bud3Frame::decode_wire`]).
///
/// # Errors
///
/// Returns [`Bud3QrError`] if the PNG is malformed, contains no readable QR
/// symbol, or carries an invalid [`Bud3Frame`].
pub fn png_to_frame(png_bytes: &[u8], meter: &mut Meter) -> Result<Bud3Frame, Bud3QrError> {
    let wire = png_to_optical_frame(png_bytes)?;
    Ok(Bud3Frame::decode_wire(&wire, meter)?)
}

/// Render `object` into second-by-second ephemeral QR-PNG batches under `profile`.
///
/// # Errors
///
/// Returns [`Bud3QrError`] if framing or QR rasterization fails.
pub fn render_optical_seconds(
    object: &Object,
    profile: &Profile,
    repair_per_segment: u32,
) -> Result<Vec<OpticalSecond>, Bud3QrError> {
    let frames = frames_for_object_bytes(&object.encode(), profile, repair_per_segment)?;
    let fps = usize::from(profile.fps.max(1));
    let mut seconds = Vec::new();
    for (sec_idx, group) in frames.chunks(fps).enumerate() {
        let mut png_frames = Vec::with_capacity(group.len());
        for frame in group {
            png_frames.push(frame_to_png(frame)?);
        }
        seconds.push(OpticalSecond {
            second: sec_idx as u64,
            png_frames,
        });
    }
    Ok(seconds)
}

/// Convenience: render `object` on demand under a derived `P1` [`OpticalProfile`]
/// (`QR v25..=30`, `550..=900` byte symbols, `10..=30` fps) without mutating
/// the canonical P0 BOF-1 object.
///
/// # Errors
///
/// Returns [`Bud3QrError::InvalidOpticalProfile`] if `optical` is outside P1 bounds.
pub fn render_p1_optical_seconds(
    object: &Object,
    optical: &OpticalProfile,
    repair_per_segment: u32,
) -> Result<Vec<OpticalSecond>, Bud3QrError> {
    if !optical.is_valid() {
        return Err(Bud3QrError::InvalidOpticalProfile);
    }
    render_optical_seconds(object, &optical.as_ephemeral_profile(), repair_per_segment)
}
