//! One-shot Three pipe facade (A0→A1→A2→A3→A5, optional G1).
//!
//! Keeps callers from wiring every stage by hand in the common case while
//! each stage stays independently testable.

use crate::storage::payload_crypt::{derived_nonce, seal_payload, PayloadKey, SealError};
use crate::storage::qr_carousel::{
    planned_drop_count, CarouselEncoder, CarouselError, DEFAULT_BLOCK_LEN,
};
use crate::storage::qr_codec::{CodecError, CodecKind, FrameMux, RawFrameConcat};
use crate::storage::qr_video::{demux_optical_frames, QrVideo, QrVideoError, DEFAULT_FPS};
use crate::storage::qr_frame::{fold_frame_digests, frame_digest, pack_frame, FrameError};
use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadError, PayloadKind};
use crate::storage::qr_recipe::{ThreeRecipe, ThreeRecipePublic};
use crate::storage::qr_receive::{ProgressiveReceiver, ReceiveError};
use crate::storage::transformed::{CodecFlags, TransformError, TransformedPayload};

/// Errors from the facade.
#[derive(Debug)]
pub enum PipeError {
    /// A0.
    Transform(TransformError),
    /// G1.
    Seal(SealError),
    /// A1.
    Payload(PayloadError),
    /// A2.
    Carousel(CarouselError),
    /// A3.
    Frame(FrameError),
    /// A4.
    Codec(CodecError),
    /// A7.
    Receive(ReceiveError),
    /// A4 QR-video.
    Video(QrVideoError),
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transform(e) => write!(f, "{e}"),
            Self::Seal(e) => write!(f, "{e}"),
            Self::Payload(e) => write!(f, "{e}"),
            Self::Carousel(e) => write!(f, "{e}"),
            Self::Frame(e) => write!(f, "{e}"),
            Self::Codec(e) => write!(f, "{e}"),
            Self::Receive(e) => write!(f, "{e}"),
            Self::Video(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PipeError {}

impl From<TransformError> for PipeError {
    fn from(e: TransformError) -> Self {
        Self::Transform(e)
    }
}
impl From<SealError> for PipeError {
    fn from(e: SealError) -> Self {
        Self::Seal(e)
    }
}
impl From<PayloadError> for PipeError {
    fn from(e: PayloadError) -> Self {
        Self::Payload(e)
    }
}
impl From<CarouselError> for PipeError {
    fn from(e: CarouselError) -> Self {
        Self::Carousel(e)
    }
}
impl From<FrameError> for PipeError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}
impl From<CodecError> for PipeError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}
impl From<ReceiveError> for PipeError {
    fn from(e: ReceiveError) -> Self {
        Self::Receive(e)
    }
}
impl From<QrVideoError> for PipeError {
    fn from(e: QrVideoError) -> Self {
        Self::Video(e)
    }
}

/// Result of encoding content into the Three pipe.
#[derive(Debug, Clone)]
pub struct EncodedPipe {
    /// A1 packed container.
    pub packed: Vec<u8>,
    /// Public recipe (stream_id = frame-fold when frames were emitted).
    pub recipe: ThreeRecipePublic,
    /// Optical frames (A3).
    pub frames: Vec<Vec<u8>>,
    /// A2 stream commitment used to bind frames.
    pub stream_commitment: [u8; 32],
}

/// Encode plaintext (optionally sealed) through A0–A3/A5.
///
/// # Errors
///
/// Any stage failure.
pub fn encode_plain(
    content: &[u8],
    block_len: u16,
    seal_key: Option<&PayloadKey>,
) -> Result<EncodedPipe, PipeError> {
    let transformed = TransformedPayload::from_bytes(
        content.to_vec(),
        if seal_key.is_some() {
            CodecFlags::CIPHERTEXT
        } else {
            CodecFlags::NONE
        },
    )?;
    let (kind, body) = if let Some(key) = seal_key {
        let sealed = seal_payload(key, &derived_nonce(b"three_pipe"), &transformed.bytes)?;
        (PayloadKind::EncryptedContent, sealed)
    } else {
        (PayloadKind::ContentBytes, transformed.bytes)
    };
    let packed = pack_payload(kind, &body)?;
    let commit = payload_commitment(&packed);
    let enc = CarouselEncoder::new(&packed, block_len)?;
    let stream_commitment = enc.params().stream_commitment(&commit);
    let n = planned_drop_count(enc.params().k, 0);
    let mut frames = Vec::with_capacity(n as usize);
    let mut digests = Vec::with_capacity(n as usize);
    for seq in 0..n {
        let drop = enc.drop_at(seq);
        digests.push(frame_digest(&stream_commitment, seq, &drop.to_bytes()));
        frames.push(pack_frame(&stream_commitment, &drop));
    }
    let fold = fold_frame_digests(&digests)?;
    let recipe = ThreeRecipePublic::new(commit, enc.params(), fold);
    Ok(EncodedPipe {
        packed,
        recipe,
        frames,
        stream_commitment,
    })
}

/// Decode frames back to A1 body kind + bytes (not decrypting G1).
///
/// # Errors
///
/// Receive / unpack failures.
pub fn decode_frames(
    stream_commitment: &[u8; 32],
    frames: &[Vec<u8>],
) -> Result<(PayloadKind, Vec<u8>), PipeError> {
    let mut rx = ProgressiveReceiver::new(*stream_commitment);
    for fr in frames {
        rx.push_frame(fr)?;
        if rx.is_complete() {
            break;
        }
    }
    Ok(rx.finish_unpacked()?)
}

/// Optional A4 raw concat of already-built frames.
pub fn mux_raw(frames: &[Vec<u8>]) -> Result<Vec<u8>, PipeError> {
    Ok(RawFrameConcat.mux(CodecKind::RawFrames, frames)?)
}

/// Recipe commitment helper.
#[must_use]
pub fn recipe_commitment(recipe: &ThreeRecipePublic) -> [u8; 32] {
    ThreeRecipe::Public(recipe.clone()).commitment()
}

/// Default block length re-export for callers.
pub const PIPE_DEFAULT_BLOCK_LEN: u16 = DEFAULT_BLOCK_LEN;

/// Full product object: recipe + QR-video blob (BDLV of QR PNGs).
#[derive(Debug, Clone)]
pub struct EncodedQrVideo {
    /// Pipe encoding (packed, recipe, optical frames, stream id).
    pub pipe: EncodedPipe,
    /// QR-video container.
    pub video: QrVideo,
    /// Serialized BDLV bytes (what NFT/tarif re-emits as the video object).
    pub video_blob: Vec<u8>,
}

/// Root 3.0 encode: content → (optional seal) → A1…A3 → QR matrices → BDLV video.
pub fn encode_qr_video(
    content: &[u8],
    block_len: u16,
    seal_key: Option<&PayloadKey>,
) -> Result<EncodedQrVideo, PipeError> {
    let pipe = encode_plain(content, block_len, seal_key)?;
    let video = QrVideo::from_optical_frames(
        &pipe.recipe,
        &pipe.stream_commitment,
        &pipe.frames,
        DEFAULT_FPS,
    )?;
    let video_blob = video.to_bytes();
    Ok(EncodedQrVideo {
        pipe,
        video,
        video_blob,
    })
}

/// Root 3.0 decode: BDLV → optical frames → content body (kind + bytes).
pub fn decode_qr_video(video_blob: &[u8]) -> Result<(PayloadKind, Vec<u8>, QrVideo), PipeError> {
    let video = QrVideo::from_bytes(video_blob)?;
    let optical = demux_optical_frames(&video)?;
    let (kind, raw) = decode_frames(&video.stream_commitment, &optical)?;
    Ok((kind, raw, video))
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::payload_crypt::{open_payload, PayloadKey};

    #[test]
    fn plain_pipe_round_trip() {
        let content = b"facade-plain-content".repeat(20);
        let enc = encode_plain(&content, PIPE_DEFAULT_BLOCK_LEN, None).unwrap();
        let (kind, raw) = decode_frames(&enc.stream_commitment, &enc.frames).unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(raw, content.as_slice());
        let _ = recipe_commitment(&enc.recipe);
        let blob = mux_raw(&enc.frames).unwrap();
        assert!(blob.starts_with(b"BDLR"));
    }

    #[test]
    fn qr_video_root_round_trip() {
        let content = b"root-qr-video-product".repeat(5);
        let enc = encode_qr_video(&content, 64, None).unwrap();
        assert!(enc.video_blob.starts_with(b"BDLV"));
        let (kind, raw, _v) = decode_qr_video(&enc.video_blob).unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(raw, content.as_slice());
        // re-emit video from recipe path must match blob commitment if same frames
        let again = encode_qr_video(&content, 64, None).unwrap();
        assert_eq!(enc.video_blob, again.video_blob);
    }

    #[test]
    fn sealed_pipe_round_trip() {
        let key = PayloadKey::derive(b"facade-key");
        let content = b"facade-secret";
        let enc = encode_plain(content, 64, Some(&key)).unwrap();
        let (kind, body) = decode_frames(&enc.stream_commitment, &enc.frames).unwrap();
        assert_eq!(kind, PayloadKind::EncryptedContent);
        assert_eq!(open_payload(&key, &body).unwrap(), content);
    }
}
