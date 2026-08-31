//! One-shot Three pipe facade (A0→A1→A2→A3→A5, optional G1).
//!
//! Keeps callers from wiring every stage by hand in the common case while
//! each stage stays independently testable.

use crate::storage::payload_crypt::{seal_payload_csprng, PayloadKey, SealError};
use crate::storage::qr_carousel::{
    oneshot_drop_count, CarouselEncoder, CarouselError, DEFAULT_BLOCK_LEN,
    ONESHOT_REPAIR_PERMILLAGE,
};
use crate::storage::qr_codec::{CodecError, CodecKind, FrameMux};
use crate::storage::qr_frame::{fold_frame_digests, frame_digest, pack_frame, FrameError};
use crate::storage::qr_payload::{
    pack_payload_opts, payload_commitment, PayloadError, PayloadKind,
};
use crate::storage::qr_receive::{ProgressiveReceiver, ReceiveError};
use crate::storage::qr_recipe::{ThreeRecipe, ThreeRecipePublic};
use crate::storage::qr_video::{demux_optical_frames, QrVideo, QrVideoError, DEFAULT_FPS};
use crate::storage::transformed::{
    transform_content, CodecFlags, ContentClass, TransformError, TransformOpts, TransformedPayload,
};

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
    /// Public recipe (`stream_id` = frame-fold when frames were emitted).
    pub recipe: ThreeRecipePublic,
    /// Optical frames (A3).
    pub frames: Vec<Vec<u8>>,
    /// A2 stream commitment used to bind frames.
    pub stream_commitment: [u8; 32],
    /// A0 content class after transform.
    pub class: ContentClass,
    /// A0 codec flags of the same pass: whether zlib bought anything, whether the
    /// input was already entropy-coded. Reported next to `class` because A1 runs
    /// its own compression pass over the result, so a caller that wants to know
    /// what A0 did cannot read it back out of the container.
    pub flags: CodecFlags,
}

impl EncodedPipe {
    /// Source block count `k` locked by the carousel params.
    #[must_use]
    pub const fn pipe_recipe_k(&self) -> u16 {
        self.recipe.carousel.k
    }
}

/// Encode plaintext (optionally sealed) through A0-A3/A5.
///
/// # Errors
///
/// Any stage failure.
fn encode_plain(
    content: &[u8],
    block_len: u16,
    seal_key: Option<&PayloadKey>,
) -> Result<EncodedPipe, PipeError> {
    // A0: classify + zlib-if-shrinks (entropy types skip zlib).
    let transformed = transform_content(content, TransformOpts::default())?;
    encode_payload(transformed, block_len, seal_key)
}

/// A1-A5 over an already transformed payload.
///
/// Exists so a caller that produced the A0 pass itself (a recipe that pins its
/// knobs, a re-emission that must reproduce byte for byte) hands the same payload
/// to the container instead of transforming the content a second time and hoping
/// two implementations agree.
///
/// # Errors
///
/// Digest mismatch, seal or container failure.
fn encode_payload(
    prepared: TransformedPayload,
    block_len: u16,
    seal_key: Option<&PayloadKey>,
) -> Result<EncodedPipe, PipeError> {
    // A1 handoff: the body that goes into the carousel must still carry the
    // digest this transform pinned. A stale or forged payload is refused here,
    // before a commitment is computed over bytes nobody verified.
    if !prepared.verify_hash() {
        return Err(TransformError::HashMismatch.into());
    }
    let class = prepared.class;
    let flags = prepared.codec_flags;
    let (kind, body) = if let Some(key) = seal_key {
        // A fresh CSPRNG nonce per call: two seals under the same key would share a
        // keystream, and XORing their ciphertexts leaks the plaintexts.
        let sealed = seal_payload_csprng(key, &prepared.bytes)?;
        (PayloadKind::EncryptedContent, sealed)
    } else {
        (PayloadKind::ContentBytes, prepared.bytes)
    };
    // The A0 class drives the A1 compression attempt. Ciphertext never shrinks,
    // and an entropy-coded class already refused zlib at classification, so the
    // container skips the attempt instead of re-running it over bytes that
    // cannot compress. The unpacked bytes are identical either way.
    let allow_zlib = match kind {
        PayloadKind::EncryptedContent => false,
        _ => class.may_try_zlib(),
    };
    let packed = pack_payload_opts(kind, &body, allow_zlib)?;
    let commit = payload_commitment(&packed);
    let enc = CarouselEncoder::new(&packed, block_len)?;
    let stream_commitment = enc.params().stream_commitment(&commit);
    // One-shot handover, not a carousel broadcast: systematic pass plus a
    // repair margin, never the 2k cycle. See `oneshot_drop_count`.
    let n = oneshot_drop_count(enc.params().k, ONESHOT_REPAIR_PERMILLAGE);
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
        class,
        flags,
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

/// Mux a frame list through `M` and split the blob back, returning the frames the
/// container hands an ordinary reader.
///
/// This is the only A4 entry point the crate writes: a container is usable when
/// its own reader finds what its own writer put in, so the pair is offered
/// together and a caller cannot pin a blob nobody can split. A linked container
/// reaches the same path by implementing [`FrameMux`].
///
/// # Errors
///
/// Propagates `PipeError` from either half.
pub fn concat_round_trip<M>(frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, PipeError>
where
    M: Default + FrameMux,
{
    let muxer = M::default();
    let blob = muxer.mux(CodecKind::RawFrames, frames)?;
    Ok(muxer.split(CodecKind::RawFrames, &blob)?)
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
/// # Errors
///
/// Propagates `PipeError` from the step that failed; its variants name the refused conditions.
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
/// # Errors
///
/// Propagates `PipeError` from the step that failed; its variants name the refused conditions.
pub fn decode_qr_video(video_blob: &[u8]) -> Result<(PayloadKind, Vec<u8>, QrVideo), PipeError> {
    let video = QrVideo::from_bytes(video_blob)?;
    let optical = demux_optical_frames(&video)?;
    let (kind, raw) = decode_frames(&video.stream_commitment, &optical)?;
    Ok((kind, raw, video))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::payload_crypt::{open_payload, PayloadKey, SEALED_NONCE_LEN};
    use crate::storage::qr_carousel::{oneshot_drop_count, planned_drop_count};
    use crate::storage::qr_codec::{FrameMux, RawFrameConcat};
    use crate::storage::qr_payload::{packed_is_zlib, unpack_payload};

    /// Incompressible bytes, so `k` is large enough that `k + repair` and the
    /// `2k` carousel floor are different numbers. A repeated-text payload
    /// would shrink to one block at A1 and the two counts would both be small.
    fn incompressible(len: usize) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut out = Vec::with_capacity(len);
        let mut i: u64 = 0;
        while out.len() < len {
            let mut h = Sha256::new();
            h.update(b"oneshot-count-seed");
            h.update(i.to_le_bytes());
            out.extend_from_slice(&h.finalize());
            i += 1;
        }
        out.truncate(len);
        out
    }

    /// A one-shot encode is not a carousel broadcast: the receiver gets the
    /// frames in order, so the systematic pass alone already carries every
    /// source block. `planned_drop_count(k, p)` is `max(ceil(1.02kT), 2k)`, so
    /// below k=197 the `2k` floor binds and the carousel plan writes the
    /// content twice; the QR-video inherits that doubling frame by frame.
    #[test]
    fn oneshot_encode_emits_k_plus_repair_not_two_k() {
        // Direct count check first: same k, two different budgets.
        assert_eq!(
            oneshot_drop_count(100, ONESHOT_REPAIR_PERMILLAGE),
            115,
            "15% repair margin: k + ceil(k * 150/1000)"
        );
        assert_eq!(planned_drop_count(100, 0), 200, "carousel floor is 2k");

        let content = incompressible(20_000);
        let enc = encode_plain(&content, PIPE_DEFAULT_BLOCK_LEN, None).unwrap();
        let k = enc.pipe_recipe_k();
        assert!(
            k > 4,
            "need enough blocks to separate k+repair from 2k, got {k}"
        );

        let expected = oneshot_drop_count(k, ONESHOT_REPAIR_PERMILLAGE);
        let carousel = planned_drop_count(k, 0);
        assert_eq!(
            enc.frames.len() as u32,
            expected,
            "one-shot frame count must be k+repair"
        );
        assert!(
            (enc.frames.len() as u32) < carousel,
            "one-shot {} must stay below the 2k carousel plan {}",
            enc.frames.len(),
            carousel
        );

        let (kind, raw) = decode_frames(&enc.stream_commitment, &enc.frames).unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(raw, content.as_slice());
    }

    /// Frame loss is the reason repair drops exist at all. With the systematic
    /// pass only, a single lost frame must still be recoverable from the
    /// repair margin; this pins that the margin is real, not decorative.
    #[test]
    fn oneshot_survives_sparse_frame_loss() {
        let content = b"oneshot-loss-margin-payload".repeat(60);
        let enc = encode_plain(&content, PIPE_DEFAULT_BLOCK_LEN, None).unwrap();
        let kept: Vec<Vec<u8>> = enc
            .frames
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 20 != 0)
            .map(|(_, f)| f.clone())
            .collect();
        let (kind, raw) = decode_frames(&enc.stream_commitment, &kept).unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(raw, content.as_slice());
    }

    #[test]
    fn plain_pipe_round_trip() {
        let content = b"facade-plain-content".repeat(20);
        let enc = encode_plain(&content, PIPE_DEFAULT_BLOCK_LEN, None).unwrap();
        let (kind, raw) = decode_frames(&enc.stream_commitment, &enc.frames).unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(raw, content.as_slice());
        let _ = recipe_commitment(&enc.recipe);
        let blob = RawFrameConcat
            .mux(CodecKind::RawFrames, &enc.frames)
            .unwrap();
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

    /// The sealed body's nonce: 4 B magic + 1 B version + 24 B nonce.
    fn sealed_nonce_of(enc: &EncodedPipe) -> [u8; SEALED_NONCE_LEN] {
        let (_, body) = unpack_payload(&enc.packed).unwrap();
        let mut n = [0u8; SEALED_NONCE_LEN];
        n.copy_from_slice(&body[5..5 + SEALED_NONCE_LEN]);
        n
    }

    fn sealed_body_of(enc: &EncodedPipe) -> Vec<u8> {
        let (_, body) = unpack_payload(&enc.packed).unwrap();
        body
    }

    /// In XChaCha20-Poly1305 a repeated (key, nonce) pair is a keystream repeat:
    /// two ciphertexts under the same key XOR into the XOR of their plaintexts.
    /// So every seal must carry a fresh nonce, and the deterministic `derived_nonce`
    /// is not available to the production path.
    #[test]
    fn sealed_pipe_uses_a_fresh_nonce_per_call() {
        let key = PayloadKey::derive(b"facade-key");
        let content = b"facade-secret-payload";
        let a = encode_plain(content, 64, Some(&key)).unwrap();
        let b = encode_plain(content, 64, Some(&key)).unwrap();
        assert_ne!(
            sealed_nonce_of(&a),
            sealed_nonce_of(&b),
            "the same key sealed twice with the same nonce: keystream repeat"
        );
        assert_ne!(
            sealed_body_of(&a),
            sealed_body_of(&b),
            "ciphertext ayni kalmis: muhur hala deterministik"
        );
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

    /// The A0 class drives the A1 compression attempt: entropy-coded content
    /// reaches the container with zlib skipped, and sealed content never
    /// attempts zlib over ciphertext.
    #[test]
    fn entropy_and_sealed_classes_skip_the_a1_zlib_attempt() {
        // JPEG-magic bytes classify as EntropyMedia: the A0 pass refused zlib,
        // so A1 must not re-attempt it.
        let mut jpegish = vec![0xff, 0xd8, 0xff, 0xe0];
        jpegish.extend_from_slice(&[0xabu8; 2048]);
        let enc = encode_plain(&jpegish, PIPE_DEFAULT_BLOCK_LEN, None).unwrap();
        assert!(
            !packed_is_zlib(&enc.packed),
            "entropy class must skip the A1 zlib attempt"
        );

        // Sealed content is ciphertext: it must never attempt zlib either.
        let key = PayloadKey::derive(b"class-policy-key");
        let sealed = encode_plain(b"secret body ".repeat(50).as_slice(), 64, Some(&key)).unwrap();
        assert!(
            !packed_is_zlib(&sealed.packed),
            "ciphertext must skip the A1 zlib attempt"
        );

        // Organic text still compresses: the policy only skips what cannot shrink.
        let organic = encode_plain(b"organic body ".repeat(300).as_slice(), 64, None).unwrap();
        assert!(
            packed_is_zlib(&organic.packed),
            "organic text must still attempt zlib at A1"
        );
    }
}
