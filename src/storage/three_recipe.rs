//! B.U.D. 3.0 - the recipe that **produces the QR-video**.
//!
//! WIRING: `storage::emit::qr_feed_preview` writes a recipe over the feed it
//! just encoded, seals it, and `qr_feed_frames_burst` serves frames through
//! `frame_stream` / `reemit` rather than holding a video. What is still ahead
//! of that is the reveal session's own encode loop (plan §A5), which has to
//! adopt the same recipe path to stop producing videos it then throws away.
//!
//! # What this module is
//!
//! The invention is not "content is a recipe". Organic content cannot be
//! regenerated from a short description; that is the pigeonhole argument the
//! spec already measured (200 000 recipe attempts against a 20 KB random
//! target, zero matches). The recipe here describes something else: **how to
//! rebuild the QR-video**, frame by frame, bit for bit.
//!
//! The split that makes it work:
//!
//! - **2.0** compresses the content and that compressed body is what is stored.
//! - **3.0** stores a recipe instead of the video. The recipe plus the stored
//!   body regenerate the QR-video on demand, and the video yields the content.
//!
//! So the durable objects are a small body and a fixed-size recipe. The video
//! is a derivative: produced when someone opens the content, never held.

use crate::core::hash::{calculate_hash_bytes, hash_fields_bytes};
use crate::storage::qr_carousel::{oneshot_drop_count, CarouselEncoder, CarouselError};
use crate::storage::qr_frame::{fold_frame_digests, frame_digest, pack_frame, FrameError};
use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadError, PayloadKind};
use crate::storage::qr_png::frame_to_qr_png;
use crate::storage::qr_recipe::ThreeRecipePublic;
use crate::storage::qr_video::{QrVideo, QrVideoError, MAX_VIDEO_FRAMES, VIDEO_MAGIC};
use crate::storage::three_pipe::{EncodedPipe, EncodedQrVideo, PipeError};
use crate::storage::transformed::{
    transform_content, CodecFlags, ContentClass, TransformError, TransformOpts,
};

/// Errors from the recipe layer.
#[derive(Debug)]
pub enum VideoRecipeError {
    /// Body hash does not match the recipe's pin.
    BodyMismatch,
    /// Sealed recipe was asked to open with the wrong full recipe.
    SealedMismatch,
    /// Sealed recipe needs the full recipe to produce anything.
    NeedFullRecipe,
    /// Nested pipe failure.
    Pipe(PipeError),
    /// Nested video failure.
    Video(QrVideoError),
    /// Nested A1 container failure.
    Payload(PayloadError),
    /// Nested A0 transform failure.
    Transform(TransformError),
    /// Nested A2 carousel failure.
    Carousel(CarouselError),
    /// Nested A3 frame failure.
    Frame(FrameError),
}

impl std::fmt::Display for VideoRecipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyMismatch => write!(f, "video recipe body hash mismatch"),
            Self::SealedMismatch => write!(f, "sealed video recipe does not open with this recipe"),
            Self::NeedFullRecipe => write!(f, "sealed video recipe needs the full recipe"),
            Self::Pipe(e) => write!(f, "video recipe pipe: {e}"),
            Self::Video(e) => write!(f, "video recipe video: {e}"),
            Self::Payload(e) => write!(f, "video recipe payload: {e}"),
            Self::Transform(e) => write!(f, "video recipe transform: {e}"),
            Self::Carousel(e) => write!(f, "video recipe carousel: {e}"),
            Self::Frame(e) => write!(f, "video recipe frame: {e}"),
        }
    }
}

impl std::error::Error for VideoRecipeError {}

impl From<PipeError> for VideoRecipeError {
    fn from(e: PipeError) -> Self {
        Self::Pipe(e)
    }
}

impl From<QrVideoError> for VideoRecipeError {
    fn from(e: QrVideoError) -> Self {
        Self::Video(e)
    }
}

impl From<PayloadError> for VideoRecipeError {
    fn from(e: PayloadError) -> Self {
        Self::Payload(e)
    }
}

impl From<TransformError> for VideoRecipeError {
    fn from(e: TransformError) -> Self {
        Self::Transform(e)
    }
}

impl From<CarouselError> for VideoRecipeError {
    fn from(e: CarouselError) -> Self {
        Self::Carousel(e)
    }
}

impl From<FrameError> for VideoRecipeError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

/// The transform knobs a recipe pins.
///
/// This mirrors [`TransformOpts`] but owns its data: `TransformOpts` carries a
/// `&'static str` MIME hint, which is right for a call site and wrong for a
/// wire object, because a deserialized recipe cannot promise a `'static`
/// string. The conversion is explicit in both directions so the two cannot
/// drift silently.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecipeTransform {
    /// Forced class. `None` means "sniff the body".
    pub force_class: Option<ContentClass>,
    /// Apply shrink-only zlib at A0. Off by default because A1 already does it.
    pub apply_zlib: bool,
}

impl RecipeTransform {
    /// Pin whatever a runtime transform call would have done, so re-emission
    /// classifies the body the same way even without the original MIME hint.
    #[must_use]
    pub fn pin_from(opts: TransformOpts, body: &[u8]) -> Self {
        Self {
            force_class: Some(
                opts.force_class
                    .unwrap_or_else(|| ContentClass::classify(body, opts.mime_hint)),
            ),
            apply_zlib: opts.apply_zlib,
        }
    }

    /// Back to runtime options. The MIME hint is dropped on purpose: the class
    /// is already pinned, and a hint could only contradict it.
    #[must_use]
    pub const fn as_opts(&self) -> TransformOpts {
        TransformOpts {
            mime_hint: None,
            force_class: self.force_class,
            apply_zlib: self.apply_zlib,
        }
    }
}

/// The complete, re-runnable production of one QR-video.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VideoRecipe {
    /// Content bytes the pipe consumes. These are the compressed 2.0 body; the
    /// recipe pins them by hash so a wrong body cannot produce a valid video.
    pub content_bytes: Vec<u8>,
    /// A0 knobs, pinned so the transform reruns identically.
    pub transform: RecipeTransform,
    /// A1 container kind tag.
    pub payload_kind: u8,
    /// A2 source-block length.
    pub block_len: u16,
    /// A2 one-shot repair margin, permillage of `k`.
    pub repair_permillage: u32,
    /// Display pacing hint written into the video header.
    pub fps: u16,
    /// SHA-256 of `content_bytes`.
    pub content_sha256: [u8; 32],
    /// Commitment over the whole BDLV blob this recipe produces.
    pub video_commitment: [u8; 32],
    /// Frame count, so a client knows how many to ask for before starting.
    pub frame_count: u32,
}

/// Sealed form: enough to verify and meter, not enough to produce.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VideoRecipeSealed {
    /// Digest of the full [`VideoRecipe`].
    pub recipe_commitment: [u8; 32],
    /// Commitment over the produced BDLV blob.
    pub video_commitment: [u8; 32],
    /// Hash of the body, so a holder can check what they were given.
    pub content_sha256: [u8; 32],
    /// Declared content length.
    pub content_len: u32,
    /// Declared frame count.
    pub frame_count: u32,
    /// Display pacing hint.
    pub fps: u16,
}

impl VideoRecipe {
    /// Write the recipe for an already-encoded video.
    ///
    /// # Errors
    ///
    /// Only through the nested commitment step.
    pub fn from_encoded(
        content: &[u8],
        transform: RecipeTransform,
        payload_kind: u8,
        block_len: u16,
        repair_permillage: u32,
        fps: u16,
        encoded: &EncodedQrVideo,
    ) -> Self {
        Self {
            content_bytes: content.to_vec(),
            transform,
            payload_kind,
            block_len,
            repair_permillage,
            fps,
            content_sha256: calculate_hash_bytes(content),
            video_commitment: QrVideo::blob_commitment(&encoded.video_blob),
            frame_count: encoded.video.png_frames.len() as u32,
        }
    }

    /// Domain-separated commitment. This is what the NFT pins.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_THREE_VIDEO_RECIPE_V1",
            &self.content_sha256,
            &self.video_commitment,
            &self.content_bytes.len().to_le_bytes(),
            &self.frame_count.to_le_bytes(),
            &self.fps.to_le_bytes(),
            &self.block_len.to_le_bytes(),
            &self.repair_permillage.to_le_bytes(),
            &[self.payload_kind],
            &[u8::from(self.transform.apply_zlib)],
            &[self
                .transform
                .force_class
                .map(|c| c as u8)
                .unwrap_or(u8::MAX)],
        ])
    }

    /// Seal into the on-chain public form. No body, no key material.
    #[must_use]
    pub fn seal(&self) -> VideoRecipeSealed {
        VideoRecipeSealed {
            recipe_commitment: self.commitment(),
            video_commitment: self.video_commitment,
            content_sha256: self.content_sha256,
            content_len: self.content_bytes.len() as u32,
            frame_count: self.frame_count,
            fps: self.fps,
        }
    }

    /// Produce the QR-video this recipe describes.
    ///
    /// `body` must be the bytes the recipe pins; anything else is refused
    /// before a single frame is generated.
    ///
    /// # Errors
    ///
    /// Body hash mismatch, or any pipe/video failure.
    pub fn reemit(&self, body: &[u8]) -> Result<EncodedQrVideo, VideoRecipeError> {
        if calculate_hash_bytes(body) != self.content_sha256 {
            return Err(VideoRecipeError::BodyMismatch);
        }
        let encoded = encode_qr_video_internal(
            body,
            self.transform,
            self.payload_kind,
            self.block_len,
            self.repair_permillage,
            self.fps,
        )?;
        if QrVideo::blob_commitment(&encoded.video_blob) != self.video_commitment {
            return Err(VideoRecipeError::BodyMismatch);
        }
        Ok(encoded)
    }

    /// Frame-by-frame production, for progressive delivery.
    ///
    /// Returns frame `seq` only, holding nothing else. A client that wants the
    /// video asks for `0..frame_count` in order and can start playing before
    /// the last frame exists.
    ///
    /// # Errors
    ///
    /// Body hash mismatch, out-of-range `seq`, or any pipe/video failure.
    pub fn frame_at(&self, body: &[u8], seq: u32) -> Result<Vec<u8>, VideoRecipeError> {
        if seq >= self.frame_count {
            return Err(VideoRecipeError::Video(QrVideoError::TooMany(seq)));
        }
        self.frame_stream(body)?.frame_at(seq)
    }

    /// Open an incremental cursor over this recipe's frames.
    ///
    /// The shared work (transform, pack, carousel) runs once here, so asking
    /// for frame 999 after frame 0 costs one frame, not a second video.
    ///
    /// # Errors
    ///
    /// Body hash mismatch, or any A0-A2 failure.
    pub fn frame_stream(&self, body: &[u8]) -> Result<VideoFrameStream, VideoRecipeError> {
        if calculate_hash_bytes(body) != self.content_sha256 {
            return Err(VideoRecipeError::BodyMismatch);
        }
        let core = RecipeCore::from_body(
            body,
            self.transform.as_opts(),
            self.payload_kind,
            self.block_len,
            self.repair_permillage,
            self.fps,
        )?;
        Ok(VideoFrameStream { core, next_seq: 0 })
    }
}

impl VideoRecipeSealed {
    /// Open with the full recipe. Refuses a recipe that does not match.
    ///
    /// # Errors
    ///
    /// [`VideoRecipeError::SealedMismatch`].
    pub fn open_with(&self, full: &VideoRecipe) -> Result<(), VideoRecipeError> {
        if full.commitment() != self.recipe_commitment {
            return Err(VideoRecipeError::SealedMismatch);
        }
        Ok(())
    }

    /// Produce through an opened full recipe.
    ///
    /// # Errors
    ///
    /// Sealed mismatch, body mismatch, or pipe failure.
    pub fn reemit_with(
        &self,
        full: &VideoRecipe,
        body: &[u8],
    ) -> Result<EncodedQrVideo, VideoRecipeError> {
        self.open_with(full)?;
        full.reemit(body)
    }
}

/// Everything the production path needs once the knobs are pinned, but before
/// any frame is materialised.
///
/// Holding this is what lets the recipe hand frames over one at a time: the
/// expensive shared work (transform, pack, carousel) runs once, and each frame
/// afterwards is its own independent PNG.
#[derive(Clone)]
struct RecipeCore {
    /// The packed A1 body, owned so the encoder can borrow it.
    packed: Vec<u8>,
    /// A0 class the pinned knobs produced, carried so the pipe reports the
    /// transform that actually ran instead of a re-classification of the packed
    /// bytes.
    class: ContentClass,
    /// A0 codec flags of the same pass.
    flags: CodecFlags,
    /// Carousel encoder over `packed`.
    enc: CarouselEncoder,
    /// Stream binding every frame carries.
    stream_commitment: [u8; 32],
    /// Frame count the recipe pins.
    n: u32,
    /// Pinned pacing hint.
    fps: u16,
}

impl RecipeCore {
    /// Run A0-A2 under pinned knobs. No frame is produced yet.
    ///
    /// `opts` is the A0 knob set; a caller that already transformed once passes
    /// it straight through so the body is never transformed twice.
    fn from_body(
        content: &[u8],
        opts: TransformOpts,
        payload_kind: u8,
        block_len: u16,
        repair_permillage: u32,
        fps: u16,
    ) -> Result<Self, VideoRecipeError> {
        // A0: classify with the pinned knobs.
        let transformed = transform_content(content, opts)?;

        // A1: pack under the pinned kind.
        let kind = match payload_kind {
            1 => PayloadKind::ContentBytes,
            2 => PayloadKind::PublicRecipeWire,
            3 => PayloadKind::EncryptedContent,
            other => {
                return Err(VideoRecipeError::Pipe(PipeError::Payload(
                    PayloadError::BadKind(other),
                )));
            }
        };
        let packed = pack_payload(kind, &transformed.bytes)?;
        let commit = payload_commitment(&packed);

        // A2: systematic pass plus the pinned repair margin, never 2k carousel.
        let enc = CarouselEncoder::new(&packed, block_len)?;
        let stream_commitment = enc.params().stream_commitment(&commit);
        let n = oneshot_drop_count(enc.params().k, repair_permillage);
        if n > MAX_VIDEO_FRAMES {
            return Err(VideoRecipeError::Video(QrVideoError::TooMany(n)));
        }

        Ok(Self {
            packed,
            class: transformed.class,
            flags: transformed.codec_flags,
            enc,
            stream_commitment,
            n,
            fps,
        })
    }

    /// One optical (A3) frame. Independent of every other frame.
    fn optical_frame(&self, seq: u32) -> Vec<u8> {
        let drop = self.enc.drop_at(seq);
        pack_frame(&self.stream_commitment, &drop)
    }

    /// Materialise every frame and mux the BDLV container (A3-A4).
    fn finish(&self) -> Result<EncodedQrVideo, VideoRecipeError> {
        let mut frames = Vec::with_capacity(self.n as usize);
        let mut digests = Vec::with_capacity(self.n as usize);
        for seq in 0..self.n {
            let drop = self.enc.drop_at(seq);
            digests.push(frame_digest(&self.stream_commitment, seq, &drop.to_bytes()));
            frames.push(pack_frame(&self.stream_commitment, &drop));
        }
        let fold = fold_frame_digests(&digests)?;
        let pipe_recipe =
            ThreeRecipePublic::new(payload_commitment(&self.packed), self.enc.params(), fold);

        // A4: QR matrices to PNG frames, muxed into the BDLV container.
        let video =
            QrVideo::from_optical_frames(&pipe_recipe, &self.stream_commitment, &frames, self.fps)?;
        let video_blob = video.to_bytes();
        Ok(EncodedQrVideo {
            pipe: EncodedPipe {
                packed: self.packed.clone(),
                recipe: pipe_recipe,
                frames,
                stream_commitment: self.stream_commitment,
                // The core carries what A0 decided, so the pipe cannot be built
                // from a re-classification of the packed container: that number
                // is a different measurement and would be reported as the A0 one.
                class: self.class,
                flags: self.flags,
            },
            video,
            video_blob,
        })
    }
}

/// Encode with every production knob pinned by a recipe.
///
/// This is the single production path: both the first encode at upload and the
/// re-emit from a recipe run through here, which is what makes the two
/// bit-equal. The frame stream in [`VideoFrameStream`] shares the same
/// `RecipeCore`, so a streamed frame and a re-emitted frame cannot drift.
///
/// # Errors
///
/// Any pipe failure.
fn encode_qr_video_internal(
    content: &[u8],
    transform: RecipeTransform,
    payload_kind: u8,
    block_len: u16,
    repair_permillage: u32,
    fps: u16,
) -> Result<EncodedQrVideo, VideoRecipeError> {
    let opts = transform.as_opts();
    let core = RecipeCore::from_body(
        content,
        opts,
        payload_kind,
        block_len,
        repair_permillage,
        fps,
    )?;
    core.finish()
}

/// Frames of one produced video, handed over one at a time.
///
/// Opening does the shared work once; each [`next_frame`](Self::next_frame) is a single
/// QR matrix and a single PNG, independent of the others. This is what makes
/// "fast open, then progressive" real instead of a claim.
pub struct VideoFrameStream {
    core: RecipeCore,
    next_seq: u32,
}

impl std::fmt::Debug for VideoFrameStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VideoFrameStream")
            .field("next_seq", &self.next_seq)
            .field("len", &self.core.n)
            .finish()
    }
}

impl VideoFrameStream {
    /// Frame `seq` of the stream, without producing the frames before it.
    ///
    /// # Errors
    ///
    /// [`QrVideoError::TooMany`] past the end, or any A4 failure.
    pub fn frame_at(&self, seq: u32) -> Result<Vec<u8>, VideoRecipeError> {
        if seq >= self.core.n {
            return Err(VideoRecipeError::Video(QrVideoError::TooMany(seq)));
        }
        let optical = self.core.optical_frame(seq);
        // QrPngError -> QrVideoError::Png, the same wrapper the muxer uses.
        frame_to_qr_png(&optical)
            .map_err(QrVideoError::from)
            .map_err(VideoRecipeError::from)
    }

    /// Frames still to come, including the next one.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        self.core.n.saturating_sub(self.next_seq)
    }

    /// Total frame count the recipe pins.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.core.n
    }

    /// True when every frame has been handed over.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Take the next frame in order. `None` once the video is exhausted.
    ///
    /// Not [`Iterator`] on purpose: a stream is *opened* fallibly (the body pin
    /// is checked first), which [`Iterator`] has no shape for.
    ///
    /// # Errors
    ///
    /// Any A4 failure on that frame.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, VideoRecipeError> {
        if self.next_seq >= self.core.n {
            return Ok(None);
        }
        let frame = self.frame_at(self.next_seq)?;
        self.next_seq += 1;
        Ok(Some(frame))
    }
}

/// BDLV magic, re-exported so callers can recognise a produced video.
pub const RECIPE_VIDEO_MAGIC: [u8; 4] = VIDEO_MAGIC;

/// What class a recipe's pinned transform will classify the body as.
#[must_use]
pub fn recipe_class(recipe: &VideoRecipe) -> ContentClass {
    recipe.transform.force_class.unwrap_or_else(|| {
        ContentClass::classify(&recipe.content_bytes, recipe.transform.as_opts().mime_hint)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_video::DEFAULT_FPS;
    use crate::storage::three_pipe::decode_qr_video;
    use std::time::Instant;

    fn incompressible(len: usize) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut out = Vec::with_capacity(len);
        let mut i: u64 = 0;
        while out.len() < len {
            let mut h = Sha256::new();
            h.update(b"video-recipe-seed");
            h.update(i.to_le_bytes());
            out.extend_from_slice(&h.finalize());
            i += 1;
        }
        out.truncate(len);
        out
    }

    fn upload(content: &[u8]) -> (VideoRecipe, EncodedQrVideo) {
        let t = RecipeTransform::pin_from(TransformOpts::default(), content);
        let encoded = encode_qr_video_internal(content, t, 1, 200, 50, DEFAULT_FPS).unwrap();
        let recipe = VideoRecipe::from_encoded(content, t, 1, 200, 50, DEFAULT_FPS, &encoded);
        (recipe, encoded)
    }

    /// The whole claim: the stored recipe plus the stored body rebuild the
    /// video byte for byte, and that video yields the content back.
    #[test]
    fn recipe_reproduces_the_video_bit_equal() {
        let content = incompressible(20_000);
        let (recipe, encoded) = upload(&content);

        let again = recipe.reemit(&content).unwrap();
        assert_eq!(
            again.video_blob, encoded.video_blob,
            "re-emitted video must be byte-identical"
        );
        assert_eq!(
            QrVideo::blob_commitment(&again.video_blob),
            recipe.video_commitment
        );

        let (kind, raw, _video) = decode_qr_video(&again.video_blob).unwrap();
        assert_eq!(kind.tag(), recipe.payload_kind);
        assert_eq!(raw, content.as_slice(), "video must yield the content");
    }

    /// A recipe is pinned to its body. Feeding it anything else must fail
    /// closed rather than quietly produce a different video.
    #[test]
    fn wrong_body_is_refused() {
        let content = incompressible(8_000);
        let (recipe, _encoded) = upload(&content);

        let mut wrong = content.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 0xff;
        assert!(matches!(
            recipe.reemit(&wrong),
            Err(VideoRecipeError::BodyMismatch)
        ));
    }

    /// The sealed form is what goes on chain: it carries no body, so it cannot
    /// produce, and it refuses a full recipe that does not match.
    #[test]
    fn sealed_form_carries_no_body_and_refuses_a_stranger() {
        let content = incompressible(4_000);
        let (recipe, _encoded) = upload(&content);
        let sealed = recipe.seal();

        assert!(sealed.content_len > 0);
        assert_eq!(sealed.video_commitment, recipe.video_commitment);

        let other_content = incompressible(4_001);
        let (other_recipe, _other_encoded) = upload(&other_content);
        assert!(matches!(
            sealed.open_with(&other_recipe),
            Err(VideoRecipeError::SealedMismatch)
        ));

        sealed.open_with(&recipe).unwrap();
        let again = sealed.reemit_with(&recipe, &content).unwrap();
        assert_eq!(
            QrVideo::blob_commitment(&again.video_blob),
            sealed.video_commitment
        );
    }

    /// The first frame is what a phone shows first, so its cost must be one
    /// frame, not `n` videos. Frames must be handed over *progressively*: one at a time, in order,
    /// and - this is the point of the whole shape - **without re-encoding the
    /// whole video for each frame**. The first frame is what a phone shows
    /// first, so its cost must be one frame, not `n` videos.
    #[test]
    fn first_frame_costs_one_frame_not_the_whole_video() {
        let content = incompressible(9_000);
        let (recipe, _video) = upload(&content);

        let t0 = Instant::now();
        let _first = recipe.frame_at(&content, 0).unwrap();
        let one_frame = t0.elapsed();

        let t1 = Instant::now();
        let full = recipe.reemit(&content).unwrap();
        let whole_video = t1.elapsed();

        // One frame cannot cost as much as the entire video. If it does, the
        // implementation is re-encoding per frame and the progressive promise
        // is fiction on any real content size.
        assert!(
            one_frame < whole_video,
            "first frame took {one_frame:?} but the whole video took {whole_video:?}"
        );
        assert!(
            whole_video.as_nanos() > 3 * one_frame.as_nanos(),
            "first frame is not clearly cheaper: frame {one_frame:?}, video {whole_video:?}"
        );
        assert!(!full.video.png_frames.is_empty());
    }

    /// The incremental cursor must be *the* video: byte for byte, same order,
    /// same count. Any drift means the on-chain recipe and the streamed frames
    /// describe two different videos, which breaks the whole claim.
    #[test]
    fn frame_stream_is_bit_equal_to_reemit() {
        let content = incompressible(3_000);
        let (recipe, _video) = upload(&content);
        let full = recipe.reemit(&content).unwrap();

        let mut stream = recipe.frame_stream(&content).unwrap();
        for expected in &full.video.png_frames {
            let got = stream
                .next_frame()
                .expect("frame must be produced")
                .expect("stream ran short");
            assert_eq!(&got, expected, "frame drift against reemit");
        }
        assert!(
            stream
                .next_frame()
                .expect("exhaust must not fail")
                .is_none(),
            "stream must stop after {}",
            full.video.png_frames.len()
        );
    }

    /// A stream opened on a body that is not the pinned one must refuse at
    /// open time, exactly like `reemit`, and must not yield a single frame.
    #[test]
    fn frame_stream_refuses_a_wrong_body_at_open() {
        let content = incompressible(2_000);
        let (recipe, _video) = upload(&content);
        let mut wrong = content.clone();
        wrong[0] ^= 0xff;

        let err = recipe.frame_stream(&wrong).unwrap_err();
        assert!(matches!(err, VideoRecipeError::BodyMismatch));
    }

    #[test]
    fn frames_are_produced_one_at_a_time_in_order() {
        let content = incompressible(6_000);
        let (recipe, encoded) = upload(&content);
        assert!(
            recipe.frame_count > 3,
            "need several frames, got {}",
            recipe.frame_count
        );

        let mut assembled: Vec<Vec<u8>> = Vec::new();
        for seq in 0..recipe.frame_count {
            let frame = recipe.frame_at(&content, seq).unwrap();
            assert!(
                frame.starts_with(&[0x89, b'P', b'N', b'G']),
                "frame is a PNG"
            );
            assembled.push(frame);
        }
        assert_eq!(assembled, encoded.video.png_frames);
        assert!(matches!(
            recipe.frame_at(&content, recipe.frame_count),
            Err(VideoRecipeError::Video(QrVideoError::TooMany(_)))
        ));
    }

    /// The produced video must actually carry what the recipe pins. Comparing
    /// re-emit against a first encode cannot catch this: if the production path
    /// drifts, both sides drift together. So read the BDLV header back.
    #[test]
    fn produced_video_carries_the_pinned_header() {
        let content = incompressible(5_000);
        let (recipe, encoded) = upload(&content);
        let blob = &encoded.video_blob;

        assert_eq!(blob.get(0..4), Some(RECIPE_VIDEO_MAGIC.as_slice()));
        assert_eq!(blob.get(4).copied(), Some(1u8), "container version");

        let fps = u16::from_le_bytes([blob[6], blob[7]]);
        assert_eq!(fps, recipe.fps, "recipe fps must reach the video header");

        let frames = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]);
        assert_eq!(frames, recipe.frame_count, "recipe frame count must match");

        // A non-default fps must survive the round trip too, otherwise the pin
        // is decorative.
        let t = RecipeTransform::pin_from(TransformOpts::default(), &content);
        let other_fps = DEFAULT_FPS + 7;
        let encoded2 = encode_qr_video_internal(&content, t, 1, 200, 50, other_fps).unwrap();
        let recipe2 = VideoRecipe::from_encoded(&content, t, 1, 200, 50, other_fps, &encoded2);
        let again = recipe2.reemit(&content).unwrap();
        let fps2 = u16::from_le_bytes([again.video_blob[6], again.video_blob[7]]);
        assert_eq!(fps2, other_fps);
        assert_eq!(again.video_blob, encoded2.video_blob);
    }

    /// The recipe commitment must move when anything the production depends on
    /// moves, and stay put across two identical writes.
    #[test]
    fn recipe_commitment_tracks_every_production_knob() {
        let content = incompressible(3_000);
        let (recipe, _encoded) = upload(&content);
        let (recipe2, _encoded2) = upload(&content);
        assert_eq!(recipe.commitment(), recipe2.commitment());

        let mut moved = recipe.clone();
        moved.fps = recipe.fps + 1;
        assert_ne!(recipe.commitment(), moved.commitment());

        let mut moved = recipe.clone();
        moved.repair_permillage = recipe.repair_permillage + 1;
        assert_ne!(recipe.commitment(), moved.commitment());

        let mut moved = recipe.clone();
        moved.block_len = recipe.block_len + 1;
        assert_ne!(recipe.commitment(), moved.commitment());

        let mut moved = recipe.clone();
        moved.payload_kind = recipe.payload_kind + 1;
        assert_ne!(recipe.commitment(), moved.commitment());
    }
}
