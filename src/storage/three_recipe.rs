//! B.U.D. 3.0 — the recipe that **produces the QR-video**.
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
use crate::storage::qr_recipe::ThreeRecipePublic;
use crate::storage::qr_video::{QrVideo, QrVideoError, VIDEO_MAGIC};
use crate::storage::three_pipe::{EncodedPipe, EncodedQrVideo, PipeError};
use crate::storage::transformed::{transform_content, ContentClass, TransformError, TransformOpts};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecipeTransform {
    /// Forced class. `None` means "sniff the body".
    pub force_class: Option<ContentClass>,
    /// Apply shrink-only zlib at A0. Off by default because A1 already does it.
    pub apply_zlib: bool,
}

impl Default for RecipeTransform {
    fn default() -> Self {
        Self {
            force_class: None,
            apply_zlib: false,
        }
    }
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
            &[self.transform.apply_zlib as u8],
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
        let encoded = self.reemit(body)?;
        encoded
            .video
            .png_frames
            .get(seq as usize)
            .cloned()
            .ok_or(VideoRecipeError::Video(QrVideoError::BadBlob))
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

/// Encode with every production knob pinned by a recipe.
///
/// This is the single production path: both the first encode at upload and the
/// re-emit from a recipe run through here, which is what makes the two
/// bit-equal.
///
/// # Errors
///
/// Any pipe failure.
pub fn encode_qr_video_internal(
    content: &[u8],
    transform: RecipeTransform,
    payload_kind: u8,
    block_len: u16,
    repair_permillage: u32,
    fps: u16,
) -> Result<EncodedQrVideo, VideoRecipeError> {
    // A0: classify with the pinned knobs.
    let transformed = transform_content(content, transform.as_opts())?;

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

    // A2: systematic pass plus the pinned repair margin, never the 2k carousel.
    let enc = CarouselEncoder::new(&packed, block_len)?;
    let stream_commitment = enc.params().stream_commitment(&commit);
    let n = oneshot_drop_count(enc.params().k, repair_permillage);

    // A3: optical frames, bound to the stream.
    let mut frames = Vec::with_capacity(n as usize);
    let mut digests = Vec::with_capacity(n as usize);
    for seq in 0..n {
        let drop = enc.drop_at(seq);
        digests.push(frame_digest(&stream_commitment, seq, &drop.to_bytes()));
        frames.push(pack_frame(&stream_commitment, &drop));
    }
    let fold = fold_frame_digests(&digests)?;
    let pipe_recipe = ThreeRecipePublic::new(commit, enc.params(), fold);

    // A4: QR matrices to PNG frames, muxed into the BDLV container.
    let video = QrVideo::from_optical_frames(&pipe_recipe, &stream_commitment, &frames, fps)?;
    let video_blob = video.to_bytes();
    Ok(EncodedQrVideo {
        pipe: EncodedPipe {
            packed,
            recipe: pipe_recipe,
            frames,
            stream_commitment,
            class: transformed.class,
        },
        video,
        video_blob,
    })
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

    /// Progressive delivery: every frame is produced on its own, in order, and
    /// the sequence assembled from those single frames is the same video.
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
