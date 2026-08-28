//! B.U.D. 3.0 recipe → stream re-emit (plan §CH A6, K-QR-GERIDONUS).
//!
//! WIRING: unwired - `verify_stream_id` is called only by this module's test;
//! the production caller is the reveal session's emit path (plan §A9), which
//! is not wired yet, so the pin currently guards the tests.
//!
//! Given a [`ThreeRecipePublic`] and the packed A1 bytes whose commitment the
//! recipe pins, regenerate carousel drops and optical frames **bit-equal** to
//! the original encode. Sealed recipes must be opened first (holder of the
//! full public recipe + body).
//!
//! # What this module does not claim
//!
//! - Video mux (A4) — frames are optical payloads, not a container file.
//! - Progressive decode UX (A7) — that is the receiver side.
//! - Catalogue avatar re-render (`render.rs`) — different address space.

use crate::storage::qr_carousel::{CarouselEncoder, CarouselError, Drop};
use crate::storage::qr_frame::{fold_frame_digests, frame_digest, pack_frame, FrameError};
use crate::storage::qr_payload::{payload_commitment, PayloadError};
use crate::storage::qr_recipe::{three_recipe_digest, ThreeRecipePublic};

/// Errors re-emitting a stream from a recipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReemitError {
    /// Packed bytes do not match the recipe's payload commitment.
    PayloadCommitmentMismatch,
    /// Carousel params derived from the body disagree with the recipe.
    CarouselMismatch,
    /// Recomputed stream id (frame fold or param commitment) disagrees.
    StreamMismatch,
    /// Nested carousel error.
    Carousel(CarouselError),
    /// Nested frame error.
    Frame(FrameError),
    /// Nested payload error (if caller asked us to pack — not used on re-emit path).
    Payload(PayloadError),
}

impl std::fmt::Display for ReemitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadCommitmentMismatch => {
                write!(f, "re-emit payload commitment mismatch")
            }
            Self::CarouselMismatch => write!(f, "re-emit carousel params mismatch"),
            Self::StreamMismatch => write!(f, "re-emit stream id mismatch"),
            Self::Carousel(e) => write!(f, "re-emit carousel: {e}"),
            Self::Frame(e) => write!(f, "re-emit frame: {e}"),
            Self::Payload(e) => write!(f, "re-emit payload: {e}"),
        }
    }
}

impl std::error::Error for ReemitError {}

impl From<CarouselError> for ReemitError {
    fn from(e: CarouselError) -> Self {
        Self::Carousel(e)
    }
}

impl From<FrameError> for ReemitError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

/// Verified encoder bound to a public recipe and its packed body.
#[derive(Debug, Clone)]
pub struct RecipeEmitter {
    recipe: ThreeRecipePublic,
    encoder: CarouselEncoder,
    /// Stream commitment used in A3 frame binding (params ‖ payload commit).
    stream_commitment: [u8; 32],
}

impl RecipeEmitter {
    /// Open a public recipe against packed A1 bytes.
    ///
    /// Verifies payload commitment and carousel parameter equality. The
    /// recipe's `stream_id` may be either:
    /// - the A2 `stream_commitment` (params bound only), or
    /// - a folded frame-digest id from a prior A3 pass.
    ///
    /// On open we recompute the A2 stream commitment and require the recipe's
    /// carousel/payload fields to match; `stream_id` is checked only when the
    /// caller asks [`Self::verify_frame_fold`] after emitting frames.
    ///
    /// # Errors
    ///
    /// Commitment or param mismatch; carousel build failure.
    pub fn open(recipe: ThreeRecipePublic, packed: &[u8]) -> Result<Self, ReemitError> {
        let got = payload_commitment(packed);
        if got != recipe.payload_commitment {
            return Err(ReemitError::PayloadCommitmentMismatch);
        }
        let encoder = CarouselEncoder::new(packed, recipe.block_len)?;
        if encoder.params() != recipe.carousel {
            return Err(ReemitError::CarouselMismatch);
        }
        if recipe.block_len != recipe.carousel.block_len {
            return Err(ReemitError::CarouselMismatch);
        }
        let stream_commitment = encoder
            .params()
            .stream_commitment(&recipe.payload_commitment);
        Ok(Self {
            recipe,
            encoder,
            stream_commitment,
        })
    }

    /// Recipe digest (stable pin).
    #[must_use]
    pub fn recipe_digest(&self) -> [u8; 32] {
        three_recipe_digest(&self.recipe)
    }

    /// A2 stream commitment used to bind frames.
    #[must_use]
    pub const fn stream_commitment(&self) -> [u8; 32] {
        self.stream_commitment
    }

    /// Drop at absolute `seq` (bit-equal to the original encoder).
    #[must_use]
    pub fn drop_at(&self, seq: u32) -> Drop {
        self.encoder.drop_at(seq)
    }

    /// Optical frame at `seq`.
    #[must_use]
    pub fn frame_at(&self, seq: u32) -> Vec<u8> {
        pack_frame(&self.stream_commitment, &self.drop_at(seq))
    }

    /// Emit `count` frames starting at `seq_start`; return frames and fold id.
    ///
    /// # Errors
    ///
    /// Frame fold refuses an empty set (`count == 0`).
    pub fn emit_frames(
        &self,
        seq_start: u32,
        count: u32,
    ) -> Result<(Vec<Vec<u8>>, [u8; 32]), ReemitError> {
        if count == 0 {
            return Err(ReemitError::Frame(FrameError::Truncated));
        }
        let mut frames = Vec::with_capacity(count as usize);
        let mut digests = Vec::with_capacity(count as usize);
        for i in 0..count {
            let seq = seq_start.wrapping_add(i);
            let drop = self.drop_at(seq);
            let frame = pack_frame(&self.stream_commitment, &drop);
            digests.push(frame_digest(&self.stream_commitment, seq, &drop.to_bytes()));
            frames.push(frame);
        }
        let fold = fold_frame_digests(&digests)?;
        Ok((frames, fold))
    }

    /// If the recipe pinned a frame-fold stream id, check it equals a fresh fold.
    ///
    /// # Errors
    ///
    /// [`ReemitError::StreamMismatch`] when the recipe's `stream_id` is non-zero
    /// and disagrees with both the A2 commitment and the provided fold.
    pub fn verify_stream_id(&self, frame_fold: &[u8; 32]) -> Result<(), ReemitError> {
        let pinned = self.recipe.stream_id;
        if pinned == [0u8; 32] {
            return Ok(());
        }
        if pinned == self.stream_commitment || pinned == *frame_fold {
            return Ok(());
        }
        Err(ReemitError::StreamMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::payload_crypt::{derived_nonce, open_payload, seal_payload, PayloadKey};
    use crate::storage::qr_carousel::{planned_drop_count, CarouselDecoder, DEFAULT_BLOCK_LEN};
    use crate::storage::qr_frame::unpack_frame;
    use crate::storage::qr_payload::{pack_payload, unpack_payload, PayloadKind};
    use crate::storage::qr_recipe::ThreeRecipePublic;

    fn packed_plain(content: &[u8]) -> Vec<u8> {
        pack_payload(PayloadKind::ContentBytes, content).unwrap()
    }

    #[test]
    fn reemit_drops_bit_equal() {
        let packed = packed_plain(b"reemit-bit-equal-content-bytes!!");
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, DEFAULT_BLOCK_LEN).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let recipe = ThreeRecipePublic::new(commit, enc.params(), stream);
        let emitter = RecipeEmitter::open(recipe, &packed).unwrap();
        for seq in 0..20 {
            assert_eq!(emitter.drop_at(seq), enc.drop_at(seq));
            assert_eq!(
                emitter.frame_at(seq),
                pack_frame(&stream, &enc.drop_at(seq))
            );
        }
    }

    #[test]
    fn wrong_body_refused() {
        let packed = packed_plain(b"body-a");
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 32).unwrap();
        let recipe = ThreeRecipePublic::new(
            commit,
            enc.params(),
            enc.params().stream_commitment(&commit),
        );
        let other = packed_plain(b"body-b");
        assert_eq!(
            RecipeEmitter::open(recipe, &other).unwrap_err(),
            ReemitError::PayloadCommitmentMismatch
        );
    }

    #[test]
    fn reemit_through_decode_recovers() {
        let content = b"a6-reemit-full-pipe-content".repeat(12);
        let packed = packed_plain(&content);
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, DEFAULT_BLOCK_LEN).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let recipe = ThreeRecipePublic::new(commit, enc.params(), stream);
        let emitter = RecipeEmitter::open(recipe, &packed).unwrap();
        let n = planned_drop_count(enc.params().k, 0);
        let (frames, fold) = emitter.emit_frames(0, n.min(500)).unwrap();
        emitter.verify_stream_id(&fold).unwrap();
        let mut dec = CarouselDecoder::new();
        for frame in &frames {
            let drop = unpack_frame(&stream, frame).unwrap();
            dec.push(&drop).unwrap();
            if dec.is_complete() {
                break;
            }
        }
        assert!(dec.is_complete());
        let (kind, raw) = unpack_payload(&dec.finish().unwrap()).unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(raw, content.as_slice());
    }

    #[test]
    fn sealed_content_reemit() {
        let key = PayloadKey::derive(b"a6-secret");
        let pt = b"private body for reemit";
        let sealed = seal_payload(&key, &derived_nonce(b"a6"), pt).unwrap();
        let packed = pack_payload(PayloadKind::EncryptedContent, &sealed).unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 40).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let recipe = ThreeRecipePublic::new(commit, enc.params(), stream);
        let emitter = RecipeEmitter::open(recipe, &packed).unwrap();
        let mut dec = CarouselDecoder::new();
        for seq in 0..u32::from(enc.params().k) * 2 {
            dec.push(&emitter.drop_at(seq)).unwrap();
            if dec.is_complete() {
                break;
            }
        }
        let body = dec.finish().unwrap();
        let (kind, sealed_got) = unpack_payload(&body).unwrap();
        assert_eq!(kind, PayloadKind::EncryptedContent);
        assert_eq!(open_payload(&key, &sealed_got).unwrap(), pt);
    }
}
