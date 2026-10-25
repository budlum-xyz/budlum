//! G3 - reveal session (plan §CH G3).
//!
//! After `may_view` / `may_open_three_recipe` succeeds, a short-lived session
//! may re-emit frames **in memory**. Nothing is written to durable storage.
//!
//! # Honesty
//!
//! - Revoke stops **new** sessions; already-emitted frames on a device are not
//!   clawed back (T3).
//! - This module does not talk to RPC; the gateway must call `may_view` first.

use crate::storage::qr_carousel::{oneshot_drop_count, ONESHOT_REPAIR_PERMILLAGE};
use crate::storage::qr_recipe::{may_open_three_recipe, ThreeRecipe, ThreeRecipePublic};
use crate::storage::qr_reemit::{RecipeEmitter, ReemitError};

/// Errors opening a reveal session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealError {
    /// Grant / public check failed.
    Forbidden,
    /// Sealed recipe presented without the full public opening.
    NeedFullRecipe,
    /// The opening was sent but it does not open this sealed recipe.
    WrongOpening,
    /// Nested re-emit error.
    Reemit(ReemitError),
}

impl std::fmt::Display for RevealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden => write!(f, "three reveal forbidden without grant"),
            Self::NeedFullRecipe => {
                write!(f, "three reveal needs full public recipe to open sealed")
            }
            Self::WrongOpening => {
                write!(f, "three reveal opening does not open the sealed recipe")
            }
            Self::Reemit(e) => write!(f, "three reveal reemit: {e}"),
        }
    }
}

impl std::error::Error for RevealError {}

impl From<ReemitError> for RevealError {
    fn from(e: ReemitError) -> Self {
        Self::Reemit(e)
    }
}

/// In-memory reveal session: emitter bound to packed body.
///
/// The frame-fold pin is verified on the first frame the session actually
/// serves, not when it opens. Opening used to run the whole one-shot pass just
/// to keep its fold, which made one cheap request buy a full carousel encode -
/// and a caller that never asked for a frame still paid for one (CWE-407). The
/// check is not weakened by moving it: `frame_at` and `frames_with_fold` are
/// the only ways out of a session, and both go through `verify_stream_pin`.
#[derive(Debug)]
pub struct RevealSession {
    emitter: RecipeEmitter,
    /// Carousel width the one-shot pass is built from.
    k: u16,
    /// Whether the pin has already been checked for this session.
    verified: std::sync::atomic::AtomicBool,
}

impl Clone for RevealSession {
    /// `AtomicBool` is not `Clone`; a clone inherits the verification result
    /// rather than repeating the pass.
    fn clone(&self) -> Self {
        Self {
            emitter: self.emitter.clone(),
            k: self.k,
            verified: std::sync::atomic::AtomicBool::new(
                self.verified.load(std::sync::atomic::Ordering::Acquire),
            ),
        }
    }
}

impl RevealSession {
    /// Open a session.
    ///
    /// * `recipe` - public or sealed form.
    /// * `full` - required when recipe is sealed (the opening).
    /// * `packed` - A1 bytes whose commitment the public recipe pins.
    /// * `grant_allows` - result of the caller's `may_view` check.
    ///
    /// # Errors
    ///
    /// Forbidden without grant on sealed; missing full recipe; re-emit open fail.
    pub fn open(
        recipe: &ThreeRecipe,
        full: Option<&ThreeRecipePublic>,
        packed: &[u8],
        grant_allows: bool,
    ) -> Result<Self, RevealError> {
        if !may_open_three_recipe(recipe, grant_allows) {
            return Err(RevealError::Forbidden);
        }
        let public = match recipe {
            ThreeRecipe::Public(p) => p.clone(),
            ThreeRecipe::Sealed(s) => {
                let full = full.ok_or(RevealError::NeedFullRecipe)?;
                s.open_with(full).map_err(|_| RevealError::WrongOpening)?;
                full.clone()
            }
        };
        let public_k = public.carousel.k;
        let emitter = RecipeEmitter::open(public, packed)?;
        Ok(Self {
            emitter,
            k: public_k,
            verified: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Check the recipe's pinned stream id against the fold of the whole
    /// one-shot pass, once per session.
    ///
    /// The pin covers the complete pass, so it cannot be checked on a subset:
    /// a range a client later asks for is a slice of this pass. Building the
    /// pass is the expensive step, which is why it happens here and not in
    /// [`Self::open`].
    fn verify_stream_pin(&self) -> Result<(), RevealError> {
        use std::sync::atomic::Ordering;
        if self.verified.load(Ordering::Acquire) {
            return Ok(());
        }
        let pass = oneshot_drop_count(self.k, ONESHOT_REPAIR_PERMILLAGE);
        let (_, pass_fold) = self.emitter.emit_frames(0, pass)?;
        self.emitter.verify_stream_id(&pass_fold)?;
        self.verified.store(true, Ordering::Release);
        Ok(())
    }

    /// Optical frame at `seq` (ephemeral).
    ///
    /// # Errors
    ///
    /// A drop that does not fit one frame.
    pub fn frame_at(&self, seq: u32) -> Result<Vec<u8>, RevealError> {
        self.verify_stream_pin()?;
        Ok(self.emitter.frame_at(seq)?)
    }

    /// Frames `seq_start..seq_start + count` with the fold a client checks them
    /// against, under the gate this session already applied.
    ///
    /// A read path that wants a range asks for it here instead of opening an
    /// emitter beside the session, which is how a range used to bypass the
    /// sealed-recipe and grant rules the session exists to enforce.
    ///
    /// # Errors
    ///
    /// The emitter's own range failures, wrapped as [`RevealError::Reemit`].
    pub fn frames_with_fold(
        &self,
        seq_start: u32,
        count: u32,
    ) -> Result<(Vec<Vec<u8>>, [u8; 32]), RevealError> {
        self.verify_stream_pin()?;
        Ok(self.emitter.emit_frames(seq_start, count)?)
    }

    /// Stream commitment for receivers.
    #[must_use]
    pub const fn stream_commitment(&self) -> [u8; 32] {
        self.emitter.stream_commitment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_carousel::CarouselEncoder;
    use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadKind};
    use crate::storage::qr_recipe::ThreeRecipePublic;

    fn sample() -> (ThreeRecipePublic, Vec<u8>) {
        let packed = pack_payload(PayloadKind::ContentBytes, b"reveal-body").unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 32).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        (ThreeRecipePublic::new(commit, enc.params(), stream), packed)
    }

    #[test]
    fn public_opens_without_grant() {
        let (full, packed) = sample();
        let recipe = ThreeRecipe::Public(full.clone());
        let s = RevealSession::open(&recipe, None, &packed, false).unwrap();
        assert!(!s.frame_at(0).unwrap().is_empty());
    }

    #[test]
    fn sealed_forbidden_without_grant() {
        let (full, packed) = sample();
        let recipe = ThreeRecipe::Sealed(full.seal());
        assert_eq!(
            RevealSession::open(&recipe, Some(&full), &packed, false).unwrap_err(),
            RevealError::Forbidden
        );
    }

    #[test]
    fn a_wrong_opening_is_told_apart_from_a_missing_one() {
        let (full, packed) = sample();
        let recipe = ThreeRecipe::Sealed(full.seal());
        assert_eq!(
            RevealSession::open(&recipe, None, &packed, true).unwrap_err(),
            RevealError::NeedFullRecipe
        );
        let mut other = full;
        other.stream_id = [9u8; 32];
        assert_eq!(
            RevealSession::open(&recipe, Some(&other), &packed, true).unwrap_err(),
            RevealError::WrongOpening
        );
    }

    #[test]
    fn forged_stream_pin_refused_at_open() {
        let (mut full, packed) = sample();
        full.stream_id = [7u8; 32];
        let recipe = ThreeRecipe::Public(full);
        // The pin is checked on the first served frame, not on `open`: opening
        // a session must not cost a full carousel pass by itself.
        let s = RevealSession::open(&recipe, None, &packed, false).unwrap();
        assert_eq!(
            s.frame_at(0).unwrap_err(),
            RevealError::Reemit(ReemitError::StreamMismatch)
        );
        // A refused check does not mark the session verified either.
        assert_eq!(
            s.frames_with_fold(0, 1).unwrap_err(),
            RevealError::Reemit(ReemitError::StreamMismatch)
        );
    }

    #[test]
    fn forged_stream_pin_refused_when_sealed_and_granted() {
        let (mut full, packed) = sample();
        full.stream_id = [7u8; 32];
        let recipe = ThreeRecipe::Sealed(full.seal());
        let s = RevealSession::open(&recipe, Some(&full), &packed, true).unwrap();
        assert_eq!(
            s.frame_at(0).unwrap_err(),
            RevealError::Reemit(ReemitError::StreamMismatch)
        );
    }

    #[test]
    fn pass_fold_pin_opens() {
        let (mut full, packed) = sample();
        let emitter = RecipeEmitter::open(full.clone(), &packed).unwrap();
        let n = oneshot_drop_count(full.carousel.k, ONESHOT_REPAIR_PERMILLAGE);
        let (_, fold) = emitter.emit_frames(0, n).unwrap();
        full.stream_id = fold;
        let recipe = ThreeRecipe::Public(full);
        let s = RevealSession::open(&recipe, None, &packed, false).unwrap();
        // The honest pin is accepted where it is checked: on the first frame.
        assert!(!s.frame_at(0).unwrap().is_empty());
    }

    #[test]
    fn sealed_opens_with_grant() {
        let (full, packed) = sample();
        let recipe = ThreeRecipe::Sealed(full.seal());
        let s = RevealSession::open(&recipe, Some(&full), &packed, true).unwrap();
        assert_eq!(
            s.stream_commitment(),
            full.carousel.stream_commitment(&full.payload_commitment)
        );
    }
}
