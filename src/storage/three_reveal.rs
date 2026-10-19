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
#[derive(Debug, Clone)]
pub struct RevealSession {
    emitter: RecipeEmitter,
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
                s.open_with(full).map_err(|_| RevealError::NeedFullRecipe)?;
                full.clone()
            }
        };
        let public_k = public.carousel.k;
        let emitter = RecipeEmitter::open(public, packed)?;
        // The pinned stream id is the fold of the whole one-shot pass. Build
        // that pass once, keep only its fold, and refuse a recipe that pins
        // another stream. A session that serves a range later is a subset of
        // this pass, so the check cannot be done on the requested range.
        let pass = oneshot_drop_count(public_k, ONESHOT_REPAIR_PERMILLAGE);
        let (_, pass_fold) = emitter.emit_frames(0, pass)?;
        emitter.verify_stream_id(&pass_fold)?;
        Ok(Self { emitter })
    }

    /// Optical frame at `seq` (ephemeral).
    ///
    /// # Errors
    ///
    /// A drop that does not fit one frame.
    pub fn frame_at(&self, seq: u32) -> Result<Vec<u8>, RevealError> {
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
    fn forged_stream_pin_refused_at_open() {
        let (mut full, packed) = sample();
        full.stream_id = [7u8; 32];
        let recipe = ThreeRecipe::Public(full);
        assert_eq!(
            RevealSession::open(&recipe, None, &packed, false).unwrap_err(),
            RevealError::Reemit(ReemitError::StreamMismatch)
        );
    }

    #[test]
    fn forged_stream_pin_refused_when_sealed_and_granted() {
        let (mut full, packed) = sample();
        full.stream_id = [7u8; 32];
        let recipe = ThreeRecipe::Sealed(full.seal());
        assert_eq!(
            RevealSession::open(&recipe, Some(&full), &packed, true).unwrap_err(),
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
        assert!(RevealSession::open(&recipe, None, &packed, false).is_ok());
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
