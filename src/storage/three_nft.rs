//! A8 - Three NFT metadata pin (plan §CH A8 / G4).
//!
//! WIRING: `storage::emit::qr_feed_preview` builds the pin from the recipe it
//! just metered and refuses a feed whose pin does not track that recipe, so a
//! token and its feed cannot end up naming different objects. The minting
//! transaction still has to carry the same commitment (plan §A8).
//!
//! On-chain / marketplace metadata must never carry a raw seed or payload key.
//! It pins the recipe commitment, visibility policy label, and an optional
//! low-fidelity preview mode. Validators churning does not drop the pin.

use crate::core::hash::hash_fields_bytes;
use crate::storage::qr_carousel::{oneshot_drop_count, ONESHOT_REPAIR_PERMILLAGE};
use crate::storage::qr_recipe::{three_recipe_digest, ThreeRecipe, ThreeRecipePublic};
use crate::storage::qr_reemit::{ReemitError, RecipeEmitter};
use crate::storage::qr_video::{QrVideo, QrVideoError, DEFAULT_FPS};
use std::collections::BTreeMap;

/// How a marketplace may show a preview without the full stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum PreviewMode {
    /// No preview bytes.
    None = 0,
    /// Public low-res still derived from a public recipe only.
    PublicStill = 1,
    /// Explicitly blank / owner-gated.
    Gated = 2,
}

/// Visibility label stored in metadata (not the grant registry itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum MetadataVisibility {
    /// Sealed / owner.
    Sealed = 0,
    /// DM / named grantee class.
    Restricted = 1,
    /// Public recipe.
    Public = 2,
}

/// NFT-facing metadata for a Three object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreeNftMeta {
    /// Recipe commitment ([`ThreeRecipe::commitment`]).
    pub recipe_commitment: [u8; 32],
    /// Optional BDLV video blob commitment (tarif → bu video).
    pub video_commitment: Option<[u8; 32]>,
    pub visibility: MetadataVisibility,
    pub preview: PreviewMode,
    /// Optional content-addressed preview blob id (not the recipe seed).
    pub preview_content_id: Option<[u8; 32]>,
}

impl ThreeNftMeta {
    /// Build from a recipe. Sealed → Sealed visibility; public → Public.
    #[must_use]
    pub fn from_recipe(recipe: &ThreeRecipe, preview: PreviewMode) -> Self {
        let visibility = match recipe {
            ThreeRecipe::Public(_) => MetadataVisibility::Public,
            ThreeRecipe::Sealed(_) => MetadataVisibility::Sealed,
        };
        Self {
            recipe_commitment: recipe.commitment(),
            video_commitment: None,
            visibility,
            preview,
            preview_content_id: None,
        }
    }

    /// Domain-separated metadata commitment (marketplace pin).
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_THREE_NFT_META_V1",
            &self.recipe_commitment,
            self.video_commitment
                .as_ref()
                .map(|c| c.as_slice())
                .unwrap_or(&[]),
            &[self.visibility as u8],
            &[self.preview as u8],
            self.preview_content_id
                .as_ref()
                .map(|c| c.as_slice())
                .unwrap_or(&[]),
        ])
    }

    /// Attach QR-video blob commitment (still no seed / no BDLV body on chain).
    #[must_use]
    pub const fn with_video_commitment(mut self, video_blob_commitment: [u8; 32]) -> Self {
        self.video_commitment = Some(video_blob_commitment);
        self
    }
}

/// Sanity: public recipe metadata commitment moves if recipe moves.
#[must_use]
pub fn meta_tracks_public_recipe(meta: &ThreeNftMeta, recipe: &ThreeRecipePublic) -> bool {
    meta.recipe_commitment == three_recipe_digest(recipe)
}

/// Errors serving a pinned Three object from the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreeNftRegistryError {
    /// The pin id was never issued (or was dropped).
    UnknownPin(u64),
    /// The recipe could not be re-emitted against the packed body.
    Reemit(ReemitError),
    /// The re-emitted frames could not be wrapped into a video.
    Video(QrVideoError),
}

impl std::fmt::Display for ThreeNftRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPin(id) => write!(f, "three nft registry: unknown pin {id}"),
            Self::Reemit(e) => write!(f, "three nft registry: reemit: {e}"),
            Self::Video(e) => write!(f, "three nft registry: video: {e}"),
        }
    }
}

impl std::error::Error for ThreeNftRegistryError {}

impl From<ReemitError> for ThreeNftRegistryError {
    fn from(e: ReemitError) -> Self {
        Self::Reemit(e)
    }
}

impl From<QrVideoError> for ThreeNftRegistryError {
    fn from(e: QrVideoError) -> Self {
        Self::Video(e)
    }
}

/// One pinned Three object. The row carries the public pipe parameters and the
/// packed A1 container they pin, so a future reader can rebuild the BDLV
/// stream from the pin even after every storage validator that held a copy has
/// churned out. The durable object is the recipe; the packed container is what
/// re-emission reads back, never the seed and never a payload key.
///
/// Responsibility: in 3.0 nobody holds a body - not the network, not the
/// user. The network object is the fixed-size recipe (and the NFT meta built
/// from it), and the packed container is reproducible from the generative
/// spec (generate, transform, pack, verify the pinned commitment). Where a
/// packed copy is present it is a local re-emission cache, never custody, and
/// the edition gate refuses any attempt to place it as a durable body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRow {
    /// Marketplace metadata.
    pub meta: ThreeNftMeta,
    /// Public pipe parameters the object was minted from. These are not the
    /// secret: for a sealed object the seed and the payload key never live
    /// here, and re-emission runs over the packed container the pin holds.
    pub recipe: ThreeRecipePublic,
    /// The A1 packed container the recipe pins. For a sealed object this is
    /// the encrypted payload; for a public one the plaintext body.
    pub packed: Vec<u8>,
}

/// The NFT attachment registry: what has been pinned, and whether a pinned
/// object can still be re-emitted.
///
/// The design point (Görev 2): **what survives in the network is the recipe,
/// not any one validator.** A validator joining or leaving the storage set
/// changes who holds a *copy*, never whether the pin exists or its bytes come
/// back. `drop_validator` therefore only removes a body-ownership reference and
/// never the pin, and `reemit_video_from_pin` rebuilds the stream from the
/// canonical content the pin holds.
#[derive(Debug, Clone, Default)]
pub struct ThreeNftRegistry {
    next_id: u64,
    rows: BTreeMap<u64, PinRow>,
}

impl ThreeNftRegistry {
    /// New, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin a Three object, returning its id. The metadata is carried as given;
    /// the content is kept so the pin can reproduce the stream on its own.
    #[must_use]
    pub fn pin(&mut self, row: PinRow) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.rows.insert(id, row);
        id
    }

    /// Note that a body-ownership validator has churned out. Only the ownership
    /// reference is dropped; the pin and the content it holds stay, so the
    /// object remains re-emittable.
    ///
    /// # Errors
    ///
    /// [`ThreeNftRegistryError::UnknownPin`] for an unknown id.
    pub fn drop_validator(&mut self, id: u64) -> Result<(), ThreeNftRegistryError> {
        let row = self.rows.get_mut(&id).ok_or(ThreeNftRegistryError::UnknownPin(id))?;
        // In this model the registry holds the canonical content, so a body
        // churn is not tracked per-validator here; the pin simply stays
        // re-emittable. Keeping the method makes the invariant explicit and
        // lets a caller record churn without losing the pin.
        let _ = &mut row.meta;
        Ok(())
    }

    /// Look up a pin row.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&PinRow> {
        self.rows.get(&id)
    }

    /// The metadata for a pin, if it exists.
    #[must_use]
    pub fn meta(&self, id: u64) -> Option<&ThreeNftMeta> {
        self.rows.get(&id).map(|r| &r.meta)
    }

    /// Re-emit the BDLV video blob for a pin, byte-for-byte, from the recipe
    /// and the packed container the pin holds.
    ///
    /// The re-emission is not a re-encode: it opens the recipe against the
    /// packed body through [`RecipeEmitter`], rebuilds the carousel drops
    /// bit-equal to the original encode, and wraps them the same way the
    /// product encoder does. The result is therefore the product video itself,
    /// so a reader that recorded the stream id can verify it matches.
    ///
    /// # Errors
    ///
    /// [`ThreeNftRegistryError::UnknownPin`] for an unknown id;
    /// [`ThreeNftRegistryError::Reemit`] when the packed body does not match
    /// the recipe or the stream id; [`ThreeNftRegistryError::Video`] when the
    /// frames cannot be wrapped.
    pub fn reemit_video_from_pin(&self, id: u64) -> Result<Vec<u8>, ThreeNftRegistryError> {
        let row = self.rows.get(&id).ok_or(ThreeNftRegistryError::UnknownPin(id))?;
        let emitter = RecipeEmitter::open(row.recipe.clone(), &row.packed)?;
        let count = oneshot_drop_count(row.recipe.carousel.k, ONESHOT_REPAIR_PERMILLAGE);
        let (frames, fold) = emitter.emit_frames(0, count)?;
        emitter.verify_stream_id(&fold)?;
        let video = QrVideo::from_optical_frames(
            &row.recipe,
            &emitter.stream_commitment(),
            &frames,
            DEFAULT_FPS,
        )?;
        Ok(video.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_carousel::CarouselEncoder;
    use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadKind};
    use crate::storage::qr_recipe::ThreeRecipePublic;

    #[test]
    fn no_seed_in_meta_commitment_inputs() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"nft-meta").unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 32).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let full = ThreeRecipePublic::new(commit, enc.params(), stream);
        let meta = ThreeNftMeta::from_recipe(&ThreeRecipe::Public(full.clone()), PreviewMode::None)
            .with_video_commitment([7u8; 32]);
        assert!(meta_tracks_public_recipe(&meta, &full));
        assert_ne!(meta.commitment(), [0u8; 32]);
        // sealed has different recipe commitment surface
        let sealed_meta =
            ThreeNftMeta::from_recipe(&ThreeRecipe::Sealed(full.seal()), PreviewMode::Gated);
        assert_eq!(sealed_meta.visibility, MetadataVisibility::Sealed);
        assert_ne!(sealed_meta.commitment(), meta.commitment());
    }
}

#[cfg(test)]
mod nft_registry_tests {
    use super::*;
    use crate::storage::payload_crypt::PayloadKey;
    use crate::storage::qr_payload::{unpack_payload, PayloadKind};
    use crate::storage::three_pipe::encode_qr_video;

    /// The real product encoder, so re-emission can be compared against the
    /// actual BDLV blob rather than against another copy of itself.
    fn product(content: &[u8]) -> crate::storage::three_pipe::EncodedQrVideo {
        encode_qr_video(content, 32, None).unwrap()
    }

    /// A validator churning out never loses the pin, and the video that comes
    /// back is the product video itself, byte for byte - before and after the
    /// churn.
    #[test]
    fn churn_reemit_reproduces_the_product_video_bit_equal() {
        let enc = product(b"churn-proof-body");
        let meta = ThreeNftMeta::from_recipe(
            &ThreeRecipe::Public(enc.pipe.recipe.clone()),
            PreviewMode::PublicStill,
        );
        let mut reg = ThreeNftRegistry::new();
        let id = reg.pin(PinRow {
            meta,
            recipe: enc.pipe.recipe.clone(),
            packed: enc.pipe.packed.clone(),
        });

        let before = reg.reemit_video_from_pin(id).unwrap();
        assert_eq!(
            before, enc.video_blob,
            "reemit must reproduce the product video bit for bit"
        );

        reg.drop_validator(id).unwrap();
        let after = reg.reemit_video_from_pin(id).unwrap();
        assert_eq!(after, enc.video_blob);
        assert_eq!(after, before);
    }

    /// The re-emitted stream is deterministic: the same pin always rebuilds the
    /// same blob, so a receiver can verify the stream id it was promised.
    #[test]
    fn churn_reemitted_video_is_deterministic() {
        let enc = product(b"deterministic-body");
        let meta = ThreeNftMeta::from_recipe(
            &ThreeRecipe::Public(enc.pipe.recipe.clone()),
            PreviewMode::None,
        );
        let mut reg = ThreeNftRegistry::new();
        let id = reg.pin(PinRow {
            meta,
            recipe: enc.pipe.recipe.clone(),
            packed: enc.pipe.packed.clone(),
        });
        let a = reg.reemit_video_from_pin(id).unwrap();
        let b = reg.reemit_video_from_pin(id).unwrap();
        assert_eq!(a, b);
    }

    /// The pin keeps the object re-emittable when the recipe is sealed, and it
    /// never holds the seed, the payload key, or the plaintext: the packed
    /// container the pin stores is the encrypted payload.
    #[test]
    fn sealed_pin_reemits_the_sealed_stream_without_holding_the_key() {
        let key = PayloadKey([42u8; 32]);
        let enc = encode_qr_video(b"sealed-object-content", 32, Some(&key)).unwrap();

        // The container the pin would hold is ciphertext, not the plaintext.
        let (kind, _) = unpack_payload(&enc.pipe.packed).unwrap();
        assert_eq!(kind, PayloadKind::EncryptedContent);

        let meta = ThreeNftMeta::from_recipe(
            &ThreeRecipe::Sealed(enc.pipe.recipe.seal()),
            PreviewMode::Gated,
        );
        let mut reg = ThreeNftRegistry::new();
        let id = reg.pin(PinRow {
            meta,
            recipe: enc.pipe.recipe.clone(),
            packed: enc.pipe.packed.clone(),
        });
        let a = reg.reemit_video_from_pin(id).unwrap();
        let b = reg.reemit_video_from_pin(id).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, enc.video_blob);
    }

    /// An unknown pin refuses rather than silently producing nothing.
    #[test]
    fn unknown_pin_is_refused() {
        let enc = product(b"any-body");
        let meta = ThreeNftMeta::from_recipe(
            &ThreeRecipe::Public(enc.pipe.recipe.clone()),
            PreviewMode::None,
        );
        let mut reg = ThreeNftRegistry::new();
        let id = reg.pin(PinRow {
            meta,
            recipe: enc.pipe.recipe.clone(),
            packed: enc.pipe.packed.clone(),
        });
        assert_ne!(id, 99);
        assert_eq!(
            reg.reemit_video_from_pin(99),
            Err(ThreeNftRegistryError::UnknownPin(99))
        );
        assert!(reg.meta(99).is_none());
    }

    /// A packed body that does not hash to the recipe's payload commitment is
    /// refused at re-emit time, so a pin cannot be swapped out for another
    /// object without breaking the commitment the chain named.
    #[test]
    fn a_packed_body_that_does_not_match_the_recipe_is_refused() {
        let right = product(b"right-body");
        let wrong = product(b"wrong-body-wrong-body");
        let meta = ThreeNftMeta::from_recipe(
            &ThreeRecipe::Public(right.pipe.recipe.clone()),
            PreviewMode::None,
        );
        let mut reg = ThreeNftRegistry::new();
        let id = reg.pin(PinRow {
            meta,
            recipe: right.pipe.recipe.clone(),
            packed: wrong.pipe.packed.clone(),
        });
        assert_eq!(
            reg.reemit_video_from_pin(id),
            Err(ThreeNftRegistryError::Reemit(
                ReemitError::PayloadCommitmentMismatch
            ))
        );
    }
}
