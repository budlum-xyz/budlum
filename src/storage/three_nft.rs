//! A8 — Three NFT metadata pin (plan §CH A8 / G4).
//!
//! On-chain / marketplace metadata must never carry a raw seed or payload key.
//! It pins the recipe commitment, visibility policy label, and an optional
//! low-fidelity preview mode. Validators churning does not drop the pin.

use crate::core::hash::hash_fields_bytes;
use crate::storage::qr_recipe::{three_recipe_digest, ThreeRecipe, ThreeRecipePublic};

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
    pub fn with_video_commitment(mut self, video_blob_commitment: [u8; 32]) -> Self {
        self.video_commitment = Some(video_blob_commitment);
        self
    }
}

/// Sanity: public recipe metadata commitment moves if recipe moves.
#[must_use]
pub fn meta_tracks_public_recipe(meta: &ThreeNftMeta, recipe: &ThreeRecipePublic) -> bool {
    meta.recipe_commitment == three_recipe_digest(recipe)
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
