//! B.U.D. 3.0 content-QR recipe (plan §CH A5).
//!
//! Binds the A1 payload commitment, A2 carousel parameters, and the A3
//! optical stream id so a holder of the recipe (public or sealed) can
//! regenerate the same drop/frame sequence - or verify a stream - without
//! holding the body as storage.
//!
//! This is **not** the catalogue [`crate::storage::generated::GeneratedSpec`]
//! avatar path. Catalogue recipes invent pixels; this recipe describes how
//! transformed content bytes were packaged into the Three pipe.

use crate::core::hash::hash_fields_bytes;
use crate::storage::qr_carousel::CarouselParams;

/// Public recipe: everything needed to re-emit the stream is on the wire.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreeRecipePublic {
    /// A1 `payload_commitment` over the packed container.
    pub payload_commitment: [u8; 32],
    /// Carousel parameters locked for the stream.
    pub carousel: CarouselParams,
    /// A3 folded frame-digest stream id (or zeros if frames not yet folded).
    pub stream_id: [u8; 32],
    /// Block length used at encode (mirrors `carousel.block_len`; pinned twice
    /// so a partial decode of old recipes stays honest).
    pub block_len: u16,
}

/// Sealed recipe: public metering fields + commitment to the full public recipe.
///
/// Holders without the opening cannot re-emit drops; validators still see
/// sizes needed for refuse-absurd checks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreeRecipeSealed {
    /// `three_recipe_digest` of the full [`ThreeRecipePublic`].
    pub recipe_commitment: [u8; 32],
    /// Declared original content length (from `carousel.total_len`).
    pub total_len: u32,
    /// Source block count.
    pub k: u16,
    /// Block length.
    pub block_len: u16,
}

/// Either visibility mode.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThreeRecipe {
    /// Fully public pipe parameters.
    Public(ThreeRecipePublic),
    /// Commitment-only; open with the full public recipe off-chain.
    Sealed(ThreeRecipeSealed),
}

/// Domain-separated digest of a public recipe (what sealed commits to).
#[must_use]
pub fn three_recipe_digest(r: &ThreeRecipePublic) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_THREE_RECIPE_V1",
        &r.payload_commitment,
        &r.carousel.k.to_le_bytes(),
        &r.carousel.block_len.to_le_bytes(),
        &r.carousel.total_len.to_le_bytes(),
        &r.stream_id,
        &r.block_len.to_le_bytes(),
    ])
}

/// Commitment over a sealed recipe's public fields.
#[must_use]
pub fn three_sealed_recipe_commitment(s: &ThreeRecipeSealed) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_THREE_RECIPE_SEALED_V1",
        &s.recipe_commitment,
        &s.total_len.to_le_bytes(),
        &s.k.to_le_bytes(),
        &s.block_len.to_le_bytes(),
    ])
}

impl ThreeRecipePublic {
    /// Build from pipe pieces after A1-A3.
    #[must_use]
    pub const fn new(
        payload_commitment: [u8; 32],
        carousel: CarouselParams,
        stream_id: [u8; 32],
    ) -> Self {
        Self {
            payload_commitment,
            block_len: carousel.block_len,
            carousel,
            stream_id,
        }
    }

    /// Seal into the public-commitment form.
    #[must_use]
    pub fn seal(&self) -> ThreeRecipeSealed {
        ThreeRecipeSealed {
            recipe_commitment: three_recipe_digest(self),
            total_len: self.carousel.total_len,
            k: self.carousel.k,
            block_len: self.block_len,
        }
    }
}

impl ThreeRecipeSealed {
    /// # Errors
    ///
    /// When the candidate public recipe does not open this commitment, or
    /// metering fields disagree.
    pub fn open_with(&self, full: &ThreeRecipePublic) -> Result<(), String> {
        if full.carousel.total_len != self.total_len {
            return Err("sealed three recipe total_len mismatch".into());
        }
        if full.carousel.k != self.k {
            return Err("sealed three recipe k mismatch".into());
        }
        if full.block_len != self.block_len {
            return Err("sealed three recipe block_len mismatch".into());
        }
        let d = three_recipe_digest(full);
        if d != self.recipe_commitment {
            return Err("sealed three recipe commitment mismatch".into());
        }
        Ok(())
    }
}

impl ThreeRecipe {
    /// Digest suitable for a manifest / grant pin.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        match self {
            Self::Public(p) => three_recipe_digest(p),
            Self::Sealed(s) => three_sealed_recipe_commitment(s),
        }
    }

    /// G2: whether this recipe form is publicly re-emittable without a grant.
    #[must_use]
    pub const fn is_publicly_reemitable(&self) -> bool {
        matches!(self, Self::Public(_))
    }
}

/// G2 - may the actor open/re-emit a Three recipe right now?
///
/// - [`ThreeRecipe::Public`]: yes (V2).
/// - [`ThreeRecipe::Sealed`]: only when `grant_allows` is true (caller already
///   checked [`crate::storage::ViewGrantRegistry::may_view`] for this content).
///
/// This does **not** deliver key material; it only answers the authorization
/// question so reveal RPC cannot skip the grant check (T14).
#[must_use]
pub const fn may_open_three_recipe(recipe: &ThreeRecipe, grant_allows: bool) -> bool {
    match recipe {
        ThreeRecipe::Public(_) => true,
        ThreeRecipe::Sealed(_) => grant_allows,
    }
}

// CarouselParams needs serde - check if it has derives; if not, add manually in tests only via fields.
// We derived Serialize on CarouselParams? Check - we only have Debug Clone Copy PartialEq Eq.
// Fix: implement serde on CarouselParams in qr_carousel or store raw fields only.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_carousel::{CarouselEncoder, DEFAULT_BLOCK_LEN};
    use crate::storage::qr_frame::{fold_frame_digests, frame_digest, pack_frame};
    use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadKind};

    /// The fee schedule prices content by recipe bytes. This measures what a
    /// recipe actually costs on the wire and pins it.
    ///
    /// Why it exists: `BUD_RECIPE_PUBLIC_BYTES = 74` and
    /// `BUD_RECIPE_SEALED_BYTES = 40` live in the fee crate
    /// (`crates/ai-inference/crates/ai-serve/src/fee_scenario.rs`) and nothing
    /// tied them to this struct. The two agreed by discipline, not by a gate.
    /// Every storage price in the 3.0 spec is `recipes * 74`, so a field added
    /// here would silently make every published cost number wrong while all
    /// existing tests stayed green.
    ///
    /// bincode 1.x is held deliberately because its byte output is consensus
    /// input, so this size is a wire fact and not an implementation detail:
    ///   public = 32 commitment + 8 carousel (u16+u16+u32) + 32 stream + 2 block
    ///   sealed = 32 commitment + 4 total_len + 2 k + 2 block_len
    ///
    /// If this fails, do not edit the number here. Change the fee constants in
    /// the same commit, or the network charges for bytes it does not send.
    #[test]
    fn recipe_wire_size_is_the_size_the_fee_schedule_charges_for() {
        const FEE_PUBLIC_BYTES: usize = 74;
        const FEE_SEALED_BYTES: usize = 40;

        let packed = pack_payload(PayloadKind::ContentBytes, b"wire-size-probe").unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, DEFAULT_BLOCK_LEN).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let full = ThreeRecipePublic::new(commit, enc.params(), stream);
        let sealed = full.seal();

        let public_wire = bincode::serialize(&full).unwrap();
        let sealed_wire = bincode::serialize(&sealed).unwrap();

        assert_eq!(
            public_wire.len(),
            FEE_PUBLIC_BYTES,
            "public recipe is {} B on the wire but the fee schedule charges for {FEE_PUBLIC_BYTES} B",
            public_wire.len()
        );
        assert_eq!(
            sealed_wire.len(),
            FEE_SEALED_BYTES,
            "sealed recipe is {} B on the wire but the fee schedule charges for {FEE_SEALED_BYTES} B",
            sealed_wire.len()
        );

        // The size must not depend on the content: pricing is per recipe, not
        // per payload. A variable-length field would break that and is the
        // exact drift this test is here to catch.
        let other = pack_payload(PayloadKind::ContentBytes, &[7u8; 4096]).unwrap();
        let other_commit = payload_commitment(&other);
        let other_enc = CarouselEncoder::new(&other, 128).unwrap();
        let other_stream = other_enc.params().stream_commitment(&other_commit);
        let other_full = ThreeRecipePublic::new(other_commit, other_enc.params(), other_stream);
        assert_eq!(
            bincode::serialize(&other_full).unwrap().len(),
            FEE_PUBLIC_BYTES,
            "recipe size changed with the payload; pricing per recipe is no longer sound"
        );
    }

    #[test]
    fn public_recipe_stable_digest() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"recipe-content-xx").unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, DEFAULT_BLOCK_LEN).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let r1 = ThreeRecipePublic::new(commit, enc.params(), stream);
        let r2 = ThreeRecipePublic::new(commit, enc.params(), stream);
        assert_eq!(three_recipe_digest(&r1), three_recipe_digest(&r2));
        let mut other = stream;
        other[0] ^= 1;
        let r3 = ThreeRecipePublic::new(commit, enc.params(), other);
        assert_ne!(three_recipe_digest(&r1), three_recipe_digest(&r3));
    }

    #[test]
    fn sealed_opens_with_full() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"sealed-recipe-body").unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 64).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let full = ThreeRecipePublic::new(commit, enc.params(), stream);
        let sealed = full.seal();
        sealed.open_with(&full).unwrap();
        let mut bad = full.clone();
        bad.stream_id[1] ^= 0xaa;
        assert!(sealed.open_with(&bad).is_err());
    }

    #[test]
    fn sealed_requires_grant_to_open() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"g2").unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 32).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let full = ThreeRecipePublic::new(commit, enc.params(), stream);
        let sealed = ThreeRecipe::Sealed(full.seal());
        let public = ThreeRecipe::Public(full);
        assert!(may_open_three_recipe(&public, false));
        assert!(!may_open_three_recipe(&sealed, false));
        assert!(may_open_three_recipe(&sealed, true));
    }

    #[test]
    fn recipe_binds_frame_fold() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"fold-bind").unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 32).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let mut digests = Vec::new();
        for seq in 0..3 {
            let d = enc.drop_at(seq);
            let frame = pack_frame(&stream, &d).unwrap();
            let _ = frame;
            digests.push(frame_digest(&stream, seq, &d.to_bytes()));
        }
        let fold = fold_frame_digests(&digests).unwrap();
        let recipe = ThreeRecipe::Public(ThreeRecipePublic::new(commit, enc.params(), fold));
        assert_ne!(recipe.commitment(), [0u8; 32]);
    }
}
