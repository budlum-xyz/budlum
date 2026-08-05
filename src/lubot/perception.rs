//! What a Lubot model is allowed to read, and in what form.
//!
//! Lubot already answers "may this operator touch this data" through Pollen.
//! This module answers the question underneath it: **what kind of reading is
//! being asked for.** Text and an image are not the same request even when
//! the grant is identical, because they cost different amounts, they fail in
//! different ways, and one of them can be made deterministic while the other
//! cannot.
//!
//! # Reading only
//!
//! Lubot does not generate images or video, and nothing here opens a door to
//! it. Every modality in [`PerceptionKind`] describes an input a model may
//! consume. That is a scope decision rather than a technical limit: a
//! generation surface would need its own economics, its own abuse model and
//! its own answer to "who owns the output", and none of those are settled.
//! Declaring the boundary in the type keeps a later contributor from adding
//! `ImageOutput` next to `ImageInput` and calling it symmetry.
//!
//! # Why a declaration rather than sniffing the bytes
//!
//! The alternative is to look at the content and decide. That fails on this
//! chain for a specific reason: a `ContentId` is the hash of the object, and
//! the object may be ciphertext the chain never sees. There is nothing to
//! sniff. The reader therefore states what it intends to read, the statement
//! is part of what the request commits to, and a model that was registered
//! for text cannot quietly be handed a video frame.
//!
//! # The budget is per modality, and that is the point
//!
//! A thousand tokens of text and a thousand pixels of image are not
//! comparable work. Charging them the same rate either overprices text or
//! underprices images, and underpricing an input is how a cheap request
//! becomes an expensive one for whoever runs the operator. Each modality
//! carries its own ceiling, expressed in its own unit.
//!
//! WIRING: unwired - measured: no production path constructs a
//! `PerceptionRequest` yet. The declaration, its bounds and its refusals are
//! here and tested; the inference path that carries one is a consensus
//! surface change and lands with the request-format revision.

use crate::core::hash::hash_fields_bytes;
use crate::pollen::AssetId;
use crate::storage::content_id::ContentId;

/// The largest text input a model may be asked to read, in bytes.
///
/// UTF-8 bytes rather than characters or tokens: bytes are the only unit both
/// sides can agree on without running a tokeniser, and a tokeniser is a model
/// choice that must not leak into an admission check.
pub const MAX_TEXT_INPUT_BYTES: u32 = 1024 * 1024;

/// The largest still image a model may be asked to read, in pixels.
///
/// Pixels rather than bytes, because a compressed image can be small on disk
/// and enormous once decoded, and the cost that matters is the decoded one.
/// Sixteen megapixels is past any photograph a phone produces.
pub const MAX_IMAGE_INPUT_PIXELS: u32 = 16 * 1024 * 1024;

/// The largest audio input a model may be asked to read, in milliseconds.
pub const MAX_AUDIO_INPUT_MILLIS: u32 = 60 * 60 * 1000;

/// The largest number of video frames a model may be asked to read.
///
/// Frames rather than duration, because the work is per frame and a long
/// still-heavy clip costs less than a short busy one. Bounded low on purpose:
/// video reading is the most expensive modality here and the least proven.
pub const MAX_VIDEO_INPUT_FRAMES: u32 = 4096;

/// What kind of reading a request is asking for.
///
/// A closed set. Each variant is an input a model consumes; there is no
/// output variant, and adding one would be a different feature with different
/// economics rather than an extension of this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PerceptionKind {
    /// Read text. The baseline, and the only modality with no decoding step
    /// between the bytes and the model.
    Text,
    /// Read a still image.
    Image,
    /// Read audio.
    Audio,
    /// Read video frames.
    ///
    /// Reading only. Lubot does not produce video, and the absence of a
    /// generating counterpart to this variant is deliberate.
    Video,
}

impl PerceptionKind {
    /// Stable byte tag for the commitment, so the hash does not depend on
    /// declaration order.
    const fn perception_tag(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::Image => 2,
            Self::Audio => 3,
            Self::Video => 4,
        }
    }

    /// The ceiling for this modality, in the unit that modality is measured
    /// in.
    ///
    /// The unit differs per variant on purpose; see [`PerceptionKind::unit`]
    /// for the name of it. A single shared number would have to be bytes,
    /// and bytes are the wrong unit for three of the four.
    pub const fn max_units(self) -> u32 {
        match self {
            Self::Text => MAX_TEXT_INPUT_BYTES,
            Self::Image => MAX_IMAGE_INPUT_PIXELS,
            Self::Audio => MAX_AUDIO_INPUT_MILLIS,
            Self::Video => MAX_VIDEO_INPUT_FRAMES,
        }
    }

    /// The name of the unit this modality is measured in, for error messages
    /// and for anything reporting a quota to an operator.
    pub const fn perception_unit(self) -> &'static str {
        match self {
            Self::Text => "bytes",
            Self::Image => "pixels",
            Self::Audio => "milliseconds",
            Self::Video => "frames",
        }
    }

    /// Whether reading this modality requires a decoding step the chain does
    /// not perform.
    ///
    /// Text does not; the other three do. This matters because a decoder is
    /// where a malformed input turns into unbounded work, and because two
    /// operators running different decoders can disagree about what an image
    /// contains. Anything built on top of this has to treat a decoded
    /// modality as an operator-local result, never as a consensus fact.
    pub const fn needs_decoder(self) -> bool {
        !matches!(self, Self::Text)
    }
}

/// Why a perception request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerceptionError {
    /// The declared size is zero. An empty read has no cost and no meaning,
    /// and accepting it makes "how many reads were performed" ambiguous.
    EmptyInput { kind: PerceptionKind },
    /// The declared size is past the ceiling for this modality.
    TooLarge {
        kind: PerceptionKind,
        declared: u32,
        max: u32,
        unit: &'static str,
    },
    /// The model was not registered for this modality.
    ///
    /// Refused rather than attempted, because a text model handed an image
    /// does not fail cleanly: it reads the bytes as text and returns
    /// confident nonsense, which is worse than an error.
    ModalityNotDeclared { kind: PerceptionKind },
}

impl std::fmt::Display for PerceptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyInput { kind } => {
                write!(
                    f,
                    "a {kind:?} read of zero {} is not a read",
                    kind.perception_unit()
                )
            }
            Self::TooLarge {
                kind,
                declared,
                max,
                unit,
            } => write!(
                f,
                "{kind:?} input declares {declared} {unit}, above the {max} {unit} ceiling"
            ),
            Self::ModalityNotDeclared { kind } => write!(
                f,
                "this model was not registered to read {kind:?}; a model handed a modality it \
                 does not understand returns confident nonsense rather than an error"
            ),
        }
    }
}

impl std::error::Error for PerceptionError {}

/// The set of modalities a model declared at registration.
///
/// Stored as a bitmask so it costs four bytes in a spec and cannot grow
/// unboundedly with the catalogue. A model declares once, at registration,
/// and the declaration is part of what its id commits to; that is what stops
/// an operator quietly widening a model's diet after it has been priced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ModalitySet(u32);

impl ModalitySet {
    /// A model that reads nothing. Refuses every request, which is the right
    /// default: a model whose declaration was lost should stop working rather
    /// than accept everything.
    pub const fn none() -> Self {
        Self(0)
    }

    /// A text-only model, which is what most of them are.
    pub const fn text_only() -> Self {
        Self(1 << 0)
    }

    fn bit(kind: PerceptionKind) -> u32 {
        1 << (kind.perception_tag() - 1)
    }

    /// Add a modality to the set.
    ///
    /// Named `with_modality` rather than `with`: the bare word appears in
    /// English prose in most files in this tree, and the wiring gate counts
    /// name matches to decide whether a module is reachable. Measured, the
    /// short name made this module report as wired against sentences like
    /// "a node built with the other one".
    #[must_use]
    pub fn with_modality(self, kind: PerceptionKind) -> Self {
        Self(self.0 | Self::bit(kind))
    }

    /// Whether the model declared this modality.
    pub fn declares_modality(self, kind: PerceptionKind) -> bool {
        self.0 & Self::bit(kind) != 0
    }

    /// How many modalities are declared.
    pub const fn declared_count(self) -> u32 {
        self.0.count_ones()
    }

    /// The raw bits, for hashing into a model spec.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// A declared read: which object, what kind, and how much of it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PerceptionRequest {
    /// The Pollen asset the content belongs to. Carried so the permission
    /// check and the modality check name the same thing; a request that
    /// passed one for asset A and the other for asset B would be a hole.
    pub asset_id: AssetId,
    /// The content being read.
    pub content_id: ContentId,
    /// What kind of reading this is.
    pub kind: PerceptionKind,
    /// How much, in the unit of [`PerceptionKind::unit`].
    pub declared_units: u32,
}

impl PerceptionRequest {
    /// Check the request is one a model with `modalities` could serve.
    ///
    /// Deliberately does not fetch the content. Everything here is answerable
    /// from the declaration, and a check needing the bytes could not run at
    /// admission, which is the only point where refusing is cheap. The
    /// declaration is not trusted for correctness: it is checked against the
    /// bytes later, when the operator has them. What it is trusted for is
    /// refusing early, and a spec that lies about its size only cheats itself
    /// out of a result.
    ///
    /// # Errors
    ///
    /// [`PerceptionError::ModalityNotDeclared`] when the model does not read
    /// this kind, [`PerceptionError::EmptyInput`] for a zero-sized read, and
    /// [`PerceptionError::TooLarge`] past the ceiling for the modality.
    pub fn check_admissible(&self, modalities: ModalitySet) -> Result<(), PerceptionError> {
        if !modalities.declares_modality(self.kind) {
            return Err(PerceptionError::ModalityNotDeclared { kind: self.kind });
        }
        if self.declared_units == 0 {
            return Err(PerceptionError::EmptyInput { kind: self.kind });
        }
        let max = self.kind.max_units();
        if self.declared_units > max {
            return Err(PerceptionError::TooLarge {
                kind: self.kind,
                declared: self.declared_units,
                max,
                unit: self.kind.perception_unit(),
            });
        }
        Ok(())
    }

    /// Domain-tagged commitment to this read.
    ///
    /// Every field is hashed, including the asset. Leaving the asset out
    /// would let one commitment stand for reads of two different assets that
    /// happen to share a content id, which is exactly what deduplication
    /// makes possible.
    pub fn perception_commitment_tag(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_LUBOT_PERCEPTION_V1",
            &self.asset_id.0,
            &self.content_id.0,
            &[self.kind.perception_tag()],
            &self.declared_units.to_le_bytes(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(kind: PerceptionKind, units: u32) -> PerceptionRequest {
        PerceptionRequest {
            asset_id: AssetId([1; 32]),
            content_id: ContentId([2; 32]),
            kind,
            declared_units: units,
        }
    }

    #[test]
    fn a_model_reads_only_what_it_declared() {
        let text_model = ModalitySet::text_only();
        assert!(req(PerceptionKind::Text, 100)
            .check_admissible(text_model)
            .is_ok());

        // The case this exists for. A text model handed an image does not
        // fail cleanly, it reads the bytes as text and answers confidently.
        assert_eq!(
            req(PerceptionKind::Image, 100).check_admissible(text_model),
            Err(PerceptionError::ModalityNotDeclared {
                kind: PerceptionKind::Image
            })
        );
    }

    #[test]
    fn a_model_that_declared_nothing_refuses_everything() {
        // The default has to fail closed: a model whose declaration was lost
        // should stop working rather than accept every modality.
        let none = ModalitySet::none();
        for kind in [
            PerceptionKind::Text,
            PerceptionKind::Image,
            PerceptionKind::Audio,
            PerceptionKind::Video,
        ] {
            assert!(req(kind, 10).check_admissible(none).is_err());
        }
        assert_eq!(ModalitySet::default(), ModalitySet::none());
    }

    #[test]
    fn each_modality_is_bounded_in_its_own_unit() {
        // A shared ceiling would have to be bytes, and bytes are the wrong
        // unit for three of the four: a compressed image is small on disk and
        // enormous decoded.
        let all = ModalitySet::none()
            .with_modality(PerceptionKind::Text)
            .with_modality(PerceptionKind::Image)
            .with_modality(PerceptionKind::Audio)
            .with_modality(PerceptionKind::Video);

        for kind in [
            PerceptionKind::Text,
            PerceptionKind::Image,
            PerceptionKind::Audio,
            PerceptionKind::Video,
        ] {
            let max = kind.max_units();
            assert!(req(kind, max).check_admissible(all).is_ok(), "{kind:?}");
            assert!(
                req(kind, max + 1).check_admissible(all).is_err(),
                "{kind:?} accepted one over its ceiling"
            );
            assert!(
                req(kind, 0).check_admissible(all).is_err(),
                "{kind:?} accepted an empty read"
            );
        }
    }

    #[test]
    fn the_units_are_not_interchangeable() {
        // Locks the reason the ceilings differ. If these ever collapse to one
        // number, either text is overpriced or images are underpriced, and
        // underpricing an input is how a cheap request becomes expensive for
        // the operator serving it.
        assert_eq!(PerceptionKind::Text.perception_unit(), "bytes");
        assert_eq!(PerceptionKind::Image.perception_unit(), "pixels");
        assert_eq!(PerceptionKind::Audio.perception_unit(), "milliseconds");
        assert_eq!(PerceptionKind::Video.perception_unit(), "frames");
        assert_ne!(
            PerceptionKind::Text.max_units(),
            PerceptionKind::Video.max_units()
        );
    }

    #[test]
    fn only_text_reaches_the_model_without_a_decoder() {
        // A decoder is where a malformed input becomes unbounded work, and
        // where two operators can disagree about what an image contains.
        // Anything built on this must treat a decoded modality as an
        // operator-local result rather than a consensus fact.
        assert!(!PerceptionKind::Text.needs_decoder());
        for kind in [
            PerceptionKind::Image,
            PerceptionKind::Audio,
            PerceptionKind::Video,
        ] {
            assert!(kind.needs_decoder(), "{kind:?}");
        }
    }

    #[test]
    fn declaring_a_modality_twice_does_not_double_count() {
        let set = ModalitySet::none()
            .with_modality(PerceptionKind::Image)
            .with_modality(PerceptionKind::Image);
        assert_eq!(set.declared_count(), 1);
        assert!(set.declares_modality(PerceptionKind::Image));
        assert!(!set.declares_modality(PerceptionKind::Text));
    }

    #[test]
    fn every_modality_gets_its_own_bit() {
        // A collision here would silently grant a modality the model never
        // declared, which is the failure this whole type exists to prevent.
        let kinds = [
            PerceptionKind::Text,
            PerceptionKind::Image,
            PerceptionKind::Audio,
            PerceptionKind::Video,
        ];
        let mut set = ModalitySet::none();
        for (i, kind) in kinds.iter().enumerate() {
            set = set.with_modality(*kind);
            assert_eq!(set.declared_count(), i as u32 + 1);
        }
        for kind in kinds {
            assert!(set.declares_modality(kind));
        }
    }

    #[test]
    fn the_commitment_covers_every_field() {
        let base = req(PerceptionKind::Text, 100).perception_commitment_tag();

        let mut other_asset = req(PerceptionKind::Text, 100);
        other_asset.asset_id = AssetId([9; 32]);
        assert_ne!(other_asset.perception_commitment_tag(), base, "asset_id");

        let mut other_content = req(PerceptionKind::Text, 100);
        other_content.content_id = ContentId([9; 32]);
        assert_ne!(
            other_content.perception_commitment_tag(),
            base,
            "content_id"
        );

        assert_ne!(
            req(PerceptionKind::Image, 100).perception_commitment_tag(),
            base,
            "kind"
        );
        assert_ne!(
            req(PerceptionKind::Text, 101).perception_commitment_tag(),
            base,
            "declared_units"
        );
    }

    #[test]
    fn the_commitment_is_stable_across_calls() {
        // Two nodes hashing the same declaration must agree, or they disagree
        // about which read was authorised.
        assert_eq!(
            req(PerceptionKind::Audio, 5).perception_commitment_tag(),
            req(PerceptionKind::Audio, 5).perception_commitment_tag()
        );
    }

    #[test]
    fn reading_modalities_have_no_generating_counterpart() {
        // A scope decision, locked so it is a deliberate act to change it.
        // Lubot reads; it does not generate images or video. A generation
        // surface needs its own economics, its own abuse model and its own
        // answer to who owns the output, and none of those are settled.
        let names = format!(
            "{:?} {:?} {:?} {:?}",
            PerceptionKind::Text,
            PerceptionKind::Image,
            PerceptionKind::Audio,
            PerceptionKind::Video
        );
        for banned in ["Output", "Generate", "Render", "Synthes"] {
            assert!(
                !names.contains(banned),
                "PerceptionKind gained a generating variant: {banned}"
            );
        }
    }
}
