//! Provider-side emit path: bytes in, QR feed out, with the ceilings checked
//! before any of them is paid for.
//!
//! The stages below `src/storage` each refuse on their own terms: the carousel
//! caps `k`, the frame header caps the wire, the matrix caps a QR symbol, the
//! provider refuses a transport derivative as a body. Nothing stood at the
//! front of that queue and answered the operator's actual question, which is
//! not "does `encode_qr_video` compile" but "what will this cost me, what will
//! the viewer hold, and do the two agree".
//!
//! `qr_feed_preview` is that front seat. It measures the request against every
//! ceiling, encodes once, reassembles what a viewer would reassemble from those
//! frames, re-emits frame zero from the recipe alone and compares, and reports
//! the commitments a publish would pin. It also runs the durable step against a
//! scratch `InMemoryStorageProvider`: the receipt it reports is the receipt a
//! publish returns, and the refusal it reports for the video blob is the refusal
//! a publish would raise. The scratch store is discarded with the preview, which
//! is the point - the node does not select a provider at startup, so this path
//! must not need one to answer.
//!
//! # What this does not do
//!
//! It does not authorise anything. Both entry points take their bytes from the
//! caller and publish no handle into stored content, so there is no viewer here
//! to grant: the grant and Pollen checks belong to whichever path reads content
//! out of a registry, and adding a second copy of that registry here would give
//! the answer twice and let the two disagree.

use crate::core::hash::hash_fields_bytes;
use crate::storage::generated::{
    generate_content, held_bytes, is_three_recipe, recipe_seed_is_public, ContentSource,
    GenerateError, SealedGeneratedSpec,
};
use crate::storage::payload_crypt::{
    open_payload, PayloadKey, SealError, MAX_SEAL_PLAINTEXT, SEALED_HEADER_LEN, SEALED_MAGIC,
    SEALED_NONCE_LEN, SEALED_VERSION,
};
use crate::storage::provider::{InMemoryStorageProvider, StorageProvider, StorageProviderError};
use crate::storage::qr_carousel::{
    oneshot_drop_count, planned_drop_count, repair_margin_for, CarouselEncoder, CarouselError,
    CarouselParams, DROP_HEADER_LEN, DROP_VERSION, MAX_CAROUSEL_BYTES, MAX_K,
    ONESHOT_REPAIR_PERMILLAGE,
};
use crate::storage::qr_codec::{gate_codec, CodecError, CodecKind, RawFrameConcat};
use crate::storage::qr_encode::MAX_DATA_BYTES;
use crate::storage::qr_frame::{
    stream_id_prefix, FrameError, MAX_DROP_WIRE, THREE_FRAME_HEADER_LEN, THREE_FRAME_VERSION,
};
use crate::storage::qr_matrix::{QrMatrix, QrMatrixError, MAX_QR_PAYLOAD, THREE_QR_EC};
use crate::storage::qr_payload::{
    pack_payload, packed_is_zlib, unpack_payload, PayloadError, PayloadKind, MAX_PAYLOAD_CONTENT,
    THREE_PAYLOAD_HEADER_LEN, THREE_PAYLOAD_VERSION,
};
use crate::storage::qr_png::{frame_to_qr_png, matrix_to_png, QrPngError};
use crate::storage::qr_receive::{ProgressiveReceiver, ReceiveError};
use crate::storage::qr_recipe::{three_sealed_recipe_commitment, ThreeRecipe, ThreeRecipeSealed};
use crate::storage::qr_reemit::{RecipeEmitter, ReemitError};
use crate::storage::qr_video::{
    png_to_optical_frame, QrVideo, QrVideoError, DEFAULT_FPS, VIDEO_VERSION,
};
use crate::storage::three_gate::{classify_three_blob, is_transport_derivative, ThreeBlobKind};
use crate::storage::three_meter::{MeterError, ThreeMeter};
use crate::storage::three_nft::{
    meta_tracks_public_recipe, MetadataVisibility, PreviewMode, ThreeNftMeta,
};
use crate::storage::three_pipe::{
    concat_round_trip, decode_frames, decode_qr_video, encode_qr_video, recipe_commitment,
    PipeError,
};
use crate::storage::three_recipe::{
    recipe_class, RecipeTransform, VideoFrameStream, VideoRecipe, VideoRecipeError,
    VideoRecipeSealed, RECIPE_VIDEO_MAGIC,
};
use crate::storage::three_reveal::{RevealError, RevealSession};
use crate::storage::three_visibility::{
    delete_implies_key_rotate, policy_for_upload, recipe_for_upload, UploadVisibility,
};
use crate::storage::transformed::{transform_content, CodecFlags, TransformError, TransformOpts};
use crate::storage::{ContentId, ContentManifest};

/// Largest body this path will encode in one call.
///
/// The ceilings below bound the *produced* bytes, not the request; a caller who
/// sends 60 MiB of body is billed for a full carousel before the first refusal.
/// This is the number that bounds the request itself.
pub const MAX_PREVIEW_CONTENT_BYTES: usize = 1 << 20;

/// Knobs for one emit.
///
/// The A2 repair margin is deliberately not a knob: the only production encode
/// path (`three_pipe::encode_qr_video`) seals and packs under
/// `ONESHOT_REPAIR_PERMILLAGE`, and a policy field that a stage ignores is a
/// lie a caller would pay for. The margin the encode used is reported back in
/// [`FeedPreview`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitPolicy {
    /// A2 source block length.
    pub block_len: u16,
    /// Display pacing hint written into the video header.
    pub fps: u16,
    /// A9 meter budget; `None` is unlimited and belongs to the lab, not to an
    /// endpoint a caller can hit twice.
    pub meter_budget: Option<u64>,
    /// G1 seal seed. `Some` seals the body before it is carouselled, so the
    /// feed carries ciphertext under a plaintext recipe.
    pub seal_seed: Option<[u8; 32]>,
    /// Frames one burst may return. A burst is a screenful, not a download.
    pub max_burst_frames: u32,
}

impl Default for EmitPolicy {
    fn default() -> Self {
        Self {
            block_len: crate::storage::three_pipe::PIPE_DEFAULT_BLOCK_LEN,
            fps: DEFAULT_FPS,
            meter_budget: Some(4096),
            seal_seed: None,
            max_burst_frames: 32,
        }
    }
}

/// What one publish would pin, and what a viewer would end up holding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPreview {
    /// Content id of the durable packed container, the thing a publish stores.
    pub content_id: ContentId,
    /// Provider commitment of that put (zeros when no manifest was supplied).
    pub provider_commitment: [u8; 32],
    /// Bytes in the packed container.
    pub packed_len: usize,
    /// Whether A1 zlib-compressed the body.
    pub packed_is_zlib: bool,
    /// Whether A0's own zlib pass shrank the content. A1 compresses again over
    /// whatever A0 returned, so the two answers are different measurements and
    /// only the first one says what the transform did to the upload.
    pub transform_shrank: bool,
    /// Leading contiguous solved blocks after the feed was replayed frame by
    /// frame: how far a viewer plays before the carousel closes.
    pub progressive_prefix_blocks: usize,
    /// A2 source block count the carousel locked over the packed container.
    pub k: u16,
    /// Blocks the pre-flight bound put on the request, before anything was
    /// transformed or packed. Reported so the caller can see how much the
    /// shrink bought.
    pub preflight_k: u16,
    /// Drops a full 2k carousel cycle would emit at this `k`.
    pub ceiling_drops: u32,
    /// Drops the one-shot schedule emits at this `k`.
    pub planned_drops: u32,
    /// Drop bound the A9 budget was charged against before the encode.
    pub drop_bound: u32,
    /// Repair margin the encode used, permillage of `k`.
    pub repair_permillage: u32,
    /// Repair drops the margin adds above the systematic pass, at this `k`
    /// and with no spare frames.
    pub repair_margin: u32,
    /// Frames the encode produced.
    pub frame_count: u32,
    /// Nested wire length of frame zero's drop.
    pub drop_wire_len: usize,
    /// A2 stream commitment the frames are bound to.
    pub stream_commitment: [u8; 32],
    /// A3 stream id prefix carried in every frame header.
    pub stream_prefix: u32,
    /// Feed identity: this body, this stream, this many frames.
    pub feed_id: [u8; 32],
    /// Commitment the recipe pins the produced video blob with.
    pub video_commitment: [u8; 32],
    /// Commitment over the full recipe, the sealed form's only field a holder
    /// needs to verify a re-emission.
    pub recipe_commitment: [u8; 32],
    /// Fold over the burst the emitter re-produced from the recipe alone.
    pub burst_fold: [u8; 32],
    /// Frames that burst carried.
    pub burst_len: usize,
    /// Whether the A4 raw concat is on the allow list in this build. The concat
    /// is produced only when this is true; `gate_codec` is what refuses at the
    /// muxer itself.
    pub codec_allowed: bool,
    /// Frames the reassembly accepted / rejected, from the receiver's counters.
    pub frames_accepted: u32,
    /// Frames the receiver rejected as unusable.
    pub frames_rejected: u32,
    /// A9 weighted work the emit was charged for.
    pub meter_weight: u64,
    /// Raster modules of frame zero's QR symbol, quiet zone included.
    pub raster_modules: u32,
    /// Pixels on one side of that raster, as the renderer reports it.
    pub raster_side: u32,
    /// PNG bytes a browser would scan.
    pub png_len: usize,
    /// EC level the matrix builder pins for QR ECC, as it prints.
    pub ec_level: String,
    /// Classifier's verdict on the produced video blob.
    pub video_blob_kind: ThreeBlobKind,
    /// Set when a Three-edition manifest named a public recipe: the length of
    /// the bytes the generator produced.
    pub regenerated_len: Option<usize>,
    /// Whether the manifest's source puts the regenerating seed on chain.
    pub seed_is_public: bool,
    /// Commitment of the sealed recipe capsule: what a validator meters without
    /// holding the body or the seed.
    pub sealed_recipe: [u8; 32],
    /// Whether a holder of the public recipe form can re-emit this feed without
    /// a grant (`false` means the sealed form is the one on chain).
    pub publicly_reemitable: bool,
    /// Body length the frame decoder of the pipe reports, measured on top of the
    /// receiver path so the two cannot disagree silently.
    pub decoded_body_len: usize,
    /// Body length the BDLV container decodes back to.
    pub video_body_len: usize,
    /// The class the recipe's pinned transform forced the body into, reported so
    /// a client opens the feed the way the recipe meant it to be opened.
    pub recipe_class: String,
    /// Whether A4's independent frame stream was measured against the published
    /// frames. `false` means the feed is sealed and the measurement is not
    /// available to anyone holding the public recipe.
    pub a4_agreement: bool,
    /// Domain-separated commitment of the NFT metadata this feed would mint
    /// against: what a marketplace pins, measured here rather than assumed.
    pub nft_meta: [u8; 32],
    /// Which on-chain recipe form a mint would name for this feed, and with it
    /// the grant class the upload path pairs: `OwnerOnly` opens nobody,
    /// `NamedGrantee` the named, `PublicKeyId` everyone.
    pub visibility: String,
    /// Whether deleting the content from social/DM is treated as a key rotation
    /// signal. Frames already handed to a device are not clawed back; this says
    /// the *new* sessions stop opening.
    pub rotate_key_on_delete: bool,
}

/// Errors from the emit path.
#[derive(Debug)]
pub enum EmitError {
    /// Empty body: nothing to encode, and an empty frame stream is not a feed.
    Empty,
    /// Body over [`MAX_PREVIEW_CONTENT_BYTES`].
    TooLarge {
        /// Bytes offered.
        len: usize,
        /// Ceiling.
        limit: usize,
    },
    /// A2 payload ceiling.
    CarouselTooLarge {
        /// Bytes offered.
        len: usize,
        /// Ceiling.
        limit: usize,
    },
    /// G1 seal ceiling.
    SealTooLarge {
        /// Bytes offered.
        len: usize,
        /// Ceiling.
        limit: usize,
    },
    /// A1 container ceiling.
    PayloadTooLarge {
        /// Bytes offered.
        len: usize,
        /// Ceiling.
        limit: usize,
    },
    /// `k` over the residual path's bound.
    TooManyBlocks {
        /// Blocks the policy implies.
        k: u16,
        /// Ceiling.
        limit: u16,
    },
    /// The policy asked for zero-length blocks: nothing divides by it, and a
    /// feed of empty blocks carries no body.
    ZeroBlockLen,
    /// A drop's wire would not fit the frame header's bound.
    WireTooLarge {
        /// Wire length.
        wire: usize,
        /// Ceiling.
        limit: usize,
    },
    /// A frame would not fit one QR symbol.
    QrOverflow {
        /// Frame length.
        len: usize,
        /// Ceiling.
        limit: usize,
    },
    /// The matrix builder's cap and the encoder's cap disagree, so which one
    /// binds is not knowable here.
    QrCapsDisagree {
        /// Cap the matrix builder enforces.
        matrix: usize,
        /// Cap the symbol encoder enforces.
        encoder: usize,
    },
    /// The one-shot schedule emitted more drops than the full cycle ceiling.
    PlanMismatch {
        /// Drops planned.
        planned: u32,
        /// Drops produced.
        actual: u32,
    },
    /// A burst wider than the policy allows, or wider than the stream.
    BurstTooWide {
        /// Frames asked for.
        count: u32,
        /// Ceiling.
        limit: u32,
    },
    /// Frame number past the end of the feed.
    FrameOutOfRange {
        /// Frame asked for.
        seq: u32,
        /// Frames the feed has.
        len: u32,
    },
    /// Frame zero rebuilt from the recipe alone is not frame zero as emitted.
    ReemitMismatch,
    /// The reveal gate refused to open the session this read path needed: either
    /// the bytes are sealed without an opening, or the caller may not view them.
    /// Reported as its own failure because a refused read is not a broken feed.
    Reveal(RevealError),
    /// The renderer reports fewer pixels than the modules it must draw, so a
    /// client sizing a canvas from this preview would size the wrong one.
    RasterDegenerate {
        /// Modules the matrix reports.
        modules: u32,
        /// Pixels the renderer reports on one side.
        side: u32,
    },
    /// The optional A4 concat does not split back into the frames it carried.
    ConcatMismatch {
        /// Frames put in.
        want: usize,
        /// Frames split out.
        got: usize,
    },
    /// Reassembly did not reproduce the packed container that was carouselled.
    ReassemblyMismatch,
    /// The receiver never completed on a stream it was handed in full.
    Incomplete {
        /// Blocks still missing.
        missing: usize,
    },
    /// The seal did not open back to the bytes A1 packed.
    SealMismatch,
    /// A sealed feed's body is not ciphertext.
    SealKindMismatch {
        /// Kind the container declared.
        kind: u8,
    },
    /// The provider stored a transport derivative it should have refused, so
    /// the durable/derivative boundary has moved without this path noticing.
    DerivativeAccepted(ThreeBlobKind),
    /// A stage refused.
    Carousel(CarouselError),
    /// A stage refused.
    Payload(PayloadError),
    /// A stage refused.
    Pipe(PipeError),
    /// A stage refused.
    Receive(ReceiveError),
    /// A stage refused.
    Reemit(ReemitError),
    /// A stage refused.
    Codec(CodecError),
    /// A stage refused.
    Frame(FrameError),
    /// A stage refused.
    Matrix(QrMatrixError),
    /// A stage refused.
    Png(QrPngError),
    /// A stage refused.
    Seal(SealError),
    /// A stage refused.
    Transform(TransformError),
    /// A stage refused.
    Video(QrVideoError),
    /// A stage refused.
    Recipe(VideoRecipeError),
    /// The provider refused.
    Provider(StorageProviderError),
    /// The A9 budget is spent.
    Meter(MeterError),
    /// The generator refused to produce the body a recipe names.
    Generate(GenerateError),
    /// The manifest's edition and source are not a legal pair.
    Edition(String),
    /// A Three-edition manifest names a sealed recipe: the seed is not on
    /// chain, so nobody but its holder can say what bytes this feed carries.
    SeedNotPublic,
    /// A Three-edition manifest named a source that is not a recipe at all.
    RecipeOnlyEdition,
    /// The body offered is not the body the manifest's recipe produces.
    BodyNotRecipe {
        /// Hash of the regenerated bytes.
        want: [u8; 32],
        /// Hash of the bytes offered.
        got: [u8; 32],
    },
    /// A manifest whose source contradicts its own declared sizes.
    SelfContradictingSource,
    /// A container carries a version byte this build does not emit. Refused
    /// here, at the encoder, rather than by a viewer that cannot parse it.
    VersionDrift {
        /// Which container disagreed.
        stage: &'static str,
        /// Byte the container carries.
        found: u8,
        /// Byte this build writes.
        want: u8,
    },
    /// The A1 header's zlib bit and the container's own report disagree.
    FlagMismatch,
    /// Two independent decode paths of the same feed disagree, so one of them is
    /// not decoding what was encoded.
    DecodePathMismatch,
    /// The NFT metadata does not track the recipe it was built from. The mint
    /// and the feed would name different objects.
    MetaDrift,
    /// A feed whose on-chain form is sealed and whose metadata is gated was
    /// about to be emitted over a clear body: the seal and the gate both
    /// promise a key, and plaintext frames need none. Refused unless the body
    /// was sealed (a seal seed) or the uploader already encrypted it (the
    /// manifest's `encryption` field).
    UnsealedGated,
    /// The manifest names a sealed recipe. Its public fields are metered, and
    /// then the emit stops: without the seed nobody can say which bytes this
    /// feed carries.
    SealedRecipe {
        /// Declared output length of the sealed spec.
        output_len: u32,
        /// Steps the sealed spec paid for.
        step_budget: u32,
    },
}

impl std::fmt::Display for EmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty body"),
            Self::ZeroBlockLen => write!(f, "block_len must be at least 1"),
            Self::TooLarge { len, limit } => {
                write!(f, "body of {len} bytes over emit cap {limit}")
            }
            Self::CarouselTooLarge { len, limit } => {
                write!(f, "body of {len} bytes over carousel cap {limit}")
            }
            Self::SealTooLarge { len, limit } => {
                write!(f, "body of {len} bytes over seal cap {limit}")
            }
            Self::PayloadTooLarge { len, limit } => {
                write!(f, "body of {len} bytes over payload cap {limit}")
            }
            Self::TooManyBlocks { k, limit } => {
                write!(f, "carousel k={k} over block bound {limit}")
            }
            Self::WireTooLarge { wire, limit } => {
                write!(f, "drop wire of {wire} bytes over frame bound {limit}")
            }
            Self::QrOverflow { len, limit } => {
                write!(
                    f,
                    "frame of {len} bytes does not fit one QR symbol ({limit})"
                )
            }
            Self::QrCapsDisagree { matrix, encoder } => {
                write!(f, "qr caps disagree: matrix {matrix}, encoder {encoder}")
            }
            Self::PlanMismatch { planned, actual } => {
                write!(
                    f,
                    "one-shot schedule emitted {actual} drops, planned {planned}"
                )
            }
            Self::BurstTooWide { count, limit } => {
                write!(f, "burst of {count} frames over burst bound {limit}")
            }
            Self::FrameOutOfRange { seq, len } => {
                write!(f, "frame {seq} past a feed of {len} frames")
            }
            Self::ReemitMismatch => write!(f, "recipe re-emitted a frame the pipe did not produce"),
            Self::Reveal(e) => write!(f, "three reveal gate refused the read: {e}"),
            Self::RasterDegenerate { modules, side } => {
                write!(f, "raster side {side} cannot hold {modules} modules")
            }
            Self::ConcatMismatch { want, got } => {
                write!(f, "raw concat split back into {got} frames, not {want}")
            }
            Self::ReassemblyMismatch => write!(f, "reassembly did not reproduce the packed body"),
            Self::Incomplete { missing } => {
                write!(f, "receiver missed {missing} blocks on a full stream")
            }
            Self::SealMismatch => write!(f, "sealed body does not open to the packed bytes"),
            Self::SealKindMismatch { kind } => {
                write!(f, "sealed feed declared non-ciphertext kind {kind}")
            }
            Self::DerivativeAccepted(kind) => {
                write!(f, "provider accepted a {kind:?} as a durable body")
            }
            Self::Carousel(e) => write!(f, "carousel: {e}"),
            Self::Payload(e) => write!(f, "payload: {e}"),
            Self::Pipe(e) => write!(f, "pipe: {e}"),
            Self::Receive(e) => write!(f, "receive: {e}"),
            Self::Reemit(e) => write!(f, "reemit: {e}"),
            Self::Codec(e) => write!(f, "codec: {e}"),
            Self::Frame(e) => write!(f, "frame: {e}"),
            Self::Matrix(e) => write!(f, "matrix: {e}"),
            Self::Png(e) => write!(f, "png: {e}"),
            Self::Seal(e) => write!(f, "seal: {e}"),
            Self::Transform(e) => write!(f, "transform: {e}"),
            Self::Video(e) => write!(f, "video: {e}"),
            Self::Recipe(e) => write!(f, "recipe: {e}"),
            Self::Provider(e) => write!(f, "provider: {e:?}"),
            Self::Meter(e) => write!(f, "meter: {e}"),
            Self::Generate(e) => write!(f, "generator: {e}"),
            Self::Edition(reason) => write!(f, "edition refuses: {reason}"),
            Self::SeedNotPublic => write!(f, "sealed recipe: the seed is not on chain"),
            Self::RecipeOnlyEdition => {
                write!(f, "edition Three carries no durable body to emit")
            }
            Self::BodyNotRecipe { want, got } => write!(
                f,
                "body is not the recipe's output: want {}, got {}",
                hex(*want),
                hex(*got)
            ),
            Self::SelfContradictingSource => {
                write!(f, "manifest source contradicts its declared sizes")
            }
            Self::VersionDrift {
                stage,
                found,
                want,
            } => write!(f, "{stage} carries version {found}, this build emits {want}"),
            Self::FlagMismatch => write!(f, "a1 zlib flag disagrees with the container report"),
            Self::MetaDrift => write!(f, "nft metadata does not track its recipe"),
            Self::UnsealedGated => write!(
                f,
                "non-public feed refused: the body is neither sealed nor declared ciphertext"
            ),
            Self::DecodePathMismatch => {
                write!(f, "two decode paths of one feed disagreed about the body")
            }
            Self::SealedRecipe {
                output_len,
                step_budget,
            } => write!(
                f,
                "sealed recipe is metered but not openable: output_len={output_len} step_budget={step_budget}"
            ),
        }
    }
}

impl std::error::Error for EmitError {}

impl From<CarouselError> for EmitError {
    fn from(e: CarouselError) -> Self {
        Self::Carousel(e)
    }
}

impl From<PipeError> for EmitError {
    fn from(e: PipeError) -> Self {
        Self::Pipe(e)
    }
}

impl From<ReceiveError> for EmitError {
    fn from(e: ReceiveError) -> Self {
        Self::Receive(e)
    }
}

impl From<ReemitError> for EmitError {
    fn from(e: ReemitError) -> Self {
        Self::Reemit(e)
    }
}

impl From<CodecError> for EmitError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

impl From<MeterError> for EmitError {
    fn from(e: MeterError) -> Self {
        Self::Meter(e)
    }
}

impl From<StorageProviderError> for EmitError {
    fn from(e: StorageProviderError) -> Self {
        Self::Provider(e)
    }
}

impl From<RevealError> for EmitError {
    fn from(e: RevealError) -> Self {
        Self::Reveal(e)
    }
}

/// The two numbers a sealed-generated record exposes for metering before anyone
/// knows the seed: the declared output length and the step budget.
#[must_use]
fn sealed_generated_meters(sealed: &SealedGeneratedSpec) -> (u32, u32) {
    (sealed.output_len, sealed.step_budget)
}

impl From<VideoRecipeError> for EmitError {
    fn from(e: VideoRecipeError) -> Self {
        Self::Recipe(e)
    }
}

impl From<TransformError> for EmitError {
    fn from(e: TransformError) -> Self {
        Self::Transform(e)
    }
}

impl From<PayloadError> for EmitError {
    fn from(e: PayloadError) -> Self {
        Self::Payload(e)
    }
}

impl From<SealError> for EmitError {
    fn from(e: SealError) -> Self {
        Self::Seal(e)
    }
}

impl From<GenerateError> for EmitError {
    fn from(e: GenerateError) -> Self {
        Self::Generate(e)
    }
}

impl From<QrMatrixError> for EmitError {
    fn from(e: QrMatrixError) -> Self {
        Self::Matrix(e)
    }
}

impl From<QrPngError> for EmitError {
    fn from(e: QrPngError) -> Self {
        Self::Png(e)
    }
}

impl From<FrameError> for EmitError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

fn hex(bytes: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Everything the ceilings say about a body before a single drop is built.
///
/// The bound is computed on `len + THREE_PAYLOAD_HEADER_LEN`, not on `len`:
/// A1 may shrink the body but never grows it, so the packed container is the
/// larger of the two and the carousel locks `k` over it. Charging the request
/// on the smaller number would let a caller walk up to a ceiling and be told it
/// is fine, then pay for the encode anyway.
///
/// # Errors
///
/// [`EmitError`] naming the first ceiling the request crosses.
fn plan(content: &[u8], policy: &EmitPolicy) -> Result<(u16, u32), EmitError> {
    if content.is_empty() {
        return Err(EmitError::Empty);
    }
    let len = content.len();
    if len > MAX_PREVIEW_CONTENT_BYTES {
        return Err(EmitError::TooLarge {
            len,
            limit: MAX_PREVIEW_CONTENT_BYTES,
        });
    }
    if len > MAX_CAROUSEL_BYTES {
        return Err(EmitError::CarouselTooLarge {
            len,
            limit: MAX_CAROUSEL_BYTES,
        });
    }
    if len > MAX_SEAL_PLAINTEXT {
        return Err(EmitError::SealTooLarge {
            len,
            limit: MAX_SEAL_PLAINTEXT,
        });
    }
    if len > MAX_PAYLOAD_CONTENT {
        return Err(EmitError::PayloadTooLarge {
            len,
            limit: MAX_PAYLOAD_CONTENT,
        });
    }
    if MAX_QR_PAYLOAD != MAX_DATA_BYTES {
        return Err(EmitError::QrCapsDisagree {
            matrix: MAX_QR_PAYLOAD,
            encoder: MAX_DATA_BYTES,
        });
    }
    let wire = usize::from(policy.block_len)
        .saturating_add(DROP_HEADER_LEN)
        .saturating_add(THREE_FRAME_HEADER_LEN);
    let bound = usize::from(MAX_DROP_WIRE);
    if wire > bound {
        return Err(EmitError::WireTooLarge { wire, limit: bound });
    }
    if wire > MAX_QR_PAYLOAD {
        return Err(EmitError::QrOverflow {
            len: wire,
            limit: MAX_QR_PAYLOAD,
        });
    }
    gate_codec(CodecKind::RawFrames)?;
    // `div_ceil` by zero panics; a zero block length arrives from the RPC
    // caller unchecked, so it is refused here, before the divide, as a
    // request error rather than a worker panic.
    if policy.block_len == 0 {
        return Err(EmitError::ZeroBlockLen);
    }
    let blok = usize::from(policy.block_len);
    let bloklar = len.saturating_add(THREE_PAYLOAD_HEADER_LEN).div_ceil(blok);
    let k = u16::try_from(bloklar).map_err(|_| EmitError::TooManyBlocks {
        k: MAX_K,
        limit: MAX_K,
    })?;
    if k > MAX_K {
        return Err(EmitError::TooManyBlocks { k, limit: MAX_K });
    }
    let bound_drops = oneshot_drop_count(k, ONESHOT_REPAIR_PERMILLAGE);
    Ok((k, bound_drops))
}

/// The recipe-shaped truth about an already-encoded feed: what a publish pins
/// and what a viewer can rebuild from the frames alone.
///
/// # Errors
///
/// [`EmitError`] when a ceiling, a reassembly, a re-emission or the provider
/// disagrees with the encode.
pub fn qr_feed_preview(
    content: &[u8],
    policy: &EmitPolicy,
    manifest: Option<&ContentManifest>,
) -> Result<FeedPreview, EmitError> {
    let (preflight_k, drop_bound) = plan(content, policy)?;
    let mut meter = ThreeMeter::with_budget(policy.meter_budget);
    meter.record_pack()?;
    meter.record_drops(drop_bound.into())?;
    if policy.seal_seed.is_some() {
        meter.record_seal()?;
    }
    let key = policy.seal_seed.map(|seed| PayloadKey::derive(&seed));
    // A manifest may declare the shards to be ciphertext the uploader already
    // produced (client-side encryption). That is the one clear-body case that
    // is still nobody's plaintext, and the visibility enforcement below reads
    // this rather than asking a client to seal the same bytes twice.
    let declared_ciphertext = manifest.is_some_and(|m| m.encryption.is_encrypted());
    // The pipe writes the pacing it pins, not the pacing a caller asks for, so a
    // policy naming any other rate is refused here rather than reported wrongly
    // by the preview below.
    if policy.fps != DEFAULT_FPS {
        return Err(EmitError::PlanMismatch {
            planned: u32::from(DEFAULT_FPS),
            actual: u32::from(policy.fps),
        });
    }
    let encoded = encode_qr_video(content, policy.block_len, key.as_ref())?;
    let pipe = &encoded.pipe;
    // A0 measured here on purpose: the pipe keeps the payload it built, and the
    // preview reports the transform's own answer next to the container's. One
    // pass serves both the report and the cross-check below, so the two cannot
    // describe different encodes.
    let a0 = transform_content(content, TransformOpts::default())?;
    // The carousel locks `k` over the packed container, so that is what the
    // plan is measured against here; `k` from the request is only ever a bound.
    let params = CarouselParams::from_payload(&pipe.packed, policy.block_len)?;
    let planned = oneshot_drop_count(params.k, ONESHOT_REPAIR_PERMILLAGE);
    let ceiling = planned_drop_count(params.k, ONESHOT_REPAIR_PERMILLAGE);
    let repair_margin = repair_margin_for(params.k, ONESHOT_REPAIR_PERMILLAGE, 0);
    let actual = u32::try_from(pipe.frames.len()).map_err(|_| EmitError::PlanMismatch {
        planned,
        actual: u32::MAX,
    })?;
    meter.record_frames(actual.into())?;
    if actual != planned || actual > ceiling || actual > drop_bound {
        return Err(EmitError::PlanMismatch { planned, actual });
    }
    if params.k != pipe.pipe_recipe_k() {
        return Err(EmitError::PlanMismatch {
            planned: u32::from(params.k),
            actual: u32::from(pipe.pipe_recipe_k()),
        });
    }

    let mut regenerated_len = None;
    let mut seed_is_public = false;
    if let Some(manifest) = manifest {
        manifest
            .edition
            .check_source(&manifest.source)
            .map_err(EmitError::Edition)?;
        let _ = held_bytes(&manifest.source, manifest.content_size)
            .ok_or(EmitError::SelfContradictingSource)?;
        seed_is_public = recipe_seed_is_public(&manifest.source);
        if let ContentSource::SealedGenerated(sealed) = &manifest.source {
            // The public fields of a sealed spec exist so a validator can meter it
            // and refuse an absurd budget without learning the seed. Both numbers a
            // refusal reports are the numbers the ceiling was judged on, read once:
            // an error text disagreeing with the bound that fired is a bug in the
            // one direction nobody checks. Then the emit stops: nobody can say
            // which bytes a sealed recipe carries.
            let (output_len, step_budget) = sealed_generated_meters(sealed);
            let plan_len = usize::try_from(output_len).unwrap_or(usize::MAX);
            if plan_len > MAX_PREVIEW_CONTENT_BYTES {
                return Err(EmitError::TooLarge {
                    len: plan_len,
                    limit: MAX_PREVIEW_CONTENT_BYTES,
                });
            }
            return Err(EmitError::SealedRecipe {
                output_len,
                step_budget,
            });
        }
        if !manifest.edition.admits_body() {
            // Edition Three holds no body: the feed's bytes are the generator's
            // output, so the caller's copy is checked against it, not trusted.
            let ContentSource::Generated(spec) = &manifest.source else {
                return Err(if is_three_recipe(&manifest.source) {
                    EmitError::SeedNotPublic
                } else {
                    EmitError::RecipeOnlyEdition
                });
            };
            let regen = generate_content(spec)?;
            let want = ContentId::of(&regen);
            let got = ContentId::of(content);
            if want != got {
                return Err(EmitError::BodyNotRecipe {
                    want: *want.as_bytes(),
                    got: *got.as_bytes(),
                });
            }
            regenerated_len = Some(regen.len());
        }
    }

    // What a viewer holding every frame can rebuild, measured here rather than
    // assumed: the frames are pushed one at a time, exactly as a camera hands
    // them over.
    let mut rx = ProgressiveReceiver::new(pipe.stream_commitment);
    let mut accepted = 0u32;
    for frame in &pipe.frames {
        rx.push_frame(frame)?;
        accepted += 1;
        if rx.is_complete() {
            break;
        }
    }
    // How far a viewer can play from what has arrived so far, measured on the
    // receiver this feed just produced rather than promised by the ordering.
    let prefix = rx.progressive_prefix_blocks();
    let (got, rejected) = rx.stats();
    if !rx.is_complete() {
        return Err(EmitError::Incomplete {
            missing: rx.missing(),
        });
    }
    if got != accepted {
        return Err(EmitError::ReassemblyMismatch);
    }
    if rejected != 0 || rx.finish_packed()? != pipe.packed {
        return Err(EmitError::ReassemblyMismatch);
    }
    let (kind, body_len_bytes) = rx.finish_unpacked()?;

    // Two decoders of the same frames, measured against each other: the
    // progressive receiver above and the pipe's own frame decoder. If either
    // drifts, the feed is not what the commitment says.
    let (kind2, body2) = decode_frames(&pipe.stream_commitment, &pipe.frames)?;
    if kind2 != kind || body2 != body_len_bytes {
        return Err(EmitError::DecodePathMismatch);
    }
    let (kind3, video_body, video3) = decode_qr_video(&encoded.video_blob)?;
    let video_frames = u32::try_from(video3.png_frames.len()).unwrap_or(u32::MAX);
    if kind3 != kind || video_body != body_len_bytes || video_frames != actual {
        return Err(EmitError::DecodePathMismatch);
    }
    if video3.stream_commitment != pipe.stream_commitment
        || video3.recipe_commitment != recipe_commitment(&pipe.recipe)
    {
        return Err(EmitError::DecodePathMismatch);
    }
    let decoded_body_len = body_len_bytes.len();
    let video_body_len = video_body.len();
    // Version bytes are read back out of the containers the emit produced. A
    // writer that bumped one of them without bumping the reader is caught here,
    // where the operator sees it, and not by a viewer three hops away.
    let (packed_kind, _) = unpack_payload(&pipe.packed)?;
    if pipe
        .packed
        .get(4)
        .copied()
        .filter(|v| *v == THREE_PAYLOAD_VERSION)
        .is_none()
    {
        return Err(EmitError::VersionDrift {
            stage: "a1",
            found: pipe.packed.get(4).copied().unwrap_or_default(),
            want: THREE_PAYLOAD_VERSION,
        });
    }
    if packed_kind != kind {
        return Err(EmitError::DecodePathMismatch);
    }
    // The flag byte and the helper that reads it look at the same offset, so the
    // comparison that used to sit here could not fail: it reported a cross-layer
    // agreement it never measured. What can disagree is the container against the
    // payload it wraps. A1 stores A0's bytes as its body, compressing them only if
    // that shrinks, so unpacking must return exactly what A0 produced. A sealed
    // feed is excluded: its A1 body is the ciphertext, and the seal branch below
    // measures that case against the key.
    if key.is_none() {
        let (_, a1_body) = unpack_payload(&pipe.packed)?;
        if a1_body.len() != a0.bytes.len() {
            return Err(EmitError::FlagMismatch);
        }
    }
    if let Some(key) = key.as_ref() {
        let (_, body) = unpack_payload(&pipe.packed)?;
        if kind != PayloadKind::EncryptedContent {
            return Err(EmitError::SealKindMismatch { kind: kind.tag() });
        }
        if body.len() < SEALED_HEADER_LEN
            || body.get(..4) != Some(SEALED_MAGIC.as_slice())
            || body.get(4) != Some(&SEALED_VERSION)
            || body.get(5..5 + SEALED_NONCE_LEN).is_none()
        {
            return Err(EmitError::SealMismatch);
        }
        let clear = open_payload(key, &body)?;
        if ContentId::of(&clear) != ContentId::of(&a0.bytes) {
            return Err(EmitError::SealMismatch);
        }
    }

    // The recipe alone, with no pipe and no frames held, must reproduce frame
    // zero byte for byte. This is the whole reason a recipe can be published
    // instead of a video.
    let emitter = RecipeEmitter::open(pipe.recipe.clone(), &pipe.packed)?;
    let drop0 = emitter.drop_at(0);
    if drop0.to_bytes().get(4) != Some(&DROP_VERSION) {
        return Err(EmitError::VersionDrift {
            stage: "a2",
            found: drop0.to_bytes().get(4).copied().unwrap_or_default(),
            want: DROP_VERSION,
        });
    }
    let drop_wire_len = drop0.to_bytes().len();
    if pipe
        .frames
        .first()
        .and_then(|f| f.get(2))
        .copied()
        .filter(|v| *v == THREE_FRAME_VERSION)
        .is_none()
    {
        return Err(EmitError::VersionDrift {
            stage: "a3",
            found: pipe
                .frames
                .first()
                .and_then(|f| f.get(2))
                .copied()
                .unwrap_or_default(),
            want: THREE_FRAME_VERSION,
        });
    }
    if encoded
        .video_blob
        .get(4)
        .copied()
        .filter(|v| *v == VIDEO_VERSION)
        .is_none()
    {
        return Err(EmitError::VersionDrift {
            stage: "a4",
            found: encoded.video_blob.get(4).copied().unwrap_or_default(),
            want: VIDEO_VERSION,
        });
    }
    // The systematic pass alone, fed as A2 drops with no frame header at all:
    // this is what a viewer that caught the drops over the wire rebuilds from.
    let enc = CarouselEncoder::new(&pipe.packed, policy.block_len)?;
    let drops = enc.encode_range(0, planned);
    if drops.len() != usize::try_from(planned).unwrap_or(usize::MAX) {
        return Err(EmitError::PlanMismatch {
            planned,
            actual: u32::try_from(drops.len()).unwrap_or(u32::MAX),
        });
    }
    let mut rx2 = ProgressiveReceiver::new(pipe.stream_commitment);
    for drop in &drops {
        rx2.push_drop(drop.clone())?;
    }
    if !rx2.is_complete() || rx2.finish_packed()? != pipe.packed {
        return Err(EmitError::ReassemblyMismatch);
    }
    let frame0 = emitter.frame_at(0);
    if Some(&frame0) != pipe.frames.first() {
        return Err(EmitError::ReemitMismatch);
    }
    let want = policy.max_burst_frames.min(actual).max(1);
    if want > policy.max_burst_frames {
        return Err(EmitError::BurstTooWide {
            count: want,
            limit: policy.max_burst_frames,
        });
    }
    let (burst, burst_fold) = emitter.emit_frames(0, want)?;
    // The recipe pins the identity of the pass a reader can rebuild. Verified
    // against the fold of the whole published frame list, which only this path
    // holds: comparing the pinned word with itself, as an earlier shape of this
    // line did, accepts any recipe. Reproducing every frame is also what makes
    // the pin meaningful, so the frame list is compared, not just its digest.
    let (pass, pass_fold) = emitter.emit_frames(0, actual)?;
    if pass != pipe.frames {
        return Err(EmitError::ReemitMismatch);
    }
    emitter.verify_stream_id(&pass_fold)?;
    let burst_len = burst.len();
    if burst.first() != Some(&frame0) {
        return Err(EmitError::ReemitMismatch);
    }

    // Frame zero as the thing a browser scans, plus the raster a client sizes a
    // canvas from.
    let matrix = QrMatrix::encode_at(&frame0, THREE_QR_EC)?;
    if matrix.pixel_side() < matrix.raster_modules() {
        return Err(EmitError::RasterDegenerate {
            modules: matrix.raster_modules(),
            side: matrix.pixel_side(),
        });
    }
    let png = frame_to_qr_png(&frame0)?;
    // The one-step render and the two-step render must be the same bytes: a
    // client that scans the poster must be scanning the frame, not a sibling of
    // it produced by a different path.
    if matrix_to_png(&matrix)? != png {
        return Err(EmitError::DecodePathMismatch);
    }
    // Scanning the poster has to give the frame back, so the frame is read out of
    // the PNG and compared. The two render paths agreeing above says nothing
    // about whether the optical frame survives the container a browser sees.
    if png_to_optical_frame(&png).map_err(EmitError::Video)? != frame0 {
        return Err(EmitError::DecodePathMismatch);
    }
    let raster_modules = matrix.raster_modules();
    let raster_side = matrix.pixel_side();
    let png_len = png.len();
    // The level the symbol carries, not the level this file pins: a report that
    // names an intention is how a silent table change would go unnoticed.
    let ec_level = format!("{:?}", matrix.ec_level());

    // The optional A4 concat, produced only when it is allowed and split back
    // here so the muxer is not trusted on its word alone.
    let codec_allowed = CodecKind::RawFrames.is_allowed();
    if codec_allowed {
        let back = concat_round_trip::<RawFrameConcat>(&pipe.frames)?;
        if back.len() != pipe.frames.len() {
            return Err(EmitError::ConcatMismatch {
                want: pipe.frames.len(),
                got: back.len(),
            });
        }
        if back != pipe.frames {
            return Err(EmitError::ConcatMismatch {
                want: pipe.frames.len(),
                got: back.len(),
            });
        }
    }

    let video_blob_kind = classify_three_blob(&encoded.video_blob);
    if !is_transport_derivative(&encoded.video_blob) {
        return Err(EmitError::DerivativeAccepted(video_blob_kind));
    }

    let stream_prefix = stream_id_prefix(&pipe.stream_commitment);
    let a3_recipe = recipe_commitment(&pipe.recipe);
    let feed_id = hash_fields_bytes(&[
        b"BDLM_EMIT_FEED_V1",
        &pipe.stream_commitment,
        &a3_recipe,
        &actual.to_le_bytes(),
        &encoded.video_blob.len().to_le_bytes(),
    ]);
    let sealed_capsule: ThreeRecipeSealed = pipe.recipe.seal();
    let sealed_recipe = three_sealed_recipe_commitment(&sealed_capsule);
    if sealed_capsule.k != params.k || sealed_capsule.block_len != policy.block_len {
        return Err(EmitError::PlanMismatch {
            planned: u32::from(params.k),
            actual: u32::from(sealed_capsule.k),
        });
    }
    // Which on-chain form a mint would name. This is not invented here: the
    // upload path has a product default (start sealed, open later through key
    // infrastructure), and a preview that reported a different form than the
    // upload would write would pin metadata nobody can open.
    let vis = if seed_is_public {
        UploadVisibility::Public
    } else {
        UploadVisibility::default()
    };
    let grant_policy = policy_for_upload(vis);
    let recipe_form = recipe_for_upload(&pipe.recipe, vis);

    // Reported as the recipe's own answer about its visibility form: a sealed A3
    // recipe can be pinned on chain while the frames it describes are nobody's to
    // rebuild, and a client choosing a marketplace listing off that difference
    // needs the flag to mean the form rather than a hope. It must name the form
    // being pinned (`recipe_form`), not a public construction of it: reporting
    // "publicly re-emittable" for a sealed pin would tell a marketplace anyone
    // can rebuild a feed the chain holds behind a commitment.
    let publicly_reemitable = recipe_form.is_publicly_reemitable();

    // The seal and the gate are one promise in two places: the sealed recipe
    // says nobody without the opening can rebuild the feed, and the gated
    // metadata says a key is needed to view it. Both are false over a clear
    // body, because the frames themselves carry the content. Enforced rather
    // than reported: a non-public feed whose frames are not ciphertext is
    // refused unless the uploader already encrypted the body (client-side
    // ciphertext is clear transport over bytes that are nobody's plaintext).
    if !publicly_reemitable && key.is_none() && !declared_ciphertext {
        return Err(EmitError::UnsealedGated);
    }
    // The metadata a mint would pin, built here and checked against this feed
    // rather than trusted: a token whose recipe commitment is not the feed's
    // recipe is a token for a different object, and nothing else in the pipeline
    // would notice.
    let meta = ThreeNftMeta::from_recipe(
        &recipe_form,
        if matches!(vis, UploadVisibility::Public) {
            PreviewMode::PublicStill
        } else {
            PreviewMode::Gated
        },
    )
    .with_video_commitment(QrVideo::blob_commitment(&encoded.video_blob));
    // Two ways this can be wrong and both are refused: a public upload has to
    // track the recipe the chain names, and a sealed one must not let its pin be
    // matched against a candidate public recipe, which is the whole point of the
    // seal.
    if meta_tracks_public_recipe(&meta, &pipe.recipe) != matches!(vis, UploadVisibility::Public) {
        return Err(EmitError::MetaDrift);
    }
    // The second half of the same promise: the metadata's own recorded
    // visibility has to say what the upload mode says. A token pinned as `Gated`
    // on a public upload tells a buyer to hunt for a key that does not exist, and
    // the recipe commitment check above cannot notice, because a public recipe
    // opens either way.
    let meta_vis: MetadataVisibility = meta.visibility;
    if (meta_vis == MetadataVisibility::Public) != matches!(vis, UploadVisibility::Public) {
        return Err(EmitError::MetaDrift);
    }
    let nft_meta = meta.commitment();
    let visibility = format!("{vis:?} + {grant_policy:?}");
    let rotate_key_on_delete = delete_implies_key_rotate();

    let (content_id, provider_commitment) = if let Some(manifest) = manifest {
        let mut scratch = InMemoryStorageProvider::with_operator(feed_id);
        let receipt = scratch.put(manifest, &pipe.packed)?;
        // The video blob is a rendering of bytes that already carry a
        // commitment. If a provider ever accepts it into a body slot, this path
        // has started handing out pixels-of-pixels.
        match scratch.put(manifest, &encoded.video_blob) {
            Err(StorageProviderError::DurableDerivative(ThreeBlobKind::QrVideo)) => {}
            Err(other) => return Err(EmitError::Provider(other)),
            Ok(_) => return Err(EmitError::DerivativeAccepted(ThreeBlobKind::QrVideo)),
        }
        (receipt.content_id, receipt.provider_commitment)
    } else {
        let packed = pack_payload(PayloadKind::ContentBytes, content)?;
        (ContentId::of(&packed), [0u8; 32])
    };

    let recipe = VideoRecipe::from_encoded(
        content,
        RecipeTransform::pin_from(TransformOpts::default(), content),
        kind.tag(),
        policy.block_len,
        ONESHOT_REPAIR_PERMILLAGE,
        policy.fps,
        &encoded,
    );
    let sealed: VideoRecipeSealed = recipe.seal();
    if sealed.frame_count != actual {
        return Err(EmitError::PlanMismatch {
            planned: actual,
            actual: sealed.frame_count,
        });
    }
    if recipe.video_commitment != QrVideo::blob_commitment(&encoded.video_blob) {
        return Err(EmitError::Video(QrVideoError::CommitmentMismatch));
    }
    // The blob this build produced must carry the tag this build reads. The
    // decoder is not consulted for this: a blob whose four leading bytes are
    // foreign is refused before anything is asked of it.
    if encoded.video_blob.get(0..4) != Some(RECIPE_VIDEO_MAGIC.as_slice()) {
        return Err(EmitError::DerivativeAccepted(video_blob_kind));
    }

    // A4 is a second and independent producer of the same frames: it walks the
    // recipe alone and never sees the carousel. Its frames must be the ones
    // being published, otherwise the feed answers "what is frame zero" twice.
    //
    // A sealed feed is not measured this way, and the reason is structural: the
    // A1 layer of a sealed feed is ciphertext whose key lives in `seal_seed`,
    // which a recipe deliberately does not carry. Asking A4 to reproduce frame
    // counts from plaintext it cannot pack is not a check, it is a false
    // accusation (measured: a sealed feed reported 3 frames against 13). So the
    // agreement is skipped there and reported as skipped, not passed.
    let mut a4_agreement = false;
    if kind != PayloadKind::EncryptedContent {
        // The recipe's promise is a reproduction, not a description: the body
        // plus the knobs it pins must rebuild this exact BDLV blob. Frames
        // agreeing is weaker than the blob agreeing - a header or a commitment
        // field could drift while every frame matched - so the whole container is
        // compared, through the sealed form as well, which is the only form a
        // marketplace holds.
        let again = recipe.reemit(content)?;
        if again.video_blob != encoded.video_blob {
            return Err(EmitError::ReemitMismatch);
        }
        let via_sealed = sealed.reemit_with(&recipe, content)?;
        if via_sealed.video_blob != encoded.video_blob {
            return Err(EmitError::ReemitMismatch);
        }
        // And the knobs the recipe pinned are the knobs this preview ran under:
        // two transform option sets agreeing on the payload hash is what lets the
        // reported class describe the feed a reader would rebuild.
        let pinned = transform_content(content, recipe.transform.as_opts())?;
        if pinned.content_sha256 != a0.content_sha256 {
            return Err(EmitError::PlanMismatch {
                planned: actual,
                actual,
            });
        }
        let mut stream: VideoFrameStream = recipe.frame_stream(content)?;
        if stream.len() != actual {
            return Err(EmitError::PlanMismatch {
                planned: stream.len(),
                actual,
            });
        }
        let gez = want.min(actual).min(3);
        let mut alinan = 0u32;
        while alinan < gez {
            let kare = stream.next_frame()?.ok_or(EmitError::DecodePathMismatch)?;
            if video3.png_frames.get(alinan as usize).map(Vec::as_slice) != Some(kare.as_slice()) {
                return Err(EmitError::DecodePathMismatch);
            }
            alinan += 1;
        }
        if stream.remaining() != actual - alinan || (actual == alinan) != stream.is_empty() {
            return Err(EmitError::PlanMismatch {
                planned: actual,
                actual: alinan,
            });
        }
        a4_agreement = true;
    }
    // Which class the recipe's pinned transform forces: a client decides how to
    // open the feed from this, and the answer must come from the recipe rather
    // than from whatever the transport's blob kind happens to imply.
    let recipe_class = format!("{:?}", recipe_class(&recipe));

    Ok(FeedPreview {
        content_id,
        provider_commitment,
        packed_len: pipe.packed.len(),
        packed_is_zlib: packed_is_zlib(&pipe.packed),
        transform_shrank: a0.codec_flags.contains(CodecFlags::PRE_SHRUNK),
        progressive_prefix_blocks: prefix,
        k: params.k,
        preflight_k,
        drop_bound,
        repair_permillage: ONESHOT_REPAIR_PERMILLAGE,
        ceiling_drops: ceiling,
        planned_drops: planned,
        repair_margin,
        frame_count: actual,
        drop_wire_len,
        stream_commitment: pipe.stream_commitment,
        stream_prefix,
        feed_id,
        video_commitment: recipe.video_commitment,
        recipe_commitment: sealed.recipe_commitment,
        burst_fold,
        burst_len,
        codec_allowed,
        frames_accepted: accepted,
        frames_rejected: rejected,
        meter_weight: meter.weight(),
        raster_modules,
        raster_side,
        png_len,
        ec_level,
        video_blob_kind,
        regenerated_len,
        seed_is_public,
        sealed_recipe,
        publicly_reemitable,
        decoded_body_len,
        video_body_len,
        recipe_class,
        a4_agreement,
        nft_meta,
        visibility,
        rotate_key_on_delete,
    })
}

/// Frames `seq_start..seq_start + count` of the feed, with the fold a client
/// checks them against.
///
/// This is the read path a progressive player uses: the recipe re-emits each
/// frame without the video being held anywhere, and every frame is compared to
/// what the pipe produced, so a client cannot be handed a frame nobody emitted.
///
/// # Errors
///
/// [`EmitError`] when the burst is wider than the policy or past the end of the
/// feed, or when a re-emitted frame differs from the emitted one.
pub fn qr_feed_frames_burst(
    content: &[u8],
    policy: &EmitPolicy,
    seq_start: u32,
    count: u32,
) -> Result<(Vec<Vec<u8>>, [u8; 32]), EmitError> {
    let (preflight_k, _) = plan(content, policy)?;
    if count == 0 || count > policy.max_burst_frames {
        return Err(EmitError::BurstTooWide {
            count,
            limit: policy.max_burst_frames,
        });
    }
    let key = policy.seal_seed.map(|seed| PayloadKey::derive(&seed));
    let encoded = encode_qr_video(content, policy.block_len, key.as_ref())?;
    let total = u32::try_from(encoded.pipe.frames.len()).unwrap_or(u32::MAX);
    if seq_start.saturating_add(count) > total {
        return Err(EmitError::FrameOutOfRange {
            seq: seq_start,
            len: total,
        });
    }
    if u32::from(preflight_k) == 0 {
        return Err(EmitError::Empty);
    }
    // The read path goes through the reveal session rather than opening an
    // emitter beside it: the session is what decides whether these bytes may be
    // re-emitted at all, and it refuses a sealed recipe nobody opened. A public
    // feed needs no grant, so `true` here names that fact; the day this path
    // carries a sealed recipe the same argument is what makes it refuse.
    let recipe = ThreeRecipe::Public(encoded.pipe.recipe.clone());
    let session = RevealSession::open(&recipe, None, &encoded.pipe.packed, true)?;
    let (frames, fold) = session.frames_with_fold(seq_start, count)?;
    if frames.first() != encoded.pipe.frames.get(seq_start as usize) {
        return Err(EmitError::ReemitMismatch);
    }
    Ok((frames, fold))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect()
    }

    #[test]
    fn preview_reports_a_feed_that_reassembles() {
        // A sealed policy: the production default upload is sealed, and an
        // unsealed preview of real content is refused below rather than
        // measured as if it could be published.
        let policy = EmitPolicy {
            seal_seed: Some([1u8; 32]),
            ..EmitPolicy::default()
        };
        let p = qr_feed_preview(&body(4096), &policy, None).expect("preview");
        assert_eq!(p.frames_rejected, 0);
        assert!(p.planned_drops <= p.ceiling_drops);
        assert_eq!(
            p.burst_len,
            usize::try_from(p.planned_drops.min(32)).unwrap()
        );
        assert!(p.png_len > 0);
        assert!(p.drop_wire_len <= usize::from(MAX_DROP_WIRE));
    }

    #[test]
    fn ceilings_refuse_before_anything_is_paid_for() {
        let big = body(MAX_PREVIEW_CONTENT_BYTES + 1);
        assert!(matches!(
            qr_feed_preview(&big, &EmitPolicy::default(), None),
            Err(EmitError::TooLarge { .. })
        ));
        let tiny_policy = EmitPolicy {
            block_len: 4095,
            ..EmitPolicy::default()
        };
        assert!(matches!(
            qr_feed_preview(&body(4096), &tiny_policy, None),
            Err(EmitError::QrOverflow { .. }) | Err(EmitError::WireTooLarge { .. })
        ));
        assert!(matches!(
            qr_feed_preview(&[], &EmitPolicy::default(), None),
            Err(EmitError::Empty)
        ));
        // A zero block length used to reach `div_ceil` and panic the
        // request; it is a caller error and is reported as one.
        let zero_policy = EmitPolicy {
            block_len: 0,
            ..EmitPolicy::default()
        };
        assert!(matches!(
            qr_feed_preview(&body(64), &zero_policy, None),
            Err(EmitError::ZeroBlockLen)
        ));
        assert!(matches!(
            qr_feed_frames_burst(&body(64), &zero_policy, 0, 1),
            Err(EmitError::ZeroBlockLen)
        ));
    }

    #[test]
    fn a_sealed_feed_still_opens_to_the_packed_body() {
        let policy = EmitPolicy {
            seal_seed: Some([7u8; 32]),
            ..EmitPolicy::default()
        };
        let p = qr_feed_preview(&body(2048), &policy, None).expect("sealed preview");
        assert!(!p.packed_is_zlib || p.packed_len > 0);
        // The A4 agreement is not measured across a seal, and the preview says
        // so rather than reporting a check it never ran.
        assert!(!p.a4_agreement);
        // The sealed pin is not publicly re-emittable: the flag names the form
        // on chain, not a public construction of it.
        assert!(!p.publicly_reemitable);
        assert_ne!(p.nft_meta, [0u8; 32]);
        assert!(p.rotate_key_on_delete);
        // The same body without a seal is refused, not reported as a gated feed
        // over clear frames: the seal and the gate promise a key the frames
        // would not need.
        assert!(matches!(
            qr_feed_preview(&body(2048), &EmitPolicy::default(), None),
            Err(EmitError::UnsealedGated)
        ));
    }

    #[test]
    fn a_clear_body_with_no_seal_and_no_ciphertext_is_refused() {
        // The default policy is the production default: sealed recipe, gated
        // metadata. Over clear frames that is a claim about the content that
        // the frames would not honour, so the emit refuses.
        assert!(matches!(
            qr_feed_preview(&body(1024), &EmitPolicy::default(), None),
            Err(EmitError::UnsealedGated)
        ));
    }

    #[test]
    fn client_side_ciphertext_passes_without_a_seed() {
        // The one clear-transport case that is nobody's plaintext: the
        // uploader already encrypted the shards and says so in the manifest.
        let data = body(1024);
        let manifest = crate::storage::ContentManifest::from_bytes_sliced(&data, 256)
            .unwrap()
            .with_encryption(crate::storage::ContentEncryption::ClientSide(
                crate::storage::ContentCipher::XChaCha20Poly1305,
            ));
        let p = qr_feed_preview(&data, &EmitPolicy::default(), Some(&manifest))
            .expect("client-side ciphertext preview");
        // The recipe form stays sealed (the seed is not on chain), but the
        // frames carry the uploader's ciphertext, not plaintext.
        assert!(!p.publicly_reemitable);
        assert!(p.a4_agreement);
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn sealing_hides_the_body_from_the_frames() {
        // A body the A1 zlib pass cannot shrink: if the frames carried it in
        // the clear, the marker would survive byte for byte.
        // Incompressible body (a fixed xorshift stream): the A1 zlib pass keeps
        // it verbatim, so a clear frame carries the marker byte for byte.
        let mut data = Vec::new();
        data.extend_from_slice(b"BDLM_MARKER_");
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..2048 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.push((x & 0xFF) as u8);
        }
        let marker = b"BDLM_MARKER_";

        let sealed = EmitPolicy {
            seal_seed: Some([9u8; 32]),
            ..EmitPolicy::default()
        };
        let (frames, _) = qr_feed_frames_burst(&data, &sealed, 0, 2).expect("sealed burst");
        assert!(
            frames.iter().all(|f| find_subslice(f, marker).is_none()),
            "sealed frames must not carry the body in the clear"
        );

        // The transparent transport of the same body does carry the marker:
        // this is what sealing removes.
        let plain = EmitPolicy::default();
        let (frames, _) = qr_feed_frames_burst(&data, &plain, 0, 2).expect("plain burst");
        assert!(
            frames.iter().any(|f| find_subslice(f, marker).is_some()),
            "the transparent transport is the plaintext baseline the seal is measured against"
        );
    }

    #[test]
    fn a_burst_reemits_the_frames_the_pipe_produced() {
        let content = body(6000);
        let policy = EmitPolicy::default();
        let (burst, fold) = qr_feed_frames_burst(&content, &policy, 0, 2).expect("burst");
        assert_eq!(burst.len(), 2);
        assert_ne!(fold, [0u8; 32]);
        assert!(matches!(
            qr_feed_frames_burst(&content, &policy, 0, policy.max_burst_frames + 1),
            Err(EmitError::BurstTooWide { .. })
        ));
        assert!(matches!(
            qr_feed_frames_burst(&content, &policy, 10_000, 1),
            Err(EmitError::FrameOutOfRange { .. })
        ));
    }
}
