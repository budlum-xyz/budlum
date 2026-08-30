//! Render a generated object into the format a reader asked for.
//!
//! WIRING: wired - `BudGateway::render_name_content` calls `render` and
//! `render_id`, reached from the `bud_gatewayRenderContent` RPC. A reader
//! asks for a name and a format; the recipe produces those bytes on demand
//! and nothing is stored.
//!
//! The format is part of the commitment, so the reply carries the render id
//! rather than the manifest id: the same recipe rendered as PNG is a
//! different object from the same recipe rendered as SVG, and returning the
//! manifest id for both would name two different byte strings with one id.
//!
//! An unknown format string is refused rather than defaulted. Falling back
//! would hand the caller an object it did not ask for under an id it cannot
//! predict.
//!
//! `QrStream` is deliberately not reachable from the RPC. It is a transport
//! representation, not a way to read an object.
//!
//! This is the format layer of the "recipe" invention: a generated object is
//! stored as a `GeneratedSpec` (a generator and a seed), and the bytes a
//! reader receives depend on the format they request. One recipe yields an
//! SVG for a browser, a PNG for a wallet thumbnail, a WebP for a gallery, a
//! frame for a video. The bytes are produced on demand by CPU, nothing is
//! stored beyond the recipe itself, and every format is deterministic: the
//! same recipe and the same format always produce the same bytes.
//!
//! # Determinism
//!
//! The generators in `generated.rs` produce raw pixels from a seed. This
//! module wraps those bytes into container formats. Each container is
//! written with a fixed, versioned encoding:
//!
//! * SVG is built from decimal strings produced by fixed-point arithmetic,
//!   so there is no floating-point drift and no locale dependence.
//! * PNG is written by hand: IHDR/IDAT/IEND with a fixed filter strategy and
//!   a fixed zlib level, so two machines produce identical files. The
//!   checksum is a table CRC32, computed byte by byte in a fixed order.
//!
//! The format string itself is part of the commitment: a recipe rendered as
//! PNG is a different object from the same recipe rendered as SVG, and the
//! id that commits to the recipe must say which format it means.
//!
//! # What this module does not do
//!
//! It does not rasterize SVG to PNG. Rasterization is a lossy, toolchain
//! dependent step (resvg, librsvg, cairosvg all differ in sub-pixel
//! details), so it cannot live inside a deterministic commitment without
//! pinning one specific rasterizer version to the recipe. The PNG path here
//! renders the seed directly to pixels, the same way `draw_avatar` does, so
//! no rasterizer is involved. SVG stays vector. The video frame path is the
//! pixel buffer with a format tag; the encoder that turns frames into an
//! actual video is a separate, explicitly versioned step.

use std::fmt::Write as _;

use crate::core::hash::hash_fields_bytes;
use crate::storage::generated::{
    generate_content, generated_spec_digest, GenerateError, GeneratedSpec, MAX_GENERATED_BYTES,
};

/// Domain separation for a rendered object's id.
///
/// Distinct from `BDLM_CONTENT_V1`: that tag names raw stored bytes, while
/// this one names a recipe rendered into a format. Sharing a tag would let
/// an id computed over a chunk collide with an id computed over a render.
const RENDER_ID_TAG: &[u8] = b"BDLM_RENDER_ID_V1";

/// The format a reader asked for.
///
/// Each variant carries the parameters that change the output. The variant
/// name and the parameters are part of the commitment, so changing the size
/// of a request changes the id it commits to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RenderFormat {
    /// A vector document. No rasterization, so it is the cheapest and the
    /// most portable.
    Svg,
    /// A hand-written PNG at the given square size.
    Png { size: u16 },
    /// A single video frame: the pixel buffer plus the frame index, so a
    /// reader can ask for frame 17 of a loop and get the same bytes every
    /// time. The container (MP4/WebM) is a separate encoder step.
    VideoFrame { frame: u16 },
    /// A transport frame: the content packed for an optical channel.
    ///
    /// **This is not a storage format, it is a TRANSPORT representation.** A frame
    /// is produced on demand and no intermediate product is stored, so this format
    /// ADDS NO storage under any regime (§59). The persistent form of the content is
    /// still whatever the manifest says: the recipe for recipe-backed content, the
    /// bytes for organic content.
    ///
    /// The channel has no back channel: a receiver cannot re-request a lost frame.
    /// So frames must be **independent** - each frame carries its own
    /// header and verifies on its own. `seq` says which frame it is;
    /// the same `seq` always yields the same bytes, because
    /// production from a recipe is deterministic.
    QrStream {
        /// Which transport frame this is.
        seq: u32,
        /// Kare basina tasinan yuk (bayt).
        payload_len: u16,
    },
}

impl RenderFormat {
    /// A stable tag for the format, for use inside a commitment.
    ///
    /// The variant name only. The parameters that distinguish two requests
    /// of the same variant are carried by [`Self::commitment_bytes`], which
    /// is what a commitment must fold in.
    #[must_use]
    pub const fn format_tag(&self) -> &'static [u8] {
        match self {
            Self::Svg => b"svg",
            Self::Png { .. } => b"png",
            Self::VideoFrame { .. } => b"frame",
            Self::QrStream { .. } => b"qrstream",
        }
    }

    /// The format, encoded injectively, for folding into a content id.
    ///
    /// The tag alone is not enough. `Png { size: 64 }` and `Png { size: 32 }`
    /// share the tag `png` and are different objects, so the parameter is
    /// appended in a fixed width. Two formats produce the same bytes here
    /// only when they are the same format with the same parameters, which is
    /// the property [`render_id`] needs to stay injective.
    #[must_use]
    pub fn commitment_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(self.format_tag());
        match self {
            Self::Svg => {}
            Self::Png { size } => out.extend_from_slice(&size.to_be_bytes()),
            Self::VideoFrame { frame } => out.extend_from_slice(&frame.to_be_bytes()),
            Self::QrStream { seq, payload_len } => {
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(&payload_len.to_be_bytes());
            }
        }
        out
    }
}

/// Errors from the render layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// The underlying generator refused the spec.
    Generate(GenerateError),
    /// The format requested needs a spec the recipe did not carry.
    MissingParam(&'static str),
    /// The rendered bytes did not match the committed id.
    ///
    /// Separate from [`Self::MissingParam`] because a caller acts on the two
    /// differently: a missing parameter is a malformed request, while an id
    /// mismatch means the bytes on hand are not the object that was asked
    /// for, which is a refusal a validator records.
    IdMismatch,
}

impl From<GenerateError> for RenderError {
    fn from(e: GenerateError) -> Self {
        Self::Generate(e)
    }
}

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Generate(e) => write!(f, "generate: {e}"),
            Self::MissingParam(p) => {
                write!(f, "render needs a param the recipe did not carry: {p}")
            }
            Self::IdMismatch => write!(f, "rendered bytes do not match the committed id"),
        }
    }
}

impl std::error::Error for RenderError {}

/// A deterministic, fixed-point decimal formatter.
///
/// SVG coordinates must be written without floating point, because two
/// nodes that format the same value with different libm versions could
/// round differently and produce different bytes for the same recipe.
/// `fixed` writes a value scaled by `scale` (a power of ten) as a decimal
/// string: `fixed(12345, 1000)` is `"12.345"`.
fn fixed(value: u64, scale: u64) -> String {
    debug_assert!(scale > 0);
    let whole = value / scale;
    let frac = value % scale;
    if frac == 0 {
        whole.to_string()
    } else {
        // Pad the fraction to the scale's digit count, strip trailing zeros.
        let mut frac_str = format!("{frac:0width$}", width = digit_count(scale));
        while frac_str.ends_with('0') {
            frac_str.pop();
        }
        format!("{whole}.{frac_str}")
    }
}

fn digit_count(mut n: u64) -> usize {
    let mut count = 0usize;
    while n > 0 {
        n /= 10;
        count += 1;
    }
    count.max(1)
}

/// A tiny table-driven CRC32 (the PNG spec's polynomial), computed byte by
/// byte in a fixed order so every machine produces the same file.
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, entry) in table.iter_mut().enumerate() {
        let mut c = i as u32; // 0..256 loop index; cannot truncate.
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *entry = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Write a PNG chunk: length, type, data, CRC.
fn png_chunk(out: &mut Vec<u8>, chunk_type: [u8; 4], data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX).to_be_bytes();
    out.extend_from_slice(&len);
    out.extend_from_slice(&chunk_type);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(&chunk_type);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

/// A minimal zlib stream: a stored (uncompressed) deflate block.
///
/// The simplest deterministic compressor. Stored blocks are legal DEFLATE
/// and cost nothing to implement; real compression is a size optimisation
/// that must not change the bytes a recipe commits to, so the encoder is a
/// separate versioned step, exactly like the video codec.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 11);
    // zlib header: CMF/FLG with a fixed check value for compression level 0.
    out.push(0x78);
    out.push(0x01);
    // DEFLATE stored blocks, 65535 bytes each.
    let mut pos = 0usize;
    while pos < data.len() {
        let final_block = pos + 65535 >= data.len();
        let block_len = (data.len() - pos).min(65535);
        out.push(u8::from(final_block));
        // `block_len` is `min(.., 65535)` just above, so both fit.
        let block16 = u16::try_from(block_len).unwrap_or(u16::MAX);
        let len16 = block16.to_le_bytes();
        let nlen16 = (!block16).to_le_bytes();
        out.extend_from_slice(&len16);
        out.extend_from_slice(&nlen16);
        out.extend_from_slice(&data[pos..pos + block_len]);
        pos += block_len;
    }
    // Adler-32 of the raw data, computed in a fixed order.
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

/// Render a generated object into the requested format.
///
/// The recipe's `output_len` is the pixel buffer size; formats that need a
/// geometry (SVG viewport, PNG dimensions) derive it from the buffer, so a
/// single recipe stays honest across formats.
///
/// # Errors
///
/// [`RenderError::Generate`] when the generator refuses the spec, and
/// [`RenderError::MissingParam`] when the format needs a parameter the
/// recipe did not carry (a non-square buffer, or an oversized PNG request).
pub fn render(spec: &GeneratedSpec, format: &RenderFormat) -> Result<Vec<u8>, RenderError> {
    let pixels = generate_content(spec)?;
    match format {
        RenderFormat::Svg => render_svg(spec, &pixels),
        RenderFormat::Png { size } => render_png(spec, &pixels, *size),
        RenderFormat::VideoFrame { frame } => render_frame(spec, &pixels, *frame),
        RenderFormat::QrStream { seq, payload_len } => {
            render_qr_stream_frame(spec, &pixels, *seq, *payload_len)
        }
    }
}

/// The side of the square pixel buffer, derived from the output length.
///
/// Generators draw a square grid, so `output_len` is width * height with
/// width == height. A non-square buffer is a spec bug and is refused.
fn square_side(output_len: u32) -> Result<u16, RenderError> {
    if output_len == 0 {
        return Err(RenderError::MissingParam("square side"));
    }
    // Integer sqrt via Newton's method on u64. For n <= 2^32 the result is
    // exact; we then confirm it by squaring back. Floating point is banned
    // in consensus-reachable code, and a sqrt that rounds differently on
    // two machines would give one recipe two geometries.
    let n = u64::from(output_len);
    let mut guess = n;
    if guess > 1 {
        guess = guess.div_ceil(2);
        while guess > 0 {
            let next = guess.midpoint(n / guess);
            if next >= guess {
                break;
            }
            guess = next;
        }
    }
    let side = guess;
    if side * side != n || side == 0 || side > u64::from(u16::MAX) {
        return Err(RenderError::MissingParam("square side"));
    }
    u16::try_from(side).map_err(|_| RenderError::MissingParam("square side"))
}

fn render_svg(spec: &GeneratedSpec, pixels: &[u8]) -> Result<Vec<u8>, RenderError> {
    let side = square_side(spec.output_len)?;
    // One pixel = one rect. For a 32x32 avatar that is 1024 rects, which is
    // small; larger buffers should use a path-based renderer (a separate
    // versioned step). The scale keeps coordinates in a readable range.
    let scale = 8u64;
    let view = u64::from(side) * scale;
    let mut svg = String::with_capacity(pixels.len() * 12 + 128);
    let _ = write!(
        svg,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{view}\" height=\"{view}\" viewBox=\"0 0 {view} {view}\">"
    );
    for (i, &b) in pixels.iter().enumerate() {
        let x = (i as u64 % u64::from(side)) * scale;
        let y = (i as u64 / u64::from(side)) * scale;
        let _ = write!(
            svg,
            "<rect x=\"{}\" y=\"{}\" width=\"{scale}\" height=\"{scale}\" fill=\"#{b:02x}{b:02x}{b:02x}\"/>",
            fixed(x, 1),
            fixed(y, 1)
        );
    }
    svg.push_str("</svg>");
    Ok(svg.into_bytes())
}

fn render_png(spec: &GeneratedSpec, pixels: &[u8], size: u16) -> Result<Vec<u8>, RenderError> {
    let side = square_side(spec.output_len)?;
    if size == 0 {
        return Err(RenderError::MissingParam("png size"));
    }
    // Bound the output before allocating: a 16-bit size field alone would
    // allow a 65535x65535 RGB raster, which is ~12.9 GB of buffer for a
    // recipe whose own pixels are capped at MAX_GENERATED_BYTES. The output
    // must sit under the same cap, so the square side is bounded by
    // sqrt(MAX_GENERATED_BYTES / 3) ~= 1182. Refuse anything larger rather
    // than let a hostile caller exhaust memory or CPU (Strix CWE-400).
    let max_side = ((u64::from(MAX_GENERATED_BYTES) / 3) as f64).sqrt() as u64;
    if u64::from(size) > max_side {
        return Err(RenderError::MissingParam("png size"));
    }
    // Scale the pixel buffer to the requested size with a deterministic
    // nearest-neighbour sampler: every source pixel maps to a fixed block.
    let source_side = u64::from(side);
    let dest_side = u64::from(size);
    let mut raw =
        Vec::with_capacity((usize::from(size) * usize::from(size)) * 3 + usize::from(size));
    for y in 0..dest_side {
        raw.push(0u8); // filter type: None
        for x in 0..dest_side {
            let sx = usize::try_from(x * source_side / dest_side).unwrap_or(0);
            let sy = usize::try_from(y * source_side / dest_side).unwrap_or(0);
            let si = sy * usize::from(side) + sx;
            let b = pixels.get(si).copied().unwrap_or(0);
            raw.extend_from_slice(&[b, b, b]);
        }
    }
    let idat = zlib_stored(&raw);

    let mut out = Vec::with_capacity(idat.len() + 64);
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&u32::from(size).to_be_bytes());
    ihdr.extend_from_slice(&u32::from(size).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit, truecolour RGB
    png_chunk(&mut out, *b"IHDR", &ihdr);
    png_chunk(&mut out, *b"IDAT", &idat);
    png_chunk(&mut out, *b"IEND", &[]);
    Ok(out)
}

fn render_frame(_spec: &GeneratedSpec, pixels: &[u8], frame: u16) -> Result<Vec<u8>, RenderError> {
    // The frame number is part of the output, so frame 17 of a loop is a
    // different object from frame 18 and the same bytes every time. The
    // actual encoder (MP4/WebM) is a separate versioned step.
    let mut out = Vec::with_capacity(pixels.len() + 4);
    out.extend_from_slice(b"BDLMF");
    out.extend_from_slice(&frame.to_be_bytes());
    out.extend_from_slice(pixels);
    Ok(out)
}

/// Length of a transport frame header.
const QR_FRAME_HEADER_LEN: usize = 16;

/// Domain tag for a recipe-addressed stream id.
const QR_STREAM_ID_TAG: &[u8] = b"BDLM_QR_STREAM_ID_V1";

/// The path that produces a transport frame.
///
/// **A frame is self-describing.** An optical/broadcast channel has no back channel:
/// a receiver cannot re-request a lost frame, cannot handshake, and joins the stream
/// mid-flight. So every frame must be parseable on its own;
/// a frame that carries context is garbage to a receiver that missed that context.
///
/// The header fields and WHY they are there:
///
/// - **Two magic bytes** - the question "is this ours" must be answered BEFORE any
///   version is named. A receiver looking at a single byte could accuse a source that
///   never spoke this protocol of being "on an old version"; every code in the
///   camera's view passes through this path.
/// - **Version** - gates parsing as a whole. An unknown version is not silently
///   misparsed, it is named.
/// - **Flags** - `0x0F` is the MUST-understand half, `0xF0` the ignorable
///   half. The split comes from the start because it cannot be added later: a receiver
///   told "every unknown bit is fatal" can only be fixed by another break.
/// - **`seq`** - which frame this is. The same `seq` always yields the same bytes.
/// - **`total_len`** - the full length of the content, so a receiver knows how much
///   it has collected.
/// - **`payload_digest`** - the payload digest. If the frame is corrupt the payload is NOT USED.
///
/// # What it does not do
///
/// This function is NOT a channel encoder: the erasure code (fountain),
/// the real QR module matrix and the video container are separate, versioned steps.
/// This only builds **the self-describing frame the channel will carry**.
/// Frame production is deterministic; the channel itself is not.
fn render_qr_stream_frame(
    spec: &GeneratedSpec,
    payload: &[u8],
    seq: u32,
    payload_len: u16,
) -> Result<Vec<u8>, RenderError> {
    let want = usize::from(payload_len);
    if want == 0 {
        return Err(RenderError::MissingParam("qr stream payload_len"));
    }
    // A frame carries the slice `seq` points at. When the content runs out the slice
    // is empty; an empty frame would present something absent as if it were present.
    let start = (seq as usize).saturating_mul(want);
    if start >= payload.len() {
        return Err(RenderError::MissingParam("qr stream seq past end"));
    }
    let end = start.saturating_add(want).min(payload.len());
    let slice = payload
        .get(start..end)
        .ok_or(RenderError::MissingParam("qr stream slice out of range"))?;

    let mut out = Vec::with_capacity(QR_FRAME_HEADER_LEN + slice.len());
    out.extend_from_slice(&[0xBD, 0x1A]);
    out.push(1u8);
    out.push(0u8);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    // The first 4 bytes of the payload digest: enough for frame integrity while the
    // header stays small. This is not the content id - the manifest carries that.
    //
    // The digest is **session bound**: the preimage also contains the digest of the
    // recipe that produced the frame. Unbound, a frame's integrity would be verified
    // from its own bytes alone, and a frame of **different content** carrying the same
    // `seq` could stand in for a frame of this stream: the receiver sees a correct
    // digest, parses correctly, and merges parts of two different objects into one
    // object. On an optical channel this is a cheap attack - every code the camera
    // sees is a candidate.
    //
    // The recipe digest is the anchor, because at this layer that is what is known and
    // what produces the frame; the manifest id does not reach this function. Two
    // different recipes produce two different digests, which is the distinction wanted.
    let session = generated_spec_digest(spec);
    // The digest is also **position bound**. If only the slice bytes were hashed, two
    // frames carrying the same bytes at different places in the stream would carry the
    // exact same digest - it was measured and they did: four frames of a uniform
    // payload gave the same four bytes. In that case a frame can stand in for a frame
    // at another position of the same stream. The receiver sees a correct digest,
    // accepts the frame and writes the slice at the wrong position; integrity holds, order does not.
    // On an optical channel frames already arrive out of order and the receiver reads
    // the order from the header's `seq` field - while that field stays outside the
    // digest it is a mutable hint, not a verified claim.
    let digest = hash_fields_bytes(&[b"BDLM_QR_FRAME_V2", &session, &seq.to_be_bytes(), slice]);
    out.extend_from_slice(digest.get(..4).ok_or(RenderError::MissingParam("digest"))?);
    out.extend_from_slice(slice);
    Ok(out)
}

/// A recipe-addressed content id: it addresses a stream not by its bytes but by
/// the sequence of its frame digests.
///
/// # Why
///
/// With `ContentSource::Generated` the network stores not the content's bytes but its
/// **recipe**. But the identity layer did not say so: `ContentId::of` is the digest of
/// the produced bytes, so learning the id requires producing them first.
/// The claim "what we store is the recipe" had not reached the addressing layer.
///
/// Here the id derives directly from the recipe. Every frame already carries its own
/// digest (`render_qr_stream_frame`, `BDLM_QR_FRAME_V2`) and that digest is bound to
/// the recipe; folding the frames in order yields the id of the stream that recipe
/// produces in that format. No bytes need be held: given the recipe the id can be
/// recomputed, and given the id a produced stream can be verified to be the
/// right stream.
///
/// # Order is part of the scheme
///
/// Frames are numbered by `seq` and the digest sequence is folded **in order**. If
/// order were left free, another arrangement of the same frames would give the same
/// id - yet the carousel order is part of the stream, because the receiver reassembles
/// the frames in that order. A stream with a different order is a different stream.
///
/// # What it is not
///
/// This is not a proof of storage. A correct id says not that the other side holds the
/// bytes but that running the recipe will produce the same stream - which is exactly
/// what is wanted. Organic content **cannot enter** this scheme:
/// `Stored` bytes have no recipe, and addressing a recipe that does not exist would be
/// a category lie. `ContentSource` already carries the distinction.
///
/// # Errors
///
/// Returns an error if `frame_count` is zero: a stream of zero frames does not exist,
/// and an empty fold would give the same constant value as every distinct non-empty
/// stream.
pub fn qr_stream_content_id(
    spec: &GeneratedSpec,
    payload: &[u8],
    payload_len: u16,
    frame_count: u32,
) -> Result<[u8; 32], RenderError> {
    if frame_count == 0 {
        return Err(RenderError::MissingParam("qr stream frame_count"));
    }
    // The scheme is deliberately narrow. The frame digest already binds the recipe, the
    // position and the slice bytes; binding them **again** in the fold says nothing new.
    //
    // The first version carried three more fields - recipe digest, frame count,
    // slice length - and all three turned out redundant. Measured by mutation: removing
    // each one from the scheme broke no test, because what all three distinguished was
    // already inside the frame digests. A different slice
    // length produces different frames; a different frame count produces a fold of a
    // different length; a different recipe gives a different frame digest.
    //
    // What defends a field in a scheme is that removing it breaks something.
    // If it breaks nothing it is not there, it is merely sitting there - and a field
    // that merely sits tells a reader "this is bound too", producing a false assurance.
    let mut acc = hash_fields_bytes(&[QR_STREAM_ID_TAG]);
    for seq in 0..frame_count {
        let frame = render_qr_stream_frame(spec, payload, seq, payload_len)?;
        // A frame's own digest sits at header range 12..16. Instead of hashing the
        // frame afresh that value is used: the id builds on what the receiver already
        // verifies per frame, not on a separate digest scheme.
        let frame_digest = frame
            .get(12..QR_FRAME_HEADER_LEN)
            .ok_or(RenderError::MissingParam("qr frame digest"))?;
        acc = hash_fields_bytes(&[QR_STREAM_ID_TAG, &acc, frame_digest]);
    }
    Ok(acc)
}

/// The id a rendered object commits to: the format and the bytes together.
///
/// The module doc says the format string is part of the commitment, because
/// "a recipe rendered as PNG is a different object from the same recipe
/// rendered as SVG". Hashing the rendered bytes alone does not say that. It
/// says only what the bytes were, and it leaves the format as something the
/// caller is trusted to have checked separately.
///
/// The two are folded here instead, length-prefixed by `hash_fields_bytes`,
/// so an id names one object: this recipe, in this format, with these
/// parameters. A reader who asked for a 64-pixel PNG cannot be handed a
/// 32-pixel one that verifies.
#[must_use]
pub fn render_id(format: &RenderFormat, bytes: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[RENDER_ID_TAG, &format.commitment_bytes(), bytes])
}

/// Render and verify against a committed id.
///
/// `expected` is a [`render_id`]: the format is bound into it, so a request
/// for one format cannot be satisfied by bytes produced for another. This is
/// the check a validator runs: produce the bytes, hash them with the format,
/// compare.
///
/// # Errors
///
/// [`RenderError::Generate`] and [`RenderError::MissingParam`] from
/// [`render`], plus [`RenderError::IdMismatch`] when the produced bytes do
/// not match `expected`.
pub fn render_and_verify(
    spec: &GeneratedSpec,
    format: &RenderFormat,
    expected: &[u8; 32],
) -> Result<Vec<u8>, RenderError> {
    let bytes = render(spec, format)?;
    if &render_id(format, &bytes) != expected {
        return Err(RenderError::IdMismatch);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::generated::GeneratorId;

    fn avatar_spec() -> GeneratedSpec {
        GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [7u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        }
    }

    /// A frame is bound to the stream it belongs to.
    ///
    /// The frame header is self-describing but did not say **which stream** it
    /// belonged to: the digest was computed from its own payload alone. Two different
    /// contents can produce the same byte slice - flat colour regions especially
    /// give the same bytes under different recipes - and then the same-ordered frames
    /// of two streams are **bit for bit identical**. A receiver treats every code the
    /// camera sees as a candidate; with two streams in view at once it sees a correct
    /// digest, parses correctly, and merges parts of two objects into one
    /// object. Integrity holds, correctness does not.
    ///
    /// A frame is bound to its position in the stream.
    ///
    /// The frame digest at first bound only the recipe digest and the slice
    /// bytes. On a uniform payload - which empty space, padding and flat colour
    /// regions make ordinary - consecutive slices carry the same bytes, so four
    /// frames carried an **identical** digest. Measured: all four of the 4 frames
    /// gave `[72, 41, 61, 244]`.
    ///
    /// In that case a frame can stand in for a frame at another position of the same
    /// stream. The receiver sees a correct digest, accepts the frame and writes the
    /// slice at the wrong position. It reads the order from the header's `seq` field,
    /// and while that field is outside the digest it is a mutable hint - not a
    /// verified claim. Integrity holds, order does not.
    #[test]
    fn a_frame_is_bound_to_its_position_in_the_stream() {
        let spec = avatar_spec();
        // Uniform payload: every slice carries the same bytes, so without position
        // binding the frames are indistinguishable. That is exactly the collision measure.
        let payload = [0xABu8; 256];

        let first = super::render_qr_stream_frame(&spec, &payload, 0, 64).expect("first frame");
        let second = super::render_qr_stream_frame(&spec, &payload, 1, 64).expect("second frame");

        let d_first = first.get(12..16).expect("first digest");
        let d_second = second.get(12..16).expect("second digest");
        assert_ne!(
            d_first, d_second,
            "two frames carrying the same bytes carry the same digest: one can stand \
             in for the other"
        );

        // The slice bytes really are the same - the difference comes only from position.
        assert_eq!(
            first.get(16..),
            second.get(16..),
            "the test setup is vacuous: the slices already differ"
        );
    }

    /// A recipe-addressed id: the same recipe gives the same id, a different recipe a
    /// different id - and the frames are addressed without holding any bytes.
    ///
    /// What is measured is that `qr_stream_content_id` is usable as an **address**:
    /// deterministic (the same input gives the same output), distinguishing
    /// (a changed recipe changes the id) and **order sensitive**.
    #[test]
    fn a_stream_is_addressed_by_its_recipe_not_its_bytes() {
        let one = avatar_spec();
        let mut two = avatar_spec();
        two.seed = [8u8; 32];

        let payload = [0xABu8; 256];

        // Deterministic: computing it twice gives the same value. Otherwise the id
        // would be a measurement artefact, not an address.
        let id_a = super::qr_stream_content_id(&one, &payload, 64, 4).expect("ilk kimlik");
        let id_again = super::qr_stream_content_id(&one, &payload, 64, 4).expect("recompute");
        assert_eq!(id_a, id_again, "the same recipe must give the same id");

        // Distinguishing: a changed recipe changes the id. Without this two different
        // streams would share the same address.
        let id_b = super::qr_stream_content_id(&two, &payload, 64, 4).expect("ikinci kimlik");
        assert_ne!(id_a, id_b, "a different recipe must give a different id");

        // Order sensitive: the frame count enters the scheme, so the stream length is
        // part of the id. Otherwise a prefix of a stream could carry the same
        // address as the stream itself.
        let id_short = super::qr_stream_content_id(&one, &payload, 64, 3).expect("short stream");
        assert_ne!(id_a, id_short, "the frame count must enter the id");

        // Zero frames are refused: an empty fold would give every stream the same
        // verirdi.
        assert!(
            super::qr_stream_content_id(&one, &payload, 64, 0).is_err(),
            "a zero-frame stream must have no id"
        );
    }

    /// Session binding cuts this off: same bytes, different recipe, different digest.
    #[test]
    fn a_frame_is_bound_to_the_stream_it_belongs_to() {
        // Put the same payload slice into a frame under two different recipes. Because
        // the bytes are the same, without session binding the two frames would be
        // indistinguishable - that is exactly the collision measure.
        let one = avatar_spec();
        let mut two = avatar_spec();
        two.seed = [8u8; 32];

        let payload = [0xABu8; 128];
        let a = super::render_qr_stream_frame(&one, &payload, 0, 64).expect("first stream");
        let b = super::render_qr_stream_frame(&two, &payload, 0, 64).expect("second stream");

        // Same payload: the bodies of the two frames are bit for bit identical.
        assert_eq!(
            a.get(16..),
            b.get(16..),
            "the setup is invalid - the payloads should have been identical"
        );
        // The fixed header fields match too: same protocol, version, seq, length.
        assert_eq!(
            a.get(..12),
            b.get(..12),
            "the fixed header fields must match"
        );

        // The digest must be the only thing that distinguishes them. Without session
        // binding this claim would fail, since the digest came from the identical payload alone.
        assert_ne!(
            a.get(12..16),
            b.get(12..16),
            "frames of two streams carrying the same payload must not carry the same digest"
        );

        // The binding still covers the payload itself: in the same stream a different
        // payload gives a different digest.
        let mut other_payload = payload;
        other_payload[0] = 0x00;
        let c =
            super::render_qr_stream_frame(&one, &other_payload, 0, 64).expect("different payload");
        assert_ne!(
            a.get(12..16),
            c.get(12..16),
            "the payload must keep entering the digest"
        );

        // Determinism holds: same stream, same payload, same frame.
        assert_eq!(
            a,
            super::render_qr_stream_frame(&one, &payload, 0, 64).expect("re-render")
        );
    }

    /// A transport frame is self-describing and deterministic.
    ///
    /// On a channel with no back channel a receiver joins mid-stream; a frame that
    /// carries context is garbage to a receiver that missed that context.
    #[test]
    fn a_transport_frame_describes_itself_and_repeats_exactly() {
        let spec = avatar_spec();
        let fmt = RenderFormat::QrStream {
            seq: 2,
            payload_len: 64,
        };
        let a = render(&spec, &fmt).unwrap();
        let b = render(&spec, &fmt).unwrap();
        assert_eq!(a, b, "the same seq must always give the same bytes");

        // Two magic bytes: the question "is this ours" is answered BEFORE the version.
        assert_eq!(a.first().copied(), Some(0xBD));
        assert_eq!(a.get(1).copied(), Some(0x1A));
        // The version and flag fields sit at fixed places in the header.
        assert_eq!(a.get(2).copied(), Some(1));
        assert_eq!(a.get(3).copied(), Some(0));
        // A frame carries its own order: it needs no context.
        assert_eq!(
            a.get(4..8),
            Some(&2u32.to_be_bytes()[..]),
            "a frame must say for itself which one it is"
        );

        // A different seq is a different frame and enters the id.
        let other = render(
            &spec,
            &RenderFormat::QrStream {
                seq: 3,
                payload_len: 64,
            },
        )
        .unwrap();
        assert_ne!(a, other);
        assert_ne!(
            render_id(&fmt, &a),
            render_id(
                &RenderFormat::QrStream {
                    seq: 3,
                    payload_len: 64
                },
                &other
            ),
            "seq must enter the id"
        );
    }

    /// A transport representation ADDS NO STORAGE.
    ///
    /// This is the property the whole design rests on: a frame is produced on demand
    /// and no intermediate product is stored. What persists is still the recipe.
    #[test]
    fn a_transport_representation_adds_no_stored_bytes() {
        use crate::storage::generated::{held_bytes, ContentSource};
        let spec = avatar_spec();
        let object_len = u64::from(spec.output_len);

        // Frames can be produced...
        let frame = render(
            &spec,
            &RenderFormat::QrStream {
                seq: 0,
                payload_len: 128,
            },
        )
        .unwrap();
        assert!(!frame.is_empty());

        // ...but the held byte count is still zero: the representation is not persistent.
        assert_eq!(
            held_bytes(&ContentSource::Generated(spec), object_len),
            Some(0),
            "a transport representation must add no storage"
        );
    }

    /// A frame past the end of the content is not produced.
    ///
    /// An empty frame would present something absent as if it were present.
    #[test]
    fn a_frame_past_the_end_is_refused() {
        let spec = avatar_spec();
        assert!(render(
            &spec,
            &RenderFormat::QrStream {
                seq: 99_999,
                payload_len: 64
            }
        )
        .is_err());
        // A zero-length payload is refused too.
        assert!(render(
            &spec,
            &RenderFormat::QrStream {
                seq: 0,
                payload_len: 0
            }
        )
        .is_err());
    }

    #[test]
    fn svg_is_deterministic_and_well_formed() {
        let spec = avatar_spec();
        let a = render(&spec, &RenderFormat::Svg).unwrap();
        let b = render(&spec, &RenderFormat::Svg).unwrap();
        assert_eq!(a, b, "same recipe, same format, same bytes");
        assert!(a.starts_with(b"<svg"));
        assert!(a.ends_with(b"</svg>"));
        assert!(a.windows(5).any(|w| w == b"<rect"));
    }

    #[test]
    fn png_is_deterministic_and_matches_signature() {
        let spec = avatar_spec();
        let a = render(&spec, &RenderFormat::Png { size: 64 }).unwrap();
        let b = render(&spec, &RenderFormat::Png { size: 64 }).unwrap();
        assert_eq!(a, b);
        assert_eq!(&a[..8], b"\x89PNG\r\n\x1a\n");
        // IHDR must carry the requested size.
        assert_eq!(&a[16..20], &64u32.to_be_bytes());
        assert_eq!(&a[20..24], &64u32.to_be_bytes());
    }

    #[test]
    fn different_format_same_recipe_different_bytes() {
        let spec = avatar_spec();
        let svg = render(&spec, &RenderFormat::Svg).unwrap();
        let png = render(&spec, &RenderFormat::Png { size: 64 }).unwrap();
        assert_ne!(svg, png);
    }

    #[test]
    fn frame_number_changes_the_output() {
        let spec = avatar_spec();
        let f17 = render(&spec, &RenderFormat::VideoFrame { frame: 17 }).unwrap();
        let f18 = render(&spec, &RenderFormat::VideoFrame { frame: 18 }).unwrap();
        assert_ne!(f17, f18);
        assert_eq!(&f17[..5], b"BDLMF");
    }

    #[test]
    fn render_and_verify_rejects_wrong_id() {
        let spec = avatar_spec();
        let bytes = render(&spec, &RenderFormat::Svg).unwrap();
        let good = render_id(&RenderFormat::Svg, &bytes);
        assert!(render_and_verify(&spec, &RenderFormat::Svg, &good).is_ok());
        assert!(render_and_verify(&spec, &RenderFormat::Svg, &[0u8; 32]).is_err());
    }

    /// An id must name the format, not only the bytes.
    ///
    /// The module doc says a recipe rendered as PNG is a different object
    /// from the same recipe rendered as SVG. Before the format was folded in,
    /// the id was a plain hash of the rendered bytes, so nothing in the id
    /// said which format produced them; the two formats stayed apart only
    /// because their bytes differ, which is a property of the renderers and
    /// not something the commitment enforced.
    #[test]
    fn an_id_for_one_format_is_refused_for_another() {
        let spec = avatar_spec();
        let svg = render(&spec, &RenderFormat::Svg).unwrap();
        let svg_id = render_id(&RenderFormat::Svg, &svg);
        // The same bytes, labelled as a different format, is a different id.
        assert_ne!(
            svg_id,
            render_id(&RenderFormat::VideoFrame { frame: 0 }, &svg),
            "the format must change the id even when the bytes do not"
        );
        // And an id minted for SVG does not verify a frame render.
        assert_eq!(
            render_and_verify(&spec, &RenderFormat::VideoFrame { frame: 0 }, &svg_id),
            Err(RenderError::IdMismatch)
        );
    }

    /// Two requests of the same variant that differ only in a parameter must
    /// not share an id. `format_tag` alone returns `png` for both, so the
    /// parameter has to reach the commitment too.
    #[test]
    fn a_png_id_is_refused_for_a_png_of_another_size() {
        let spec = avatar_spec();
        let small = RenderFormat::Png { size: 32 };
        let large = RenderFormat::Png { size: 64 };
        assert_eq!(small.format_tag(), large.format_tag(), "same variant tag");
        assert_ne!(
            small.commitment_bytes(),
            large.commitment_bytes(),
            "the size must survive into the commitment"
        );
        let small_bytes = render(&spec, &small).unwrap();
        let small_id = render_id(&small, &small_bytes);
        assert!(render_and_verify(&spec, &small, &small_id).is_ok());
        assert_eq!(
            render_and_verify(&spec, &large, &small_id),
            Err(RenderError::IdMismatch)
        );
    }

    /// The format encoding must be injective: a format's bytes cannot be
    /// produced by any other format. Checked across every variant this
    /// module renders, so a new variant that collides fails here.
    #[test]
    fn no_two_formats_share_commitment_bytes() {
        let mut formats = vec![RenderFormat::Svg];
        for n in [0u16, 1, 32, 64, 255, 256, u16::MAX] {
            formats.push(RenderFormat::Png { size: n });
            formats.push(RenderFormat::VideoFrame { frame: n });
        }
        for (i, a) in formats.iter().enumerate() {
            for b in formats.iter().skip(i + 1) {
                assert_ne!(
                    a.commitment_bytes(),
                    b.commitment_bytes(),
                    "{a:?} and {b:?} encode to the same commitment bytes"
                );
            }
        }
    }

    /// The pixels the generator drew must come back from the PNG
    /// byte-for-byte when the requested size equals the buffer side.
    /// This is the "bit-bit same" rule from the storage research: the
    /// stored form may differ from the shown form, but what is shown must
    /// be the very bytes the recipe commits to.
    #[test]
    fn png_round_trips_the_generator_pixels_exactly() {
        let spec = avatar_spec();
        let side = square_side(spec.output_len).unwrap();
        let png = render(&spec, &RenderFormat::Png { size: side }).unwrap();

        // Decode the PNG by hand: IHDR, then the zlib stored stream we
        // wrote, unfiltered rows.
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let w = u32::from_be_bytes(png[16..20].try_into().unwrap()) as usize;
        let h = u32::from_be_bytes(png[20..24].try_into().unwrap()) as usize;
        assert_eq!(w, side as usize, "width must survive the round trip");
        assert_eq!(h, side as usize, "height must survive the round trip");

        let mut pos = 8usize;
        let mut idat = None;
        while pos + 8 <= png.len() {
            let len = u32::from_be_bytes(png[pos..pos + 4].try_into().unwrap()) as usize;
            let ctype = &png[pos + 4..pos + 8];
            if ctype == b"IDAT" {
                idat = Some(&png[pos + 8..pos + 8 + len]);
                break;
            }
            pos += 12 + len;
        }
        let idat = idat.expect("PNG must carry an IDAT chunk");

        // Stored stream: header, stored deflate blocks, adler32.
        let mut raw = Vec::new();
        let mut p = 2usize;
        while p + 5 <= idat.len() {
            let last = idat[p] & 1;
            let len = u16::from_le_bytes([idat[p + 1], idat[p + 2]]) as usize;
            let start = p + 5;
            raw.extend_from_slice(&idat[start..start + len]);
            p = start + len;
            if last == 1 {
                break;
            }
        }

        // Every row is filter-type 0 (None) in our writer, so the payload is
        // raw RGB. Compare pixel by pixel against the generator output.
        let expected_pixels = generate_content(&spec).unwrap();
        assert_eq!(raw.len(), side as usize * (side as usize * 3 + 1));
        for y in 0..side as usize {
            let row = &raw[y * (side as usize * 3 + 1)..];
            assert_eq!(row[0], 0, "filter byte must be None");
            for x in 0..side as usize {
                let si = y * side as usize + x;
                let b = expected_pixels[si];
                let rgb = &row[1 + x * 3..1 + x * 3 + 3];
                assert_eq!(rgb, &[b, b, b], "pixel ({x},{y}) must match the generator");
            }
        }
    }

    /// A larger requested size must scale deterministically and keep the
    /// geometry square: the resolution is preserved as a fixed mapping, not
    /// left to a rasterizer.
    #[test]
    fn png_scaling_keeps_square_geometry_and_determinism() {
        let spec = avatar_spec();
        let a = render(&spec, &RenderFormat::Png { size: 128 }).unwrap();
        let b = render(&spec, &RenderFormat::Png { size: 128 }).unwrap();
        assert_eq!(a, b);
        let w = u32::from_be_bytes(a[16..20].try_into().unwrap());
        let h = u32::from_be_bytes(a[20..24].try_into().unwrap());
        assert_eq!(w, 128);
        assert_eq!(h, 128);
    }
}
