//! Render a generated object into the format a reader asked for.
//!
//! WIRING: unwired - this is the B.U.D. "recipe to bytes" format surface;
//! nothing in production requests a render yet, so the module is reached by
//! its own tests and by the re-export in `mod.rs` only. The validator-facing
//! render/verify path (Layer 3) will be the first caller.
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

use crate::storage::content_id::ContentId;
use crate::storage::generated::{
    generate_content, GenerateError, GeneratedSpec, MAX_GENERATED_BYTES,
};

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
}

impl RenderFormat {
    /// A stable tag for the format, for use inside a commitment.
    #[must_use]
    pub const fn format_tag(&self) -> &'static [u8] {
        match self {
            Self::Svg => b"svg",
            Self::Png { .. } => b"png",
            Self::VideoFrame { .. } => b"frame",
        }
    }
}

/// Errors from the render layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// The underlying generator refused the spec.
    Generate(GenerateError),
    /// The format requested needs a spec the recipe did not carry.
    MissingParam(&'static str),
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
        let mut c = u32::try_from(i).expect("table index < 256");
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
    let len = u32::try_from(data.len())
        .expect("chunk < 4 GiB")
        .to_be_bytes();
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
        let len16 = u16::try_from(block_len)
            .expect("stored block <= 65535")
            .to_le_bytes();
        let nlen16 = (!u16::try_from(block_len).expect("stored block <= 65535")).to_le_bytes();
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
    Ok(u16::try_from(side).expect("square side <= u16::MAX checked above"))
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
            let sx = usize::try_from(x * source_side / dest_side).expect("pixel index fits");
            let sy = usize::try_from(y * source_side / dest_side).expect("pixel index fits");
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

/// Render and verify against a committed id.
///
/// `expected` must be the id of the *rendered* bytes: the recipe id commits
/// to the format too, so `format_tag()` is folded into the expected id by
/// the caller. This is the check a validator runs: produce the bytes, hash
/// them, compare.
///
/// # Errors
///
/// [`RenderError::Generate`] and [`RenderError::MissingParam`] from
/// [`render`], plus [`RenderError::MissingParam`] when the produced bytes
/// do not match `expected`.
pub fn render_and_verify(
    spec: &GeneratedSpec,
    format: &RenderFormat,
    expected: &[u8; 32],
) -> Result<Vec<u8>, RenderError> {
    let bytes = render(spec, format)?;
    let produced = ContentId::of(&bytes);
    if produced.as_bytes() != expected {
        return Err(RenderError::MissingParam("id mismatch"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::content_id::ContentId;
    use crate::storage::generated::GeneratorId;

    fn avatar_spec() -> GeneratedSpec {
        GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [7u8; 32],
            output_len: 32 * 32,
            step_budget: 1_000_000,
        }
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
        let good = ContentId::of(&bytes);
        assert!(render_and_verify(&spec, &RenderFormat::Svg, good.as_bytes()).is_ok());
        assert!(render_and_verify(&spec, &RenderFormat::Svg, &[0u8; 32]).is_err());
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
