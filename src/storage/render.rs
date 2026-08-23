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
    /// Bir tasima karesi: icerigin optik kanal icin paketlenmis hali.
    ///
    /// **Bu bir depolama bicimi degil, bir TASIMA temsilidir.** Kare talep
    /// aninda uretilir, hicbir ara urun saklanmaz - dolayisiyla bu format
    /// hicbir rejimde depolama EKLEMEZ (§59). Icerigin kalici hali yine
    /// manifest'in soyledigi seydir: tarifli icerikte tarif, organik
    /// icerikte baytlar.
    ///
    /// Kanal geri kanalsizdir: alici kayip kareyi yeniden isteyemez. Bu
    /// yuzden kareler **bagimsiz** olmak zorundadir - her kare kendi
    /// basligini tasir ve tek basina dogrulanir. `seq` kacinci kare
    /// oldugunu soyler; ayni `seq` her zaman ayni baytlari verir, cunku
    /// uretim tariften belirlenimlidir.
    QrStream {
        /// Kacinci tasima karesi.
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

/// Tasima karesi basliginin uzunlugu.
const QR_FRAME_HEADER_LEN: usize = 16;

/// Tasima karesi ureten yol.
///
/// **Kare kendini tanimlar.** Optik/yayin kanalinda geri kanal yoktur: alici
/// kayip bir kareyi yeniden isteyemez, el sikisma yapamaz, akisa ortasindan
/// katilir. Bu yuzden her kare tek basina ayristirilabilir olmak zorundadir;
/// baglam tasiyan bir kare, o baglami kaciran alici icin coptur.
///
/// Baslik alanlari ve NEDEN oradalar:
///
/// - **Iki sihirli bayt** - "bu bizim mi" sorusu, herhangi bir surum
///   adlandirilmadan ONCE cevaplanmali. Tek bayta bakan bir alici, hicbir
///   zaman bu protokolu konusmamis bir kaynagi "surumun eski" diye
///   suclayabilir; kamera goruntusundeki her kod bu yoldan gecer.
/// - **Surum** - ayristirmayi butunuyle kapiya baglar. Bilinmeyen surum
///   sessizce yanlis ayristirilmaz, adlandirilir.
/// - **Bayraklar** - `0x0F` anlasilmasi ZORUNLU yari, `0xF0` yok sayilabilir
///   yari. Bolme bastan gelir cunku sonradan eklenemez: "her bilinmeyen bit
///   olumcul" denmis bir aliciyi ancak yeni bir kirilma duzeltir.
/// - **`seq`** - kacinci kare. Ayni `seq` her zaman ayni baytlari verir.
/// - **`total_len`** - icerigin tam uzunlugu; alici ne kadarini topladigini
///   bilir.
/// - **`payload_digest`** - yukun ozeti. Kare bozuksa yuk KULLANILMAZ.
///
/// # Ne yapmaz
///
/// Bu fonksiyon bir kanal kodlayici DEGILDIR: silinti kodu (fountain),
/// gercek QR modul matrisi ve video konteyneri ayri, surumlenmis adimlardir.
/// Burasi yalnizca **kanalin tasiyacagi kendini-tanimlayan kareyi** kurar.
/// Kare uretimi belirlenimlidir; kanalin kendisi degildir.
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
    // Kare `seq`'in gosterdigi dilimi tasir. Icerik bittiginde dilim bos
    // kalir; bos bir kare, olmayan bir seyi varmis gibi gosterirdi.
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
    // Yuk ozetinin ilk 4 bayti: kare butunlugu icin yeterli, baslik kucuk
    // kalir. Icerik kimligi bu degildir - onu manifest tasir.
    //
    // Ozet **oturuma bagli**: on-goruntu, kareyi ureten tarifin ozetini de
    // iceriyor. Bagli olmasaydi bir karenin butunlugu yalnizca kendi
    // baytlarindan dogrulanirdi, ve ayni `seq` degerini tasiyan **baska bir
    // icerigin** karesi bu akisin karesi yerine gecebilirdi: alici dogru bir
    // ozet gorur, dogru ayristirir ve iki farkli nesnenin parcalarini tek
    // nesne diye birlestirir. Optik kanalda bu ucuz bir saldiri - kameranin
    // gordugu her kod aday.
    //
    // Cape tarif ozeti, cunku bu katmanda bilinen ve kareyi ureten sey odur;
    // manifest kimligi bu fonksiyona ulasmiyor. Iki farkli tarif iki farkli
    // ozet uretir, ki aranan ayirt etme budur.
    let session = generated_spec_digest(spec);
    let digest = hash_fields_bytes(&[b"BDLM_QR_FRAME_V2", &session, slice]);
    out.extend_from_slice(digest.get(..4).ok_or(RenderError::MissingParam("digest"))?);
    out.extend_from_slice(slice);
    Ok(out)
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

    /// Kare, ait oldugu akisa baglidir.
    ///
    /// Kare basligi kendini tanimlar ama **hangi akisa** ait oldugunu
    /// soylemiyordu: ozet yalnizca kendi yukunden hesaplaniyordu. Iki farkli
    /// icerik ayni bayt dilimini uretebilir - ozellikle duz renkli bolgeler
    /// farkli tariflerde ayni baytlari verir - ve o durumda iki akisin ayni
    /// sirali kareleri **bit bit ayni** olur. Alici, kameranin gordugu her
    /// kodu aday sayar; iki akis ayni anda goruntudeyse dogru bir ozet
    /// gorur, dogru ayristirir ve iki nesnenin parcalarini tek nesne diye
    /// birlestirir. Butunluk korunur, dogruluk korunmaz.
    ///
    /// Oturum baglamasi bunu keser: ayni baytlar, farkli tarif, farkli ozet.
    #[test]
    fn a_frame_is_bound_to_the_stream_it_belongs_to() {
        // Ayni yuk dilimini iki farkli tarif altinda kareye koy. Baytlar
        // ayni oldugu icin, oturum baglamasi olmadan iki kare ayirt
        // edilemezdi - carpismanin tam olarak olcusu bu.
        let one = avatar_spec();
        let mut two = avatar_spec();
        two.seed = [8u8; 32];

        let payload = [0xABu8; 128];
        let a = super::render_qr_stream_frame(&one, &payload, 0, 64).expect("ilk akis");
        let b = super::render_qr_stream_frame(&two, &payload, 0, 64).expect("ikinci akis");

        // Yuk ayni: iki karenin govdesi bit bit ayni.
        assert_eq!(
            a.get(16..),
            b.get(16..),
            "kurulum gecerli degil - yukler ayni olmaliydi"
        );
        // Sabit baslik alanlari da ayni: ayni protokol, surum, seq, uzunluk.
        assert_eq!(
            a.get(..12),
            b.get(..12),
            "sabit baslik alanlari ayni olmali"
        );

        // Ayirt eden tek sey ozet olmali. Oturum baglamasi olmasaydi bu
        // iddia dusetdi, cunku ozet yalnizca ayni olan yukten hesaplanirdi.
        assert_ne!(
            a.get(12..16),
            b.get(12..16),
            "ayni yuku tasiyan iki akisin karesi ayni ozeti tasimamali"
        );

        // Baglanma yukun kendisini de kapsamaya devam ediyor: ayni akista
        // farkli yuk farkli ozet.
        let mut other_payload = payload;
        other_payload[0] = 0x00;
        let c = super::render_qr_stream_frame(&one, &other_payload, 0, 64).expect("farkli yuk");
        assert_ne!(
            a.get(12..16),
            c.get(12..16),
            "yuk ozete girmeye devam etmeli"
        );

        // Belirlenimlilik korunuyor: ayni akis, ayni yuk, ayni kare.
        assert_eq!(
            a,
            super::render_qr_stream_frame(&one, &payload, 0, 64).expect("yeniden uretim")
        );
    }

    /// Tasima karesi kendini tanimlar ve belirlenimlidir.
    ///
    /// Geri kanalsiz bir kanalda alici akisa ortasindan katilir; baglam
    /// tasiyan bir kare o baglami kaciran alici icin coptur.
    #[test]
    fn a_transport_frame_describes_itself_and_repeats_exactly() {
        let spec = avatar_spec();
        let fmt = RenderFormat::QrStream {
            seq: 2,
            payload_len: 64,
        };
        let a = render(&spec, &fmt).unwrap();
        let b = render(&spec, &fmt).unwrap();
        assert_eq!(a, b, "ayni seq her zaman ayni baytlari vermeli");

        // Iki sihirli bayt: "bu bizim mi" sorusu surumden ONCE cevaplanir.
        assert_eq!(a.first().copied(), Some(0xBD));
        assert_eq!(a.get(1).copied(), Some(0x1A));
        // Surum ve bayrak alanlari basligin sabit yerinde.
        assert_eq!(a.get(2).copied(), Some(1));
        assert_eq!(a.get(3).copied(), Some(0));
        // Kare kendi sirasini tasir: baglam gerektirmez.
        assert_eq!(
            a.get(4..8),
            Some(&2u32.to_be_bytes()[..]),
            "kare kacinci oldugunu kendi soylemeli"
        );

        // Farkli seq farkli karedir ve kimlige girer.
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
            "seq kimlige girmeli"
        );
    }

    /// Tasima temsili DEPOLAMA EKLEMEZ.
    ///
    /// Bu, tum tasarimin dayandigi ozellik: kare talep aninda uretilir ve
    /// hicbir ara urun saklanmaz. Kalici olan sey yine tariftir.
    #[test]
    fn a_transport_representation_adds_no_stored_bytes() {
        use crate::storage::generated::{held_bytes, ContentSource};
        let spec = avatar_spec();
        let object_len = u64::from(spec.output_len);

        // Kareler uretilebiliyor...
        let frame = render(
            &spec,
            &RenderFormat::QrStream {
                seq: 0,
                payload_len: 128,
            },
        )
        .unwrap();
        assert!(!frame.is_empty());

        // ...ama tutulan bayt hala sifir: temsil kalici degil.
        assert_eq!(
            held_bytes(&ContentSource::Generated(spec), object_len),
            Some(0),
            "tasima temsili depolama eklememeli"
        );
    }

    /// Icerigin sonunu gecen kare uretilmez.
    ///
    /// Bos bir kare, olmayan bir seyi varmis gibi gosterirdi.
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
        // Sifir uzunluklu yuk de reddedilir.
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
