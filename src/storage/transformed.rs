//! A0 - 2.0 → 3.0 transform contract (plan §CH A0 / §CJ.6).
//!
//! User product: content is **transformed** (format + ops) before the Three
//! QR-video pipe. This module is the single mouth: classify → optional
//! shrink-only zlib → pin sha256 → [`TransformedPayload`].
//!
//! [`TransformedPayload::verify_hash`] is the digest half of the A1 handoff:
//! `three_pipe::encode_plain` refuses a payload whose body no longer matches
//! the pinned sha256 before the bytes move into the packed carousel. That path
//! is not yet reachable from a binary, so the guard counts as unwired until the
//! reveal session gains a caller.
//!
//! Real 2.0 codecs elsewhere still exist; new call sites must enter here so
//! 3.0 never greps scattered helpers. Entropy-coded types **do not** try zlib
//! (K-QR-SIKISTIR / şartname §16).

use crate::core::hash::calculate_hash_bytes;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

/// Flags describing how the bytes were produced before A1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct CodecFlags(pub u32);

impl CodecFlags {
    /// No special marking.
    pub const NONE: Self = Self(0);
    /// Input was already entropy-coded (jpeg/mp4/zip/cipher) - zlib not tried.
    pub const ENTROPY_CODED: Self = Self(1 << 0);
    /// This transform applied shrink-only zlib.
    pub const PRE_SHRUNK: Self = Self(1 << 1);
    /// Bytes are ciphertext (G1 seal typically follows).
    pub const CIPHERTEXT: Self = Self(1 << 2);
    /// Caller declared organic compressible (text/json/…).
    pub const ORGANIC_COMPRESSIBLE: Self = Self(1 << 3);

    /// Bit test.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Union.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Content class for transform policy (şartname format taraması özeti).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ContentClass {
    /// Unknown - try zlib-if-shrinks.
    Generic = 0,
    /// utf8 / json / xml / plain - zlib likely helps.
    TextOrganic = 1,
    /// Already compressed media container.
    EntropyMedia = 2,
    /// Archive / zip / gzip / zstd payload.
    EntropyArchive = 3,
    /// Caller-sealed ciphertext.
    Ciphertext = 4,
    /// Generative recipe wire (catalogue) - usually tiny; still may zlib.
    RecipeWire = 5,
    /// SVG / XML vector document - organic text underneath.
    VectorOrganic = 6,
    /// Raw / lightly packed bitmap (BMP) - piece-constant, zlib helps.
    RasterFlat = 7,
    /// PCM audio (WAV) - low entropy samples, zlib helps.
    AudioPcm = 8,
    /// Office / OOXML package - zip container but measurably shrinkable.
    DocumentOrganic = 9,
    /// Executable image (ELF / PE) - zlib refused.
    Exec = 10,
}

impl ContentClass {
    /// Sniff a few magic bytes + optional MIME hint.
    #[must_use]
    pub fn classify(bytes: &[u8], mime_hint: Option<&str>) -> Self {
        if let Some(m) = mime_hint {
            let m = m.to_ascii_lowercase();
            if m.starts_with("text/")
                || m.contains("json")
                || m.contains("xml")
                || m == "application/javascript"
            {
                return Self::TextOrganic;
            }
            if m.starts_with("image/svg") {
                return Self::VectorOrganic;
            }
            if m.starts_with("image/bmp") {
                return Self::RasterFlat;
            }
            if m.starts_with("audio/wav") || m.starts_with("audio/x-wav") {
                return Self::AudioPcm;
            }
            if m.contains("officedocument") || m.starts_with("application/msword") {
                return Self::DocumentOrganic;
            }
            if m.starts_with("image/jpeg")
                || m.starts_with("image/png")
                || m.starts_with("image/gif")
                || m.starts_with("image/webp")
                || m.starts_with("video/")
                || m.starts_with("audio/")
            {
                // PNG gövdesi zaten deflate taşır: ölçüm zlib denemesinin
                // kazandırmadığını gösterdi, EntropyMedia tarafında kalır.
                return Self::EntropyMedia;
            }
            if m.contains("zip") || m.contains("gzip") || m.contains("zstd") {
                return Self::EntropyArchive;
            }
        }
        sniff_magic(bytes)
    }

    /// Whether zlib-if-shrinks may run.
    #[must_use]
    pub const fn may_try_zlib(self) -> bool {
        match self {
            Self::EntropyMedia | Self::EntropyArchive | Self::Ciphertext | Self::Exec => false,
            Self::Generic
            | Self::TextOrganic
            | Self::RecipeWire
            | Self::VectorOrganic
            | Self::RasterFlat
            | Self::AudioPcm
            | Self::DocumentOrganic => true,
        }
    }
}

fn sniff_magic(bytes: &[u8]) -> ContentClass {
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return ContentClass::EntropyMedia; // JPEG
    }
    if bytes.get(0..4) == Some(b"\x89PNG") {
        return ContentClass::EntropyMedia; // govde zaten deflate; zlib kazandirmiyor
    }
    if bytes.len() >= 4
        && (bytes[0..4] == *b"ftyp" || (bytes.len() >= 8 && &bytes[4..8] == b"ftyp"))
    {
        return ContentClass::EntropyMedia; // ISO BMFF
    }
    if bytes.len() >= 12 && bytes[0..4] == *b"RIFF" && bytes[8..12] == *b"WAVE" {
        return ContentClass::AudioPcm; // WAV: PCM ornekleri, dusuk entropi
    }
    if bytes.len() >= 4 && bytes[0..4] == *b"RIFF" {
        return ContentClass::EntropyMedia;
    }
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        return ContentClass::EntropyArchive; // gzip
    }
    if bytes.len() >= 4 && bytes[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        return ContentClass::EntropyArchive; // zstd
    }
    if bytes.len() >= 4 && bytes[0..4] == *b"PK\x03\x04" {
        // OOXML paketi ilk girdi olarak [Content_Types].xml tasir; duz zip
        // EntropyArchive kalir, ofis belge sikistirilabilir organic sayilir.
        let head = &bytes[..bytes.len().min(512)];
        if head.windows(19).any(|w| w == b"[Content_Types].xml") {
            return ContentClass::DocumentOrganic;
        }
        return ContentClass::EntropyArchive; // zip
    }
    if bytes.len() >= 4 && bytes[0..4] == *b"\x7fELF" {
        return ContentClass::Exec; // ELF
    }
    if bytes.len() >= 2 && bytes[0..2] == *b"MZ" {
        return ContentClass::Exec; // PE
    }
    if bytes.len() >= 2 && bytes[0..2] == *b"BM" {
        return ContentClass::RasterFlat; // bitmap
    }
    if bytes.starts_with(b"<svg") || bytes.starts_with(b"<?xml") {
        return ContentClass::VectorOrganic;
    }
    if bytes.len() >= 4 && bytes[0..4] == *b"BDLC" {
        return ContentClass::Ciphertext;
    }
    // High printable ratio → text organic
    if !bytes.is_empty() {
        let sample = bytes.len().min(512);
        let mut printable = 0usize;
        for &b in bytes.iter().take(sample) {
            if (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
                printable += 1;
            }
        }
        if printable * 10 >= sample * 8 {
            return ContentClass::TextOrganic;
        }
    }
    ContentClass::Generic
}

/// Normalised 2.0 output ready for the Three pipe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransformedPayload {
    /// Transformed content bytes (not yet A1-packed).
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`.
    pub content_sha256: [u8; 32],
    /// What this transform claims about these bytes.
    pub codec_flags: CodecFlags,
    /// Class used for policy.
    pub class: ContentClass,
}

impl TransformedPayload {
    /// Build from raw transformed bytes (no extra zlib).
    ///
    /// # Errors
    ///
    /// Empty bytes refused.
    pub fn from_bytes(bytes: Vec<u8>, codec_flags: CodecFlags) -> Result<Self, TransformError> {
        if bytes.is_empty() {
            return Err(TransformError::Empty);
        }
        let class = if codec_flags.contains(CodecFlags::CIPHERTEXT) {
            ContentClass::Ciphertext
        } else if codec_flags.contains(CodecFlags::ENTROPY_CODED) {
            ContentClass::EntropyMedia
        } else {
            ContentClass::classify(&bytes, None)
        };
        let content_sha256 = calculate_hash_bytes(&bytes);
        Ok(Self {
            bytes,
            content_sha256,
            codec_flags,
            class,
        })
    }

    /// Verify the pinned hash still matches the body.
    #[must_use]
    pub fn verify_hash(&self) -> bool {
        calculate_hash_bytes(&self.bytes) == self.content_sha256
    }
}

/// A0 errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformError {
    /// Empty transform refused.
    Empty,
    /// Pinned digest no longer matches the body at the A1 handoff.
    HashMismatch,
    /// Input larger than lab hard cap.
    TooLarge {
        /// Observed.
        len: usize,
        /// Max.
        max: usize,
    },
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "transformed payload refuses empty bytes"),
            Self::HashMismatch => {
                write!(f, "transformed payload body does not match its pinned hash")
            }
            Self::TooLarge { len, max } => {
                write!(f, "transform input {len} exceeds max {max}")
            }
        }
    }
}

impl std::error::Error for TransformError {}

/// Lab hard cap (same order as A1).
pub const MAX_TRANSFORM_IN: usize = 64 * 1024 * 1024;

/// Options for [`transform_content`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TransformOpts {
    /// Optional MIME hint (e.g. `image/jpeg`).
    pub mime_hint: Option<&'static str>,
    /// Force class (skips sniff) when `Some`.
    pub force_class: Option<ContentClass>,
    /// Apply shrink-only zlib here (default **false**).
    ///
    /// Product rule: A1 pack already does K-QR-SIKISTIR. A0 default is
    /// classify + pin only so the pipe does not double-zlib and so decode
    /// returns the same user bytes. Set true only for standalone 2.0 export
    /// paths that will not re-enter A1 compression.
    pub apply_zlib: bool,
}

/// **Main A0 entry:** classify → zlib-if-shrinks when allowed → pin.
///
/// # Errors
///
/// Empty / oversized input.
pub fn transform_content(
    input: &[u8],
    opts: TransformOpts,
) -> Result<TransformedPayload, TransformError> {
    if input.is_empty() {
        return Err(TransformError::Empty);
    }
    if input.len() > MAX_TRANSFORM_IN {
        return Err(TransformError::TooLarge {
            len: input.len(),
            max: MAX_TRANSFORM_IN,
        });
    }
    let class = opts
        .force_class
        .unwrap_or_else(|| ContentClass::classify(input, opts.mime_hint));
    let mut flags = CodecFlags::NONE;
    match class {
        ContentClass::EntropyMedia | ContentClass::EntropyArchive | ContentClass::Exec => {
            flags = flags.union(CodecFlags::ENTROPY_CODED);
        }
        ContentClass::Ciphertext => flags = flags.union(CodecFlags::CIPHERTEXT),
        ContentClass::TextOrganic
        | ContentClass::VectorOrganic
        | ContentClass::RasterFlat
        | ContentClass::AudioPcm
        | ContentClass::DocumentOrganic => flags = flags.union(CodecFlags::ORGANIC_COMPRESSIBLE),
        ContentClass::Generic | ContentClass::RecipeWire => {}
    }

    let (bytes, flags) = if opts.apply_zlib && class.may_try_zlib() {
        match try_zlib9(input) {
            Some(z) if z.len() < input.len() => (z, flags.union(CodecFlags::PRE_SHRUNK)),
            _ => (input.to_vec(), flags),
        }
    } else {
        (input.to_vec(), flags)
    };

    let content_sha256 = calculate_hash_bytes(&bytes);
    Ok(TransformedPayload {
        bytes,
        content_sha256,
        codec_flags: flags,
        class,
    })
}

fn try_zlib9(data: &[u8]) -> Option<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_hash() {
        let t = TransformedPayload::from_bytes(b"abc".to_vec(), CodecFlags::NONE).unwrap();
        assert!(t.verify_hash());
        assert_eq!(t.content_sha256, calculate_hash_bytes(b"abc"));
    }

    #[test]
    fn empty_refused() {
        assert_eq!(
            TransformedPayload::from_bytes(vec![], CodecFlags::NONE).unwrap_err(),
            TransformError::Empty
        );
        assert_eq!(
            transform_content(b"", TransformOpts::default()).unwrap_err(),
            TransformError::Empty
        );
    }

    #[test]
    fn text_classified_default_no_double_zlib() {
        let input = b"hello world ".repeat(400);
        let t = transform_content(&input, TransformOpts::default()).unwrap();
        assert_eq!(t.class, ContentClass::TextOrganic);
        assert!(!t.codec_flags.contains(CodecFlags::PRE_SHRUNK));
        assert_eq!(t.bytes, input);
    }

    #[test]
    fn text_zlib_when_opt_in() {
        let input = b"hello world ".repeat(400);
        let t = transform_content(
            &input,
            TransformOpts {
                apply_zlib: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(t.codec_flags.contains(CodecFlags::PRE_SHRUNK));
        assert!(t.bytes.len() < input.len());
        assert!(t.verify_hash());
    }

    #[test]
    fn jpeg_magic_skips_zlib() {
        let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe0];
        jpeg.extend(std::iter::repeat_n(0xABu8, 2000));
        let t = transform_content(&jpeg, TransformOpts::default()).unwrap();
        assert_eq!(t.class, ContentClass::EntropyMedia);
        assert!(t.codec_flags.contains(CodecFlags::ENTROPY_CODED));
        assert!(!t.codec_flags.contains(CodecFlags::PRE_SHRUNK));
        assert_eq!(t.bytes, jpeg);
    }

    /// Görev 3 adım 1: on format sınıfının kokusu ve zlib politikası.
    #[test]
    fn format_matrix_ten_classes_sniffed() {
        // (girdi, beklenen sınıf, beklenen may_try_zlib)
        let cases: Vec<(&str, Vec<u8>, ContentClass, bool)> = vec![
            (
                "generic",
                vec![0x01u8, 0x02, 0x00, 0xfe, 0x03, 0x80, 0x00, 0x99],
                ContentClass::Generic,
                true,
            ),
            (
                "metin",
                b"the quick brown fox jumps over the lazy dog ".repeat(4),
                ContentClass::TextOrganic,
                true,
            ),
            (
                "svg",
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>".to_vec(),
                ContentClass::VectorOrganic,
                true,
            ),
            (
                "xml-bildirimi",
                b"<?xml version=\"1.0\"?><doc><a/></doc>".to_vec(),
                ContentClass::VectorOrganic,
                true,
            ),
            (
                "bmp",
                {
                    let mut v = b"BM".to_vec();
                    v.extend_from_slice(&[0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    v.extend(std::iter::repeat_n(0x7fu8, 64));
                    v
                },
                ContentClass::RasterFlat,
                true,
            ),
            (
                "wav",
                {
                    let mut v = b"RIFF".to_vec();
                    v.extend_from_slice(&[0x24, 0x00, 0x00, 0x00]);
                    v.extend_from_slice(b"WAVEfmt ");
                    v.extend(std::iter::repeat_n(0x10u8, 48));
                    v
                },
                ContentClass::AudioPcm,
                true,
            ),
            (
                "ooxml",
                {
                    let mut v = b"PK\x03\x04".to_vec();
                    v.extend(std::iter::repeat_n(0u8, 26));
                    v.extend_from_slice(b"[Content_Types].xml");
                    v.extend(std::iter::repeat_n(0u8, 64));
                    v
                },
                ContentClass::DocumentOrganic,
                true,
            ),
            (
                "elf",
                {
                    let mut v = b"\x7fELF".to_vec();
                    v.extend(std::iter::repeat_n(0x00u8, 60));
                    v
                },
                ContentClass::Exec,
                false,
            ),
            (
                "pe",
                {
                    let mut v = b"MZ".to_vec();
                    v.extend(std::iter::repeat_n(0x90u8, 62));
                    v
                },
                ContentClass::Exec,
                false,
            ),
            (
                "zip",
                {
                    let mut v = b"PK\x03\x04".to_vec();
                    v.extend(std::iter::repeat_n(0u8, 26));
                    v.extend_from_slice(b"data.bin");
                    v.extend(std::iter::repeat_n(0u8, 64));
                    v
                },
                ContentClass::EntropyArchive,
                false,
            ),
            (
                "gzip",
                {
                    let mut v = vec![0x1fu8, 0x8b, 0x08];
                    v.extend(std::iter::repeat_n(0x33u8, 64));
                    v
                },
                ContentClass::EntropyArchive,
                false,
            ),
            (
                "jpeg",
                {
                    let mut v = vec![0xffu8, 0xd8, 0xff, 0xe0];
                    v.extend(std::iter::repeat_n(0xABu8, 64));
                    v
                },
                ContentClass::EntropyMedia,
                false,
            ),
            (
                "png",
                {
                    let mut v = b"\x89PNG".to_vec();
                    v.extend(std::iter::repeat_n(0x0Du8, 64));
                    v
                },
                ContentClass::EntropyMedia,
                false,
            ),
            (
                "ciphertext",
                {
                    let mut v = b"BDLC".to_vec();
                    v.extend(std::iter::repeat_n(0x5Au8, 64));
                    v
                },
                ContentClass::Ciphertext,
                false,
            ),
        ];
        for (ad, girdi, sinif, zlib) in cases {
            let got = ContentClass::classify(&girdi, None);
            assert_eq!(got, sinif, "sniff yanlis: {ad}");
            assert_eq!(got.may_try_zlib(), zlib, "zlib politikasi yanlis: {ad}");
        }
        // RecipeWire koklanmaz; zorla secilir ve zlib deneyebilir.
        assert!(ContentClass::RecipeWire.may_try_zlib());
    }

    /// Görev 3 adım 6: entropi siniflarinda PRE_SHRUNK asla kalkmaz.
    #[test]
    fn matrix_zlib_never_grows_entropy() {
        let entropy_inputs: Vec<Vec<u8>> = vec![
            {
                let mut v = vec![0xffu8, 0xd8, 0xff, 0xe0];
                v.extend(std::iter::repeat_n(0xABu8, 2000));
                v
            },
            {
                let mut v = b"\x89PNG".to_vec();
                v.extend(std::iter::repeat_n(0x0Du8, 2000));
                v
            },
            {
                let mut v = vec![0x1fu8, 0x8b, 0x08];
                v.extend(std::iter::repeat_n(0x33u8, 2000));
                v
            },
            {
                let mut v = b"\x7fELF".to_vec();
                v.extend(std::iter::repeat_n(0x00u8, 2000));
                v
            },
            {
                let mut v = b"BDLC".to_vec();
                v.extend(std::iter::repeat_n(0x5Au8, 2000));
                v
            },
        ];
        for girdi in entropy_inputs {
            let t = transform_content(
                &girdi,
                TransformOpts {
                    apply_zlib: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(!t.class.may_try_zlib(), "entropi sinifi zlib istedi");
            assert!(!t.codec_flags.contains(CodecFlags::PRE_SHRUNK));
            assert_eq!(t.bytes, girdi);
        }
    }

    /// Görev 3 adım 7: her sinif QR-video zincirinden bayt esit geri doner.
    #[test]
    fn matrix_e2e_each_class_round_trips() {
        use crate::storage::three_pipe::{decode_qr_video, encode_qr_video};
        let inputs: Vec<(&str, Vec<u8>)> = vec![
            ("metin", b"log satiri ".repeat(300)),
            (
                "svg",
                b"<svg><path d=\"M0 0L10 10\"/></svg><!-- ".repeat(80),
            ),
            ("bmp", {
                let mut v = b"BM".to_vec();
                v.extend(std::iter::repeat_n(0x7fu8, 3000));
                v
            }),
            ("wav", {
                let mut v = b"RIFF".to_vec();
                v.extend_from_slice(&[0x00, 0x0c, 0x00, 0x00]);
                v.extend_from_slice(b"WAVEfmt ");
                v.extend(std::iter::repeat_n(0x10u8, 3000));
                v
            }),
            ("jpeg", {
                let mut v = vec![0xffu8, 0xd8, 0xff, 0xe0];
                v.extend((0..3000u32).map(|i| (i % 251) as u8));
                v
            }),
            ("png", {
                let mut v = b"\x89PNG".to_vec();
                v.extend((0..3000u32).map(|i| (i % 199) as u8));
                v
            }),
            ("gzip", {
                let mut v = vec![0x1fu8, 0x8b, 0x08];
                v.extend((0..3000u32).map(|i| (i % 173) as u8));
                v
            }),
            ("elf", {
                let mut v = b"\x7fELF".to_vec();
                v.extend((0..3000u32).map(|i| (i % 131) as u8));
                v
            }),
            ("ciphertext", {
                let mut v = b"BDLC".to_vec();
                v.extend((0..3000u32).map(|i| (i % 97) as u8));
                v
            }),
            (
                "generic",
                (0..3000u32).map(|i| ((i * 37) % 256) as u8).collect(),
            ),
        ];
        for (ad, icerik) in inputs {
            let enc = encode_qr_video(&icerik, 64, None).unwrap();
            let (_kind, raw, _v) = decode_qr_video(&enc.video_blob).unwrap();
            assert_eq!(raw, icerik, "sinif zincirden bozuk cikti: {ad}");
        }
    }

    #[test]
    fn mime_hint_text() {
        let t = transform_content(
            b"{ \"a\": 1 }",
            TransformOpts {
                mime_hint: Some("application/json"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(t.class, ContentClass::TextOrganic);
    }
}
