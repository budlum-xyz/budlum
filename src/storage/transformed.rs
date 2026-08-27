//! A0 — 2.0 → 3.0 transform contract (plan §CH A0 / §CJ.6).
//!
//! User product: content is **transformed** (format + ops) before the Three
//! QR-video pipe. This module is the single mouth: classify → optional
//! shrink-only zlib → pin sha256 → [`TransformedPayload`].
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
    /// Input was already entropy-coded (jpeg/mp4/zip/cipher) — zlib not tried.
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
    /// Unknown — try zlib-if-shrinks.
    Generic = 0,
    /// utf8 / json / xml / plain — zlib likely helps.
    TextOrganic = 1,
    /// Already compressed media container.
    EntropyMedia = 2,
    /// Archive / zip / gzip / zstd payload.
    EntropyArchive = 3,
    /// Caller-sealed ciphertext.
    Ciphertext = 4,
    /// Generative recipe wire (catalogue) — usually tiny; still may zlib.
    RecipeWire = 5,
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
            if m.starts_with("image/jpeg")
                || m.starts_with("image/png")
                || m.starts_with("image/gif")
                || m.starts_with("image/webp")
                || m.starts_with("video/")
                || m.starts_with("audio/")
            {
                // PNG can be compressible; JPEG/MP4 entropy. Be conservative:
                // PNG → Generic (allow zlib try); jpeg/mp4 → entropy.
                if m.starts_with("image/png") {
                    return Self::Generic;
                }
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
            Self::EntropyMedia | Self::EntropyArchive | Self::Ciphertext => false,
            Self::Generic | Self::TextOrganic | Self::RecipeWire => true,
        }
    }
}

fn sniff_magic(bytes: &[u8]) -> ContentClass {
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return ContentClass::EntropyMedia; // JPEG
    }
    if bytes.len() >= 4 && bytes[0..4] == *b"\x89PNG" {
        return ContentClass::Generic; // try zlib; often already deflated inside
    }
    if bytes.len() >= 4
        && (bytes[0..4] == *b"ftyp" || (bytes.len() >= 8 && &bytes[4..8] == b"ftyp"))
    {
        return ContentClass::EntropyMedia; // ISO BMFF
    }
    if bytes.len() >= 4 && bytes[0..4] == *b"RIFF" {
        return ContentClass::EntropyMedia;
    }
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        return ContentClass::EntropyArchive; // gzip
    }
    if bytes.len() >= 4 && bytes[0..4] == *b"PK\x03\x04" {
        return ContentClass::EntropyArchive; // zip
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
        ContentClass::EntropyMedia | ContentClass::EntropyArchive => {
            flags = flags.union(CodecFlags::ENTROPY_CODED);
        }
        ContentClass::Ciphertext => flags = flags.union(CodecFlags::CIPHERTEXT),
        ContentClass::TextOrganic => flags = flags.union(CodecFlags::ORGANIC_COMPRESSIBLE),
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
