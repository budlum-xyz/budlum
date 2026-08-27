//! B.U.D. 3.0 payload container (plan §CH A1).
//!
//! First stage of the real edition-Three pipe (user architecture §CG), not the
//! catalogue avatar generators:
//!
//! ```text
//! transformed content bytes
//!   → optional zlib-if-shrinks (K-QR-SIKISTIR)
//!   → Three payload header + body
//!   → (next slices) carousel / QR frames / recipe
//! ```
//!
//! # What this module does not claim
//!
//! - It does not encode QR video yet (A2–A4).
//! - It does not write a full content QR recipe (A5).
//! - Decimen source is not copied (AGPL); only the measured rule we already
//!   pinned: try zlib only when it shrinks; never claim QR as storage.
//!
//! # Wire layout
//!
//! ```text
//! magic[4]       = b"BDL3"
//! version u8     = 1
//! flags u8       = bit0 = zlib applied
//! kind u8        = payload kind tag
//! orig_len u64 LE
//! content_sha256 [32]   // sha256 of the uncompressed original
//! body [...]            // raw or zlib(raw)
//! ```

use crate::core::hash::{calculate_hash_bytes, hash_fields_bytes};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Wire magic: "BDL3" — B.U.D. edition Three payload, not a storage blob id.
pub const THREE_PAYLOAD_MAGIC: [u8; 4] = *b"BDL3";
/// Current header version. Unknown versions refuse on unpack.
pub const THREE_PAYLOAD_VERSION: u8 = 1;
/// `flags` bit0: body is zlib-compressed; clear means body is raw original.
pub const FLAG_ZLIB: u8 = 1 << 0;

/// Fixed header size before the body: magic4 + ver + flags + kind + orig_len8 + sha32.
pub const THREE_PAYLOAD_HEADER_LEN: usize = 4 + 1 + 1 + 1 + 8 + 32;

/// Hard cap for a single payload pack in this process (not a network consensus
/// limit — that lands with domain params later). 64 MiB keeps lab tests honest
/// without letting one pack exhaust a 2 GB sandbox.
pub const MAX_PAYLOAD_CONTENT: usize = 64 * 1024 * 1024;

/// What the body carries before QR packaging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadKind {
    /// Opaque transformed content bytes (2.0 pipe output).
    ContentBytes = 1,
    /// A public generative recipe wire (catalogue path) — not the main invent.
    PublicRecipeWire = 2,
    /// Ciphertext of content bytes (privacy G1). Body is encrypted; the committed
    /// sha256 is of the bytes the caller passed (typically the ciphertext).
    EncryptedContent = 3,
}

impl PayloadKind {
    /// Wire tag for this kind.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Parse a wire tag; unknown tags are refused.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::ContentBytes),
            2 => Some(Self::PublicRecipeWire),
            3 => Some(Self::EncryptedContent),
            _ => None,
        }
    }
}

/// Errors packing or unpacking a three payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    /// Empty content is refused — a zero-length payload is not a valid 3.0 unit.
    Empty,
    /// Content or declared `orig_len` exceeds [`MAX_PAYLOAD_CONTENT`].
    TooLarge {
        /// Observed length.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// First four bytes were not [`THREE_PAYLOAD_MAGIC`].
    BadMagic,
    /// Header version is not [`THREE_PAYLOAD_VERSION`].
    BadVersion(u8),
    /// Kind tag is not a known [`PayloadKind`].
    BadKind(u8),
    /// Buffer shorter than the header, or body cut off.
    Truncated,
    /// Zlib inflate failed.
    Inflate,
    /// Uncompressed body does not match the committed sha256.
    ContentHashMismatch,
    /// Zlib flag / `orig_len` / body length disagree.
    ZlibInconsistent,
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "three payload refuses empty content"),
            Self::TooLarge { len, max } => {
                write!(f, "content {len} bytes exceeds three-payload max {max}")
            }
            Self::BadMagic => write!(f, "three payload bad magic"),
            Self::BadVersion(v) => write!(f, "three payload unsupported version {v}"),
            Self::BadKind(k) => write!(f, "three payload unknown kind {k}"),
            Self::Truncated => write!(f, "three payload truncated"),
            Self::Inflate => write!(f, "three payload zlib inflate failed"),
            Self::ContentHashMismatch => write!(f, "three payload content sha256 mismatch"),
            Self::ZlibInconsistent => {
                write!(f, "three payload zlib flag inconsistent with body")
            }
        }
    }
}

impl std::error::Error for PayloadError {}

/// Pack original content into the A1 container.
///
/// Zlib level 9 is applied **only** when it strictly shrinks; otherwise the
/// raw bytes are stored and [`FLAG_ZLIB`] is clear (K-QR-SIKISTIR).
///
/// # Errors
///
/// [`PayloadError::Empty`] on zero-length content;
/// [`PayloadError::TooLarge`] when `content` exceeds [`MAX_PAYLOAD_CONTENT`].
pub fn pack_payload(kind: PayloadKind, content: &[u8]) -> Result<Vec<u8>, PayloadError> {
    if content.is_empty() {
        return Err(PayloadError::Empty);
    }
    if content.len() > MAX_PAYLOAD_CONTENT {
        return Err(PayloadError::TooLarge {
            len: content.len(),
            max: MAX_PAYLOAD_CONTENT,
        });
    }
    let content_sha = calculate_hash_bytes(content);
    let (body, flags) = match try_zlib9(content) {
        Some(z) if z.len() < content.len() => (z, FLAG_ZLIB),
        _ => (content.to_vec(), 0u8),
    };

    let mut out = Vec::with_capacity(THREE_PAYLOAD_HEADER_LEN + body.len());
    out.extend_from_slice(&THREE_PAYLOAD_MAGIC);
    out.push(THREE_PAYLOAD_VERSION);
    out.push(flags);
    out.push(kind.tag());
    out.extend_from_slice(&(content.len() as u64).to_le_bytes());
    out.extend_from_slice(&content_sha);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Unpack a packed container and verify the content hash.
///
/// # Errors
///
/// Any of the [`PayloadError`] variants when the buffer is malformed, the
/// version/kind is unknown, inflate fails, or the sha256 does not match.
pub fn unpack_payload(packed: &[u8]) -> Result<(PayloadKind, Vec<u8>), PayloadError> {
    if packed.len() < THREE_PAYLOAD_HEADER_LEN {
        return Err(PayloadError::Truncated);
    }
    let magic = packed.get(0..4).ok_or(PayloadError::Truncated)?;
    if magic != THREE_PAYLOAD_MAGIC {
        return Err(PayloadError::BadMagic);
    }
    let version = *packed.get(4).ok_or(PayloadError::Truncated)?;
    if version != THREE_PAYLOAD_VERSION {
        return Err(PayloadError::BadVersion(version));
    }
    let flags = *packed.get(5).ok_or(PayloadError::Truncated)?;
    let kind_tag = *packed.get(6).ok_or(PayloadError::Truncated)?;
    let kind = PayloadKind::from_tag(kind_tag).ok_or(PayloadError::BadKind(kind_tag))?;

    let orig_len_bytes = packed.get(7..15).ok_or(PayloadError::Truncated)?;
    let mut orig_len_arr = [0u8; 8];
    orig_len_arr.copy_from_slice(orig_len_bytes);
    let orig_len_u64 = u64::from_le_bytes(orig_len_arr);
    let orig_len = usize::try_from(orig_len_u64).map_err(|_| PayloadError::TooLarge {
        len: usize::MAX,
        max: MAX_PAYLOAD_CONTENT,
    })?;

    let expect_sha_slice = packed.get(15..47).ok_or(PayloadError::Truncated)?;
    let mut expect_sha = [0u8; 32];
    expect_sha.copy_from_slice(expect_sha_slice);

    let body = packed.get(47..).ok_or(PayloadError::Truncated)?;

    if orig_len == 0 || orig_len > MAX_PAYLOAD_CONTENT {
        return Err(PayloadError::TooLarge {
            len: orig_len,
            max: MAX_PAYLOAD_CONTENT,
        });
    }

    let raw = if flags & FLAG_ZLIB != 0 {
        inflate_zlib(body).map_err(|_| PayloadError::Inflate)?
    } else {
        body.to_vec()
    };
    if raw.len() != orig_len {
        return Err(PayloadError::ZlibInconsistent);
    }
    let got = calculate_hash_bytes(&raw);
    if got != expect_sha {
        return Err(PayloadError::ContentHashMismatch);
    }
    Ok((kind, raw))
}

/// Commitment over the packed container (what a recipe can bind without holding body).
#[must_use]
pub fn payload_commitment(packed: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[b"BDLM_THREE_PAYLOAD_V1", packed])
}

/// True when the packed header has the zlib flag set. Returns false on short buffers.
#[must_use]
pub fn packed_is_zlib(packed: &[u8]) -> bool {
    packed.get(5).is_some_and(|f| f & FLAG_ZLIB != 0)
}

fn try_zlib9(data: &[u8]) -> Option<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).ok()?;
    enc.finish().ok()
}

fn inflate_zlib(data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|_| ())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_raw_when_random_does_not_shrink() {
        let mut content = vec![0u8; 2048];
        for (i, b) in content.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        // High-entropy-ish: zlib may or may not shrink; either way unpack works.
        let packed = pack_payload(PayloadKind::ContentBytes, &content).unwrap();
        assert_eq!(&packed[0..4], &THREE_PAYLOAD_MAGIC);
        let (k, raw) = unpack_payload(&packed).unwrap();
        assert_eq!(k, PayloadKind::ContentBytes);
        assert_eq!(raw, content);
        let _ = payload_commitment(&packed);
    }

    #[test]
    fn compressible_text_sets_zlib_flag_when_smaller() {
        let content = b"hello world ".repeat(500);
        let packed = pack_payload(PayloadKind::ContentBytes, &content).unwrap();
        let flags = packed[5];
        // Highly repetitive → almost certainly zlib-smaller.
        assert_eq!(
            flags & FLAG_ZLIB,
            FLAG_ZLIB,
            "expected zlib flag on repetitive text"
        );
        let (_, raw) = unpack_payload(&packed).unwrap();
        assert_eq!(raw, content.as_slice());
        assert!(packed_is_zlib(&packed));
    }

    #[test]
    fn empty_refused() {
        assert_eq!(
            pack_payload(PayloadKind::ContentBytes, b"").unwrap_err(),
            PayloadError::Empty
        );
    }

    #[test]
    fn tampered_body_fails_hash() {
        let content = b"deterministic payload for hash check";
        let mut packed = pack_payload(PayloadKind::ContentBytes, content).unwrap();
        let last = packed.len() - 1;
        packed[last] ^= 0xff;
        assert_eq!(
            unpack_payload(&packed).unwrap_err(),
            PayloadError::ContentHashMismatch
        );
    }

    #[test]
    fn bad_magic_refused() {
        let mut packed = pack_payload(PayloadKind::ContentBytes, b"abc").unwrap();
        packed[0] = b'X';
        assert_eq!(unpack_payload(&packed).unwrap_err(), PayloadError::BadMagic);
    }

    #[test]
    fn truncated_refused() {
        assert_eq!(
            unpack_payload(&[0u8; 10]).unwrap_err(),
            PayloadError::Truncated
        );
    }

    #[test]
    fn encrypted_kind_round_trips_opaque_bytes() {
        // G1 placeholder: caller encrypts first; we only pack ciphertext bytes
        // and still commit sha of what they passed as "content".
        let cipher = vec![0xAAu8; 128];
        let packed = pack_payload(PayloadKind::EncryptedContent, &cipher).unwrap();
        let (k, raw) = unpack_payload(&packed).unwrap();
        assert_eq!(k, PayloadKind::EncryptedContent);
        assert_eq!(raw, cipher);
    }

    #[test]
    fn commitment_changes_when_body_changes() {
        let a = pack_payload(PayloadKind::ContentBytes, b"one").unwrap();
        let b = pack_payload(PayloadKind::ContentBytes, b"two").unwrap();
        assert_ne!(payload_commitment(&a), payload_commitment(&b));
        assert_eq!(payload_commitment(&a), payload_commitment(&a));
    }

    #[test]
    fn bad_version_refused() {
        let mut packed = pack_payload(PayloadKind::ContentBytes, b"abc").unwrap();
        packed[4] = 99;
        assert_eq!(
            unpack_payload(&packed).unwrap_err(),
            PayloadError::BadVersion(99)
        );
    }

    #[test]
    fn bad_kind_refused() {
        let mut packed = pack_payload(PayloadKind::ContentBytes, b"abc").unwrap();
        packed[6] = 0xff;
        assert_eq!(
            unpack_payload(&packed).unwrap_err(),
            PayloadError::BadKind(0xff)
        );
    }
}
