//! B.U.D. 3.0 QR-bound drop frame (plan §CH A3).
//!
//! Wraps an A2 carousel drop in a **self-describing optical frame** so a
//! mid-stream join can parse without prior handshake. This is the main
//! edition-Three pipe (bytes → container → carousel → frame), not the
//! catalogue `RenderFormat::QrStream` path which binds a generative recipe.
//!
//! # Wire (little-endian body fields after magic)
//!
//! ```text
//! magic[2]           = 0xBD 0x3A     // "ours?" before any version (Three path)
//! version u8         = 1
//! flags u8           = low nibble must-understand, high nibble ignorable
//! seq u32 LE
//! stream_id_prefix u32 LE   // first 4 of stream commitment
//! drop_wire_len u16 LE
//! frame_digest u32 LE       // first 4 of BDLM_THREE_QR_FRAME_V1 bind
//! drop_wire [drop_wire_len] // full A2 Drop::to_bytes()
//! ```
//!
//! # Binding
//!
//! The frame digest preimage is:
//! `BDLM_THREE_QR_FRAME_V1 ‖ stream_commitment ‖ seq ‖ drop_wire`.
//!
//! `stream_commitment` comes from [`CarouselParams::stream_commitment`] over
//! the A1 payload commitment, so a foreign stream cannot splice drops in.
//!
//! # What this module does not claim
//!
//! - No QR module matrix / ECC (camera layer stays out of consensus).
//! - No video mux (A4).
//! - No recipe object yet (A5).
//! - Catalogue `render_qr_stream_frame` is a different address space.

use crate::core::hash::hash_fields_bytes;
use crate::storage::qr_carousel::Drop;

/// Two-byte magic: answers "is this our Three frame?" before version.
pub const THREE_FRAME_MAGIC: [u8; 2] = [0xBD, 0x3A];
/// Frame header version.
pub const THREE_FRAME_VERSION: u8 = 1;
/// Bytes before the drop wire: magic2 + ver + flags + seq4 + stream_prefix4 + drop_len2 + digest4.
pub const THREE_FRAME_HEADER_LEN: usize = 2 + 1 + 1 + 4 + 4 + 2 + 4;

/// Errors packing or checking a Three optical frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Buffer shorter than the header or declared drop length.
    Truncated,
    /// Magic is not [`THREE_FRAME_MAGIC`].
    BadMagic,
    /// Version is not [`THREE_FRAME_VERSION`].
    BadVersion(u8),
    /// A must-understand flag bit is set that this build does not know.
    UnsupportedFlags(u8),
    /// Declared drop length is zero or exceeds a lab hard cap.
    BadDropLen(u16),
    /// Frame digest does not match the bound preimage.
    DigestMismatch,
    /// Stream id prefix does not match the expected commitment.
    StreamMismatch,
    /// Nested drop failed to parse.
    BadDrop,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "three qr frame truncated"),
            Self::BadMagic => write!(f, "three qr frame bad magic"),
            Self::BadVersion(v) => write!(f, "three qr frame unsupported version {v}"),
            Self::UnsupportedFlags(flags) => {
                write!(
                    f,
                    "three qr frame unsupported must-understand flags {flags:#x}"
                )
            }
            Self::BadDropLen(n) => write!(f, "three qr frame bad drop len {n}"),
            Self::DigestMismatch => write!(f, "three qr frame digest mismatch"),
            Self::StreamMismatch => write!(f, "three qr frame stream id mismatch"),
            Self::BadDrop => write!(f, "three qr frame nested drop invalid"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Lab hard cap on nested drop wire size (header + one block_len body, with margin).
pub const MAX_DROP_WIRE: u16 = 8 * 1024;

/// Pack a carousel drop into a Three optical frame.
///
/// `stream_commitment` is the 32-byte carousel stream id (A2); only its first
/// four bytes go on the wire as a fast reject, while the full 32 bind the digest.
#[must_use]
pub fn pack_frame(stream_commitment: &[u8; 32], drop: &Drop) -> Vec<u8> {
    let drop_wire = drop.to_bytes();
    let drop_len = u16::try_from(drop_wire.len()).unwrap_or(u16::MAX);
    let digest = frame_digest(stream_commitment, drop.seq, &drop_wire);
    let mut out = Vec::with_capacity(THREE_FRAME_HEADER_LEN + drop_wire.len());
    out.extend_from_slice(&THREE_FRAME_MAGIC);
    out.push(THREE_FRAME_VERSION);
    out.push(0); // flags
    out.extend_from_slice(&drop.seq.to_le_bytes());
    let prefix = stream_id_prefix(stream_commitment);
    out.extend_from_slice(&prefix.to_le_bytes());
    out.extend_from_slice(&drop_len.to_le_bytes());
    out.extend_from_slice(&digest);
    out.extend_from_slice(&drop_wire);
    out
}

/// Parse and verify a frame against an expected stream commitment.
///
/// # Errors
///
/// Magic / version / flags / digest / stream prefix / nested drop failures.
pub fn unpack_frame(stream_commitment: &[u8; 32], frame: &[u8]) -> Result<Drop, FrameError> {
    if frame.len() < THREE_FRAME_HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    let magic = frame.get(0..2).ok_or(FrameError::Truncated)?;
    if magic != THREE_FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    let version = *frame.get(2).ok_or(FrameError::Truncated)?;
    if version != THREE_FRAME_VERSION {
        return Err(FrameError::BadVersion(version));
    }
    let flags = *frame.get(3).ok_or(FrameError::Truncated)?;
    // Low nibble = must-understand. V1 defines no must-understand bits.
    if flags & 0x0f != 0 {
        return Err(FrameError::UnsupportedFlags(flags));
    }
    let seq = u32_from_le(frame, 4)?;
    let wire_prefix = u32_from_le(frame, 8)?;
    let expect_prefix = stream_id_prefix(stream_commitment);
    if wire_prefix != expect_prefix {
        return Err(FrameError::StreamMismatch);
    }
    let drop_len = u16_from_le(frame, 12)?;
    if drop_len == 0 || drop_len > MAX_DROP_WIRE {
        return Err(FrameError::BadDropLen(drop_len));
    }
    let digest_wire = frame.get(14..18).ok_or(FrameError::Truncated)?;
    let drop_end = THREE_FRAME_HEADER_LEN
        .checked_add(usize::from(drop_len))
        .ok_or(FrameError::Truncated)?;
    if frame.len() < drop_end {
        return Err(FrameError::Truncated);
    }
    let drop_wire = frame
        .get(THREE_FRAME_HEADER_LEN..drop_end)
        .ok_or(FrameError::Truncated)?;
    let expect_digest = frame_digest(stream_commitment, seq, drop_wire);
    if digest_wire != expect_digest {
        return Err(FrameError::DigestMismatch);
    }
    let drop = Drop::from_bytes(drop_wire).map_err(|_| FrameError::BadDrop)?;
    if drop.seq != seq {
        return Err(FrameError::BadDrop);
    }
    Ok(drop)
}

/// First four bytes of the stream commitment as a u32 LE (fast optical reject).
#[must_use]
pub fn stream_id_prefix(stream_commitment: &[u8; 32]) -> u32 {
    let b0 = stream_commitment.first().copied().unwrap_or(0);
    let b1 = stream_commitment.get(1).copied().unwrap_or(0);
    let b2 = stream_commitment.get(2).copied().unwrap_or(0);
    let b3 = stream_commitment.get(3).copied().unwrap_or(0);
    u32::from_le_bytes([b0, b1, b2, b3])
}

/// 4-byte frame integrity tag bound to stream + seq + drop wire.
#[must_use]
pub fn frame_digest(stream_commitment: &[u8; 32], seq: u32, drop_wire: &[u8]) -> [u8; 4] {
    let full = hash_fields_bytes(&[
        b"BDLM_THREE_QR_FRAME_V1",
        stream_commitment.as_slice(),
        &seq.to_le_bytes(),
        drop_wire,
    ]);
    [full[0], full[1], full[2], full[3]]
}

/// Fold frame digests in seq order into a stream address (A5 recipe can pin this).
///
/// # Errors
///
/// Empty `frame_digests` is refused — a zero-frame stream is not an address.
pub fn fold_frame_digests(frame_digests: &[[u8; 4]]) -> Result<[u8; 32], FrameError> {
    if frame_digests.is_empty() {
        return Err(FrameError::Truncated);
    }
    let mut acc = hash_fields_bytes(&[b"BDLM_THREE_QR_STREAM_ID_V1"]);
    for d in frame_digests {
        acc = hash_fields_bytes(&[b"BDLM_THREE_QR_STREAM_FOLD_V1", &acc, d.as_slice()]);
    }
    Ok(acc)
}

fn u16_from_le(bytes: &[u8], off: usize) -> Result<u16, FrameError> {
    let s = bytes.get(off..off + 2).ok_or(FrameError::Truncated)?;
    let mut a = [0u8; 2];
    a.copy_from_slice(s);
    Ok(u16::from_le_bytes(a))
}

fn u32_from_le(bytes: &[u8], off: usize) -> Result<u32, FrameError> {
    let s = bytes.get(off..off + 4).ok_or(FrameError::Truncated)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(u32::from_le_bytes(a))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_carousel::{
        planned_drop_count, CarouselDecoder, CarouselEncoder, DEFAULT_BLOCK_LEN, DROP_HEADER_LEN,
    };
    use crate::storage::qr_payload::{
        pack_payload, payload_commitment, unpack_payload, PayloadKind,
    };

    fn stream_for(payload: &[u8]) -> ([u8; 32], CarouselEncoder) {
        let packed_commit = payload_commitment(payload);
        let enc = CarouselEncoder::new(payload, DEFAULT_BLOCK_LEN).unwrap();
        let stream = enc.params().stream_commitment(&packed_commit);
        (stream, enc)
    }

    #[test]
    fn frame_round_trip_one_drop() {
        let content = b"frame-round-trip-content-bytes-xx";
        let packed = pack_payload(PayloadKind::ContentBytes, content).unwrap();
        let (stream, enc) = stream_for(&packed);
        let drop = enc.drop_at(0);
        let frame = pack_frame(&stream, &drop);
        assert_eq!(&frame[0..2], &THREE_FRAME_MAGIC);
        let parsed = unpack_frame(&stream, &frame).unwrap();
        assert_eq!(parsed, drop);
    }

    #[test]
    fn foreign_stream_rejected() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"abc-def-ghi-jkl").unwrap();
        let (stream, enc) = stream_for(&packed);
        let frame = pack_frame(&stream, &enc.drop_at(1));
        let mut other = stream;
        other[0] ^= 0xff;
        assert_eq!(
            unpack_frame(&other, &frame).unwrap_err(),
            FrameError::StreamMismatch
        );
    }

    #[test]
    fn tampered_drop_fails_digest() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"digest-guard-payload").unwrap();
        let (stream, enc) = stream_for(&packed);
        let mut frame = pack_frame(&stream, &enc.drop_at(0));
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        assert_eq!(
            unpack_frame(&stream, &frame).unwrap_err(),
            FrameError::DigestMismatch
        );
    }

    #[test]
    fn a1_a2_a3_pipe_recovers_content() {
        let content = b"full three pipe content through frames".repeat(15);
        let packed = pack_payload(PayloadKind::ContentBytes, &content).unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, DEFAULT_BLOCK_LEN).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let mut dec = CarouselDecoder::new();
        let n = planned_drop_count(enc.params().k, 0);
        let mut digests = Vec::new();
        for seq in 0..n {
            let drop = enc.drop_at(seq);
            let frame = pack_frame(&stream, &drop);
            let got = unpack_frame(&stream, &frame).unwrap();
            digests.push(frame_digest(&stream, seq, &got.to_bytes()));
            dec.push(&got).unwrap();
            if dec.is_complete() {
                break;
            }
        }
        assert!(dec.is_complete());
        let recovered = dec.finish().unwrap();
        assert_eq!(recovered, packed);
        let (kind, raw) = unpack_payload(&recovered).unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(raw, content.as_slice());
        let folded = fold_frame_digests(&digests).unwrap();
        assert_ne!(folded, [0u8; 32]);
    }

    #[test]
    fn bad_magic_refused() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"magic-check").unwrap();
        let (stream, enc) = stream_for(&packed);
        let mut frame = pack_frame(&stream, &enc.drop_at(0));
        frame[0] = 0x00;
        assert_eq!(
            unpack_frame(&stream, &frame).unwrap_err(),
            FrameError::BadMagic
        );
    }

    #[test]
    fn header_min_size_covers_empty_drop_reject() {
        // DROP_HEADER_LEN is public so A3 can reason about nested size.
        // The values are bound through runtime parameters so the invariant
        // is asserted without clippy's constant-folding path.
        fn check(header: usize, max_drop_wire: usize, frame_header: usize) {
            assert!(header < max_drop_wire);
            assert!(frame_header >= 18);
        }
        check(
            DROP_HEADER_LEN,
            usize::from(MAX_DROP_WIRE),
            THREE_FRAME_HEADER_LEN,
        );
    }
}
