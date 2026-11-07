//! Framing: a big-endian `u32` length, then one protobuf [`pb::Envelope`].
//!
//! The frame bound and the version check live here and nowhere else, so every
//! reader and writer in the crate (client, server, fuzz target) has the same
//! two rules: a frame never exceeds [`MAX_FRAME_BYTES`], and an envelope on
//! another ABI version is refused before its body is interpreted.
//!
//! exposed for: UEL worker framing transport (`execution/` workers and `src/execution/coordinator`).

use crate::pb;
use prost::Message;
use std::io::{self, Read, Write};

/// The ABI version this build speaks. Bump it with any wire change to
/// `ee.proto`; the golden vectors in `tests/frames.rs` are what notices one.
pub const ABI_VERSION: u32 = 1;

/// The largest frame body in bytes.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Why a frame could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The length header (or the body being written) exceeds the limit.
    TooLarge { len: usize },
    /// The stream ended inside a frame.
    Truncated,
    /// The stream ended cleanly between frames.
    Closed,
    /// A zero-length frame carries no envelope.
    Empty,
    /// The peer speaks another ABI version.
    VersionMismatch { got: u32, want: u32 },
    /// The body is not a valid envelope.
    Decode(String),
    /// A socket deadline passed.
    Timeout,
    /// Any other I/O failure.
    Io(io::ErrorKind),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { len } => {
                write!(
                    f,
                    "frame of {len} bytes exceeds the {MAX_FRAME_BYTES} byte limit"
                )
            }
            Self::Truncated => write!(f, "stream ended inside a frame"),
            Self::Closed => write!(f, "stream closed"),
            Self::Empty => write!(f, "empty frame"),
            Self::VersionMismatch { got, want } => {
                write!(f, "ABI version {got} is not the supported version {want}")
            }
            Self::Decode(e) => write!(f, "envelope does not decode: {e}"),
            Self::Timeout => write!(f, "socket deadline passed"),
            Self::Io(kind) => write!(f, "i/o error: {kind}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::UnexpectedEof => Self::Truncated,
            kind => Self::Io(kind),
        }
    }
}

/// The ABI version at the head of an encoded envelope: field 1, a varint. A
/// body that does not start with that field reads as version 0 (proto3 omits a
/// zero), which no peer speaks.
fn peek_version(body: &[u8]) -> u32 {
    if body.first() != Some(&0x08) {
        return 0;
    }
    let mut value: u64 = 0;
    for (i, byte) in body.iter().skip(1).take(5).enumerate() {
        value |= u64::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return u32::try_from(value).unwrap_or(u32::MAX);
        }
    }
    // An unterminated or over-long varint is not a version this crate knows.
    u32::MAX
}

fn check_version(got: u32) -> Result<(), FrameError> {
    if got == ABI_VERSION {
        Ok(())
    } else {
        Err(FrameError::VersionMismatch {
            got,
            want: ABI_VERSION,
        })
    }
}

fn decode_body(body: &[u8]) -> Result<pb::Envelope, FrameError> {
    if body.is_empty() {
        return Err(FrameError::Empty);
    }
    check_version(peek_version(body))?;
    let envelope = pb::Envelope::decode(body).map_err(|e| FrameError::Decode(e.to_string()))?;
    // Protobuf permits repeated scalar fields: the last value wins. A peer
    // must not pass the early version check and then override that value.
    check_version(envelope.abi_version)?;
    Ok(envelope)
}

/// Encodes `envelope` as one frame (length header included).
///
/// # Errors
///
/// [`FrameError::VersionMismatch`] when the envelope names another ABI version,
/// [`FrameError::TooLarge`] when the body exceeds [`MAX_FRAME_BYTES`].
pub fn encode_frame(envelope: &pb::Envelope) -> Result<Vec<u8>, FrameError> {
    check_version(envelope.abi_version)?;
    let len = envelope.encoded_len();
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len });
    }
    let header = u32::try_from(len).map_err(|_| FrameError::TooLarge { len })?;
    let mut out = Vec::with_capacity(4 + len);
    out.extend_from_slice(&header.to_be_bytes());
    envelope
        .encode(&mut out)
        .map_err(|e| FrameError::Decode(e.to_string()))?;
    Ok(out)
}

/// Decodes one frame from the front of `bytes`, returning the envelope and how
/// many bytes the frame used.
///
/// # Errors
///
/// See [`FrameError`]. An over-limit header is refused before the body is
/// looked at.
pub fn decode_frame(bytes: &[u8]) -> Result<(pb::Envelope, usize), FrameError> {
    let Some(header) = bytes.get(..4) else {
        return Err(FrameError::Truncated);
    };
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(header);
    let len = usize::try_from(u32::from_be_bytes(len_bytes)).unwrap_or(usize::MAX);
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len });
    }
    let end = 4 + len;
    let Some(body) = bytes.get(4..end) else {
        return Err(FrameError::Truncated);
    };
    Ok((decode_body(body)?, end))
}

/// Writes `envelope` as one frame and flushes.
///
/// # Errors
///
/// As [`encode_frame`], plus any write failure.
pub fn write_frame<W: Write>(writer: &mut W, envelope: &pb::Envelope) -> Result<(), FrameError> {
    let frame = encode_frame(envelope)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

/// Reads one frame. The body is read only as far as the stream actually
/// delivers it, so a header that promises more than arrives costs nothing.
///
/// # Errors
///
/// [`FrameError::Closed`] on a clean end of stream before any byte, otherwise
/// as [`decode_frame`].
pub fn read_frame<R: Read>(reader: &mut R) -> Result<pb::Envelope, FrameError> {
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        let n = reader.read(&mut header[filled..])?;
        if n == 0 {
            return Err(if filled == 0 {
                FrameError::Closed
            } else {
                FrameError::Truncated
            });
        }
        filled += n;
    }
    let len = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { len });
    }
    let mut body = Vec::new();
    let wanted = u64::try_from(len).unwrap_or(u64::MAX);
    let got = reader.take(wanted).read_to_end(&mut body)?;
    if got < len {
        return Err(FrameError::Truncated);
    }
    decode_body(&body)
}
