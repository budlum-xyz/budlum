//! A4 - optical channel codec gate.
//!
//! In-tree we do **not** ship an H.264/VP9 muxer. What we can pin now is the
//! *policy* measured in the 3.0 spec: which codecs are allowed to carry
//! QR frames without destroying module readability, and that a mux step is
//! optional and versioned separately from A1-A3.
//!
//! # Measured posture
//!
//! - H.264 CRF ≤ 28: lab green for fountain recovery (lossy on modules, fountain repairs).
//! - VP9: green at high CRF in the measurement environment.
//! - AV1: no decoder in the measurement environment - **red** until proven.
//! - Raw frame list / live carousel: always allowed (no mux).
//!
//! A future mux adapter implements [`FrameMux`] and is refused unless
//! [`CodecKind::is_allowed`] is true.

/// Magic of the [`CodecKind::RawFrames`] carrier: frames concatenated under a
/// count header. Named here so the durable-storage classifier reads the same
/// constant the muxer writes - a bumped magic cannot silently un-classify a blob.
pub const RAW_CONCAT_MAGIC: [u8; 4] = *b"BDLR";

/// Channel kinds that may carry Three optical frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum CodecKind {
    /// No container - ordered frame blobs (lab default).
    RawFrames = 1,
    /// Live infinite carousel over a network/optical link.
    LiveCarousel = 2,
    /// H.264 in a minimal annex-B or MP4 (external tool).
    H264 = 3,
    /// VP9.
    Vp9 = 4,
    /// AV1 - not allowed until a lab decoder proves recovery.
    Av1 = 5,
}

impl CodecKind {
    /// Whether this build allows the codec as a Three channel.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        match self {
            Self::RawFrames | Self::LiveCarousel | Self::H264 | Self::Vp9 => true,
            Self::Av1 => false,
        }
    }

    /// Wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Errors from the codec gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Codec is not on the allow list.
    Forbidden(CodecKind),
    /// Mux adapter not linked in this build.
    MuxNotLinked,
    /// Empty frame list.
    EmptyFrames,
    /// Bytes remain after the declared frame list.
    TrailingBytes,
    /// Declared frame count is larger than the blob can physically hold.
    BadFrameCount {
        /// Declared count.
        count: u64,
    },
    /// A frame or the frame count does not fit the container's 32-bit field.
    ///
    /// The writer used to cast with `as u32`, which silently truncates: a
    /// 4 GiB frame became a short frame followed by bytes the reader then
    /// counted as the next header. Refusing the write is the only answer that
    /// keeps the container self-describing.
    FieldTooWide {
        /// The field that did not fit.
        field: &'static str,
        /// The value that did not fit.
        value: u64,
    },
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden(k) => write!(f, "three codec {k:?} forbidden by K-QR-KODEK gate"),
            Self::MuxNotLinked => write!(f, "three codec mux adapter not linked in this build"),
            Self::EmptyFrames => write!(f, "three codec refuses empty frame list"),
            Self::TrailingBytes => write!(f, "three codec container has trailing bytes"),
            Self::BadFrameCount { count } => {
                write!(f, "three codec refuses declared frame count {count}")
            }
            Self::FieldTooWide { field, value } => write!(
                f,
                "three codec refuses {field} {value}: it does not fit the 32-bit container field"
            ),
        }
    }
}

impl std::error::Error for CodecError {}

/// Gate a codec choice before any external mux runs.
///
/// # Errors
///
/// [`CodecError::Forbidden`] when the kind is not allowed.
pub const fn gate_codec(kind: CodecKind) -> Result<(), CodecError> {
    if kind.is_allowed() {
        Ok(())
    } else {
        Err(CodecError::Forbidden(kind))
    }
}

/// Optional mux trait - implement out-of-tree or behind a feature later.
///
/// A container is a pair of operations, not one: whoever links an encoder has to
/// supply the reader too, because the durable path refuses a blob it cannot split
/// back into frames. That is why `split` is on the trait rather than a free
/// function beside the raw placeholder, and why every consumer of the A4 carrier
/// goes through a `FrameMux` bound instead of the raw helpers.
pub trait FrameMux {
    /// Mux optical frames into a container file/stream.
    ///
    /// # Errors
    ///
    /// Implementation-defined; gate must pass first.
    fn mux(&self, kind: CodecKind, frames: &[Vec<u8>]) -> Result<Vec<u8>, CodecError>;

    /// Read the frames back out of a container this type wrote.
    ///
    /// # Errors
    ///
    /// [`CodecError::EmptyFrames`] when the blob is shorter than its own header or
    /// a length prefix runs past the end.
    fn split(&self, kind: CodecKind, blob: &[u8]) -> Result<Vec<Vec<u8>>, CodecError>;
}

/// Width check for one container field.
///
/// # Errors
///
/// [`CodecError::FieldTooWide`] when `value` does not fit a `u32`.
fn field_u32(field: &'static str, value: usize) -> Result<u32, CodecError> {
    u32::try_from(value).map_err(|_| CodecError::FieldTooWide {
        field,
        value: u64::try_from(value).unwrap_or(u64::MAX),
    })
}

/// In-tree placeholder mux: only [`CodecKind::RawFrames`] concatenates with a length prefix.
#[derive(Debug, Default, Clone, Copy)]
pub struct RawFrameConcat;

impl FrameMux for RawFrameConcat {
    fn mux(&self, kind: CodecKind, frames: &[Vec<u8>]) -> Result<Vec<u8>, CodecError> {
        gate_codec(kind)?;
        if kind != CodecKind::RawFrames {
            return Err(CodecError::MuxNotLinked);
        }
        if frames.is_empty() {
            return Err(CodecError::EmptyFrames);
        }
        let mut out = Vec::new();
        let count = field_u32("frame count", frames.len())?;
        out.extend_from_slice(&RAW_CONCAT_MAGIC);
        out.extend_from_slice(&count.to_le_bytes());
        for fr in frames {
            let len = field_u32("frame length", fr.len())?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(fr);
        }
        Ok(out)
    }
    fn split(&self, kind: CodecKind, blob: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
        gate_codec(kind)?;
        if kind != CodecKind::RawFrames {
            return Err(CodecError::MuxNotLinked);
        }
        if blob.len() < 8 || blob.get(0..4) != Some(RAW_CONCAT_MAGIC.as_slice()) {
            return Err(CodecError::EmptyFrames);
        }
        let n = {
            let s = blob.get(4..8).ok_or(CodecError::EmptyFrames)?;
            let mut a = [0u8; 4];
            a.copy_from_slice(s);
            u32::from_le_bytes(a) as usize
        };
        // The declared count cannot exceed what the blob can physically hold:
        // every frame costs at least its 4-byte length header. Bound it before
        // `Vec::with_capacity(n)` turns a forged count into a huge reservation.
        if n == 0 {
            return Err(CodecError::EmptyFrames);
        }
        let max_frames = (blob.len().saturating_sub(8)) / 4;
        if n > max_frames {
            return Err(CodecError::BadFrameCount { count: n as u64 });
        }
        let mut out = Vec::with_capacity(n);
        let mut off = 8usize;
        for _ in 0..n {
            let s = blob.get(off..off + 4).ok_or(CodecError::EmptyFrames)?;
            let mut a = [0u8; 4];
            a.copy_from_slice(s);
            let len = u32::from_le_bytes(a) as usize;
            off += 4;
            let end = off.checked_add(len).ok_or(CodecError::EmptyFrames)?;
            let fr = blob.get(off..end).ok_or(CodecError::EmptyFrames)?.to_vec();
            off = end;
            out.push(fr);
        }
        // Reject appended data instead of decoding an alias.
        if off != blob.len() {
            return Err(CodecError::TrailingBytes);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn av1_forbidden() {
        assert_eq!(
            gate_codec(CodecKind::Av1).unwrap_err(),
            CodecError::Forbidden(CodecKind::Av1)
        );
    }

    #[test]
    fn h264_allowed_but_mux_not_linked() {
        gate_codec(CodecKind::H264).unwrap();
        let mux = RawFrameConcat;
        assert_eq!(
            mux.mux(CodecKind::H264, &[vec![1, 2, 3]]).unwrap_err(),
            CodecError::MuxNotLinked
        );
    }

    #[test]
    fn raw_concat_refuses_trailers_zero_count_and_truncated_lengths() {
        let blob = RawFrameConcat
            .mux(CodecKind::RawFrames, &[vec![1, 2, 3]])
            .unwrap();
        for trailer in [&[0u8][..], &blob[..]] {
            let mut aliased = blob.clone();
            aliased.extend_from_slice(trailer);
            assert_eq!(
                RawFrameConcat.split(CodecKind::RawFrames, &aliased),
                Err(CodecError::TrailingBytes)
            );
        }
        let mut empty = RAW_CONCAT_MAGIC.to_vec();
        empty.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            RawFrameConcat.split(CodecKind::RawFrames, &empty),
            Err(CodecError::EmptyFrames)
        );
        let mut huge = blob;
        huge[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            RawFrameConcat.split(CodecKind::RawFrames, &huge),
            Err(CodecError::EmptyFrames)
        );
    }

    #[test]
    fn raw_concat_round_trip() {
        let frames = vec![vec![1, 2, 3], vec![4, 5]];
        let blob = RawFrameConcat.mux(CodecKind::RawFrames, &frames).unwrap();
        assert_eq!(
            RawFrameConcat.split(CodecKind::RawFrames, &blob).unwrap(),
            frames
        );
    }

    #[test]
    fn split_refuses_a_container_it_did_not_write() {
        // The reader is the writer's mirror, so a foreign blob (right length, wrong
        // magic) has to be refused rather than half-parsed.
        let blob = vec![b'X', b'Y', b'Z', b'Q', 1, 0, 0, 0, 3, 0, 0, 0, 9, 9, 9];
        assert_eq!(
            RawFrameConcat
                .split(CodecKind::RawFrames, &blob)
                .unwrap_err(),
            CodecError::EmptyFrames
        );
    }

    /// A tiny blob that declares a 4-billion-frame count must be refused before
    /// the reader reserves a `Vec` for it.
    #[test]
    fn split_refuses_a_forged_frame_count() {
        let mut blob = Vec::new();
        blob.extend_from_slice(RAW_CONCAT_MAGIC.as_slice());
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            RawFrameConcat
                .split(CodecKind::RawFrames, &blob)
                .unwrap_err(),
            CodecError::BadFrameCount {
                count: u64::from(u32::MAX)
            }
        );
    }
}

#[cfg(test)]
mod field_width_tests {
    use super::*;

    /// The container field is 32 bits, and the writer refuses a wider value
    /// instead of truncating it. A truncated length is what let a 4 GiB frame
    /// read back as a short frame followed by a forged header.
    #[test]
    fn a_container_field_wider_than_32_bits_is_refused() {
        assert_eq!(field_u32("frame length", 0).unwrap(), 0);
        assert_eq!(
            field_u32("frame length", u32::MAX as usize).unwrap(),
            u32::MAX
        );
        let error = field_u32("frame length", u32::MAX as usize + 1)
            .expect_err("a value past u32::MAX must be refused");
        let text = error.to_string();
        assert!(text.contains("frame length"), "{text}");
        assert!(text.contains("32-bit"), "{text}");
    }

    /// A container the writer wrote splits back into the frames it was given.
    #[test]
    fn a_muxed_container_splits_back_into_its_frames() {
        let frames = vec![b"one".to_vec(), Vec::new(), b"three".to_vec()];
        let blob = RawFrameConcat
            .mux(CodecKind::RawFrames, &frames)
            .expect("mux");
        assert_eq!(
            RawFrameConcat
                .split(CodecKind::RawFrames, &blob)
                .expect("split"),
            frames
        );
    }
}
