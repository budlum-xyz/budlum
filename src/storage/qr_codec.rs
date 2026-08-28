//! A4 - optical channel codec gate (plan §CH A4, K-QR-KODEK).
//!
//! In-tree we do **not** ship an H.264/VP9 muxer. What we can pin now is the
//! *policy* measured in the 3.0 spec: which codecs are allowed to carry
//! QR frames without destroying module readability, and that a mux step is
//! optional and versioned separately from A1-A3.
//!
//! # Measured posture (spec K4/K5/K9)
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
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden(k) => write!(f, "three codec {k:?} forbidden by K-QR-KODEK gate"),
            Self::MuxNotLinked => write!(f, "three codec mux adapter not linked in this build"),
            Self::EmptyFrames => write!(f, "three codec refuses empty frame list"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Gate a codec choice before any external mux runs.
///
/// # Errors
///
/// [`CodecError::Forbidden`] when the kind is not allowed.
pub fn gate_codec(kind: CodecKind) -> Result<(), CodecError> {
    if kind.is_allowed() {
        Ok(())
    } else {
        Err(CodecError::Forbidden(kind))
    }
}

/// Optional mux trait - implement out-of-tree or behind a feature later.
pub trait FrameMux {
    /// Mux optical frames into a container file/stream.
    ///
    /// # Errors
    ///
    /// Implementation-defined; gate must pass first.
    fn mux(&self, kind: CodecKind, frames: &[Vec<u8>]) -> Result<Vec<u8>, CodecError>;
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
        out.extend_from_slice(&RAW_CONCAT_MAGIC);
        out.extend_from_slice(&(frames.len() as u32).to_le_bytes());
        for fr in frames {
            out.extend_from_slice(&(fr.len() as u32).to_le_bytes());
            out.extend_from_slice(fr);
        }
        Ok(out)
    }
}

/// Split a [`RawFrameConcat`] blob back into frames.
///
/// # Errors
///
/// Malformed blob.
pub fn split_raw_concat(blob: &[u8]) -> Result<Vec<Vec<u8>>, CodecError> {
    if blob.len() < 8 || blob.get(0..4) != Some(RAW_CONCAT_MAGIC.as_slice()) {
        return Err(CodecError::EmptyFrames);
    }
    let n = {
        let s = blob.get(4..8).ok_or(CodecError::EmptyFrames)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(s);
        u32::from_le_bytes(a) as usize
    };
    let mut out = Vec::with_capacity(n);
    let mut off = 8usize;
    for _ in 0..n {
        let s = blob.get(off..off + 4).ok_or(CodecError::EmptyFrames)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(s);
        let len = u32::from_le_bytes(a) as usize;
        off += 4;
        let fr = blob
            .get(off..off + len)
            .ok_or(CodecError::EmptyFrames)?
            .to_vec();
        off += len;
        out.push(fr);
    }
    Ok(out)
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
    fn raw_concat_round_trip() {
        let frames = vec![vec![1, 2, 3], vec![4, 5]];
        let blob = RawFrameConcat.mux(CodecKind::RawFrames, &frames).unwrap();
        assert_eq!(split_raw_concat(&blob).unwrap(), frames);
    }
}
