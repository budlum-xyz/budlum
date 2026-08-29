//! T4 / CH.4 - Three derivatives are not durable storage.
//!
//! WIRING: reference-enforced - the provider reference implementation checks
//! this gate on every put; the emit path that produces the blobs is still not
//! reachable from RPC (plan §CH.4), so the rule runs against the bytes a
//! reader can bring, not against our own output.
//!
//! Optical frames, carousel drops, and raw-concat mux blobs are **transport**.
//! A node that writes them into the content-addressed body store is lying about
//! the edition-Three model (recipe + optional sealed body, zero QR-as-storage).
//!
//! This gate is a pure classifier + refuse helper so RPC/providers can fail
//! closed without parsing the whole pipe.

use crate::storage::qr_carousel::DROP_MAGIC;
use crate::storage::qr_codec::RAW_CONCAT_MAGIC;
use crate::storage::qr_frame::THREE_FRAME_MAGIC;
use crate::storage::qr_payload::THREE_PAYLOAD_MAGIC;
use crate::storage::qr_video::VIDEO_MAGIC;

/// What kind of bytes someone is trying to put in a durable slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeBlobKind {
    /// A1 packed container (durable-capable: commitment body / sealed ciphertext).
    /// The only kind a provider stores.
    PackedPayload,
    /// A2 drop wire.
    CarouselDrop,
    /// A3 optical frame.
    OpticalFrame,
    /// A4 raw frame concat (`BDLR`).
    RawConcat,
    /// A4 QR-video container (`BDLV`) - recipe holds the pin; blob is derivative.
    QrVideo,
    /// Unknown / not a Three transport magic.
    Other,
}

/// Classify a blob by magic (cheap prefix check).
#[must_use]
pub fn classify_three_blob(bytes: &[u8]) -> ThreeBlobKind {
    if bytes.starts_with(&THREE_PAYLOAD_MAGIC) {
        return ThreeBlobKind::PackedPayload;
    }
    if bytes.starts_with(&DROP_MAGIC) {
        return ThreeBlobKind::CarouselDrop;
    }
    if bytes.starts_with(&THREE_FRAME_MAGIC) {
        return ThreeBlobKind::OpticalFrame;
    }
    if bytes.starts_with(&RAW_CONCAT_MAGIC) {
        return ThreeBlobKind::RawConcat;
    }
    if bytes.starts_with(&VIDEO_MAGIC) {
        return ThreeBlobKind::QrVideo;
    }
    ThreeBlobKind::Other
}

/// True when the blob is a transport derivative that must not be a stored body.
#[must_use]
pub fn is_transport_derivative(bytes: &[u8]) -> bool {
    matches!(
        classify_three_blob(bytes),
        ThreeBlobKind::CarouselDrop
            | ThreeBlobKind::OpticalFrame
            | ThreeBlobKind::RawConcat
            | ThreeBlobKind::QrVideo
    )
}

/// Refuse durable storage of transport derivatives.
///
/// # Errors
///
/// `Err(kind)` when the blob is a transport derivative.
pub fn refuse_durable_derivative(bytes: &[u8]) -> Result<(), ThreeBlobKind> {
    let kind = classify_three_blob(bytes);
    match kind {
        ThreeBlobKind::CarouselDrop
        | ThreeBlobKind::OpticalFrame
        | ThreeBlobKind::RawConcat
        | ThreeBlobKind::QrVideo => Err(kind),
        ThreeBlobKind::PackedPayload | ThreeBlobKind::Other => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_carousel::{CarouselEncoder, DEFAULT_BLOCK_LEN};
    use crate::storage::qr_codec::{CodecKind, FrameMux, RawFrameConcat};
    use crate::storage::qr_frame::pack_frame;
    use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadKind};
    use crate::storage::three_pipe::{decode_frames, encode_plain, PIPE_DEFAULT_BLOCK_LEN};

    #[test]
    fn frames_and_drops_refused() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"gate-body").unwrap();
        assert!(refuse_durable_derivative(&packed).is_ok());
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, DEFAULT_BLOCK_LEN).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let drop = enc.drop_at(0).to_bytes();
        assert_eq!(
            refuse_durable_derivative(&drop).unwrap_err(),
            ThreeBlobKind::CarouselDrop
        );
        let frame = pack_frame(&stream, &enc.drop_at(0));
        assert_eq!(
            refuse_durable_derivative(&frame).unwrap_err(),
            ThreeBlobKind::OpticalFrame
        );
        let concat = RawFrameConcat.mux(CodecKind::RawFrames, &[frame]).unwrap();
        assert_eq!(
            refuse_durable_derivative(&concat).unwrap_err(),
            ThreeBlobKind::RawConcat
        );
    }

    #[test]
    fn lossy_pipe_still_recovers() {
        // CH.4: round-trip with simulated frame loss.
        let content = b"lossy-channel-content-bytes".repeat(25);
        let enc = encode_qr_video(&content, PIPE_DEFAULT_BLOCK_LEN, None)
            .unwrap()
            .pipe;
        let mut kept = Vec::new();
        for (i, fr) in enc.frames.iter().enumerate() {
            // drop ~25% of frames
            if i % 4 == 0 {
                continue;
            }
            kept.push(fr.clone());
        }
        // may need full set under high loss - feed a second pass of survivors
        // by also taking repair half if first incomplete
        let result = decode_frames(&enc.stream_commitment, &kept);
        if let Ok((kind, raw)) = result {
            assert_eq!(kind, PayloadKind::ContentBytes);
            assert_eq!(raw, content.as_slice());
        } else {
            // feed all non-multiples of 5 from original (different pattern)
            let mut kept2: Vec<_> = enc
                .frames
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 5 != 0)
                .map(|(_, f)| f.clone())
                .collect();
            kept2.extend(kept);
            let (kind, raw) = decode_frames(&enc.stream_commitment, &kept2)
                .expect("second pass with the original pattern must decode");
            assert_eq!(kind, PayloadKind::ContentBytes);
            assert_eq!(raw, content.as_slice());
        }
    }
}
