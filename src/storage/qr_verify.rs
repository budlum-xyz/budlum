//! Fail-closed check of a QR video against commitments the caller holds.
//!
//! `decode_qr_video` reads the stream and recipe commitments out of the video
//! it decodes. A video that is consistent with itself therefore decodes, even
//! when it is not the video the caller meant to get. This module compares the
//! decoded result with commitments that were computed on the encode side, from
//! the content and the pipe, and not from the video.
//!
//! Every failure and every late answer is a refusal. There is no bypass, no
//! fast path and no trusted-content exception.
//!
//! WIRING: `storage::emit::qr_feed_preview` calls [`verify_qr_video`] for the
//! video it has just encoded (RPC `bud_storageQrFeedPreview`).

use crate::core::hash::{calculate_hash_bytes, hash_fields_bytes};
use crate::storage::content_id::ContentId;
use crate::storage::qr_payload::PayloadKind;
use crate::storage::qr_verify_indep::{confirm, IndepError, PrimaryClaim};
use crate::storage::qr_video::{demux_optical_frames, QrVideo};
use crate::storage::three_pipe::{decode_qr_video, recipe_commitment, EncodedPipe, PipeError};
use std::time::{Duration, Instant};

/// Name of the decode path the record reports.
pub const VERIFY_PATH: &str = "decode_qr_video";

/// Commitments held by the caller. None of them is read from the video.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedCommitments {
    /// `ContentId` of the body the video must carry.
    pub content_id: ContentId,
    /// Commitment of the public recipe the video must carry.
    pub recipe_commitment: [u8; 32],
    /// A2 stream commitment the video must carry.
    pub stream_commitment: [u8; 32],
    /// Payload kind the video must carry. `None` means the A1 header of the
    /// pipe has no known kind: no video can match it, so every video is refused.
    pub kind: Option<PayloadKind>,
}

impl ExpectedCommitments {
    /// Build the expectations from an encode step.
    ///
    /// `body` is what the video must decode to: the content for a clear feed,
    /// or the sealed body for a sealed feed (its nonce is random, so the
    /// encoder is the only party that holds it).
    #[must_use]
    pub fn from_encode(body: &[u8], pipe: &EncodedPipe) -> Self {
        Self {
            content_id: ContentId::of(body),
            recipe_commitment: recipe_commitment(&pipe.recipe),
            stream_commitment: pipe.stream_commitment,
            // Byte 6 of the A1 container is the kind tag.
            kind: pipe.packed.get(6).copied().and_then(PayloadKind::from_tag),
        }
    }
}

/// Why a video was refused.
#[derive(Debug)]
pub enum VerifyError {
    /// The video did not decode.
    Decode(PipeError),
    /// The decoded body is not the expected content.
    ContentIdMismatch {
        /// Expected.
        want: [u8; 32],
        /// Decoded.
        got: [u8; 32],
    },
    /// The video carries another recipe.
    RecipeMismatch {
        /// Expected.
        want: [u8; 32],
        /// In the video.
        got: [u8; 32],
    },
    /// The video carries another stream commitment.
    StreamMismatch {
        /// Expected.
        want: [u8; 32],
        /// In the video.
        got: [u8; 32],
    },
    /// The video carries another payload kind.
    KindMismatch {
        /// Expected.
        want: Option<PayloadKind>,
        /// Decoded.
        got: PayloadKind,
    },
    /// The independent verifier refused or disagreed with the primary decode.
    Independent(IndepError),
    /// The check took longer than the deadline.
    TimedOut {
        /// Deadline in microseconds.
        limit_micros: u64,
        /// Time used, in microseconds.
        elapsed_micros: u64,
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "qr video does not decode: {e}"),
            Self::ContentIdMismatch { .. } => write!(f, "qr video content id is not expected"),
            Self::RecipeMismatch { .. } => write!(f, "qr video recipe commitment is not expected"),
            Self::StreamMismatch { .. } => write!(f, "qr video stream commitment is not expected"),
            Self::KindMismatch { .. } => write!(f, "qr video payload kind is not expected"),
            Self::Independent(e) => write!(f, "qr video independent check: {e}"),
            Self::TimedOut {
                limit_micros,
                elapsed_micros,
            } => write!(
                f,
                "qr video check used {elapsed_micros} us, limit {limit_micros} us"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<PipeError> for VerifyError {
    fn from(e: PipeError) -> Self {
        Self::Decode(e)
    }
}

/// Node-local record of one accepted check. It holds hashes and a duration, no keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRecord {
    /// Tagged hash of the video bytes.
    pub input_hash: [u8; 32],
    /// `ContentId` of the decoded body.
    pub output_hash: [u8; 32],
    /// Decode path used.
    pub path: &'static str,
    /// Time used, in microseconds. Not a consensus input.
    pub duration_micros: u64,
}

/// Payload kind, decoded body, the parsed video and the record.
pub type VerifiedVideo = (PayloadKind, Vec<u8>, QrVideo, VerificationRecord);

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// Decode a QR video and compare it with the expected commitments.
///
/// Returns the payload kind, the decoded body and the parsed video, with the record. Any
/// decode error, any mismatch and a check over `deadline` is an error.
///
/// # Errors
///
/// [`VerifyError`] naming the first failed check.
pub fn verify_qr_video(
    video_blob: &[u8],
    expected: &ExpectedCommitments,
    deadline: Duration,
) -> Result<VerifiedVideo, VerifyError> {
    let started = Instant::now();
    let input_hash = hash_fields_bytes(&[b"BDLM_QR_VERIFY_INPUT_V1", video_blob]);
    let outcome = check(video_blob, expected, input_hash, started, deadline);
    match &outcome {
        Ok((_, _, _, rec)) => tracing::info!(
            input_hash = ?rec.input_hash,
            output_hash = ?rec.output_hash,
            path = rec.path,
            duration_micros = rec.duration_micros,
            "qr video verified"
        ),
        Err(e) => tracing::warn!(
            input_hash = ?input_hash,
            path = VERIFY_PATH,
            duration_micros = micros(started.elapsed()),
            reason = %e,
            "qr video refused"
        ),
    }
    outcome
}

fn check(
    video_blob: &[u8],
    expected: &ExpectedCommitments,
    input_hash: [u8; 32],
    started: Instant,
    deadline: Duration,
) -> Result<VerifiedVideo, VerifyError> {
    // The decoder is `decode_qr_video`. The optical frames are read a second
    // time here because the independent verifier below needs them.
    let (kind, body, video) = decode_qr_video(video_blob)?;
    let optical = demux_optical_frames(&video).map_err(PipeError::from)?;
    let got = ContentId::of(&body);
    if got != expected.content_id {
        return Err(VerifyError::ContentIdMismatch {
            want: *expected.content_id.as_bytes(),
            got: *got.as_bytes(),
        });
    }
    if video.recipe_commitment != expected.recipe_commitment {
        return Err(VerifyError::RecipeMismatch {
            want: expected.recipe_commitment,
            got: video.recipe_commitment,
        });
    }
    if video.stream_commitment != expected.stream_commitment {
        return Err(VerifyError::StreamMismatch {
            want: expected.stream_commitment,
            got: video.stream_commitment,
        });
    }
    if expected.kind != Some(kind) {
        return Err(VerifyError::KindMismatch {
            want: expected.kind,
            got: kind,
        });
    }
    // Second reading of the same frames by code that shares nothing with the
    // decoder above. It returns no content: it confirms kind and body hash.
    let claim = PrimaryClaim {
        kind_tag: kind.tag(),
        content_sha256: calculate_hash_bytes(&body),
    };
    confirm(&video.stream_commitment, &optical, &claim).map_err(VerifyError::Independent)?;
    let elapsed = started.elapsed();
    if elapsed > deadline {
        return Err(VerifyError::TimedOut {
            limit_micros: micros(deadline),
            elapsed_micros: micros(elapsed),
        });
    }
    let record = VerificationRecord {
        input_hash,
        output_hash: *got.as_bytes(),
        path: VERIFY_PATH,
        duration_micros: micros(elapsed),
    };
    Ok((kind, body, video, record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::payload_crypt::PayloadKey;
    use crate::storage::qr_carousel::CarouselEncoder;
    use crate::storage::qr_frame::pack_frame;
    use crate::storage::three_pipe::{decode_qr_video, encode_qr_video};

    const LIMIT: Duration = Duration::from_secs(60);

    fn honest(content: &[u8]) -> (Vec<u8>, ExpectedCommitments) {
        let enc = encode_qr_video(content, 64, None).unwrap();
        let exp = ExpectedCommitments::from_encode(content, &enc.pipe);
        (enc.video_blob, exp)
    }

    #[test]
    fn honest_video_passes_with_filled_record() {
        let content = b"verify-honest-video".repeat(9);
        let (blob, exp) = honest(&content);
        let (kind, body, _video, rec) = verify_qr_video(&blob, &exp, LIMIT).unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(body, content);
        assert_eq!(rec.path, VERIFY_PATH);
        assert_eq!(rec.output_hash, *ContentId::of(&content).as_bytes());
        assert_eq!(
            rec.input_hash,
            hash_fields_bytes(&[b"BDLM_QR_VERIFY_INPUT_V1", &blob])
        );
        assert_ne!(rec.input_hash, [0u8; 32]);
    }

    #[test]
    fn zero_byte_content_is_verified() {
        let (blob, exp) = honest(b"");
        let (_, body, _video, rec) = verify_qr_video(&blob, &exp, LIMIT).unwrap();
        assert!(body.is_empty());
        assert_eq!(rec.output_hash, *ContentId::of(b"").as_bytes());
    }

    #[test]
    fn self_consistent_fake_video_is_refused() {
        let (fake_blob, _) = honest(&b"fake-video-body".repeat(7));
        let (_, expected) = honest(&b"real-content-body".repeat(7));
        // The fake decodes alone, so decode_qr_video accepts it.
        assert!(decode_qr_video(&fake_blob).is_ok());
        assert!(verify_qr_video(&fake_blob, &expected, LIMIT).is_err());
    }

    #[test]
    fn content_id_mismatch_is_refused() {
        let (blob, mut exp) = honest(b"content-id-case");
        exp.content_id = ContentId::of(b"other");
        assert!(matches!(
            verify_qr_video(&blob, &exp, LIMIT),
            Err(VerifyError::ContentIdMismatch { .. })
        ));
    }

    #[test]
    fn recipe_mismatch_is_refused() {
        let (blob, mut exp) = honest(b"recipe-case");
        exp.recipe_commitment[0] ^= 1;
        assert!(matches!(
            verify_qr_video(&blob, &exp, LIMIT),
            Err(VerifyError::RecipeMismatch { .. })
        ));
    }

    #[test]
    fn stream_mismatch_is_refused() {
        let (blob, mut exp) = honest(b"stream-case");
        exp.stream_commitment[0] ^= 1;
        assert!(matches!(
            verify_qr_video(&blob, &exp, LIMIT),
            Err(VerifyError::StreamMismatch { .. })
        ));
    }

    #[test]
    fn broken_video_is_refused() {
        let (blob, exp) = honest(b"broken-case");
        let cut = &blob[..blob.len() / 2];
        assert!(matches!(
            verify_qr_video(cut, &exp, LIMIT),
            Err(VerifyError::Decode(_))
        ));
        assert!(matches!(
            verify_qr_video(&[], &exp, LIMIT),
            Err(VerifyError::Decode(_))
        ));
    }

    #[test]
    fn zero_deadline_is_refused() {
        let (blob, exp) = honest(b"deadline-case");
        assert!(matches!(
            verify_qr_video(&blob, &exp, Duration::ZERO),
            Err(VerifyError::TimedOut { .. })
        ));
    }

    #[test]
    fn expected_kind_follows_the_pipe() {
        let clear = encode_qr_video(b"kind-clear", 64, None).unwrap();
        assert_eq!(
            ExpectedCommitments::from_encode(b"kind-clear", &clear.pipe).kind,
            Some(PayloadKind::ContentBytes)
        );
        let key = PayloadKey([9u8; 32]);
        let sealed = encode_qr_video(b"kind-sealed", 64, Some(&key)).unwrap();
        assert_eq!(
            ExpectedCommitments::from_encode(b"kind-sealed", &sealed.pipe).kind,
            Some(PayloadKind::EncryptedContent)
        );
    }

    #[test]
    fn kind_mismatch_is_refused() {
        let (blob, mut exp) = honest(b"kind-case");
        exp.kind = Some(PayloadKind::EncryptedContent);
        assert!(matches!(
            verify_qr_video(&blob, &exp, LIMIT),
            Err(VerifyError::KindMismatch {
                want: Some(PayloadKind::EncryptedContent),
                got: PayloadKind::ContentBytes
            })
        ));
        exp.kind = None;
        assert!(matches!(
            verify_qr_video(&blob, &exp, LIMIT),
            Err(VerifyError::KindMismatch { want: None, .. })
        ));
    }

    #[test]
    fn independent_path_refuses_a_stream_id_the_bytes_do_not_give() {
        // Frames bound to an arbitrary stream id once decoded alone and
        // matched expectations built from the same id; the primary receive
        // path now recomputes the commitment from the rebuilt bytes at
        // finish, so the forgery already dies at decode - and the
        // independent path refuses the same frames for the same reason
        // (pinned directly in `qr_verify_indep`).
        let content = b"forged-stream-id".repeat(12);
        let enc = encode_qr_video(&content, 64, None).unwrap();
        let sc = [7u8; 32];
        let carousel = CarouselEncoder::new(&enc.pipe.packed, 64).unwrap();
        let frames: Vec<Vec<u8>> = carousel
            .encode_range(0, 16)
            .iter()
            .map(|d| pack_frame(&sc, d).unwrap())
            .collect();
        let video = QrVideo::from_optical_frames(&enc.pipe.recipe, &sc, &frames, 10).unwrap();
        let exp = ExpectedCommitments {
            content_id: ContentId::of(&content),
            recipe_commitment: video.recipe_commitment,
            stream_commitment: sc,
            kind: Some(PayloadKind::ContentBytes),
        };
        let blob = video.to_bytes();
        assert!(decode_qr_video(&blob).is_err());
        assert!(matches!(
            verify_qr_video(&blob, &exp, LIMIT),
            Err(VerifyError::Decode(_))
        ));
    }
}
