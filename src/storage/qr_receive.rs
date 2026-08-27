//! B.U.D. 3.0 progressive receiver (plan §CH A7, K-QR-AKIS / K-QR-KARUSEL).
//!
//! Ingests A3 optical frames (or raw A2 drops), peels the carousel, and
//! exposes **prefix availability**: how many leading source blocks are solid
//! so a UI can show progressive content before the full object is recovered.
//!
//! # What this module does not claim
//!
//! - UI/UX chrome.
//! - Video demux (A4).
//! - Automatic sealed-body decrypt (caller supplies key after finish).

use crate::storage::qr_carousel::{CarouselDecoder, CarouselError, Drop};
use crate::storage::qr_frame::{unpack_frame, FrameError};
use crate::storage::qr_payload::{unpack_payload, PayloadError, PayloadKind};

/// Errors from the progressive receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError {
    /// Nested frame error.
    Frame(FrameError),
    /// Nested carousel error.
    Carousel(CarouselError),
    /// Nested payload error on finish.
    Payload(PayloadError),
    /// Finish called before the carousel is complete.
    Incomplete {
        /// Missing source blocks.
        missing: usize,
    },
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "receive frame: {e}"),
            Self::Carousel(e) => write!(f, "receive carousel: {e}"),
            Self::Payload(e) => write!(f, "receive payload: {e}"),
            Self::Incomplete { missing } => {
                write!(f, "receive incomplete, {missing} blocks missing")
            }
        }
    }
}

impl std::error::Error for ReceiveError {}

impl From<FrameError> for ReceiveError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

impl From<CarouselError> for ReceiveError {
    fn from(e: CarouselError) -> Self {
        Self::Carousel(e)
    }
}

impl From<PayloadError> for ReceiveError {
    fn from(e: PayloadError) -> Self {
        Self::Payload(e)
    }
}

/// Progressive Three-pipe receiver.
#[derive(Debug, Clone)]
pub struct ProgressiveReceiver {
    stream_commitment: [u8; 32],
    decoder: CarouselDecoder,
    /// Dedup map: seq → body hash; conflicting payload for same seq drops both.
    seen: std::collections::BTreeMap<u32, u32>,
    frames_accepted: u32,
    frames_rejected: u32,
}

impl ProgressiveReceiver {
    /// Bind to an expected A2/A3 stream commitment (from the recipe).
    #[must_use]
    pub fn new(stream_commitment: [u8; 32]) -> Self {
        Self {
            stream_commitment,
            decoder: CarouselDecoder::new(),
            seen: std::collections::BTreeMap::new(),
            frames_accepted: 0,
            frames_rejected: 0,
        }
    }

    /// Ingest one optical frame.
    ///
    /// # Errors
    ///
    /// Frame authentication / carousel push failures. Duplicate identical
    /// frames are ignored (not an error). Conflicting same-seq different body
    /// rejects the new frame (counted) without poisoning the decoder.
    pub fn push_frame(&mut self, frame: &[u8]) -> Result<(), ReceiveError> {
        let drop = match unpack_frame(&self.stream_commitment, frame) {
            Ok(d) => d,
            Err(e) => {
                self.frames_rejected = self.frames_rejected.saturating_add(1);
                return Err(e.into());
            }
        };
        self.push_drop(drop)
    }

    /// Ingest a raw A2 drop (already authenticated by the caller).
    pub fn push_drop(&mut self, drop: Drop) -> Result<(), ReceiveError> {
        let body_tag = fnv1a32_local(&drop.body);
        if let Some(prev) = self.seen.get(&drop.seq) {
            if *prev == body_tag {
                // exact duplicate — ignore
                return Ok(());
            }
            // conflict: drop both (do not push)
            self.frames_rejected = self.frames_rejected.saturating_add(1);
            return Ok(());
        }
        self.seen.insert(drop.seq, body_tag);
        self.decoder.push(&drop)?;
        self.frames_accepted = self.frames_accepted.saturating_add(1);
        Ok(())
    }

    /// True when every source block is known.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.decoder.is_complete()
    }

    /// How many source blocks are still unknown.
    #[must_use]
    pub fn missing(&self) -> usize {
        self.decoder.missing()
    }

    /// Leading contiguous solved blocks (progressive prefix length in blocks).
    ///
    /// K-QR-KARUSEL: systematic scan makes this climb early under low loss.
    #[must_use]
    pub fn solid_prefix_blocks(&self) -> usize {
        // CarouselDecoder does not expose solved directly — use finish attempt
        // on a clone only when complete; otherwise we need an accessor.
        // We added no public solved view; approximate via missing==0 full else 0
        // until we expose prefix. For real progressive, query decoder.
        self.decoder.solid_prefix_blocks()
    }

    /// Accepted / rejected frame counters (lab metrics).
    #[must_use]
    pub const fn stats(&self) -> (u32, u32) {
        (self.frames_accepted, self.frames_rejected)
    }

    /// Finish: packed A1 bytes.
    ///
    /// # Errors
    ///
    /// Incomplete carousel.
    pub fn finish_packed(&self) -> Result<Vec<u8>, ReceiveError> {
        if !self.is_complete() {
            return Err(ReceiveError::Incomplete {
                missing: self.missing(),
            });
        }
        Ok(self.decoder.finish()?)
    }

    /// Finish and unpack A1 → (kind, raw body bytes).
    pub fn finish_unpacked(&self) -> Result<(PayloadKind, Vec<u8>), ReceiveError> {
        let packed = self.finish_packed()?;
        Ok(unpack_payload(&packed)?)
    }
}

fn fnv1a32_local(data: &[u8]) -> u32 {
    let mut h = 0x811c_9dc5_u32;
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_carousel::{planned_drop_count, CarouselEncoder, DEFAULT_BLOCK_LEN};
    use crate::storage::qr_frame::pack_frame;
    use crate::storage::qr_payload::{pack_payload, payload_commitment, PayloadKind};
    use crate::storage::qr_recipe::ThreeRecipePublic;
    use crate::storage::qr_reemit::RecipeEmitter;

    #[test]
    fn progressive_prefix_grows_on_systematic() {
        let packed =
            pack_payload(PayloadKind::ContentBytes, &b"prefix-progress".repeat(30)).unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, DEFAULT_BLOCK_LEN).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let mut rx = ProgressiveReceiver::new(stream);
        let k = u32::from(enc.params().k);
        // Feed first 10% systematic drops
        let first = (k / 10).max(1);
        for seq in 0..first {
            rx.push_frame(&pack_frame(&stream, &enc.drop_at(seq)))
                .unwrap();
        }
        let prefix = rx.solid_prefix_blocks();
        assert!(
            prefix >= first as usize || rx.is_complete(),
            "prefix {prefix} after {first} systematic"
        );
    }

    #[test]
    fn full_receive_via_emitter() {
        let content = b"a7-receive-content-bytes".repeat(8);
        let packed = pack_payload(PayloadKind::ContentBytes, &content).unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 64).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let recipe = ThreeRecipePublic::new(commit, enc.params(), stream);
        let emitter = RecipeEmitter::open(recipe, &packed).unwrap();
        let mut rx = ProgressiveReceiver::new(stream);
        let n = planned_drop_count(enc.params().k, 0);
        for seq in 0..n {
            rx.push_frame(&emitter.frame_at(seq)).unwrap();
            if rx.is_complete() {
                break;
            }
        }
        assert!(rx.is_complete());
        let (kind, raw) = rx.finish_unpacked().unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(raw, content.as_slice());
    }

    #[test]
    fn duplicate_frame_ignored() {
        let packed = pack_payload(PayloadKind::ContentBytes, b"dup-frame-test-bytes").unwrap();
        let commit = payload_commitment(&packed);
        let enc = CarouselEncoder::new(&packed, 32).unwrap();
        let stream = enc.params().stream_commitment(&commit);
        let mut rx = ProgressiveReceiver::new(stream);
        let f = pack_frame(&stream, &enc.drop_at(0));
        rx.push_frame(&f).unwrap();
        rx.push_frame(&f).unwrap();
        let (ok, bad) = rx.stats();
        assert_eq!(ok, 1);
        assert_eq!(bad, 0);
    }
}
