//! Live streams (T-Expansion, WP-55).
//!
//! A live source is cut into fixed time segments. Each segment is its own
//! BOF-1 object with the `bit1` live flag set, and the `prev_object` field
//! chains the segments into one ordered broadcast. The send order is
//! ratioless: every source frame first, then continuous repair frames, with
//! no fixed source-to-repair ratio. A viewer joins at any moment and starts
//! from the newest complete segment; the join latency budget is two segment
//! durations. When the broadcast ends, the chain's final object commitment
//! is bound to an NFT.
//!
//! * Segments: the default segment duration is [`LIVE_SEGMENT_MS`]. It is a
//!   starting parameter; governance changes it once measurements arrive.
//!   The window of a segment is `[start_ms, start_ms + LIVE_SEGMENT_MS)` and
//!   the windows are contiguous: the next segment starts exactly when the
//!   previous one ends.
//! * The profile: objects are P0. The P1 optical profile is a property of
//!   the transport derived at request time and is never written in an
//!   object, so a live segment object carries P0 like every other object.
//! * The optical transfer: the frames are the RFC 6330 symbols of the
//!   segment object. [`RatiolessPlan`] yields the order they are sent in;
//!   the sender maps each frame to its symbol through `SegmentEncoder`.
//! * The gate: live segments are T-Expansion work. `ACTIVATION` holds no
//!   height, so every step is refused at testnet launch
//!   (`bud3_live_is_closed_on_testnet`). The activation height is set after
//!   launch (M7), and bit1 objects are accepted only at and above it.
//!
//! WIRING: unwired - the block executor reaches live segments through the
//! live StorageTx variants once the activation height is set, and the final
//! NFT binding is written through `StorageTxV3::BindNft`. Until then the
//! state machine is exercised by its tests, like the rest of `bud3`.

use super::bof1::{Bof1Error, Flags, Header, Object, CODEC_RAW};
use super::content_id::ContentId;
use super::fountain::MAX_ESI;
use super::limits::Profile;
use super::registry::NftId;
use super::segment::{commit_object, ObjectCommitment};
use crate::core::hash::hash_fields_bytes;

/// The default segment duration, in milliseconds. TESTNET-DEFAULT.
pub const LIVE_SEGMENT_MS: u64 = 2_000;

/// A viewer joins within this many segment durations of the head (two).
pub const MAX_JOIN_LATENCY_SEGMENTS: u64 = 2;

/// The join latency budget in milliseconds.
pub const MAX_JOIN_LATENCY_MS: u64 = MAX_JOIN_LATENCY_SEGMENTS * LIVE_SEGMENT_MS;

/// The stream id domain separation tag.
pub const LIVE_STREAM_TAG: &[u8] = b"BDLM_BUD3_LIVE_STREAM_V1";

/// The stream end domain separation tag.
pub const LIVE_END_TAG: &[u8] = b"BDLM_BUD3_LIVE_END_V1";

/// When live segments open. `None`: closed on this chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveActivation {
    /// The activation height; `None` refuses every live segment.
    pub height: Option<u64>,
}

impl LiveActivation {
    /// Whether live segments are open at `height`.
    #[must_use]
    pub fn is_open_at(&self, height: u64) -> bool {
        self.height.is_some_and(|h| height >= h)
    }
}

/// TESTNET-DEFAULT: closed. The activation height is set after launch (M7).
pub const ACTIVATION: LiveActivation = LiveActivation { height: None };

/// The gate context of one live call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveContext {
    /// The block height the call is applied at.
    pub height: u64,
    /// The chain's activation schedule.
    pub activation: LiveActivation,
}

impl LiveContext {
    /// The testnet launch context: closed, at height 1.
    #[must_use]
    pub const fn closed() -> Self {
        Self {
            height: 1,
            activation: ACTIVATION,
        }
    }

    fn check_open(&self) -> Result<(), LiveError> {
        if self.activation.is_open_at(self.height) {
            Ok(())
        } else {
            Err(LiveError::Closed)
        }
    }
}

/// Why a live stream refused a step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveError {
    /// bit1 objects are refused before the activation height (and at testnet
    /// launch).
    Closed,
    /// The segment does not continue the stream's timeline.
    NonContiguous {
        /// Where the next segment must start.
        expected_start_ms: u64,
        /// Where it started.
        got_start_ms: u64,
    },
    /// A segment with no bytes is not a segment.
    EmptySegment,
    /// The fixed segment window would exceed the timestamp domain.
    TimestampOverflow,
    /// The broadcast has no segment yet.
    EmptyStream,
    /// The newest segment ended more than two segment durations ago, so the
    /// join latency budget cannot be honored.
    HeadStale {
        /// How far the head is behind the requested time.
        age_ms: u64,
        /// The budget, [`MAX_JOIN_LATENCY_MS`].
        max_ms: u64,
    },
    /// The BOF-1 object carries no live flag.
    NotLive {
        /// Position in the checked chain.
        index: u64,
    },
    /// The `prev_object` link of segment `index` does not match.
    ChainBroken {
        /// Position in the checked chain.
        index: u64,
    },
    /// The object would not parse as BOF-1.
    Object(Bof1Error),
    /// The object commitment could not be computed.
    CommitFailed,
    /// A per-segment repair-limit table has the wrong length.
    RepairLimitCountMismatch {
        /// Number of source-count entries.
        segments: usize,
        /// Number of repair-limit entries.
        limits: usize,
    },
    /// A repair limit exceeds the RFC 6330 ESI domain.
    RepairLimitOutOfRange {
        /// Segment whose limit is invalid.
        segment: u64,
        /// Requested inclusive repair ESI limit.
        limit: u32,
    },
}

/// One produced live segment: the BOF-1 object and its commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSegment {
    /// The P0 BOF-1 object with the live flag set.
    pub object: Object,
    /// The object commitment of the segment object; the link the next
    /// segment carries in `prev_object`.
    pub commitment: ObjectCommitment,
    /// Position in the stream, from 0.
    pub index: u64,
    /// Inclusive start of the segment window.
    pub start_ms: u64,
    /// Exclusive end of the segment window; `start_ms + LIVE_SEGMENT_MS`.
    pub end_ms: u64,
}

/// The writer side of one live broadcast.
///
/// The stream is created by [`LiveStream::begin`] and closed by
/// [`LiveStream::finish`]. The segments are produced in time order; the
/// object of every segment carries the commitment of the previous segment in
/// `prev_object`. The first segment carries the stream id.
#[derive(Debug, Clone)]
pub struct LiveStream {
    stream_id: [u8; 32],
    ctx: LiveContext,
    segments: Vec<LiveSegment>,
}

impl LiveStream {
    /// Start a stream. Refused while the chain has not opened live.
    ///
    /// # Errors
    ///
    /// [`LiveError::Closed`] at testnet launch and below the activation
    /// height.
    pub fn begin(
        originator: [u8; 32],
        nonce: [u8; 32],
        ctx: LiveContext,
    ) -> Result<Self, LiveError> {
        ctx.check_open()?;
        Ok(Self {
            stream_id: hash_fields_bytes(&[LIVE_STREAM_TAG, &originator, &nonce]),
            ctx,
            segments: Vec::new(),
        })
    }

    /// The stream id: the head of the segment chain.
    #[must_use]
    pub fn stream_id(&self) -> [u8; 32] {
        self.stream_id
    }

    /// The produced segments, in order.
    #[must_use]
    pub fn segments(&self) -> &[LiveSegment] {
        &self.segments
    }

    /// The end of the newest segment, if any.
    #[must_use]
    pub fn head_end_ms(&self) -> Option<u64> {
        self.segments.last().map(|segment| segment.end_ms)
    }

    /// The commitment of the newest segment, if any.
    #[must_use]
    pub fn head_commitment(&self) -> Option<ObjectCommitment> {
        self.segments.last().map(|segment| segment.commitment)
    }

    /// Produce the next time segment.
    ///
    /// `start_ms` continues the timeline: the first segment starts when the
    /// caller says the broadcast starts, every later segment starts exactly
    /// when the previous one ended. A gap or an overlap is refused, so two
    /// honest producers of the same timeline reach the same chain.
    ///
    /// # Errors
    ///
    /// [`LiveError::Closed`] before the activation height,
    /// [`LiveError::EmptySegment`] for empty content,
    /// [`LiveError::TimestampOverflow`] when the fixed window cannot be
    /// represented,
    /// [`LiveError::NonContiguous`] when `start_ms` does not continue the
    /// timeline.
    pub fn push_segment(
        &mut self,
        start_ms: u64,
        content: &[u8],
    ) -> Result<LiveSegment, LiveError> {
        self.ctx.check_open()?;
        if content.is_empty() {
            return Err(LiveError::EmptySegment);
        }
        let expected_start_ms = self.segments.last().map_or(start_ms, |segment| segment.end_ms);
        if start_ms != expected_start_ms {
            return Err(LiveError::NonContiguous {
                expected_start_ms,
                got_start_ms: start_ms,
            });
        }
        let index = self.segments.len() as u64;
        let end_ms = start_ms
            .checked_add(LIVE_SEGMENT_MS)
            .ok_or(LiveError::TimestampOverflow)?;
        let prev_object = self.segments.last().map_or(self.stream_id, |segment| segment.commitment);
        let id = ContentId::public(content);
        let object = Object {
            header: Header {
                flags: Flags::from_byte(Flags::LIVE).map_err(LiveError::Object)?,
                profile: Profile::P0.id,
                codec: CODEC_RAW,
                dictionary: 0,
                base: None,
                content_len: id.len,
                content_digest: id.digest,
                payload_len: content.len() as u64,
                prev_object: Some(prev_object),
                context_manifest: None,
            },
            payload: content.to_vec(),
        };
        let bytes = object.encode();
        let commitment = commit_object(&bytes, &Profile::P0).ok_or(LiveError::CommitFailed)?;
        let segment = LiveSegment {
            object,
            commitment,
            index,
            start_ms,
            end_ms,
        };
        self.segments.push(segment.clone());
        Ok(segment)
    }

    /// Join the stream at `now_ms`.
    ///
    /// The viewer starts at the newest complete segment; the source-first
    /// frame order makes that segment independently decodable. The join is
    /// refused when no segment exists yet or when the newest segment ended
    /// more than two segment durations ago, so a stale stream can never be
    /// served to a viewer as live.
    ///
    /// # Errors
    ///
    /// [`LiveError::EmptyStream`] before the first segment,
    /// [`LiveError::HeadStale`] when the head is older than
    /// [`MAX_JOIN_LATENCY_MS`].
    pub fn viewer_join(&self, now_ms: u64) -> Result<ViewerTicket, LiveError> {
        let head = self.segments.last().ok_or(LiveError::EmptyStream)?;
        let latency_ms = now_ms.saturating_sub(head.end_ms);
        if latency_ms > MAX_JOIN_LATENCY_MS {
            return Err(LiveError::HeadStale {
                age_ms: latency_ms,
                max_ms: MAX_JOIN_LATENCY_MS,
            });
        }
        Ok(ViewerTicket {
            stream_id: self.stream_id,
            start_index: head.index,
            head_commitment: head.commitment,
            latency_ms,
        })
    }

    /// Finish the broadcast and bind the chain's final object commitment to
    /// `nft`.
    ///
    /// The binding record is deterministic: two nodes that apply the same
    /// transactions compute the same [`StreamEnd::bind_tag`]. The chain
    /// writes the binding through `StorageTxV3::BindNft`; that wiring lands
    /// with the storage transactions package.
    ///
    /// # Errors
    ///
    /// [`LiveError::Closed`] before the activation height,
    /// [`LiveError::EmptyStream`] when the broadcast produced no segment.
    pub fn finish(self, nft: NftId) -> Result<StreamEnd, LiveError> {
        self.ctx.check_open()?;
        let head = self.segments.last().ok_or(LiveError::EmptyStream)?;
        let segment_count = self.segments.len() as u64;
        let bind_tag = hash_fields_bytes(&[
            LIVE_END_TAG,
            &self.stream_id,
            &nft,
            &head.commitment,
            &segment_count.to_le_bytes(),
        ]);
        Ok(StreamEnd {
            stream_id: self.stream_id,
            final_commitment: head.commitment,
            segments: segment_count,
            nft,
            bind_tag,
        })
    }
}

/// Where a viewer starts watching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewerTicket {
    /// The stream the viewer joined.
    pub stream_id: [u8; 32],
    /// The first segment the viewer needs: the newest complete one.
    pub start_index: u64,
    /// The head commitment to verify the chain against.
    pub head_commitment: ObjectCommitment,
    /// How far the head was behind the requested time.
    pub latency_ms: u64,
}

/// The end of a broadcast, bound to an NFT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEnd {
    /// The stream that ended.
    pub stream_id: [u8; 32],
    /// The final object commitment of the chain.
    pub final_commitment: ObjectCommitment,
    /// How many segments the broadcast produced.
    pub segments: u64,
    /// The NFT the final commitment is bound to.
    pub nft: NftId,
    /// The domain-separated digest of this binding record.
    pub bind_tag: [u8; 32],
}

/// Verify a chain of live segment objects against `stream_id`.
///
/// The first object must carry `stream_id` in `prev_object`; every later
/// object must carry the commitment of the previous object. Returns the
/// commitments in order. This is the light-client check: any tampering with
/// a segment object breaks its commitment or a link.
///
/// # Errors
///
/// [`LiveError::EmptyStream`] when no segment object is supplied,
/// [`LiveError::NotLive`] for an object without the live flag,
/// [`LiveError::ChainBroken`] for a mismatched link,
/// [`LiveError::CommitFailed`] when a commitment cannot be computed.
pub fn verify_chain(
    stream_id: [u8; 32],
    objects: &[Object],
) -> Result<Vec<ObjectCommitment>, LiveError> {
    if objects.is_empty() {
        return Err(LiveError::EmptyStream);
    }
    let mut commitments = Vec::with_capacity(objects.len());
    let mut prev = stream_id;
    for (index, object) in objects.iter().enumerate() {
        let index = index as u64;
        if !object.header.flags.has(Flags::LIVE) {
            return Err(LiveError::NotLive { index });
        }
        if object.header.prev_object != Some(prev) {
            return Err(LiveError::ChainBroken { index });
        }
        let bytes = object.encode();
        let commitment = commit_object(&bytes, &Profile::P0).ok_or(LiveError::CommitFailed)?;
        commitments.push(commitment);
        prev = commitment;
    }
    Ok(commitments)
}

/// One frame in the ratioless send order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveFrame {
    /// Source symbol `esi` of segment `segment`.
    Source {
        /// The segment the symbol belongs to.
        segment: u64,
        /// The encoding symbol id.
        esi: u32,
    },
    /// Repair symbol `esi` of segment `segment`.
    Repair {
        /// The segment the symbol belongs to.
        segment: u64,
        /// The encoding symbol id.
        esi: u32,
    },
}

/// The ratioless emission order: first every source frame of every segment,
/// in segment order, then continuous repair frames round-robin over the
/// segments with ever-increasing ESIs and no fixed source-to-repair ratio.
///
/// The order is total and deterministic, so the sender and every receiver
/// agree on it. A zero-entry plan yields nothing; a plan terminates after
/// every segment reaches its inclusive repair limit. [`RatiolessPlan::new`]
/// uses [`MAX_ESI`]; a real encoder can supply a lower per-segment limit.
#[derive(Debug, Clone)]
pub struct RatiolessPlan {
    sources: std::vec::IntoIter<LiveFrame>,
    /// The next repair ESI to emit, per segment (starts at the segment's
    /// source symbol count).
    next_repair_esi: Vec<u32>,
    /// Inclusive last repair ESI each segment's encoder can produce.
    repair_limit_esi: Vec<u32>,
    /// Round-robin cursor into `next_repair_esi`.
    cursor: usize,
}

impl RatiolessPlan {
    /// Build the plan for segments whose source-symbol counts are `ks`.
    #[must_use]
    pub fn new(ks: &[u32]) -> Self {
        Self::build(ks, vec![MAX_ESI; ks.len()])
    }

    /// Build a plan with each segment's inclusive last repair ESI.
    ///
    /// `SegmentEncoder::max_esi` accounts for RFC 6330 source-block padding;
    /// using that value prevents the plan from emitting frames the encoder
    /// must refuse. Length mismatches and limits above [`MAX_ESI`] are errors.
    ///
    /// # Errors
    /// [`LiveError::RepairLimitCountMismatch`] or
    /// [`LiveError::RepairLimitOutOfRange`].
    pub fn with_repair_limits(ks: &[u32], repair_limits: &[u32]) -> Result<Self, LiveError> {
        if ks.len() != repair_limits.len() {
            return Err(LiveError::RepairLimitCountMismatch {
                segments: ks.len(),
                limits: repair_limits.len(),
            });
        }
        for (index, limit) in repair_limits.iter().copied().enumerate() {
            if limit > MAX_ESI {
                return Err(LiveError::RepairLimitOutOfRange {
                    segment: index as u64,
                    limit,
                });
            }
        }
        Ok(Self::build(ks, repair_limits.to_vec()))
    }

    fn build(ks: &[u32], repair_limit_esi: Vec<u32>) -> Self {
        let mut sources = Vec::new();
        let mut next_repair_esi = Vec::with_capacity(ks.len());
        for (index, k) in ks.iter().enumerate() {
            let segment = index as u64;
            for esi in 0..*k {
                sources.push(LiveFrame::Source { segment, esi });
            }
            next_repair_esi.push(*k);
        }
        Self {
            sources: sources.into_iter(),
            next_repair_esi,
            repair_limit_esi,
            cursor: 0,
        }
    }
}

impl Iterator for RatiolessPlan {
    type Item = LiveFrame;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(frame) = self.sources.next() {
            return Some(frame);
        }
        if self.next_repair_esi.is_empty() {
            return None;
        }
        for _ in 0..self.next_repair_esi.len() {
            let index = self.cursor % self.next_repair_esi.len();
            self.cursor = self.cursor.wrapping_add(1);
            let esi = self.next_repair_esi[index];
            if esi <= self.repair_limit_esi[index] {
                self.next_repair_esi[index] = esi + 1;
                return Some(LiveFrame::Repair {
                    segment: index as u64,
                    esi,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::meter::Meter;

    const ORIGINATOR: [u8; 32] = [7; 32];
    const NONCE: [u8; 32] = [9; 32];
    const NFT: NftId = [5; 32];

    fn open_ctx() -> LiveContext {
        LiveContext {
            height: 10,
            activation: LiveActivation { height: Some(10) },
        }
    }

    fn open_stream() -> LiveStream {
        LiveStream::begin(ORIGINATOR, NONCE, open_ctx()).unwrap()
    }

    #[test]
    fn bud3_live_is_closed_on_testnet() {
        assert_eq!(ACTIVATION.height, None);
        assert_eq!(
            LiveStream::begin(ORIGINATOR, NONCE, LiveContext::closed()).map(|_| ()),
            Err(LiveError::Closed)
        );
        let mut stream = LiveStream {
            stream_id: [1; 32],
            ctx: LiveContext::closed(),
            segments: Vec::new(),
        };
        assert_eq!(
            stream.push_segment(0, b"frame").map(|_| ()),
            Err(LiveError::Closed)
        );
        let end = stream.finish(NFT).map(|end| end.segments);
        assert_eq!(end, Err(LiveError::Closed));
    }

    #[test]
    fn bud3_live_stream_segments_chain_in_order() {
        let mut stream = open_stream();
        let first = stream.push_segment(0, b"segment zero").unwrap();
        let second = stream.push_segment(2_000, b"segment one").unwrap();
        assert_eq!(first.index, 0);
        assert_eq!(second.index, 1);
        assert_eq!(first.start_ms, 0);
        assert_eq!(first.end_ms, 2_000);
        assert_eq!(second.start_ms, 2_000);
        assert_eq!(second.end_ms, 4_000);
        assert_eq!(first.object.header.prev_object, Some(stream.stream_id()));
        assert_eq!(second.object.header.prev_object, Some(first.commitment));
        assert!(first.object.header.flags.has(Flags::LIVE));
        assert!(second.object.header.flags.has(Flags::LIVE));

        let objects: Vec<Object> = stream.segments().iter().map(|s| s.object.clone()).collect();
        let commitments = verify_chain(stream.stream_id(), &objects).unwrap();
        assert_eq!(commitments, vec![first.commitment, second.commitment]);
    }

    #[test]
    fn bud3_live_stream_refuses_gap_and_overlap() {
        let mut stream = open_stream();
        stream.push_segment(0, b"segment zero").unwrap();
        assert_eq!(
            stream.push_segment(2_001, b"late"),
            Err(LiveError::NonContiguous {
                expected_start_ms: 2_000,
                got_start_ms: 2_001,
            })
        );
        assert_eq!(
            stream.push_segment(1_999, b"early"),
            Err(LiveError::NonContiguous {
                expected_start_ms: 2_000,
                got_start_ms: 1_999,
            })
        );
        stream.push_segment(2_000, b"segment one").unwrap();
        assert_eq!(stream.segments().len(), 2);
    }

    #[test]
    fn bud3_live_stream_refuses_empty_segment() {
        let mut stream = open_stream();
        assert_eq!(stream.push_segment(0, b""), Err(LiveError::EmptySegment));
    }

    #[test]
    fn bud3_live_stream_refuses_timestamp_overflow_and_empty_chain() {
        let mut stream = open_stream();
        assert_eq!(
            stream.push_segment(u64::MAX, b"overflow"),
            Err(LiveError::TimestampOverflow)
        );
        assert!(stream.segments().is_empty());
        assert_eq!(
            verify_chain(stream.stream_id(), &[]),
            Err(LiveError::EmptyStream)
        );
    }

    #[test]
    fn bud3_live_stream_viewer_joins_mid_stream_within_two_segments() {
        let mut stream = open_stream();
        for index in 0..6u64 {
            let start = index * LIVE_SEGMENT_MS;
            stream.push_segment(start, format!("segment {index}").as_bytes()).unwrap();
        }
        // The head segment ends at 12_000 ms. A viewer joining at 13_500 ms
        // is served within the two-segment budget.
        let ticket = stream.viewer_join(13_500).unwrap();
        assert_eq!(ticket.start_index, 5);
        assert_eq!(ticket.latency_ms, 1_500);
        assert!(ticket.latency_ms <= MAX_JOIN_LATENCY_MS);
        assert_eq!(ticket.head_commitment, stream.head_commitment().unwrap());
        // A viewer may also join inside the head window: zero extra latency.
        let ticket = stream.viewer_join(11_000).unwrap();
        assert_eq!(ticket.latency_ms, 0);
        // The join starts at the newest complete segment once the window
        // closed; it never starts after the head.
        assert_eq!(ticket.start_index, 5);
    }

    #[test]
    fn bud3_live_stream_viewer_join_refused_when_head_is_stale() {
        let mut stream = open_stream();
        stream.push_segment(0, b"segment zero").unwrap();
        assert_eq!(
            stream.viewer_join(2_000 + MAX_JOIN_LATENCY_MS + 1),
            Err(LiveError::HeadStale {
                age_ms: MAX_JOIN_LATENCY_MS + 1,
                max_ms: MAX_JOIN_LATENCY_MS,
            })
        );
        // A stream with no segment at all is not joinable.
        let stream = open_stream();
        assert_eq!(stream.viewer_join(0), Err(LiveError::EmptyStream));
    }

    #[test]
    fn bud3_live_stream_end_binds_final_commitment_to_nft() {
        let mut stream = open_stream();
        for index in 0..3u64 {
            let start = index * LIVE_SEGMENT_MS;
            stream.push_segment(start, format!("segment {index}").as_bytes()).unwrap();
        }
        let end = stream.finish(NFT).unwrap();
        let mut stream = open_stream();
        for index in 0..3u64 {
            let start = index * LIVE_SEGMENT_MS;
            stream.push_segment(start, format!("segment {index}").as_bytes()).unwrap();
        }
        let end_again = stream.finish(NFT).unwrap();
        // The binding record is deterministic.
        assert_eq!(end, end_again);
        assert_eq!(end.nft, NFT);
        assert_eq!(end.segments, 3);
        assert_eq!(
            end.bind_tag,
            hash_fields_bytes(&[
                LIVE_END_TAG,
                &end.stream_id,
                &NFT,
                &end.final_commitment,
                &3u64.to_le_bytes(),
            ])
        );
        // An empty broadcast cannot be bound.
        let empty = open_stream();
        assert_eq!(empty.finish(NFT), Err(LiveError::EmptyStream));
    }

    #[test]
    fn bud3_live_stream_detects_tampering() {
        let mut stream = open_stream();
        stream.push_segment(0, b"segment zero").unwrap();
        stream.push_segment(2_000, b"segment one").unwrap();
        let mut objects: Vec<Object> = stream.segments().iter().map(|s| s.object.clone()).collect();
        // Tamper with the first segment's payload.
        objects[0].payload.push(0x00);
        // The chain breaks at index 0: its commitment no longer matches.
        assert_eq!(
            verify_chain(stream.stream_id(), &objects),
            Err(LiveError::ChainBroken { index: 1 })
        );
        // Rewrite the second link to the tampered first commitment: the
        // forged chain verifies structurally, so the viewer must also check
        // the NFT binding against the chain head out of band.
        let first = objects[0].clone();
        let first_bytes = first.encode();
        let first_commitment = commit_object(&first_bytes, &Profile::P0).unwrap();
        objects[1].header.prev_object = Some(first_commitment);
        assert!(verify_chain(stream.stream_id(), &objects).is_ok());
        // An object without the live flag is refused.
        let mut not_live = stream.segments()[0].object.clone();
        not_live.header.flags = Flags::from_byte(0).unwrap();
        not_live.header.prev_object = Some(stream.stream_id());
        assert_eq!(
            verify_chain(stream.stream_id(), &[not_live]),
            Err(LiveError::NotLive { index: 0 })
        );
    }

    #[test]
    fn ratioless_plan_emits_sources_first_then_continuous_repairs() {
        let plan = RatiolessPlan::new(&[2, 1]);
        let frames: Vec<LiveFrame> = plan.take(12).collect();
        assert_eq!(
            frames,
            vec![
                LiveFrame::Source { segment: 0, esi: 0 },
                LiveFrame::Source { segment: 0, esi: 1 },
                LiveFrame::Source { segment: 1, esi: 0 },
                LiveFrame::Repair { segment: 0, esi: 2 },
                LiveFrame::Repair { segment: 1, esi: 1 },
                LiveFrame::Repair { segment: 0, esi: 3 },
                LiveFrame::Repair { segment: 1, esi: 2 },
                LiveFrame::Repair { segment: 0, esi: 4 },
                LiveFrame::Repair { segment: 1, esi: 3 },
                LiveFrame::Repair { segment: 0, esi: 5 },
                LiveFrame::Repair { segment: 1, esi: 4 },
                LiveFrame::Repair { segment: 0, esi: 6 },
            ]
        );
        // An empty plan yields nothing.
        assert_eq!(RatiolessPlan::new(&[]).next(), None);
        // Repair ESIs never repeat within one segment.
        let plan = RatiolessPlan::new(&[1]);
        let repairs: Vec<u32> = plan
            .filter_map(|frame| match frame {
                LiveFrame::Repair { esi, .. } => Some(esi),
                LiveFrame::Source { .. } => None,
            })
            .take(64)
            .collect();
        let mut sorted = repairs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(repairs.len(), sorted.len());
        assert_eq!(sorted.first(), Some(&1));
    }

    #[test]
    fn ratioless_plan_honors_per_segment_repair_limits() {
        let plan = RatiolessPlan::with_repair_limits(&[1], &[1]).unwrap();
        let frames: Vec<LiveFrame> = plan.collect();
        assert_eq!(
            frames,
            vec![
                LiveFrame::Source { segment: 0, esi: 0 },
                LiveFrame::Repair { segment: 0, esi: 1 },
            ]
        );
        assert_eq!(
            RatiolessPlan::with_repair_limits(&[1], &[]).unwrap_err(),
            LiveError::RepairLimitCountMismatch {
                segments: 1,
                limits: 0,
            }
        );
        assert_eq!(
            RatiolessPlan::with_repair_limits(&[1], &[MAX_ESI + 1]).unwrap_err(),
            LiveError::RepairLimitOutOfRange {
                segment: 0,
                limit: MAX_ESI + 1,
            }
        );
    }

    #[test]
    fn live_segment_objects_parse_as_bof1() {
        let mut stream = open_stream();
        stream.push_segment(0, b"segment zero").unwrap();
        let bytes = stream.segments()[0].object.encode();
        let parsed = Object::decode(&bytes, &mut Meter::for_object(1 << 20)).unwrap();
        assert!(parsed.header.flags.has(Flags::LIVE));
        assert_eq!(parsed.header.prev_object, Some(stream.stream_id()));
    }
}
