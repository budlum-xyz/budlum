//! The live stream (Section 6.16, WP-55).
//!
//! A live source is cut into time segments of two seconds. Each segment is its
//! own object, and the object carries flag bit1: it names the commitment of the
//! previous segment in `prev_object`, so a viewer that joined late can tell
//! whether the segment it received follows the one it already has.
//!
//! # The three rules that make the chain checkable
//!
//! 1. **The first segment names no predecessor.** It is the stream's head, and
//!    a chain that claims a predecessor for it is claiming a stream it cannot
//!    verify.
//! 2. **A segment names its predecessor's commitment, not its object bytes.**
//!    The commitment is the 32-byte fold of the object, so a viewer checks the
//!    link from the slice it received alone.
//! 3. **The index is contiguous.** A gap is a dropped segment, which the viewer
//!    asks for again; a repeated index is a fork, which it refuses.
//!
//! # Ratio-free transmission
//!
//! The stream sends source frames first and then keeps sending repair frames.
//! No ratio is declared or negotiated: a viewer collects until the segment
//! decodes (`k + 2` symbols in the ordinary case, Section 6.23 T6), and the
//! repair frames that arrive afterwards are spare. This is why the stream
//! carries no `k` in its segment record: `k` follows from the segment length and
//! the profile, exactly as it does for a stored object.
//!
//! # The end of the stream
//!
//! When the stream ends, the last segment's commitment is bound to an NFT
//! ([`LiveStream::close`]). The binding is a value the caller writes into
//! `StorageTx::BindNft`; this module computes it and refuses to close a stream
//! that accepted no segment.
//!
//! # Testnet
//!
//! The testnet chain refuses an object that carries bit1 (Section 6.16 item 6),
//! so [`LIVE_ACTIVATION`] holds no height and [`LiveStream::admit`] refuses
//! every segment. `Object::decode` does not know the chain, so it parses bit1;
//! the refusal lives here, in the one place that knows which chain a segment is
//! being admitted to, and every reader reaches it through [`live_is_open_at`].
//!
//! # Wire changes
//!
//! None. A live segment is an ordinary BOF-1 object that carries bit1 and fills
//! `prev_object`; the binding at the end is a 32-byte value a caller writes, not
//! a new transaction type. The one new hash domain,
//! `BDLM_BUD3_LIVE_BINDING_V1`, is listed in `src/crypto/domain_tags.rs`.
//!
//! Not yet wired: the upload session (`upload.rs`) feeds a segment, the
//! `StorageTx` v3 door carries the closed stream's binding, and RPC serves the
//! segment index. Until those land, this module is reached by
//! `src/tests/bud3_live.rs` and by its own unit tests.

use super::bof1::{Flags, Header};
use super::content_id::ContentId;
use super::limits::{Profile, ProfileId};
use super::meter::Meter;
use super::object::{header_bytes, ObjectError, SegmentCommit};
use super::segment::ObjectCommitment;
use crate::core::hash::hash_fields_bytes;
use std::collections::BTreeMap;

/// WIRING: the segment clock the upload session reads when it cuts a stream.
///
/// A live segment's nominal duration, in seconds.
pub const SEGMENT_SECS: u64 = 2;

/// WIRING: RPC reports this as the viewer lag bound.
///
/// The largest allowed delay between a live source and a viewer, measured in
/// segment durations (Section 6.16 item 4).
pub const MAX_LAG_SEGMENTS: u64 = 2;

/// WIRING: the chain config carries one of these once the height is set, and
/// genesis writes it; see [`LIVE_ACTIVATION`] for this chain's value.
///
/// When bit1 objects are accepted on a chain. `height: None`: closed.
///
/// The shape is the one `ObjectLayerActivation` uses in `src/object_layer`, so
/// a chain states its activation once and every reader reaches the same
/// answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveActivation {
    /// WIRING: read by the chain config, written by genesis.
    ///
    /// The height the live path opens at. `None`: never on this chain.
    pub height: Option<u64>,
}

impl LiveActivation {
    /// WIRING: reached through [`live_is_open_at`].
    ///
    /// Whether a live segment is admissible at `height`.
    #[must_use]
    pub fn is_open_at(&self, height: u64) -> bool {
        self.height.is_some_and(|open| height >= open)
    }
}

/// This chain's activation. `None`: the live path is closed.
///
/// TESTNET-DEFAULT: closed. The activation height arrives with a governance
/// value after the live path has run on the rehearsal network (WP-46, M7).
pub const LIVE_ACTIVATION: LiveActivation = LiveActivation { height: None };

/// Whether a live segment is admissible on this chain at `height`.
///
/// This is the admission the card requires of the testnet chain: one function,
/// one constant, and every door that admits a segment asks it.
///
/// WIRING: the record path in [`super::registry`] calls this before it stores an
/// object that carries bit1; until that door lands, the stream's own `admit`
/// asks it through the stream's activation and the acceptance test asks it
/// directly.
#[must_use]
pub fn live_is_open_at(height: u64) -> bool {
    LIVE_ACTIVATION.is_open_at(height)
}

/// WIRING: the upload session maps these onto its own refusal codes, and RPC
/// reports `OutOfOrder` as "ask again".
///
/// Why the stream refused an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveError {
    /// The live path is closed at this height.
    ClosedAt(u64),
    /// The segment index is not the next one this stream expects.
    OutOfOrder {
        /// The index the stream expects.
        expected: u64,
        /// The index the segment carries.
        got: u64,
    },
    /// The segment names another predecessor than the stream's head.
    BrokenLink {
        /// The commitment the stream holds for the previous segment.
        expected: ObjectCommitment,
        /// The commitment the segment names.
        got: ObjectCommitment,
    },
    /// A segment after the head names no predecessor at all.
    MissingLink,
    /// The first segment of a stream names a predecessor.
    HeadWithPredecessor,
    /// The header does not carry bit1.
    NotALiveObject,
    /// The payload handed over is not the length the header declares.
    PayloadMismatch {
        /// The length the header declares.
        claimed: u64,
        /// The length of the payload given.
        got: u64,
    },
    /// The profile does not segment, or a length does not fit.
    Object(ObjectError),
    /// The stream has not ended, so its chain has no binding to offer.
    NotClosed,
}

impl From<ObjectError> for LiveError {
    fn from(e: ObjectError) -> Self {
        Self::Object(e)
    }
}

/// WIRING: the segment index RPC serves to a late joiner.
///
/// One segment, as the stream records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentRef {
    /// Position in the stream, from zero.
    pub index: u64,
    /// The segment's object commitment.
    pub commitment: ObjectCommitment,
    /// The predecessor it names, `None` for the head.
    pub prev: Option<ObjectCommitment>,
    /// The stream time the segment starts at, in milliseconds.
    pub started_at_ms: u64,
    /// Content length of the segment's object.
    pub object_len: u64,
}

/// WIRING: the upload session holds one of these per live source.
///
/// The live stream's local state: the chain of segments and its head.
///
/// Nothing here is chain state. What reaches the chain is each segment's object
/// (flag bit1 plus `prev_object`) and, at the end, the NFT binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveStream {
    activation: LiveActivation,
    profile: ProfileId,
    segments: Vec<SegmentRef>,
    started_at_ms: u64,
    binding: Option<ObjectCommitment>,
}

impl LiveStream {
    /// A stream that opens at `started_at_ms` under `profile`.
    ///
    /// This is the production entry point: it takes this chain's
    /// [`LIVE_ACTIVATION`], so a caller cannot open a stream on a chain that has
    /// not activated the feature.
    ///
    /// # Errors
    ///
    /// [`LiveError::Object`] with [`ObjectError::BadProfile`] when the profile
    /// does not segment, because a stream of unsegmentable objects would carry
    /// no symbols to send.
    pub fn open(profile: Profile, started_at_ms: u64) -> Result<Self, LiveError> {
        Self::with_activation(profile, started_at_ms, LIVE_ACTIVATION)
    }

    /// A stream under an explicit activation.
    ///
    /// The production path uses [`Self::open`], which takes this chain's
    /// [`LIVE_ACTIVATION`]. The explicit form exists for two callers: a chain
    /// that carries its own activation value, and a test that must exercise the
    /// chain mechanics while the shipped activation stays closed.
    ///
    /// WIRING: the rehearsal network's genesis carries an open activation.
    ///
    /// # Errors
    ///
    /// [`LiveError::Object`] with [`ObjectError::BadProfile`] when the profile
    /// does not segment.
    pub fn with_activation(
        profile: Profile,
        started_at_ms: u64,
        activation: LiveActivation,
    ) -> Result<Self, LiveError> {
        if !profile.is_valid() {
            return Err(LiveError::Object(ObjectError::BadProfile));
        }
        Ok(Self {
            activation,
            profile: profile.id,
            segments: Vec::new(),
            started_at_ms,
            binding: None,
        })
    }

    /// The segments this stream has accepted, in order.
    #[must_use]
    pub fn segments(&self) -> &[SegmentRef] {
        &self.segments
    }

    /// The commitment of the last accepted segment, if any.
    #[must_use]
    pub fn head(&self) -> Option<ObjectCommitment> {
        self.segments.last().map(|segment| segment.commitment)
    }

    /// The activation this stream runs under.
    #[must_use]
    pub const fn activation(&self) -> LiveActivation {
        self.activation
    }

    /// The profile the stream is coded with.
    #[must_use]
    pub const fn profile(&self) -> ProfileId {
        self.profile
    }

    /// The header of the next segment: bit1 set, and `prev_object` naming the
    /// current head.
    ///
    /// The header a live segment carries is built here rather than by the
    /// caller, so a segment cannot be emitted without its link.
    ///
    /// # Errors
    ///
    /// [`LiveError::ClosedAt`] when the chain refuses bit1 at `height`, and
    /// [`LiveError::Object`] when the profile is not registered.
    pub fn next_header(
        &self,
        content: &ContentId,
        payload_len: u64,
        codec: u16,
        height: u64,
    ) -> Result<Header, LiveError> {
        self.segment_header(content, payload_len, codec, height, self.head())
    }

    /// The header of one segment given the predecessor it must name.
    ///
    /// This is the function a viewer uses too: a received segment is checked by
    /// rebuilding this header and comparing it with the one that arrived, so a
    /// segment whose link was edited is refused rather than accepted with a
    /// different predecessor.
    ///
    /// # Errors
    ///
    /// [`LiveError::ClosedAt`] when bit1 is closed at `height`, and
    /// [`LiveError::Object`] when the profile is not registered.
    pub fn segment_header(
        &self,
        content: &ContentId,
        payload_len: u64,
        codec: u16,
        height: u64,
        prev: Option<ObjectCommitment>,
    ) -> Result<Header, LiveError> {
        if !self.activation.is_open_at(height) {
            return Err(LiveError::ClosedAt(height));
        }
        let profile = Profile::by_id(self.profile)
            .ok_or(LiveError::Object(ObjectError::BadProfile))?;
        Ok(Header {
            flags: Flags::from_byte(Flags::LIVE).map_err(|_| LiveError::NotALiveObject)?,
            profile: profile.id,
            codec,
            dictionary: 0,
            base: None,
            content_len: content.len,
            content_digest: content.digest,
            payload_len,
            prev_object: Some(prev.unwrap_or([0u8; 32])),
            context_manifest: None,
        })
    }

    /// Accept a segment: the header must carry bit1 and name the current head.
    ///
    /// The commitment is computed from the object bytes the caller has already
    /// produced, so the link a viewer checks is the same value the stream
    /// records.
    ///
    /// # Errors
    ///
    /// [`LiveError::ClosedAt`] when bit1 is closed at `height`,
    /// [`LiveError::NotALiveObject`] when the header does not carry bit1,
    /// [`LiveError::PayloadMismatch`] when the payload is not the declared length,
    /// [`LiveError::HeadWithPredecessor`] for a nonzero predecessor on the head,
    /// [`LiveError::MissingLink`] for a zero predecessor after the head,
    /// [`LiveError::BrokenLink`] when the predecessor is not the head, and
    /// [`LiveError::OutOfOrder`] when the index is not the next one.
    pub fn admit(
        &mut self,
        index: u64,
        header: &Header,
        payload: &[u8],
        height: u64,
    ) -> Result<SegmentRef, LiveError> {
        if !self.activation.is_open_at(height) {
            return Err(LiveError::ClosedAt(height));
        }
        if !header.is_live() {
            return Err(LiveError::NotALiveObject);
        }
        let given = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        if given != header.payload_len {
            return Err(LiveError::PayloadMismatch {
                claimed: header.payload_len,
                got: given,
            });
        }
        let expected_index = u64::try_from(self.segments.len()).unwrap_or(u64::MAX);
        if index != expected_index {
            return Err(LiveError::OutOfOrder {
                expected: expected_index,
                got: index,
            });
        }
        let claimed = header.prev_object.unwrap_or([0u8; 32]);
        let prev = match (self.head(), claimed) {
            (None, zero) if zero == [0u8; 32] => None,
            (None, _) => return Err(LiveError::HeadWithPredecessor),
            (Some(_), zero) if zero == [0u8; 32] => return Err(LiveError::MissingLink),
            (Some(head), claimed) if claimed == head => Some(head),
            (Some(head), claimed) => {
                return Err(LiveError::BrokenLink {
                    expected: head,
                    got: claimed,
                })
            }
        };
        let profile = Profile::by_id(self.profile)
            .ok_or(LiveError::Object(ObjectError::BadProfile))?;
        let object_len = u64::try_from(
            header
                .encoded_len()
                .saturating_add(payload.len()),
        )
        .unwrap_or(u64::MAX);
        let mut commit = SegmentCommit::new(object_len, &profile)?;
        let mut meter = Meter::new(u64::MAX, u64::MAX);
        commit.push(&header_bytes(header, header.payload_len), &mut meter)?;
        commit.push(payload, &mut meter)?;
        let commitment = commit.finish()?;
        let segment = SegmentRef {
            index,
            commitment,
            prev,
            started_at_ms: self
                .started_at_ms
                .saturating_add(index.saturating_mul(SEGMENT_SECS * 1000)),
            object_len,
        };
        self.segments.push(segment);
        Ok(segment)
    }

    /// WIRING: RPC reads the budget from here so one number serves both doors.
    ///
    /// The delay budget a viewer at `segment_index` may see, in segments.
    ///
    /// The target is at most two segment durations (Section 6.16 item 4); the
    /// function returns how many segments behind the source a viewer may be
    /// before the stream is out of its own contract.
    #[must_use]
    pub const fn lag_budget_segments() -> u64 {
        MAX_LAG_SEGMENTS
    }

    /// End the stream and bind its chain to an NFT.
    ///
    /// The binding folds the stream's head and its segment count, so two
    /// streams that end on the same commitment but with a different number of
    /// segments are two different bindings. The caller writes the value into
    /// the NFT; this module never touches the registry.
    ///
    /// # Errors
    ///
    /// [`LiveError::NotClosed`] when the stream has no segment to bind.
    pub fn close(&mut self) -> Result<[u8; 32], LiveError> {
        let head = self.head().ok_or(LiveError::NotClosed)?;
        let count = u64::try_from(self.segments.len()).unwrap_or(u64::MAX);
        let binding = hash_fields_bytes(&[
            b"BDLM_BUD3_LIVE_BINDING_V1",
            &head,
            &count.to_le_bytes(),
        ]);
        self.binding = Some(binding);
        Ok(binding)
    }

    /// The binding this stream closed with, if it closed.
    #[must_use]
    pub const fn binding(&self) -> Option<ObjectCommitment> {
        self.binding
    }

    /// The segment index a viewer holds, for the query a late joiner makes:
    /// every accepted segment's start time and commitment.
    ///
    /// WIRING: RPC serves this map once the live query door lands; the
    /// acceptance test walks it as a late joiner would.
    #[must_use]
    pub fn index_map(&self) -> BTreeMap<u64, SegmentRef> {
        self.segments
            .iter()
            .map(|segment| (segment.index, *segment))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content(byte: u8) -> ContentId {
        ContentId::public(&[byte; 16])
    }

    /// The closed path is what the testnet answers, so the unit tests drive the
    /// stream through the header builder directly with a hypothetical open
    /// height, and pin the closed answer separately.
    #[test]
    fn the_live_path_is_closed_on_the_testnet_chain() {
        let stream = LiveStream::open(Profile::P0, 0).unwrap();
        assert_eq!(LIVE_ACTIVATION.height, None);
        assert!(!live_is_open_at(0));
        assert!(!live_is_open_at(u64::MAX - 1));
        assert_eq!(
            stream.next_header(&content(1), 16, 0, 5),
            Err(LiveError::ClosedAt(5))
        );
        assert_eq!(LiveStream::lag_budget_segments(), 2);
        assert_eq!(SEGMENT_SECS, 2);
    }

    #[test]
    fn an_unsegmentable_profile_cannot_open_a_stream() {
        let broken = Profile {
            id: 0,
            qr_version: 40,
            symbol_size: 0,
            fps: 10,
            k_max: 0,
        };
        assert_eq!(
            LiveStream::open(broken, 0),
            Err(LiveError::Object(ObjectError::BadProfile))
        );
    }
}
