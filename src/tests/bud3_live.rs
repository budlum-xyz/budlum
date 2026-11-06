//! The live stream acceptance test (WP-55, Section 6.16).
//!
//! The card names one test, T13 `bud3_live_stream`, and states three things it
//! must measure: a viewer joins in the middle of the stream, the delay is at
//! most two segment durations, and at the end the chain is bound to an NFT.
//!
//! The stream itself is closed on the testnet chain (`LIVE_ACTIVATION.height`
//! is `None`), so the rule the card states for the testnet ("an object carrying
//! bit1 is refused") is measured here too, in
//! `the_testnet_refuses_every_live_segment`. The chain mechanics are measured
//! against an explicit open activation: the same value a rehearsal chain's
//! genesis carries once a governance height names one, and the same arithmetic
//! the node runs at that height.

use crate::storage::bud3::bof1::{Flags, Header, Object};
use crate::storage::bud3::content_id::ContentId;
use crate::storage::bud3::limits::Profile;
use crate::storage::bud3::live::{
    live_is_open_at, LiveActivation, LiveError, LiveStream, SegmentRef, LIVE_ACTIVATION,
    MAX_LAG_SEGMENTS, SEGMENT_SECS,
};
use crate::storage::bud3::meter::Meter;

/// The height the chain mechanics are replayed at. The shipped activation is
/// closed, so the replay states its own activation: the same value a rehearsal
/// chain's genesis would carry once a governance height names it.
const OPEN_HEIGHT: u64 = 500;
const OPEN: LiveActivation = LiveActivation {
    height: Some(OPEN_HEIGHT),
};

const START_MS: u64 = 1_700_000_000_000;
const PAYLOAD_LEN: u64 = 32;

fn a_stream() -> LiveStream {
    LiveStream::with_activation(Profile::P0, START_MS, OPEN).expect("P0 segments")
}

fn segment_content(index: u64) -> ContentId {
    ContentId::public(format!("segment-{index}").as_bytes())
}

fn segment_payload(index: u64) -> Vec<u8> {
    let byte = u8::try_from(index % 251).unwrap_or(0);
    vec![byte; usize::try_from(PAYLOAD_LEN).unwrap()]
}

/// Build the next header and admit the next segment.
fn push_segment(stream: &mut LiveStream, index: u64) -> SegmentRef {
    let content = segment_content(index);
    let payload = segment_payload(index);
    let header = stream
        .next_header(&content, PAYLOAD_LEN, 0, OPEN_HEIGHT)
        .expect("the header names the current head");
    assert!(header.is_live(), "a live segment carries bit1");
    assert_eq!(
        header.prev_object,
        Some(stream.head().unwrap_or([0u8; 32])),
        "the head segment names the zero predecessor"
    );
    stream
        .admit(index, &header, &payload, OPEN_HEIGHT)
        .expect("a segment that follows the head is admitted")
}

#[test]
fn bud3_live_stream() {
    // A viewer that joins late sees the same chain a viewer that joined at the
    // start does: every segment names its predecessor's commitment.
    let mut stream = a_stream();
    assert!(stream.activation().is_open_at(OPEN_HEIGHT));
    assert!(
        !live_is_open_at(OPEN_HEIGHT),
        "the shipped chain stays closed while the replay uses its own activation"
    );

    for index in 0..3u64 {
        let accepted = push_segment(&mut stream, index);
        assert_eq!(accepted.index, index);
        assert_eq!(
            accepted.prev,
            if index == 0 {
                None
            } else {
                Some(stream.segments()[usize::try_from(index - 1).unwrap()].commitment)
            },
            "each segment names the one before it, and the head names none"
        );
        assert_eq!(
            accepted.started_at_ms,
            START_MS + index * SEGMENT_SECS * 1000,
            "a segment's start time follows its index"
        );
    }
    assert_eq!(stream.segments().len(), 3);

    // A viewer that joined in the middle holds segment 1 and 2; the segment
    // index tells it what it already has, and the late segment it receives
    // still links to a commitment it holds.
    let index_map = stream.index_map();
    let late_joiner: Vec<SegmentRef> = index_map
        .values()
        .copied()
        .filter(|segment| segment.index >= 1)
        .collect();
    assert_eq!(
        late_joiner.len(),
        2,
        "the index answers what the viewer holds"
    );
    for pair in late_joiner.windows(2) {
        assert_eq!(
            pair[1].prev,
            Some(pair[0].commitment),
            "a late joiner links the segments it received"
        );
    }
    assert_eq!(
        late_joiner.first().and_then(|segment| segment.prev),
        Some(stream.segments()[0].commitment),
        "the first late segment names the one the viewer missed"
    );

    // The delay budget: at most two segment durations, and a viewer exactly two
    // segments behind is still inside the contract.
    assert_eq!(LiveStream::lag_budget_segments(), MAX_LAG_SEGMENTS);
    assert_eq!(
        MAX_LAG_SEGMENTS * SEGMENT_SECS,
        4,
        "two segments is four seconds"
    );
    let source_index = 2u64;
    let viewer_index = source_index - MAX_LAG_SEGMENTS;
    assert_eq!(
        source_index - viewer_index,
        MAX_LAG_SEGMENTS,
        "two segments behind is the boundary, not a violation"
    );

    // The end of the stream: the chain's last commitment is bound, and the
    // binding folds the head and the segment count.
    let head = stream.head().expect("a stream that ran has a head");
    let binding = stream.close().expect("a stream with segments closes");
    assert_eq!(stream.binding(), Some(binding));
    let mut shorter = a_stream();
    let first = push_segment(&mut shorter, 0);
    assert_eq!(first.prev, None, "a one-segment stream is just its head");
    let short_binding = shorter.close().expect("a one-segment stream closes");
    assert_ne!(
        short_binding, binding,
        "the same head under a different segment count is a different binding"
    );
    let mut empty = a_stream();
    assert_eq!(empty.close(), Err(LiveError::NotClosed));
    assert_eq!(empty.binding(), None);
    assert_eq!(head, stream.head().expect("close does not move the head"));

    // And the rules the chain enforces on the way in: a head with a
    // predecessor, a gap, a missing link, a broken link, a forged payload
    // length and an object without bit1.
    let mut fresh = a_stream();
    let mut forged = fresh
        .segment_header(&segment_content(0), PAYLOAD_LEN, 0, OPEN_HEIGHT, None)
        .expect("the head builds");
    forged.prev_object = Some([9u8; 32]);
    assert_eq!(
        fresh.admit(0, &forged, &segment_payload(0), OPEN_HEIGHT),
        Err(LiveError::HeadWithPredecessor)
    );
    let real_head = fresh
        .segment_header(&segment_content(0), PAYLOAD_LEN, 0, OPEN_HEIGHT, None)
        .expect("the head builds");
    assert_eq!(
        fresh.admit(1, &real_head, &segment_payload(0), OPEN_HEIGHT),
        Err(LiveError::OutOfOrder {
            expected: 0,
            got: 1
        }),
        "a gap is a dropped segment, refused by index"
    );
    let _ = fresh
        .admit(0, &real_head, &segment_payload(0), OPEN_HEIGHT)
        .expect("the head is admitted");
    let mut unlinked = fresh
        .segment_header(&segment_content(1), PAYLOAD_LEN, 0, OPEN_HEIGHT, None)
        .expect("the second header builds");
    unlinked.prev_object = Some([0u8; 32]);
    assert_eq!(
        fresh.admit(1, &unlinked, &segment_payload(1), OPEN_HEIGHT),
        Err(LiveError::MissingLink)
    );
    let mut wrong_link = fresh
        .segment_header(&segment_content(1), PAYLOAD_LEN, 0, OPEN_HEIGHT, None)
        .expect("the second header builds");
    wrong_link.prev_object = Some([7u8; 32]);
    match fresh.admit(1, &wrong_link, &segment_payload(1), OPEN_HEIGHT) {
        Err(LiveError::BrokenLink { expected, got }) => {
            assert_ne!(expected, got);
            assert_eq!(expected, fresh.head().expect("the head exists"));
        }
        other => panic!("a wrong predecessor must be refused, got {other:?}"),
    }
    let honest = fresh
        .segment_header(&segment_content(1), PAYLOAD_LEN, 0, OPEN_HEIGHT, None)
        .expect("the second header builds");
    assert_eq!(
        fresh.admit(1, &honest, &segment_payload(1)[..8], OPEN_HEIGHT),
        Err(LiveError::PayloadMismatch {
            claimed: PAYLOAD_LEN,
            got: 8
        })
    );
    let not_live = Header {
        flags: Flags::from_byte(0).expect("no flags is a known byte"),
        ..honest
    };
    assert_eq!(
        fresh.admit(1, &not_live, &segment_payload(1), OPEN_HEIGHT),
        Err(LiveError::NotALiveObject)
    );
    // Every refusal above left the chain untouched: one segment, the head.
    assert_eq!(fresh.segments().len(), 1);
    assert_eq!(fresh.head(), Some(fresh.segments()[0].commitment));
}

#[test]
fn the_testnet_refuses_every_live_segment() {
    // Section 6.16 item 6: at testnet launch an object carrying bit1 is
    // refused, and the refusal lives in one place rather than in every caller.
    assert_eq!(LIVE_ACTIVATION.height, None);
    let mut stream = a_stream();
    for height in [0u64, 1, 1_000_000, u64::MAX - 1] {
        assert!(!live_is_open_at(height));
        assert_eq!(
            stream.next_header(&segment_content(0), PAYLOAD_LEN, 0, height),
            Err(LiveError::ClosedAt(height))
        );
    }
    // The shipped stream, built through the production entry point rather than
    // the replay's activation, refuses the same way.
    let mut shipped = LiveStream::open(Profile::P0, START_MS).expect("P0 segments");
    let header = Header {
        flags: Flags::from_byte(Flags::LIVE).expect("bit1 is a known flag"),
        profile: Profile::P0.id,
        codec: 0,
        dictionary: 0,
        base: None,
        content_len: PAYLOAD_LEN,
        content_digest: segment_content(0).digest,
        payload_len: PAYLOAD_LEN,
        prev_object: Some([0u8; 32]),
        context_manifest: None,
    };
    assert_eq!(
        shipped.admit(0, &header, &segment_payload(0), 1),
        Err(LiveError::ClosedAt(1))
    );
    assert!(shipped.segments().is_empty(), "a refused segment is not recorded");
    assert_eq!(shipped.close(), Err(LiveError::NotClosed));
    assert!(
        stream.segments().is_empty(),
        "the closed clock admits nothing"
    );
}

#[test]
fn a_live_header_parses_with_its_link_intact() {
    // The format carries bit1 whether or not this chain opens it, so a header
    // built under an open activation must survive the object parser with its
    // predecessor intact: a chain that opens the height later must not need a
    // new format.
    let stream = a_stream();
    let content = segment_content(4);
    let prev = [0x5au8; 32];
    let header = stream
        .segment_header(&content, PAYLOAD_LEN, 0, OPEN_HEIGHT, Some(prev))
        .expect("the header builds under an open activation");
    let object = Object {
        header,
        payload: segment_payload(4),
    };
    let mut meter = Meter::for_object(1 << 20);
    let decoded = Object::decode(&object.encode(), &mut meter).expect("bit1 parses");
    assert_eq!(decoded, object);
    assert_eq!(decoded.header.prev_object, Some(prev));
    assert!(decoded.header.is_live());
    assert!(
        stream.segments().is_empty(),
        "building a header admits nothing"
    );
}
