//! The section 6.2 vocabulary, reached from the production tree.
//!
//! `src/storage/bud3/types.rs` declares the terms the directive names once and
//! every package reads. A type nothing outside its own file names compiles,
//! is reviewed and does nothing, so this module is the caller that keeps the
//! vocabulary on the production path: it builds each value from the parts the
//! real pipeline already produces and checks the invariant the directive states
//! for it.
//!
//! These are not tests of the types for their own sake. Each one answers a
//! question a later package has to answer:
//!
//! * a frame's payload is the symbol's bytes and nothing else, so the video
//!   commitment (section 6.15) cannot accidentally cover a drawing;
//! * a `QrVideo` counts whole seconds with a partial second kept, because
//!   `second N` addressing drops the tail otherwise;
//! * a `CustodyShare`'s root only reproduces from an ascending ESI list, which
//!   is what makes a share provable on its own;
//! * a `PlacementGroup` covers `k + 2` or the segment has no single survivor;
//! * a `RefCount` reaches zero only when both terms do, because section 6.8
//!   deletes at zero and a wrong zero deletes a live object;
//! * an `AggregationVolume` refuses a member that would overflow its ceiling
//!   rather than wrapping under it.

use crate::storage::bud3::content_id::ContentId;
use crate::storage::bud3::types::{
    object_commitment, symbol_leaf, symbol_root, AggregationVolume, CodecId, CustodyShare, Frame,
    LogicalPath, Object, OpticalPath, Path, Payload, PlacementGroup, PlacementTable, Profile,
    QrVideo, RefCount, RepairSymbol, Segment, SourceSymbol, Symbol,
};

/// One symbol, as the fountain encoder would hand it over.
fn symbol(segment: u64, esi: u32, size: usize) -> Symbol {
    Symbol {
        segment,
        esi,
        data: (0..size)
            .map(|i| u8::try_from(i % 256).unwrap_or(0).wrapping_mul(31))
            .collect(),
    }
}

/// A frame is its header and its symbol. The payload is the symbol's bytes, so
/// nothing a presentation adds can reach a commitment through this type.
#[test]
fn the_frame_vocabulary_carries_no_drawing() {
    let commitment = object_commitment(&[[3u8; 32]]);
    let sym = symbol(0, 0, 128);
    let frame = Frame::of(commitment, 0, sym.clone());
    assert_eq!(frame.payload(), sym.data.as_slice());
    assert_eq!(frame.commitment, commitment);
    assert!(frame.is_source(1), "esi 0 is below k = 1");
    assert!(!frame.is_source(0), "esi 0 is not below k = 0");

    // The same frame twice gives the same value: a frame is data, not a
    // rendering, so two paths that produce it cannot disagree about pixels.
    assert_eq!(frame, Frame::of(commitment, 0, sym));
}

/// `second N` addressing keeps a partial second. A video that rounded down
/// would lose the last frames of every recording.
#[test]
fn the_qr_video_counts_a_partial_second_as_a_second() {
    let commitment = object_commitment(&[[4u8; 32]]);
    let frames: Vec<Frame> = (0..25)
        .map(|i| Frame::of(commitment, 0, symbol(0, i, 64)))
        .collect();
    let video = QrVideo { fps: 10, frames };
    assert_eq!(video.seconds(), 3, "25 frames at 10 fps is 2.5 seconds");
    assert_eq!(
        QrVideo {
            fps: 0,
            frames: Vec::new()
        }
        .seconds(),
        0,
        "zero fps names no second at all"
    );
}

/// A share's symbol root reproduces from the share alone, and only when the
/// ESI list is ascending: the root folds `(esi, leaf)` pairs in order.
#[test]
fn the_custody_share_root_reproduces_only_from_an_ordered_list() {
    let symbols: Vec<Symbol> = (0..4).map(|esi| symbol(1, esi, 64)).collect();
    let leaves: Vec<(u32, [u8; 32])> = symbols
        .iter()
        .map(|s| (s.esi, symbol_leaf(&s.data)))
        .collect();
    let root = symbol_root(&leaves);
    let share = CustodyShare {
        commitment: object_commitment(&[[5u8; 32]]),
        segment: 1,
        esi: symbols.iter().map(|s| s.esi).collect(),
        symbol_root: root,
    };
    assert!(share.esi_is_ordered());
    assert_eq!(share.len(), 4);
    assert!(!share.is_empty());

    // The same leaves in another order do not reach the same root, which is
    // exactly why the share carries the order rather than a set.
    let mut reversed = leaves.clone();
    reversed.reverse();
    assert_ne!(symbol_root(&reversed), root);

    let unordered = CustodyShare {
        esi: vec![2, 1],
        ..share
    };
    assert!(!unordered.esi_is_ordered());
}

/// A group covers `k + 2` or the segment has no single surviving validator.
#[test]
fn the_placement_group_covers_k_plus_two() {
    let group = PlacementGroup {
        segment: 0,
        n_full: 4,
        s_full: 96,
        n_mobile: 64,
        s_mobile: 12,
        f: 20,
        holder: vec![[6u8; 32]; 68],
    };
    assert_eq!(group.symbols(), 4 * 96 + 64 * 12);
    assert!(group.covers(400));
    assert!(!group.covers(u32::try_from(group.symbols()).unwrap_or(u32::MAX)));

    let thin = PlacementGroup {
        n_full: 1,
        s_full: 1,
        n_mobile: 0,
        s_mobile: 1,
        ..group
    };
    assert!(!thin.covers(2), "1 + 0 symbols does not reach k + 2 = 4");
}

/// Section 6.8 deletes at zero, so zero must mean both terms are zero.
#[test]
fn the_reference_counter_reaches_zero_only_when_nothing_names_the_object() {
    let mut count = RefCount::default();
    assert!(count.is_zero());
    count.add_reference();
    count.add_reference();
    assert_eq!(count.total(), 2);
    assert_eq!(count.release_reference(), Ok(()));
    count.bound = 1;
    assert_eq!(count.release_reference(), Ok(()));
    assert!(!count.is_zero(), "the bound object still names it");
    count.bound = 0;
    assert!(count.is_zero());
    assert_eq!(
        count.release_reference(),
        Err("references"),
        "a release with nothing held is state corruption, not a no-op"
    );
}

/// The volume's ceiling is enforced before a member is added, and a length that
/// would overflow saturates above the ceiling instead of wrapping under it.
#[test]
fn the_aggregation_volume_refuses_a_member_past_its_ceiling() {
    let volume = AggregationVolume::new();
    assert_eq!(volume.capacity_bytes, 4 * 1024 * 1024);
    assert!(volume.is_empty());
    assert!(volume.admits(4 * 1024 * 1024 - 1, 1));
    assert!(!volume.admits(4 * 1024 * 1024, 1));
    assert!(
        !volume.admits(u64::MAX, 1),
        "a sum that cannot be paid is refused, not wrapped"
    );
}

/// The payload newtype is the A0 output and nothing else: its length is the
/// header's `payload_len`.
#[test]
fn the_payload_is_the_codec_output_and_zero_is_a_payload() {
    let empty = Payload(Vec::new());
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty(), "zero content still has a payload");

    let bytes = Payload(vec![9u8; 17]);
    assert_eq!(bytes.len(), 17);
    assert_eq!(bytes.as_bytes(), &[9u8; 17]);
    assert_eq!(ContentId::public(bytes.as_bytes()).len, 17);
}

/// Only one of the two paths produces pixels; the other is the encoder's own
/// values. This is the difference G4 and G5 are named for.
#[test]
fn the_two_paths_are_distinguishable_by_construction() {
    assert!(!Path::Logical(LogicalPath::Encoder).is_optical());
    assert!(Path::Optical(OpticalPath::Raster).is_optical());
}

#[test]
fn bud3_section_6_2_vocabulary_and_genesis_limits_wire_cleanly() {
    use crate::storage::bud3::limits::{Bud3Limits, GIB, RFC6330_MAX_SOURCE_SYMBOLS};
    use crate::storage::bud3::meter::{Meter, MeterError};
    use crate::storage::bud3::varint;

    let limits = Bud3Limits::TESTNET_DEFAULT;
    assert!(limits.validate().is_ok());
    assert!(limits.admit_content(GIB).is_ok());
    assert!(limits.admit_lifetime(limits.min_lifetime_days).is_ok());
    assert!(limits.admit_mobile_quota(limits.mobile_quota_min_bytes).is_ok());
    assert!(Profile::P0.is_valid());
    assert!(Profile::P0.k_max <= RFC6330_MAX_SOURCE_SYMBOLS);
    assert!(Profile::P0.segment_bytes() > 0);
    assert_eq!(Profile::by_id(0), Some(Profile::P0));

    let raw_codec: CodecId = 0;
    let obj = Object {
        content_id: ContentId::public(b"bud3"),
        profile: Profile::P0.id,
        codec: raw_codec,
        dictionary_id: 0,
        flags: 0,
        payload: Payload(b"bud3".to_vec()),
    };
    let seg = Segment {
        index: 0,
        k: 1,
        symbol_size: Profile::P0.symbol_size,
        root: [0x11; 32],
    };
    let src = SourceSymbol(symbol(seg.index, 0, usize::from(seg.symbol_size)));
    let rep = RepairSymbol(symbol(seg.index, 1, usize::from(seg.symbol_size)));
    assert_eq!(src.0.esi, 0);
    assert_eq!(rep.0.esi, 1);

    let commit = object_commitment(&[seg.root]);
    let table = PlacementTable {
        epoch: 1,
        commitment: commit,
        groups: Vec::new(),
    };
    assert_eq!(table.epoch, 1);
    assert_eq!(obj.payload.len(), 4);

    let mut enc = Vec::new();
    varint::write(&mut enc, 16_384);
    assert_eq!(enc.len(), varint::len(16_384));
    assert_eq!(varint::read(&enc, 4), Ok((16_384, enc.len())));

    let meter = Meter::for_object(64);
    assert!(meter.bytes_left() >= 64);
    assert!(meter.steps_left() > 0);
    let mut small = Meter::new(8, 4);
    assert_eq!(small.charge_bytes(5), Ok(()));
    assert!(matches!(small.charge_bytes(4), Err(MeterError::BytesExhausted { .. })));
    assert_eq!(small.charge_steps(3), Ok(()));
    assert!(matches!(small.charge_steps(2), Err(MeterError::StepsExhausted { .. })));
}
