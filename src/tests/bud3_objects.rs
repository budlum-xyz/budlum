//! B.U.D. 3.0 object path: the nine acceptance tests of WP-19
//! (Section 6.4, 6.5, 6.15, 6.23 T9 and T10).
//!
//! Every test named `bud3_*` here is a named acceptance test from the
//! directive. The unit tests inside `src/storage/bud3/{object,frames,stages,
//! volume,repair}.rs` cover the pieces; these tests cover what the directive
//! claims about the whole path. The remaining tests in this file cover the
//! supporting pieces of the same package (the A0 stage chain, the aggregation
//! volume and the repair decision) so that the package ships its own
//! evidence.
//!
//! Two profiles are used on purpose:
//!
//! * [`NARROW`] carries a 64-byte symbol, so a small object has several
//!   segments and several frames and the tests stay quick. It is never
//!   rendered as a QR symbol.
//! * [`Profile::P0`] is the canonical profile, whose 2911-byte symbol is the
//!   only size a QR frame at version 40, EC L, byte mode can carry. Every test
//!   that renders a raster uses it.

use crate::storage::bud3::bof1::Flags;
use crate::storage::bud3::frames::{
    frame_for_symbol, frames_for_object, is_png, object_from_optical, optical_video,
    round_trip_shape, symbol_from_frame, symbol_from_frame_sized, symbols_to_collect,
    two_paths_identical, FrameError,
};
use crate::storage::bud3::object::TextFrame;
use crate::storage::bud3::object::{
    b64url_decode, b64url_encode, encode_symbols, fold_frame_digests, frame_digest,
    header_from_text_fields, object_commitment_of, object_from_frames_checked,
    object_from_symbols, object_from_text, object_to_text, text_form, video_commitment,
    ObjectError, SegmentCommit,
};
use crate::storage::bud3::repair::{
    assign_repairer, plan_segment, repair_is_bad, shrink_plan, LossBudget,
};
use crate::storage::bud3::stages::{
    aggregate_applies, recognise, ContentClass, Stage, StageChain, StageOutcome,
};
use crate::storage::bud3::volume::{member_leaf, Volume, VolumeError, VOLUME_TARGET_BYTES};
use crate::storage::bud3::{limits::Profile, meter::Meter, Object, Symbol};
use crate::storage::bud3::{placement::Class, placement::Share};

/// 64-byte symbols and eight per segment: many segments, no raster.
const NARROW: Profile = Profile {
    id: 0,
    qr_version: 40,
    symbol_size: 64,
    fps: 4,
    k_max: 8,
};

fn content(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 37 % 251) as u8).collect()
}

/// One content class T1 names: the label the failure message reports and the
/// bytes themselves.
///
/// The samples carry the signature and shape of their class, not a whole
/// document: the codec on this path is the raw codec, so the round trip is the
/// identity function and what the samples are *for* is proving that the frame,
/// object and text layers do not care which bytes they carry. A class whose
/// bytes happened to round trip while another did not would be a bug in the
/// path, and this list is what would catch it.
fn format_samples() -> Vec<(&'static str, Vec<u8>)> {
    let sample_text = "The object carries the content, the network carries its symbols.\n";
    vec![
        ("text", sample_text.as_bytes().to_vec()),
        ("json", br#"{"a":1,"b":[true,null,"x"]}"#.to_vec()),
        ("records", content(4096)),
        ("csv", b"id,value\n1,2\n3,4\n".to_vec()),
        ("source", b"pub fn main() { println!(\"hello\"); }\n".to_vec()),
        (
            "png",
            [
                &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A][..],
                &content(512)[..],
            ]
            .concat(),
        ),
        ("jpeg", [&[0xFF, 0xD8, 0xFF, 0xE0][..], &content(400)[..]].concat()),
        ("mp4", [&b"\0\0\0\x18ftypmp42"[..], &content(600)[..]].concat()),
        ("wav", [&b"RIFF\x24\0\0\0WAVE"[..], &content(300)[..]].concat()),
        ("mp3", [&[0x49, 0x44, 0x33, 0x04][..], &content(256)[..]].concat()),
        ("zip", [&[b'P', b'K', 0x03, 0x04][..], &content(700)[..]].concat()),
        ("docx", [&[b'P', b'K', 0x03, 0x04][..], &content(900)[..]].concat()),
        ("pdf", [&b"%PDF-1.7\n"[..], &content(800)[..]].concat()),
        ("random", content(1024)),
        ("zero bytes", Vec::new()),
        ("one byte", vec![0xAB]),
    ]
}

fn object_of(n: usize) -> Object {
    Object::raw_public(&content(n))
}

fn symbols_of(bytes: &[u8], profile: &Profile, per_segment: u32) -> Vec<Symbol> {
    encode_symbols(bytes, profile, per_segment)
        .unwrap_or_default()
        .into_iter()
        .flatten()
        .collect()
}

/// T1 / Section 6.15: every format round trips. Text, JSON, records, CSV,
/// source, PNG, JPEG, MP4, WAV, MP3, ZIP, DOCX, PDF, random bytes, zero bytes
/// and one byte: content, video, object, video and content are bit equal.
#[test]
fn bud3_every_format_round_trips() {
    for (label, payload) in format_samples() {
        let object = Object::raw_public(&payload);
        let bytes = object.encode();

        // Content -> object -> symbols -> object -> content.
        let symbols = symbols_of(&bytes, &NARROW, 12);
        let back = object_from_symbols(&symbols, &NARROW, bytes.len() as u64)
            .unwrap_or_else(|e| panic!("{label}: symbols did not decode: {e:?}"));
        assert_eq!(back, bytes, "{label}: object bytes");
        let mut meter = Meter::for_object(1 << 20);
        let parsed = Object::decode(&back, &mut meter)
            .unwrap_or_else(|e| panic!("{label}: object did not parse: {e:?}"));
        assert_eq!(parsed.payload, payload, "{label}: content");

        // Content -> object -> frames -> symbols -> object -> content.
        let frames: Vec<Vec<u8>> = frames_for_object(&bytes, &NARROW, 12)
            .unwrap_or_else(|e| panic!("{label}: framing failed: {e:?}"))
            .iter()
            .map(|s| frame_for_symbol(s).unwrap_or_else(|e| panic!("{label}: {e:?}")))
            .collect();
        let read: Vec<Symbol> = frames
            .iter()
            .map(|f| symbol_from_frame(f).unwrap_or_else(|e| panic!("{label}: {e:?}")))
            .collect();
        assert_eq!(
            object_from_symbols(&read, &NARROW, bytes.len() as u64)
                .unwrap_or_else(|e| panic!("{label}: frames did not decode: {e:?}")),
            bytes,
            "{label}: frame bytes"
        );

        // Content -> text -> content, for a public object.
        let text = object_to_text(&object, &NARROW, 12)
            .unwrap_or_else(|e| panic!("{label}: text form failed: {e:?}"));
        let mut meter = Meter::for_object(1 << 20);
        let from_text = object_from_text(&text, &NARROW, &mut meter)
            .unwrap_or_else(|e| panic!("{label}: text did not read: {e:?}"));
        assert_eq!(from_text, bytes, "{label}: text bytes");

        // And the video commitment is the same commitment on both sides.
        let commitment = video_commitment(&symbols, &NARROW)
            .unwrap_or_else(|e| panic!("{label}: no video commitment: {e:?}"));
        let from_frames = video_commitment(&read, &NARROW)
            .unwrap_or_else(|e| panic!("{label}: no video commitment: {e:?}"));
        assert_eq!(from_frames, commitment, "{label}: video commitment");
    }
}

/// Section 6.4 Y11: the logical path and the optical path write the same object.
#[test]
fn bud3_two_paths_are_identical() {
    for n in [0usize, 1, 100, 5000] {
        let bytes = object_of(n).encode();
        two_paths_identical(&bytes, &Profile::P0, 4).unwrap();
    }
}

/// Section 6.5 G4 and G5: what a camera reads and what the device decodes are
/// the same bytes, symbol for symbol.
#[test]
fn bud3_logical_equals_optical() {
    let bytes = object_of(6000).encode();
    let pngs = optical_video(&bytes, &Profile::P0, 8).unwrap();
    assert!(!pngs.is_empty());
    assert!(pngs.iter().all(|p| is_png(p)));
    let optical = object_from_optical(&pngs, &Profile::P0, bytes.len() as u64).unwrap();
    let symbols = symbols_of(&bytes, &Profile::P0, 8);
    let logical = object_from_symbols(&symbols, &Profile::P0, bytes.len() as u64).unwrap();
    assert_eq!(optical, logical);
    assert_eq!(logical, bytes);
}

/// Section 6.5 G3: a lossy channel loses frames and the object still comes back,
/// because the repair symbols carry the loss.
#[test]
fn bud3_lossy_channel() {
    let object = object_of(12_000);
    let bytes = object.encode();
    let symbols = symbols_of(&bytes, &Profile::P0, 10);
    // Drop every third frame. The stream keeps more than the k source symbols
    // of each segment, which is the redundancy the loss rule buys (G3).
    let thinned: Vec<Symbol> = symbols
        .into_iter()
        .enumerate()
        .filter(|(i, _)| i % 3 != 0)
        .map(|(_, s)| s)
        .collect();
    let back = object_from_symbols(&thinned, &Profile::P0, bytes.len() as u64).unwrap();
    assert_eq!(back, bytes);
    // The checked entry point also verifies the commitment the uploader made.
    let commitment = object_commitment_of(&object.header, &object.payload).unwrap();
    assert_eq!(
        object_from_frames_checked(&thinned, &Profile::P0, bytes.len() as u64, &commitment)
            .unwrap(),
        bytes
    );
    let wrong = [0u8; 32];
    assert_eq!(
        object_from_frames_checked(&thinned, &Profile::P0, bytes.len() as u64, &wrong),
        Err(ObjectError::CommitmentMismatch)
    );

    // A stream that lost more than the budget is refused, not padded: one
    // source symbol cannot rebuild the object.
    let thin = vec![Symbol {
        segment: 0,
        esi: 0,
        data: vec![0u8; usize::from(Profile::P0.symbol_size)],
    }];
    assert!(object_from_symbols(&thin, &Profile::P0, bytes.len() as u64).is_err());
}

/// Cross architecture: the golden vectors do not depend on the machine. Every
/// hash input is little-endian, every length is a varint, and no field is
/// serialised as a platform `usize`, so the same object gives the same values
/// on every target.
#[test]
fn bud3_golden_vectors_cross_arch() {
    let object = Object::raw_public(b"bud3");
    let bytes = object.encode();
    assert_eq!(hex::encode(&bytes[..2]), "4233", "the magic is B3");

    let commitment = object_commitment_of(&object.header, &object.payload).unwrap();
    let symbols = symbols_of(&bytes, &Profile::P0, 8);
    let video = video_commitment(&symbols, &Profile::P0).unwrap();
    let fold = fold_frame_digests(&symbols.iter().map(frame_digest).collect::<Vec<_>>()).unwrap();
    for _ in 0..3 {
        assert_eq!(
            object_commitment_of(&object.header, &object.payload).unwrap(),
            commitment
        );
        assert_eq!(video_commitment(&symbols, &Profile::P0).unwrap(), video);
        assert_eq!(
            fold_frame_digests(&symbols.iter().map(frame_digest).collect::<Vec<_>>()).unwrap(),
            fold
        );
    }
    // The header length the reader derives is the length the encoder wrote.
    assert_eq!(object.header.encoded_len(), object.header_bytes(4).len());
    assert_eq!(bytes.len(), object.header.encoded_len() + 4);
}

/// T8, the frozen half: the exact bytes and digests a given object and a given
/// frame set produce. The determinism workflow runs this test on x86_64 and
/// aarch64, so a value that depended on the platform, the endianness of a
/// native integer or the width of `usize` would fail on one of them. The
/// values were computed from the construction the modules document and are
/// written here as hex so a change to any of them is visible in the diff.
#[test]
fn bud3_golden_frame_vectors_are_frozen() {
    // The public raw object of `abc`: magic, version, flags, profile, codec,
    // dictionary, content length, the content digest, the payload length and
    // the payload.
    let object = Object::raw_public(b"abc");
    let bytes = object.encode();
    assert_eq!(
        hex::encode(&bytes),
        "4233010000000003ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad03616263"
    );

    // One segment, so the commitment is the segment digest folded once.
    let commitment = object_commitment_of(&object.header, &object.payload).unwrap();
    assert_eq!(
        hex::encode(commitment),
        "c9b1401acbe2f605b36aec8a33b634a14bff1d4fefcc252fbb0b1597f672b4ad"
    );

    // Four deterministic frames of one segment: the per-frame digest and the
    // video commitment over them.
    let frames: Vec<Symbol> = (0u32..4)
        .map(|esi| Symbol {
            segment: 0,
            esi,
            data: vec![(esi % 251) as u8; 64],
        })
        .collect();
    assert_eq!(
        hex::encode(frame_digest(&frames[0])),
        "dee559159bc32d32dce5729af1378829141dbd3823f15764d9f64ebbec3a1a8d"
    );
    assert_eq!(
        hex::encode(video_commitment(&frames, &NARROW).unwrap()),
        "412d371c95b240f18259ac25da13bcedcfb0c5f38f6f81b1721371d25905e36b"
    );
}

/// T9 / Section 6.15: the information law canary. The object is never smaller
/// than its header, its declared lengths are the lengths it holds, and a
/// truncated object is refused rather than read as a shorter one.
#[test]
fn bud3_information_law_canary() {
    let empty = object_of(0);
    let empty_bytes = empty.encode();
    assert_eq!(empty_bytes.len(), empty.header.encoded_len());
    assert!(empty_bytes.len() >= 2 + 1 + 1);

    let mut meter = Meter::for_object(1 << 20);
    let parsed = Object::decode(&empty_bytes, &mut meter).unwrap();
    assert_eq!(parsed.header.payload_len, 0);
    assert_eq!(parsed.header.content_len, 0);
    assert_eq!(parsed.payload.len(), 0);

    let long = object_of(4096);
    let long_bytes = long.encode();
    assert_eq!(
        long_bytes.len(),
        long.header.encoded_len() + long.payload.len()
    );
    let mut meter = Meter::for_object(1 << 20);
    let parsed = Object::decode(&long_bytes, &mut meter).unwrap();
    assert_eq!(parsed.payload.len(), parsed.header.payload_len as usize);
    assert_eq!(parsed.header.content_len, 4096);

    // One byte short is not a smaller object.
    let short = &long_bytes[..long_bytes.len() - 1];
    let mut meter = Meter::for_object(1 << 20);
    assert!(Object::decode(short, &mut meter).is_err());
    // One byte after the payload is not part of the object either.
    let mut longer = long_bytes.clone();
    longer.push(0);
    let mut meter = Meter::for_object(1 << 20);
    assert!(Object::decode(&longer, &mut meter).is_err());
}

/// Section 6.3.3: the text form round trips and refuses what it cannot express.
#[test]
fn bud3_text_format_round_trips() {
    let object = object_of(300);
    let bytes = object.encode();
    let text = object_to_text(&object, &NARROW, 12).unwrap();
    assert!(text.starts_with("BUD3-OBJECT 1\n"));
    assert!(text.contains("\nsecond 0\n"));
    assert!(text.contains("\nend commitment="));
    assert!(text.ends_with('\n'));

    let mut meter = Meter::for_object(1 << 20);
    let form = text_form(&text, &mut meter).unwrap();
    assert_eq!(form.profile_id, 0);
    assert_eq!(form.payload_len, 300);
    assert_eq!(form.object_len().unwrap(), bytes.len() as u64);
    assert!(form
        .frames
        .iter()
        .any(|f| matches!(f, TextFrame::Source(_))));
    assert!(form
        .frames
        .iter()
        .any(|f| matches!(f, TextFrame::Repair { .. })));

    let mut meter = Meter::for_object(1 << 20);
    let back = object_from_text(&text, &NARROW, &mut meter).unwrap();
    assert_eq!(back, bytes);

    // A header built from the form's fields is the object's own header.
    let header = header_from_text_fields(
        form.profile_id,
        form.codec,
        form.dictionary,
        form.content_len,
        form.content_digest,
        form.payload_len,
    )
    .unwrap();
    assert_eq!(header, object.header);
    // An unregistered profile is refused rather than defaulted.
    assert_eq!(
        header_from_text_fields(99, form.codec, 0, 0, [0u8; 32], 0),
        Err(ObjectError::BadProfile)
    );

    // A sealed object has a flag the text form cannot express.
    let mut sealed = object_of(10);
    sealed.header.flags = Flags::from_byte(Flags::SEALED).unwrap();
    assert_eq!(
        object_to_text(&sealed, &NARROW, 12),
        Err(ObjectError::TextRefusedFlags(Flags::SEALED))
    );

    // One changed character breaks the commitment (Section 6.3.3 madde 3): the
    // body of a source frame is one base64url digit longer or shorter than the
    // bytes it carries, and the object it writes is a different object.
    let tampered = text.replacen(" S 0 0 ", " S 0 0 A", 1);
    assert_ne!(tampered, text);
    let mut meter = Meter::for_object(1 << 20);
    assert!(object_from_text(&tampered, &NARROW, &mut meter).is_err());

    // A grouping that skips a second is refused.
    let out_of_order = text.replacen("second 1", "second 5", 1);
    let mut meter = Meter::for_object(1 << 20);
    assert_eq!(
        text_form(&out_of_order, &mut meter),
        Err(ObjectError::Text("second order"))
    );
}

/// Section 6.21.2: every parser runs under a budget, never panics, and never
/// allocates from an untrusted length before it has the bytes. The fuzz
/// targets are the property form; these are the seed cases.
#[test]
fn bud3_parsers_fuzz() {
    // Every truncation of a valid object is refused, and none panics.
    let bytes = object_of(200).encode();
    for cut in 0..bytes.len() {
        let mut meter = Meter::for_object(1 << 20);
        assert!(
            Object::decode(&bytes[..cut], &mut meter).is_err(),
            "a truncated object decoded at {cut}"
        );
    }

    // A frame with a bad magic, a bad version or a short header is refused.
    let symbol = Symbol {
        segment: 0,
        esi: 0,
        data: vec![7u8; usize::from(NARROW.symbol_size)],
    };
    let good = frame_for_symbol(&symbol).unwrap();
    assert_eq!(symbol_from_frame(b"no"), Err(FrameError::Truncated));
    assert_eq!(symbol_from_frame(b"nope"), Err(FrameError::BadMagic));
    let mut bad_version = good.clone();
    bad_version[3] = 9;
    assert_eq!(symbol_from_frame(&bad_version), Err(FrameError::BadVersion(9)));
    assert_eq!(symbol_from_frame(&good[..5]), Err(FrameError::Truncated));
    assert_eq!(symbol_from_frame(&good[..16]), Err(FrameError::BadPayloadLen(0)));
    assert_eq!(symbol_from_frame_sized(&good, &NARROW), Ok(symbol));

    // A form with an unknown keyword, a bad base64 body or a repair frame
    // that carries bytes is refused.
    let text = object_to_text(&object_of(70), &NARROW, 12).unwrap();
    for bad in [
        String::from("BUD3-OBJECT 1\nnonsense\n"),
        text.replacen("S 0 0 ", "S 0 0 !!", 1),
        text.replacen("derived", "payload", 1),
        text.replacen("BUD3-OBJECT 1", "BUD3-OBJECT 2", 1),
    ] {
        let mut meter = Meter::for_object(1 << 20);
        assert!(text_form(&bad, &mut meter).is_err(), "{bad}");
    }

    // A volume with a mangled header is refused.
    assert_eq!(
        Volume::decode(b"B3VOL", false),
        Err(VolumeError::Malformed("version"))
    );
    assert!(Volume::decode(b"NOPE!!9", false).is_err());

    // base64url refuses an impossible length, an outside character and a
    // non-zero tail.
    assert_eq!(b64url_decode("A"), None);
    assert_eq!(b64url_decode("AA*"), None);
    assert_eq!(b64url_decode("AB"), None, "a non-zero tail is not padding");
    assert_eq!(b64url_encode(b"a"), String::from("YQ"));
    assert_eq!(b64url_decode("YQ"), Some(vec![b'a']));

    // The frame count a viewer must collect is k + 2, and a segment that does
    // not exist is refused.
    assert_eq!(symbols_to_collect(&NARROW, 512, 0), Ok(10));
    assert!(symbols_to_collect(&NARROW, 512, 9).is_err());
}

/// Section 6.15, BLG-214: the video commitment is over the logical frames. The
/// PNG bytes, the raster size and the frame rate are not part of it.
#[test]
fn video_commitment_ignores_png_bytes() {
    let bytes = object_of(6000).encode();
    let symbols = symbols_of(&bytes, &Profile::P0, 10);
    let commitment = video_commitment(&symbols, &Profile::P0).unwrap();

    // Rendering the same frames twice yields byte identical PNGs, and the
    // commitment never saw them.
    let first = optical_video(&bytes, &Profile::P0, 10).unwrap();
    let second = optical_video(&bytes, &Profile::P0, 10).unwrap();
    assert_eq!(first, second);
    assert_eq!(video_commitment(&symbols, &Profile::P0).unwrap(), commitment);

    // Different raster bytes for the same frame leave the commitment alone.
    let mut pngs = first.clone();
    if let Some(png) = pngs.first_mut() {
        png.push(0);
    }
    assert_ne!(pngs.first(), first.first());
    assert_eq!(video_commitment(&symbols, &Profile::P0).unwrap(), commitment);

    // The same frames in another order are the same video.
    let mut shuffled = symbols.clone();
    shuffled.reverse();
    assert_eq!(
        video_commitment(&shuffled, &Profile::P0).unwrap(),
        commitment
    );

    // A frame whose bytes changed is a different video.
    let mut altered = symbols.clone();
    if let Some(s) = altered.first_mut() {
        s.data = vec![0u8; s.data.len()];
    }
    assert_ne!(
        video_commitment(&altered, &Profile::P0).unwrap(),
        commitment
    );
}

// ---------------------------------------------------------------------------
// The supporting pieces of the same package.
// ---------------------------------------------------------------------------

#[test]
fn bud3_stage_chain_records_every_stage() {
    let outcomes: Vec<(Stage, StageOutcome)> = Stage::ALL
        .iter()
        .map(|s| {
            (
                *s,
                StageOutcome::Declined {
                    reason: String::from("n/a"),
                },
            )
        })
        .collect();
    let chain = StageChain::build(&outcomes, &[1000; 6], &[1000; 6]).unwrap();
    assert_eq!(chain.applied_count(), 0);
    assert_eq!(chain.ratio_ppm(), 1_000_000);
    assert!(chain.to_line().starts_with("S0=-n/a"));
    assert_eq!(recognise(b"{\"a\": 1}"), ContentClass::Records);
    assert_eq!(recognise(b"pub struct S;"), ContentClass::Source);
    // S4 applies to a payload that fits one volume and not to a larger one.
    assert!(aggregate_applies(&NARROW, VOLUME_TARGET_BYTES));
    assert!(!aggregate_applies(&NARROW, VOLUME_TARGET_BYTES + 1));
    // A chain where nothing applied stops at its last row.
    assert_eq!(chain.stopped_at(), Some(Stage::Seal));
}

/// The parts of a member proof that survive a removal: everything but the
/// offset, which is the volume's business.
struct MemberProofAfterRemoval {
    index: u32,
    len: u64,
    commitment: [u8; 32],
}

#[test]
fn bud3_volume_hides_nothing_from_its_members() {
    let mut volume = Volume::public();
    let first = volume.insert(false, [1u8; 32], b"one").unwrap();
    let second = volume.insert(false, [2u8; 32], b"two").unwrap();
    assert_ne!(member_leaf(&first), member_leaf(&second));
    let bytes = volume.encode().unwrap();
    let mut back = Volume::decode(&bytes, false).unwrap();
    assert_eq!(back.member_bytes(&first).unwrap(), b"one");
    assert_eq!(back.member_bytes(&second).unwrap(), b"two");
    assert_eq!(
        back.insert(true, [3u8; 32], b"sealed"),
        Err(VolumeError::VisibilityMismatch)
    );
    assert_ne!(back.commitment().unwrap(), [0u8; 32]);
    // A member that leaves takes its bytes with it.
    let shifted = MemberProofAfterRemoval {
        index: second.index,
        len: second.len,
        commitment: second.commitment,
    };
    back.remove(0).unwrap();
    assert_eq!(back.members().len(), 1);
    // The member that stayed moved to the front of the body, and its own
    // commitment is unchanged: only its offset moved.
    let offset = back.offset_of(shifted.index).unwrap();
    assert_eq!(offset, 0);
    let proof = crate::storage::bud3::volume::MemberProof {
        index: shifted.index,
        offset,
        len: shifted.len,
        commitment: shifted.commitment,
    };
    assert_eq!(back.member_bytes(&proof).unwrap(), b"two");
}

#[test]
fn bud3_repair_fires_below_the_threshold() {
    let held = vec![(
        Share {
            validator: [1u8; 32],
            class: Class::Full,
            first_esi: 0,
            symbols: 3,
        },
        vec![0u32, 1, 2],
    )];
    let mut task = plan_segment(
        [4u8; 32],
        0,
        512,
        &NARROW,
        LossBudget { f: 4, k: 8 },
        &held,
        [5u8; 32],
    )
    .unwrap()
    .unwrap();
    assert!(!task.missing_esis.is_empty());
    assert_eq!(task.slash_percent, 1);

    let eligible = [
        (
            Share {
                validator: [6u8; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: 1,
            },
            Class::Full,
        ),
        (
            Share {
                validator: [7u8; 32],
                class: Class::Mobile,
                first_esi: 0,
                symbols: 1,
            },
            Class::Mobile,
        ),
    ];
    assign_repairer(&mut task, &eligible, &|_| 10).unwrap();
    assert_eq!(task.repairer, [6u8; 32], "only a Full share repairs");
    assert!(!repair_is_bad(&[], &[]));

    let plan = shrink_plan(512, &NARROW, 8, 1).unwrap();
    assert!(plan.iter().all(|p| p.symbols_per_survivor >= 8 + 2));
    // The loss budget of a row: one eighth of its shares, at least one, and a
    // repair threshold of half of it.
    let budget = LossBudget::from_row(8, 0, 8);
    assert_eq!(budget.f, 1);
    assert_eq!(budget.threshold(), 1);
    assert!(budget.fires(8, 8));
    let budget = LossBudget::from_row(16, 512, 4096);
    assert_eq!(budget.f, 66);
    assert_eq!(budget.threshold(), 33);
}

#[test]
fn bud3_commit_reads_stream_in_any_chunking() {
    let object = object_of(2000);
    let bytes = object.encode();
    let want = object_commitment_of(&object.header, &object.payload).unwrap();
    for chunk in [1usize, 13, 512, 2000] {
        let mut commit = SegmentCommit::new(bytes.len() as u64, &NARROW).unwrap();
        let mut meter = Meter::new(u64::MAX, u64::MAX);
        for piece in bytes.chunks(chunk) {
            commit.push(piece, &mut meter).unwrap();
        }
        assert_eq!(commit.finish().unwrap(), want, "chunk {chunk}");
    }
}

#[test]
fn bud3_shape_is_stable_across_profiles() {
    let bytes = object_of(6000).encode();
    let narrow = round_trip_shape(&bytes, &NARROW).unwrap();
    let canonical = round_trip_shape(&bytes, &Profile::P0).unwrap();
    assert!(narrow.0 >= canonical.0, "a smaller symbol needs more segments");
    assert_eq!(narrow.1, (bytes.len() as u64).div_ceil(u64::from(NARROW.symbol_size)));
    // The fold of an empty frame list is not a video.
    assert!(fold_frame_digests(&[]).is_err());
}
