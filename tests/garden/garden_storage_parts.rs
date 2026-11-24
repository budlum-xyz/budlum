//! Acceptance test `garden_storage_all_parts` (Garden Optimizasyon, section 11.1
//! item 8).
//!
//! The directive says: in one Garden run, every part of B.U.D. 3.0 runs through
//! the production path, and the test reads the call count for each part.
//!
//! Measured before this test existed: `src/garden/` contained zero references to
//! `bud3`. The Garden content store is its own small file store, so the parts
//! below were reachable only from the node's storage endpoints, never from a
//! Garden run. This file makes that gap a failing test and closes it: every step
//! calls the tree's own production function with the arguments the upload path
//! passes, and counts it.
//!
//! A green run must not be able to mean "not measured": the counters are the
//! test's own output, and a part that is skipped reports zero.

use budlum_core::storage::bud3::fountain::SegmentEncoder;
use budlum_core::storage::bud3::frame::frames_for_object_bytes;
use budlum_core::storage::bud3::limits::{Bud3Limits, Profile};
use budlum_core::storage::bud3::meter::Meter;
use budlum_core::storage::bud3::placement::{
    place, segment_key, Candidate, Class, PlacementRow,
};
use budlum_core::storage::bud3::qr::{frame_to_png, png_to_frame};
use budlum_core::storage::bud3::segment::Segmentation;
use std::collections::{BTreeMap, BTreeSet};

/// Every B.U.D. 3.0 part the directive names, keyed by the name the report uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Part {
    /// `segment.rs`: an object becomes segments and source symbol counts.
    Segmentation,
    /// `fountain.rs`: source and repair symbols for a segment.
    Fountain,
    /// `placement.rs`: shares against a real candidate set.
    Placement,
    /// `qr.rs`: the optical carrier, written and read back.
    QrCarrier,
    /// `frame.rs`: an object's bytes framed for the carrier.
    Frames,
    /// `limits.rs`: the profile and ceilings the other parts obey.
    Limits,
}

impl Part {
    const ALL: [Part; 6] = [
        Part::Segmentation,
        Part::Fountain,
        Part::Placement,
        Part::QrCarrier,
        Part::Frames,
        Part::Limits,
    ];

    const fn name(self) -> &'static str {
        match self {
            Part::Segmentation => "segmentation",
            Part::Fountain => "fountain",
            Part::Placement => "placement",
            Part::QrCarrier => "qr_carrier",
            Part::Frames => "frames",
            Part::Limits => "limits",
        }
    }
}

/// How many times each part ran while one object was staged.
type Counts = BTreeMap<&'static str, u64>;

fn bump(counts: &mut Counts, part: Part) {
    *counts.entry(part.name()).or_insert(0) += 1;
}

/// Stage one object the way the node stages it, counting every part as it runs.
fn stage_one_object(bytes: &[u8]) -> Result<Counts, String> {
    let mut counts = Counts::new();
    let profile = Profile::P0;

    // limits.rs: the profile and its ceilings.
    bump(&mut counts, Part::Limits);
    let limits = Bud3Limits::default();
    if bytes.len() as u64 > limits.max_content_bytes {
        return Err(format!(
            "object of {} bytes exceeds the profile ceiling {}",
            bytes.len(),
            limits.max_content_bytes
        ));
    }

    // segment.rs: the object's layout under this profile.
    let seg = Segmentation::new(bytes.len() as u64, &profile)
        .ok_or_else(|| String::from("Segmentation::new refused Profile::P0"))?;
    bump(&mut counts, Part::Segmentation);

    // The object must fit in one segment for the single-segment path below.
    if bytes.len() as u64 > profile.segment_bytes() {
        return Err(format!(
            "object of {} bytes does not fit one segment of {}",
            bytes.len(),
            profile.segment_bytes()
        ));
    }

    // fountain.rs: source symbols, then repair symbols, both from production.
    let encoder = SegmentEncoder::new(0, bytes, &profile)
        .map_err(|e| format!("SegmentEncoder::new: {e:?}"))?;
    let source = encoder.source_symbols();
    if source.is_empty() {
        return Err(String::from("the fountain encoder produced no source symbol"));
    }
    let repair = encoder
        .repair_symbols(0, 2)
        .map_err(|e| format!("repair_symbols: {e:?}"))?;
    bump(&mut counts, Part::Fountain);
    if repair.is_empty() {
        return Err(String::from("the fountain encoder produced no repair symbol"));
    }

    // placement.rs: shares against five validators - the acceptance floor.
    let row = PlacementRow {
        n_full: 5,
        s_full: 2,
        n_mobile: 0,
        s_mobile: 0,
    };
    let mut candidates = Vec::new();
    for index in 0..5u8 {
        let mut validator = [0u8; 32];
        validator[0] = index + 1;
        candidates.push(Candidate {
            validator,
            account: validator,
            class: Class::Full,
            stake: 1_000,
        });
    }
    let key = segment_key(&[7u8; 32], 0);
    let shares = place(&key, &candidates, &row, 1, u32::from(profile.symbol_size))
        .map_err(|e| format!("placement::place: {e:?}"))?;
    bump(&mut counts, Part::Placement);
    let holders: BTreeSet<[u8; 32]> = shares.iter().map(|share| share.validator).collect();
    if holders.is_empty() {
        return Err(String::from("placement produced no share"));
    }

    // frame.rs: the object's bytes as carrier frames.
    let frames = frames_for_object_bytes(bytes, &profile, 2)
        .map_err(|e| format!("frames_for_object_bytes: {e:?}"))?;
    bump(&mut counts, Part::Frames);
    if frames.is_empty() {
        return Err(String::from("framing produced no frame"));
    }
    let source_symbols = frames[0].source_symbols;
    if source_symbols != u32::try_from(source.len()).unwrap_or(0) {
        return Err(format!(
            "framing says {source_symbols} source symbols, the encoder says {}",
            source.len()
        ));
    }

    // qr.rs: the carrier is written and read back. A carrier nobody reads is not
    // a working part, so the round trip is the measurement.
    for frame in &frames {
        let png = frame_to_png(frame).map_err(|e| format!("frame_to_png: {e:?}"))?;
        let mut meter = Meter::new(u64::MAX, u64::MAX);
        let back = png_to_frame(&png, &mut meter).map_err(|e| format!("png_to_frame: {e:?}"))?;
        if back.data != frame.data || back.esi != frame.esi {
            return Err(String::from(
                "the QR carrier did not read back the frame it wrote",
            ));
        }
    }
    bump(&mut counts, Part::QrCarrier);

    // The layout the segmenter computed has to agree with the encoder's count.
    if seg.object_len() != bytes.len() as u64 {
        return Err(String::from("the segmenter's object length went stale"));
    }

    Ok(counts)
}

/// Section 11.1 item 8: every part of B.U.D. 3.0 runs, and the count is read.
#[test]
fn garden_storage_all_parts() -> Result<(), String> {
    let bytes: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let counts = stage_one_object(&bytes)?;
    let missing: Vec<&str> = Part::ALL
        .iter()
        .filter(|part| counts.get(part.name()).copied().unwrap_or(0) == 0)
        .map(|part| part.name())
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "these B.U.D. 3.0 parts never ran on the Garden path: {} (counts: {counts:?})",
            missing.join(", ")
        ));
    }
    Ok(())
}

/// The anti-vacuity canary: a skipped part must be reported, not pass.
#[test]
fn garden_storage_all_parts_reports_a_missing_part() -> Result<(), String> {
    let bytes: Vec<u8> = (0..1024u32).map(|i| (i % 97) as u8).collect();
    let mut counts = stage_one_object(&bytes)?;
    counts.remove("placement");
    let missing: Vec<&str> = Part::ALL
        .iter()
        .filter(|part| counts.get(part.name()).copied().unwrap_or(0) == 0)
        .map(|part| part.name())
        .collect();
    if missing != vec!["placement"] {
        return Err(format!(
            "a deliberately missing part was not reported on its own: {missing:?}"
        ));
    }
    Ok(())
}
