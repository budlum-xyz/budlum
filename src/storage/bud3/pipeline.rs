//! The upload and view paths over the B.U.D. 3.0 parts.
//!
//! Upload: content -> BOF-1 object -> segments -> RFC 6330 symbols (source
//! and repair, as many as the placement row asks for) -> per-segment symbol
//! roots -> [`ObjectRecord`]. The record is what the chain keeps: the content
//! id, the object length, the object commitment, the profile and one symbol
//! root per segment. The symbols themselves go to the custody shares.
//!
//! View: symbols from any holders -> each segment decoded from any `k`
//! independent symbols -> object bytes checked against the commitment ->
//! BOF-1 parsed -> content checked against the content id. Content is shown
//! only when every check passes.
//!
//! The codec register sits between content and payload: the upload path
//! selects the codec and stores its payload, the view path decodes it back.
//! Nothing after the object changes with the codec.
//! Convenience: public B.U.D. 3.0 upload preparation and public view decode entry points for gateway and CLI.

use super::bof1::{Bof1Error, CodecId, Object};
use super::content_id::ContentId;
use super::custody::{symbol_leaf, symbol_root};
use super::fountain::{FountainError, SegmentDecoder, SegmentEncoder, Symbol};
use super::limits::{Bud3Limits, LimitError, Profile};
use super::meter::Meter;
use super::segment::{commit_object, Segmentation};
use super::volume::{self, AggregationVolume, Visibility, VolumeError, VolumeMember};

/// What the chain records for one object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectRecord {
    /// The content id.
    pub content_id: ContentId,
    /// The object length in bytes.
    pub object_len: u64,
    /// The object commitment.
    pub commitment: [u8; 32],
    /// The profile the object is coded with.
    pub profile: Profile,
    /// The A0 codec the object payload carries.
    pub codec: CodecId,
    /// Symbols per segment in the placement.
    pub symbols_per_segment: u32,
    /// The symbol root of every segment.
    pub symbol_roots: Vec<[u8; 32]>,
}

/// One object small enough to share a placed segment with other objects.
#[derive(Debug, Clone)]
pub struct SmallObject {
    /// The content id.
    pub content_id: ContentId,
    /// The object commitment. It does not change when the object joins a
    /// volume.
    pub commitment: [u8; 32],
    /// The object bytes.
    pub bytes: Vec<u8>,
}

/// What the chain records for one aggregation volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeRecord {
    /// The id of the volume bytes.
    pub volume_id: [u8; 32],
    /// The member root.
    pub root: [u8; 32],
    /// Volume length in bytes.
    pub bytes_len: u64,
    /// The profile the volume is coded with.
    pub profile: Profile,
    /// Symbols in the placement of the volume.
    pub symbols_per_segment: u32,
    /// The symbol root of the volume.
    pub symbol_root: [u8; 32],
    /// What the volume carries.
    pub visibility: Visibility,
    /// The member table.
    pub members: Vec<VolumeMember>,
}

/// A volume ready for placement: the record, its symbols and the volume.
#[derive(Debug, Clone)]
pub struct PreparedVolume {
    /// The record.
    pub record: VolumeRecord,
    /// Symbols of the volume, in ESI order.
    pub symbols: Vec<Symbol>,
    /// The volume itself.
    pub volume: AggregationVolume,
}

/// An upload ready for placement: the record and every coded symbol, by
/// segment.
#[derive(Debug, Clone)]
pub struct PreparedUpload {
    /// The record.
    pub record: ObjectRecord,
    /// Symbols of each segment, in ESI order.
    pub segments: Vec<Vec<Symbol>>,
}

/// Why an upload or a view failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    /// A limit refused the content.
    Limit(LimitError),
    /// Coding failed.
    Fountain(FountainError),
    /// The object did not parse or match.
    Object(Bof1Error),
    /// The placement asks for fewer symbols than a segment needs.
    TooFewSymbols { want: u32, k: u32 },
    /// Some segment did not decode from the symbols given.
    SegmentMissing(u64),
    /// The decoded object does not match the commitment.
    CommitmentMismatch,
    /// The decoded content does not match the content id.
    ContentMismatch,
    /// The object does not fit this platform.
    TooLarge,
    /// The aggregation volume refused a member or a view.
    Volume(VolumeError),
}

impl From<VolumeError> for PipelineError {
    fn from(e: VolumeError) -> Self {
        Self::Volume(e)
    }
}

impl From<FountainError> for PipelineError {
    fn from(e: FountainError) -> Self {
        Self::Fountain(e)
    }
}

impl From<Bof1Error> for PipelineError {
    fn from(e: Bof1Error) -> Self {
        Self::Object(e)
    }
}

/// Prepare public content for upload. `symbols_per_segment` is the
/// placement row's total; it must cover `k + 2` of the largest segment.
///
/// # Errors
///
/// [`PipelineError`] for a refused length, a too-small placement or a coding
/// error.
pub fn prepare_public_upload(
    content: &[u8],
    profile: &Profile,
    limits: &Bud3Limits,
    symbols_per_segment: u32,
) -> Result<PreparedUpload, PipelineError> {
    limits
        .admit_content(content.len() as u64)
        .map_err(PipelineError::Limit)?;
    // The codec register picks the shortest verified representation; the
    // object carries the codec and its payload, and nothing after the
    // object changes with the codec.
    let selected = bud_codec::select(content);
    let codec = selected.codec;
    let object = Object::public_coded(codec, selected.payload, content)?;
    let bytes = object.encode();
    let seg = Segmentation::new(bytes.len() as u64, profile)
        .ok_or(PipelineError::Fountain(FountainError::InvalidProfile))?;
    let commitment = commit_object(&bytes, profile).ok_or(PipelineError::TooLarge)?;
    let mut segments = Vec::new();
    let mut symbol_roots = Vec::new();
    for index in 0..seg.count() {
        let start = usize::try_from(seg.offset(index).ok_or(PipelineError::TooLarge)?)
            .map_err(|_| PipelineError::TooLarge)?;
        let len = usize::try_from(seg.len(index).ok_or(PipelineError::TooLarge)?)
            .map_err(|_| PipelineError::TooLarge)?;
        let end = start.checked_add(len).ok_or(PipelineError::TooLarge)?;
        let slice = bytes.get(start..end).ok_or(PipelineError::TooLarge)?;
        let enc = SegmentEncoder::new(index, slice, profile)?;
        let k = enc.k();
        if symbols_per_segment < k.saturating_add(2) {
            return Err(PipelineError::TooFewSymbols {
                want: symbols_per_segment,
                k,
            });
        }
        let mut symbols = enc.source_symbols();
        symbols.extend(enc.repair_symbols(0, symbols_per_segment - k)?);
        let leaves: Vec<(u32, [u8; 32])> = symbols
            .iter()
            .map(|s| (s.esi, symbol_leaf(&s.data)))
            .collect();
        symbol_roots.push(symbol_root(&leaves));
        segments.push(symbols);
    }
    Ok(PreparedUpload {
        record: ObjectRecord {
            content_id: ContentId::public(content),
            object_len: bytes.len() as u64,
            commitment,
            profile: *profile,
            codec,
            symbols_per_segment,
            symbol_roots,
        },
        segments,
    })
}

/// Prepare small objects for one aggregation volume (section 6.12).
///
/// Every object must be smaller than one symbol, so it is not placed on its
/// own. The volume is coded and placed exactly like one segment. The capacity
/// is the smaller of the genesis volume length and one segment of the profile.
///
/// # Errors
///
/// [`PipelineError`] for an empty batch, an object the limits or the volume
/// refuse, a too-small placement or a coding error.
///
/// WIRING: the upload session of WP-21 calls this for a batch of sub-symbol
/// objects once the `bud3` door replaces the legacy storage path.
pub fn prepare_volume_upload(
    objects: &[SmallObject],
    visibility: Visibility,
    profile: &Profile,
    limits: &Bud3Limits,
    symbols_per_segment: u32,
) -> Result<PreparedVolume, PipelineError> {
    if objects.is_empty() {
        return Err(PipelineError::Volume(VolumeError::EmptyVolume));
    }
    let capacity = limits.volume_bytes.min(profile.segment_bytes());
    let mut volume = AggregationVolume::new(visibility, capacity)?;
    for object in objects {
        limits
            .admit_content(object.bytes.len() as u64)
            .map_err(PipelineError::Limit)?;
        volume.push(
            &object.content_id,
            object.commitment,
            &object.bytes,
            u32::from(profile.symbol_size),
        )?;
    }
    let bytes = volume.bytes().to_vec();
    let encoder = SegmentEncoder::new(0, &bytes, profile)?;
    let k = encoder.k();
    if symbols_per_segment < k.saturating_add(2) {
        return Err(PipelineError::TooFewSymbols {
            want: symbols_per_segment,
            k,
        });
    }
    let mut symbols = encoder.source_symbols();
    symbols.extend(encoder.repair_symbols(0, symbols_per_segment - k)?);
    let leaves: Vec<(u32, [u8; 32])> = symbols
        .iter()
        .map(|s| (s.esi, symbol_leaf(&s.data)))
        .collect();
    let record = VolumeRecord {
        volume_id: volume.volume_id(),
        root: volume.root(),
        bytes_len: bytes.len() as u64,
        profile: *profile,
        symbols_per_segment,
        symbol_root: symbol_root(&leaves),
        visibility,
        members: volume.members().to_vec(),
    };
    Ok(PreparedVolume {
        record,
        symbols,
        volume,
    })
}

/// Rebuild and check public content from symbols. Symbols may arrive in any
/// order, from any holders, with duplicates; malformed ones are skipped.
///
/// # Errors
///
/// [`PipelineError`] when a segment does not decode, or the object or the
/// content does not match the record.
pub fn view_public<I>(record: &ObjectRecord, symbols: I) -> Result<Vec<u8>, PipelineError>
where
    I: IntoIterator<Item = Symbol>,
{
    let seg = Segmentation::new(record.object_len, &record.profile)
        .ok_or(PipelineError::Fountain(FountainError::InvalidProfile))?;
    let count = usize::try_from(seg.count()).map_err(|_| PipelineError::TooLarge)?;
    let mut decoders = Vec::with_capacity(count.min(1 << 16));
    for index in 0..seg.count() {
        let len = seg.len(index).ok_or(PipelineError::TooLarge)?;
        decoders.push(SegmentDecoder::new(index, len, &record.profile)?);
    }
    let mut meter = Meter::new(
        record.object_len.saturating_mul(4).saturating_add(1 << 20),
        u64::from(record.symbols_per_segment).saturating_mul(seg.count()),
    );
    for s in symbols {
        let Some(dec) = usize::try_from(s.segment)
            .ok()
            .and_then(|i| decoders.get_mut(i))
        else {
            continue;
        };
        if dec.is_done() {
            continue;
        }
        // A malformed symbol from one holder does not stop the view.
        let _ = dec.push(s, &mut meter);
    }
    let cap = usize::try_from(record.object_len).map_err(|_| PipelineError::TooLarge)?;
    let mut object = Vec::with_capacity(cap);
    for (index, dec) in decoders.into_iter().enumerate() {
        let bytes = dec
            .into_bytes()
            .ok_or(PipelineError::SegmentMissing(index as u64))?;
        object.extend_from_slice(&bytes);
    }
    if commit_object(&object, &record.profile) != Some(record.commitment) {
        return Err(PipelineError::CommitmentMismatch);
    }
    let mut parse_meter = Meter::for_object(record.object_len);
    let parsed = Object::decode(&object, &mut parse_meter)?;
    if parsed.header.codec != record.codec {
        return Err(PipelineError::ContentMismatch);
    }
    let content = parsed
        .public_content()
        .map_err(|_| PipelineError::ContentMismatch)?;
    if !record.content_id.matches_public(&content) {
        return Err(PipelineError::ContentMismatch);
    }
    Ok(content)
}

/// Rebuild the bytes of a placed volume from symbols and check them against
/// the record: the length, the volume id, the member table layout and the
/// member root.
///
/// # Errors
///
/// [`PipelineError`] when the symbols do not decode, the length differs, the
/// bytes are not the recorded bytes, or the member table does not tile them.
///
/// WIRING: the reveal session of WP-21 calls this when the viewer has collected
/// the symbols of a volume.
pub fn view_volume_bytes<I>(record: &VolumeRecord, symbols: I) -> Result<Vec<u8>, PipelineError>
where
    I: IntoIterator<Item = Symbol>,
{
    let mut decoder = SegmentDecoder::new(0, record.bytes_len, &record.profile)?;
    let mut meter = Meter::new(
        record.bytes_len.saturating_mul(4).saturating_add(1 << 20),
        u64::from(record.symbols_per_segment),
    );
    for symbol in symbols {
        if symbol.segment != 0 || decoder.is_done() {
            continue;
        }
        // A malformed symbol from one holder does not stop the view.
        let _ = decoder.push(symbol, &mut meter);
    }
    let bytes = decoder
        .into_bytes()
        .ok_or(PipelineError::SegmentMissing(0))?;
    let got = bytes.len() as u64;
    if got != record.bytes_len {
        return Err(PipelineError::Volume(VolumeError::LengthMismatch {
            want: record.bytes_len,
            got,
        }));
    }
    if volume::volume_id_of(&record.visibility, &bytes) != record.volume_id {
        return Err(PipelineError::Volume(VolumeError::IdMismatch));
    }
    check_volume_layout(&record.members, &bytes)?;
    if volume::root_of(&record.members) != record.root {
        return Err(PipelineError::Volume(VolumeError::RootMismatch));
    }
    Ok(bytes)
}

/// One member from a placed volume, checked against its position, its proof
/// and its own object commitment.
///
/// # Errors
///
/// [`PipelineError`] when the volume does not verify, the content id is not a
/// member, the proof fails, or the member bytes do not match the recorded
/// commitment.
///
/// WIRING: the reveal session of WP-21 calls this for the one member the viewer
/// asked for.
pub fn view_volume_member<I>(
    record: &VolumeRecord,
    symbols: I,
    content_id: &ContentId,
) -> Result<Vec<u8>, PipelineError>
where
    I: IntoIterator<Item = Symbol>,
{
    let bytes = view_volume_bytes(record, symbols)?;
    let index = record
        .members
        .iter()
        .position(|m| m.content_id == *content_id)
        .ok_or(PipelineError::Volume(VolumeError::UnknownMember))?;
    let member = record.members[index];
    let proof = volume::proof_for(&record.members, index);
    if !volume::verify_member(
        &record.root,
        record.members.len() as u64,
        index as u64,
        &member,
        &proof,
    ) {
        return Err(PipelineError::Volume(VolumeError::ProofMismatch));
    }
    let offset = usize::try_from(member.offset).map_err(|_| PipelineError::TooLarge)?;
    let len = usize::try_from(member.len).map_err(|_| PipelineError::TooLarge)?;
    let end = offset.checked_add(len).ok_or(PipelineError::TooLarge)?;
    let out = bytes.get(offset..end).ok_or(PipelineError::TooLarge)?;
    if commit_object(out, &record.profile) != Some(member.commitment) {
        return Err(PipelineError::CommitmentMismatch);
    }
    Ok(out.to_vec())
}

/// The member table must tile the volume bytes. A slot freed by a deletion is
/// zeroed, so a hole is all zero bytes.
fn check_volume_layout(members: &[VolumeMember], bytes: &[u8]) -> Result<(), PipelineError> {
    let mut expect = 0usize;
    for member in members {
        let offset = usize::try_from(member.offset).map_err(|_| PipelineError::TooLarge)?;
        let len = usize::try_from(member.len).map_err(|_| PipelineError::TooLarge)?;
        let end = offset.checked_add(len).ok_or(PipelineError::TooLarge)?;
        if offset < expect {
            return Err(PipelineError::Volume(VolumeError::LayoutMismatch));
        }
        bytes.get(offset..end).ok_or(PipelineError::TooLarge)?;
        let hole = bytes.get(expect..offset).ok_or(PipelineError::TooLarge)?;
        if !hole.iter().all(|byte| *byte == 0) {
            return Err(PipelineError::Volume(VolumeError::LayoutMismatch));
        }
        expect = end;
    }
    if expect != bytes.len() {
        return Err(PipelineError::Volume(VolumeError::LayoutMismatch));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };

    fn content(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn upload_then_view_with_loss_across_segments() {
        let data = content(128 * 16 * 2 + 999);
        let up = prepare_public_upload(&data, &SMALL, &Bud3Limits::default(), 24).unwrap();
        assert_eq!(up.segments.len(), 3);
        assert_eq!(up.record.symbol_roots.len(), 3);
        // Lose a third of every segment's symbols.
        let kept = up
            .segments
            .iter()
            .flat_map(|s| s.iter().filter(|x| x.esi % 3 != 0).cloned())
            .collect::<Vec<_>>();
        assert_eq!(view_public(&up.record, kept).unwrap(), data);
    }

    #[test]
    fn view_refuses_tampered_and_missing_symbols() {
        let data = content(3000);
        let up = prepare_public_upload(&data, &SMALL, &Bud3Limits::default(), 20).unwrap();
        // Too few symbols for segment 1.
        let few = up
            .segments
            .iter()
            .flat_map(|s| {
                s.iter()
                    .take(if s[0].segment == 1 { 3 } else { 20 })
                    .cloned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            view_public(&up.record, few),
            Err(PipelineError::SegmentMissing(1))
        );

        // A flipped bit in a source symbol decodes to bytes the commitment
        // refuses.
        let mut bad = up.segments.concat();
        bad[0].data[0] ^= 1;
        assert_eq!(
            view_public(&up.record, bad),
            Err(PipelineError::CommitmentMismatch)
        );

        // A record with another content id refuses correct bytes.
        let mut wrong = up.record.clone();
        wrong.content_id = ContentId::public(b"other");
        wrong.commitment = up.record.commitment;
        assert_eq!(
            view_public(&wrong, up.segments.concat()),
            Err(PipelineError::ContentMismatch)
        );
    }

    #[test]
    fn upload_refuses_limits_and_thin_placements() {
        let limits = Bud3Limits {
            max_content_bytes: 10,
            ..Default::default()
        };
        assert!(matches!(
            prepare_public_upload(&content(11), &SMALL, &limits, 20),
            Err(PipelineError::Limit(_))
        ));
        assert!(matches!(
            prepare_public_upload(&content(3000), &SMALL, &Bud3Limits::default(), 17),
            Err(PipelineError::TooFewSymbols { .. })
        ));
    }

    #[test]
    fn empty_content_round_trips() {
        let up = prepare_public_upload(b"", &SMALL, &Bud3Limits::default(), 4).unwrap();
        assert_eq!(view_public(&up.record, up.segments.concat()).unwrap(), b"");
    }
    use super::super::volume::{Visibility, VolumeError};

    fn small_object(bytes: &[u8]) -> SmallObject {
        SmallObject {
            content_id: ContentId::public(bytes),
            commitment: commit_object(bytes, &SMALL).unwrap(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn bud3_aggregation_volume() {
        let limits = Bud3Limits::default();
        // Two members below one symbol each, together above one symbol, so the
        // volume needs two source symbols and losing symbols costs nothing.
        let first: Vec<u8> = (0..100u8).map(|i| i.wrapping_mul(7)).collect();
        let second: Vec<u8> = (0..96u8).map(|i| i.wrapping_mul(11)).collect();
        let objects = vec![small_object(&first), small_object(&second)];
        let prepared =
            prepare_volume_upload(&objects, Visibility::Public, &SMALL, &limits, 12).unwrap();
        assert_eq!(prepared.volume.members().len(), 2);
        assert_eq!(prepared.record.members, prepared.volume.members());
        assert_eq!(prepared.record.bytes_len, (first.len() + second.len()) as u64);
        // The volume is coded as one segment. Lose a third of its symbols and
        // every member still comes back byte for byte, found by its position
        // and its proof.
        let kept: Vec<Symbol> = prepared
            .symbols
            .iter()
            .filter(|symbol| symbol.esi % 3 != 0)
            .cloned()
            .collect();
        let found = view_volume_member(&prepared.record, kept.clone(), &objects[0].content_id);
        assert_eq!(found.unwrap(), first);
        let found = view_volume_member(&prepared.record, kept, &objects[1].content_id);
        assert_eq!(found.unwrap(), second);
        let rebuilt = view_volume_bytes(&prepared.record, prepared.symbols.clone());
        assert_eq!(rebuilt.unwrap(), prepared.volume.bytes());
        // The member table is the only door: a content id outside it is
        // refused even when the volume itself verifies.
        let absent = ContentId::public(b"absent");
        let refused = view_volume_member(&prepared.record, prepared.symbols.clone(), &absent);
        assert_eq!(refused, Err(PipelineError::Volume(VolumeError::UnknownMember)));
    }

    #[test]
    fn bud3_volume_refuses_a_member_that_is_not_small() {
        let limits = Bud3Limits::default();
        let big = vec![7u8; usize::from(SMALL.symbol_size)];
        let objects = vec![small_object(&big)];
        let large = prepare_volume_upload(&objects, Visibility::Public, &SMALL, &limits, 12);
        assert!(matches!(
            large,
            Err(PipelineError::Volume(VolumeError::NotSmall { .. }))
        ));
        let empty = prepare_volume_upload(&[], Visibility::Public, &SMALL, &limits, 12);
        assert!(matches!(
            empty,
            Err(PipelineError::Volume(VolumeError::EmptyVolume))
        ));
        // The volume is one segment, so the placement must still cover the
        // coder.
        let objects = vec![small_object(b"a"), small_object(b"b")];
        assert!(matches!(
            prepare_volume_upload(&objects, Visibility::Public, &SMALL, &limits, 2),
            Err(PipelineError::TooFewSymbols { .. })
        ));
    }

    #[test]
    fn bud3_volume_view_refuses_tampered_bytes() {
        let limits = Bud3Limits::default();
        let objects = vec![small_object(b"only member")];
        let prepared =
            prepare_volume_upload(&objects, Visibility::Public, &SMALL, &limits, 4).unwrap();

        // Bytes that are not the recorded bytes never pass the volume id.
        let mut record = prepared.record.clone();
        record.volume_id[0] ^= 1;
        let seen = view_volume_bytes(&record, prepared.symbols.clone());
        assert_eq!(seen, Err(PipelineError::Volume(VolumeError::IdMismatch)));

        // The member table must tile the bytes.
        let mut record = prepared.record.clone();
        record.members[0].offset = 1;
        let seen = view_volume_bytes(&record, prepared.symbols.clone());
        assert_eq!(seen, Err(PipelineError::Volume(VolumeError::LayoutMismatch)));

        // The member root binds the table.
        let mut record = prepared.record.clone();
        record.root[0] ^= 1;
        let seen = view_volume_bytes(&record, prepared.symbols.clone());
        assert_eq!(seen, Err(PipelineError::Volume(VolumeError::RootMismatch)));
    }
}
