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

use super::bof1::{Bof1Error, CodecId, Object};
use super::content_id::ContentId;
use super::custody::{symbol_leaf, symbol_root};
use super::fountain::{FountainError, SegmentDecoder, SegmentEncoder, Symbol};
use super::limits::{Bud3Limits, LimitError, Profile};
use super::meter::Meter;
use super::segment::{commit_object, Segmentation};

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
    /// Two-path optical extraction or verification failed.
    TwoPath(super::two_path::TwoPathError),
    /// Sealed object encryption/decryption or Padme framing failed.
    Seal(super::seal::SealBud3Error),
    /// The object does not fit this platform.
    TooLarge,
}

impl From<super::seal::SealBud3Error> for PipelineError {
    fn from(e: super::seal::SealBud3Error) -> Self {
        Self::Seal(e)
    }
}

impl From<super::two_path::TwoPathError> for PipelineError {
    fn from(e: super::two_path::TwoPathError) -> Self {
        Self::TwoPath(e)
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

/// Convenience: prepare public content through the full optical two-path and
/// round-trip gates (Y10, Y11, Y12), ensuring the registered `ObjectRecord`
/// comes from the QR-extracted object bytes.
///
/// # Errors
///
/// Returns [`PipelineError`] if limits, coding, or two-path verification fails.
pub fn prepare_public_upload_two_path(
    content: &[u8],
    profile: &Profile,
    limits: &Bud3Limits,
    symbols_per_segment: u32,
) -> Result<(PreparedUpload, [u8; 32]), PipelineError> {
    limits
        .admit_content(content.len() as u64)
        .map_err(PipelineError::Limit)?;
    let selected = bud_codec::select(content);
    let candidate = Object::public_coded(selected.codec, selected.payload, content)?;
    let verified =
        super::two_path::verify_upload_two_path_and_round_trip(&candidate, profile, 2)?;
    let up = prepare_public_upload(content, profile, limits, symbols_per_segment)?;
    if commit_object(&verified.object.encode(), profile) != Some(up.record.commitment) {
        return Err(PipelineError::CommitmentMismatch);
    }
    Ok((up, verified.video_commitment))
}

/// Convenience: G5 optical view path verified against `record`.
///
/// # Errors
///
/// Returns [`PipelineError`] if pixel QR decoding or content check fails.
pub fn view_public_optical(
    record: &ObjectRecord,
    seconds: &[super::qr::OpticalSecond],
) -> Result<Vec<u8>, PipelineError> {
    let mut meter = Meter::for_object(record.object_len.saturating_mul(8).saturating_add(1 << 20));
    let content = super::two_path::decode_optical_path(seconds, &mut meter)?;
    if !record.content_id.matches_public(&content) {
        return Err(PipelineError::ContentMismatch);
    }
    Ok(content)
}

/// Prepare sealed content (`Flags::SEALED`, Padme-padded `XChaCha20Poly1305`,
/// `content_len = 0`, `codec = CODEC_RAW`) for upload.
///
/// # Errors
///
/// [`PipelineError`] for a refused length, sealing failure, or coding error.
pub fn prepare_sealed_upload(
    content: &[u8],
    content_key: &super::content_id::ContentKey,
    salt: [u8; super::seal::SEAL_SALT_LEN],
    profile: &Profile,
    limits: &Bud3Limits,
    symbols_per_segment: u32,
) -> Result<PreparedUpload, PipelineError> {
    limits
        .admit_content(content.len() as u64)
        .map_err(PipelineError::Limit)?;
    let object = super::seal::seal_object(content, content_key, salt)?;
    let content_id = ContentId {
        kind: super::content_id::ContentIdKind::Sealed,
        digest: object.header.content_digest,
        len: 0,
    };
    let codec = object.header.codec;
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
            content_id,
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

/// Rebuild and decrypt sealed content from symbols using an authorized
/// `ContentKey` (obtained by the owner or via an active HPKE X-Wing view grant).
///
/// # Errors
///
/// [`PipelineError`] when segments fail to decode, the commitment mismatches,
/// or AEAD / keyed `ContentId` verification fails.
pub fn view_sealed<I>(
    record: &ObjectRecord,
    content_key: &super::content_id::ContentKey,
    symbols: I,
) -> Result<Vec<u8>, PipelineError>
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
    if parsed.header.codec != record.codec
        || record.content_id.kind != super::content_id::ContentIdKind::Sealed
        || parsed.header.content_digest != record.content_id.digest
    {
        return Err(PipelineError::ContentMismatch);
    }
    let plaintext = super::seal::open_sealed_object(
        &parsed,
        content_key,
        &mut Meter::for_object(record.object_len.saturating_mul(8).saturating_add(1 << 20)),
    )?;
    Ok(plaintext)
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

    #[test]
    fn bud3_sealed_needs_grant() {
        let owner_key = super::super::keys::derive_object_content_key(&[0x55; 32], 1);
        let wrong_key = super::super::keys::derive_object_content_key(&[0x55; 32], 2);
        let secret = b"sealed B.U.D. 3.0 payload requiring active grant key";
        let up = prepare_sealed_upload(
            secret,
            &owner_key,
            [0x19; super::super::seal::SEAL_SALT_LEN],
            &SMALL,
            &Bud3Limits::default(),
            10,
        )
        .unwrap();
        // Public view refuses sealed content; wrong key fails AEAD / keyed ContentId.
        assert!(view_public(&up.record, up.segments.concat()).is_err());
        assert!(view_sealed(&up.record, &wrong_key, up.segments.concat()).is_err());
        // Authorized grant / owner key recovers exact plaintext.
        assert_eq!(
            view_sealed(&up.record, &owner_key, up.segments.concat()).unwrap(),
            secret
        );
    }
}
