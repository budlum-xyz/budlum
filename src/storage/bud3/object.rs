//! The B.U.D. 3.0 object: the BOF-1 header over a payload, both paths that
//! produce it, and the commitment that binds the two.
//!
//! An object is not held in memory to be committed. The header is small
//! (at most a couple of hundred bytes), so it is built first, then the
//! payload is streamed through [`SegmentCommit`], which cuts
//! `header_bytes ++ payload` into segments of `k_max x symbol_size` bytes and
//! digests each one as it fills. Memory stays at one segment however large
//! the content is, which is what lets a 16 GiB object be committed on a
//! machine that cannot hold 16 GiB.
//!
//! # Two paths, one object
//!
//! * The logical path writes the object from the encoder: header, then
//!   payload, then the segments of that byte string.
//! * The optical path writes the object from frames that were produced from
//!   the same byte string and read back.
//!
//! [`object_from_symbols`] turns whatever frames arrived back into object
//! bytes, so the two paths can be compared byte for byte (Section 6.4 Y11). The
//! comparison is what the upload gate asks, and it is what the tests in
//! `src/tests/bud3_objects.rs` measure.
//!
//! # Video commitment
//!
//! The commitment is computed from the logical frames (the symbols), never
//! from the bytes that present them. [`video_commitment`] folds the frame
//! digests of each segment with [`fold_frame_digests`] and binds the segment
//! results in order, so an H.264 or PNG byte stream with a different size
//! produces the same value (Section 6.15, BLG-214).
//!
//! # Text form
//!
//! [`Object::to_text`] writes the canonical text form of Section 6.3.3 and
//! [`object_from_text`] reads it back. The text carries the coded frames, not
//! the payload bytes, so a text that decodes to a different commitment is
//! refused. The text form is defined for the plain public object (flags 0);
//! a sealed, live, base-relative or context-bound object is refused rather
//! than written in a form that cannot express it.
//!
//! WIRING: unwired - the upload session (`upload.rs`) is the door that writes
//! objects into the pipeline, and the view session reads them back through
//! `view.rs`. Until those land, this module is exercised by its own tests and
//! by `src/tests/bud3_objects.rs`.

use super::bof1::{self, Bof1Error, CodecId, Header, Object, VERSION};
use super::fountain::{FountainError, SegmentDecoder, SegmentEncoder, Symbol};
use super::limits::Profile;
use super::meter::Meter;
use super::segment::{object_commitment, segment_digest, ObjectCommitment, Segmentation, OBJECT_TAG};
use crate::core::hash::hash_fields_bytes;

/// The frame digest tag: one logical frame (one symbol) of one segment.
pub const FRAME_TAG: &[u8] = b"BDLM_BUD3_FRAME_V1";
/// The video commitment tag: the per-segment frame folds, bound in order.
pub const VIDEO_TAG: &[u8] = b"BDLM_BUD3_VIDEO_V1";
/// The fold tag: one segment's running frame fold.
pub const VIDEO_FOLD_TAG: &[u8] = b"BDLM_BUD3_VIDEO_FOLD_V1";
/// The text form's first line.
pub const TEXT_MAGIC: &str = "BUD3-OBJECT";

/// Why an object path was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectError {
    /// The header or the text form is not canonical.
    Bof1(Bof1Error),
    /// The profile is not usable for segmentation.
    BadProfile,
    /// A length does not fit this platform.
    TooLarge,
    /// The meter refused the bytes.
    Budget(super::meter::MeterError),
    /// A frame carried a symbol the segment cannot use.
    Fountain(FountainError),
    /// A segment did not decode from the frames given.
    SegmentMissing(u64),
    /// The text form is malformed.
    Text(&'static str),
    /// The text form carries flags it cannot express (sealed, live, base or
    /// context bound).
    TextRefusedFlags(u8),
    /// The commitment computed from the input is not the one claimed.
    CommitmentMismatch,
    /// The decoded content does not match the header.
    ContentMismatch,
}

impl From<Bof1Error> for ObjectError {
    fn from(e: Bof1Error) -> Self {
        Self::Bof1(e)
    }
}

impl From<FountainError> for ObjectError {
    fn from(e: FountainError) -> Self {
        Self::Fountain(e)
    }
}

impl From<super::meter::MeterError> for ObjectError {
    fn from(e: super::meter::MeterError) -> Self {
        Self::Budget(e)
    }
}

/// Build the header of a public object.
///
/// The caller has already chosen the codec and produced the payload, so the
/// lengths are known before the object exists.
#[must_use]
pub fn public_header(
    profile: &Profile,
    codec: CodecId,
    content_len: u64,
    content_digest: [u8; 32],
    payload_len: u64,
) -> Header {
    Header {
        flags: bof1::Flags::default(),
        profile: profile.id,
        codec,
        dictionary: 0,
        base: None,
        content_len,
        content_digest,
        payload_len,
        prev_object: None,
        context_manifest: None,
    }
}

/// The header a public object is built from when the text form is read back.
///
/// The text form (Section 6.3.3) carries the profile, the codec, the dictionary,
/// the content length and digest, and the payload length; every other header
/// field is zero for a public object, which is what [`public_header`] writes.
/// The builder refuses a codec that is not registered, because a text form is
/// untrusted input and a codec id it names must be one the node knows.
///
/// # Errors
///
/// [`ObjectError::BadProfile`] for a profile id that is not registered, and
/// [`ObjectError::Text`] for a codec id that is not registered.
pub fn header_from_text_fields(
    profile_id: u16,
    codec: CodecId,
    dictionary: u32,
    content_len: u64,
    content_digest: [u8; 32],
    payload_len: u64,
) -> Result<Header, ObjectError> {
    let profile = Profile::by_id(profile_id).ok_or(ObjectError::BadProfile)?;
    if !bof1::codec_is_registered(codec) {
        return Err(ObjectError::Text("unregistered codec"));
    }
    if !bof1::dictionary_is_registered(dictionary) {
        return Err(ObjectError::Text("unregistered dictionary"));
    }
    Ok(public_header(
        &profile,
        codec,
        content_len,
        content_digest,
        payload_len,
    ))
}

/// The segments of an object, committed while they are produced.
///
/// The caller feeds the encoded header and then the payload. Nothing larger
/// than one segment is held, and the digest list grows with the segment
/// count, not with the content length.
pub struct SegmentCommit {
    seg: Segmentation,
    seg_index: u64,
    buf: Vec<u8>,
    digests: Vec<[u8; 32]>,
    fed: u64,
    capacity: u64,
}

impl SegmentCommit {
    /// A commit for an object of `object_len` bytes under `profile`.
    ///
    /// # Errors
    ///
    /// [`ObjectError::BadProfile`] when the profile does not segment.
    pub fn new(object_len: u64, profile: &Profile) -> Result<Self, ObjectError> {
        let seg = Segmentation::new(object_len, profile).ok_or(ObjectError::BadProfile)?;
        let seg_len = usize::try_from(seg.len(0).ok_or(ObjectError::TooLarge)?)
            .map_err(|_| ObjectError::TooLarge)?;
        Ok(Self {
            seg,
            seg_index: 0,
            buf: Vec::with_capacity(seg_len),
            digests: Vec::new(),
            fed: 0,
            capacity: seg.count(),
        })
    }

    /// Feed the next bytes of the object.
    ///
    /// # Errors
    ///
    /// [`ObjectError::TooLarge`] when more bytes arrive than the object was
    /// declared to hold, and [`ObjectError::Budget`] when the meter refuses a
    /// segment copy.
    pub fn push(&mut self, bytes: &[u8], meter: &mut Meter) -> Result<(), ObjectError> {
        let end = self.fed.saturating_add(bytes.len() as u64);
        if end > self.seg.object_len() {
            return Err(ObjectError::TooLarge);
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            let want = self
                .seg
                .len(self.seg_index)
                .ok_or(ObjectError::TooLarge)?;
            let want = usize::try_from(want).map_err(|_| ObjectError::TooLarge)?;
            let room = want.saturating_sub(self.buf.len());
            if room == 0 {
                self.close_segment(meter)?;
                continue;
            }
            let take = room.min(rest.len());
            let (head, tail) = rest.split_at(take);
            meter.charge_bytes(take as u64)?;
            self.buf.extend_from_slice(head);
            rest = tail;
            self.fed = self.fed.saturating_add(take as u64);
            if self.buf.len() == want {
                self.close_segment(meter)?;
            }
        }
        Ok(())
    }

    /// Digest the segment that just filled and start the next one.
    fn close_segment(&mut self, meter: &mut Meter) -> Result<(), ObjectError> {
        meter.charge_steps(1)?;
        self.digests.push(segment_digest(self.seg_index, &self.buf));
        self.seg_index = self.seg_index.saturating_add(1);
        self.buf.clear();
        if self.seg_index >= self.capacity {
            // A full object that was declared one segment short.
            return Ok(());
        }
        let want = usize::try_from(self.seg.len(self.seg_index).ok_or(ObjectError::TooLarge)?)
            .map_err(|_| ObjectError::TooLarge)?;
        self.buf.reserve(want.saturating_sub(self.buf.capacity()));
        Ok(())
    }

    /// The object commitment, once every byte was fed.
    ///
    /// # Errors
    ///
    /// [`ObjectError::TooLarge`] when fewer bytes were fed than declared, or
    /// `content_len` does not agree with the segmentation: an object that is
    /// not complete has no commitment.
    pub fn finish(mut self) -> Result<ObjectCommitment, ObjectError> {
        if self.fed != self.seg.object_len() {
            return Err(ObjectError::TooLarge);
        }
        // The last segment is committed when it fills. A last segment that is
        // still short is committed here, and a zero-byte object still has the
        // one empty segment the segmentation names.
        if self.digests.len() as u64 < self.capacity {
            self.digests.push(segment_digest(self.seg_index, &self.buf));
        }
        if self.digests.len() as u64 != self.capacity {
            return Err(ObjectError::TooLarge);
        }
        Ok(object_commitment(&self.digests))
    }
}

/// The commitment of an object held as a header and a payload.
///
/// # Errors
///
/// [`ObjectError::BadProfile`] when the header names a profile that does not
/// segment, and [`ObjectError::TooLarge`] when the lengths do not fit.
pub fn object_commitment_of(
    header: &Header,
    payload: &[u8],
) -> Result<ObjectCommitment, ObjectError> {
    let profile = header.profile().ok_or(ObjectError::BadProfile)?;
    let object_len = (header.encoded_len() as u64).saturating_add(payload.len() as u64);
    let mut commit = SegmentCommit::new(object_len, &profile)?;
    let mut meter = Meter::new(u64::MAX, u64::MAX);
    commit.push(&header_bytes(header, payload.len() as u64), &mut meter)?;
    commit.push(payload, &mut meter)?;
    commit.finish()
}

/// The header bytes of an object whose payload is `payload_len` bytes.
///
/// The encoder writes the same bytes as part of the object, so a streaming
/// commit needs them without the payload in hand.
#[must_use]
pub fn header_bytes(header: &Header, payload_len: u64) -> Vec<u8> {
    Object {
        header: *header,
        payload: Vec::new(),
    }
    .header_bytes(payload_len)
}

impl Object {
    /// The canonical header bytes of this object, with `payload_len` in the
    /// payload-length field. Returns the whole encoding when `payload_len`
    /// matches the payload held here.
    #[must_use]
    pub fn header_bytes(&self, payload_len: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header.encoded_len());
        out.extend_from_slice(bof1::MAGIC);
        out.push(VERSION);
        out.push(self.header.flags.bits());
        super::varint::write(&mut out, u64::from(self.header.profile));
        super::varint::write(&mut out, u64::from(self.header.codec));
        super::varint::write(&mut out, u64::from(self.header.dictionary));
        if self.header.flags.has(bof1::Flags::HAS_BASE) {
            out.extend_from_slice(&self.header.base.unwrap_or([0u8; 32]));
        }
        super::varint::write(&mut out, self.header.content_len);
        out.extend_from_slice(&self.header.content_digest);
        super::varint::write(&mut out, payload_len);
        if self.header.flags.has(bof1::Flags::LIVE) {
            out.extend_from_slice(&self.header.prev_object.unwrap_or([0u8; 32]));
        }
        if self.header.flags.has(bof1::Flags::HAS_CONTEXT) {
            out.extend_from_slice(&self.header.context_manifest.unwrap_or([0u8; 32]));
        }
        out
    }
}

/// The digest of one logical frame: its segment, its ESI and its symbol.
#[must_use]
pub fn frame_digest(symbol: &Symbol) -> [u8; 32] {
    hash_fields_bytes(&[
        FRAME_TAG,
        &symbol.segment.to_le_bytes(),
        &symbol.esi.to_le_bytes(),
        &symbol.data,
    ])
}

/// Fold one segment's frame digests, in ESI order, into one value.
///
/// # Errors
///
/// [`ObjectError::Text`] is never returned here; the fold of an empty segment
/// is refused as [`ObjectError::SegmentMissing`] because a segment with no
/// frame carries no content.
pub fn fold_frame_digests(digests: &[[u8; 32]]) -> Result<[u8; 32], ObjectError> {
    let mut acc = hash_fields_bytes(&[VIDEO_FOLD_TAG]);
    if digests.is_empty() {
        return Err(ObjectError::SegmentMissing(0));
    }
    for d in digests {
        acc = hash_fields_bytes(&[VIDEO_FOLD_TAG, &acc, d]);
    }
    Ok(acc)
}

/// The video commitment over the logical frames, grouped by segment.
///
/// Symbol order inside a segment does not matter: the fold sorts by ESI, so a
/// viewer that joined late and holds the frames in another order computes the
/// same commitment.
///
/// # Errors
///
/// [`ObjectError::BadProfile`] when `profile` does not segment, and
/// [`ObjectError::SegmentMissing`] when a segment has no frame.
pub fn video_commitment(symbols: &[Symbol], profile: &Profile) -> Result<[u8; 32], ObjectError> {
    let mut by_segment: std::collections::BTreeMap<u64, Vec<(u32, [u8; 32])>> =
        std::collections::BTreeMap::new();
    for s in symbols {
        by_segment
            .entry(s.segment)
            .or_default()
            .push((s.esi, frame_digest(s)));
    }
    if !profile.is_valid() {
        return Err(ObjectError::BadProfile);
    }
    if by_segment.is_empty() {
        return Err(ObjectError::SegmentMissing(0));
    }
    let first = *by_segment.keys().next().unwrap_or(&0);
    let last = by_segment.keys().next_back().copied().unwrap_or(0);
    if first != 0 {
        return Err(ObjectError::SegmentMissing(0));
    }
    let count = last.saturating_add(1);
    let mut acc = hash_fields_bytes(&[VIDEO_TAG, &count.to_le_bytes()]);
    for index in 0..count {
        let rows = by_segment
            .get(&index)
            .ok_or(ObjectError::SegmentMissing(index))?;
        let mut sorted: Vec<[u8; 32]> = rows.iter().map(|(_, d)| *d).collect();
        sorted.sort_unstable();
        let fold = fold_frame_digests(&sorted)?;
        acc = hash_fields_bytes(&[VIDEO_TAG, &acc, &index.to_le_bytes(), &fold]);
    }
    Ok(acc)
}

/// Cut `object` bytes into connected segments and code each one.
///
/// # Errors
///
/// [`ObjectError::BadProfile`] for a profile that does not segment, and
/// [`ObjectError::Fountain`] when a segment cannot be coded.
pub fn encode_symbols(
    object: &[u8],
    profile: &Profile,
    symbols_per_segment: u32,
) -> Result<Vec<Vec<Symbol>>, ObjectError> {
    let seg = Segmentation::new(object.len() as u64, profile).ok_or(ObjectError::BadProfile)?;
    let mut out = Vec::with_capacity(usize::try_from(seg.count()).unwrap_or(0));
    for index in 0..seg.count() {
        let start = usize::try_from(seg.offset(index).ok_or(ObjectError::TooLarge)?)
            .map_err(|_| ObjectError::TooLarge)?;
        let len =
            usize::try_from(seg.len(index).ok_or(ObjectError::TooLarge)?).map_err(|_| {
                ObjectError::TooLarge
            })?;
        let end = start.checked_add(len).ok_or(ObjectError::TooLarge)?;
        let slice = object.get(start..end).ok_or(ObjectError::TooLarge)?;
        let enc = SegmentEncoder::new(index, slice, profile)?;
        let k = enc.k();
        let mut symbols = enc.source_symbols();
        let repair = symbols_per_segment.saturating_sub(k);
        if repair > 0 {
            symbols.extend(enc.repair_symbols(0, repair)?);
        }
        out.push(symbols);
    }
    Ok(out)
}

/// Write the object bytes back from frames.
///
/// Symbols may arrive in any order, from any holder, duplicated, and with
/// repair symbols mixed in; a malformed symbol is skipped. Every segment must
/// reach `k` independent symbols, so a stream that lost a segment is refused
/// rather than padded.
///
/// # Errors
///
/// [`ObjectError::BadProfile`], [`ObjectError::SegmentMissing`] for a segment
/// that did not decode, and [`ObjectError::TooLarge`] when the length does not
/// fit this platform.
pub fn object_from_symbols(
    symbols: &[Symbol],
    profile: &Profile,
    object_len: u64,
) -> Result<Vec<u8>, ObjectError> {
    let seg = Segmentation::new(object_len, profile).ok_or(ObjectError::BadProfile)?;
    let count = usize::try_from(seg.count()).map_err(|_| ObjectError::TooLarge)?;
    let mut decoders = Vec::with_capacity(count);
    for index in 0..seg.count() {
        let len = seg.len(index).ok_or(ObjectError::TooLarge)?;
        decoders.push(SegmentDecoder::new(index, len, profile)?);
    }
    let mut meter = Meter::new(
        object_len.saturating_mul(4).saturating_add(1 << 20),
        u64::from(object_len).saturating_add(1 << 20),
    );
    for s in symbols {
        let Some(slot) = usize::try_from(s.segment).ok() else {
            continue;
        };
        let Some(dec) = decoders.get_mut(slot) else {
            continue;
        };
        if dec.is_done() {
            continue;
        }
        let _ = dec.push(s.clone(), &mut meter);
    }
    let cap = usize::try_from(object_len).map_err(|_| ObjectError::TooLarge)?;
    let mut object = Vec::with_capacity(cap);
    for (index, dec) in decoders.into_iter().enumerate() {
        let bytes = dec
            .into_bytes()
            .ok_or(ObjectError::SegmentMissing(index as u64))?;
        object.extend_from_slice(&bytes);
    }
    if object.len() as u64 != object_len {
        return Err(ObjectError::TooLarge);
    }
    Ok(object)
}

/// The commitment of an object that arrived as frames, checked against the
/// claims the uploader made.
///
/// # Errors
///
/// Every [`ObjectError`] of [`object_from_symbols`], plus
/// [`ObjectError::CommitmentMismatch`] when the reconstructed bytes commit to
/// something else, and [`ObjectError::ContentMismatch`] when the object's own
/// content does not match its header.
pub fn object_from_frames_checked(
    symbols: &[Symbol],
    profile: &Profile,
    object_len: u64,
    claimed: &ObjectCommitment,
) -> Result<Vec<u8>, ObjectError> {
    let object = object_from_symbols(symbols, profile, object_len)?;
    let mut meter = Meter::for_object(object_len);
    let parsed = Object::decode(&object, &mut meter)?;
    let ours = object_commitment_of(&parsed.header, &parsed.payload)?;
    if &ours != claimed {
        return Err(ObjectError::CommitmentMismatch);
    }
    // The object is public by construction here: a sealed payload would have
    // needed the key, and the key never reaches this path. The content the
    // payload decodes to is checked against the digest the header names, so a
    // codec that produced other bytes is refused rather than stored.
    let content = parsed
        .public_content()
        .map_err(|_| ObjectError::ContentMismatch)?;
    if content.len() as u64 != parsed.header.content_len
        || super::content_id::ContentId::public(&content).digest != parsed.header.content_digest
    {
        return Err(ObjectError::ContentMismatch);
    }
    Ok(object)
}

/// The canonical text form of a public object (Section 6.3.3).
///
/// Frames are grouped eight per profile second at most; the grouping is
/// presentation only and a reader accepts any grouping, because the frame
/// carries its own segment and ESI.
///
/// # Errors
///
/// [`ObjectError::TextRefusedFlags`] for a flag set the text form cannot
/// express, [`ObjectError::BadProfile`] for a profile that does not segment,
/// and [`ObjectError::Fountain`] when a segment cannot be coded.
pub fn object_to_text(
    object: &Object,
    profile: &Profile,
    symbols_per_segment: u32,
) -> Result<String, ObjectError> {
    let flags = object.header.flags.bits();
    if flags != 0 {
        return Err(ObjectError::TextRefusedFlags(flags));
    }
    let bytes = object.encode();
    let segments = encode_symbols(&bytes, profile, symbols_per_segment)?;
    let commitment = object_commitment_of(&object.header, &object.payload)?;
    let mut out = String::new();
    out.push_str(TEXT_MAGIC);
    out.push(' ');
    out.push_str(&VERSION.to_string());
    out.push('\n');
    out.push_str(&format!(
        "profile {} codec {} dictionary {}\n",
        object.header.profile, object.header.codec, object.header.dictionary
    ));
    out.push_str(&format!(
        "content len={} digest={}\n",
        object.header.content_len,
        hex::encode(object.header.content_digest)
    ));
    out.push_str(&format!("payload len={}\n", object.payload.len()));
    let fps = usize::from(profile.fps.max(1));
    let seg = Segmentation::new(bytes.len() as u64, profile).ok_or(ObjectError::BadProfile)?;
    let mut flat: Vec<&Symbol> = Vec::new();
    for group in &segments {
        for s in group {
            flat.push(s);
        }
    }
    for (index, symbol) in flat.iter().enumerate() {
        if index % fps == 0 {
            out.push_str(&format!("second {}\n", index / fps));
        }
        // A source frame is one whose ESI is below its segment's k; anything
        // else is a repair frame. The classification comes from the
        // segmentation, not from the request, so a caller that asks for no
        // repair frames and one that asks for many write the same S lines.
        let k = u32::try_from(seg.source_symbols(symbol.segment).unwrap_or(0))
            .map_err(|_| ObjectError::TooLarge)?;
        let kind = if symbol.esi < k { 'S' } else { 'R' };
        out.push(' ');
        out.push(kind);
        out.push(' ');
        out.push_str(&symbol.segment.to_string());
        out.push(' ');
        out.push_str(&symbol.esi.to_string());
        out.push(' ');
        if kind == 'S' {
            out.push_str(&b64url_encode(&symbol.data));
        } else {
            out.push_str("derived");
        }
        out.push('\n');
    }
    out.push_str(&format!("end commitment={}\n", hex::encode(commitment)));
    Ok(out)
}

/// What one line of the text form said about a frame.
///
/// The reader keeps the frame's identity and, for a source frame, its bytes;
/// a repair frame names no bytes and is recorded as [`TextFrame::Repair`] so
/// the reader can check that the object still decodes without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextFrame {
    /// A source frame: its symbol, with the bytes it carries.
    Source(Symbol),
    /// A repair frame: the segment and ESI it names, no bytes.
    Repair {
        /// The segment.
        segment: u64,
        /// The ESI.
        esi: u32,
    },
}

impl TextFrame {
    /// The segment the frame belongs to.
    #[must_use]
    pub const fn segment(&self) -> u64 {
        match self {
            Self::Source(symbol) => symbol.segment,
            Self::Repair { segment, .. } => *segment,
        }
    }

    /// The ESI of the frame.
    #[must_use]
    pub const fn esi(&self) -> u32 {
        match self {
            Self::Source(symbol) => symbol.esi,
            Self::Repair { esi, .. } => *esi,
        }
    }
}

/// The text form, read but not yet decoded into object bytes.
///
/// Reading and decoding are separate steps because the text form names the
/// object's header before it names any frame: the reader needs the header to
/// know how long the object is, and the decoder charges a meter for every
/// symbol it is asked to hold. A caller that only wants the header (an
/// inspector, a record check) reads the form and stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextForm {
    /// The profile id the form names.
    pub profile_id: u16,
    /// The codec id the form names.
    pub codec: CodecId,
    /// The dictionary index the form names.
    pub dictionary: u32,
    /// Content length.
    pub content_len: u64,
    /// Content digest.
    pub content_digest: [u8; 32],
    /// Payload length.
    pub payload_len: u64,
    /// The frames, in the order the form wrote them.
    pub frames: Vec<TextFrame>,
    /// The commitment the `end` line claims.
    pub commitment: [u8; 32],
}

impl TextForm {
    /// The header the form describes.
    ///
    /// # Errors
    ///
    /// [`ObjectError::BadProfile`] or [`ObjectError::Text`] from
    /// [`header_from_text_fields`].
    pub fn header(&self) -> Result<Header, ObjectError> {
        header_from_text_fields(
            self.profile_id,
            self.codec,
            self.dictionary,
            self.content_len,
            self.content_digest,
            self.payload_len,
        )
    }

    /// The object length the form describes: the header plus the payload.
    ///
    /// # Errors
    ///
    /// [`ObjectError`] from [`TextForm::header`].
    pub fn object_len(&self) -> Result<u64, ObjectError> {
        let header = self.header()?;
        Ok(u64::try_from(header.encoded_len())
            .unwrap_or(u64::MAX)
            .saturating_add(self.payload_len))
    }

    /// The source frames, in form order.
    #[must_use]
    pub fn source_frames(&self) -> Vec<Symbol> {
        self.frames
            .iter()
            .filter_map(|frame| match frame {
                TextFrame::Source(symbol) => Some(symbol.clone()),
                TextFrame::Repair { .. } => None,
            })
            .collect()
    }
}

/// Read the canonical text form: every line is checked, every length is
/// bounded, and a grouping that names a frame out of order is refused.
///
/// The meter is charged for each symbol body the form carries, so a form with
/// a million frames cannot be read for the cost of its first line.
///
/// # Errors
///
/// [`ObjectError::Text`] for a malformed line, an unknown keyword, an
/// unregistered codec, or a grouping that is out of order, and
/// [`ObjectError::Budget`] when the meter refuses a body.
pub fn text_form(text: &str, meter: &mut Meter) -> Result<TextForm, ObjectError> {
    let mut lines = text.lines();
    let first = lines.next().ok_or(ObjectError::Text("empty"))?;
    let mut head = first.split(' ');
    if head.next() != Some(TEXT_MAGIC) {
        return Err(ObjectError::Text("magic"));
    }
    match head.next() {
        Some(v) if v == VERSION.to_string() => {}
        _ => return Err(ObjectError::Text("version")),
    }
    if head.next().is_some() {
        return Err(ObjectError::Text("magic line trailing field"));
    }
    let mut profile_id: Option<u16> = None;
    let mut codec: Option<CodecId> = None;
    let mut dictionary: Option<u32> = None;
    let mut content_len: Option<u64> = None;
    let mut content_digest: Option<[u8; 32]> = None;
    let mut payload_len: Option<u64> = None;
    let mut commitment: Option<[u8; 32]> = None;
    let mut frames: Vec<TextFrame> = Vec::new();
    let mut second: Option<u64> = None;
    let mut frames_in_second = 0u64;
    let mut ended = false;
    for line in lines {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        if ended {
            return Err(ObjectError::Text("bytes after the end line"));
        }
        if line == "end" || line.starts_with("end ") {
            let Some(hex_text) = line.split_once("commitment=").map(|(_, h)| h.trim()) else {
                return Err(ObjectError::Text("end without a commitment"));
            };
            commitment = Some(decode32(hex_text).ok_or(ObjectError::Text("commitment hex"))?);
            ended = true;
            continue;
        }
        let mut fields = line.split(' ');
        let key = fields.next().ok_or(ObjectError::Text("empty line"))?;
        match key {
            "profile" => {
                let (Some(p), Some(c), Some(d)) = (fields.next(), fields.next(), fields.next())
                else {
                    return Err(ObjectError::Text("profile line"));
                };
                if fields.next().is_some() {
                    return Err(ObjectError::Text("profile trailing field"));
                }
                profile_id = Some(
                    p.parse()
                        .map_err(|_| ObjectError::Text("profile number"))?,
                );
                codec = Some(
                    c.parse()
                        .map_err(|_| ObjectError::Text("codec number"))?,
                );
                dictionary = Some(
                    d.parse()
                        .map_err(|_| ObjectError::Text("dictionary number"))?,
                );
            }
            "content" => {
                for field in fields {
                    if let Some(v) = field.strip_prefix("len=") {
                        content_len = Some(v.parse().map_err(|_| ObjectError::Text("len"))?);
                    } else if let Some(v) = field.strip_prefix("digest=") {
                        content_digest = Some(decode32(v).ok_or(ObjectError::Text("digest hex"))?);
                    } else {
                        return Err(ObjectError::Text("content field"));
                    }
                }
            }
            "payload" => {
                let Some(v) = fields.next() else {
                    return Err(ObjectError::Text("payload line"));
                };
                let Some(len) = v.strip_prefix("len=") else {
                    return Err(ObjectError::Text("payload field"));
                };
                if fields.next().is_some() {
                    return Err(ObjectError::Text("payload trailing field"));
                }
                payload_len = Some(len.parse().map_err(|_| ObjectError::Text("len"))?);
            }
            "second" => {
                let n: u64 = fields
                    .next()
                    .ok_or(ObjectError::Text("second number"))?
                    .parse()
                    .map_err(|_| ObjectError::Text("second number"))?;
                if fields.next().is_some() {
                    return Err(ObjectError::Text("second trailing field"));
                }
                let expect = second.map_or(0, |s| s.saturating_add(1));
                if n != expect {
                    return Err(ObjectError::Text("second order"));
                }
                if second.is_some() && frames_in_second == 0 {
                    return Err(ObjectError::Text("empty second"));
                }
                second = Some(n);
                frames_in_second = 0;
            }
            "S" | "R" => {
                if second.is_none() {
                    return Err(ObjectError::Text("frame before second"));
                }
                let segment: u64 = fields
                    .next()
                    .ok_or(ObjectError::Text("frame segment"))?
                    .parse()
                    .map_err(|_| ObjectError::Text("frame segment"))?;
                let esi: u32 = fields
                    .next()
                    .ok_or(ObjectError::Text("frame esi"))?
                    .parse()
                    .map_err(|_| ObjectError::Text("frame esi"))?;
                let body = fields.next().ok_or(ObjectError::Text("frame body"))?;
                if fields.next().is_some() {
                    return Err(ObjectError::Text("frame trailing field"));
                }
                frames_in_second = frames_in_second.saturating_add(1);
                if key == "S" {
                    let data = b64url_decode(body).ok_or(ObjectError::Text("frame base64"))?;
                    meter.charge_bytes(data.len() as u64)?;
                    meter.charge_steps(1)?;
                    frames.push(TextFrame::Source(Symbol {
                        segment,
                        esi,
                        data,
                    }));
                } else {
                    if body != "derived" {
                        return Err(ObjectError::Text("repair frame carries a payload"));
                    }
                    frames.push(TextFrame::Repair { segment, esi });
                }
            }
            _ => return Err(ObjectError::Text("unknown keyword")),
        }
    }
    let Some(profile_id) = profile_id else {
        return Err(ObjectError::Text("no profile line"));
    };
    let Some(codec) = codec else {
        return Err(ObjectError::Text("no codec"));
    };
    let Some(dictionary) = dictionary else {
        return Err(ObjectError::Text("no dictionary"));
    };
    let content_len = content_len.ok_or(ObjectError::Text("no content length"))?;
    let content_digest = content_digest.ok_or(ObjectError::Text("no content digest"))?;
    let payload_len = payload_len.ok_or(ObjectError::Text("no payload length"))?;
    let commitment = commitment.ok_or(ObjectError::Text("no commitment"))?;
    if frames.is_empty() {
        return Err(ObjectError::Text("no frames"));
    }
    Ok(TextForm {
        profile_id,
        codec,
        dictionary,
        content_len,
        content_digest,
        payload_len,
        frames,
        commitment,
    })
}

/// Read the canonical text form back into object bytes.
///
/// The frames are decoded under `profile` and the result is checked against
/// the commitment the `end` line claims and against the object's own header:
/// a form whose frames write a different object is refused rather than
/// returned, because the commitment is what a record quotes.
///
/// # Errors
///
/// [`ObjectError::Text`] from [`text_form`], [`ObjectError::BadProfile`] when
/// `profile` does not segment the object the form describes,
/// [`ObjectError::SegmentMissing`] for a segment that did not decode, and
/// [`ObjectError::CommitmentMismatch`] when the bytes do not commit to the
/// claimed value.
pub fn object_from_text(
    text: &str,
    profile: &Profile,
    meter: &mut Meter,
) -> Result<Vec<u8>, ObjectError> {
    let form = text_form(text, meter)?;
    let object_len = form.object_len()?;
    let symbols = form.source_frames();
    let object = object_from_symbols(&symbols, profile, object_len)?;
    let mut parse_meter = Meter::for_object(object_len);
    let parsed = Object::decode(&object, &mut parse_meter)?;
    let ours = object_commitment_of(&parsed.header, &parsed.payload)?;
    if ours != form.commitment {
        return Err(ObjectError::CommitmentMismatch);
    }
    if parsed.header.content_len != form.content_len
        || parsed.header.content_digest != form.content_digest
        || parsed.header.payload_len != form.payload_len
        || parsed.header.codec != form.codec
        || parsed.header.dictionary != form.dictionary
    {
        return Err(ObjectError::ContentMismatch);
    }
    Ok(object)
}

/// The bound commitment of an object, for a caller that only has the record.
///
/// The object commitment is the only identity the chain carries for the
/// bytes; the content id is the identity of the content. Keeping the two
/// apart is what lets a better codec replace the object under the same
/// content id.
#[must_use]
pub fn commitment_tag() -> &'static [u8] {
    OBJECT_TAG
}

fn decode32(hex_text: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_text).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding, integers only.
#[must_use]
pub fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk.first().copied().unwrap_or(0));
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        let digits = [
            (n >> 18) & 0x3f,
            (n >> 12) & 0x3f,
            (n >> 6) & 0x3f,
            n & 0x3f,
        ];
        let take = chunk.len() + 1;
        for (i, d) in digits.iter().enumerate().take(take) {
            let ch = B64_ALPHABET
                .get(*d as usize)
                .copied()
                .unwrap_or(b'A');
            out.push(char::from(ch));
        }
    }
    out
}

/// Decode base64url without padding. `None` for a character outside the
/// alphabet or a length that is not a whole number of bytes.
#[must_use]
pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(text.len() * 3 / 4 + 1);
    for ch in text.chars() {
        let value = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '-' => 62,
            '_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // The remaining bits must be zero padding: a non-zero tail is a malformed
    // encoding, not a shorter value.
    if bits >= 6 {
        return None;
    }
    if acc & ((1u32 << bits) - 1) != 0 && bits > 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 64,
        fps: 4,
        k_max: 8,
    };

    fn content(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 13 % 251) as u8).collect()
    }

    #[test]
    fn header_len_matches_the_encoder() {
        let object = Object::raw_public(b"abc");
        assert_eq!(object.header.encoded_len(), object.header_bytes(3).len());
        let bytes = object.encode();
        assert_eq!(&bytes[..object.header.encoded_len()], &object.header_bytes(3)[..]);
    }

    #[test]
    fn segment_commit_streams_in_any_chunking() {
        let object = Object::raw_public(&content(500));
        let bytes = object.encode();
        let want = object_commitment_of(&object.header, &object.payload).unwrap();
        for chunk in [1usize, 7, 64, 500] {
            let mut commit = SegmentCommit::new(bytes.len() as u64, &SMALL).unwrap();
            let mut meter = Meter::new(u64::MAX, u64::MAX);
            for piece in bytes.chunks(chunk) {
                commit.push(piece, &mut meter).unwrap();
            }
            assert_eq!(commit.finish().unwrap(), want, "chunk {chunk}");
        }
    }

    #[test]
    fn video_commitment_ignores_frame_order() {
        let object = Object::raw_public(&content(300));
        let mut symbols: Vec<Symbol> = encode_symbols(&object.encode(), &SMALL, 12)
            .unwrap()
            .into_iter()
            .flatten()
            .collect();
        let first = video_commitment(&symbols, &SMALL).unwrap();
        symbols.reverse();
        assert_eq!(video_commitment(&symbols, &SMALL).unwrap(), first);
    }
}
