//! Independent verifier for the A3, A2 and A1 layers of a QR video.
//!
//! `verify_qr_video` decodes a video with `decode_qr_video`. This module reads
//! the same optical frames again with its own code and only confirms the
//! first result. It never returns content: its answer is `Ok(())` or an error.
//!
//! # What is independent
//!
//! - A3: the frame header (18 bytes), its digest and the stream prefix.
//! - A2: the drop header (24 bytes), the counter-PRNG row choice and a GF(2)
//!   elimination. The elimination is written here and is not the carousel
//!   decoder.
//! - A1: the container header (47 bytes), the length rules, the empty rule and
//!   the SHA-256 of the content.
//!
//! The layouts below are written from the wire specification in the module
//! docs of `qr_frame`, `qr_carousel` and `qr_payload`. Nothing in this file
//! imports a parser, a decoder or a constant from those modules. The tests
//! tie each copied constant to the original.
//!
//! # What is shared
//!
//! - The QR symbol layer (`rqrr`) and the PNG reader. This module starts from
//!   the optical frames that layer produces, so a fault there reaches both
//!   paths. It is not covered by this check.
//! - The hash and compression crates (`sha2`, `flate2`).
//!
//! # Extra checks
//!
//! The stream commitment is recomputed from the rebuilt A1 bytes and the
//! carousel parameters, and the result must match the one the video carries.
//! The kind tag and the content hash must match what the primary path found.
//!
//! WIRING: `storage::qr_verify::verify_qr_video` calls [`confirm`] after the
//! primary decode and the commitment checks.

use flate2::read::ZlibDecoder;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;

const FRAME_MAGIC: [u8; 2] = [0xBD, 0x3A];
const FRAME_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 18;
const FRAME_TAG: &[u8] = b"BDLM_THREE_QR_FRAME_V1";

const DROP_MAGIC: [u8; 4] = *b"BDLD";
const DROP_VERSION: u8 = 1;
const DROP_HEADER_LEN: usize = 24;
const PRNG_TAG: &[u8] = b"BDLM_CAROUSEL_PRNG_V1";
const CAROUSEL_TAG: &[u8] = b"BDLM_THREE_CAROUSEL_V1";

const MAX_K: u16 = 4096;
const MAX_DROP_WIRE: usize = 8 * 1024;
const MAX_BLOCK_LEN: usize = MAX_DROP_WIRE - DROP_HEADER_LEN;
const MAX_BYTES: usize = 64 * 1024 * 1024;
/// The receiver never needs more distinct seqs than two carousel cycles.
const MAX_SEQS: usize = 2 * MAX_K as usize;

const A1_MAGIC: [u8; 4] = *b"BDL3";
const A1_VERSION: u8 = 1;
const A1_HEADER_LEN: usize = 47;
const A1_TAG: &[u8] = b"BDLM_THREE_PAYLOAD_V1";
const A1_FLAG_ZLIB: u8 = 1;
const A1_FLAG_EMPTY: u8 = 2;

/// What the primary path found. The verifier confirms it and returns nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimaryClaim {
    /// Wire tag of the payload kind the primary path decoded.
    pub kind_tag: u8,
    /// SHA-256 of the body the primary path decoded.
    pub content_sha256: [u8; 32],
}

/// Why the independent path refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndepError {
    /// No optical frames.
    NoFrames,
    /// One frame is not valid. The text names the broken rule.
    Frame {
        /// Position of the frame in the video.
        index: usize,
        /// The rule that failed.
        fault: &'static str,
    },
    /// Two drops carry other stream parameters.
    ParamMismatch,
    /// The parameters are not what the encoder produces.
    BadParams,
    /// Two frames carry the same seq and different bodies.
    ConflictingSeq(u32),
    /// More distinct seqs than a carousel can need.
    TooManySeqs,
    /// A repair row contradicts the other rows.
    Inconsistent,
    /// The frames do not span all source blocks.
    Incomplete {
        /// Rank reached.
        rank: usize,
        /// Source blocks needed.
        k: usize,
    },
    /// The stream commitment is not the one the rebuilt bytes give.
    StreamCommitment,
    /// The A1 container is not valid. The text names the broken rule.
    Container(&'static str),
    /// The kind tag differs from the primary result.
    KindDisagrees {
        /// Tag the primary path found.
        primary: u8,
        /// Tag in the A1 header.
        independent: u8,
    },
    /// The content hash differs from the primary result.
    ContentDisagrees,
}

impl std::fmt::Display for IndepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFrames => write!(f, "independent check: no frames"),
            Self::Frame { index, fault } => {
                write!(f, "independent check: frame {index}: {fault}")
            }
            Self::ParamMismatch => write!(f, "independent check: drops disagree on parameters"),
            Self::BadParams => write!(f, "independent check: stream parameters are not valid"),
            Self::ConflictingSeq(s) => write!(f, "independent check: seq {s} has two bodies"),
            Self::TooManySeqs => write!(f, "independent check: too many distinct seqs"),
            Self::Inconsistent => write!(f, "independent check: rows contradict each other"),
            Self::Incomplete { rank, k } => {
                write!(f, "independent check: rank {rank} of {k}")
            }
            Self::StreamCommitment => {
                write!(f, "independent check: stream commitment does not match")
            }
            Self::Container(why) => write!(f, "independent check: container: {why}"),
            Self::KindDisagrees {
                primary,
                independent,
            } => write!(
                f,
                "independent check: kind {independent}, primary path {primary}"
            ),
            Self::ContentDisagrees => {
                write!(
                    f,
                    "independent check: content hash differs from primary path"
                )
            }
        }
    }
}

impl std::error::Error for IndepError {}

/// Rebuild the content from the optical frames with this module's own code
/// and confirm the primary result.
///
/// # Errors
///
/// [`IndepError`] for the first rule that fails, or when the rebuilt kind tag
/// or content hash differs from `claim`.
pub fn confirm(
    stream_commitment: &[u8; 32],
    frames: &[Vec<u8>],
    claim: &PrimaryClaim,
) -> Result<(), IndepError> {
    let found = reconstruct(stream_commitment, frames)?;
    if found.kind_tag != claim.kind_tag {
        return Err(IndepError::KindDisagrees {
            primary: claim.kind_tag,
            independent: found.kind_tag,
        });
    }
    if found.content_sha256 != claim.content_sha256 {
        return Err(IndepError::ContentDisagrees);
    }
    Ok(())
}

fn fields_hash(fields: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for field in fields {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field);
    }
    h.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Found {
    kind_tag: u8,
    content_sha256: [u8; 32],
}

fn reconstruct(stream_commitment: &[u8; 32], frames: &[Vec<u8>]) -> Result<Found, IndepError> {
    if frames.is_empty() {
        return Err(IndepError::NoFrames);
    }
    let mut params: Option<Params> = None;
    let mut basis: Option<Basis> = None;
    let mut seen: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for (index, frame) in frames.iter().enumerate() {
        let drop = parse_frame(stream_commitment, frame)
            .map_err(|fault| IndepError::Frame { index, fault })?;
        match params {
            None => {
                let p = Params {
                    k: drop.k,
                    block_len: drop.block_len,
                    total_len: drop.total_len,
                };
                basis = Some(Basis::new(&p));
                params = Some(p);
            }
            Some(p) if p != drop.params() => return Err(IndepError::ParamMismatch),
            Some(_) => {}
        }
        if let Some(prev) = seen.get(&drop.seq) {
            if *prev == drop.body {
                continue;
            }
            return Err(IndepError::ConflictingSeq(drop.seq));
        }
        if seen.len() >= MAX_SEQS {
            return Err(IndepError::TooManySeqs);
        }
        let p = params.ok_or(IndepError::NoFrames)?;
        let b = basis.as_mut().ok_or(IndepError::NoFrames)?;
        let cols = row_columns(&drop, &p).map_err(|fault| IndepError::Frame { index, fault })?;
        seen.insert(drop.seq, drop.body.clone());
        b.add(&cols, drop.body)?;
        if b.rank == b.k {
            break;
        }
    }
    let p = params.ok_or(IndepError::NoFrames)?;
    let b = basis.ok_or(IndepError::NoFrames)?;
    if b.rank != b.k {
        return Err(IndepError::Incomplete {
            rank: b.rank,
            k: b.k,
        });
    }
    let mut packed = b.solve()?;
    packed.truncate(usize::try_from(p.total_len).map_err(|_| IndepError::BadParams)?);
    let payload_commitment = fields_hash(&[A1_TAG, &packed]);
    let derived = fields_hash(&[
        CAROUSEL_TAG,
        &payload_commitment,
        &p.k.to_le_bytes(),
        &p.block_len.to_le_bytes(),
        &p.total_len.to_le_bytes(),
    ]);
    if derived != *stream_commitment {
        return Err(IndepError::StreamCommitment);
    }
    read_container(&packed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Params {
    k: u16,
    block_len: u16,
    total_len: u32,
}

struct RawDrop {
    seq: u32,
    k: u16,
    block_len: u16,
    total_len: u32,
    degree: u8,
    body: Vec<u8>,
}

impl RawDrop {
    const fn params(&self) -> Params {
        Params {
            k: self.k,
            block_len: self.block_len,
            total_len: self.total_len,
        }
    }
}

fn le_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes(<[u8; 2]>::try_from(s).ok()?))
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes(<[u8; 4]>::try_from(s).ok()?))
}

fn le_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes(<[u8; 8]>::try_from(s).ok()?))
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut h = 0x811c_9dc5_u32;
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn parse_frame(stream: &[u8; 32], frame: &[u8]) -> Result<RawDrop, &'static str> {
    if frame.len() < FRAME_HEADER_LEN {
        return Err("frame shorter than header");
    }
    if frame.get(0..2) != Some(FRAME_MAGIC.as_slice()) {
        return Err("frame magic");
    }
    if frame.get(2).copied() != Some(FRAME_VERSION) {
        return Err("frame version");
    }
    if frame.get(3).copied().unwrap_or(0xff) & 0x0f != 0 {
        return Err("frame must-understand flags");
    }
    let seq = le_u32(frame, 4).ok_or("frame seq")?;
    if le_u32(frame, 8) != le_u32(stream, 0) {
        return Err("frame stream prefix");
    }
    let wire_len = usize::from(le_u16(frame, 12).ok_or("frame drop length")?);
    if wire_len == 0 || wire_len > MAX_DROP_WIRE {
        return Err("frame drop length range");
    }
    let wire = frame
        .get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + wire_len)
        .ok_or("frame shorter than drop length")?;
    let digest = fields_hash(&[FRAME_TAG, stream, &seq.to_le_bytes(), wire]);
    if frame.get(14..18) != digest.get(..4) {
        return Err("frame digest");
    }
    parse_drop(wire, seq)
}

fn parse_drop(wire: &[u8], frame_seq: u32) -> Result<RawDrop, &'static str> {
    if wire.len() < DROP_HEADER_LEN {
        return Err("drop shorter than header");
    }
    if wire.get(0..4) != Some(DROP_MAGIC.as_slice()) {
        return Err("drop magic");
    }
    if wire.get(4).copied() != Some(DROP_VERSION) {
        return Err("drop version");
    }
    let seq = le_u32(wire, 6).ok_or("drop seq")?;
    let k = le_u16(wire, 10).ok_or("drop k")?;
    let block_len = le_u16(wire, 12).ok_or("drop block length")?;
    let total_len = le_u32(wire, 14).ok_or("drop total length")?;
    let degree = wire.get(18).copied().ok_or("drop degree")?;
    let body_hash = le_u32(wire, 20).ok_or("drop body hash")?;
    let body = wire.get(DROP_HEADER_LEN..).ok_or("drop body")?;
    if seq != frame_seq {
        return Err("drop seq differs from frame seq");
    }
    if block_len == 0 || usize::from(block_len) > MAX_BLOCK_LEN {
        return Err("drop block length range");
    }
    if k == 0 || k > MAX_K {
        return Err("drop k range");
    }
    let total = usize::try_from(total_len).map_err(|_| "drop total length")?;
    if total == 0 || total > MAX_BYTES {
        return Err("drop total length range");
    }
    if body.len() != usize::from(block_len) {
        return Err("drop body length");
    }
    if fnv1a(body) != body_hash {
        return Err("drop body hash");
    }
    if degree == 0 || u16::from(degree) > k {
        return Err("drop degree range");
    }
    // The encoder cuts the payload into exactly this many blocks.
    if total.div_ceil(usize::from(block_len)) != usize::from(k) {
        return Err("drop k does not fit total length");
    }
    Ok(RawDrop {
        seq,
        k,
        block_len,
        total_len,
        degree,
        body: body.to_vec(),
    })
}

/// Source blocks that the body of this drop is the XOR of.
///
/// Positions `0..k` of each `2k` cycle are systematic (one block). The rest
/// are repair rows drawn from a SHA-256 counter stream seeded by the seq.
fn row_columns(drop: &RawDrop, p: &Params) -> Result<Vec<usize>, &'static str> {
    let k = u32::from(p.k);
    let pos = drop.seq % (2 * k);
    if pos < k {
        if drop.degree != 1 {
            return Err("systematic drop with degree other than 1");
        }
        return Ok(vec![usize::try_from(pos).map_err(|_| "position")?]);
    }
    let k_usize = usize::from(p.k);
    let mut prng = Prng::new(drop.seq);
    let want = 1 + usize::try_from(prng.next() % k).map_err(|_| "degree")?;
    let mut pool: Vec<usize> = (0..k_usize).collect();
    let mut cols = Vec::with_capacity(want);
    for i in 0..want {
        let remain = u32::try_from(k_usize - i).map_err(|_| "pool")?;
        let j = i + usize::try_from(prng.next() % remain).map_err(|_| "pool")?;
        pool.swap(i, j);
        cols.push(*pool.get(i).ok_or("pool")?);
    }
    if u8::try_from(cols.len()).unwrap_or(u8::MAX) != drop.degree {
        return Err("repair drop degree");
    }
    Ok(cols)
}

struct Prng {
    seed: u32,
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl Prng {
    fn new(seed: u32) -> Self {
        let mut p = Self {
            seed,
            counter: 0,
            block: [0; 32],
            used: 32,
        };
        p.refill();
        p
    }

    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(PRNG_TAG);
        h.update(self.seed.to_le_bytes());
        h.update(self.counter.to_le_bytes());
        self.block = h.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }

    fn next(&mut self) -> u32 {
        if self.used + 4 > 32 {
            self.refill();
        }
        let v = le_u32(&self.block, self.used).unwrap_or(0);
        self.used += 4;
        v
    }
}

/// Row echelon basis over GF(2). A row is stored at its lowest set column.
struct Basis {
    k: usize,
    block_len: usize,
    rows: Vec<Option<(Vec<u64>, Vec<u8>)>>,
    rank: usize,
}

impl Basis {
    fn new(p: &Params) -> Self {
        Self {
            k: usize::from(p.k),
            block_len: usize::from(p.block_len),
            rows: vec![None; usize::from(p.k)],
            rank: 0,
        }
    }

    fn add(&mut self, cols: &[usize], rhs: Vec<u8>) -> Result<(), IndepError> {
        let mut mask = vec![0u64; self.k.div_ceil(64)];
        for &c in cols {
            flip(&mut mask, c);
        }
        let mut rhs = rhs;
        while let Some(lead) = lowest_bit(&mask) {
            match self.rows.get(lead).ok_or(IndepError::BadParams)? {
                Some((row_mask, row_rhs)) => {
                    xor_words(&mut mask, row_mask);
                    xor_bytes(&mut rhs, row_rhs);
                }
                None => {
                    *self.rows.get_mut(lead).ok_or(IndepError::BadParams)? = Some((mask, rhs));
                    self.rank += 1;
                    return Ok(());
                }
            }
        }
        if rhs.iter().any(|b| *b != 0) {
            return Err(IndepError::Inconsistent);
        }
        Ok(())
    }

    /// Back-substitute a full-rank basis and return the blocks joined.
    fn solve(&self) -> Result<Vec<u8>, IndepError> {
        let mut blocks: Vec<Vec<u8>> = vec![Vec::new(); self.k];
        for c in (0..self.k).rev() {
            let (mask, rhs) =
                self.rows
                    .get(c)
                    .and_then(Option::as_ref)
                    .ok_or(IndepError::Incomplete {
                        rank: self.rank,
                        k: self.k,
                    })?;
            let mut value = rhs.clone();
            for j in (c + 1)..self.k {
                if test(mask, j) {
                    xor_bytes(&mut value, blocks.get(j).ok_or(IndepError::BadParams)?);
                }
            }
            *blocks.get_mut(c).ok_or(IndepError::BadParams)? = value;
        }
        let mut out = Vec::with_capacity(self.k * self.block_len);
        for b in blocks {
            out.extend_from_slice(&b);
        }
        Ok(out)
    }
}

fn flip(mask: &mut [u64], i: usize) {
    if let Some(w) = mask.get_mut(i / 64) {
        *w ^= 1u64 << (i % 64);
    }
}

fn test(mask: &[u64], i: usize) -> bool {
    mask.get(i / 64).is_some_and(|w| (w >> (i % 64)) & 1 == 1)
}

fn lowest_bit(mask: &[u64]) -> Option<usize> {
    mask.iter().enumerate().find_map(|(wi, w)| {
        (*w != 0).then(|| wi * 64 + usize::try_from(w.trailing_zeros()).unwrap_or(0))
    })
}

fn xor_words(dst: &mut [u64], src: &[u64]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

fn xor_bytes(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

/// Read the A1 container and check every length, flag and hash rule.
fn read_container(packed: &[u8]) -> Result<Found, IndepError> {
    let bad = IndepError::Container;
    if packed.len() < A1_HEADER_LEN {
        return Err(bad("shorter than header"));
    }
    if packed.get(0..4) != Some(A1_MAGIC.as_slice()) {
        return Err(bad("magic"));
    }
    if packed.get(4).copied() != Some(A1_VERSION) {
        return Err(bad("version"));
    }
    let flags = packed.get(5).copied().ok_or_else(|| bad("flags"))?;
    let kind_tag = packed.get(6).copied().ok_or_else(|| bad("kind"))?;
    if !(1..=3).contains(&kind_tag) {
        return Err(bad("unknown kind"));
    }
    let orig_len = le_u64(packed, 7).ok_or_else(|| bad("length"))?;
    let want_sha = packed.get(15..47).ok_or_else(|| bad("sha"))?;
    let body = packed.get(A1_HEADER_LEN..).ok_or_else(|| bad("body"))?;
    let zlib = flags & A1_FLAG_ZLIB != 0;
    let empty = flags & A1_FLAG_EMPTY != 0;
    if flags & !(A1_FLAG_ZLIB | A1_FLAG_EMPTY) != 0 || (zlib && empty) {
        return Err(bad("flags"));
    }
    if empty != (orig_len == 0) {
        return Err(bad("empty flag and length disagree"));
    }
    let orig = usize::try_from(orig_len).map_err(|_| bad("length range"))?;
    if orig > MAX_BYTES {
        return Err(bad("length range"));
    }
    let raw = if zlib {
        let mut out = Vec::new();
        ZlibDecoder::new(body)
            .take(
                u64::try_from(MAX_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut out)
            .map_err(|_| bad("inflate"))?;
        out
    } else {
        body.to_vec()
    };
    if raw.len() != orig {
        return Err(bad("length differs from body"));
    }
    let mut h = Sha256::new();
    h.update(&raw);
    let got: [u8; 32] = h.finalize().into();
    if got.as_slice() != want_sha {
        return Err(bad("content sha256 mismatch"));
    }
    Ok(Found {
        kind_tag,
        content_sha256: got,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hash::{calculate_hash_bytes, hash_fields_bytes};
    use crate::storage::payload_crypt::PayloadKey;
    use crate::storage::qr_carousel as car;
    use crate::storage::qr_frame as fr;
    use crate::storage::qr_payload as pl;
    use crate::storage::three_pipe::{decode_frames, encode_qr_video, EncodedPipe};

    fn xorshift_bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut s = seed | 1;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s.to_le_bytes()[0]
            })
            .collect()
    }

    fn pipe_of(content: &[u8], block_len: u16, key: Option<&PayloadKey>) -> EncodedPipe {
        encode_qr_video(content, block_len, key).unwrap().pipe
    }

    fn claim_from_primary(sc: &[u8; 32], frames: &[Vec<u8>]) -> PrimaryClaim {
        let (kind, body) = decode_frames(sc, frames).unwrap();
        PrimaryClaim {
            kind_tag: kind.tag(),
            content_sha256: calculate_hash_bytes(&body),
        }
    }

    /// Frames built by hand from a packed container under an arbitrary stream id.
    fn frames_under(packed: &[u8], sc: &[u8; 32], block_len: u16, n: u32) -> Vec<Vec<u8>> {
        let enc = car::CarouselEncoder::new(packed, block_len).unwrap();
        enc.encode_range(0, n)
            .iter()
            .map(|d| fr::pack_frame(sc, d).unwrap())
            .collect()
    }

    #[test]
    fn copied_constants_equal_the_originals() {
        assert_eq!(FRAME_MAGIC, fr::THREE_FRAME_MAGIC);
        assert_eq!(FRAME_VERSION, fr::THREE_FRAME_VERSION);
        assert_eq!(FRAME_HEADER_LEN, fr::THREE_FRAME_HEADER_LEN);
        assert_eq!(DROP_MAGIC, car::DROP_MAGIC);
        assert_eq!(DROP_VERSION, car::DROP_VERSION);
        assert_eq!(DROP_HEADER_LEN, car::DROP_HEADER_LEN);
        assert_eq!(MAX_K, car::MAX_K);
        assert_eq!(MAX_BLOCK_LEN, usize::from(car::MAX_BLOCK_LEN));
        assert_eq!(MAX_DROP_WIRE, usize::from(fr::MAX_DROP_WIRE));
        assert_eq!(MAX_BYTES, car::MAX_CAROUSEL_BYTES);
        assert_eq!(A1_MAGIC, pl::THREE_PAYLOAD_MAGIC);
        assert_eq!(A1_VERSION, pl::THREE_PAYLOAD_VERSION);
        assert_eq!(A1_HEADER_LEN, pl::THREE_PAYLOAD_HEADER_LEN);
        assert_eq!(MAX_BYTES, pl::MAX_PAYLOAD_CONTENT);
    }

    #[test]
    fn copied_tags_and_flags_give_the_same_hashes() {
        let sc = [3u8; 32];
        let wire = b"drop-wire";
        let want = fr::frame_digest(&sc, 9, wire);
        let got = fields_hash(&[FRAME_TAG, &sc, &9u32.to_le_bytes(), wire]);
        assert_eq!(want.as_slice(), got.get(..4).unwrap());
        let packed = pl::pack_payload(pl::PayloadKind::ContentBytes, b"abc").unwrap();
        assert_eq!(
            pl::payload_commitment(&packed),
            fields_hash(&[A1_TAG, &packed])
        );
        let empty = pl::pack_payload(pl::PayloadKind::ContentBytes, b"").unwrap();
        assert_eq!(empty.get(5).copied(), Some(A1_FLAG_EMPTY));
        let text = b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let zipped = pl::pack_payload(pl::PayloadKind::ContentBytes, text).unwrap();
        assert_eq!(zipped.get(5).copied(), Some(A1_FLAG_ZLIB));
        let p = car::CarouselParams::from_payload(&packed, 64).unwrap();
        let pc = pl::payload_commitment(&packed);
        assert_eq!(
            p.stream_commitment(&pc),
            fields_hash(&[
                CAROUSEL_TAG,
                &pc,
                &p.k.to_le_bytes(),
                &p.block_len.to_le_bytes(),
                &p.total_len.to_le_bytes()
            ])
        );
        assert_eq!(hash_fields_bytes(&[b"x", b"y"]), fields_hash(&[b"x", b"y"]));
    }

    fn content_set() -> Vec<Vec<u8>> {
        let mut set = vec![
            Vec::new(),
            vec![0x5a],
            b"short clear text".to_vec(),
            b"compressible ".repeat(40),
        ];
        // Packed length is 47 + n for incompressible bytes, so these sit on a
        // 64 byte block edge: one under, on, one over.
        for n in [16usize, 17, 18, 16 + 64, 17 + 64, 18 + 64, 17 + 64 * 20] {
            set.push(xorshift_bytes(0x9e37_79b9 + n as u64, n));
        }
        for seed in 1..=4u64 {
            set.push(xorshift_bytes(
                seed,
                300 + 211 * usize::try_from(seed).unwrap(),
            ));
        }
        set
    }

    #[test]
    fn two_paths_agree_on_the_whole_content_set() {
        let key = PayloadKey([0x42; 32]);
        for content in content_set() {
            for sealed in [None, Some(&key)] {
                let pipe = pipe_of(&content, 64, sealed);
                let claim = claim_from_primary(&pipe.stream_commitment, &pipe.frames);
                let found = reconstruct(&pipe.stream_commitment, &pipe.frames).unwrap();
                assert_eq!(found.kind_tag, claim.kind_tag);
                assert_eq!(found.content_sha256, claim.content_sha256);
                assert_eq!(
                    confirm(&pipe.stream_commitment, &pipe.frames, &claim),
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn two_paths_agree_when_systematic_frames_are_lost() {
        let content = xorshift_bytes(77, 64 * 40);
        let pipe = pipe_of(&content, 64, None);
        let sc = pipe.stream_commitment;
        let claim = claim_from_primary(&sc, &pipe.frames);
        let kept: Vec<Vec<u8>> = pipe
            .frames
            .iter()
            .enumerate()
            .filter(|(i, _)| ![2usize, 5, 9].contains(i))
            .map(|(_, f)| f.clone())
            .collect();
        assert!(decode_frames(&sc, &kept).is_ok(), "primary needs repairs");
        assert_eq!(confirm(&sc, &kept, &claim), Ok(()));
        // Too few frames: both refuse.
        let few: Vec<Vec<u8>> = pipe.frames.iter().skip(20).cloned().collect();
        assert!(decode_frames(&sc, &few).is_err());
        assert!(matches!(
            confirm(&sc, &few, &claim),
            Err(IndepError::Incomplete { .. })
        ));
    }

    #[test]
    fn bad_container_hash_is_refused_by_both_paths() {
        let mut packed =
            pl::pack_payload(pl::PayloadKind::ContentBytes, b"payload sha case").unwrap();
        // Flip one bit of the committed content sha (bytes 15..47).
        *packed.get_mut(20).unwrap() ^= 1;
        let enc = car::CarouselEncoder::new(&packed, 64).unwrap();
        let sc = enc
            .params()
            .stream_commitment(&pl::payload_commitment(&packed));
        let frames = frames_under(&packed, &sc, 64, 12);
        assert!(decode_frames(&sc, &frames).is_err());
        let claim = PrimaryClaim {
            kind_tag: 1,
            content_sha256: calculate_hash_bytes(b"payload sha case"),
        };
        assert_eq!(
            confirm(&sc, &frames, &claim),
            Err(IndepError::Container("content sha256 mismatch"))
        );
    }

    #[test]
    fn stream_id_not_derived_from_the_bytes_fools_only_the_primary_path() {
        let packed =
            pl::pack_payload(pl::PayloadKind::ContentBytes, &xorshift_bytes(5, 300)).unwrap();
        let sc = [7u8; 32];
        let frames = frames_under(&packed, &sc, 64, 12);
        let claim = claim_from_primary(&sc, &frames);
        assert_eq!(
            confirm(&sc, &frames, &claim),
            Err(IndepError::StreamCommitment)
        );
    }

    #[test]
    fn disagreement_with_the_primary_claim_is_refused() {
        let pipe = pipe_of(b"claim case", 64, None);
        let sc = pipe.stream_commitment;
        let good = claim_from_primary(&sc, &pipe.frames);
        let mut bad_sha = good;
        bad_sha.content_sha256[0] ^= 1;
        assert_eq!(
            confirm(&sc, &pipe.frames, &bad_sha),
            Err(IndepError::ContentDisagrees)
        );
        let mut bad_kind = good;
        bad_kind.kind_tag = 3;
        assert_eq!(
            confirm(&sc, &pipe.frames, &bad_kind),
            Err(IndepError::KindDisagrees {
                primary: 3,
                independent: 1
            })
        );
    }

    #[test]
    fn broken_frames_are_refused() {
        let pipe = pipe_of(&xorshift_bytes(11, 400), 64, None);
        let sc = pipe.stream_commitment;
        let claim = claim_from_primary(&sc, &pipe.frames);
        assert_eq!(confirm(&sc, &[], &claim), Err(IndepError::NoFrames));
        let first = pipe.frames.first().unwrap().clone();

        let mut f = pipe.frames.clone();
        *f.get_mut(0).unwrap() = first.get(..10).unwrap().to_vec();
        assert!(matches!(
            confirm(&sc, &f, &claim),
            Err(IndepError::Frame { index: 0, .. })
        ));
        for (offset, name) in [
            (0usize, "magic"),
            (2, "version"),
            (3, "flags"),
            (8, "stream prefix"),
            (14, "digest"),
            (30, "digest"),
        ] {
            let mut f = pipe.frames.clone();
            let broken = f.get_mut(1).unwrap();
            *broken.get_mut(offset).unwrap() ^= 0x01;
            assert!(
                matches!(
                    confirm(&sc, &f, &claim),
                    Err(IndepError::Frame { index: 1, .. })
                ),
                "{name}"
            );
        }
        // Same seq, other body: a frame repacked with a different drop body.
        let packed =
            pl::pack_payload(pl::PayloadKind::ContentBytes, &xorshift_bytes(12, 300)).unwrap();
        let enc = car::CarouselEncoder::new(&packed, 64).unwrap();
        let mut d = enc.drop_at(0);
        let mut frames = vec![fr::pack_frame(&sc, &d).unwrap()];
        d.body[0] ^= 0xff;
        frames.push(fr::pack_frame(&sc, &d).unwrap());
        assert_eq!(
            confirm(&sc, &frames, &claim),
            Err(IndepError::ConflictingSeq(0))
        );
        // Frame from another stream.
        let other = frames_under(&packed, &[9u8; 32], 64, 3);
        assert!(matches!(
            confirm(&sc, &other, &claim),
            Err(IndepError::Frame { index: 0, .. })
        ));
    }
}
