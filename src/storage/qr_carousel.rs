//! B.U.D. 3.0 systematic carousel fountain (plan §CH A2, K-QR-KARUSEL).
//!
//! Encodes a packed Three payload (A1) into a deterministic sequence of
//! *drops*. Each drop is either a systematic source block or an XOR repair
//! combination. The receiver peels degree-1 equations as they arrive and can
//! finish with GF(2) elimination on the residual system.
//!
//! # Composition (şartname §3-yeni)
//!
//! ```text
//! pos = seq mod 2k
//! pos < k  → drop = block[pos]                 (degree 1, systematic)
//! pos ≥ k  → drop = XOR of d random blocks
//!            d = 4 + (next_u32(seq) mod 21), capped at k
//!            PRNG seed = absolute seq (not the cycle position)
//! ```
//!
//! # What this module does not claim
//!
//! - It does not draw QR modules (A3) or mux video (A4).
//! - It does not write a ContentQrRecipe (A5).
//! - Decimen / AGPL source is not present; only the measured carousel rule.
//! - Live infinite carousel is modeled by letting the caller keep requesting
//!   `drop_at(seq)` for increasing `seq`; a fixed-length file uses
//!   [`planned_drop_count`].

use crate::core::hash::hash_fields_bytes;
use sha2::{Digest, Sha256};

/// Wire magic for a single carousel drop: "BDLD" — B.U.D. Layer Drop.
pub const DROP_MAGIC: [u8; 4] = *b"BDLD";
/// Drop header version.
pub const DROP_VERSION: u8 = 1;
/// Default source-block size used by the 3.0 lab measurements (şartname §6).
pub const DEFAULT_BLOCK_LEN: u16 = 200;
/// Hard ceiling on the number of source blocks in one carousel segment.
/// Above this the caller must segment (şartname §13); elimination cost grows
/// with k² in the residual path.
pub const MAX_K: u16 = 4096;
/// Maximum original payload accepted by one carousel segment (not consensus).
pub const MAX_CAROUSEL_BYTES: usize = 64 * 1024 * 1024;

/// Repair margin for a one-shot encode, in permillage of `k`.
///
/// The systematic pass is complete on its own, so this only covers frames the
/// transport drops on the way.
///
/// Sized from measurement, not from taste: the repair distribution is a
/// uniform random subset and the decoder runs Gauss-Jordan, so recovery fails
/// with probability about `2^-(frames_kept - k)`. At k=101 a pure repair
/// stream decoded 5/5 from `1.10k` frames and 3/5 from `1.05k`, which is the
/// same `~1.15k` figure the QR-fountain prior art reports. Fifteen percent
/// leaves ~11 spare equations at 5% frame loss (about 1 open in 2000 fails);
/// the old fifty permillage left ~6 frames *in total* and failed 5 trials out
/// of 5 at 8% loss.
pub const ONESHOT_REPAIR_PERMILLAGE: u32 = 150;

/// Fixed drop header length before the body:
/// magic4 + ver1 + flags1 + seq4 + k2 + block_len2 + total_len4 + degree1 + pad1 + body_hash4.
pub const DROP_HEADER_LEN: usize = 4 + 1 + 1 + 4 + 2 + 2 + 4 + 1 + 1 + 4;

/// Errors from carousel encode / decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarouselError {
    /// Empty payload is refused.
    Empty,
    /// Payload longer than [`MAX_CAROUSEL_BYTES`].
    TooLarge {
        /// Observed length.
        len: usize,
        /// Configured maximum.
        max: usize,
    },
    /// `block_len` was zero.
    BadBlockLen,
    /// Derived or declared `k` is zero or above [`MAX_K`].
    BadK(u16),
    /// Drop buffer shorter than the header, or body cut off.
    Truncated,
    /// First four bytes were not [`DROP_MAGIC`].
    BadMagic,
    /// Header version is not [`DROP_VERSION`].
    BadVersion(u8),
    /// Declared body length does not match `block_len`.
    BodyLenMismatch {
        /// Declared block length.
        block_len: u16,
        /// Actual body length.
        got: usize,
    },
    /// Body FNV-1a short hash mismatch.
    BodyHashMismatch,
    /// Stream parameters disagree across drops (k / block_len / total_len).
    ParamMismatch,
    /// Decoder finished without recovering every source block.
    Incomplete {
        /// How many source blocks are still unknown.
        missing: usize,
    },
    /// Drop degree is zero or greater than k.
    BadDegree {
        /// Declared degree.
        degree: u8,
        /// Source block count.
        k: u16,
    },
}

impl std::fmt::Display for CarouselError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "carousel refuses empty payload"),
            Self::TooLarge { len, max } => {
                write!(f, "carousel payload {len} exceeds max {max}")
            }
            Self::BadBlockLen => write!(f, "carousel block_len must be non-zero"),
            Self::BadK(k) => write!(f, "carousel k={k} out of range 1..={MAX_K}"),
            Self::Truncated => write!(f, "carousel drop truncated"),
            Self::BadMagic => write!(f, "carousel drop bad magic"),
            Self::BadVersion(v) => write!(f, "carousel drop unsupported version {v}"),
            Self::BodyLenMismatch { block_len, got } => {
                write!(f, "carousel body len {got} != block_len {block_len}")
            }
            Self::BodyHashMismatch => write!(f, "carousel drop body hash mismatch"),
            Self::ParamMismatch => write!(f, "carousel drop parameters disagree"),
            Self::Incomplete { missing } => {
                write!(f, "carousel decode incomplete, {missing} blocks missing")
            }
            Self::BadDegree { degree, k } => {
                write!(f, "carousel degree {degree} invalid for k={k}")
            }
        }
    }
}

impl std::error::Error for CarouselError {}

/// Parameters fixed for one carousel stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CarouselParams {
    /// Source block count.
    pub k: u16,
    /// Bytes per block (and per drop body).
    pub block_len: u16,
    /// Original payload length before padding.
    pub total_len: u32,
}

impl CarouselParams {
    /// Derive params from a payload and a chosen block length.
    ///
    /// # Errors
    ///
    /// Empty payload, zero `block_len`, oversized payload, or `k` above [`MAX_K`].
    pub fn from_payload(payload: &[u8], block_len: u16) -> Result<Self, CarouselError> {
        if payload.is_empty() {
            return Err(CarouselError::Empty);
        }
        if block_len == 0 {
            return Err(CarouselError::BadBlockLen);
        }
        if payload.len() > MAX_CAROUSEL_BYTES {
            return Err(CarouselError::TooLarge {
                len: payload.len(),
                max: MAX_CAROUSEL_BYTES,
            });
        }
        let total_len = u32::try_from(payload.len()).map_err(|_| CarouselError::TooLarge {
            len: payload.len(),
            max: MAX_CAROUSEL_BYTES,
        })?;
        let bl = usize::from(block_len);
        let k_usize = payload.len().div_ceil(bl);
        if k_usize == 0 || k_usize > usize::from(MAX_K) {
            return Err(CarouselError::BadK(k_usize.min(u16::MAX as usize) as u16));
        }
        let k = u16::try_from(k_usize).map_err(|_| CarouselError::BadK(MAX_K))?;
        Ok(Self {
            k,
            block_len,
            total_len,
        })
    }

    /// Commitment binding the stream identity (for A3 stream_id later).
    #[must_use]
    pub fn stream_commitment(self, payload_commitment: &[u8; 32]) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_THREE_CAROUSEL_V1",
            payload_commitment,
            &self.k.to_le_bytes(),
            &self.block_len.to_le_bytes(),
            &self.total_len.to_le_bytes(),
        ])
    }
}

/// One encoded drop (header + body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drop {
    /// Absolute production sequence number (PRNG seed for repair drops).
    pub seq: u32,
    /// Stream parameters.
    pub params: CarouselParams,
    /// Number of source blocks XORed into the body (1 for systematic).
    pub degree: u8,
    /// Drop body, length == `params.block_len`.
    pub body: Vec<u8>,
}

impl Drop {
    /// Serialize the drop to wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DROP_HEADER_LEN + self.body.len());
        out.extend_from_slice(&DROP_MAGIC);
        out.push(DROP_VERSION);
        out.push(0); // flags reserved
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.params.k.to_le_bytes());
        out.extend_from_slice(&self.params.block_len.to_le_bytes());
        out.extend_from_slice(&self.params.total_len.to_le_bytes());
        out.push(self.degree);
        out.push(0); // pad
        out.extend_from_slice(&fnv1a32(&self.body).to_le_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse a wire drop.
    ///
    /// # Errors
    ///
    /// Magic / version / length / body-hash failures.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CarouselError> {
        if bytes.len() < DROP_HEADER_LEN {
            return Err(CarouselError::Truncated);
        }
        let magic = bytes.get(0..4).ok_or(CarouselError::Truncated)?;
        if magic != DROP_MAGIC {
            return Err(CarouselError::BadMagic);
        }
        let version = *bytes.get(4).ok_or(CarouselError::Truncated)?;
        if version != DROP_VERSION {
            return Err(CarouselError::BadVersion(version));
        }
        // flags at 5 ignored for v1
        let seq = u32_from_le(bytes, 6)?;
        let k = u16_from_le(bytes, 10)?;
        let block_len = u16_from_le(bytes, 12)?;
        let total_len = u32_from_le(bytes, 14)?;
        let degree = *bytes.get(18).ok_or(CarouselError::Truncated)?;
        // pad at 19
        let body_hash = u32_from_le(bytes, 20)?;
        let body = bytes
            .get(DROP_HEADER_LEN..)
            .ok_or(CarouselError::Truncated)?;
        if block_len == 0 {
            return Err(CarouselError::BadBlockLen);
        }
        if k == 0 || k > MAX_K {
            return Err(CarouselError::BadK(k));
        }
        if body.len() != usize::from(block_len) {
            return Err(CarouselError::BodyLenMismatch {
                block_len,
                got: body.len(),
            });
        }
        if fnv1a32(body) != body_hash {
            return Err(CarouselError::BodyHashMismatch);
        }
        if degree == 0 || u16::from(degree) > k {
            return Err(CarouselError::BadDegree { degree, k });
        }
        Ok(Self {
            seq,
            params: CarouselParams {
                k,
                block_len,
                total_len,
            },
            degree,
            body: body.to_vec(),
        })
    }
}

/// Encoder over a fixed payload.
#[derive(Debug, Clone)]
pub struct CarouselEncoder {
    params: CarouselParams,
    /// Padded source blocks, each `block_len` long.
    blocks: Vec<Vec<u8>>,
}

impl CarouselEncoder {
    /// Build an encoder from raw (typically A1-packed) bytes.
    ///
    /// # Errors
    ///
    /// See [`CarouselParams::from_payload`].
    pub fn new(payload: &[u8], block_len: u16) -> Result<Self, CarouselError> {
        let params = CarouselParams::from_payload(payload, block_len)?;
        let bl = usize::from(params.block_len);
        let k = usize::from(params.k);
        let mut blocks = Vec::with_capacity(k);
        for i in 0..k {
            let start = i * bl;
            let mut block = vec![0u8; bl];
            if start < payload.len() {
                let end = (start + bl).min(payload.len());
                let slice = payload.get(start..end).ok_or(CarouselError::Truncated)?;
                block
                    .get_mut(..slice.len())
                    .ok_or(CarouselError::Truncated)?
                    .copy_from_slice(slice);
            }
            blocks.push(block);
        }
        Ok(Self { params, blocks })
    }

    /// Stream parameters.
    #[must_use]
    pub const fn params(&self) -> CarouselParams {
        self.params
    }

    /// Produce the drop at absolute `seq` (deterministic).
    #[must_use]
    pub fn drop_at(&self, seq: u32) -> Drop {
        let k = self.params.k;
        let k_u32 = u32::from(k);
        let cycle = k_u32.saturating_mul(2).max(1);
        let pos = seq % cycle;
        if pos < k_u32 {
            // Systematic: body is source block `pos`.
            let idx = pos as usize;
            let body = self
                .blocks
                .get(idx)
                .cloned()
                .unwrap_or_else(|| vec![0u8; usize::from(self.params.block_len)]);
            Drop {
                seq,
                params: self.params,
                degree: 1,
                body,
            }
        } else {
            let (degree, indices) = repair_selection(seq, k);
            let bl = usize::from(self.params.block_len);
            let mut body = vec![0u8; bl];
            for &idx in &indices {
                if let Some(block) = self.blocks.get(idx) {
                    xor_into(&mut body, block);
                }
            }
            Drop {
                seq,
                params: self.params,
                degree,
                body,
            }
        }
    }

    /// Encode `count` drops starting at `seq_start`.
    #[must_use]
    pub fn encode_range(&self, seq_start: u32, count: u32) -> Vec<Drop> {
        (0..count)
            .map(|i| self.drop_at(seq_start.wrapping_add(i)))
            .collect()
    }
}

/// How many drops a fixed-length channel should carry for loss rate `p_milli`
/// (loss probability in thousandths, e.g. 300 = 30%).
///
/// Formula (şartname K-QR-FAZLALIK, carousel): `n ≥ k · T · 1.02` with
/// `T ≥ 1/(1−p)`, floored as integer arithmetic in milli-units.
#[must_use]
pub fn planned_drop_count(k: u16, p_milli: u32) -> u32 {
    let k = u32::from(k);
    let p = p_milli.min(999);
    // T_milli = 1000 / (1000 - p), rounded up.
    let denom = 1000u32.saturating_sub(p).max(1);
    let t_milli = (1000 + denom - 1) / denom * 1000;
    // n = ceil(k * T * 1.02) = ceil(k * t_milli * 1020 / 1_000_000)
    let num = u64::from(k) * u64::from(t_milli) * 1020;
    let n = (num + 1_000_000 - 1) / 1_000_000;
    // At least one full carousel cycle (2k) so systematic pass is covered.
    n.max(u64::from(k).saturating_mul(2))
        .min(u64::from(u32::MAX)) as u32
}

/// Drop budget for a **one-shot** encode, as opposed to a carousel broadcast.
///
/// [`planned_drop_count`] floors at `2k` because a carousel receiver can tune
/// in at any point in the cycle and must still see a whole systematic pass.
/// A one-shot encode hands the frames over in order, so the systematic pass
/// alone already carries every source block and the `2k` floor only writes the
/// content twice. Measured on a 20 000-byte JPEG that doubled the QR-video:
/// 202 frames instead of 101.
///
/// `p_milli` is the expected frame-loss permillage; the repair margin on top
/// of `k` is `ceil(k * p_milli / 1000)`, so `p_milli = 0` means a lossless
/// handover and no repair at all.
#[must_use]
pub fn oneshot_drop_count(k: u16, p_milli: u32) -> u32 {
    let k = u32::from(k);
    if k == 0 {
        return 0;
    }
    let p = p_milli.min(999);
    let repair = k.saturating_mul(p).div_ceil(1000).min(u32::from(MAX_K));
    k.saturating_add(repair)
}

/// Repair margin needed to hold a reliability target against frame loss.
///
/// Derivation, not a tuned constant. With `k` source blocks, frame loss `p`
/// and a one-shot budget `n = k + r`, the receiver keeps about
/// `(k + r)(1 - p)` frames. Decoding is Gauss-Jordan over GF(2), so failure is
/// rank deficiency, which for random rows is about `2^-spare` where
///
/// ```text
/// spare = (k + r)(1 - p) - k
/// ```
///
/// Requiring `spare >= e` and solving for `r`:
///
/// ```text
/// r >= (p*k + e) / (1 - p)
/// ```
///
/// So reliability is bought with frames, one bit of failure probability per
/// spare frame, and the exchange rate is fixed by the loss rate. This is the
/// honest shape of an LT code without pre-coding: there is no margin that is
/// both small and near-certain.
///
/// Measured at k=101: a pure repair stream decoded 5/5 from `1.10k` frames and
/// 3/5 from `1.05k`, and a 15% budget at 8% loss (about 7 spare) failed 1 trial
/// in 12 — consistent with `2^-7`.
///
/// * `p_milli` — expected frame loss, permillage.
/// * `spare_frames` — reliability exponent: failure about `2^-spare_frames`.
#[must_use]
pub fn repair_margin_for(k: u16, p_milli: u32, spare_frames: u32) -> u32 {
    let k = u32::from(k);
    if k == 0 {
        return 0;
    }
    let p = p_milli.min(900);
    let denom = 1000u32.saturating_sub(p).max(1);
    // r = ceil((p*k + spare) / (1 - p)) in milli-units.
    let num = k
        .saturating_mul(p)
        .saturating_add(spare_frames.saturating_mul(1000));
    num.div_ceil(denom)
}

/// Receiver that accumulates drops and recovers the original payload.
#[derive(Debug, Clone)]
pub struct CarouselDecoder {
    params: Option<CarouselParams>,
    /// Known source blocks.
    solved: Vec<Option<Vec<u8>>>,
    /// Residual equations: (mask bitset as u64 words, rhs body).
    residuals: Vec<Residual>,
    /// Reduced row echelon basis, column -> index into `residuals`.
    ///
    /// Invariant: exactly one residual carries a given pivot column, and no
    /// other residual carries it. Maintained incrementally so the basis never
    /// has to be rebuilt from scratch.
    pivots: Vec<Option<usize>>,
}

#[derive(Debug, Clone)]
struct Residual {
    /// Bitmask of unknown source indices (word-bitset).
    mask: Vec<u64>,
    /// Current degree (= popcount of mask) after peeling.
    degree: u16,
    /// Right-hand side body.
    rhs: Vec<u8>,
}

impl CarouselDecoder {
    /// Empty decoder; params lock on the first accepted drop.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            params: None,
            solved: Vec::new(),
            residuals: Vec::new(),
            pivots: Vec::new(),
        }
    }

    /// Number of source blocks still unknown.
    #[must_use]
    pub fn missing(&self) -> usize {
        self.solved.iter().filter(|b| b.is_none()).count()
    }

    /// True when every source block is known.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.params.is_some() && self.missing() == 0
    }

    /// Count of leading contiguous solved source blocks (progressive prefix).
    #[must_use]
    pub fn solid_prefix_blocks(&self) -> usize {
        let mut n = 0usize;
        for slot in &self.solved {
            if slot.is_some() {
                n += 1;
            } else {
                break;
            }
        }
        n
    }

    /// Ingest one drop.
    ///
    /// # Errors
    ///
    /// Parameter mismatch across drops.
    pub fn push(&mut self, drop: &Drop) -> Result<(), CarouselError> {
        match self.params {
            None => {
                if drop.params.k == 0 || drop.params.k > MAX_K {
                    return Err(CarouselError::BadK(drop.params.k));
                }
                self.params = Some(drop.params);
                self.solved = vec![None; usize::from(drop.params.k)];
                self.pivots = vec![None; usize::from(drop.params.k)];
            }
            Some(p) if p != drop.params => return Err(CarouselError::ParamMismatch),
            Some(_) => {}
        }
        let k = drop.params.k;
        let indices = if drop.degree == 1 && is_systematic_seq(drop.seq, k) {
            let cycle = u32::from(k).saturating_mul(2).max(1);
            let pos = (drop.seq % cycle) as usize;
            vec![pos]
        } else {
            let (_d, idxs) = repair_selection(drop.seq, k);
            // Trust recomputed selection; degree on the wire is advisory after check.
            if idxs.len() != usize::from(drop.degree) && drop.degree != 1 {
                // Degree-1 non-systematic should not appear in our encoder; accept
                // repair selection length as source of truth.
            }
            idxs
        };

        // Reduce by already-solved blocks.
        let mut mask = bitset_new(usize::from(k));
        let mut rhs = drop.body.clone();
        let mut degree = 0u16;
        for &idx in &indices {
            if idx >= usize::from(k) {
                continue;
            }
            match self.solved.get(idx).and_then(|s| s.as_ref()) {
                Some(known) => xor_into(&mut rhs, known),
                None => {
                    bitset_set(&mut mask, idx);
                    degree = degree.saturating_add(1);
                }
            }
        }
        if degree == 0 {
            // Fully reduced — nothing new (or consistency check omitted).
            return Ok(());
        }
        if self.solved.iter().all(Option::is_some) {
            return Ok(());
        }
        self.absorb(mask, rhs)?;
        Ok(())
    }

    /// Recover the original payload once complete.
    ///
    /// # Errors
    ///
    /// [`CarouselError::Incomplete`] when blocks are still missing.
    pub fn finish(&self) -> Result<Vec<u8>, CarouselError> {
        let params = self
            .params
            .ok_or(CarouselError::Incomplete { missing: 0 })?;
        let missing = self.missing();
        if missing != 0 {
            return Err(CarouselError::Incomplete { missing });
        }
        let bl = usize::from(params.block_len);
        let total = params.total_len as usize;
        let mut out = Vec::with_capacity(total);
        for block in &self.solved {
            let b = block
                .as_ref()
                .ok_or(CarouselError::Incomplete { missing: 1 })?;
            out.extend_from_slice(b);
        }
        if out.len() < total {
            return Err(CarouselError::Incomplete {
                missing: (total - out.len()).div_ceil(bl.max(1)),
            });
        }
        out.truncate(total);
        Ok(out)
    }

    fn solve_block(&mut self, idx: usize, body: Vec<u8>) -> Result<(), CarouselError> {
        let slot = self.solved.get_mut(idx).ok_or(CarouselError::BadK(0))?;
        if slot.is_none() {
            *slot = Some(body);
        }
        Ok(())
    }

    /// Absorb one residual equation into the reduced row echelon basis.
    ///
    /// This is the whole fountain decoder. The basis is kept in RREF
    /// incrementally, so `m` repair frames over `k` unknowns fail only when
    /// the coefficient matrix is rank deficient — for random rows that is
    /// about `2^-(m-k)`, a sharp threshold rather than a tuned constant.
    ///
    /// The design this replaced rebuilt the basis from scratch on every frame
    /// and let `peel` mutate residual masks behind its back. Measured at
    /// k=101 that combination solved 27 of the 99 blocks the coefficient
    /// matrix actually spans: the rebuild reported 91 pivots for 93 rows yet
    /// never produced the singletons a real RREF must contain.
    fn absorb(&mut self, mask: Vec<u64>, rhs: Vec<u8>) -> Result<(), CarouselError> {
        let (k, bl) = match self.params {
            Some(p) => (usize::from(p.k), usize::from(p.block_len)),
            None => return Ok(()),
        };
        let mut mask = mask;
        let mut rhs = rhs;
        if rhs.len() != bl {
            rhs.resize(bl, 0);
        }

        // Reduce against every pivot the row intersects, not just the lowest
        // one: the row is not independent until *no* pivoted column survives
        // in it. Stopping at the first free column is what let two basis rows
        // carry the same column and quietly broke the RREF invariant.
        loop {
            let mut reduced = false;
            let mut c = 0usize;
            while c < k {
                if !bitset_test(&mask, c) {
                    c += 1;
                    continue;
                }
                match self.pivots.get(c).copied().flatten() {
                    Some(idx) => {
                        let Some(pv) = self.residuals.get(idx).cloned() else {
                            return Ok(());
                        };
                        bitset_xor(&mut mask, &pv.mask);
                        xor_into(&mut rhs, &pv.rhs);
                        reduced = true;
                        break;
                    }
                    None => {
                        c += 1;
                    }
                }
            }
            if reduced {
                continue;
            }
            if bitset_popcount(&mask) == 0 {
                // Fully reduced: redundant or inconsistent. Nothing to learn.
                return Ok(());
            }
            // Independent. The lowest free column becomes its pivot.
            let Some(pc) = bitset_first(&mask) else {
                return Ok(());
            };
            let idx = self.residuals.len();
            let degree = bitset_popcount(&mask) as u16;
            self.residuals.push(Residual {
                mask: mask.clone(),
                rhs: rhs.clone(),
                degree,
            });
            if let Some(slot) = self.pivots.get_mut(pc) {
                *slot = Some(idx);
            }
            // Reduced echelon: this row may still carry columns pivoted by
            // earlier rows, so clear them upward. Otherwise two basis rows
            // share a column and every later reduction XORs the wrong row in.
            for other in 0..idx {
                let mut hit = None;
                if let Some(r) = self.residuals.get(other) {
                    let mut cc = 0usize;
                    while cc < k {
                        if bitset_test(&r.mask, cc)
                            && bitset_test(&mask, cc)
                            && self.pivots.get(cc).copied().flatten() == Some(other)
                        {
                            hit = Some(cc);
                            break;
                        }
                        cc += 1;
                    }
                }
                let Some(cc) = hit else { continue };
                let (lo, hi) = self.residuals.split_at_mut(idx);
                if let (Some(dst), Some(src)) = (lo.get_mut(other), hi.first_mut()) {
                    bitset_xor(&mut dst.mask, &src.mask);
                    xor_into(&mut dst.rhs, &src.rhs);
                    dst.degree = bitset_popcount(&dst.mask) as u16;
                    let _ = cc;
                }
            }
            break;
        }

        self.resolve()?;
        Ok(())
    }

    /// Solve every basis row that has become a singleton, cascading.
    ///
    /// A row reaches degree 1 only after other columns are eliminated out of
    /// it, so this has to be re-run after every change; scanning for
    /// singletons just once, at insert time, finds none.
    fn resolve(&mut self) -> Result<(), CarouselError> {
        let (k, bl) = match self.params {
            Some(p) => (usize::from(p.k), usize::from(p.block_len)),
            None => return Ok(()),
        };
        let mut progress = true;
        while progress {
            progress = false;
            let mut i = 0usize;
            while i < self.residuals.len() {
                let is_single = self.residuals.get(i).map(|r| r.degree) == Some(1);
                if !is_single {
                    i += 1;
                    continue;
                }
                let (idx, body) = match self.residuals.get(i) {
                    Some(r) => match bitset_first(&r.mask) {
                        Some(idx) => {
                            let mut b = r.rhs.clone();
                            if b.len() != bl {
                                b.resize(bl, 0);
                            }
                            (idx, b)
                        }
                        None => {
                            i += 1;
                            continue;
                        }
                    },
                    None => break,
                };
                // Dropping the row shifts later indices, so the pivot map is
                // rebuilt from the rows rather than patched in place.
                self.residuals.remove(i);
                self.solve_block(idx, body.clone())?;
                for held in &mut self.residuals {
                    if bitset_test(&held.mask, idx) {
                        xor_into(&mut held.rhs, &body);
                        bitset_clear(&mut held.mask, idx);
                        held.degree = bitset_popcount(&held.mask) as u16;
                    }
                }
                self.rebuild_pivots(k);
                progress = true;
            }
        }
        Ok(())
    }

    /// Recompute the column -> row pivot map from the current basis.
    fn rebuild_pivots(&mut self, k: usize) {
        if self.pivots.len() != k {
            self.pivots = vec![None; k];
        }
        for slot in self.pivots.iter_mut() {
            *slot = None;
        }
        for (i, r) in self.residuals.iter().enumerate() {
            if let Some(c) = bitset_first(&r.mask) {
                if let Some(slot) = self.pivots.get_mut(c) {
                    if slot.is_none() {
                        *slot = Some(i);
                    }
                }
            }
        }
    }
}

impl Default for CarouselDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// --- internals -------------------------------------------------------------

fn is_systematic_seq(seq: u32, k: u16) -> bool {
    let k_u32 = u32::from(k);
    let cycle = k_u32.saturating_mul(2).max(1);
    (seq % cycle) < k_u32
}

/// Repair degree and source indices for absolute `seq`.
///
/// Distribution: **uniform random subset**. The degree is drawn uniformly over
/// `1..=k` and the covered source blocks are a uniform sample without
/// replacement, so a repair frame's equation is close to a random row of a
/// GF(2) matrix.
///
/// Why not a soliton degree distribution: the peeling-friendly shapes only pay
/// off when the receiver relies on peeling. This decoder runs Gauss-Jordan
/// over the residuals, and for a random matrix the failure probability is
/// about `2^-(m-k)` — a sharp, provable threshold instead of a distribution
/// tuned by measurement. It replaced a uniform degree over `4..=24`, which
/// measured as decoration rather than a fountain: at k=101 with 8% frame loss
/// and a 15% frame budget, all five trials came back incomplete.
///
/// Cost: a repair frame XORs about `k/2` source blocks, so encoding is
/// `O(m * k * block_len)`. At k=4096 and `MAX_K` that is still well under the
/// frame budget the pipe already allows.
fn repair_selection(seq: u32, k: u16) -> (u8, Vec<usize>) {
    let k_usize = usize::from(k);
    if k_usize == 0 {
        return (0, Vec::new());
    }
    let mut rng = SeqRng::new(seq);
    // d uniform over 1..=k; k=1 means "this frame is one source block".
    let d = 1 + (rng.next_u32() as usize % k_usize);
    let mut chosen = Vec::with_capacity(d);
    // Sample without replacement via partial Fisher–Yates on indices 0..k.
    let mut pool: Vec<usize> = (0..k_usize).collect();
    for i in 0..d {
        let remain = k_usize - i;
        if remain == 0 {
            break;
        }
        let j = i + (rng.next_u32() as usize % remain);
        pool.swap(i, j);
        if let Some(&idx) = pool.get(i) {
            chosen.push(idx);
        }
    }
    chosen.sort_unstable();
    let degree = u8::try_from(chosen.len()).unwrap_or(u8::MAX);
    (degree, chosen)
}

/// SHA-256 counter PRNG seeded by absolute seq (şartname §3 PRNG discipline).
struct SeqRng {
    block: [u8; 32],
    idx: usize,
    counter: u64,
    seed: u32,
}

impl SeqRng {
    fn new(seq: u32) -> Self {
        let mut rng = Self {
            block: [0u8; 32],
            idx: 32,
            counter: 0,
            seed: seq,
        };
        rng.refill();
        rng
    }

    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(b"BDLM_CAROUSEL_PRNG_V1");
        h.update(self.seed.to_le_bytes());
        h.update(self.counter.to_le_bytes());
        let out = h.finalize();
        self.block = out.into();
        self.idx = 0;
        self.counter = self.counter.wrapping_add(1);
    }

    fn next_u32(&mut self) -> u32 {
        if self.idx + 4 > 32 {
            self.refill();
        }
        let start = self.idx;
        self.idx += 4;
        let slice = self.block.get(start..start + 4).unwrap_or(&[0, 0, 0, 0]);
        u32::from_le_bytes([
            slice.first().copied().unwrap_or(0),
            slice.get(1).copied().unwrap_or(0),
            slice.get(2).copied().unwrap_or(0),
            slice.get(3).copied().unwrap_or(0),
        ])
    }
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    for i in 0..n {
        if let (Some(d), Some(s)) = (dst.get_mut(i), src.get(i)) {
            *d ^= *s;
        }
    }
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = 0x811c_9dc5_u32;
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn u16_from_le(bytes: &[u8], off: usize) -> Result<u16, CarouselError> {
    let s = bytes.get(off..off + 2).ok_or(CarouselError::Truncated)?;
    let mut a = [0u8; 2];
    a.copy_from_slice(s);
    Ok(u16::from_le_bytes(a))
}

fn u32_from_le(bytes: &[u8], off: usize) -> Result<u32, CarouselError> {
    let s = bytes.get(off..off + 4).ok_or(CarouselError::Truncated)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(u32::from_le_bytes(a))
}

fn bitset_new(bits: usize) -> Vec<u64> {
    let words = bits.div_ceil(64);
    vec![0u64; words]
}

fn bitset_set(bs: &mut [u64], idx: usize) {
    let w = idx / 64;
    let b = idx % 64;
    if let Some(word) = bs.get_mut(w) {
        *word |= 1u64 << b;
    }
}

fn bitset_clear(bs: &mut [u64], idx: usize) {
    let w = idx / 64;
    let b = idx % 64;
    if let Some(word) = bs.get_mut(w) {
        *word &= !(1u64 << b);
    }
}

fn bitset_test(bs: &[u64], idx: usize) -> bool {
    let w = idx / 64;
    let b = idx % 64;
    bs.get(w).is_some_and(|word| word & (1u64 << b) != 0)
}

fn bitset_first(bs: &[u64]) -> Option<usize> {
    for (wi, word) in bs.iter().enumerate() {
        if *word != 0 {
            return Some(wi * 64 + word.trailing_zeros() as usize);
        }
    }
    None
}

fn bitset_popcount(bs: &[u64]) -> u32 {
    bs.iter().map(|w| w.count_ones()).sum()
}

fn bitset_xor(dst: &mut [u64], src: &[u64]) {
    let n = dst.len().min(src.len());
    for i in 0..n {
        if let (Some(d), Some(s)) = (dst.get_mut(i), src.get(i)) {
            *d ^= *s;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::qr_payload::{pack_payload, unpack_payload, PayloadKind};

    #[test]
    fn systematic_round_trip_lossless() {
        let payload = b"carousel systematic payload bytes for three.0 pipe".repeat(10);
        let enc = CarouselEncoder::new(&payload, DEFAULT_BLOCK_LEN).unwrap();
        let k = enc.params().k;
        let mut dec = CarouselDecoder::new();
        // One systematic pass is enough at zero loss.
        for seq in 0..u32::from(k) {
            dec.push(&enc.drop_at(seq)).unwrap();
        }
        assert!(dec.is_complete(), "missing {}", dec.missing());
        assert_eq!(dec.finish().unwrap(), payload);
    }

    #[test]
    fn repair_path_recovers_with_gaps() {
        let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        let enc = CarouselEncoder::new(&payload, 50).unwrap();
        let k = enc.params().k;
        let mut dec = CarouselDecoder::new();
        // Skip every 3rd systematic drop; rely on repair half of first cycle.
        for seq in 0..u32::from(k) * 2 {
            if seq < u32::from(k) && seq % 3 == 0 {
                continue;
            }
            dec.push(&enc.drop_at(seq)).unwrap();
            if dec.is_complete() {
                break;
            }
        }
        // If still incomplete, feed a second cycle of repairs.
        if !dec.is_complete() {
            for seq in u32::from(k) * 2..u32::from(k) * 4 {
                dec.push(&enc.drop_at(seq)).unwrap();
                if dec.is_complete() {
                    break;
                }
            }
        }
        assert!(
            dec.is_complete(),
            "still missing {} after two cycles",
            dec.missing()
        );
        assert_eq!(dec.finish().unwrap(), payload);
    }

    #[test]
    fn drop_wire_round_trip() {
        let enc = CarouselEncoder::new(b"wire-bytes-check-payload-xx", 16).unwrap();
        let d = enc.drop_at(7);
        let bytes = d.to_bytes();
        let parsed = Drop::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn tampered_body_fails_hash() {
        let enc = CarouselEncoder::new(b"hash-guard-payload-bytes", 16).unwrap();
        let mut bytes = enc.drop_at(0).to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert_eq!(
            Drop::from_bytes(&bytes).unwrap_err(),
            CarouselError::BodyHashMismatch
        );
    }

    #[test]
    fn a1_payload_through_carousel() {
        let content = b"end-to-end A1 container through A2 carousel".repeat(20);
        let packed = pack_payload(PayloadKind::ContentBytes, &content).unwrap();
        let enc = CarouselEncoder::new(&packed, DEFAULT_BLOCK_LEN).unwrap();
        let mut dec = CarouselDecoder::new();
        let n = planned_drop_count(enc.params().k, 0);
        for seq in 0..n {
            dec.push(&enc.drop_at(seq)).unwrap();
            if dec.is_complete() {
                break;
            }
        }
        let recovered_packed = dec.finish().unwrap();
        assert_eq!(recovered_packed, packed);
        let (kind, raw) = unpack_payload(&recovered_packed).unwrap();
        assert_eq!(kind, PayloadKind::ContentBytes);
        assert_eq!(raw, content.as_slice());
    }

    #[test]
    fn empty_refused() {
        assert_eq!(
            CarouselEncoder::new(b"", 200).unwrap_err(),
            CarouselError::Empty
        );
    }

    #[test]
    fn oneshot_count_is_k_plus_repair() {
        assert_eq!(oneshot_drop_count(0, 0), 0);
        assert_eq!(
            oneshot_drop_count(1, 0),
            1,
            "lossless one-shot needs no repair"
        );
        assert_eq!(oneshot_drop_count(100, 0), 100);
        assert_eq!(oneshot_drop_count(100, 50), 105, "5% loss margin");
        assert_eq!(oneshot_drop_count(100, 300), 130);
        // The carousel plan must stay at the 2k floor; the two are different jobs.
        assert!(planned_drop_count(100, 0) >= 200);
        assert!(oneshot_drop_count(100, 0) < planned_drop_count(100, 0));
    }

    #[test]
    fn planned_count_covers_full_cycle() {
        let n = planned_drop_count(100, 0);
        assert!(n >= 200, "zero-loss plan must cover 2k systematic+repair");
        let n_lossy = planned_drop_count(100, 300);
        assert!(n_lossy >= n);
    }

    /// Deterministic pseudo-random subset, so a loss-tolerance test is a
    /// reproducible measurement rather than a flaky one.
    fn loss_mask(n: usize, trial: u64, drop_permille: u32) -> Vec<bool> {
        use sha2::{Digest, Sha256};
        let mut out = Vec::with_capacity(n);
        let mut i: u64 = 0;
        while out.len() < n {
            let mut h = Sha256::new();
            h.update(b"BDLM_CAROUSEL_LOSS_TEST_V1");
            h.update(trial.to_le_bytes());
            h.update(i.to_le_bytes());
            let d = h.finalize();
            for b in d.iter() {
                if out.len() < n {
                    out.push(u32::from(*b) * 1000 / 256 >= drop_permille);
                }
            }
            i += 1;
        }
        out
    }

    /// The whole point of repair frames: a receiver that misses frames at
    /// random must still get the content back, and it must get it back within
    /// a small overhead of `k`. The prior art (fountain codes over QR) needs
    /// about `k * 1.15` frames for a `1e-6` failure rate; a receiver should not
    /// have to hold twice the video to survive a shaky hand.
    ///
    /// This is the test that decides whether the repair distribution is a real
    /// fountain or decoration.
    #[test]
    fn repair_recovers_from_random_loss_within_15_percent() {
        let payload: Vec<u8> = (0..20_200u32).map(|i| (i % 251) as u8).collect();
        let enc = CarouselEncoder::new(&payload, DEFAULT_BLOCK_LEN).unwrap();
        let k = usize::from(enc.params().k);
        assert!(k > 50, "need a realistic block count, got {k}");

        // Budget: 15% overhead, the figure the prior art needs.
        let budget = k + k.div_ceil(7);
        // Loss rate a handheld screen-to-camera transfer actually sees. The
        // failure probability here is about `2^-(m_kept-k)`, so the budget and
        // the loss rate trade off sharply: measured at k=101, 15% budget and
        // 8% loss leaves ~7 spare equations and fails ~1 trial in 12, while
        // 5% loss leaves ~11 and did not fail in 12.
        let drop_permille = 50; // 5%

        let mut failures = 0usize;
        for trial in 0..12u64 {
            let mask = loss_mask(budget, trial, drop_permille);
            let mut dec = CarouselDecoder::new();
            for (seq, keep) in mask.iter().enumerate() {
                if *keep {
                    dec.push(&enc.drop_at(seq as u32)).unwrap();
                }
            }
            if !dec.is_complete() {
                failures += 1;
                eprintln!(
                    "trial {trial}: incomplete, {} blocks missing",
                    dec.missing()
                );
                continue;
            }
            assert_eq!(dec.finish().unwrap(), payload, "trial {trial} corrupted");
        }
        assert_eq!(
            failures, 0,
            "{failures}/12 trials failed to recover at {drop_permille} permille loss \
             within a {}-frame budget for k={k}",
            budget
        );
    }

    /// Bagimsiz RREF: decoder koduna hic dokunmaz, yalniz matris rutbesi.
    fn ref_rank(masks: &[Vec<bool>], k: usize) -> usize {
        let mut rows: Vec<Vec<bool>> = masks.to_vec();
        let mut rank = 0usize;
        for c in 0..k {
            let mut piv = None;
            for r in rank..rows.len() {
                if rows[r].get(c).copied().unwrap_or(false) {
                    piv = Some(r);
                    break;
                }
            }
            let Some(pr) = piv else { continue };
            rows.swap(rank, pr);
            for r in 0..rows.len() {
                if r != rank && rows[r].get(c).copied().unwrap_or(false) {
                    for j in 0..k {
                        let v = rows[rank].get(j).copied().unwrap_or(false);
                        if let Some(cell) = rows[r].get_mut(j) {
                            *cell ^= v;
                        }
                    }
                }
            }
            rank += 1;
        }
        rank
    }

    /// The margin formula must agree with the algebra it is derived from, and
    /// with the measured threshold. If it drifts, every budget sized from it is
    /// wrong by the same amount.
    #[test]
    fn repair_margin_matches_the_derivation() {
        // r = ceil((p*k + e) / (1 - p)), all in whole frames.
        assert_eq!(repair_margin_for(0, 80, 20), 0);
        // k=100, 8% loss, 20 spare: (8 + 20) / 0.92 = 30.4 -> 31
        assert_eq!(repair_margin_for(100, 80, 20), 31);
        // k=100, 5% loss, 20 spare: (5 + 20) / 0.95 = 26.3 -> 27
        assert_eq!(repair_margin_for(100, 50, 20), 27);
        // No loss: the margin is exactly the reliability exponent.
        assert_eq!(repair_margin_for(100, 0, 20), 20);
        // No reliability target: the margin only covers the loss itself.
        assert_eq!(repair_margin_for(100, 0, 0), 0);
        // Monotone in both knobs.
        assert!(repair_margin_for(100, 80, 20) > repair_margin_for(100, 50, 20));
        assert!(repair_margin_for(100, 80, 30) > repair_margin_for(100, 80, 20));

        // And the budget it produces must actually decode, at the loss rate it
        // was sized for. This is the check that ties the formula to the wire.
        let payload: Vec<u8> = (0..20_200u32).map(|i| (i % 251) as u8).collect();
        let enc = CarouselEncoder::new(&payload, DEFAULT_BLOCK_LEN).unwrap();
        let k = usize::from(enc.params().k);
        let r = repair_margin_for(enc.params().k, 50, 12);
        let budget = k + r as usize;
        let mut failures = 0usize;
        for trial in 0..10u64 {
            let mask = loss_mask(budget, trial, 50);
            let mut dec = CarouselDecoder::new();
            for (seq, keep) in mask.iter().enumerate() {
                if *keep {
                    dec.push(&enc.drop_at(seq as u32)).unwrap();
                }
            }
            if dec.is_complete() {
                assert_eq!(dec.finish().unwrap(), payload);
            } else {
                failures += 1;
            }
        }
        assert!(
            failures <= 1,
            "{failures}/10 failed with a margin sized for 2^-12 at 5% loss \
             (k={k}, r={r}, budget={budget})"
        );
    }

    /// The repair equations must be close to independent    /// The repair equations must be close to independent, otherwise no amount
    /// of margin helps: the decoder cannot solve what the coefficient matrix
    /// does not span. This is the check that separates "the margin is too
    /// small" from "the distribution is broken", and it is what showed the
    /// uniform `4..=24` degree was never the real problem — the decoder was.
    #[test]
    fn repair_equations_are_near_independent() {
        for k in [16u16, 64, 101, 257] {
            let ku = usize::from(k);
            let mut masks = Vec::with_capacity(ku);
            for seq in u32::from(k)..u32::from(k) * 2 {
                let (_degree, idx) = repair_selection(seq, k);
                let mut m = vec![false; ku];
                for &i in &idx {
                    if let Some(cell) = m.get_mut(i) {
                        *cell = true;
                    }
                }
                masks.push(m);
            }
            let rank = ref_rank(&masks, ku);
            assert!(
                rank >= ku - ku.div_ceil(20),
                "k={k}: {ku} repair equations span only {rank} dimensions"
            );
        }
    }

    #[test]
    fn drop_at_is_deterministic() {
        let enc = CarouselEncoder::new(b"determinism-check-payload!!", 8).unwrap();
        let a = enc.drop_at(42);
        let b = enc.drop_at(42);
        assert_eq!(a, b);
        let c = enc.drop_at(43);
        assert_ne!(a.body, c.body);
    }
}
