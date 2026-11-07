//! WIRING: self-describing logical frame wire format wired into B.U.D. 3.0 two-path upload and optical view.
//! Self-describing B.U.D. 3.0 logical frame wire format.
//!
//! Each RFC 6330 symbol (source or repair) wraps into a compact 26-byte header
//! (`B3F1`) so any single frame decoded off a screen or stream names its
//! segment index, unpadded segment byte length, ESI, and segment `k` without
//! external out-of-band state. At canonical `Profile::P0` (`symbol_size = 2911`),
//! `26 + 2911 = 2937 <= 2953`, fitting inside one ISO QR Version 40 ECC-L
//! byte-mode symbol.

use super::fountain::{FountainError, SegmentEncoder, Symbol, SymbolKind, MAX_ESI};
use super::limits::Profile;
use super::meter::{Meter, MeterError};
use super::segment::Segmentation;
use crate::core::hash::hash_fields_bytes;

/// Domain-separation tag for logical frame digests.
pub const BUD3_FRAME_TAG: &[u8] = b"BDLM_BUD3_FRAME_V1";

/// Wire magic of a self-describing B.U.D. 3.0 frame.
pub const BUD3_FRAME_MAGIC: [u8; 4] = *b"B3F1";

/// Fixed header length in bytes (`4 + 1 + 1 + 8 + 4 + 4 + 4 = 26`).
pub const BUD3_FRAME_HEADER_LEN: usize = 26;

const KIND_SOURCE: u8 = 0;
const KIND_REPAIR: u8 = 1;

/// Why encoding or parsing a logical frame failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameWireError {
    /// Input shorter than [`BUD3_FRAME_HEADER_LEN`] or empty symbol payload.
    Truncated,
    /// Magic is not `B3F1`.
    BadMagic,
    /// Kind byte is neither source (`0`) nor repair (`1`), or disagrees with `(esi, k)`.
    BadKind(u8),
    /// Reserved byte is non-zero.
    ReservedNonZero(u8),
    /// Declared segment length or `k` is zero or inconsistent with symbol size.
    BadGeometry,
    /// ESI exceeds RFC 6330 24-bit ceiling.
    EsiOutOfRange(u32),
    /// Underlying fountain error.
    Fountain(FountainError),
    /// Parser budget exceeded.
    Budget(MeterError),
}

impl From<FountainError> for FrameWireError {
    fn from(e: FountainError) -> Self {
        Self::Fountain(e)
    }
}

impl From<MeterError> for FrameWireError {
    fn from(e: MeterError) -> Self {
        Self::Budget(e)
    }
}

/// One self-describing logical frame carrying one RFC 6330 symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bud3Frame {
    /// Source (`esi < source_symbols`) or derived repair (`esi >= source_symbols`).
    pub kind: SymbolKind,
    /// Zero-based segment index inside the BOF-1 object.
    pub segment: u64,
    /// Exact unpadded byte length of `segment` inside the BOF-1 object.
    pub segment_len: u32,
    /// RFC 6330 Encoding Symbol ID (`0..=MAX_ESI`).
    pub esi: u32,
    /// Source symbol count `k` of `segment`.
    pub source_symbols: u32,
    /// Symbol payload bytes (`profile.symbol_size` bytes).
    pub data: Vec<u8>,
}

impl Bud3Frame {
    /// Construct a validated logical frame from a coded [`Symbol`].
    ///
    /// # Errors
    ///
    /// Returns [`FrameWireError`] if `segment_len == 0`, `source_symbols == 0`,
    /// `data` is empty, or `esi > MAX_ESI`.
    pub fn from_symbol(
        symbol: Symbol,
        segment_len: u32,
        source_symbols: u32,
    ) -> Result<Self, FrameWireError> {
        if segment_len == 0 || source_symbols == 0 || symbol.data.is_empty() {
            return Err(FrameWireError::BadGeometry);
        }
        if symbol.esi > MAX_ESI {
            return Err(FrameWireError::EsiOutOfRange(symbol.esi));
        }
        let kind = symbol.kind(source_symbols);
        Ok(Self {
            kind,
            segment: symbol.segment,
            segment_len,
            esi: symbol.esi,
            source_symbols,
            data: symbol.data,
        })
    }

    /// Unwrap into the underlying RFC 6330 [`Symbol`].
    #[must_use]
    pub fn into_symbol(self) -> Symbol {
        Symbol {
            segment: self.segment,
            esi: self.esi,
            data: self.data,
        }
    }

    /// Canonical wire bytes (`26`-byte header + `data`).
    #[must_use]
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BUD3_FRAME_HEADER_LEN.saturating_add(self.data.len()));
        out.extend_from_slice(&BUD3_FRAME_MAGIC);
        let kind_tag = match self.kind {
            SymbolKind::Source => KIND_SOURCE,
            SymbolKind::Repair => KIND_REPAIR,
        };
        out.push(kind_tag);
        out.push(0u8);
        out.extend_from_slice(&self.segment.to_le_bytes());
        out.extend_from_slice(&self.segment_len.to_le_bytes());
        out.extend_from_slice(&self.esi.to_le_bytes());
        out.extend_from_slice(&self.source_symbols.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Parse a self-describing logical frame from untrusted bytes without panicking.
    ///
    /// # Errors
    ///
    /// Returns [`FrameWireError`] on truncation, bad magic, non-zero reserved byte,
    /// inconsistent `(kind, esi, source_symbols, segment_len)`, or meter exhaustion.
    pub fn decode_wire(bytes: &[u8], meter: &mut Meter) -> Result<Self, FrameWireError> {
        let header = bytes
            .get(..BUD3_FRAME_HEADER_LEN)
            .ok_or(FrameWireError::Truncated)?;
        let payload = bytes
            .get(BUD3_FRAME_HEADER_LEN..)
            .ok_or(FrameWireError::Truncated)?;
        if payload.is_empty() {
            return Err(FrameWireError::Truncated);
        }
        if header.get(..4) != Some(BUD3_FRAME_MAGIC.as_slice()) {
            return Err(FrameWireError::BadMagic);
        }
        let kind_tag = header.get(4).copied().ok_or(FrameWireError::Truncated)?;
        let kind = match kind_tag {
            KIND_SOURCE => SymbolKind::Source,
            KIND_REPAIR => SymbolKind::Repair,
            other => return Err(FrameWireError::BadKind(other)),
        };
        let reserved = header.get(5).copied().ok_or(FrameWireError::Truncated)?;
        if reserved != 0 {
            return Err(FrameWireError::ReservedNonZero(reserved));
        }

        let mut seg_buf = [0u8; 8];
        seg_buf.copy_from_slice(header.get(6..14).ok_or(FrameWireError::Truncated)?);
        let segment = u64::from_le_bytes(seg_buf);

        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(header.get(14..18).ok_or(FrameWireError::Truncated)?);
        let segment_len = u32::from_le_bytes(len_buf);

        let mut esi_buf = [0u8; 4];
        esi_buf.copy_from_slice(header.get(18..22).ok_or(FrameWireError::Truncated)?);
        let esi = u32::from_le_bytes(esi_buf);

        let mut k_buf = [0u8; 4];
        k_buf.copy_from_slice(header.get(22..26).ok_or(FrameWireError::Truncated)?);
        let source_symbols = u32::from_le_bytes(k_buf);

        if segment_len == 0 || source_symbols == 0 {
            return Err(FrameWireError::BadGeometry);
        }
        if esi > MAX_ESI {
            return Err(FrameWireError::EsiOutOfRange(esi));
        }
        let expected_k = u64::from(segment_len).div_ceil(payload.len() as u64);
        if expected_k != u64::from(source_symbols) {
            return Err(FrameWireError::BadGeometry);
        }
        let expected_kind = if esi < source_symbols {
            SymbolKind::Source
        } else {
            SymbolKind::Repair
        };
        if kind != expected_kind {
            return Err(FrameWireError::BadKind(kind_tag));
        }

        meter.charge_bytes(payload.len() as u64)?;
        meter.charge_steps(1)?;
        Ok(Self {
            kind,
            segment,
            segment_len,
            esi,
            source_symbols,
            data: payload.to_vec(),
        })
    }

    /// Domain-separated digest of this logical frame (`BDLM_BUD3_FRAME_V1`).
    /// Never includes PNG, BDLV, or H.264 container bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let kind_tag = match self.kind {
            SymbolKind::Source => KIND_SOURCE,
            SymbolKind::Repair => KIND_REPAIR,
        };
        hash_fields_bytes(&[
            BUD3_FRAME_TAG,
            &[kind_tag],
            &self.segment.to_le_bytes(),
            &self.segment_len.to_le_bytes(),
            &self.esi.to_le_bytes(),
            &self.source_symbols.to_le_bytes(),
            &self.data,
        ])
    }
}

/// Emit ordered logical frames (`0..k` source symbols followed by
/// `repair_per_segment` derived repair symbols per segment) for serialized
/// BOF-1 `object_bytes` under `profile`.
///
/// # Errors
///
/// Returns [`FrameWireError`] if `object_bytes` is empty or profile coding fails.
pub fn frames_for_object_bytes(
    object_bytes: &[u8],
    profile: &Profile,
    repair_per_segment: u32,
) -> Result<Vec<Bud3Frame>, FrameWireError> {
    let seg =
        Segmentation::new(object_bytes.len() as u64, profile).ok_or(FrameWireError::BadGeometry)?;
    let mut frames = Vec::new();
    for seg_idx in 0..seg.count() {
        let range = seg.byte_range(seg_idx).ok_or(FrameWireError::BadGeometry)?;
        let start = usize::try_from(range.start).map_err(|_| FrameWireError::BadGeometry)?;
        let end = usize::try_from(range.end).map_err(|_| FrameWireError::BadGeometry)?;
        let slice = object_bytes
            .get(start..end)
            .ok_or(FrameWireError::BadGeometry)?;
        let seg_len = u32::try_from(slice.len()).map_err(|_| FrameWireError::BadGeometry)?;
        let enc = SegmentEncoder::new(seg_idx, slice, profile)?;
        let k = enc.k();
        for sym in enc.source_symbols() {
            frames.push(Bud3Frame::from_symbol(sym, seg_len, k)?);
        }
        for sym in enc.repair_symbols(0, repair_per_segment)? {
            frames.push(Bud3Frame::from_symbol(sym, seg_len, k)?);
        }
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::super::bof1::Object;
    use super::*;

    #[test]
    fn p0_frame_fits_qr_v40_budget_and_round_trips() {
        let obj = Object::raw_public(&[0x5au8; 4096]);
        let frames = frames_for_object_bytes(&obj.encode(), &Profile::P0, 2).unwrap();
        assert!(!frames.is_empty());
        for f in &frames {
            let wire = f.encode_wire();
            assert_eq!(wire.len(), BUD3_FRAME_HEADER_LEN + 2911);
            assert!(wire.len() <= crate::storage::qr_encode::MAX_DATA_BYTES);
            let mut m = Meter::for_object(1 << 20);
            let parsed = Bud3Frame::decode_wire(&wire, &mut m).unwrap();
            assert_eq!(&parsed, f);
        }
    }

    #[test]
    fn malformed_frames_refuse_without_panicking() {
        let obj = Object::raw_public(b"frame check");
        let f = frames_for_object_bytes(&obj.encode(), &Profile::P0, 0)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let good = f.encode_wire();
        let mut m = Meter::for_object(1 << 20);

        assert_eq!(
            Bud3Frame::decode_wire(&good[..10], &mut m),
            Err(FrameWireError::Truncated)
        );
        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            Bud3Frame::decode_wire(&bad_magic, &mut m),
            Err(FrameWireError::BadMagic)
        );
        let mut bad_res = good.clone();
        bad_res[5] = 1;
        assert_eq!(
            Bud3Frame::decode_wire(&bad_res, &mut m),
            Err(FrameWireError::ReservedNonZero(1))
        );
        let mut bad_kind = good;
        bad_kind[4] = KIND_REPAIR;
        assert_eq!(
            Bud3Frame::decode_wire(&bad_kind, &mut m),
            Err(FrameWireError::BadKind(KIND_REPAIR))
        );
    }
}
