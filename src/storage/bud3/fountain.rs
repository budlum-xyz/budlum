//! A2: the RFC 6330 (RaptorQ) fountain code.
//!
//! Each segment is one RFC 6330 source block, coded on its own with source
//! block number 0, one sub-block and alignment 1. The code is systematic: the
//! first `k` symbols (ESI `0..k`) are the segment bytes, the last one
//! zero-padded to the symbol size; repair symbols have ESI `k` and above and
//! are derived from the source symbols, so an object never stores them.
//!
//! The implementation is the `raptorq` crate, pinned with `=` in
//! `Cargo.toml`. The golden vectors in `tests/vectors/bud3/fountain/` lock the
//! symbols that crate version produces: a different version that changes one
//! byte fails the test.
//!
//! The decoder takes untrusted symbols. It checks every symbol (segment,
//! length, ESI range) before the crate sees it, so a malformed symbol is
//! refused and never reaches a crate assertion, and it caps the symbols it
//! keeps so a flood of repair symbols cannot grow its memory.

use super::limits::Profile;
use super::meter::{Meter, MeterError};
use super::segment::{object_commitment, segment_digest, ObjectCommitment, Segmentation};
use raptorq::{
    extended_source_block_symbols, EncodingPacket, ObjectTransmissionInformation, PayloadId,
    SourceBlockDecoder, SourceBlockEncoder,
};
use std::io::Read;

/// RFC 6330 carries the ESI in 24 bits.
pub const MAX_ESI: u32 = (1 << 24) - 1;

/// The decoder keeps at most this many symbols beyond `k`.
pub const MAX_EXTRA_SYMBOLS: u32 = 1024;

/// One coded symbol of one segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Segment index in the object.
    pub segment: u64,
    /// Encoding symbol id inside the segment.
    pub esi: u32,
    /// Exactly `symbol_size` bytes.
    pub data: Vec<u8>,
}

/// Source or repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// ESI below `k`: a slice of the segment bytes.
    Source,
    /// ESI at or above `k`: derived.
    Repair,
}

impl Symbol {
    /// Source when `esi < k`, repair otherwise.
    #[must_use]
    pub const fn kind(&self, k: u32) -> SymbolKind {
        if self.esi < k {
            SymbolKind::Source
        } else {
            SymbolKind::Repair
        }
    }
}

/// Why coding failed or a symbol was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FountainError {
    /// The profile is not usable for RFC 6330.
    InvalidProfile,
    /// The segment is longer than `k_max x symbol_size`.
    SegmentTooLong { len: u64, max: u64 },
    /// The symbol belongs to another segment.
    WrongSegment { want: u64, got: u64 },
    /// The symbol is not `symbol_size` bytes.
    WrongSymbolSize { want: usize, got: usize },
    /// The ESI is outside the RFC 6330 range for this segment.
    EsiOutOfRange(u32),
    /// The decoder already holds its cap of symbols.
    TooManySymbols,
    /// The meter refused the symbol.
    Budget(MeterError),
    /// Reading the object failed or ended early.
    Io(String),
    /// The object length does not fit this platform.
    TooLarge,
}

impl From<MeterError> for FountainError {
    fn from(e: MeterError) -> Self {
        Self::Budget(e)
    }
}

fn oti(padded_len: u64, profile: &Profile) -> ObjectTransmissionInformation {
    ObjectTransmissionInformation::new(padded_len, profile.symbol_size, 1, 1, 1)
}

/// `k` for a segment of `len` bytes: at least one symbol.
fn source_count(len: u64, symbol_size: u16) -> u64 {
    len.div_ceil(u64::from(symbol_size)).max(1)
}

/// The largest repair index for `k` source symbols: the ISI
/// (`esi + K' - k`) must stay inside 24 bits.
fn max_esi(k: u32) -> u32 {
    let padding = extended_source_block_symbols(k).saturating_sub(k);
    MAX_ESI.saturating_sub(padding)
}

/// The encoder of one segment.
pub struct SegmentEncoder {
    segment: u64,
    k: u32,
    encoder: SourceBlockEncoder,
}

impl SegmentEncoder {
    /// Code segment `segment` with bytes `bytes` under `profile`.
    ///
    /// # Errors
    ///
    /// [`FountainError::InvalidProfile`] or [`FountainError::SegmentTooLong`].
    pub fn new(segment: u64, bytes: &[u8], profile: &Profile) -> Result<Self, FountainError> {
        if !profile.is_valid() {
            return Err(FountainError::InvalidProfile);
        }
        let len = bytes.len() as u64;
        if len > profile.segment_bytes() {
            return Err(FountainError::SegmentTooLong {
                len,
                max: profile.segment_bytes(),
            });
        }
        let k64 = source_count(len, profile.symbol_size);
        let k = u32::try_from(k64).map_err(|_| FountainError::TooLarge)?;
        let padded_len = k64 * u64::from(profile.symbol_size);
        let padded_usize = usize::try_from(padded_len).map_err(|_| FountainError::TooLarge)?;
        let mut padded = Vec::with_capacity(padded_usize);
        padded.extend_from_slice(bytes);
        padded.resize(padded_usize, 0);
        let encoder = SourceBlockEncoder::new(0, &oti(padded_len, profile), &padded);
        Ok(Self {
            segment,
            k,
            encoder,
        })
    }

    /// `k`, the number of source symbols.
    #[must_use]
    pub const fn k(&self) -> u32 {
        self.k
    }

    fn wrap(&self, packet: EncodingPacket) -> Symbol {
        let (id, data) = packet.split();
        Symbol {
            segment: self.segment,
            esi: id.encoding_symbol_id(),
            data,
        }
    }

    /// The `k` source symbols, ESI `0..k`.
    #[must_use]
    pub fn source_symbols(&self) -> Vec<Symbol> {
        self.encoder
            .source_packets()
            .into_iter()
            .map(|p| self.wrap(p))
            .collect()
    }

    /// `count` repair symbols starting at repair index `first` (ESI
    /// `k + first ..`). Repair generation is deterministic: the same index
    /// always gives the same bytes, so repair makes new symbols, never copies.
    ///
    /// # Errors
    ///
    /// [`FountainError::EsiOutOfRange`] when the last ESI leaves the RFC 6330
    /// range.
    pub fn repair_symbols(&self, first: u32, count: u32) -> Result<Vec<Symbol>, FountainError> {
        let last = self
            .k
            .checked_add(first)
            .and_then(|e| e.checked_add(count.saturating_sub(1)))
            .ok_or(FountainError::EsiOutOfRange(u32::MAX))?;
        if last > max_esi(self.k) {
            return Err(FountainError::EsiOutOfRange(last));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        Ok(self
            .encoder
            .repair_packets(first, count)
            .into_iter()
            .map(|p| self.wrap(p))
            .collect())
    }
}

/// The decoder of one segment.
pub struct SegmentDecoder {
    segment: u64,
    len: u64,
    k: u32,
    symbol_size: usize,
    held: u32,
    decoder: SourceBlockDecoder,
    result: Option<Vec<u8>>,
}

impl SegmentDecoder {
    /// A decoder for segment `segment` of `len` bytes. The length comes from
    /// the object length and the profile, never from a symbol.
    ///
    /// # Errors
    ///
    /// [`FountainError::InvalidProfile`] or [`FountainError::SegmentTooLong`].
    pub fn new(segment: u64, len: u64, profile: &Profile) -> Result<Self, FountainError> {
        if !profile.is_valid() {
            return Err(FountainError::InvalidProfile);
        }
        if len > profile.segment_bytes() {
            return Err(FountainError::SegmentTooLong {
                len,
                max: profile.segment_bytes(),
            });
        }
        let k64 = source_count(len, profile.symbol_size);
        let k = u32::try_from(k64).map_err(|_| FountainError::TooLarge)?;
        let padded_len = k64 * u64::from(profile.symbol_size);
        Ok(Self {
            segment,
            len,
            k,
            symbol_size: usize::from(profile.symbol_size),
            held: 0,
            decoder: SourceBlockDecoder::new(0, &oti(padded_len, profile), padded_len),
            result: None,
        })
    }

    /// `k`.
    #[must_use]
    pub const fn k(&self) -> u32 {
        self.k
    }

    /// Whether the segment is recovered.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.result.is_some()
    }

    /// Offer one symbol. Returns the segment bytes once enough independent
    /// symbols have arrived; later symbols are ignored.
    ///
    /// # Errors
    ///
    /// [`FountainError`] for a symbol of another segment, of the wrong size,
    /// with an ESI outside the range, beyond the symbol cap, or beyond the
    /// meter.
    pub fn push(
        &mut self,
        symbol: Symbol,
        meter: &mut Meter,
    ) -> Result<Option<&[u8]>, FountainError> {
        if self.result.is_some() {
            return Ok(self.result.as_deref());
        }
        if symbol.segment != self.segment {
            return Err(FountainError::WrongSegment {
                want: self.segment,
                got: symbol.segment,
            });
        }
        if symbol.data.len() != self.symbol_size {
            return Err(FountainError::WrongSymbolSize {
                want: self.symbol_size,
                got: symbol.data.len(),
            });
        }
        if symbol.esi > max_esi(self.k) {
            return Err(FountainError::EsiOutOfRange(symbol.esi));
        }
        if self.held >= self.k.saturating_add(MAX_EXTRA_SYMBOLS) {
            return Err(FountainError::TooManySymbols);
        }
        meter.charge_bytes(symbol.data.len() as u64)?;
        meter.charge_steps(1)?;
        self.held = self.held.saturating_add(1);
        let packet = EncodingPacket::new(PayloadId::new(0, symbol.esi), symbol.data);
        if let Some(mut bytes) = self.decoder.decode(std::iter::once(packet)) {
            let len = usize::try_from(self.len).map_err(|_| FountainError::TooLarge)?;
            bytes.truncate(len);
            self.result = Some(bytes);
        }
        Ok(self.result.as_deref())
    }

    /// The recovered bytes, if any.
    #[must_use]
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        self.result
    }
}

/// Stream an object through A2: read it segment by segment from `reader`,
/// hand every source symbol and `repair_per_segment` repair symbols to
/// `sink`, and return the object commitment. One segment buffer and one
/// encoder are alive at a time, so memory is bounded by two segments whatever
/// the object length.
///
/// # Errors
///
/// [`FountainError::Io`] when the reader fails or ends before `object_len`
/// bytes, a coding error, or the error `sink` returns.
pub fn encode_stream<R, F>(
    mut reader: R,
    object_len: u64,
    profile: &Profile,
    repair_per_segment: u32,
    mut sink: F,
) -> Result<ObjectCommitment, FountainError>
where
    R: Read,
    F: FnMut(Symbol) -> Result<(), FountainError>,
{
    let seg = Segmentation::new(object_len, profile).ok_or(FountainError::InvalidProfile)?;
    let mut digests = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    for index in 0..seg.count() {
        let len = seg.len(index).ok_or(FountainError::TooLarge)?;
        let len = usize::try_from(len).map_err(|_| FountainError::TooLarge)?;
        buf.clear();
        buf.resize(len, 0);
        reader
            .read_exact(&mut buf)
            .map_err(|e| FountainError::Io(e.to_string()))?;
        digests.push(segment_digest(index, &buf));
        let enc = SegmentEncoder::new(index, &buf, profile)?;
        for s in enc.source_symbols() {
            sink(s)?;
        }
        for s in enc.repair_symbols(0, repair_per_segment)? {
            sink(s)?;
        }
    }
    Ok(object_commitment(&digests))
}

#[cfg(test)]
mod tests {
    use super::super::segment::commit_object;
    use super::*;
    use sha2::{Digest, Sha256};

    const SMALL: Profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 64,
        fps: 10,
        k_max: 32,
    };

    fn pattern(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 0xff) as u8
            })
            .collect()
    }

    fn big_meter() -> Meter {
        Meter::new(u64::MAX, u64::MAX)
    }

    #[test]
    fn source_symbols_are_the_segment_bytes() {
        let data = pattern(1000, 1);
        let enc = SegmentEncoder::new(0, &data, &SMALL).unwrap();
        assert_eq!(enc.k(), 16);
        let src = enc.source_symbols();
        assert_eq!(src.len(), 16);
        let mut joined: Vec<u8> = src.iter().flat_map(|s| s.data.clone()).collect();
        assert!(joined[1000..].iter().all(|b| *b == 0), "zero padding");
        joined.truncate(1000);
        assert_eq!(joined, data, "the code is systematic");
        assert!(src.iter().all(|s| s.kind(16) == SymbolKind::Source));
        let rep = enc.repair_symbols(0, 3).unwrap();
        assert_eq!(
            rep.iter().map(|s| s.esi).collect::<Vec<_>>(),
            vec![16, 17, 18]
        );
        assert!(rep.iter().all(|s| s.kind(16) == SymbolKind::Repair));
        assert_eq!(
            rep,
            enc.repair_symbols(0, 3).unwrap(),
            "repair is deterministic"
        );
    }

    #[test]
    fn any_k_symbols_mostly_recover_the_segment() {
        // Drop every source symbol with an even ESI and replace them with
        // repair symbols: the segment comes back bit for bit.
        let data = pattern(32 * 64 - 7, 2);
        let enc = SegmentEncoder::new(5, &data, &SMALL).unwrap();
        let k = enc.k();
        let mut symbols: Vec<Symbol> = enc
            .source_symbols()
            .into_iter()
            .filter(|s| s.esi % 2 == 1)
            .collect();
        symbols.extend(enc.repair_symbols(0, k / 2 + 2).unwrap());
        let mut dec = SegmentDecoder::new(5, data.len() as u64, &SMALL).unwrap();
        let mut meter = big_meter();
        for s in symbols {
            dec.push(s, &mut meter).unwrap();
        }
        assert!(dec.is_done());
        assert_eq!(dec.into_bytes().unwrap(), data);
    }

    #[test]
    fn repair_only_recovers_the_segment() {
        let data = pattern(700, 3);
        let enc = SegmentEncoder::new(0, &data, &SMALL).unwrap();
        let mut dec = SegmentDecoder::new(0, 700, &SMALL).unwrap();
        let mut meter = big_meter();
        for s in enc.repair_symbols(100, enc.k() + 4).unwrap() {
            dec.push(s, &mut meter).unwrap();
        }
        assert_eq!(dec.into_bytes().unwrap(), data);
    }

    #[test]
    fn bud3_fountain_acceptance_small_loss_sweep() {
        // A reduced form of the nightly acceptance run: 5 % loss with 30 %
        // repair must decode every time across many seeds.
        let data = pattern(32 * 64, 4);
        let enc = SegmentEncoder::new(0, &data, &SMALL).unwrap();
        let k = enc.k();
        let mut all = enc.source_symbols();
        all.extend(enc.repair_symbols(0, k * 3 / 10).unwrap());
        for seed in 0..40u32 {
            let mut dec = SegmentDecoder::new(0, data.len() as u64, &SMALL).unwrap();
            let mut meter = big_meter();
            let drops = pattern(all.len(), 1000 + seed);
            for (s, d) in all.iter().zip(drops) {
                if d % 20 != 0 {
                    dec.push(s.clone(), &mut meter).unwrap();
                }
            }
            assert_eq!(dec.into_bytes().as_deref(), Some(&data[..]), "seed {seed}");
        }
    }

    #[test]
    fn malformed_symbols_are_refused_before_the_crate() {
        let mut dec = SegmentDecoder::new(2, 100, &SMALL).unwrap();
        let mut m = big_meter();
        let wrong_seg = Symbol {
            segment: 1,
            esi: 0,
            data: vec![0; 64],
        };
        assert_eq!(
            dec.push(wrong_seg, &mut m).unwrap_err(),
            FountainError::WrongSegment { want: 2, got: 1 }
        );
        let short = Symbol {
            segment: 2,
            esi: 0,
            data: vec![0; 63],
        };
        assert_eq!(
            dec.push(short, &mut m).unwrap_err(),
            FountainError::WrongSymbolSize { want: 64, got: 63 }
        );
        let far = Symbol {
            segment: 2,
            esi: MAX_ESI,
            data: vec![0; 64],
        };
        assert!(matches!(
            dec.push(far, &mut m).unwrap_err(),
            FountainError::EsiOutOfRange(_)
        ));
        let mut tiny = Meter::new(10, 10);
        let ok = Symbol {
            segment: 2,
            esi: 0,
            data: vec![0; 64],
        };
        assert!(matches!(
            dec.push(ok, &mut tiny).unwrap_err(),
            FountainError::Budget(_)
        ));
    }

    #[test]
    fn a_symbol_flood_is_capped() {
        let enc = SegmentEncoder::new(0, &pattern(64 * 32, 5), &SMALL).unwrap();
        let k = enc.k();
        // Repeat one repair symbol: duplicates never decode, and the cap stops
        // the decoder holding more than k + MAX_EXTRA_SYMBOLS.
        let one = enc.repair_symbols(0, 1).unwrap().remove(0);
        let mut dec = SegmentDecoder::new(0, 64 * 32, &SMALL).unwrap();
        let mut m = big_meter();
        let mut refused = false;
        for _ in 0..(k + MAX_EXTRA_SYMBOLS + 1) {
            if dec.push(one.clone(), &mut m) == Err(FountainError::TooManySymbols) {
                refused = true;
                break;
            }
        }
        assert!(refused, "the flood hit the cap");
        assert!(!dec.is_done());
    }

    #[test]
    fn oversized_segments_and_invalid_profiles_are_refused() {
        let too_long = vec![0u8; SMALL.segment_bytes() as usize + 1];
        assert!(matches!(
            SegmentEncoder::new(0, &too_long, &SMALL),
            Err(FountainError::SegmentTooLong { .. })
        ));
        let mut bad = SMALL;
        bad.k_max = 0;
        assert!(matches!(
            SegmentDecoder::new(0, 1, &bad),
            Err(FountainError::InvalidProfile)
        ));
        let enc = SegmentEncoder::new(0, b"x", &SMALL).unwrap();
        assert!(matches!(
            enc.repair_symbols(MAX_ESI, 1),
            Err(FountainError::EsiOutOfRange(_))
        ));
    }

    #[test]
    fn stream_encoding_matches_the_in_memory_commitment() {
        let object = pattern(64 * 32 * 3 + 500, 6);
        let mut per_segment: std::collections::BTreeMap<u64, Vec<Symbol>> = Default::default();
        let c = encode_stream(&object[..], object.len() as u64, &SMALL, 4, |s| {
            per_segment.entry(s.segment).or_default().push(s);
            Ok(())
        })
        .unwrap();
        assert_eq!(Some(c), commit_object(&object, &SMALL));
        assert_eq!(per_segment.len(), 4);
        // Decode every segment from its repair symbols plus the odd sources.
        let seg = Segmentation::new(object.len() as u64, &SMALL).unwrap();
        let mut rebuilt = Vec::new();
        for (index, symbols) in per_segment {
            let len = seg.len(index).unwrap();
            let mut dec = SegmentDecoder::new(index, len, &SMALL).unwrap();
            let mut m = big_meter();
            for s in symbols.into_iter().filter(|s| s.esi != 0) {
                dec.push(s, &mut m).unwrap();
            }
            rebuilt.extend(dec.into_bytes().unwrap());
        }
        assert_eq!(rebuilt, object);
    }

    #[test]
    fn a_short_reader_is_an_error() {
        let object = pattern(100, 7);
        let r = encode_stream(&object[..], 200, &SMALL, 0, |_| Ok(()));
        assert!(matches!(r, Err(FountainError::Io(_))));
    }

    /// The golden vector: a fixed P0 segment, its first 16 source symbols and
    /// 16 repair symbols, hashed. The file pins the bytes the pinned crate
    /// version produces.
    #[test]
    fn fountain_golden_vectors_lock_crate_version() {
        let p = Profile::P0;
        let data = pattern(usize::from(p.symbol_size) * 16 + 123, 42);
        let enc = SegmentEncoder::new(0, &data, &p).unwrap();
        assert_eq!(enc.k(), 17);
        let mut h = Sha256::new();
        for s in enc
            .source_symbols()
            .iter()
            .chain(enc.repair_symbols(0, 16).unwrap().iter())
        {
            h.update(s.esi.to_le_bytes());
            h.update(&s.data);
        }
        let got = hex::encode(h.finalize());
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/bud3/fountain/p0_k17.sha256"
        );
        let want = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            got,
            want.trim(),
            "raptorq output changed: the pinned version moved"
        );
    }
}
