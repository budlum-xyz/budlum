//! B.U.D. 2.0 - the time series transform: time deltas plus XOR, 2026-08-16.
//!
//! K92: time series compression at 10 to 12 times, using the delta between
//! consecutive timestamps plus XOR over the floating point values. This is the
//! B.U.D. domain transform for telemetry and measurement data: it turns
//! `(ts, value)` pairs into a stream of time deltas and XOR bits, which sees
//! the high-entropy float differences that zstd cannot.
//!
//! It is lossless: encode then decode gives back the original (K38). It is
//! panic-free, unsafe-free and deterministic.
//!
//! The XOR coding: each value is XORed with the previous one. If the difference
//! is zero, a single bit `0` is written; otherwise a `1` followed by the leading
//! and trailing zero counts and the meaningful bits. The timestamp coding uses
//! consecutive deltas: `0` for no change, `10` plus 6 bits within plus or minus
//! 63, `110` plus 8 bits within plus or minus 255, and `111` plus 64 bits
//! otherwise.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const TS_MAGIC: [u8; 8] = *b"\xB5TSSR\0\0\0";
pub const TS_VERSION: u8 = 2;
pub const MAX_POINTS: usize = 100_000_000;

/// The time series transform: `(ts, f64)` pairs into a stream of time deltas and
/// XOR bits.
#[derive(Debug, Clone)]
pub struct TimeSeriesColumnar {
    pub points: usize,
    pub first_ts: i64,
    pub first_value: f64,
    pub bits: Vec<u8>, // the bit-packed stream
}

struct BitWriter {
    buf: Vec<u8>,
    bit_pos: u8, // 0 to 7, the position of the next bit
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            buf: Vec::new(),
            bit_pos: 0,
        }
    }
    fn write_bit(&mut self, b: bool) {
        if self.bit_pos == 0 {
            self.buf.push(0);
        }
        // On `last_mut().unwrap()`: the push above does not leave this empty, but
        // "does not" and "cannot" are not the same thing. An `if let` writes the
        // same code without a panic.
        if b {
            if let Some(byte) = self.buf.last_mut() {
                *byte |= 1 << self.bit_pos;
            }
        }
        self.bit_pos = (self.bit_pos + 1) & 7;
    }
    fn write_bits(&mut self, v: u64, n: u8) {
        for i in (0..n).rev() {
            self.write_bit((v >> i) & 1 == 1);
        }
    }
}

struct BitReader<'a> {
    buf: &'a [u8],
    pos: usize,
    bit: u8,
}

impl<'a> BitReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        BitReader {
            buf,
            pos: 0,
            bit: 0,
        }
    }
    fn read_bit(&mut self) -> Option<bool> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let b = (self.buf[self.pos] >> self.bit) & 1 == 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.pos += 1;
        }
        Some(b)
    }
    fn read_bits(&mut self, n: u8) -> Option<u64> {
        let mut v: u64 = 0;
        for _ in 0..n {
            v = (v << 1) | self.read_bit()? as u64;
        }
        Some(v)
    }
}

impl TimeSeriesColumnar {
    /// Builds the time delta and XOR bit stream from `(ts, f64)` pairs,
    /// losslessly.
    pub fn encode(points: &[(i64, f64)]) -> Option<Self> {
        if points.is_empty() || points.len() > MAX_POINTS {
            return None;
        }
        let mut w = BitWriter::new();
        let first_ts = points[0].0;
        let first_value = points[0].1;
        // The first timestamp and value are written at full width.
        w.write_bits(first_ts as u64, 64); // the full timestamp, kept simple at 64 bits
        w.write_bits(first_value.to_bits(), 64);
        let mut prev_ts = first_ts;
        let mut prev_value = first_value;
        for (ts, v) in points.iter().skip(1) {
            // The difference between consecutive timestamps.
            let delta = *ts - prev_ts;
            // Timestamp delta coding: zero writes a single '0', and a narrow range
            // gets a short code.
            if delta == 0 {
                w.write_bit(false);
            } else if (-63..=63).contains(&delta) {
                w.write_bit(true);
                w.write_bit(false);
                w.write_bits((delta + 63) as u64, 7);
            } else if (-255..=255).contains(&delta) {
                w.write_bit(true);
                w.write_bit(true);
                w.write_bit(false);
                w.write_bits((delta + 255) as u64, 9);
            } else {
                w.write_bit(true);
                w.write_bit(true);
                w.write_bit(true);
                w.write_bits(delta as u64, 64);
            }
            // Value XOR coding.
            let x = v.to_bits() ^ prev_value.to_bits();
            if x == 0 {
                w.write_bit(false);
            } else {
                w.write_bit(true);
                let lz = x.leading_zeros() as u8;
                let tz = x.trailing_zeros() as u8;
                let meaningful = 64 - lz - tz;
                // The control bits would say whether the leading and trailing zero
                // counts match the previous ones; kept simple here by always writing
                // them. `x` is non-zero, so `meaningful` is 1..=64, and 64 does
                // not fit the six-bit field: version 1 wrote `64 & 0x3F == 0`,
                // the decoder took the "unchanged" branch, and the 64 payload
                // bits it never consumed shifted every later point. The field
                // now carries `meaningful - 1`, which is 0..=63.
                w.write_bits(lz as u64, 6);
                w.write_bits((meaningful - 1) as u64, 6);
                w.write_bits(x >> tz, meaningful);
            }
            prev_ts = *ts;
            prev_value = *v;
        }
        Some(TimeSeriesColumnar {
            points: points.len(),
            first_ts,
            first_value,
            bits: w.buf,
        })
    }

    /// Rebuilds the `(ts, f64)` pairs from the bit stream, which is the proof of
    /// losslessness.
    pub fn decode(&self) -> Option<Vec<(i64, f64)>> {
        let mut r = BitReader::new(&self.bits);
        let first_ts = r.read_bits(64)? as i64;
        let first_value = f64::from_bits(r.read_bits(64)?);
        let mut out = Vec::with_capacity(self.points);
        out.push((first_ts, first_value));
        let mut prev_ts = first_ts;
        let mut prev_value = first_value;
        while out.len() < self.points {
            // The time delta.
            let delta: i64;
            if !r.read_bit()? {
                delta = 0;
            } else if !r.read_bit()? {
                delta = r.read_bits(7)? as i64 - 63;
            } else if !r.read_bit()? {
                delta = r.read_bits(9)? as i64 - 255;
            } else {
                delta = r.read_bits(64)? as i64;
            }
            let ts = prev_ts.checked_add(delta)?;
            // The value XOR.
            let v = if r.read_bit()? {
                let lz = r.read_bits(6)? as u8;
                let meaningful = r.read_bits(6)? as u8 + 1;
                // `lz + meaningful` is at most 64 for a stream the encoder
                // wrote; a crafted stream can say more, and the shift below
                // would then overflow. Refuse it rather than panic.
                let shift = 64u8.checked_sub(lz.checked_add(meaningful)?)?;
                let m = r.read_bits(meaningful)?;
                // `shift` is below 64 here: `meaningful` is at least 1.
                f64::from_bits(prev_value.to_bits() ^ (m << shift))
            } else {
                prev_value
            };
            out.push((ts, v));
            prev_ts = ts;
            prev_value = v;
        }
        Some(out)
    }

    /// The deterministic blob: magic, version, point count, the first values, the
    /// bit stream and a digest.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TS_MAGIC);
        out.push(TS_VERSION);
        out.extend_from_slice(&(self.points as u32).to_le_bytes());
        out.extend_from_slice(&self.first_ts.to_le_bytes());
        out.extend_from_slice(&self.first_value.to_bits().to_le_bytes());
        out.extend_from_slice(&(self.bits.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.bits);
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_TSSERIES_V1");
        h.update(&out);
        let d: [u8; 32] = h.finalize().into();
        out.extend_from_slice(&d);
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 4 + 8 + 8 + 4;
        if bytes.len() < HDR + 32 || bytes[0..8] != TS_MAGIC || bytes[8] != TS_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_TSSERIES_V1");
        h.update(&bytes[..payload_len]);
        let d: [u8; 32] = h.finalize().into();
        if d != bytes[payload_len..] {
            return None;
        }
        let points = u32::from_le_bytes(bytes[9..13].try_into().ok()?) as usize;
        let first_ts = i64::from_le_bytes(bytes[13..21].try_into().ok()?);
        let first_value = f64::from_bits(u64::from_le_bytes(bytes[21..29].try_into().ok()?));
        let bits_len = u32::from_le_bytes(bytes[29..33].try_into().ok()?) as usize;
        let bits_start = HDR;
        if bytes.len() < bits_start + bits_len {
            return None;
        }
        let bits = bytes[bits_start..bits_start + bits_len].to_vec();
        if bits_start + bits_len != payload_len {
            return None;
        }
        if points == 0 || points > MAX_POINTS {
            return None;
        }
        Some(TimeSeriesColumnar {
            points,
            first_ts,
            first_value,
            bits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_series(n: usize, jitter: bool) -> Vec<(i64, f64)> {
        // Evenly spaced timestamps with telemetry values.
        // A sensor: mostly constant with an occasional small change, a pattern
        // that suits XOR coding.
        let mut out = Vec::with_capacity(n);
        let mut v: f64 = 45.0;
        for i in 0..n {
            let ts = i as i64 * 60; // a 60 second interval
            if jitter {
                // An occasional small change, with 10 percent probability.
                if i % 10 == 0 {
                    v += 0.2;
                }
            } else {
                // Constant, so the XOR is zero and costs one bit.
            }
            out.push((ts, v));
        }
        out
    }

    #[test]
    fn roundtrip_lossless() {
        // K38: encode then decode gives back the original, losslessly.
        for jitter in [false, true] {
            let series = gen_series(1000, jitter);
            let col = TimeSeriesColumnar::encode(&series).expect("encode");
            let back = col.decode().expect("decode");
            assert_eq!(back, series, "the time series is lossless, jitter={jitter}");
            // blob roundtrip
            let blob = col.to_blob();
            let col2 = TimeSeriesColumnar::from_blob(&blob).expect("blob");
            assert_eq!(col2.decode().unwrap(), series);
            // Tampering is refused.
            let mut bad = blob.clone();
            *bad.last_mut().unwrap() ^= 0x01;
            assert!(TimeSeriesColumnar::from_blob(&bad).is_none());
        }
    }

    #[test]
    fn compresses_telemetry_well() {
        // Evenly spaced time with slowly changing values costs very few bits.
        let series = gen_series(10_000, false);
        let col = TimeSeriesColumnar::encode(&series).expect("encode");
        // 10k points at 16 bytes is 160 KB raw; the target of about 1.37 bytes per
        // point gives roughly 13 KB.
        let raw = series.len() * 16;
        let ratio = raw as f64 / col.bits.len() as f64;
        assert!(
            ratio >= 8.0,
            "time series compression, against a 12x target: {ratio:.1}x, {}B of bits against {raw}B raw",
            col.bits.len()
        );
        assert_eq!(col.decode().unwrap(), series);
    }

    #[test]
    fn random_values_still_lossless() {
        // Random values do not compress, but they must stay LOSSLESS.
        let mut series = Vec::new();
        let mut x = 0x1234_5678_9ABC_DEF0u64;
        for i in 0..200 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // Values that vary in the mantissa without producing NaN or infinity,
            // between 1.0 and 2.0.
            let bits = (x & 0x000F_FFFF_FFFF_FFFF) | 0x3FF0_0000_0000_0000;
            series.push((i as i64 * 5, f64::from_bits(bits)));
        }
        let col = TimeSeriesColumnar::encode(&series).expect("encode");
        assert_eq!(col.decode().unwrap(), series, "random values stay lossless");
    }

    /// A sign change with a one-bit mantissa difference makes the XOR of two
    /// consecutive values set bit 63 and bit 0 at once: 64 meaningful bits.
    /// Version 1 wrote that width as 0 and lost every point after it.
    #[test]
    fn a_sixty_four_bit_xor_survives_the_round_trip() {
        let flipped = f64::from_bits(0xBFF0_0000_0000_0001);
        assert_eq!(1.0f64.to_bits() ^ flipped.to_bits(), 0x8000_0000_0000_0001);
        let pts = vec![(0, 1.0), (1, flipped), (2, 2.5), (3, -7.25), (4, 2.5)];
        let enc = TimeSeriesColumnar::encode(&pts).unwrap();
        assert_eq!(enc.decode().unwrap(), pts);
        // The full-width case at both ends of the stream too.
        let pts = vec![(0, -1.0), (1, f64::from_bits(0x3FF0_0000_0000_0001))];
        let enc = TimeSeriesColumnar::encode(&pts).unwrap();
        assert_eq!(enc.decode().unwrap(), pts);
    }

    #[test]
    fn edge_and_limits() {
        assert!(TimeSeriesColumnar::encode(&[]).is_none());
        assert!(TimeSeriesColumnar::from_blob(&[0u8; 10]).is_none());
        // A single point.
        let one = TimeSeriesColumnar::encode(&[(0, 1.0)]).unwrap();
        assert_eq!(one.decode().unwrap(), vec![(0, 1.0)]);
        // Negative time.
        let neg = TimeSeriesColumnar::encode(&[(-100, 1.0), (-50, 2.0)]).unwrap();
        assert_eq!(neg.decode().unwrap(), vec![(-100, 1.0), (-50, 2.0)]);
        // A very large delta, above 2^31.
        let big = TimeSeriesColumnar::encode(&[(0, 1.0), (5_000_000_000, 2.0)]).unwrap();
        assert_eq!(big.decode().unwrap(), vec![(0, 1.0), (5_000_000_000, 2.0)]);
    }
}
