//! B.U.D. 2.0 - Zaman Serisi Transformu (zaman farkı + XOR) (2026-08-16)
//!
//! K92: zaman serisi sıkıştırması 10-12x (ardışık zaman damgası farkı
//! + XOR kayan nokta değerleri). B.U.D. telemetri/ölçüm verisi için domain transformu:
//!   (ts, value) çiftlerini zaman farkı + XOR bit akışına çevirir - zstd'nin
//!   göremediği yüksek entropili float farklarını görür.
//!
//! Kayıpsız: encode → decode = orijinal (K38). Panik'siz, no unsafe, deterministik.
//!
//! XOR kodlama: her değer bir öncekiyle XOR'lanır; fark 0 ise 1 bit '0';
//! değilse '1' + leading/trailing zero uzunlukları + anlamlı bitler. Zaman damgası:
//! ardışık fark (0 → '0', ±63 → '10'+6 bit, ±255 → '110'+8 bit, başka → '111'+64 bit).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const TS_MAGIC: [u8; 8] = *b"\xB5TSSR\0\0\0";
pub const TS_VERSION: u8 = 1;
pub const MAX_POINTS: usize = 100_000_000;

/// Zaman serisi transformu: (ts, f64) çiftleri → zaman farkı + XOR bit akışı.
#[derive(Debug, Clone)]
pub struct TimeSeriesColumnar {
    pub points: usize,
    pub first_ts: i64,
    pub first_value: f64,
    pub bits: Vec<u8>, // bit-paketli akış
}

struct BitWriter {
    buf: Vec<u8>,
    bit_pos: u8, // 0..7 (sonraki bitin konumu)
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
        // `last_mut().unwrap()`: yukaridaki push bunu bos birakmaz, ama
        // "birakmaz" ile "birakamaz" ayni sey degil. `if let` ayni kodu
        // paniksiz yazar.
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
    /// (ts, f64) çiftlerinden zaman farkı + XOR bit akışı üret (kayıpsız).
    pub fn encode(points: &[(i64, f64)]) -> Option<Self> {
        if points.is_empty() || points.len() > MAX_POINTS {
            return None;
        }
        let mut w = BitWriter::new();
        let first_ts = points[0].0;
        let first_value = points[0].1;
        // İlk zaman damgası ve değer tam genişlikte yazılır.
        w.write_bits(first_ts as u64, 64); // tam ts (basit: 64 bit)
        w.write_bits(first_value.to_bits(), 64);
        let mut prev_ts = first_ts;
        let mut prev_value = first_value;
        for (ts, v) in points.iter().skip(1) {
            // Ardışık zaman damgaları arasındaki fark.
            let delta = *ts - prev_ts;
            // Zaman damgası delta kodlaması: 0 → '0', dar aralık → kısa kod.
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
            // Değer XOR kodlaması.
            let x = v.to_bits() ^ prev_value.to_bits();
            if x == 0 {
                w.write_bit(false);
            } else {
                w.write_bit(true);
                let lz = x.leading_zeros() as u8;
                let tz = x.trailing_zeros() as u8;
                let meaningful = 64 - lz - tz;
                // kontrol bitleri: lz/tz öncekiyle aynı mı (basit: her zaman yaz)
                w.write_bits(lz as u64, 6);
                w.write_bits(meaningful as u64, 6);
                if meaningful > 0 {
                    w.write_bits(x >> tz, meaningful);
                }
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

    /// Bit akışından (ts, f64) çiftlerini yeniden kur (kayıpsızlık kanıtı).
    pub fn decode(&self) -> Option<Vec<(i64, f64)>> {
        let mut r = BitReader::new(&self.bits);
        let first_ts = r.read_bits(64)? as i64;
        let first_value = f64::from_bits(r.read_bits(64)?);
        let mut out = Vec::with_capacity(self.points);
        out.push((first_ts, first_value));
        let mut prev_ts = first_ts;
        let mut prev_value = first_value;
        while out.len() < self.points {
            // zaman delta
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
            // değer XOR
            let v: f64;
            if !r.read_bit()? {
                v = prev_value;
            } else {
                let lz = r.read_bits(6)? as u8;
                let meaningful = r.read_bits(6)? as u8;
                if meaningful > 0 {
                    let m = r.read_bits(meaningful)?;
                    let x = m << (64 - lz - meaningful);
                    v = f64::from_bits(prev_value.to_bits() ^ x);
                } else {
                    v = prev_value;
                }
            }
            out.push((ts, v));
            prev_ts = ts;
            prev_value = v;
        }
        Some(out)
    }

    /// Deterministik blob (magic + sürüm + nokta sayısı + ilk değerler + bit akışı + digest).
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
        // sabit aralıklı zaman damgaları + telemetri değerleri
        // Sensör: çoğunlukla sabit, ara sıra küçük değişim; XOR kodlamasına uygun desen.
        let mut out = Vec::with_capacity(n);
        let mut v: f64 = 45.0;
        for i in 0..n {
            let ts = i as i64 * 60; // 60s aralık
            if jitter {
                // ara sıra küçük değişim (%10 olasılık)
                if i % 10 == 0 {
                    v += 0.2;
                }
            } else {
                // sabit (XOR=0 → 1 bit)
            }
            out.push((ts, v));
        }
        out
    }

    #[test]
    fn roundtrip_lossless() {
        // K38: encode → decode = orijinal (kayıpsız)
        for jitter in [false, true] {
            let series = gen_series(1000, jitter);
            let col = TimeSeriesColumnar::encode(&series).expect("encode");
            let back = col.decode().expect("decode");
            assert_eq!(back, series, "zaman serisi kayıpsız (jitter={jitter})");
            // blob roundtrip
            let blob = col.to_blob();
            let col2 = TimeSeriesColumnar::from_blob(&blob).expect("blob");
            assert_eq!(col2.decode().unwrap(), series);
            // kurcalama red
            let mut bad = blob.clone();
            *bad.last_mut().unwrap() ^= 0x01;
            assert!(TimeSeriesColumnar::from_blob(&bad).is_none());
        }
    }

    #[test]
    fn compresses_telemetry_well() {
        // Sabit aralıklı zaman + yavaş değişen değerler → çok az bit.
        let series = gen_series(10_000, false);
        let col = TimeSeriesColumnar::encode(&series).expect("encode");
        // 10k nokta × 16 bayt = 160KB ham; hedef ~1.37 bayt/nokta → ~13KB.
        let raw = series.len() * 16;
        let ratio = raw as f64 / col.bits.len() as f64;
        assert!(
            ratio >= 8.0,
            "Zaman serisi sıkıştırması (12x hedef): {ratio:.1}x (bits {}B vs raw {raw}B)",
            col.bits.len()
        );
        assert_eq!(col.decode().unwrap(), series);
    }

    #[test]
    fn random_values_still_lossless() {
        // rastgele değerler sıkışmaz ama KAYIPSIZ olmalı
        let mut series = Vec::new();
        let mut x = 0x1234_5678_9ABC_DEF0u64;
        for i in 0..200 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // NaN/Inf üretmeyen mantissa-değişken değerler (1.0..2.0 arası)
            let bits = (x & 0x000F_FFFF_FFFF_FFFF) | 0x3FF0_0000_0000_0000;
            series.push((i as i64 * 5, f64::from_bits(bits)));
        }
        let col = TimeSeriesColumnar::encode(&series).expect("encode");
        assert_eq!(col.decode().unwrap(), series, "rastgele değerler kayıpsız");
    }

    #[test]
    fn edge_and_limits() {
        assert!(TimeSeriesColumnar::encode(&[]).is_none());
        assert!(TimeSeriesColumnar::from_blob(&[0u8; 10]).is_none());
        // tek nokta
        let one = TimeSeriesColumnar::encode(&[(0, 1.0)]).unwrap();
        assert_eq!(one.decode().unwrap(), vec![(0, 1.0)]);
        // negatif zaman
        let neg = TimeSeriesColumnar::encode(&[(-100, 1.0), (-50, 2.0)]).unwrap();
        assert_eq!(neg.decode().unwrap(), vec![(-100, 1.0), (-50, 2.0)]);
        // çok büyük delta (> 2^31)
        let big = TimeSeriesColumnar::encode(&[(0, 1.0), (5_000_000_000, 2.0)]).unwrap();
        assert_eq!(big.decode().unwrap(), vec![(0, 1.0), (5_000_000_000, 2.0)]);
    }
}
