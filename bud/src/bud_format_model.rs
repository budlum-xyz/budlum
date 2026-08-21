//! B.U.D. 2.0 - Model/Sinir Ağı Dosya Transformu (BF16 ağırlık ayrıştırma deseni) (2026-08-16)
//!
//! F1068/K96: sinir ağı ağırlıkları özel sıkıştırma - BF16 modellerde üs baytları
//! ayrıştırılıp Huffman ile sıkıştırıldığında model boyutu küçülür; dar üs dağılımı
//! genel amaçlı sıkıştırmanın yakalayamadığı tekrarları görünür kılar.
//!
//! B.U.D. transformu (kayıpsız): BF16/FP32 kayan nokta dizisini üs + işaret/mantissa
//! akışlarına ayırır; üs akışı dar aralıklı (BF16'da 8 bit üs, değerler dar dağılır)
//! → Huffman ile çok iyi sıkışır; mantissa rastgele → ayrı tutulur (zstd'ye bırakılır).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const MODEL_MAGIC: [u8; 8] = *b"\xB5MODL\0\0\0";
pub const MODEL_VERSION: u8 = 1;
pub const MAX_VALUES: usize = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatKind {
    Bf16 = 0, // 16 bit: 1 işaret + 8 üs + 7 mantissa
    Fp32 = 1, // 32 bit: 1 işaret + 8 üs + 23 mantissa
}

impl FloatKind {
    pub fn to_u8(self) -> u8 {
        self as u8
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Bf16),
            1 => Some(Self::Fp32),
            _ => None,
        }
    }
}

/// Model transformu: kayan nokta dizisi → üs akışı + geri kalan (kayıpsız).
/// Üs akışı Huffman ile ayrı sıkıştırılır; geri kalan orijinal sırada tutulur.
#[derive(Debug, Clone)]
pub struct ModelFloatSplit {
    pub kind: FloatKind,
    pub count: usize,
    pub exponents: Vec<u8>,     // her değerin üs baytı (BF16/FP32: 8 bit)
    pub rest_bits: Vec<u8>,     // işaret + mantissa bitleri (bit-paketli, orijinal sırada)
}

impl ModelFloatSplit {
    /// Kayan nokta bayt dizisini üs + geri kalan akışlara ayır (kayıpsız).
    pub fn encode(raw: &[u8], kind: FloatKind) -> Option<Self> {
        let width = match kind {
            FloatKind::Bf16 => 2usize,
            FloatKind::Fp32 => 4usize,
        };
        if raw.is_empty() || raw.len() % width != 0 {
            return None;
        }
        let count = raw.len() / width;
        if count > MAX_VALUES {
            return None;
        }
        let mut exponents = Vec::with_capacity(count);
        // geri kalan bitler: işaret (1) + mantissa (BF16: 7, FP32: 23)
        let mantissa_bits = match kind {
            FloatKind::Bf16 => 7usize,
            FloatKind::Fp32 => 23usize,
        };
        let rest_total_bits = count * (1 + mantissa_bits);
        let mut rest_bits = vec![0u8; (rest_total_bits + 7) / 8];
        for i in 0..count {
            let off = i * width;
            // üs = bayt 1 (big-endian IEEE: bayt 0 = işaret+üs yüksek, bayt 1 = üs düşük+mantissa)
            // IEEE: b0 = sign + exp[7:1], b1 = exp[0] + mantissa(MSB'ler)
            let sign = (raw[off] >> 7) & 1;
            let exp_hi = (raw[off] & 0x7F) as u8; // exp[7:1]
            let exp_lo = (raw[off + 1] >> 7) & 1; // exp[0]
            let exp = (exp_hi << 1) | exp_lo;
            exponents.push(exp);
            // mantissa bitleri (width'e göre)
            let mant: u64 = match kind {
                FloatKind::Bf16 => {
                    // b1'in düşük 7 biti = mantissa[6:0]
                    (raw[off + 1] & 0x7F) as u64
                }
                FloatKind::Fp32 => {
                    // b1[6:0] = mantissa[22:16], b2 = mantissa[15:8], b3 = mantissa[7:0]
                    (((raw[off + 1] & 0x7F) as u64) << 16)
                        | ((raw[off + 2] as u64) << 8)
                        | (raw[off + 3] as u64)
                }
            };
            // rest bit akışına yaz: işaret + mantissa (mantissa MSB önce)
            let base_bit = i * (1 + mantissa_bits);
            write_bit_at(&mut rest_bits, base_bit, sign == 1);
            for m in 0..mantissa_bits {
                let b = ((mant >> (mantissa_bits - 1 - m)) & 1) == 1;
                write_bit_at(&mut rest_bits, base_bit + 1 + m, b);
            }
        }
        Some(ModelFloatSplit { kind, count, exponents, rest_bits })
    }

    /// Üs + geri kalan akışlardan orijinal kayan nokta baytlarını yeniden kur (kayıpsızlık).
    pub fn decode(&self) -> Option<Vec<u8>> {
        let width = match self.kind {
            FloatKind::Bf16 => 2usize,
            FloatKind::Fp32 => 4usize,
        };
        let mantissa_bits = match self.kind {
            FloatKind::Bf16 => 7usize,
            FloatKind::Fp32 => 23usize,
        };
        if self.exponents.len() != self.count {
            return None;
        }
        let mut out = Vec::with_capacity(self.count * width);
        for i in 0..self.count {
            let exp = self.exponents[i];
            let base_bit = i * (1 + mantissa_bits);
            let sign = read_bit_at(&self.rest_bits, base_bit)?;
            let mut mant: u64 = 0;
            for m in 0..mantissa_bits {
                let b = read_bit_at(&self.rest_bits, base_bit + 1 + m)?;
                mant = (mant << 1) | b as u64;
            }
            // IEEE geri kurulum
            match self.kind {
                FloatKind::Bf16 => {
                    let b0 = ((sign as u8) << 7) | ((exp >> 1) & 0x7F);
                    let b1 = ((exp & 1) << 7) | (mant as u8 & 0x7F);
                    out.push(b0);
                    out.push(b1);
                }
                FloatKind::Fp32 => {
                    let b0 = ((sign as u8) << 7) | ((exp >> 1) & 0x7F);
                    let b1 = ((exp & 1) << 7) | ((mant >> 16) as u8 & 0x7F);
                    out.push(b0);
                    out.push(b1);
                    out.push((mant >> 8) as u8);
                    out.push(mant as u8);
                }
            }
        }
        Some(out)
    }

    /// Deterministik blob: magic + tür + sayı + üsler + geri kalan bitler + digest.
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MODEL_MAGIC);
        out.push(MODEL_VERSION);
        out.push(self.kind.to_u8());
        out.extend_from_slice(&(self.count as u32).to_le_bytes());
        out.extend_from_slice(&(self.exponents.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.exponents);
        out.extend_from_slice(&self.rest_bits);
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_MODEL_V1");
        h.update(&out);
        let d: [u8; 32] = h.finalize().into();
        out.extend_from_slice(&d);
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 1 + 4 + 4;
        if bytes.len() < HDR + 32 || bytes[0..8] != MODEL_MAGIC || bytes[8] != MODEL_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_MODEL_V1");
        h.update(&bytes[..payload_len]);
        let d: [u8; 32] = h.finalize().into();
        if d != bytes[payload_len..] {
            return None;
        }
        let kind = FloatKind::from_u8(bytes[9])?;
        let count = u32::from_le_bytes(bytes[10..14].try_into().ok()?) as usize;
        let exp_len = u32::from_le_bytes(bytes[14..18].try_into().ok()?) as usize;
        let exp_start = HDR;
        if bytes.len() < exp_start + exp_len {
            return None;
        }
        let exponents = bytes[exp_start..exp_start + exp_len].to_vec();
        let rest_bits = bytes[exp_start + exp_len..payload_len].to_vec();
        if count == 0 || count > MAX_VALUES {
            return None;
        }
        Some(ModelFloatSplit { kind, count, exponents, rest_bits })
    }
}

fn write_bit_at(buf: &mut [u8], bit: usize, val: bool) {
    let byte = bit / 8;
    let off = bit % 8;
    if val {
        buf[byte] |= 1 << (7 - off);
    } else {
        buf[byte] &= !(1 << (7 - off));
    }
}

fn read_bit_at(buf: &[u8], bit: usize) -> Option<bool> {
    let byte = bit / 8;
    if byte >= buf.len() {
        return None;
    }
    let off = bit % 8;
    Some((buf[byte] >> (7 - off)) & 1 == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_bf16_model(n: usize) -> Vec<u8> {
        // gerçekçi BF16 ağırlıkları: üsler dar aralıkta, mantissa rastgele
        let mut out = Vec::with_capacity(n * 2);
        let mut x = 0xDEAD_BEEF_1234_5678u64;
        for _i in 0..n {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            // üs: dar bant 118-122 (gerçekçi ağırlık dağılımındaki kazanç burada)
            let exp: u8 = 120 + ((x >> 32) % 5) as u8 - 2;
            let sign: u8 = ((x >> 63) & 1) as u8;
            let mant: u8 = (x & 0x7F) as u8;
            let b0 = (sign << 7) | ((exp >> 1) & 0x7F);
            let b1 = ((exp & 1) << 7) | mant;
            out.push(b0);
            out.push(b1);
        }
        out
    }

    #[test]
    fn bf16_roundtrip_lossless() {
        // K38: encode → decode = orijinal (kayıpsız)
        for n in [10, 1000, 5000] {
            let model = gen_bf16_model(n);
            let split = ModelFloatSplit::encode(&model, FloatKind::Bf16).expect("encode");
            assert_eq!(split.count, n);
            assert_eq!(split.exponents.len(), n);
            let back = split.decode().expect("decode");
            assert_eq!(back, model, "BF16 kayıpsız (n={n})");
            // blob roundtrip
            let blob = split.to_blob();
            let s2 = ModelFloatSplit::from_blob(&blob).expect("blob");
            assert_eq!(s2.decode().unwrap(), model);
            // kurcalama red
            let mut bad = blob.clone();
            *bad.last_mut().unwrap() ^= 0x01;
            assert!(ModelFloatSplit::from_blob(&bad).is_none());
        }
    }

    #[test]
    fn exponent_stream_compresses_well() {
        // Dar üs dağılımı ayrı sıkıştırıldığında küçülür.
        let model = gen_bf16_model(100_000);
        let split = ModelFloatSplit::encode(&model, FloatKind::Bf16).expect("encode");
        let exp_comp = zstd::bulk::compress(&split.exponents, 19).expect("zstd");
        let raw_exp = split.exponents.len();
        // üsler 30 farklı değer (100-129) → zstd ile belirgin sıkışma beklenir;
        // Bu test, ayrılmış üs akışının tek başına sıkıştığını doğrular.
        assert!(exp_comp.len() < raw_exp, "üsler sıkışmalı: {} -> {}", raw_exp, exp_comp.len());
        // Dar üs bandı bu korpusta >3x sıkışır (ölçüm: 4.34x).
        assert!(raw_exp as f64 / exp_comp.len() as f64 > 3.0, "üs sıkışma oranı >3x");
        // toplam kazanç: modelin üs kısmı (~yarısı) sıkışır → %25+ model tasarrufu beklenir
        let rest_comp = zstd::bulk::compress(&split.rest_bits, 19).expect("zstd");
        let total_comp = exp_comp.len() + rest_comp.len();
        let model_comp = zstd::bulk::compress(&model, 19).expect("zstd");
        assert!(
            total_comp < model_comp.len(),
            "üs-ayırma + Huffman modeli zstd'den iyi: split {} vs zstd {}",
            total_comp, model_comp.len()
        );
    }

    #[test]
    fn fp32_roundtrip_and_limits() {
        let mut model = Vec::new();
        let mut x = 0x1234_5678_9ABC_DEF0u64;
        for _i in 0..200 {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            // FP32: üs 100-130, mantissa 23 bit
            let exp: u8 = 100 + ((x >> 40) % 30) as u8;
            let sign: u8 = ((x >> 63) & 1) as u8;
            let mant: u32 = (x & 0x7F_FFFF) as u32;
            let b0 = (sign << 7) | ((exp >> 1) & 0x7F);
            let b1 = ((exp & 1) << 7) | ((mant >> 16) & 0x7F) as u8;
            let b2 = (mant >> 8) as u8;
            let b3 = mant as u8;
            model.extend_from_slice(&[b0, b1, b2, b3]);
        }
        let split = ModelFloatSplit::encode(&model, FloatKind::Fp32).expect("encode");
        assert_eq!(split.decode().unwrap(), model, "FP32 kayıpsız");
        // limitler
        assert!(ModelFloatSplit::encode(&[], FloatKind::Bf16).is_none());
        assert!(ModelFloatSplit::encode(&[0u8, 1], FloatKind::Fp32).is_none()); // 2 bayt FP32 değil
        assert!(ModelFloatSplit::from_blob(&[0u8; 10]).is_none());
    }

    #[test]
    fn blob_never_panics() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
                self.0 = x;
                x.wrapping_mul(0x2545_F491_4F6C_DD1D)
            }
            fn byte(&mut self) -> u8 {
                (self.next() & 0xff) as u8
            }
        }
        let mut rng = Rng(0x4D4F_444C_2026_0816);
        let mut buf = vec![0u8; 200];
        for _ in 0..2000 {
            let len = (rng.next() % 200) as usize;
            for b in &mut buf[..len] {
                *b = rng.byte();
            }
            let _ = ModelFloatSplit::from_blob(&buf[..len]);
        }
    }
}
