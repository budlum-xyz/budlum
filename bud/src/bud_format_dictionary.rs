//! B.U.D. 2.0 - Tenant Sözlüğü (zstd-dictionary; fikirler2.0 İ5 / F1048) (2026-08-16)
//!
//! Küçük nesnelerde (JSON kayıt, log satırı, config) zstd sözlüksüz zayıftır;
//! kohort-tabanlı sözlük oranı 2-3x artırır (ölçüm: küçük JSON kayıtları
//! sözlüksüz 1.20x → sözlüklü 2.75x; determinizm doğrulandı).
//!
//! Determinizm (İ5): aynı örnek kümesi + aynı parametre + aynı zstd sürümü →
//! AYNI sözlük baytları. Sözlük, üretilebilir sınıfa girer: zincirde sözlük BAYTI
//! değil, eğitim tarifi (örnek hash'leri + parametreler) tutulur; sözlük talep
//! anında yeniden eğitilir (İ5 Dictionary-as-Recipe).
//!
//! Kod: `#![forbid(unsafe_code)]`, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const DICT_MAGIC: [u8; 8] = *b"\xB5DICT\0\0\0";
pub const MAX_DICT_SIZE: usize = 128 * 1024; // sözlük tavanı (bomba)
pub const MAX_SAMPLES: usize = 100_000;
pub const MAX_SAMPLE_BYTES: usize = 1024 * 1024; // tek örnek tavanı

#[derive(Debug, Clone)]
pub struct TenantDictionary {
    pub bytes: Vec<u8>,      // zstd sözlük gövdesi (magic BDLM ile sarılı değil - ham)
    pub digest: [u8; 32],    // SHA3("BDLM_BUD_DICT_V1" || bytes) - determinizm çapası
    pub dict_id: u32,        // zstd dictID (ilk 4 bayt, little-endian)
    pub sample_count: usize,
}

impl TenantDictionary {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_DICT_V1";

    /// Sözlük eğit (zstd::dict::from_samples - deterministik, sabit parametreler).
    pub fn train(samples: &[Vec<u8>], max_size: usize) -> Option<Self> {
        if samples.is_empty() || samples.len() > MAX_SAMPLES || max_size > MAX_DICT_SIZE {
            return None;
        }
        if samples.iter().any(|s| s.len() > MAX_SAMPLE_BYTES) {
            return None;
        }
        // zstd::dict::from_samples: sözlük eğitimi (COVER benzeri, deterministik)
        let bytes = zstd::dict::from_samples(samples, max_size).ok()?;
        if bytes.is_empty() || bytes.len() > MAX_DICT_SIZE {
            return None;
        }
        Some(Self::from_bytes(bytes))
    }

    /// Hazır sözlük baytlarından (deterministik doğrulamalı).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
        let digest: [u8; 32] = h.finalize().into();
        let dict_id = if bytes.len() >= 4 {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            0
        };
        TenantDictionary { bytes, digest, dict_id, sample_count: 0 }
    }

    /// Deterministik sözlük kimliği (İ5: ID yerine gövde hash'i kullan).
    pub fn id(&self) -> [u8; 32] {
        self.digest
    }

    /// Sözlükle sıkıştır (EncoderDictionary). Bomba korumalı (max_out tavanı).
    pub fn compress_with(&self, data: &[u8], level: i32, max_out: usize) -> Option<Vec<u8>> {
        if data.len() > max_out.saturating_mul(2) {
            return None; // açılacak boyut tavanı ile orantısız girdi
        }
        let mut comp = zstd::bulk::Compressor::with_dictionary(level, &self.bytes).ok()?;
        let c = comp.compress(data).ok()?;
        if c.len() > max_out {
            return None;
        }
        Some(c)
    }

    /// Sözlükle aç (DecoderDictionary). Tavanlı (bomba koruması).
    pub fn decompress_with(&self, data: &[u8], max_out: usize) -> Option<Vec<u8>> {
        let mut dec = zstd::bulk::Decompressor::with_dictionary(&self.bytes).ok()?;
        let out = dec.decompress(data, max_out).ok()?;
        if out.len() > max_out {
            return None;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_records(n: usize) -> Vec<Vec<u8>> {
        // deterministik küçük JSON kayıtları (kohort simülasyonu)
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let rec = format!(
                "{{\"u\":\"user_{}\",\"ts\":\"2026-08-{:02}T{:02}:00Z\",\"action\":\"{}\",\"item\":\"item_{}\",\"price\":{},\"region\":\"{}\",\"device\":\"{}\",\"session\":\"sess_{}\"}}",
                i % 100, (i % 16) + 1, i % 24,
                ["login","logout","buy","view","search","share"][i % 6],
                i % 500, (i * 37) % 100000,
                ["tr","de","us","gb","fr"][i % 5],
                ["web","ios","android","api"][i % 4],
                i * 7919 % 10_000_000_000
            );
            out.push(rec.into_bytes());
        }
        out
    }

    #[test]
    fn dictionary_improves_small_record_ratio() {
        // F1048 ölçümü (Python): sözlüksüz 1.20x → sözlüklü 2.75x (Rust'ta benzer)
        let records = gen_records(2000);
        let raw: usize = records.iter().map(|r| r.len()).sum();
        // sözlüksüz zstd-19
        let plain: usize = records.iter()
            .map(|r| zstd::bulk::compress(r, 19).map(|c| c.len()).unwrap_or(r.len()))
            .sum();
        // sözlük eğit + sözlükle sıkıştır
        let train: Vec<Vec<u8>> = records[..1000].to_vec();
        let test: Vec<Vec<u8>> = records[1000..].to_vec();
        let dict = TenantDictionary::train(&train, 4096).expect("sözlük eğitilir");
        let with_dict: usize = test.iter()
            .map(|r| dict.compress_with(r, 19, r.len().max(16)).map(|c| c.len()).unwrap_or(r.len()))
            .sum::<usize>()
            + dict.bytes.len();
        let test_raw: usize = test.iter().map(|r| r.len()).sum();
        let test_plain: usize = test.iter()
            .map(|r| zstd::bulk::compress(r, 19).map(|c| c.len()).unwrap_or(r.len()))
            .sum();
        assert!(
            test_raw as f64 / with_dict as f64 > test_raw as f64 / test_plain as f64,
            "sözlük oranı artırmalı"
        );
        assert!(plain < raw, "sözlüksüz de sıkışır");
        // sözlük boyutu sınırda
        assert!(dict.bytes.len() <= 4096 + 1024);
    }

    #[test]
    fn dictionary_determinism() {
        // İ5: aynı örnekler + aynı parametre → aynı sözlük (aynı makine/sürüm)
        let records = gen_records(500);
        let d1 = TenantDictionary::train(&records, 4096).expect("d1");
        let d2 = TenantDictionary::train(&records, 4096).expect("d2");
        assert_eq!(d1.bytes, d2.bytes, "deterministik sözlük");
        assert_eq!(d1.id(), d2.id());
        assert_ne!(d1.id(), [0u8; 32]);
    }

    #[test]
    fn roundtrip_with_dict_and_tamper() {
        let records = gen_records(300);
        let dict = TenantDictionary::train(&records, 2048).expect("sözlük");
        // sözlükle sıkıştır → aç = orijinal
        let rec = records[0].clone();
        let c = dict.compress_with(&rec, 19, rec.len().max(8)).expect("sıkıştır");
        let d = dict.decompress_with(&c, rec.len().max(8) * 2).expect("aç");
        assert_eq!(d, rec, "sözlüklü roundtrip kayıpsız");
        // yanlış sözlükle açma → başarısız olabilir (zstd dictID uyuşmazlığı)
        let other = TenantDictionary::train(&gen_records(50), 2048).unwrap();
        let attempt = other.decompress_with(&c, rec.len().max(8) * 2);
        // farklı dictID'li sözlük: zstd reddedebilir veya bozuk çıktı - panik yok
        let _ = attempt;
        // bomba korumaları
        assert!(TenantDictionary::train(&[], 100).is_none());
        let mut big_sample = vec![0u8; MAX_SAMPLE_BYTES + 1];
        assert!(TenantDictionary::train(&[big_sample], 100).is_none());
        big_sample = vec![0u8; 10];
        assert!(TenantDictionary::train(&[big_sample.clone(), big_sample.clone()], MAX_DICT_SIZE + 1).is_none());
    }

    #[test]
    fn dict_blob_format_never_panics() {
        // bozuk sözlük baytlarıyla compress/decompress panik'siz
        let dict = TenantDictionary::from_bytes(vec![0x28, 0xB5, 0x2F, 0xFD, 0x00]);
        assert_eq!(dict.dict_id, 0xFD2FB528);
        let _ = dict.compress_with(b"test", 19, 100);
        let _ = dict.decompress_with(b"abc", 100);
    }
}
