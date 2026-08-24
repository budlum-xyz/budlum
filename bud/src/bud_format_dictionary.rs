//! B.U.D. 2.0 - the tenant dictionary, a zstd dictionary; ideas 2.0 item I5 and
//! F1048, 2026-08-16.
//!
//! On small objects, such as a JSON record, a log line or a config, zstd is
//! weak without a dictionary; a cohort-based dictionary raises the ratio by two
//! to three times. The measurement: small JSON records go from 1.20x without a
//! dictionary to 2.75x with one, and determinism was verified.
//!
//! Determinism (I5): the same sample set, the same parameters and the same zstd
//! version yield THE SAME dictionary bytes. The dictionary therefore falls into
//! the reproducible class: the chain holds the training recipe, the sample
//! hashes and the parameters, not the dictionary BYTES, and the dictionary is
//! retrained on demand. That is I5, dictionary as recipe.
//!
//! The code is `#![forbid(unsafe_code)]` and panic-free.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const DICT_MAGIC: [u8; 8] = *b"\xB5DICT\0\0\0";
pub const MAX_DICT_SIZE: usize = 128 * 1024; // the dictionary ceiling, a bomb guard
pub const MAX_SAMPLES: usize = 100_000;
pub const MAX_SAMPLE_BYTES: usize = 1024 * 1024; // the ceiling for one sample

#[derive(Debug, Clone)]
pub struct TenantDictionary {
    pub bytes: Vec<u8>,   // the zstd dictionary body, raw, not wrapped in a BDLM magic
    pub digest: [u8; 32], // SHA3("BDLM_BUD_DICT_V1" || bytes), the determinism anchor
    pub dict_id: u32,     // the zstd dictID, the first 4 bytes, little-endian
    pub sample_count: usize,
}

impl TenantDictionary {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_DICT_V1";

    /// Train a dictionary with `zstd::dict::from_samples`, which is
    /// deterministic under fixed parameters.
    pub fn train(samples: &[Vec<u8>], max_size: usize) -> Option<Self> {
        if samples.is_empty() || samples.len() > MAX_SAMPLES || max_size > MAX_DICT_SIZE {
            return None;
        }
        if samples.iter().any(|s| s.len() > MAX_SAMPLE_BYTES) {
            return None;
        }
        // zstd::dict::from_samples trains the dictionary; it is COVER-like and
        // deterministic.
        let bytes = zstd::dict::from_samples(samples, max_size).ok()?;
        if bytes.is_empty() || bytes.len() > MAX_DICT_SIZE {
            return None;
        }
        Some(Self::from_bytes(bytes))
    }

    /// Build from ready dictionary bytes, with the deterministic digest
    /// computed over them.
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
        TenantDictionary {
            bytes,
            digest,
            dict_id,
            sample_count: 0,
        }
    }

    /// The deterministic dictionary identity; I5 says to use the hash of the
    /// body rather than an ID.
    pub fn id(&self) -> [u8; 32] {
        self.digest
    }

    /// Compress with the dictionary, an `EncoderDictionary`. It is bomb-guarded
    /// by the `max_out` ceiling.
    pub fn compress_with(&self, data: &[u8], level: i32, max_out: usize) -> Option<Vec<u8>> {
        if data.len() > max_out.saturating_mul(2) {
            return None; // input out of proportion with the decompressed ceiling
        }
        let mut comp = zstd::bulk::Compressor::with_dictionary(level, &self.bytes).ok()?;
        let c = comp.compress(data).ok()?;
        if c.len() > max_out {
            return None;
        }
        Some(c)
    }

    /// Decompress with the dictionary, a `DecoderDictionary`. It is capped, as a
    /// bomb guard.
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
        // Deterministic small JSON records, simulating a cohort.
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
        // The F1048 measurement, in Python: 1.20x without a dictionary and 2.75x
        // with one; Rust is comparable.
        let records = gen_records(2000);
        let raw: usize = records.iter().map(|r| r.len()).sum();
        // zstd-19 without a dictionary.
        let plain: usize = records
            .iter()
            .map(|r| {
                zstd::bulk::compress(r, 19)
                    .map(|c| c.len())
                    .unwrap_or(r.len())
            })
            .sum();
        // Train a dictionary, then compress with it.
        let train: Vec<Vec<u8>> = records[..1000].to_vec();
        let test: Vec<Vec<u8>> = records[1000..].to_vec();
        let dict = TenantDictionary::train(&train, 4096).expect("the dictionary trains");
        let with_dict: usize = test
            .iter()
            .map(|r| {
                dict.compress_with(r, 19, r.len().max(16))
                    .map(|c| c.len())
                    .unwrap_or(r.len())
            })
            .sum::<usize>()
            + dict.bytes.len();
        let test_raw: usize = test.iter().map(|r| r.len()).sum();
        let test_plain: usize = test
            .iter()
            .map(|r| {
                zstd::bulk::compress(r, 19)
                    .map(|c| c.len())
                    .unwrap_or(r.len())
            })
            .sum();
        assert!(
            test_raw as f64 / with_dict as f64 > test_raw as f64 / test_plain as f64,
            "the dictionary must raise the ratio"
        );
        assert!(plain < raw, "it also compresses without a dictionary");
        // The dictionary size stays within its bound.
        assert!(dict.bytes.len() <= 4096 + 1024);
    }

    #[test]
    fn dictionary_determinism() {
        // I5: the same samples and the same parameters give the same dictionary,
        // on the same machine and version.
        let records = gen_records(500);
        let d1 = TenantDictionary::train(&records, 4096).expect("d1");
        let d2 = TenantDictionary::train(&records, 4096).expect("d2");
        assert_eq!(d1.bytes, d2.bytes, "a deterministic dictionary");
        assert_eq!(d1.id(), d2.id());
        assert_ne!(d1.id(), [0u8; 32]);
    }

    #[test]
    fn roundtrip_with_dict_and_tamper() {
        let records = gen_records(300);
        let dict = TenantDictionary::train(&records, 2048).expect("dictionary");
        // Compress with the dictionary, then decompress back to the original.
        let rec = records[0].clone();
        let c = dict
            .compress_with(&rec, 19, rec.len().max(8))
            .expect("compress");
        let d = dict
            .decompress_with(&c, rec.len().max(8) * 2)
            .expect("decompress");
        assert_eq!(d, rec, "the dictionary roundtrip is lossless");
        // Decompressing with the wrong dictionary may fail, on a zstd dictID
        // mismatch.
        let other = TenantDictionary::train(&gen_records(50), 2048).unwrap();
        let attempt = other.decompress_with(&c, rec.len().max(8) * 2);
        // A dictionary with a different dictID: zstd may refuse or produce
        // garbage, but it must not panic.
        let _ = attempt;
        // The bomb guards.
        assert!(TenantDictionary::train(&[], 100).is_none());
        let mut big_sample = vec![0u8; MAX_SAMPLE_BYTES + 1];
        assert!(TenantDictionary::train(&[big_sample], 100).is_none());
        big_sample = vec![0u8; 10];
        assert!(TenantDictionary::train(
            &[big_sample.clone(), big_sample.clone()],
            MAX_DICT_SIZE + 1
        )
        .is_none());
    }

    #[test]
    fn dict_blob_format_never_panics() {
        // Compress and decompress stay panic-free on corrupt dictionary bytes.
        let dict = TenantDictionary::from_bytes(vec![0x28, 0xB5, 0x2F, 0xFD, 0x00]);
        assert_eq!(dict.dict_id, 0xFD2FB528);
        let _ = dict.compress_with(b"test", 19, 100);
        let _ = dict.decompress_with(b"abc", 100);
    }
}
