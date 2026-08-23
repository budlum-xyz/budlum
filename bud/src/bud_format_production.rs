//! B.U.D. 2.0 İcat - Üretim Oranı Kanıtı (BudProductionRecord) (2026-08-16)
//!
//! "Sıkıştırma oranı iddiasının blockchain ile doğrulanabilir yapılması":
//! her .bud konteyner ÜRETİM ANINDA bir üretim kaydı taşıyabilir - ölçülen gerçek
//! oran, boru hattı kimliği, orijinal/saklanan boyutlar ve content_root çapası.
//! Kayıt domain-etiketli SHA3 ile hash'lenir (K3), checkpoint zincirine yazılabilir,
//! BFT vote ile finalize edilebilir (ratio.rs/bud_format_bft.rs).
//!
//! Doğrulama (on-chain): herkes `record_hash`'i yeniden hesaplayabilir; `verify` oran
//! tutarlılığını kontrol eder (claimed_ratio ≈ original_len/stored_len). K19 kapısı:
//! ölçümsüz abartılı oran iddiaları (ör. 17.19x vs gerçek 7.83x) RED - üretim kanıtı
//! ancak GERÇEK üretimden gelirse geçerli.
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, testli.

#![forbid(unsafe_code)]

use crate::bud_format_container::FormatCodec;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub struct BudProductionRecord {
    pub format_codec: FormatCodec,
    pub pipe: &'static str, // "structural+zstd19", "json-columnar-exact", ...
    pub original_len: u64,
    pub stored_len: u64,
    pub payload_root: [u8; 32], // content_id(original) - K3 çapası
    pub ts_unix: u64,
    pub claimed_ratio: f64, // üretim sırasında ÖLÇÜLEN oran (uydurma değil)
}

impl BudProductionRecord {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_PRODUCTION_V1";
    pub const RATIO_TOLERANCE: f64 = 0.01;

    pub fn new(
        format_codec: FormatCodec,
        pipe: &'static str,
        original: &[u8],
        stored_len: u64,
        ts_unix: u64,
    ) -> Self {
        let root = crate::bud_format_container::content_id(original);
        let claimed_ratio = if stored_len > 0 {
            original.len() as f64 / stored_len as f64
        } else {
            1.0
        };
        BudProductionRecord {
            format_codec,
            pipe,
            original_len: original.len() as u64,
            stored_len,
            payload_root: root,
            ts_unix,
            claimed_ratio,
        }
    }

    /// Domain-etiketli kriptografik hash (K3 deseni) - zincire yazılabilir kimlik.
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((self.format_codec as u16).to_le_bytes());
        h.update((self.pipe.len() as u64).to_le_bytes());
        h.update(self.pipe.as_bytes());
        h.update(self.original_len.to_le_bytes());
        h.update(self.stored_len.to_le_bytes());
        h.update(self.payload_root);
        h.update(self.ts_unix.to_le_bytes());
        h.update(self.claimed_ratio.to_le_bytes());
        h.finalize().into()
    }

    /// Tutarlılık: oran iddiası boyutlarla eşleşiyor mu + değerler geçerli mi (K38).
    pub fn verify(&self) -> bool {
        if !self.claimed_ratio.is_finite() || self.claimed_ratio <= 0.0 {
            return false;
        }
        if self.stored_len == 0 && self.original_len > 0 {
            return false;
        }
        let actual = if self.stored_len > 0 {
            self.original_len as f64 / self.stored_len as f64
        } else {
            1.0
        };
        (self.claimed_ratio - actual).abs() <= Self::RATIO_TOLERANCE
    }

    /// K19 kapısı: iddia, ölçüm tablosundaki değerin `max_multiple` katını aşamaz.
    /// Ölçümsüz abartı (uydurma oran) → RED.    ///
    /// Deterministik blob (zincir/segment kaydı için).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.format_codec as u16).to_le_bytes());
        out.extend_from_slice(&(self.pipe.len() as u32).to_le_bytes());
        out.extend_from_slice(self.pipe.as_bytes());
        out.extend_from_slice(&self.original_len.to_le_bytes());
        out.extend_from_slice(&self.stored_len.to_le_bytes());
        out.extend_from_slice(&self.payload_root);
        out.extend_from_slice(&self.ts_unix.to_le_bytes());
        out.extend_from_slice(&self.claimed_ratio.to_le_bytes());
        out.extend_from_slice(&self.record_hash());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 + 4 + 32 + 8 + 8 + 8 + 32 {
            return None;
        }
        let mut pos = 0usize;
        let format_codec = crate::bud_format_container::FormatCodec::from_u16(u16::from_le_bytes(
            bytes[0..2].try_into().ok()?,
        ));
        pos += 2;
        let pipe_len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if bytes.len() < pos + pipe_len {
            return None;
        }
        let pipe = std::str::from_utf8(&bytes[pos..pos + pipe_len])
            .ok()?
            .to_string();
        pos += pipe_len;
        if bytes.len() < pos + 8 + 8 + 32 + 8 + 8 + 32 {
            return None;
        }
        let original_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let stored_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let mut payload_root = [0u8; 32];
        payload_root.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        let ts_unix = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let claimed_ratio = f64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        if bytes.len() != pos + 32 {
            return None;
        }
        let rec = BudProductionRecord {
            format_codec,
            pipe: Box::leak(pipe.into_boxed_str()),
            original_len,
            stored_len,
            payload_root,
            ts_unix,
            claimed_ratio,
        };
        if bytes[pos..] != rec.record_hash() {
            return None;
        }
        Some(rec)
    }

    pub fn plausible_against(&self, measured: f64, max_multiple: f64) -> bool {
        if !measured.is_finite() || measured <= 0.0 {
            return false;
        }
        self.claimed_ratio <= measured * max_multiple
    }
}

pub struct ProductionGates;

impl ProductionGates {
    /// Kayıt tutarlı + ölçülen orana göre makul mü? (K19)
    pub fn k_bud_production(rec: &BudProductionRecord, measured: f64) -> Result<(), &'static str> {
        if !rec.verify() {
            return Err("K-BUD-PRODUCTION: record inconsistent (ratio != len ratio)");
        }
        if !rec.plausible_against(measured, 1.5) {
            return Err("K-BUD-PRODUCTION: ratio > measured*1.5 (uydurma iddia)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_record_verify_and_hash() {
        let data = br#"[{"u":"u1","v":1},{"u":"u1","v":2}]"#;
        let rec = BudProductionRecord::new(FormatCodec::Json, "json-columnar-exact", data, 120, 42);
        assert!(rec.verify(), "üretim kaydı tutarlı");
        assert!((rec.claimed_ratio - data.len() as f64 / 120.0).abs() < 0.01);
        assert_ne!(rec.record_hash(), [0u8; 32], "hash boş değil");
        // aynı alanlar → aynı hash (deterministik)
        let rec2 =
            BudProductionRecord::new(FormatCodec::Json, "json-columnar-exact", data, 120, 42);
        assert_eq!(rec.record_hash(), rec2.record_hash());
        // farklı boyut → farklı hash
        let rec3 =
            BudProductionRecord::new(FormatCodec::Json, "json-columnar-exact", data, 121, 42);
        assert_ne!(rec.record_hash(), rec3.record_hash());
    }

    #[test]
    fn production_ratio_gate_rejects_fake() {
        // K19: ölçülen 7.83x'e karşı 17.19x iddiası RED (uydurma)
        let data = b"x".repeat(1000);
        let rec = BudProductionRecord::new(FormatCodec::Json, "structural+zstd19", &data, 58, 1);
        // 1000/58 = 17.24x - ölçülen JSON 7.83x'in 1.5 katını aşıyor → RED
        assert!(
            ProductionGates::k_bud_production(&rec, 7.83).is_err(),
            "17x iddiası RED"
        );
        // ölçülenle uyumlu 8.0x → OK
        let rec2 = BudProductionRecord::new(FormatCodec::Json, "structural+zstd19", &data, 125, 1);
        assert!(
            ProductionGates::k_bud_production(&rec2, 7.83).is_ok(),
            "8.0x iddiası OK"
        );
    }

    #[test]
    fn production_verify_detects_tamper() {
        let data = br#"{"a":1}"#;
        let rec = BudProductionRecord::new(FormatCodec::Json, "json-columnar-exact", data, 50, 7);
        assert!(rec.verify());
        // oranı elle şişir → verify RED
        let mut bad = rec.clone();
        bad.claimed_ratio = 999.0;
        assert!(!bad.verify(), "oran tutarsızlığı RED");
        // sıfır stored ama içerik var → RED
        let mut bad2 = rec.clone();
        bad2.stored_len = 0;
        bad2.claimed_ratio = 1.0;
        assert!(!bad2.verify(), "sıfır stored RED");
    }
}
