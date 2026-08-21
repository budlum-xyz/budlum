//! B.U.D. 2.0 - zk KÖPRÜSÜ: ÜRETİM WİTNESS'İ (nexus/zkVM köprüsü - tasarım + API)
//!
//! Kalan iş #9: "zk-STARK köprüsü - 'bu .bud şu dönüşümlerle üretildi' ispatı."
//! fikirler2.0 §1.4: zkVM ispatı ekonomik değil (222 yıl saklamaya bedel) →
//! doğru yol `generate_and_verify` (yeniden üret + hash'le). Bu modül aradaki
//! KÖPRÜYÜ kurar: engine boru hattı adımlarını STARK-dostu bir WITNESS izine
//! dönüştürür (adım listesi + girdi/çıktı özetleri + ara hash'ler). Gerçek ispat
//! (nexus/SP1) sandbox dışıdır; witness determinizmi burada test edilir ve bir
//! zkVM'nin ispatlayacağı devrenin SPEC'ini verir. Zincirde `generate_and_verify`
//! (İ9) zaten ucuz doğrulama sağlar.

#![forbid(unsafe_code)]

use crate::bud_format_engine::{EngineResult, PipeStep};
use sha3::{Digest, Sha3_256};

pub const ZK_MAGIC: [u8; 8] = *b"\xB5ZKBR\0\0\0";
pub const ZK_VERSION: u8 = 1;

/// STARK-dostu adım kaydı (devreye çevrilecek işlem).
#[derive(Debug, Clone)]
pub struct WitnessStep {
    pub op: u8,             // PipeStep::to_u8
    pub input_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub arg: u64,           // adım parametresi (ör. zstd seviyesi)
}

/// Engine çıktısından witness izi üret (deterministik).
pub fn engine_to_witness(res: &EngineResult) -> Vec<WitnessStep> {
    let mut prev = Sha3_256::new();
    prev.update(b"BDLM_ZK_INIT");
    prev.update(res.original_len.to_le_bytes());
    let mut init: [u8; 32] = prev.finalize().into();
    let mut steps = Vec::new();
    for s in &res.steps {
        let mut out = Sha3_256::new();
        out.update(init);
        out.update([s.to_u8()]);
        // adım çıktısını temsil eden özet: konteyner boyutu (deterministik ara değer)
        out.update(res.container.len().to_le_bytes());
        let o: [u8; 32] = out.finalize().into();
        let arg: u64 = match s {
            PipeStep::Zstd => 19,
            PipeStep::Split => 16 * 1024,
            PipeStep::Fcdc => 16 * 1024,
            PipeStep::Erasure => 4,
            _ => 0,
        };
        steps.push(WitnessStep { op: s.to_u8(), input_digest: init, output_digest: o, arg });
        init = o;
    }
    steps
}

/// Witness izinin kök özeti (zincire yazılır - ispat bağlanır).
pub fn witness_root(steps: &[WitnessStep]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(ZK_MAGIC);
    h.update([ZK_VERSION]);
    for s in steps {
        h.update([s.op]);
        h.update(s.input_digest);
        h.update(s.output_digest);
        h.update(s.arg.to_le_bytes());
    }
    h.finalize().into()
}

/// `generate_and_verify` (İ9): witness izinden adım sayısı + kök doğrula.
pub fn verify_witness(steps: &[WitnessStep], expected_root: &[u8; 32]) -> bool {
    if steps.is_empty() {
        return false;
    }
    // ardışık bağ: her adımın girdisi bir öncekinin çıktısı olmalı
    for w in steps.windows(2) {
        if w[1].input_digest != w[0].output_digest {
            return false;
        }
    }
    &witness_root(steps) == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_deterministik_ve_dogrulanir() {
        let data = b"zk witness test verisi ".repeat(200);
        let r1 = crate::bud_format_engine::engine_store(&data, false, 42).unwrap();
        let r2 = crate::bud_format_engine::engine_store(&data, false, 42).unwrap();
        let w1 = engine_to_witness(&r1);
        let w2 = engine_to_witness(&r2);
        assert_eq!(witness_root(&w1), witness_root(&w2), "witness deterministik");
        assert!(verify_witness(&w1, &witness_root(&w1)));
        assert!(!w1.is_empty());
    }

    #[test]
    fn bos_witness_reddedilir() {
        assert!(!verify_witness(&[], &[0u8; 32]));
    }

    #[test]
    fn alan_izi_stark_dostu() {
        let data = b"alan izi testi ".repeat(100);
        let r = crate::bud_format_engine::engine_store(&data, false, 3).unwrap();
        let w = engine_to_witness(&r);
        let rows = witness_to_field_trace(&w);
        assert!(!rows.is_empty());
        for row in &rows {
            assert_eq!(row.len(), 10);
            for &el in row {
                assert!(el < GOLDILOCKS_P, "alan elemanı p altında");
            }
        }
        // deterministik + meta
        let rows2 = witness_to_field_trace(&engine_to_witness(&crate::bud_format_engine::engine_store(&data, false, 3).unwrap()));
        let (n1, d1) = field_trace_meta(&rows);
        let (n2, d2) = field_trace_meta(&rows2);
        assert_eq!((n1, d1), (n2, d2));
    }

    #[test]
    fn zincir_baglantisi_bozulursa_red() {
        let data = b"bag testi ".repeat(100);
        let r = crate::bud_format_engine::engine_store(&data, false, 1).unwrap();
        let w = engine_to_witness(&r);
        let orijinal_kok = witness_root(&w);
        let mut bozuk = w.clone();
        if !bozuk.is_empty() {
            bozuk[0].op ^= 1;
            assert!(!verify_witness(&bozuk, &orijinal_kok), "bozuk iz orijinal kökle eşleşmemeli");
        }
    }
}

/// STARK-dostu ALAN İZİ: her adımı Goldilocks asal alanına (p = 2^64 - 2^32 + 1)
/// indirgenmiş 10 alan elemanına çevirir → nexus/SP1 devresi doğrudan tüketir.
/// Satır: [op, arg, in0..in3, out0..out3] - digest 32 bayt → 4×u64 (LE) mod p.
pub const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001; // 2^64 - 2^32 + 1

fn mod_p(w: u64) -> u64 {
    // w < 2^64; p ≈ 2^64 - 2^32 → w - p tek çıkarmada (w >= p ise)
    let mut x = w;
    if x >= GOLDILOCKS_P {
        x -= GOLDILOCKS_P;
    }
    x
}

pub fn witness_to_field_trace(steps: &[WitnessStep]) -> Vec<[u64; 10]> {
    let mut rows = Vec::with_capacity(steps.len());
    for s in steps {
        let mut row = [0u64; 10];
        row[0] = s.op as u64;
        row[1] = mod_p(s.arg);
        for (k, w) in s.input_digest.chunks_exact(8).enumerate() {
            row[2 + k] = mod_p(u64::from_le_bytes(w.try_into().unwrap()));
        }
        for (k, w) in s.output_digest.chunks_exact(8).enumerate() {
            row[6 + k] = mod_p(u64::from_le_bytes(w.try_into().unwrap()));
        }
        rows.push(row);
    }
    rows
}

/// Alan izi satır sayısı (devre boyutu göstergesi) + kök (bağlama).
pub fn field_trace_meta(rows: &[[u64; 10]]) -> (usize, [u8; 32]) {
    let mut h = Sha3_256::new();
    h.update(b"BDLM_ZK_FIELDTRACE_V1");
    h.update((rows.len() as u32).to_le_bytes());
    for r in rows {
        for w in r {
            h.update(w.to_le_bytes());
        }
    }
    (rows.len(), h.finalize().into())
}
