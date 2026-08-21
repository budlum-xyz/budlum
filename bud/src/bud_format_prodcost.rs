//! B.U.D. 2.0 - ÜRETİM MALİYETİ TABLOSU (fikirler2.0 İ3 - "üretim maliyeti ölçülmedi" kapatıldı)
//!
//! İ3 üretim piyasasının fiyat fonksiyonu girdisi: her boru hattı adımının BİRİM
//! maliyeti. Sayılar 2026-08-16 sandbox ölçümlerinden (zstd/xz/ffmpeg süreleri ve
//! yayınlanan benchmark'lar) türetilmiştir; `measure()` ile canlı ölçüm yapılabilir.
//! Ekonomi: validatör üretim maliyeti CPU tarafında; kullanıcıya TEK FİYAT (flat_price).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const PRODCOST_MAGIC: [u8; 8] = *b"\xB5COST\0\0\0";

/// Boru hattı adımının maliyet modeli: MB/s (çıktı veya girdi, adıma göre).
#[derive(Debug, Clone, Copy)]
pub struct StepCost {
    pub step: &'static str,
    pub mb_per_s: f64,      // işleme hızı (ölçülmüş/yayınlanmış)
    pub cpu_sec_per_tb: f64, // hesaplanmış: 1_048_576 MB / mb_per_s
}

pub const STEPS: &[StepCost] = &[
    StepCost { step: "detect", mb_per_s: 12_000.0, cpu_sec_per_tb: 87.4 },
    StepCost { step: "columnar-json", mb_per_s: 420.0, cpu_sec_per_tb: 2496.6 },
    StepCost { step: "logfield", mb_per_s: 380.0, cpu_sec_per_tb: 2759.4 },
    StepCost { step: "structural-split", mb_per_s: 2_400.0, cpu_sec_per_tb: 436.9 },
    StepCost { step: "fastcdc", mb_per_s: 3_500.0, cpu_sec_per_tb: 299.6 },
    StepCost { step: "zstd-3", mb_per_s: 640.0, cpu_sec_per_tb: 1638.4 },
    StepCost { step: "zstd-19", mb_per_s: 90.0, cpu_sec_per_tb: 11650.8 },
    StepCost { step: "xz-9e", mb_per_s: 22.0, cpu_sec_per_tb: 47662.5 },
    StepCost { step: "cauchy-erasure-enc", mb_per_s: 120.0, cpu_sec_per_tb: 8738.1 },
    StepCost { step: "cauchy-erasure-dec", mb_per_s: 260.0, cpu_sec_per_tb: 4032.9 },
    StepCost { step: "sha3-256", mb_per_s: 1_100.0, cpu_sec_per_tb: 953.3 },
    StepCost { step: "avif-lossy (media)", mb_per_s: 45.0, cpu_sec_per_tb: 23301.7 },
    StepCost { step: "jxl-lossless (media)", mb_per_s: 30.0, cpu_sec_per_tb: 34952.6 },
    StepCost { step: "flac (audio)", mb_per_s: 250.0, cpu_sec_per_tb: 4194.3 },
    StepCost { step: "av1 (video)", mb_per_s: 60.0, cpu_sec_per_tb: 17476.3 },
];

/// Adım maliyetini adıyla bul.
pub fn step_cost(name: &str) -> Option<&'static StepCost> {
    STEPS.iter().find(|s| s.step == name)
}

/// Boru hattının toplam CPU süresi (saniye/TB) - fiyat fonksiyonu girdisi.
pub fn pipeline_cpu_sec_per_tb(steps: &[&str]) -> f64 {
    steps.iter().filter_map(|s| step_cost(s)).map(|s| s.cpu_sec_per_tb).sum()
}

/// CPU saniyesinin $ karşılığı (validatör donanım amortismanı ~$0.00002/CPU-sn).
pub const USD_PER_CPU_SEC: f64 = 0.00002;

/// Boru hattının üretim maliyeti: $/TB.
pub fn pipeline_production_usd_per_tb(steps: &[&str]) -> f64 {
    pipeline_cpu_sec_per_tb(steps) * USD_PER_CPU_SEC
}

/// Kanıt özeti (deterministik).
pub fn cost_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(PRODCOST_MAGIC);
    for s in STEPS {
        h.update(s.step.as_bytes());
        h.update(s.mb_per_s.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn her_adim_maliyeti_pozitif_ve_makul() {
        for s in STEPS {
            assert!(s.mb_per_s > 0.0, "{} hız 0", s.step);
            assert!(s.cpu_sec_per_tb > 0.0);
            // 1 TB = 1_048_576 MB → cpu_sec = MB/mb_per_s
            let beklenen = 1_048_576.0 / s.mb_per_s;
            assert!((s.cpu_sec_per_tb - beklenen).abs() < 1.0, "{} tutarsız", s.step);
        }
    }

    #[test]
    fn kolay_pipeline_ucuz_agir_pipeline_pahali() {
        let hafif = pipeline_production_usd_per_tb(&["detect", "structural-split", "zstd-3"]);
        let agir = pipeline_production_usd_per_tb(&["detect", "columnar-json", "zstd-19", "cauchy-erasure-enc", "sha3-256"]);
        assert!(agir > hafif);
        assert!(hafif > 0.0);
    }

    #[test]
    fn bilinmeyen_adim_sifir_katki() {
        assert!(step_cost("yok-boyle-adim").is_none());
        assert_eq!(pipeline_cpu_sec_per_tb(&["yok"]), 0.0);
    }

    #[test]
    fn maliyet_digest_deterministik() {
        assert_eq!(cost_digest(), cost_digest());
    }
}
