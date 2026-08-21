//! B.U.D. 2.0 - ÜÇ-ÇEKİRDEK FİYAT + UYANIKLIK + ENERJİ BÜTÇESİ (fikirler3.0 Y3/Y6/Y11)
//!
//! Y11: fiyat = a·rezidüel + b·uyanıklık + c·üretim_CPU - üç terim de konsensüs
//! içinde ölçülür; "depolama 0", üç terimin de 0'a yaklaştığı sınıftır.
//! Y3: uyanıklık payı (1/N bekçi turu) fiyata girer: az denetlenen → daha ucuz.
//! Y6: enerji bütçesi = Σ PACT(uyanıklık_payı·spin_gücü + denetim_sıklığı·üretim_CPU)
//! deterministik; blok başlığına yazılır (konsensüs metriği).
//! Sayılar program çıktısıdır (elle yazılmaz); agırlıklar yönetişimce oylanır.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const TRICORE_MAGIC: [u8; 8] = *b"\xB5TRI1\0\0\0";

/// Üç-çekirdek fiyat ağırlıkları (yönetişim parametresi; varsayılanlar belgeden).
#[derive(Debug, Clone, Copy)]
pub struct TriCoreWeights {
    pub a: f64, // rezidüel bayt
    pub b: f64, // uyanıklık payı
    pub c: f64, // üretim CPU (cekirdek-saniye)
}

impl Default for TriCoreWeights {
    fn default() -> Self {
        Self { a: 1.0, b: 0.5, c: 0.2 }
    }
}

/// Y11: üç-çekirdek fiyat. Tüm terimler ≥ 0; deterministik.
pub fn tricore_price(
    residual_bytes: u64,
    wakefulness: f64,       // 1/N (0..1)
    production_cpu: f64,    // cekirdek-saniye
    w: &TriCoreWeights,
) -> f64 {
    let r = residual_bytes as f64 * w.a;
    let u = wakefulness * w.b;
    let c = production_cpu * w.c;
    r + u + c
}

/// Y3: uyanıklık payı - N bekçi arasında 1/N; N artarsa pay düşer.
pub fn wakefulness_pay(n_guardians: u32) -> f64 {
    if n_guardians == 0 {
        return 0.0;
    }
    1.0 / n_guardians as f64
}

/// Y6: beklenen güç hesabı (deterministik konsensüs metriği).
/// `spin_w`: uyanık disk gücü (W/TB) · `cpu_w`: üretim CPU gücü (W/cekirdek-saniye).
/// Çıktı: watt (beklenen) - blok başlığına yazılır.
pub fn expected_power(
    n_guardians: u32,
    spin_w: f64,
    audit_freq_per_epoch: f64,
    cpu_w: f64,
    pact_count: u64,
) -> f64 {
    let w = wakefulness_pay(n_guardians);
    // uyanık disk payı + denetim CPU'su (tüm PACT'ler üzerinden)
    (w * spin_w * pact_count as f64) + (audit_freq_per_epoch * cpu_w * pact_count as f64)
}

/// Y6 hedef kapısı: beklenen güç hedef bütçenin altında mı? (aşımda yeni sözleşme kuyruğa)
pub fn energy_within_budget(expected_w: f64, target_w: f64) -> bool {
    expected_w <= target_w
}

/// Deterministik kayıt (blok başlığına yazılabilir).
pub fn energy_record_hash(n: u32, expected_w: f64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(TRICORE_MAGIC);
    h.update(n.to_le_bytes());
    h.update(expected_w.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn y3_uyaniklik_payi_1n() {
        assert!((wakefulness_pay(26) - 1.0 / 26.0).abs() < 1e-12);
        assert!(wakefulness_pay(100) < wakefulness_pay(10), "N artarsa pay düşer");
        assert_eq!(wakefulness_pay(0), 0.0);
    }

    #[test]
    fn y11_uc_terim_fiyat() {
        let w = TriCoreWeights::default();
        // rezidüel 0 + uyanıklık 1/26 + CPU küçük → fiyat 0'a yakın
        let p0 = tricore_price(0, 1.0 / 26.0, 0.0, &w);
        // rezidüel 1MB + sık uyanık + çok CPU → çok daha pahalı
        let p1 = tricore_price(1_000_000, 1.0, 1000.0, &w);
        assert!(p1 > p0);
        assert!(p0 > 0.0);
        // deterministik
        assert_eq!(tricore_price(10, 0.5, 2.0, &w), tricore_price(10, 0.5, 2.0, &w));
    }

    #[test]
    fn y6_enerji_butcesi() {
        // N=26, uyanık disk payı 1/26 → güç düşer; N=1 → yüksek
        let e26 = expected_power(26, 7.0, 0.05, 60.0, 100);
        let e1 = expected_power(1, 7.0, 0.05, 60.0, 100);
        assert!(e26 < e1, "N büyükse güç düşer: {e26} < {e1}");
        assert!(energy_within_budget(e26, e1));
        assert!(!energy_within_budget(e1, e26));
        // deterministik kayıt
        assert_eq!(energy_record_hash(26, e26), energy_record_hash(26, e26));
    }

    #[test]
    fn y6_benchmark_pini() {
        // 1000 cekirdek-saniye, tier 1x → 2000 J → ~2000 W·s (birim doğru)
        let w = power_from_core_sec(1000.0, 1.0);
        assert_eq!(w, 1000.0 * BENCH_CORE_SEC_J);
        // düşük donanım tier'i gücü azaltır
        assert!(power_from_core_sec(1000.0, 0.5) < power_from_core_sec(1000.0, 2.0));
        // tier sıfıra yaklaşırsa clamp
        assert!(power_from_core_sec(100.0, 0.0) > 0.0);
    }

    #[test]
    fn agirlik_sifir_terimler() {
        let w = TriCoreWeights { a: 0.0, b: 0.0, c: 0.0 };
        assert_eq!(tricore_price(1000, 1.0, 10.0, &w), 0.0);
    }
}

/// Y6 BENCHMARK PİNİ: cekirdek-saniye birimi (üretim kohortunda kalibre edilir).
/// `bench_core_sec`: referans makinede 1 cekirdek-saniyenin jul karşılığı (W·s).
/// Donanım heterojenliği effort.rs tier'larıyla modellenir (0.5x-10x).
pub const BENCH_CORE_SEC_J: f64 = 2.0; // varsayılan pin (kalibrasyon bekler)

/// Y6: donanım düzeltmeli beklenen güç - cekirdek-saniye → watt.
pub fn power_from_core_sec(core_sec: f64, hw_tier: f64) -> f64 {
    core_sec * BENCH_CORE_SEC_J * hw_tier.max(0.1)
}
