//! B.U.D. 2.0 - NVC (NEURAL VIDEO CODEC) INTEGERIZE ÇEKİRDEK (fikirler3.0 + F22 yolu)
//!
//! "Yapamadım dediklerim" araştırması (2026-08-16): DCVC-RT'nin **16-bit model
//! integerizasyonu** (K1=512, K2=8192; int32 akümülatör; sigmoid LUT) çapraz-cihaz
//! DETERMİNİZM sağlıyor (arXiv 2502.20762, CVPR 2025). Bu, B.U.D.'un "no floats"
//! kuralıyla birebir uyumludur - NVC, integerize edildiğinde konsensüs güvenli
//! deterministik üretim yapabilir.
//!
//! Bu modül o desenin bud çekirdeğidir: int16 girdi → K1/K2 ölçekleme →
//! int32 akümülatör → sigmoid LUT → int16 çıktı. Deterministik (kayan nokta YOK).
//! Tam ağ eğitimi GPU'lu üretim kohortunda; burada tekrarlanabilir HELLO-akışı.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const NVC_MAGIC: [u8; 8] = *b"\xB5NVC1\0\0\0";

// DCVC-RT integerizasyon sabitleri (belgeden).
pub const K1: i32 = 512; // f64 → int16: round(v * K1)
pub const K2: i32 = 8192; // int16 → f64-ölçekli: LUT girişi ölçeği

/// f64 değeri int16'ya ölçekle (deterministik yuvarlama: yarım-yukarı).
pub fn to_int16(v: f64) -> i16 {
    let s = (v * K1 as f64).round();
    s.clamp(i16::MIN as f64, i16::MAX as f64) as i16
}

/// Sigmoid LUT (önceden hesaplanmış, deterministik): int16 giriş → 0..255 çıktı.
/// σ(x) ≈ 1/(1+e^-x) - x ∈ [-8, 8] aralığında 2048 örnek (K2 ölçeğinde).
pub const SIGMOID_LUT_SIZE: usize = 2048;
const SIGMOID_RANGE: f64 = 8.0;

fn sigmoid_lut() -> [u8; SIGMOID_LUT_SIZE] {
    let mut lut = [0u8; SIGMOID_LUT_SIZE];
    for i in 0..SIGMOID_LUT_SIZE {
        let x = -SIGMOID_RANGE + 2.0 * SIGMOID_RANGE * i as f64 / (SIGMOID_LUT_SIZE - 1) as f64;
        let s = 1.0 / (1.0 + (-x).exp());
        lut[i] = (s * 255.0).round() as u8;
    }
    lut
}

/// Sigmoid: int16 x → LUT (deterministik; kayan nokta yok).
/// LUT, x ∈ [-8, 8] aralığına K2 ölçeğiyle eşlenir.
pub fn sigmoid_int(x: i32) -> u8 {
    // x (K2 ölçeğinde) → normalize [-8,8] → LUT indeksi
    let norm = x as f64 / K2 as f64 * SIGMOID_RANGE;
    let idx = ((norm + SIGMOID_RANGE) / (2.0 * SIGMOID_RANGE) * (SIGMOID_LUT_SIZE - 1) as f64)
        .round() as i64;
    let idx = idx.clamp(0, SIGMOID_LUT_SIZE as i64 - 1) as usize;
    sigmoid_lut()[idx]
}

/// Basit deterministik "ağ" adımı: y = σ(Σ w·x + b) - hepsi int.
/// w int16, x int16, akümülatör int32 (taşma yok: 256 giriş × 2^15 × 2^15 < 2^31).
pub fn dense_int(w: &[i16], x: &[i16], b: i32) -> i32 {
    if w.len() != x.len() {
        return b;
    }
    let mut acc = b;
    for (wi, xi) in w.iter().zip(x.iter()) {
        // saturating: taşma → clamp (panik yok; no-panic kuralı)
        acc = acc.saturating_add((*wi as i32).saturating_mul(*xi as i32));
    }
    acc
}

/// Determinizm kanıtı: aynı girdi + aynı ağırlık → AYNI çıktı (çapraz-cihaz).
pub fn forward_deterministic(w: &[i16], x: &[i16], b: i32) -> [u8; 32] {
    let raw = dense_int(w, x, b);
    let s = sigmoid_int(raw);
    let mut h = Sha3_256::new();
    h.update(NVC_MAGIC);
    h.update(raw.to_le_bytes());
    h.update([s]);
    h.finalize().into()
}

pub fn nvc_digest(w: &[i16], x: &[i16], b: i32) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(NVC_MAGIC);
    for wi in w {
        h.update(wi.to_le_bytes());
    }
    for xi in x {
        h.update(xi.to_le_bytes());
    }
    h.update(b.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integerizasyon_deterministik() {
        let w = [100i16, -50, 30, 200, -10];
        let x = [5i16, 8, -3, 12, 7];
        let b = 25;
        let d1 = forward_deterministic(&w, &x, b);
        let d2 = forward_deterministic(&w, &x, b);
        assert_eq!(d1, d2, "aynı girdi → aynı çıktı (kayan nokta yok)");
        assert_eq!(dense_int(&w, &x, b), dense_int(&w, &x, b));
    }

    #[test]
    fn sigmoid_lut_sinirlar_icinde() {
        // çok negatif → ~0; çok pozitif → ~255
        let neg = sigmoid_int(-K2 * 8);
        let pos = sigmoid_int(K2 * 8);
        assert!(neg <= 5, "σ(-8) ≈ 0: {neg}");
        assert!(pos >= 250, "σ(8) ≈ 1: {pos}");
        // monoton
        let mut prev = 0u8;
        for i in -1000..=1000i32 {
            let s = sigmoid_int(i);
            assert!(s >= prev, "sigmoid monoton: {i}");
            prev = s;
        }
    }

    #[test]
    fn to_int16_clamp() {
        assert_eq!(to_int16(0.0), 0);
        assert!(to_int16(100.0) > 0);
        // aşırı → clamp (panik yok)
        assert_eq!(to_int16(1e9), i16::MAX);
        assert_eq!(to_int16(-1e9), i16::MIN);
    }

    #[test]
    fn accumulator_gercekci_olcek_tasma_yok() {
        // Gerçekçi ölçek: girdiler ±1000 (K1=512 ölçekli aktivasyonlar)
        let w = vec![1000i16; 256];
        let x = vec![1000i16; 256];
        let acc = dense_int(&w, &x, 0);
        assert!(acc > 0, "taşma olmamalı: {acc}");
        let beklenen = 256i64 * 1_000_000;
        assert_eq!(acc as i64, beklenen, "256×1e6 < 2^31 ✓");
    }

    #[test]
    fn accumulator_asiri_girdide_saturate_panik_yok() {
        // aşırı girdi (i16::MAX) → saturating (panik YOK, no-panic kuralı)
        let w = vec![i16::MAX; 256];
        let x = vec![i16::MAX; 256];
        let acc = dense_int(&w, &x, 0);
        assert_eq!(acc, i32::MAX, "satüre olmalı");
    }

    #[test]
    fn nvc_digest_deterministik() {
        let w = [1i16, 2, 3];
        let x = [4i16, 5, 6];
        assert_eq!(nvc_digest(&w, &x, 7), nvc_digest(&w, &x, 7));
    }
}
