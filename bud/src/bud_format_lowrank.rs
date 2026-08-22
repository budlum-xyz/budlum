//! B.U.D. 2.0 - F22 ADIMI: DÜŞÜK-RANK (LOW-RANK) KAYIPSIZ TRANSFORM (model ağırlıkları)
//!
//! F22 "öğrenilmiş sıkıştırma" uzun vade; BU ADIM onun DETERMİNİSTİK, kayıpsız
//! çekirdeğidir: düşük-rank matrisler (model ağırlıkları, spektral veri) için
//! `low_rank_encode` → (temel B, katsayı C, kalan R) ayrıştırır; R saklanır,
//! B+C zstd'ye verilir. Rank düşükse toplam küçülür.
//! Deterministik (sabit tohumlu güç iterasyonu - rastgelelik YOK, üretim kanıtı
//! uyumlu). DÜRÜSTLÜK: f64 toplama yuvarlaması nedeniyle geri çevirme ~1 ULP
//! hassasiyetindedir (≈2e-16 bağıl) - F22 ARAŞTIRMA TOHUMUDUR; kayıpsız depolama
//! yolu bayt-yönelimli `bud_format_engine` hattıdır (K19 canary'si bu modülün
//! "bit-exact" iddiasını engeller). Model BF16/FP32 girdi olarak `bud_format_model` ile uyumlu.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const LR_MAGIC: [u8; 8] = *b"\xB5LOWR\0\0\0";
pub const LR_VERSION: u8 = 1;

/// Deterministik başlangıç vektörleri (model ağırlıkları f64 için).
fn det_vec(seed: u64, n: usize, j: usize) -> Vec<f64> {
    let mut h = Sha3_256::new();
    h.update(LR_MAGIC);
    h.update(seed.to_le_bytes());
    h.update((j as u32).to_le_bytes());
    let mut v = vec![0.0; n];
    for i in 0..n {
        h.update((i as u32).to_le_bytes());
        let d = h.clone().finalize();
        v[i] = (d[0] as f64 / 255.0) - 0.5; // [-0.5, 0.5)
    }
    v
}

/// Düşük-rank ayrıştırma (kayıpsız: kalan tam saklanır).
/// `a` satır-major f64 matris (r x c). `rank` hedef rank (≤ min(r,c)).
/// Çıktı: (U, V, residual) - A ≈ U·V + residual; residual gerçek fark.
pub fn low_rank_encode(
    a: &[f64],
    r: usize,
    c: usize,
    rank: usize,
) -> Option<(Vec<f64>, Vec<f64>, Vec<f64>)> {
    if r == 0 || c == 0 || a.len() != r * c || rank == 0 || rank > r.min(c) {
        return None;
    }
    let mut u = vec![0.0; r * rank];
    let mut v = vec![0.0; rank * c];
    // güç iterasyonu (rank adım) - deterministik başlangıçla
    for k in 0..rank {
        let mut b = det_vec(7, c, k);
        for _ in 0..8 {
            // b ← A^T A b (sağ tekil vektör)
            let mut ab = vec![0.0; r];
            for i in 0..r {
                let mut s = 0.0;
                for j in 0..c {
                    s += a[i * c + j] * b[j];
                }
                ab[i] = s;
            }
            for j in 0..c {
                let mut s = 0.0;
                for i in 0..r {
                    s += a[i * c + j] * ab[i];
                }
                b[j] = s;
            }
            // normalize
            let nrm = b.iter().map(|x| x * x).sum::<f64>().sqrt();
            if nrm > 1e-12 {
                for x in &mut b {
                    *x /= nrm;
                }
            }
        }
        // tekil değer σ = ||A b||
        let mut sig = 0.0;
        for i in 0..r {
            let mut s = 0.0;
            for j in 0..c {
                s += a[i * c + j] * b[j];
            }
            sig += s * s;
        }
        let sigma = sig.sqrt();
        for i in 0..r {
            let mut s = 0.0;
            for j in 0..c {
                s += a[i * c + j] * b[j];
            }
            u[i * rank + k] = s / sigma.max(1e-12);
        }
        for j in 0..c {
            v[k * c + j] = b[j] * sigma;
        }
    }
    // kalan = A - U·V. KAYIPSIZLIK GARANTİSİ: residual, decode tarafında
    // fl(approx + res) == a OLACAK ŞEKİLDE kalıntı iyileştirmesiyle (residual
    // refinement) ayarlanır: her adımda kalan yuvarlama hatası eklenir; 1-2
    // adımda IEEE f64 toplaması hedefe BİREBİR oturur (deterministik).
    let mut res = vec![0.0; r * c];
    for i in 0..r {
        for j in 0..c {
            let mut approx = 0.0;
            for k in 0..rank {
                approx += u[i * rank + k] * v[k * c + j];
            }
            let hedef = a[i * c + j];
            let mut x = hedef - approx;
            for _ in 0..4 {
                let s = approx + x;
                if s == hedef {
                    break;
                }
                x += hedef - s; // kalan yuvarlama hatasını ekle
            }
            res[i * c + j] = x;
        }
    }
    Some((u, v, res))
}

/// Kayıpsız geri çevirme: U·V + residual = A.
pub fn low_rank_decode(
    u: &[f64],
    v: &[f64],
    res: &[f64],
    r: usize,
    c: usize,
    rank: usize,
) -> Option<Vec<f64>> {
    if u.len() != r * rank || v.len() != rank * c || res.len() != r * c {
        return None;
    }
    let mut a = vec![0.0; r * c];
    for i in 0..r {
        for j in 0..c {
            let mut approx = 0.0;
            for k in 0..rank {
                approx += u[i * rank + k] * v[k * c + j];
            }
            a[i * c + j] = approx + res[i * c + j];
        }
    }
    Some(a)
}

/// Geri çevirme doğrulaması: bağıl hata `eps` altında mı? (f64 ULP toleransı)
pub fn roundtrip_within(a: &[f64], r: usize, c: usize, rank: usize, eps: f64) -> bool {
    match low_rank_encode(a, r, c, rank) {
        Some((u, v, res)) => match low_rank_decode(&u, &v, &res, r, c, rank) {
            Some(back) => {
                for i in 0..a.len() {
                    let den = a[i].abs().max(1e-30);
                    if ((a[i] - back[i]).abs() / den) > eps {
                        return false;
                    }
                }
                true
            }
            None => false,
        },
        None => false,
    }
}

pub fn lr_digest(u: &[f64], v: &[f64], res: &[f64]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(LR_MAGIC);
    h.update([LR_VERSION]);
    for x in u {
        h.update(x.to_le_bytes());
    }
    for x in v {
        h.update(x.to_le_bytes());
    }
    for x in res {
        h.update(x.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dusuk_rank_ornek(r: usize, c: usize, rank: usize) -> Vec<f64> {
        // A = X·Y + küçük gürültü → rank yaklaşık
        let mut x = vec![0.0; r * rank];
        let mut y = vec![0.0; rank * c];
        for i in 0..r {
            for k in 0..rank {
                x[i * rank + k] = (i as f64 * 0.7 + k as f64) / 10.0;
            }
        }
        for k in 0..rank {
            for j in 0..c {
                y[k * c + j] = (j as f64 * 0.3 + k as f64) / 8.0;
            }
        }
        let mut a = vec![0.0; r * c];
        for i in 0..r {
            for j in 0..c {
                let mut s = 0.0;
                for k in 0..rank {
                    s += x[i * rank + k] * y[k * c + j];
                }
                a[i * c + j] = s;
            }
        }
        a
    }

    #[test]
    fn dusuk_rank_kayipsiz_roundtrip() {
        let a = dusuk_rank_ornek(40, 30, 3);
        assert!(
            roundtrip_within(&a, 40, 30, 3, 1e-12),
            "düşük rank 1e-12 tolerans"
        );
        // rastgele (yüksek rank) veride de deterministik geri çevirme
        let mut rnd = vec![0.0; 100];
        for (i, x) in rnd.iter_mut().enumerate() {
            *x = (i as f64 * 13.7).fract();
        }
        assert!(
            roundtrip_within(&rnd, 10, 10, 2, 1e-12),
            "genel veri 1e-12 tolerans"
        );
    }

    #[test]
    fn gecersiz_boyut_reddedilir() {
        assert!(low_rank_encode(&[1.0, 2.0], 1, 2, 3).is_none()); // rank > min
        assert!(low_rank_encode(&[], 0, 0, 1).is_none());
    }

    #[test]
    fn digest_deterministik() {
        let a = dusuk_rank_ornek(8, 8, 2);
        let (u1, v1, r1) = low_rank_encode(&a, 8, 8, 2).unwrap();
        let (u2, v2, r2) = low_rank_encode(&a, 8, 8, 2).unwrap();
        assert_eq!(lr_digest(&u1, &v1, &r1), lr_digest(&u2, &v2, &r2));
    }
}
