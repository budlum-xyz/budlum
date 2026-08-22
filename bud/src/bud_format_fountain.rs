//! B.U.D. 2.0 - FOUNTAIN/LT KODLARI (F44/F46 - SeF: hafif düğüm doğrulama)
//!
//! Kalan iş #11b: fountain codes. LT kod: k veri bloğu → n sembol (degree dağılımı
//! + XOR). Alıcı herhangi ≈k sembolle TAM veriyi geri kurar (Gaussian eleme - küçük
//!   k için belirleyici). Deterministik tohum; kayıpsız.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const LT_MAGIC: [u8; 8] = *b"\xB5LT01\0\0\0";

/// k bloğu, n sembol üret (deterministik - tohumlu üreteç).
pub fn lt_encode(blocks: &[Vec<u8>], n: usize, seed: u64) -> Option<Vec<(Vec<u8>, Vec<usize>)>> {
    if blocks.is_empty() || n == 0 {
        return None;
    }
    let k = blocks.len();
    let mut rng = LcRng::new(seed);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        // soliton-benzeri derece: 1 ağırlıklı (1/3), gerisi 2-8 - küçük derece
        // çözülebilirliği artırır (LT'nin kalbi: degree-1 semboller zincir başlatır).
        let degree = if rng.next().is_multiple_of(3) {
            1
        } else {
            2 + (rng.next() % 7) as usize
        };
        let d = degree.min(k);
        // d farklı blok seç (deterministik)
        let mut chosen = Vec::with_capacity(d);
        let mut seen = [false; 64];
        while chosen.len() < d {
            let idx = (rng.next() % k as u64) as usize;
            if idx < 64 && seen[idx] {
                continue;
            }
            if idx < 64 {
                seen[idx] = true;
            }
            chosen.push(idx);
        }
        chosen.sort_unstable();
        let mut sym = vec![0u8; blocks[0].len()];
        for &i in &chosen {
            for (a, b) in sym.iter_mut().zip(blocks[i].iter()) {
                *a ^= b;
            }
        }
        out.push((sym, chosen));
    }
    Some(out)
}

/// Toplanan sembollerden veriyi geri kur (ileri eleme + geriye süpürme; k ≤ 16).
pub fn lt_decode(symbols: &[(Vec<u8>, Vec<usize>)], k: usize) -> Option<Vec<Vec<u8>>> {
    if k == 0 || k > 16 || symbols.is_empty() {
        return None;
    }
    let blen = symbols[0].0.len();
    let mut rows: Vec<(u64, Vec<u8>)> = Vec::new();
    for (data, chosen) in symbols {
        if data.len() != blen {
            return None;
        }
        let mut mask = 0u64;
        for &i in chosen {
            if i < 64 {
                mask |= 1u64 << i;
            }
        }
        rows.push((mask, data.clone()));
    }
    // ileri eleme: her sütun için pivot satırı al, diğerlerinden XOR'la
    let mut pivots: Vec<(usize, u64, Vec<u8>)> = Vec::new();
    for col in 0..k {
        let mut sel = None;
        for (ri, (m, _)) in rows.iter().enumerate() {
            if m & (1u64 << col) != 0 {
                sel = Some(ri);
                break;
            }
        }
        let Some(ri) = sel else { continue };
        let (pm, pd) = rows.remove(ri);
        for (m, d) in rows.iter_mut() {
            if *m & (1u64 << col) != 0 {
                *m ^= pm;
                for (x, y) in d.iter_mut().zip(pd.iter()) {
                    *x ^= y;
                }
            }
        }
        pivots.push((col, pm, pd));
    }
    if pivots.len() < k {
        return None; // yeterli bağımsız denklem yok
    }
    // geriye süpürme: en yüksek pivot sütunundan başla
    let mut solved: Vec<Option<Vec<u8>>> = vec![None; k];
    for (col, mask, mut data) in pivots.into_iter().rev() {
        for c2 in (col + 1)..k {
            if mask & (1u64 << c2) != 0 {
                if let Some(s) = &solved[c2] {
                    for (x, y) in data.iter_mut().zip(s.iter()) {
                        *x ^= y;
                    }
                }
            }
        }
        solved[col] = Some(data);
    }
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(k);
    for s in solved {
        result.push(s?);
    }
    Some(result)
}

/// Basit LC üreteç (deterministik, bağımlılık yok).
struct LcRng(u64);
impl LcRng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1))
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

pub fn lt_digest(symbols: &[(Vec<u8>, Vec<usize>)]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(LT_MAGIC);
    for (d, c) in symbols {
        h.update((d.len() as u32).to_le_bytes());
        h.update(d);
        for &i in c {
            h.update((i as u32).to_le_bytes());
        }
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lt_roundtrip_kayipsiz() {
        // k=8 blok, 16 sembol topla → tümü geri gelir
        let blocks: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 64]).collect();
        let sym = lt_encode(&blocks, 32, 42).unwrap();
        // ilk 24 sembolle kur (LT: k·ln(k/δ) ≈ 16-24 yeterli)
        let dec = lt_decode(&sym[..24], 8).unwrap();
        for (a, b) in blocks.iter().zip(dec.iter()) {
            assert_eq!(a, b, "LT blok kayıpsız");
        }
    }

    #[test]
    fn lt_deterministik() {
        let blocks: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 32]).collect();
        let a = lt_encode(&blocks, 8, 7).unwrap();
        let b = lt_encode(&blocks, 8, 7).unwrap();
        assert_eq!(lt_digest(&a), lt_digest(&b));
    }

    #[test]
    fn lt_gecersiz_girdi_red() {
        assert!(lt_encode(&[], 4, 1).is_none());
        assert!(lt_encode(&[vec![1u8]], 0, 1).is_none());
        assert!(lt_decode(&[], 0).is_none());
        assert!(lt_decode(&[], 17).is_none());
    }
}
