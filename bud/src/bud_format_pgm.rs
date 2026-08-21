//! B.U.D. 2.0 - LEARNED (PGM-BENZERİ) DEDUP İNDEKS (F117 - PGM-index deseni)
//!
//! Kalan iş #10b: learned index. Sıralı chunk offset'leri için parçalı-doğrusal
//! (piecewise-linear) model: offset ≈ a·key + b. Hata ε altında model +
//! düzeltme tablosu → RAM çok az (F117: PGM 8x-70x RAM az). Deterministik.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const PGM_MAGIC: [u8; 8] = *b"\xB5PGM1\0\0\0";

#[derive(Debug, Clone, Copy)]
pub struct LinSeg {
    pub key_start: u64,
    pub a: f64,
    pub b: f64,
    pub err: u64, // modelden sapma tavanı (düzeltme tablosu aralığı)
}

/// Sıralı (key, offset) dizisinden PGM modeli üret.
/// `eps` = parça başına izin verilen maksimum sapma (bayt).
pub fn build_pgm(keys: &[u64], offsets: &[u64], eps: u64) -> Option<Vec<LinSeg>> {
    if keys.len() != offsets.len() || keys.is_empty() || eps == 0 {
        return None;
    }
    let mut segs = Vec::new();
    let mut i = 0usize;
    while i < keys.len() {
        // ilk eğim: nokta i ve i+1
        let mut a = 0.0;
        let mut b = offsets[i] as f64;
        let mut j = i;
        if i + 1 < keys.len() {
            let dx = (keys[i + 1] - keys[i]).max(1) as f64;
            a = (offsets[i + 1] as f64 - offsets[i] as f64) / dx;
            b = offsets[i] as f64 - a * keys[i] as f64;
        }
        let mut max_err = 0u64;
        // genişlet; her adımda uç noktalardan YENİDEN uydur ve tüm parçayı kontrol et
        loop {
            let mut grown = false;
            let jj = j + 1;
            // `while` idi ama gövdenin her yolu `break` ediyor ve `jj` gövde
            // içinde hiç değişmiyor: koşul yeniden değerlendirilmiyordu, yani
            // bu bir döngü değil tek geçişli daldı (clippy::never_loop).
            // Gerçek yineleme DIŞ `loop`'ta: orada `j = jj` ile ilerleyip
            // `grown` bayrağıyla tekrar giriliyor. `if` yazmak yapıyı olduğu
            // gibi gösterir; davranış birebir aynı.
            if jj < keys.len() {
                // uç noktalardan yeniden uydur (i ve jj)
                let dx = (keys[jj] - keys[i]).max(1) as f64;
                let na = (offsets[jj] as f64 - offsets[i] as f64) / dx;
                let nb = offsets[i] as f64 - na * keys[i] as f64;
                // i..jj arasındaki tüm noktalar eps içinde mi?
                let mut ok = true;
                let mut em = 0u64;
                for k in i..=jj {
                    let pred = na * keys[k] as f64 + nb;
                    let err = (offsets[k] as f64 - pred).abs().round() as u64;
                    if err > eps {
                        ok = false;
                        break;
                    }
                    em = em.max(err);
                }
                // Parça jj'ye kadar eps içinde kaldıysa bir adım büyüt ve dış
                // `loop` baştan denesin; kalmadıysa `grown` false kalır ve
                // aşağıdaki kontrol dış döngüyü bitirir.
                if ok {
                    a = na;
                    b = nb;
                    max_err = em;
                    j = jj;
                    grown = true;
                }
            }
            if !grown {
                break;
            }
        }
        if j == i {
            j = i + 1; // tek nokta
            max_err = 0;
        }
        segs.push(LinSeg { key_start: keys[i], a, b, err: max_err });
        i = j;
    }
    if segs.is_empty() {
        return None;
    }
    Some(segs)
}

/// Modelle tahmin (düzeltmesiz) - arama başlangıcı.
pub fn predict(segs: &[LinSeg], key: u64) -> Option<u64> {
    let seg = segs.iter().rev().find(|s| key >= s.key_start)?;
    Some((seg.a * key as f64 + seg.b).max(0.0) as u64)
}

/// Tahmin edilen aralık: [pred-err, pred+err] - doğru offset burada.
pub fn search_range(segs: &[LinSeg], key: u64) -> Option<(u64, u64)> {
    let seg = segs.iter().rev().find(|s| key >= s.key_start)?;
    let pred = (seg.a * key as f64 + seg.b).max(0.0) as u64;
    let e = seg.err.max(1);
    Some((pred.saturating_sub(e), pred.saturating_add(e)))
}

pub fn pgm_digest(segs: &[LinSeg]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(PGM_MAGIC);
    for s in segs {
        h.update(s.key_start.to_le_bytes());
        h.update(s.a.to_le_bytes());
        h.update(s.b.to_le_bytes());
        h.update(s.err.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pgm_tahmin_aralik_icerir() {
        // monoton artan offset'ler (chunk indeksi → byte offset)
        let keys: Vec<u64> = (0..2000).collect();
        let mut offsets = Vec::new();
        let mut off = 0u64;
        for k in &keys {
            off += 512 + (k % 7) * 13; // düzensiz ama monoton
            offsets.push(off);
        }
        let segs = build_pgm(&keys, &offsets, 512).expect("pgm");
        assert!(segs.len() < 100, "parça sayısı az: {}", segs.len());
        // her key için doğru offset tahmin aralığında
        for k in &keys {
            let (lo, hi) = search_range(&segs, *k).unwrap();
            let actual = offsets[*k as usize];
            assert!(lo <= actual && actual <= hi, "key {k}: {lo}..{hi} içinde {actual} olmalı");
        }
        // RAM: model küçük (2000 nokta → birkaç parça)
        assert!(segs.len() * 24 < 2000 * 8, "model << ham indeks");
    }

    #[test]
    fn pgm_gecersiz_girdi() {
        assert!(build_pgm(&[], &[], 1).is_none());
        assert!(build_pgm(&[1, 2], &[1], 1).is_none());
        assert!(build_pgm(&[1, 2], &[1, 2], 0).is_none());
    }

    #[test]
    fn pgm_deterministik() {
        let segs = build_pgm(&[1, 5, 9], &[100, 300, 500], 50).unwrap();
        assert_eq!(pgm_digest(&segs), pgm_digest(&segs));
    }
}
