//! B.U.D. 2.0 - Cauchy MDS Erasure (budlum erasure.rs deseni) (2026-08-16)
//!
//! Ana repodan (budlum src/storage/erasure.rs) esinlenen, bağımsız, no-unsafe uygulama:
//! GF(2^8) mod 0x11D üzerinde Cauchy MDS kodu. Sistematik: veri shard'ları byte-for-byte
//! geçer, Cauchy bloğu parity shard'ları üretir. MDS garantisi: herhangi k shard hayatta
//! kalırsa yeniden kurulur (Vandermonde'un singular alt-matris sorunu yok - Cauchy'nin
//! her kare alt-matrisi tersinir, Blomer et al. Theorem 2.2).
//!
//! Alan: GF(2^8) mod 0x11D - Intel ISA-L, Backblaze, QR Reed-Solomon ile aynı.
//! Çarpma log/exp tablolarından; ters alma exp[255 - log[a]].
//!
//! B.U.D. kullanımı: konteyner parçalarına erasure shard üretimi (V7 EVENODD 1.286x
//! alternatifi - LRC 1.031x ile birlikte fiyat düşürür). Kodlama/çözme deterministik.
//!
//! Kod: `#![forbid(unsafe_code)]`, panik'siz, tavanlı (bomba koruması).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const ERASURE_MAGIC: [u8; 8] = *b"\xB5ERAS\0\0\0";
pub const ERASURE_VERSION: u8 = 1;
pub const MAX_SHARDS: usize = 256;   // GF(2^8) sınırı
pub const MAX_SHARD_BYTES: usize = 64 * 1024 * 1024; // 64MB tek shard

/// GF(2^8) mod 0x11D - log/exp tabloları (bir kez kurulur, deterministik).
struct Gf8 {
    log: [u8; 256],
    exp: [u8; 512],
}

impl Gf8 {
    const fn new() -> Self {
        let mut log = [0u8; 256];
        let mut exp = [0u8; 512];
        let mut x: u16 = 1;
        let mut i = 0;
        while i < 255 {
            exp[i as usize] = x as u8;
            log[x as usize] = i as u8;
            x = (x << 1) ^ if x & 0x80 != 0 { 0x11D } else { 0 };
            x &= 0xFF;
            i += 1;
        }
        // exp[255..510] = exp[i+255] = exp[i] (döngü)
        let mut j = 255;
        while j < 510 {
            exp[j as usize] = exp[(j - 255) as usize];
            j += 1;
        }
        Gf8 { log, exp }
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let s = self.log[a as usize] as u16 + self.log[b as usize] as u16;
        self.exp[s as usize]
    }

    fn inv(&self, a: u8) -> Option<u8> {
        if a == 0 {
            return None;
        }
        Some(self.exp[(255 - self.log[a as usize] as u16) as usize])
    }
}

/// Cauchy MDS kodlayıcı: k veri shard + p parity shard (toplam k+p ≤ 255).
pub struct CauchyMds {
    k: usize,
    p: usize,
    gf: Gf8,
}

impl CauchyMds {
    pub fn new(k: usize, p: usize) -> Option<Self> {
        if k == 0 || p == 0 || k + p >= MAX_SHARDS {
            return None;
        }
        Some(CauchyMds { k, p, gf: Gf8::new() })
    }

    /// Cauchy matrisi elemanı: C[i][j] = 1 / (x_i + y_j), x/y kümeleri ayrık.
    /// x = 0..p-1, y = p..p+k-1 (deterministik seçim).
    fn cauchy(&self, i: usize, j: usize) -> Option<u8> {
        // x_i = i, y_j = k + j (GF toplama = XOR)
        let denom = (i as u8) ^ ((self.k + j) as u8);
        self.gf.inv(denom)
    }

    /// Kodla: k veri shard → (k + p) shard (veri aynen + p parity).
    /// Tüm shard'lar eşit boyutlu; bomba korumalı (MAX_SHARD_BYTES).
    pub fn encode(&self, data_shards: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        if data_shards.len() != self.k {
            return None;
        }
        let shard_len = data_shards[0].len();
        if shard_len == 0 || shard_len > MAX_SHARD_BYTES {
            return None;
        }
        for d in data_shards {
            if d.len() != shard_len {
                return None; // eşit boyut şart
            }
        }
        let mut out: Vec<Vec<u8>> = data_shards.to_vec();
        for i in 0..self.p {
            let mut parity = vec![0u8; shard_len];
            for j in 0..self.k {
                let c = self.cauchy(i, j)?;
                if c != 0 {
                    for b in 0..shard_len {
                        parity[b] ^= self.gf.mul(c, data_shards[j][b]);
                    }
                }
            }
            out.push(parity);
        }
        Some(out)
    }

    /// Çöz: hayatta kalan herhangi k shard'dan veriyi yeniden kur (MDS).
    /// `survivors`: (shard_indeks, shard_bayt) çiftleri - indeksler 0..k-1 veri,
    /// k..k+p-1 parity. En az k hayatta kalan olmalı.
    pub fn decode(&self, survivors: &[(usize, Vec<u8>)]) -> Option<Vec<Vec<u8>>> {
        if survivors.len() < self.k {
            return None; // MDS: k'dan az hayatta kalan → kurtarılamaz
        }
        let shard_len = survivors[0].1.len();
        for (_, s) in survivors {
            if s.len() != shard_len {
                return None;
            }
        }
        // k hayatta kalan seç (ilk k - MDS herhangi k alt-kümeyle çalışır)
        let chosen: Vec<(usize, &Vec<u8>)> = survivors.iter().take(self.k).map(|(i, s)| (*i, s)).collect();
        // k x k katsayı matrisini kur: satır = hayatta kalan shard'ın veri shard'larına
        // katkısı. Veri shard'ı j için: shard i veri ise (i==j → 1), parity ise C[i-k][j].
        // A_ij = (i < k) ? (i == j) : C[i-k][j]
        let mut a = vec![vec![0u8; self.k]; self.k];
        for (r, &(si, _)) in chosen.iter().enumerate() {
            for c in 0..self.k {
                a[r][c] = if si < self.k {
                    if si == c { 1 } else { 0 }
                } else {
                    self.cauchy(si - self.k, c).unwrap_or(0)
                };
            }
        }
        // matrisi tersine çevir (Gauss-Jordan GF(2^8)) - tekil değil (MDS)
        let inv = self.invert_matrix(&a)?;
        // veri shard'larını kur: data[c] = Σ_r inv[c][r] * shard[chosen[r]]
        let mut data: Vec<Vec<u8>> = vec![vec![0u8; shard_len]; self.k];
        for c in 0..self.k {
            for r in 0..self.k {
                let coeff = inv[c][r];
                if coeff != 0 {
                    let shard = chosen[r].1;
                    for b in 0..shard_len {
                        data[c][b] ^= self.gf.mul(coeff, shard[b]);
                    }
                }
            }
        }
        Some(data)
    }

    /// GF(2^8) matris tersi (Gauss-Jordan). Tekil → None.
    fn invert_matrix(&self, m: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        let n = m.len();
        let mut aug: Vec<Vec<u8>> = vec![vec![0u8; 2 * n]; n];
        for i in 0..n {
            for j in 0..n {
                aug[i][j] = m[i][j];
            }
            aug[i][n + i] = 1;
        }
        for col in 0..n {
            // pivot bul (sıfır değil)
            let mut pivot = None;
            for r in col..n {
                if aug[r][col] != 0 {
                    pivot = Some(r);
                    break;
                }
            }
            let pivot = pivot?; // tekil
            aug.swap(col, pivot);
            let inv = self.gf.inv(aug[col][col])?;
            for j in 0..2 * n {
                aug[col][j] = self.gf.mul(aug[col][j], inv);
            }
            for r in 0..n {
                if r != col && aug[r][col] != 0 {
                    let f = aug[r][col];
                    for j in 0..2 * n {
                        aug[r][j] ^= self.gf.mul(f, aug[col][j]);
                    }
                }
            }
        }
        Some(aug.iter().map(|row| row[n..].to_vec()).collect())
    }

    /// Erasure kaydı (deterministik blob - zincire yazılabilir).
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_ERASURE_V1");
        h.update((self.k as u32).to_le_bytes());
        h.update((self.p as u32).to_le_bytes());
        h.finalize().into()
    }

    pub fn multiplier(&self) -> f64 {
        (self.k + self.p) as f64 / self.k as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf8_arithmetic() {
        let gf = Gf8::new();
        // 1 * x = x
        assert_eq!(gf.mul(1, 5), 5);
        // x * 0 = 0
        assert_eq!(gf.mul(9, 0), 0);
        // ters: a * inv(a) = 1
        for a in [3u8, 7, 100, 200, 255] {
            let inv = gf.inv(a).expect("sıfır değil");
            assert_eq!(gf.mul(a, inv), 1, "a={a}");
        }
        assert!(gf.inv(0).is_none());
    }

    #[test]
    fn encode_decode_roundtrip() {
        // 4 veri + 2 parity; tüm tek-kayıp senaryolarında kurtar
        let mds = CauchyMds::new(4, 2).expect("geçerli");
        let data: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 64]).collect();
        let encoded = mds.encode(&data).expect("encode");
        assert_eq!(encoded.len(), 6);
        // veri shard'ları aynen
        for i in 0..4 {
            assert_eq!(encoded[i], data[i]);
        }
        // herhangi 4 hayatta kalan → kurtar
        for drop in 0..6 {
            let survivors: Vec<(usize, Vec<u8>)> = encoded.iter().enumerate()
                .filter(|(i, _)| *i != drop)
                .map(|(i, s)| (i, s.clone()))
                .collect();
            let recovered = mds.decode(&survivors).expect("kurtar");
            assert_eq!(recovered, data, "shard {drop} kaybı kurtarıldı");
        }
        // 2 kayıp → 4 hayatta → kurtar
        let survivors: Vec<(usize, Vec<u8>)> = encoded.iter().enumerate()
            .filter(|(i, _)| *i != 1 && *i != 5)
            .map(|(i, s)| (i, s.clone()))
            .collect();
        assert_eq!(mds.decode(&survivors).unwrap(), data);
        // 3 kayıp (3 hayatta < 4) → None
        let too_few: Vec<(usize, Vec<u8>)> = encoded.iter().enumerate()
            .filter(|(i, _)| *i < 3)
            .map(|(i, s)| (i, s.clone()))
            .collect();
        assert!(mds.decode(&too_few).is_none());
    }

    #[test]
    fn erasure_limits() {
        assert!(CauchyMds::new(0, 1).is_none());
        assert!(CauchyMds::new(1, 0).is_none());
        assert!(CauchyMds::new(255, 1).is_none(), "255+1 > 256");
        // eşit olmayan shard boyutu → None
        let mds = CauchyMds::new(2, 1).unwrap();
        assert!(mds.encode(&[vec![1u8; 4], vec![2u8; 5]]).is_none());
        assert!(mds.encode(&[vec![1u8; 4]]).is_none(), "k adedi şart");
    }

    #[test]
    fn multiplier_vs_v7() {
        // RS(4,2) = 1.5x; LRC 1.031x ile birlikte V7 EVENODD 1.286x'ten düşük
        let mds = CauchyMds::new(4, 2).unwrap();
        assert!((mds.multiplier() - 1.5).abs() < 0.001);
        assert!((CauchyMds::new(20, 2).unwrap().multiplier() - 1.1).abs() < 0.001);
        assert!(mds.multiplier() > 1.0);
        assert!(mds.record_hash() != [0u8; 32]);
        assert_eq!(mds.record_hash(), CauchyMds::new(4, 2).unwrap().record_hash(), "deterministik");
    }
}
