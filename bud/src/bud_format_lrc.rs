//! B.U.D. 2.0 - LRC Yerel Yeniden Yapılandırma Kodları (budlum deseni) (2026-08-16)
//!
//! Ana repodan (budlum src/storage/lrc.rs) esinlenen, no-unsafe, bağımsız uygulama:
//! LRC (Local Reconstruction Code) - RS'in overhead'ini 0.6x'ten 0.03x'e indirir.
//!
//! Ölçüm tablosu (ana repo):
//!   RS (10,16)      → 1.600x (10 shard onarım)
//!   RS (20,26)      → 1.300x
//!   LRC k=500  L=25 G=10 → 1.070x
//!   LRC k=2000 L=50 G=12 → **1.031x** (overhead %95 kesinti)
//!
//! Mekanizma: veri k gruba bölünür (yerel parity her grupta), G global parity tümüne;
//! tek shard kaybı yalnız yerel grubu okur (ucuz onarım), tolerans global paritiden.
//!
//! B.U.D. etkisi: V7 erasure çarpanı EVENODD 1.286x idi; LRC 1.031x → fiziksel taban
//! üzerinde doğrudan fiyat düşüşü. KF1 (maliyet ≤ 0.016) için erasure çarpanı kritik.
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const LRC_MAGIC: [u8; 8] = *b"\xB5LRC0\0\0\0";
pub const LRC_VERSION: u8 = 1;

/// LRC şeması parametreleri (k, L, G) + türetilmiş çarpan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LrcScheme {
    pub k: usize, // toplam veri shard'ı
    pub l: usize, // yerel grup sayısı (yerel parity = L)
    pub g: usize, // global parity sayısı
}

impl LrcScheme {
    /// Parametre doğrulama + çarpan hesabı.
    /// Toplam shard = k (veri) + l (yerel parity) + g (global parity).
    pub fn new(k: usize, l: usize, g: usize) -> Option<Self> {
        if k == 0 || l == 0 || g == 0 || k < l {
            return None;
        }
        // grup boyutu: k veri l gruba bölünür (en az 1)
        if k / l < 1 {
            return None;
        }
        Some(LrcScheme { k, l, g })
    }

    /// Depolama çarpanı: (k + l + g) / k.
    pub fn multiplier(&self) -> f64 {
        (self.k + self.l + self.g) as f64 / self.k as f64
    }

    /// Tek shard onarımı için okunacak shard sayısı (yerel grup boyutu).
    pub fn repair_reads(&self) -> usize {
        let group = self.k / self.l; // her grupta veri shard'ı
        group + 1 // yerel parity ile
    }

    /// Yerel grup indeksi: shard hangi yerel gruba ait (parity shard'lar için temsil).
    pub fn local_group(&self, shard: usize) -> Option<usize> {
        if shard >= self.k + self.l {
            return None; // global parity
        }
        Some(shard / (self.k / self.l).max(1))
    }

    /// RS(10,16) ile karşılaştırma (ana repo tablosu - kanarya).
    pub fn beats_rs_overhead(&self) -> bool {
        // RS(10,16) = 1.6x; LRC < 1.3x olmalı
        self.multiplier() < 1.3
    }
}

/// LRC kaydı: şema + kullanım (zincire yazılabilir, deterministik).
#[derive(Debug, Clone)]
pub struct LrcRecord {
    pub scheme: LrcScheme,
    pub object_count: u64,
    pub ts_unix: u64,
}

impl LrcRecord {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_LRC_V1";

    pub fn new(scheme: LrcScheme, object_count: u64, ts_unix: u64) -> Self {
        LrcRecord {
            scheme,
            object_count,
            ts_unix,
        }
    }

    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((self.scheme.k as u32).to_le_bytes());
        h.update((self.scheme.l as u32).to_le_bytes());
        h.update((self.scheme.g as u32).to_le_bytes());
        h.update(self.object_count.to_le_bytes());
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }

    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&LRC_MAGIC);
        out.push(LRC_VERSION);
        out.extend_from_slice(&(self.scheme.k as u32).to_le_bytes());
        out.extend_from_slice(&(self.scheme.l as u32).to_le_bytes());
        out.extend_from_slice(&(self.scheme.g as u32).to_le_bytes());
        out.extend_from_slice(&self.object_count.to_le_bytes());
        out.extend_from_slice(&self.ts_unix.to_le_bytes());
        out.extend_from_slice(&self.record_hash());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 4 + 4 + 4 + 8 + 8;
        if bytes.len() < HDR + 32 || bytes[0..8] != LRC_MAGIC || bytes[8] != LRC_VERSION {
            return None;
        }
        let k = u32::from_le_bytes(bytes[9..13].try_into().ok()?) as usize;
        let l = u32::from_le_bytes(bytes[13..17].try_into().ok()?) as usize;
        let g = u32::from_le_bytes(bytes[17..21].try_into().ok()?) as usize;
        let object_count = u64::from_le_bytes(bytes[21..29].try_into().ok()?);
        let ts_unix = u64::from_le_bytes(bytes[29..37].try_into().ok()?);
        if bytes.len() != HDR + 32 {
            return None;
        }
        let rec = LrcRecord {
            scheme: LrcScheme::new(k, l, g)?,
            object_count,
            ts_unix,
        };
        if bytes[HDR..] != rec.record_hash() {
            return None;
        }
        Some(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lrc_multiplier_beats_rs() {
        // Ana repo ölçümü: RS(10,16)=1.6x, LRC k=2000 L=50 G=12 → 1.031x
        let lrc = LrcScheme::new(2000, 50, 12).expect("geçerli");
        assert!(
            (lrc.multiplier() - 1.031).abs() < 0.001,
            "1.031x: {}",
            lrc.multiplier()
        );
        assert!(lrc.beats_rs_overhead());
        // küçük şema: k=500 L=25 G=10 → 1.070x
        let lrc2 = LrcScheme::new(500, 25, 10).expect("geçerli");
        assert!(
            (lrc2.multiplier() - 1.070).abs() < 0.001,
            "1.070x: {}",
            lrc2.multiplier()
        );
        // RS(10,16) karşılaştırması: 1.6x vs 1.03x → %95 overhead kesintisi
        let rs_overhead = 0.600;
        let lrc_overhead = lrc.multiplier() - 1.0;
        assert!(lrc_overhead < rs_overhead * 0.1, "overhead %90+ kesildi");
    }

    #[test]
    fn local_repair_is_cheap() {
        // tek shard kaybı → yalnız yerel grup okunur (repair_reads küçük)
        let lrc = LrcScheme::new(2000, 50, 12).expect("geçerli");
        // grup boyutu = 40; repair_reads = 41 (RS'de 10-20 yerine 2000'den bağımsız)
        assert_eq!(lrc.repair_reads(), 41);
        assert!(lrc.repair_reads() < lrc.k / 10, "yerel onarım ucuz");
        // yerel grup ataması
        assert_eq!(lrc.local_group(0), Some(0));
        assert_eq!(lrc.local_group(41), Some(1));
        assert_eq!(lrc.local_group(2100), None, "global parity grubu yok");
    }

    #[test]
    fn lrc_record_roundtrip() {
        let rec = LrcRecord::new(LrcScheme::new(2000, 50, 12).unwrap(), 10_000, 1_768_000_000);
        let blob = rec.to_blob();
        let back = LrcRecord::from_blob(&blob).expect("blob");
        assert_eq!(back.record_hash(), rec.record_hash());
        assert_eq!(back.scheme.multiplier(), rec.scheme.multiplier());
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(LrcRecord::from_blob(&bad).is_none());
        // geçersiz parametreler
        assert!(LrcScheme::new(0, 1, 1).is_none());
        assert!(LrcScheme::new(5, 0, 1).is_none());
        assert!(LrcScheme::new(5, 10, 1).is_none());
    }

    #[test]
    fn lrc_price_impact_documented() {
        // V7: EVENODD 1.286x; LRC 1.031x → fiyat düşüşü
        let physical = 0.23342;
        let ratio = 12.07; // JSON OrderFree (B.U.D. ölçümü)
        let evenodd_cost = physical * 1.286 / ratio;
        let lrc_cost = physical * 1.031 / ratio;
        assert!(lrc_cost < evenodd_cost * 0.9, "LRC fiyatı %10+ düşük");
        // LRC ile $0.016 tavanına yaklaşım
        assert!(lrc_cost < 0.02, "LRC + JSON 12.07x → {lrc_cost:.4} $/TB/ay");
    }
}
