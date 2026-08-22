//! B.U.D. 2.0 - FastCDC İçerik-Tanımlı Parçalama (F55) (2026-08-16)
//!
//! USENIX ATC16 bulgusu: FastCDC, Rabin-CDC'den 10x, Gear/AE'den 3x hızlı; aynı dedup oranı.
//! Sabit 16KB parça yerine İÇERİK-TANIMLI sınırlar (rolling hash) → dosya değişince yalnız
//! değişen parça yeni cid alır (dedup/vergi direnci - çoklu dosya dedup'ı güçlendirir).
//!
//! Gear hash (hızlı, 64-bit çarpma) + alt-bayt maskesi: hash & mask == 0 → parça sınırı.
//! Minimum/maksimum parça boyu (bomba koruması + aşırı küçük parça önleme).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use crate::bud_format_container::content_id;

pub const FASTCDC_MAGIC: [u8; 8] = *b"\xB5FCDC\0\0\0";
pub const FASTCDC_VERSION: u8 = 1;
pub const FCDC_MIN_CHUNK: usize = 4 * 1024; // 4KB
pub const FCDC_AVG_CHUNK: usize = 16 * 1024; // 16KB (V7)
pub const FCDC_MAX_CHUNK: usize = 64 * 1024; // 64KB

/// Gear hash sabitleri (deterministik - aynı girdi aynı sınırlar).
const GEAR_TABLE: [u64; 128] = [
    0x4d5d72f9a9e3a8e1,
    0x1b5e6f3c9d2a7b45,
    0x8f3a6c2e5d9b4f71,
    0x3c7d9e1a5b2f4c86,
    0xa9e3b7c5d1f2a4e8,
    0x6f2c4d8a1e5b7f93,
    0xd5a8c2f6e9b3d175,
    0x2e4b7a9c5f1d8e36,
    0x7d9a3c6e8f2b5d41,
    0xc5f1a7d3b9e2c684,
    0x3a6e8b5d2f7c9a15,
    0x9b2d4f7a8c6e3f52,
    0x5f8a2c6e9b3d7f14,
    0xe1b4c8a5f2d96703,
    0x8c3a7f5b2e9d6c41,
    0x6e2f5a9c3b7d8e52,
    0xa4c8e2f6b3d9a75c,
    0x3f7b9d5a2c6e8f14,
    0xd9a3e7b5c1f2a86d,
    0x2c6e8a5f3b9d7e41,
    0x7a9c3e5f2b8d6a53,
    0xc2f6a9d4b8e3c751,
    0x5b8d2f7a4c6e9f13,
    0x9e3c6f2a5b8d7c14,
    0x4a7c9e2f5b3d8a16,
    0xe8b2d6f4a9c3e715,
    0x6c9e3a7f5b2d8c51,
    0xf3a5c7e9b2d6f41a,
    0x8d2f6a4c8e3b7d15,
    0x3e7b9d2f5a6c8e41,
    0xb5c9e3f7a2d6b84c,
    0x7f2a5c8e3b6d9a41,
    0x5a9c3e7f2b6d8c13,
    0xd4b8e2f6a9c3d751,
    0x2f6a8c3e5b7d9a14,
    0x9c3e7b5d2f8a6c41,
    0x6e8b2d5f7a9c3e15,
    0xc7e9b3d5f2a8c641,
    0x3b6d9a2f5c8e7f14,
    0x8e2f5b7d3a6c9e51,
    0xf6a9c3e7b2d5f84a,
    0x4c8e2f7a5b3d6c91,
    0xa5c7e9b3f2d6a84c,
    0x7d2f6a8c3e5b9a41,
    0x2e5a9c3f7b6d8e13,
    0x9b3d7f2a6c8e5f14,
    0x6f2b5d8a3e7c9a51,
    0xc3e7f9a5b2d6c84d,
    0x5a7c9e2f3b6d8a15,
    0xe9b3d7f2a5c8e641,
    0x8c3e6f2b5d9a7f14,
    0x3f7a9c2e5b8d6a41,
    0xd6a8c2e5f9b3d715,
    0x2b5d7a9c3e6f8a14,
    0x7e9c3a5f2b8d6c51,
    0xa9c5e7b3f2d6a84c,
    0x4f8a2c6e3b7d9a15,
    0xc5e9b3d7f2a8c641,
    0x6a9c2e5f7b3d8a13,
    0x3e7f9b2d5a6c8e41,
    0x8d3b6f2a5c9e7f14,
    0xf2a6c8e3b5d9a741,
    0x5c8e2f7a3b6d9a15,
    0x9e3a5c7f2b8d6a41,
    0x7b9d2f5a6c8e3f14,
    0x2e8a3c6f5b7d9a51,
    0xc9e3f7b2d6a8c415,
    0x4a6c9e2f5b8d3a71,
    0xa8c2e6f3b9d5a74c,
    0x6e3a7c9f2b5d8e14,
    0x3f5b9d2a6c8e7f41,
    0x8c2e5f7b3d9a6c51,
    0x5a8c3e6f2b7d9a13,
    0xd7a9c3e5f2b8d641,
    0x2f6b9d3a5c8e7f14,
    0x9e2c5f7a3b6d8a41,
    0x6c8e2a5f3b7d9a15,
    0xc7e5b3d9f2a8c641,
    0x3b6d8a2f5c9e7f14,
    0x8f2a6c3e5b7d9a51,
    0xf5a9c3e7b2d6f84a,
    0x4c8e3f7a5b2d6c91,
    0xa7c9e5b3f2d8a64c,
    0x7e2f5a8c3b6d9a41,
    0x2b6d9a3e5f7c8e13,
    0x9c3e7f5b2d8a6c14,
    0x6f2a5c8e3b7d9a51,
    0xc3e9f7b5a2d6c84d,
    0x5a7c9e3f2b6d8a15,
    0xe9b5d7f2a3c8e641,
    0x8c3e6f5b2d9a7f14,
    0x3f7a9c2e5b8d6a41,
    0xd6a8c2e5f9b3d715,
    0x2b5d7a9c3e6f8a14,
    0x7e9c3a5f2b8d6c51,
    0xa9c5e7b3f2d6a84c,
    0x4f8a2c6e3b7d9a15,
    0xc5e9b3d7f2a8c641,
    0x6a9c2e5f7b3d8a13,
    0x3e7f9b2d5a6c8e41,
    0x8d3b6f2a5c9e7f14,
    0xf2a6c8e3b5d9a741,
    0x5c8e2f7a3b6d9a15,
    0x9e3a5c7f2b8d6a41,
    0x7b9d2f5a6c8e3f14,
    0x2e8a3c6f5b7d9a51,
    0xc9e3f7b2d6a8c415,
    0x4a6c9e2f5b8d3a71,
    0xa8c2e6f3b9d5a74c,
    0x6e3a7c9f2b5d8e14,
    0x3f5b9d2a6c8e7f41,
    0x8c2e5f7b3d9a6c51,
    0x5a8c3e6f2b7d9a13,
    0xd7a9c3e5f2b8d641,
    0x2f6b9d3a5c8e7f14,
    0x9e2c5f7a3b6d8a41,
    0x6c8e2a5f3b7d9a15,
    0xc7e5b3d9f2a8c641,
    0x3b6d8a2f5c9e7f14,
    0x8f2a6c3e5b7d9a51,
    0xf5a9c3e7b2d6f84a,
    0x4c8e3f7a5b2d6c91,
    0xa7c9e5b3f2d8a64c,
    0x7e2f5a8c3b6d9a41,
    0x2b6d9a3e5f7c8e13,
    0x9c3e7f5b2d8a6c14,
    0x6f2a5c8e3b7d9a51,
    0xc3e9f7b5a2d6c84d,
];

/// İçerik-tanımlı parçalama sonucu (FastCDC - Gear hash).
#[derive(Debug, Clone)]
pub struct FastCdcSplit {
    pub chunks: Vec<Vec<u8>>,
    pub chunk_ids: Vec<[u8; 32]>, // content_id (dedup çapası)
    pub min_chunk: usize,
    pub avg_chunk: usize,
    pub max_chunk: usize,
}

impl FastCdcSplit {
    /// Gear hash ile parçala (deterministik sınırlar).
    pub fn split(data: &[u8], min_c: usize, avg_c: usize, max_c: usize) -> Option<Self> {
        if data.is_empty()
            || min_c == 0
            || avg_c == 0
            || max_c == 0
            || min_c > avg_c
            || avg_c > max_c
        {
            return None;
        }
        let mask = Self::mask_for_avg(avg_c);
        let mut chunks = Vec::new();
        let mut chunk_ids = Vec::new();
        let mut start = 0usize;
        let mut hash: u64 = 0;
        let mut i = min_c.min(data.len());
        // ilk parça en az min_c
        if i >= data.len() {
            let c = data.to_vec();
            chunks.push(c.clone());
            chunk_ids.push(content_id(&c));
            return Some(FastCdcSplit {
                chunks,
                chunk_ids,
                min_chunk: min_c,
                avg_chunk: avg_c,
                max_chunk: max_c,
            });
        }
        while i < data.len() {
            hash = (hash.rotate_left(1))
                .wrapping_mul(GEAR_TABLE[(data[i] & 0x7F) as usize])
                .wrapping_add(data[i] as u64);
            let len = i - start;
            let cut = (hash & mask) == 0;
            if (cut && len >= min_c) || len >= max_c {
                let c = data[start..i].to_vec();
                chunks.push(c.clone());
                chunk_ids.push(content_id(&c));
                start = i;
                hash = 0;
            }
            i += 1;
        }
        // son parça
        if start < data.len() {
            let c = data[start..].to_vec();
            chunks.push(c.clone());
            chunk_ids.push(content_id(&c));
        }
        Some(FastCdcSplit {
            chunks,
            chunk_ids,
            min_chunk: min_c,
            avg_chunk: avg_c,
            max_chunk: max_c,
        })
    }

    /// Ortalama parça boyuna göre maske (avg ≈ 2^avg_bits).
    fn mask_for_avg(avg: usize) -> u64 {
        let bits = avg.ilog2().max(1);

        if bits >= 63 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
    }

    /// Birleştir → orijinal (kayıpsızlık kanıtı).
    pub fn join(&self) -> Vec<u8> {
        let total: usize = self.chunks.iter().map(|c| c.len()).sum();
        let mut out = Vec::with_capacity(total);
        for c in &self.chunks {
            out.extend_from_slice(c);
        }
        out
    }

    /// Parça sayısı + ortalama boyut (tanı).
    pub fn stats(&self) -> (usize, f64) {
        let n = self.chunks.len();
        let avg = if n > 0 {
            self.chunks.iter().map(|c| c.len()).sum::<usize>() as f64 / n as f64
        } else {
            0.0
        };
        (n, avg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fastcdc_roundtrip_lossless() {
        // K38: split → join = orijinal
        let data: Vec<u8> = (0u8..=255).cycle().take(200_000).collect();
        let split = FastCdcSplit::split(&data, FCDC_MIN_CHUNK, FCDC_AVG_CHUNK, FCDC_MAX_CHUNK)
            .expect("split");
        assert_eq!(split.join(), data, "FastCDC kayıpsız");
        assert!(split.chunks.len() > 5, "çok parça");
        // parça boyutları: maks sınıra uyar (aradaki parçalar min sınırda, son parça kısa olabilir)
        for (i, c) in split.chunks.iter().enumerate() {
            assert!(c.len() <= FCDC_MAX_CHUNK, "parça {i} maksimum sınırda");
            if i < split.chunks.len() - 1 {
                assert!(c.len() >= FCDC_MIN_CHUNK, "aradaki parça {i} min sınırda");
            }
        }
        // her parça cid'i doğru
        for (c, id) in split.chunks.iter().zip(split.chunk_ids.iter()) {
            assert_eq!(&content_id(c), id);
        }
    }

    #[test]
    fn small_data_single_chunk() {
        let data = b"kucuk veri";
        let split = FastCdcSplit::split(data, FCDC_MIN_CHUNK, FCDC_AVG_CHUNK, FCDC_MAX_CHUNK)
            .expect("split");
        assert_eq!(split.chunks.len(), 1);
        assert_eq!(split.join(), data);
    }

    #[test]
    fn dedup_friendly_on_edit() {
        // içerik-tanımlı: baştaki küçük değişiklik yalnız ilk parçayı etkiler
        let mut a: Vec<u8> = b"X".repeat(100_000);
        a.extend_from_slice(&(0u8..=255).cycle().take(100_000).collect::<Vec<u8>>());
        let mut b = a.clone();
        b[0] = b'Y'; // ilk baytı değiştir
        let sa = FastCdcSplit::split(&a, FCDC_MIN_CHUNK, FCDC_AVG_CHUNK, FCDC_MAX_CHUNK).unwrap();
        let sb = FastCdcSplit::split(&b, FCDC_MIN_CHUNK, FCDC_AVG_CHUNK, FCDC_MAX_CHUNK).unwrap();
        // ortak parça cid'leri çoğunlukla aynı (değişim yalnız sınır kaydırır - bazı parçalar)
        let ids_a: std::collections::HashSet<_> = sa.chunk_ids.iter().cloned().collect();
        let ids_b: std::collections::HashSet<_> = sb.chunk_ids.iter().cloned().collect();
        let shared = ids_a.intersection(&ids_b).count();
        assert!(
            shared >= 2,
            "içerik-tanımlı parçalama edit'e dirençli: {shared} ortak"
        );
    }

    #[test]
    fn limits() {
        assert!(FastCdcSplit::split(&[], 4, 16, 64).is_none());
        assert!(FastCdcSplit::split(&[1u8; 10], 0, 16, 64).is_none());
        assert!(FastCdcSplit::split(&[1u8; 10], 8, 4, 64).is_none()); // min > avg
        assert!(FastCdcSplit::split(&[1u8; 10], 4, 16, 8).is_none()); // avg > max
    }
}
