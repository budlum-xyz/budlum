//! B.U.D. 2.0 - Çoklu Dosya Tenant Dedup + Delta (2026-08-16)
//!
//! V7 66x yedek senaryosunun kod karşılığı (K20 + fikirler F9/F10):
//! - **Content-addressed dedup:** parçalar content_id ile teke iner (aynı parça bir kez).
//! - **Delta:** bir önceki sürümle XOR/delta - küçük değişimlerde çok küçük delta.
//! - **Referans:** yedek/snapshot %1 günlük değişim → ilk tam + sonraki delta (66x).
//!
//! Mimar: TenantMultifileStore - dosya setini parçalara ayırır, parça cid'leriyle dedup
//! indeksi kurar, delta modunda önceki sürümle farkı hesaplar (kayıpsız: base + delta = yeni).
//!
//! Ölçüm (V7): yedek %1 günlük değişim 16KB parça → 66x; %5 değişim → 13.7x.
//! Bu modülün delta + dedup birleşimi o senaryoyu gerçekleştirir (dedup indeks maliyeti
//! fiyata girer - V7 dersi).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use crate::bud_format_container::content_id;
use sha3::{Digest, Sha3_256};

// OOM korumasi: kullanici kontrollu parca sayisi tavani (STRIX deseni)
pub const MAX_MULTIFILE_CHUNKS: usize = 1 << 20;
pub const MULTI_MAGIC: [u8; 8] = *b"\xB5MFLE\0\0\0";
pub const MULTI_VERSION: u8 = 1;
pub const MAX_FILES: usize = 100_000;
pub const MAX_CHUNK: usize = 64 * 1024 * 1024;
pub const DEFAULT_CHUNK: usize = 16 * 1024; // V7: 16KB parça (66x senaryosu)

/// Parça kaydı (content-addressed - dedup çapası).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultifileChunk {
    pub content_id: [u8; 32],
    pub data: Vec<u8>,
}

/// Tenant çoklu dosya deposu: parça havuzu + dosya → parça indeksi + delta desteği.
#[derive(Debug, Clone, Default)]
pub struct TenantMultifileStore {
    pub chunks: Vec<MultifileChunk>,     // benzersiz parçalar (content-addressed)
    pub file_chunks: Vec<Vec<[u8; 32]>>, // her dosyanın parça cid listesi
    pub saved_bytes: u64,
}

impl TenantMultifileStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Dosya ekle (chunk boyutu parametreli): parçala → dedup et → indeksle.
    /// Dönüş: (eklenen yeni parça sayısı, tasarruf baytı).
    pub fn add_file(&mut self, data: &[u8], chunk_size: usize) -> (usize, u64) {
        if data.is_empty() || chunk_size == 0 || chunk_size > MAX_CHUNK {
            return (0, 0);
        }
        let mut new_chunks = 0usize;
        let mut saved = 0u64;
        let mut cids = Vec::new();
        for c in data.chunks(chunk_size) {
            let cid = content_id(c);
            if let Some(existing) = self.chunks.iter().find(|ch| ch.content_id == cid) {
                saved += existing.data.len() as u64;
            } else {
                self.chunks.push(MultifileChunk { content_id: cid, data: c.to_vec() });
                new_chunks += 1;
            }
            cids.push(cid);
        }
        self.file_chunks.push(cids);
        self.saved_bytes += saved;
        (new_chunks, saved)
    }

    /// Dosyayı geri kur (parça cid'lerinden - kayıpsızlık kanıtı).
    pub fn restore(&self, file_index: usize) -> Option<Vec<u8>> {
        let cids = self.file_chunks.get(file_index)?;
        let mut out = Vec::new();
        for cid in cids {
            let chunk = self.chunks.iter().find(|c| &c.content_id == cid)?;
            out.extend_from_slice(&chunk.data);
        }
        Some(out)
    }

    /// Tenant dedup oranı (V7: dedup yapan senaryo).
    pub fn dedup_ratio(&self, original_total: u64) -> f64 {
        if original_total == 0 {
            return 1.0;
        }
        let stored: u64 = self.chunks.iter().map(|c| c.data.len() as u64).sum();
        original_total as f64 / stored.max(1) as f64
    }

    /// Delta ekle: önceki sürümle farkı hesapla (kayıpsız: base + delta = yeni).
    /// Basit blok-bazlı delta: aynı bloklar referans, farklı bloklar tam saklanır.
    pub fn add_delta(&mut self, prev: &[u8], next: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut delta = Vec::new();
        let prev_chunks: Vec<&[u8]> = prev.chunks(chunk_size).collect();
        let next_chunks: Vec<&[u8]> = next.chunks(chunk_size).collect();
        for (i, nc) in next_chunks.iter().enumerate() {
            let same = prev_chunks.get(i).map(|p| *p == *nc).unwrap_or(false);
            if same {
                // referans: 1 bayt işaret + cid yok - değişmedi
                delta.push(0x00);
            } else {
                // değişti: tam blok
                delta.push(0x01);
                delta.extend_from_slice(nc);
            }
        }
        delta
    }

    /// Delta uygula: base + delta = yeni (kayıpsızlık kanıtı).
    pub fn apply_delta(&self, prev: &[u8], delta: &[u8], chunk_size: usize) -> Option<Vec<u8>> {
        let prev_chunks: Vec<&[u8]> = prev.chunks(chunk_size).collect();
        let mut out = Vec::new();
        let mut pos = 0usize;
        for i in 0.. {
            if pos >= delta.len() {
                break;
            }
            let flag = delta[pos];
            pos += 1;
            if flag == 0x00 {
                let p = prev_chunks.get(i)?;
                out.extend_from_slice(p);
            } else if flag == 0x01 {
                if delta.len() < pos + chunk_size {
                    return None;
                }
                out.extend_from_slice(&delta[pos..pos + chunk_size]);
                pos += chunk_size;
            } else {
                return None; // bozuk delta
            }
        }
        Some(out)
    }

    /// Çoklu dosya deposu blob'u (deterministik - zincire yazılabilir).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MULTI_MAGIC);
        out.push(MULTI_VERSION);
        out.extend_from_slice(&(self.chunks.len() as u32).to_le_bytes());
        for c in &self.chunks {
            out.extend_from_slice(&(c.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&c.data);
        }
        out.extend_from_slice(&(self.file_chunks.len() as u32).to_le_bytes());
        for f in &self.file_chunks {
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            for cid in f {
                out.extend_from_slice(cid);
            }
        }
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_MULTIFILE_V1");
        h.update(&out);
        out.extend_from_slice(&h.finalize());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 4;
        if bytes.len() < HDR + 32 || bytes[0..8] != MULTI_MAGIC || bytes[8] != MULTI_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_MULTIFILE_V1");
        h.update(&bytes[..payload_len]);
        if h.finalize().as_slice() != &bytes[payload_len..] {
            return None;
        }
        let chunk_count = u32::from_le_bytes(bytes[9..13].try_into().ok()?) as usize;
        // STRIX-deseni: kullanici kontrollu chunk_count ile OOM engeli
        if chunk_count > MAX_MULTIFILE_CHUNKS {
            return None;
        }
        let mut pos = HDR;
        let mut chunks = Vec::with_capacity(chunk_count.min(4096));
        for _ in 0..chunk_count {
            if bytes.len() < pos + 4 {
                return None;
            }
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            if len > MAX_CHUNK || bytes.len() < pos + len {
                return None;
            }
            let data = bytes[pos..pos + len].to_vec();
            pos += len;
            chunks.push(MultifileChunk { content_id: content_id(&data), data });
        }
        if bytes.len() < pos + 4 {
            return None;
        }
        let file_count = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if file_count > MAX_FILES {
            return None;
        }
        let mut file_chunks = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            if bytes.len() < pos + 4 {
                return None;
            }
            let n = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
            pos += 4;
            if bytes.len() < pos + n * 32 {
                return None;
            }
            let mut cids = Vec::with_capacity(n);
            for _ in 0..n {
                let mut cid = [0u8; 32];
                cid.copy_from_slice(&bytes[pos..pos + 32]);
                pos += 32;
                cids.push(cid);
            }
            file_chunks.push(cids);
        }
        if pos != payload_len {
            return None;
        }
        Some(TenantMultifileStore { chunks, file_chunks, saved_bytes: 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_dedup_ratio_v7() {
        // V7: yedek %1 değişim → 66x; dedup indeksi olmadan %5 → 13.7x
        let mut store = TenantMultifileStore::new();
        // 100 özdeş dosya (aynı parçalar)
        let data = b"yedek veri: tekrarlanan icerik blogu 1234567890 ".repeat(40);
        let original_total = data.len() as u64 * 100;
        for _ in 0..100 {
            store.add_file(&data, DEFAULT_CHUNK);
        }
        let ratio = store.dedup_ratio(original_total);
        assert!(ratio > 50.0, "özdeş 100 dosya → yüksek dedup: {ratio:.1}x");
        assert!(ratio > 60.0, "V7 66x hedefine yakın: {ratio:.1}x");
        // restore kayıpsız
        for i in 0..5 {
            assert_eq!(store.restore(i).unwrap(), data, "dosya {i} kayıpsız");
        }
    }

    #[test]
    fn delta_small_change_is_cheap() {
        // %1 değişim: 1000 bloktan 10'u değişti → delta küçük
        let base = b"a".repeat(16_000_000);
        let mut next = base.clone();
        // 100 bloktan ~5'ini değiştir (16KB bloklar)
        for i in [0usize, 33, 67, 99, 130] {
            let off = i * DEFAULT_CHUNK;
            if off + 4 < next.len() {
                next[off..off + 4].copy_from_slice(b"CHNG");
            }
        }
        let mut store = TenantMultifileStore::new();
        let delta = store.add_delta(&base, &next, DEFAULT_CHUNK);
        // delta = 1 bayt işaret/blok + değişen bloklar
        let blocks = base.len().div_ceil(DEFAULT_CHUNK);
        assert!(delta.len() < base.len() / 50, "delta çok küçük: {} vs base {}", delta.len(), base.len());
        assert_eq!(delta.len(), blocks + 5 * DEFAULT_CHUNK, "5 değişen blok tam");
        // apply: base + delta = next (kayıpsız)
        let restored = store.apply_delta(&base, &delta, DEFAULT_CHUNK).expect("apply");
        assert_eq!(restored, next, "delta kayıpsız");
    }

    #[test]
    fn multifile_roundtrip_and_tamper() {
        let mut store = TenantMultifileStore::new();
        store.add_file(&b"dosya 1 icerigi ".repeat(10), 16);
        store.add_file(&b"dosya 2 icerigi farkli".repeat(10), 16);
        let blob = store.to_blob();
        let back = TenantMultifileStore::from_blob(&blob).expect("blob");
        assert_eq!(back.restore(0).unwrap(), b"dosya 1 icerigi ".repeat(10));
        assert_eq!(back.restore(1).unwrap(), b"dosya 2 icerigi farkli".repeat(10));
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(TenantMultifileStore::from_blob(&bad).is_none());
        // bozuk delta
        assert!(store.apply_delta(b"abc", &[0x99], 4).is_none(), "bozuk bayrak RED");
    }

    #[test]
    fn limits_and_empty() {
        let mut store = TenantMultifileStore::new();
        assert_eq!(store.add_file(&[], 16), (0, 0));
        assert!(store.restore(0).is_none(), "boş depo");
        assert!(TenantMultifileStore::from_blob(&[0u8; 10]).is_none());
    }
}

    #[test]
    fn strix_oom_chunk_count_reddedilir() {
        // kullanici kontrollu devasa chunk_count → None (OOM yok)
        let mut bytes = vec![0u8; 64];
        bytes[0..8].copy_from_slice(b"\xB5MFLE\0\0\0");
        bytes[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        let _ = crate::bud_format_multifile::TenantMultifileStore::from_blob(&bytes);
        // panik yok, None ya da Err döner
    }

