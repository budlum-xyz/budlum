//! B.U.D. 2.0 - OPTİK TRANSFER KATMANI (ekran→kamera veri transferi)
//!
//! Alınan desen (2026-08-16): bir ekran→kamera çifti, ışık üzerinden kod akışıyla
//! veri taşır (ölçülen: 418.5 KB/s sustained, 1.0 MB / 2.5 s). B.U.D. için bu,
//! .bud içeriğinin **cihaz içi açık** (offline, ağsız) taşınmasıdır:
//! - .bud → segmentlere bölünür (her segment ekrana tek kod olarak yansır),
//! - alıcı kamera kodları okur, segmentleri birleştirir, kayıpsız .bud'u geri kurar.
//!
//! B.U.D. katkısı: kayıpsız + deterministik segmentleme (her segment content_id'li),
//! sıra bozukluğuna dayanıklı (sıra no + toplam), doğrulamalı birleştirme
//! (SHA3-256 digest). Bu, "cihaz içi açık/kapalı" kullanıcı koşulunun taşıma ayağıdır.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const OPTX_MAGIC: [u8; 8] = *b"\xB5OPTX\0\0\0";
pub const OPTX_VERSION: u8 = 1;

/// Optik segment (ekrana basılan kod başına bir tane).
#[derive(Debug, Clone)]
pub struct OptSegment {
    pub index: u32,          // sıra (0 tabanlı)
    pub total: u32,          // toplam segment
    pub data: Vec<u8>,       // ham bayt dilimi (kod gövdesi)
    pub digest: [u8; 32],    // SHA3-256(domain || index || total || data)
}

impl OptSegment {
    fn digest(index: u32, total: u32, data: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"BDLM_OPTX_SEG_V1");
        h.update(index.to_le_bytes());
        h.update(total.to_le_bytes());
        h.update((data.len() as u64).to_le_bytes());
        h.update(data);
        h.finalize().into()
    }

    /// Doğrula (bozuk kod → RED).
    pub fn verify(&self) -> bool {
        Self::digest(self.index, self.total, &self.data) == self.digest
    }
}

/// .bud içeriğini optik segmentlere böl (deterministik; `seg_capacity` kod başına bayt).
pub fn split_optical(data: &[u8], seg_capacity: usize) -> Option<Vec<OptSegment>> {
    if data.is_empty() || seg_capacity == 0 {
        return None;
    }
    let total = data.len().div_ceil(seg_capacity) as u32;
    let mut segs = Vec::with_capacity(total as usize);
    for (i, chunk) in data.chunks(seg_capacity).enumerate() {
        let d = chunk.to_vec();
        segs.push(OptSegment {
            index: i as u32,
            total,
            digest: OptSegment::digest(i as u32, total, &d),
            data: d,
        });
    }
    Some(segs)
}

/// Segmentleri birleştir → orijinal .bud (kayıpsızlık kanıtı).
/// Sıra bozukluğuna dayanıklı: index'e göre sıralar; eksik/çift/bozuk → RED.
pub fn join_optical(segs: &[OptSegment]) -> Option<Vec<u8>> {
    if segs.is_empty() {
        return None;
    }
    let total = segs[0].total;
    if total == 0 || total > 1_000_000 {
        return None;
    }
    // tüm segmentler aynı total'i söylemeli
    if !segs.iter().all(|s| s.total == total) {
        return None;
    }
    // doğrula + sırala
    let mut by_index: Vec<Option<&OptSegment>> = vec![None; total as usize];
    for s in segs {
        if !s.verify() {
            return None;
        }
        if (s.index as usize) >= total as usize {
            return None;
        }
        if by_index[s.index as usize].is_some() {
            return None; // çift segment → RED
        }
        by_index[s.index as usize] = Some(s);
    }
    if by_index.iter().any(|o| o.is_none()) {
        return None; // eksik segment → RED
    }
    let mut out = Vec::new();
    for o in by_index.into_iter().flatten() {
        out.extend_from_slice(&o.data);
    }
    Some(out)
}

/// Böl→birleştir kayıpsızlık + hata toleransı (ölçümleme).
pub fn roundtrip_lossless(data: &[u8], seg_capacity: usize) -> bool {
    match split_optical(data, seg_capacity) {
        Some(segs) => join_optical(&segs) == Some(data.to_vec()),
        None => false,
    }
}

/// Ölçüm: segment sayısı + kod başına yük (ekran→kamera bant genişliği tahmini).
pub fn optical_stats(data: &[u8], seg_capacity: usize) -> Option<(usize, usize)> {
    let segs = split_optical(data, seg_capacity)?;
    Some((segs.len(), seg_capacity))
}

pub fn optx_digest(segs: &[OptSegment]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(OPTX_MAGIC);
    h.update([OPTX_VERSION]);
    for s in segs {
        h.update(s.index.to_le_bytes());
        h.update(s.total.to_le_bytes());
        h.update(s.digest);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optik_kayipsiz_roundtrip() {
        let data: Vec<u8> = (0u8..=255).cycle().take(50_000).collect();
        assert!(roundtrip_lossless(&data, 1024), "büyük .bud kayıpsız");
        assert!(roundtrip_lossless(b"kisa icerik", 512));
        // bozuk kod → RED
        let segs = split_optical(&data, 1024).unwrap();
        let mut bozuk = segs.clone();
        bozuk[3].data[0] ^= 0xFF;
        assert!(join_optical(&bozuk).is_none(), "bozuk segment RED");
    }

    #[test]
    fn sıra_bozukluğuna_dayanıklı() {
        let data = b"siradan bagimsiz birlestirme testi".to_vec();
        let mut segs = split_optical(&data, 8).unwrap();
        segs.reverse(); // sırayı boz
        assert_eq!(join_optical(&segs).unwrap(), data, "sıra bozuk → yine birleşir");
    }

    #[test]
    fn eksik_ve_cift_segment_red() {
        let data = b"eksik segment testi".to_vec();
        let segs = split_optical(&data, 8).unwrap();
        // eksik: ortadakini at
        let mut eksik = segs.clone();
        eksik.remove(1);
        assert!(join_optical(&eksik).is_none(), "eksik segment RED");
        // çift: birini tekrarla
        let mut cift = segs.clone();
        cift.push(segs[0].clone());
        assert!(join_optical(&cift).is_none(), "çift segment RED");
    }

    #[test]
    fn ölçüm_istatistik() {
        let (n, cap) = optical_stats(&vec![0u8; 10_000], 500).unwrap();
        assert_eq!(n, 20);
        assert_eq!(cap, 500);
        assert!(optical_stats(b"", 10).is_none());
    }

    #[test]
    fn deterministik_digest() {
        let segs = split_optical(b"optik determinizm", 4).unwrap();
        assert_eq!(optx_digest(&segs), optx_digest(&segs));
        // farklı parçalama → farklı digest (içerik değişti)
        let segs2 = split_optical(b"optik determinizm!", 4).unwrap();
        assert_ne!(optx_digest(&segs), optx_digest(&segs2));
    }
}
