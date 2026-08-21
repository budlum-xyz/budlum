//! B.U.D. 2.0 - Erişim-detay seviyesi / Culling (oyun motoru deseni) (2026-08-16)
//!
//! Kapsam: oyun motorlarındaki culling yöntemlerinin .bud sıkıştırmasına uyarlanması.
//! Oyun motorları büyük sahneyi CLUSTER'lara böler; yalnız ekranda
//! GÖRÜNEN cluster'lar yüklenir (frustum/occlusion culling), mesafeye göre detay seviyesi seviyesi
//! düşer, gerisi diskte sıkışık bekler. B.U.D. karşılığı:
//!
//! **Erişim-detay seviyesi**: büyük veri nesnesi (video, 3D sahne, harita, log koleksiyonu) cluster'lara
//! bölünür; ERİŞİM SIKLIĞI "ekran görünürlüğü" rolünü oynar:
//!   - Sıcak cluster (sık erişilen) → hızlı depoda, tam detay (detay seviyesi0)
//!   - Ilık cluster (ara sıra) → zstd, orta detay (detay seviyesi1)
//!   - Soğuk cluster (nadir) → arşiv/tape, düşük detay (detay seviyesi2)
//!   - "Görünmeyen" cluster (hiç erişilmemiş) → CULLED: üretilebilir sınıfta hiç saklanmaz
//!
//! Çıktı: CullingPlan (cluster öncelikleri + detay seviyesi ataması + sıcaklık eşikleri) - deterministik,
//! zincire yazılabilir, engine'e bağlanabilir. Kayıpsız: plan, ORİJİNALİN yerine geçmez;
//! hangi cluster'ın nerede/nasıl saklanacağını söyler (tiering kararı).
//!
//! Kod: `#![forbid(unsafe_code)]`, deterministik, panik'siz.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const CULL_MAGIC: [u8; 8] = *b"\xB5CULL\0\0\0";
pub const CULL_VERSION: u8 = 1;
pub const MAX_CLUSTERS: usize = 1_000_000;

/// Cluster sıcaklık sınıfı (erişim sıklığına göre - oyun detay seviyesi karşılığı).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterTier {
    Hot,        // sık erişilen - hızlı depo, tam detay (detay seviyesi0)
    Warm,       // ara sıra - zstd, orta detay (detay seviyesi1)
    Cold,       // nadir - arşiv/tape, düşük detay (detay seviyesi2)
    Culled,     // hiç erişilmemiş - üretilebilir sınıfta saklanmaz
}

impl ClusterTier {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Hot => 0,
            Self::Warm => 1,
            Self::Cold => 2,
            Self::Culled => 3,
        }
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Hot),
            1 => Some(Self::Warm),
            2 => Some(Self::Cold),
            3 => Some(Self::Culled),
            _ => None,
        }
    }
}

/// Culling planı: cluster → tier ataması (erişim sıklığından, deterministik).
#[derive(Debug, Clone)]
pub struct CullingPlan {
    pub cluster_count: usize,
    pub tiers: Vec<ClusterTier>,       // her cluster için tier
    pub access_counts: Vec<u64>,       // erişim sayıları (sıcaklık girdisi)
    pub hot_threshold: u64,            // ≥ bu erişim → Hot
    pub cold_threshold: u64,           // < bu erişim → Cold; 0 → Culled
    pub ts_unix: u64,
}

impl CullingPlan {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_CULLING_V1";

    /// Erişim sayılarından plan üret (deterministik eşiklerle).
    /// hot_threshold ve cold_threshold çağıranın; varsayılan: hot≥10, cold≥1, 0→Culled.
    pub fn from_access(access: &[u64], hot_threshold: u64, cold_threshold: u64, ts: u64) -> Option<Self> {
        if access.is_empty() || access.len() > MAX_CLUSTERS {
            return None;
        }
        let tiers: Vec<ClusterTier> = access.iter().map(|&a| {
            if a >= hot_threshold.max(1) {
                ClusterTier::Hot
            } else if a >= cold_threshold.max(1) {
                ClusterTier::Warm
            } else if a > 0 {
                ClusterTier::Cold
            } else {
                ClusterTier::Culled // hiç erişilmemiş → culling (saklanmaz)
            }
        }).collect();
        Some(CullingPlan {
            cluster_count: access.len(),
            tiers,
            access_counts: access.to_vec(),
            hot_threshold: hot_threshold.max(1),
            cold_threshold: cold_threshold.max(1),
            ts_unix: ts,
        })
    }

    /// Saklanması gereken cluster sayısı (Culled hariç - culling kazancı).
    pub fn stored_clusters(&self) -> usize {
        self.tiers.iter().filter(|t| **t != ClusterTier::Culled).count()
    }

    /// Culling oranı: saklanmayan / toplam (oyun %70-90 culling karşılığı).
    pub fn culling_ratio(&self) -> f64 {
        if self.cluster_count == 0 {
            return 0.0;
        }
        (self.cluster_count - self.stored_clusters()) as f64 / self.cluster_count as f64
    }

    /// Tier dağılım özeti (tiering kararı için).
    pub fn tier_summary(&self) -> (usize, usize, usize, usize) {
        let mut h = 0; let mut w = 0; let mut c = 0; let mut cu = 0;
        for t in &self.tiers {
            match t {
                ClusterTier::Hot => h += 1,
                ClusterTier::Warm => w += 1,
                ClusterTier::Cold => c += 1,
                ClusterTier::Culled => cu += 1,
            }
        }
        (h, w, c, cu)
    }

    /// Deterministik kayıt (zincire yazılabilir).
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(Self::DOMAIN);
        h.update((self.cluster_count as u32).to_le_bytes());
        for (t, a) in self.tiers.iter().zip(self.access_counts.iter()) {
            h.update([t.to_u8()]);
            h.update(a.to_le_bytes());
        }
        h.update(self.hot_threshold.to_le_bytes());
        h.update(self.cold_threshold.to_le_bytes());
        h.update(self.ts_unix.to_le_bytes());
        h.finalize().into()
    }

    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&CULL_MAGIC);
        out.push(CULL_VERSION);
        out.extend_from_slice(&(self.cluster_count as u32).to_le_bytes());
        for (t, a) in self.tiers.iter().zip(self.access_counts.iter()) {
            out.push(t.to_u8());
            out.extend_from_slice(&a.to_le_bytes());
        }
        out.extend_from_slice(&self.hot_threshold.to_le_bytes());
        out.extend_from_slice(&self.cold_threshold.to_le_bytes());
        out.extend_from_slice(&self.ts_unix.to_le_bytes());
        out.extend_from_slice(&self.record_hash());
        out
    }

    pub fn from_blob(bytes: &[u8]) -> Option<Self> {
        const HDR: usize = 8 + 1 + 4;
        if bytes.len() < HDR + 32 || bytes[0..8] != CULL_MAGIC || bytes[8] != CULL_VERSION {
            return None;
        }
        let payload_len = bytes.len() - 32;
        let count = u32::from_le_bytes(bytes[9..13].try_into().ok()?) as usize;
        let _ = payload_len;
        if count > MAX_CLUSTERS {
            return None;
        }
        let mut pos = HDR;
        let mut tiers = Vec::with_capacity(count);
        let mut access_counts = Vec::with_capacity(count);
        for _ in 0..count {
            if bytes.len() < pos + 1 + 8 {
                return None;
            }
            let t = ClusterTier::from_u8(bytes[pos])?;
            pos += 1;
            let a = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
            pos += 8;
            tiers.push(t);
            access_counts.push(a);
        }
        if bytes.len() < pos + 8 + 8 + 8 {
            return None;
        }
        let hot_threshold = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let cold_threshold = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let ts_unix = u64::from_le_bytes(bytes[pos..pos + 8].try_into().ok()?);
        pos += 8;
        if bytes.len() != pos + 32 {
            return None;
        }
        let plan = CullingPlan { cluster_count: count, tiers, access_counts, hot_threshold, cold_threshold, ts_unix };
        if bytes[pos..] != plan.record_hash() {
            return None;
        }
        Some(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_based_tiering() {
        // 10 cluster: 2 sıcak (50,30), 2 ılık (10,5), 3 soğuk (1,1,1), 3 culled (0)
        // eşikler: hot≥20, warm≥5 → 50,30 Hot; 10,5 Warm; 1,1,1 Cold; 0,0,0 Culled
        let access = vec![50, 30, 10, 5, 1, 1, 1, 0, 0, 0];
        let plan = CullingPlan::from_access(&access, 20, 5, 1_768_000_000).expect("plan");
        assert_eq!(plan.tier_summary(), (2, 2, 3, 3));
        assert_eq!(plan.stored_clusters(), 7);
        assert!((plan.culling_ratio() - 0.3).abs() < 0.001, "%30 culling");
        // deterministik kayıt
        let blob = plan.to_blob();
        let back = CullingPlan::from_blob(&blob).expect("blob");
        assert_eq!(back.record_hash(), plan.record_hash());
        // kurcalama red
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(CullingPlan::from_blob(&bad).is_none());
        // limitler
        assert!(CullingPlan::from_access(&[], 10, 1, 1).is_none());
        assert!(CullingPlan::from_blob(&[0u8; 10]).is_none());
    }

    #[test]
    fn hot_content_stays_hot() {
        // sık erişilen cluster her zaman Hot (oyun: ekrandaki hep tam detay)
        let access = vec![1000; 5];
        let plan = CullingPlan::from_access(&access, 10, 1, 1).unwrap();
        assert_eq!(plan.tier_summary(), (5, 0, 0, 0));
        assert_eq!(plan.culling_ratio(), 0.0, "hepsi sıcak → culling yok");
    }

    #[test]
    fn never_accessed_culled() {
        // hiç erişilmemiş → Culled (üretilebilir sınıfta saklanmaz)
        let access = vec![0; 100];
        let plan = CullingPlan::from_access(&access, 10, 1, 1).unwrap();
        assert_eq!(plan.stored_clusters(), 0);
        assert_eq!(plan.culling_ratio(), 1.0, "%100 culling");
        assert_eq!(plan.tier_summary(), (0, 0, 0, 100));
    }
}
