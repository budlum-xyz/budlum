//! B.U.D. 2.0 - access level of detail, or culling, in the game engine pattern,
//! 2026-08-16.
//!
//! Scope: adapting the culling methods of game engines to `.bud` compression. A
//! game engine splits a large scene into CLUSTERS and loads only the clusters
//! VISIBLE on screen, by frustum and occlusion culling; the level of detail
//! drops with distance, and the rest waits on disk, compressed. The B.U.D.
//! counterpart:
//!
//! **Access level of detail**: a large data object, a video, a 3D scene, a map
//! or a log collection, is split into clusters, and ACCESS FREQUENCY plays the
//! role of screen visibility.
//!
//!   - A hot cluster, accessed often, goes to fast storage at full detail,
//!     LOD 0.
//!   - A warm cluster, accessed occasionally, goes to zstd at medium detail,
//!     LOD 1.
//!   - A cold cluster, accessed rarely, goes to archive or tape at low detail,
//!     LOD 2.
//!   - An "invisible" cluster, never accessed at all, is CULLED: in the
//!     reproducible class it is not stored at all.
//!
//! The output is a `CullingPlan`, holding the cluster priorities, the level of
//! detail assignment and the temperature thresholds. It is deterministic,
//! writable on chain and wireable into the engine. It is lossless: the plan does
//! not stand in for THE ORIGINAL, it only says where and how each cluster is to
//! be stored, which is a tiering decision.
//!
//! The code is `#![forbid(unsafe_code)]`, deterministic and panic-free.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const CULL_MAGIC: [u8; 8] = *b"\xB5CULL\0\0\0";
pub const CULL_VERSION: u8 = 1;
pub const MAX_CLUSTERS: usize = 1_000_000;

/// The cluster temperature class, by access frequency; the counterpart of a
/// game's level of detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterTier {
    Hot,    // accessed often: fast storage, full detail, LOD 0
    Warm,   // occasional: zstd, medium detail, LOD 1
    Cold,   // rare: archive or tape, low detail, LOD 2
    Culled, // never accessed: not stored at all in the reproducible class
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

/// The culling plan: the cluster-to-tier assignment, derived deterministically
/// from access frequency.
#[derive(Debug, Clone)]
pub struct CullingPlan {
    pub cluster_count: usize,
    pub tiers: Vec<ClusterTier>, // the tier of each cluster
    pub access_counts: Vec<u64>, // the access counts, the temperature input
    pub hot_threshold: u64,      // at or above this many accesses: Hot
    pub cold_threshold: u64,     // below this many accesses: Cold, and zero means Culled
    pub ts_unix: u64,
}

impl CullingPlan {
    pub const DOMAIN: &'static [u8] = b"BDLM_BUD_CULLING_V1";

    /// Build a plan from the access counts, with deterministic thresholds.
    ///
    /// `hot_threshold` and `cold_threshold` belong to the caller; the defaults
    /// are hot at 10 or more, cold at 1 or more, and zero means culled.
    pub fn from_access(
        access: &[u64],
        hot_threshold: u64,
        cold_threshold: u64,
        ts: u64,
    ) -> Option<Self> {
        if access.is_empty() || access.len() > MAX_CLUSTERS {
            return None;
        }
        let tiers: Vec<ClusterTier> = access
            .iter()
            .map(|&a| {
                if a >= hot_threshold.max(1) {
                    ClusterTier::Hot
                } else if a >= cold_threshold.max(1) {
                    ClusterTier::Warm
                } else if a > 0 {
                    ClusterTier::Cold
                } else {
                    ClusterTier::Culled // never accessed, so culled and not stored
                }
            })
            .collect();
        Some(CullingPlan {
            cluster_count: access.len(),
            tiers,
            access_counts: access.to_vec(),
            hot_threshold: hot_threshold.max(1),
            cold_threshold: cold_threshold.max(1),
            ts_unix: ts,
        })
    }

    /// How many clusters must be stored, excluding the culled ones; this is the
    /// culling gain.
    pub fn stored_clusters(&self) -> usize {
        self.tiers
            .iter()
            .filter(|t| **t != ClusterTier::Culled)
            .count()
    }

    /// The culling ratio: not stored over total. In games this is 70 to 90
    /// percent.
    pub fn culling_ratio(&self) -> f64 {
        if self.cluster_count == 0 {
            return 0.0;
        }
        (self.cluster_count - self.stored_clusters()) as f64 / self.cluster_count as f64
    }

    /// A summary of the tier distribution, for the tiering decision.
    pub fn tier_summary(&self) -> (usize, usize, usize, usize) {
        let mut h = 0;
        let mut w = 0;
        let mut c = 0;
        let mut cu = 0;
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

    /// The deterministic record, writable on chain.
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
        let plan = CullingPlan {
            cluster_count: count,
            tiers,
            access_counts,
            hot_threshold,
            cold_threshold,
            ts_unix,
        };
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
        // Ten clusters: 2 hot at 50 and 30, 2 warm at 10 and 5, 3 cold at 1, and
        // 3 culled at 0.
        // With thresholds of hot at 20 or more and warm at 5 or more: 50 and 30
        // are Hot, 10 and 5 are Warm, the three 1s are Cold and the three 0s are
        // Culled.
        let access = vec![50, 30, 10, 5, 1, 1, 1, 0, 0, 0];
        let plan = CullingPlan::from_access(&access, 20, 5, 1_768_000_000).expect("plan");
        assert_eq!(plan.tier_summary(), (2, 2, 3, 3));
        assert_eq!(plan.stored_clusters(), 7);
        assert!(
            (plan.culling_ratio() - 0.3).abs() < 0.001,
            "30 percent culling"
        );
        // The record is deterministic.
        let blob = plan.to_blob();
        let back = CullingPlan::from_blob(&blob).expect("blob");
        assert_eq!(back.record_hash(), plan.record_hash());
        // Tampering is refused.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(CullingPlan::from_blob(&bad).is_none());
        // The limits.
        assert!(CullingPlan::from_access(&[], 10, 1, 1).is_none());
        assert!(CullingPlan::from_blob(&[0u8; 10]).is_none());
    }

    #[test]
    fn hot_content_stays_hot() {
        // A frequently accessed cluster is always Hot; in a game, what is on
        // screen is always at full detail.
        let access = vec![1000; 5];
        let plan = CullingPlan::from_access(&access, 10, 1, 1).unwrap();
        assert_eq!(plan.tier_summary(), (5, 0, 0, 0));
        assert_eq!(
            plan.culling_ratio(),
            0.0,
            "everything is hot, so there is no culling"
        );
    }

    #[test]
    fn never_accessed_culled() {
        // Never accessed means Culled, and in the reproducible class that is not
        // stored.
        let access = vec![0; 100];
        let plan = CullingPlan::from_access(&access, 10, 1, 1).unwrap();
        assert_eq!(plan.stored_clusters(), 0);
        assert_eq!(plan.culling_ratio(), 1.0, "100 percent culling");
        assert_eq!(plan.tier_summary(), (0, 0, 0, 100));
    }
}
