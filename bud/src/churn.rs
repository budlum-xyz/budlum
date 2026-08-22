//! Validator churn - Quad-Ring + fixture'lar + LRC/MSR trafik
//! Crash-only, 3/4 quorum, XOR repair

#[derive(Debug, Clone)]
pub struct QuadRing {
    pub n: usize, // 4 min
    pub k: usize, // N-1 normal
}

impl QuadRing {
    /// Panik'siz kurucu: n < 4 ise None (K38 - herkese açık API panik üretmez).
    pub fn new(n: usize) -> Option<Self> {
        if n < 4 {
            return None;
        }
        Some(QuadRing { n, k: n - 1 })
    }

    pub fn expansion(&self) -> f64 {
        (self.k + 1) as f64 / self.k as f64
    }

    // Tek blok kaybi XOR'la kurtarma - iskelet dogruluk
    pub fn repair_one_missing(blocks: &[Vec<u8>], parity: &[u8]) -> Vec<u8> {
        // blocks = kalan k-1 blok + parity XOR'la kayip
        let mut out = vec![0u8; parity.len()];
        for b in blocks {
            for (o, ib) in out.iter_mut().zip(b.iter()) {
                *o ^= *ib;
            }
        }
        for (o, p) in out.iter_mut().zip(parity.iter()) {
            *o ^= *p;
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureKind {
    SingleChurn,
    DoubleChurn,
    SmartProactive,
    JournalReplay,
    ParityRotation,
    PowerDomainAntiCorrelation,
}

#[derive(Debug, Clone)]
pub struct ChurnFixture {
    pub kind: FixtureKind,
    pub n: usize,
    pub description: &'static str,
}

#[derive(Debug, Clone)]
pub struct ChurnResult {
    pub survived: bool,
    pub repair_disks: usize,
    pub traffic_mb: f64,
}

impl ChurnFixture {
    pub fn all() -> Vec<Self> {
        vec![
            ChurnFixture {
                kind: FixtureKind::SingleChurn,
                n: 4,
                description: "N=4 tek fis - 3+1 kurtarmali",
            },
            ChurnFixture {
                kind: FixtureKind::DoubleChurn,
                n: 4,
                description: "N=4 cift fis normal sinif KAYIP (durust sinir), kritik 2+2 kurtarir",
            },
            ChurnFixture {
                kind: FixtureKind::SingleChurn,
                n: 8,
                description: "N=8 tek fis",
            },
            ChurnFixture {
                kind: FixtureKind::DoubleChurn,
                n: 9,
                description: "N=9 EVENODD p=7 cift sutun kaybi kurtarmali",
            },
            ChurnFixture {
                kind: FixtureKind::SmartProactive,
                n: 8,
                description: "SMART 10-15 gun onceden proactive migration",
            },
            ChurnFixture {
                kind: FixtureKind::JournalReplay,
                n: 4,
                description: "Crash-only journal replay, commit'li kayitlar",
            },
            ChurnFixture {
                kind: FixtureKind::ParityRotation,
                n: 8,
                description: "Parite rotasyonu s_no % N, birikme yok",
            },
            ChurnFixture {
                kind: FixtureKind::PowerDomainAntiCorrelation,
                n: 16,
                description: "Guc alani anti-korelasyon, rack/power ayri",
            },
            ChurnFixture {
                kind: FixtureKind::SingleChurn,
                n: 16,
                description: "N=16 %25 churn",
            },
            ChurnFixture {
                kind: FixtureKind::SingleChurn,
                n: 32,
                description: "N=32 genisleme test",
            },
        ]
    }

    pub fn run(&self) -> ChurnResult {
        // Iskelet simulasyon - gercekte disk IO
        match self.kind {
            FixtureKind::SingleChurn => ChurnResult {
                survived: true,
                repair_disks: self.n - 1,
                traffic_mb: 256.0,
            },
            FixtureKind::DoubleChurn => {
                if self.n == 4 {
                    // normal 3+1 cift fis kaybeder, kritik 2+2 kurtarir - burada normal varsay
                    ChurnResult {
                        survived: false,
                        repair_disks: 0,
                        traffic_mb: 0.0,
                    }
                } else {
                    ChurnResult {
                        survived: true,
                        repair_disks: self.n - 1,
                        traffic_mb: 512.0,
                    }
                }
            }
            FixtureKind::SmartProactive => ChurnResult {
                survived: true,
                repair_disks: 1,
                traffic_mb: 128.0,
            },
            FixtureKind::JournalReplay => ChurnResult {
                survived: true,
                repair_disks: 0,
                traffic_mb: 0.0,
            },
            FixtureKind::ParityRotation => ChurnResult {
                survived: true,
                repair_disks: 0,
                traffic_mb: 0.0,
            },
            FixtureKind::PowerDomainAntiCorrelation => ChurnResult {
                survived: true,
                repair_disks: self.n / 2,
                traffic_mb: 1024.0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quad_ring_expansion() {
        let r = QuadRing::new(4).expect("n=4 geçerli");
        assert!((r.expansion() - 1.333).abs() < 0.01);
        assert!(QuadRing::new(3).is_none(), "n<4 None dönmeli (panik yok)");
        assert!(QuadRing::new(0).is_none());
    }
    #[test]
    fn all_fixtures_count_10() {
        assert_eq!(ChurnFixture::all().len(), 10);
    }
    #[test]
    fn single_churn_survives() {
        let f = ChurnFixture {
            kind: FixtureKind::SingleChurn,
            n: 4,
            description: "",
        };
        assert!(f.run().survived);
    }
    #[test]
    fn double_churn_n4_fails_normal() {
        let f = ChurnFixture {
            kind: FixtureKind::DoubleChurn,
            n: 4,
            description: "",
        };
        assert!(!f.run().survived);
    }
}
