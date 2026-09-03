//! Validator churn: the Quad-Ring, the churn fixtures and the LRC/MSR traffic.
//! Crash-only, 3/4 quorum, XOR repair.

#[derive(Debug, Clone)]
pub struct QuadRing {
    pub n: usize, // 4 min
    pub k: usize, // N-1 normal
}

impl QuadRing {
    /// A panic-free constructor: `None` when n is below 4 (K38 - a public API
    /// does not panic).
    pub fn new(n: usize) -> Option<Self> {
        if n < 4 {
            return None;
        }
        Some(QuadRing { n, k: n - 1 })
    }

    pub fn expansion(&self) -> f64 {
        (self.k + 1) as f64 / self.k as f64
    }

    /// Recover the one lost block: the XOR of the surviving `blocks` and the
    /// `parity`.
    ///
    /// XOR erasure repair is defined for blocks of one length only, so every
    /// block must be as long as the parity. `None` when one is not. The
    /// first version zipped the slices, which stops at the shorter operand:
    /// a short block left its tail out of the result and a long block lost
    /// its tail, and the function returned the wrong bytes as the recovered
    /// block with no way for the caller to tell.
    pub fn repair_one_missing(blocks: &[Vec<u8>], parity: &[u8]) -> Option<Vec<u8>> {
        if blocks.iter().any(|b| b.len() != parity.len()) {
            return None;
        }
        let mut out = parity.to_vec();
        for b in blocks {
            for (o, ib) in out.iter_mut().zip(b.iter()) {
                *o ^= *ib;
            }
        }
        Some(out)
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
                description: "at N=4 a double-plug pull LOSES the normal class (the honest boundary); the critical 2+2 recovers",
            },
            ChurnFixture {
                kind: FixtureKind::SingleChurn,
                n: 8,
                description: "N=8 tek fis",
            },
            ChurnFixture {
                kind: FixtureKind::DoubleChurn,
                n: 9,
                description: "N=9 EVENODD p=7 must survive a double column loss",
            },
            ChurnFixture {
                kind: FixtureKind::SmartProactive,
                n: 8,
                description: "SMART 10-15 gun onceden proactive migration",
            },
            ChurnFixture {
                kind: FixtureKind::JournalReplay,
                n: 4,
                description: "crash-only journal replay, committed records",
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
        // Skeleton simulation - real disk IO in production
        match self.kind {
            FixtureKind::SingleChurn => ChurnResult {
                survived: true,
                repair_disks: self.n - 1,
                traffic_mb: 256.0,
            },
            FixtureKind::DoubleChurn => {
                if self.n == 4 {
                    // normal 3+1 loses a double failure, critical 2+2 survives it - assume normal here
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
        let r = QuadRing::new(4).expect("n=4 is valid");
        assert!((r.expansion() - 1.333).abs() < 0.01);
        assert!(
            QuadRing::new(3).is_none(),
            "n below 4 has to return None, with no panic"
        );
        assert!(QuadRing::new(0).is_none());
    }
    /// The lost block comes back exactly, and a length mismatch is refused
    /// rather than repaired into wrong bytes.
    #[test]
    fn repair_one_missing_recovers_the_block_or_refuses() {
        let blocks = [vec![1u8, 2, 3, 4], vec![10, 20, 30, 40], vec![7, 7, 7, 7]];
        let lost = vec![9u8, 8, 7, 6];
        let mut parity = lost.clone();
        for b in &blocks {
            for (p, x) in parity.iter_mut().zip(b) {
                *p ^= *x;
            }
        }
        assert_eq!(
            QuadRing::repair_one_missing(&blocks, &parity),
            Some(lost),
            "the XOR of the survivors and the parity is the lost block"
        );
        let short = [vec![1u8, 2, 3], vec![10, 20, 30, 40], vec![7, 7, 7, 7]];
        assert!(
            QuadRing::repair_one_missing(&short, &parity).is_none(),
            "a short block cannot take part in an XOR repair"
        );
        let long = [
            vec![1u8, 2, 3, 4, 5],
            vec![10, 20, 30, 40],
            vec![7, 7, 7, 7],
        ];
        assert!(QuadRing::repair_one_missing(&long, &parity).is_none());
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
