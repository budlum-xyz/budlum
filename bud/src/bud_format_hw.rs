//! B.U.D. 2.0 - THE PHYSICAL MEDIA TIER RECORD (F303-F330 plus SMR/HAMR/
//! Silica).
//!
//! Remaining work item #14: the SMR/zoned, HAMR and Silica physical tier
//! evolution - the hardware model. For each media kind: $/TB/month, endurance,
//! power and the suitable content class. `tier_for(usd_ceiling)` picks the
//! cheapest suitable tier for a dollar budget (together with the F16 service
//! classes; the single user price of 0.016 is preserved and the internal cost
//! tiering turns underneath it).

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const HW_MAGIC: [u8; 8] = *b"\xB5HWR1\0\0\0";

#[derive(Debug, Clone, Copy)]
pub struct MediaTier {
    pub name: &'static str,
    pub usd_per_tb_month: f64,
    pub durability_years: u64,
    pub idle_w_per_tb: f64,
    pub write_once: bool,
    pub note: &'static str,
}

pub const MEDIA_TIERS: &[MediaTier] = &[
    MediaTier {
        name: "HDD-CMR",
        usd_per_tb_month: 0.23342,
        durability_years: 5,
        idle_w_per_tb: 7.0,
        write_once: false,
        note: "the price.rs floor (hot/warm)",
    },
    MediaTier {
        name: "HDD-SMR",
        usd_per_tb_month: 0.175,
        durability_years: 5,
        idle_w_per_tb: 6.0,
        write_once: false,
        note: "F303: $30-45/TB; a zoned, append-only cold tier",
    },
    MediaTier {
        name: "HAMR",
        usd_per_tb_month: 0.145,
        durability_years: 6,
        idle_w_per_tb: 6.0,
        write_once: false,
        note: "F305: 36-44TB, $4/TB by 2029; density",
    },
    MediaTier {
        name: "QLC-SSD",
        usd_per_tb_month: 0.62,
        durability_years: 4,
        idle_w_per_tb: 2.0,
        write_once: false,
        note: "F311: a hot tier; DWPD 0.1-0.3 for cold reads",
    },
    MediaTier {
        name: "LTO-tape",
        usd_per_tb_month: 0.00025,
        durability_years: 30,
        idle_w_per_tb: 0.0,
        write_once: true,
        note: "F3/F307: deep cold, 0W idle (coded as the tape class)",
    },
    MediaTier {
        name: "M-Disc",
        usd_per_tb_month: 0.012,
        durability_years: 1000,
        idle_w_per_tb: 0.0,
        write_once: true,
        note: "an optical archive; a read-write drive is required",
    },
    MediaTier {
        name: "Silica-glass",
        usd_per_tb_month: 0.01,
        durability_years: 10_000,
        idle_w_per_tb: 0.0,
        write_once: true,
        note: "F256: 7TB per plate, Azure AI reading - a future ultra-archive",
    },
    MediaTier {
        name: "DNA",
        usd_per_tb_month: 800.0,
        durability_years: 1000,
        idle_w_per_tb: 0.0,
        write_once: true,
        note: "F168: $800M/TB - REFUSED (not economical)",
    },
];

pub fn tier_get(name: &str) -> Option<&'static MediaTier> {
    MEDIA_TIERS.iter().find(|t| t.name == name)
}

/// The cheapest suitable tier for a dollar budget (the write-once constraint
/// is optional).
pub fn cheapest_tier(usd_ceiling: f64, allow_write_once: bool) -> Option<&'static MediaTier> {
    MEDIA_TIERS
        .iter()
        .filter(|t| t.usd_per_tb_month <= usd_ceiling && (allow_write_once || !t.write_once))
        // `partial_cmp().unwrap()` panics on a NaN price. `total_cmp` accepts
        // NaN as ordered and gives a determinate ordering instead of a panic.
        .min_by(|a, b| a.usd_per_tb_month.total_cmp(&b.usd_per_tb_month))
}

/// The 0.016 single-price target: which media holds it directly?
pub fn media_holds_ceiling(usd: f64, ceiling: f64) -> bool {
    usd <= ceiling
}

pub fn hw_digest() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(HW_MAGIC);
    for t in MEDIA_TIERS {
        h.update(t.name.as_bytes());
        h.update(t.usd_per_tb_month.to_le_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tape_is_under_the_0_016_ceiling() {
        assert!(media_holds_ceiling(
            tier_get("LTO-tape").unwrap().usd_per_tb_month,
            0.016
        ));
        assert!(!media_holds_ceiling(
            tier_get("HDD-CMR").unwrap().usd_per_tb_month,
            0.016
        ));
    }

    #[test]
    fn the_cheapest_tier_is_chosen_correctly() {
        // With a 0.016 budget: write-once allowed gives tape, write-once
        // forbidden gives nothing.
        assert_eq!(cheapest_tier(0.016, true).unwrap().name, "LTO-tape");
        assert!(
            cheapest_tier(0.016, false).is_none()
                || cheapest_tier(0.016, false).unwrap().usd_per_tb_month > 0.016
        );
    }

    #[test]
    fn dna_is_refused() {
        let dna = tier_get("DNA").unwrap();
        assert!(dna.usd_per_tb_month > 100.0);
    }

    #[test]
    fn the_hw_digest_is_deterministic() {
        assert_eq!(hw_digest(), hw_digest());
    }
}
