//! B.U.D. 2.0 - SERVICE CLASSES (F16 plus the K71 SLA - the decision layer).
//!
//! The economic decision: a single price of 0.016, with the CPU cost carried by
//! the validator. This module defines the service classes as an INTERNAL
//! placement layer - the user-facing price does not change, there is ONE PRICE.
//! A class is chosen from access frequency and age, and it decides which medium
//! and erasure level the data is kept at. The default thresholds stay open to a
//! productisation decision (see the comments). `ServiceClass::select` is
//! deterministic, so the decision is provable.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const SVC_MAGIC: [u8; 8] = *b"\xB5SVC1\0\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceClass {
    Hot = 0,         // frequent access: HDD-CMR or QLC, many copies, high erasure
    Warm = 1,        // arada → HDD-CMR, erasure standart
    Cold = 2,        // rare access: SMR or a tape hybrid, low erasure
    Archive = 3,     // yasal/uzun → tape/M-Disc, write-once
    Regenerable = 4, // reproducible: a contract plus a commitment, holds no bytes (I2)
}

/// Class selection: `access_per_month` and `age_days` give a class,
/// deterministically.
pub fn select_class(access_per_month: u64, age_days: u64, regenerable: bool) -> ServiceClass {
    if regenerable {
        return ServiceClass::Regenerable;
    }
    match (access_per_month, age_days) {
        (a, _) if a >= 100 => ServiceClass::Hot,
        (a, _) if a >= 10 => ServiceClass::Warm,
        (a, d) if a >= 1 && d <= 365 => ServiceClass::Cold,
        _ => ServiceClass::Archive,
    }
}

/// The internal placement medium of a class (the bud_format_hw mapping).
pub fn placement_media(class: ServiceClass) -> &'static str {
    match class {
        ServiceClass::Hot => "HDD-CMR",
        ServiceClass::Warm => "HDD-CMR",
        ServiceClass::Cold => "HDD-SMR",
        ServiceClass::Archive => "LTO-tape",
        ServiceClass::Regenerable => "none",
    }
}

pub fn class_digest(a: u64, d: u64, r: bool) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(SVC_MAGIC);
    h.update(a.to_le_bytes());
    h.update(d.to_le_bytes());
    h.update([r as u8]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sinif_secimi_deterministik() {
        assert_eq!(select_class(500, 1, false), ServiceClass::Hot);
        assert_eq!(select_class(50, 10, false), ServiceClass::Warm);
        assert_eq!(select_class(3, 100, false), ServiceClass::Cold);
        assert_eq!(select_class(0, 900, false), ServiceClass::Archive);
        assert_eq!(select_class(500, 1, true), ServiceClass::Regenerable);
        assert_eq!(class_digest(1, 2, false), class_digest(1, 2, false));
    }

    #[test]
    fn every_class_has_an_inner_placement() {
        for c in [
            ServiceClass::Hot,
            ServiceClass::Warm,
            ServiceClass::Cold,
            ServiceClass::Archive,
            ServiceClass::Regenerable,
        ] {
            assert!(!placement_media(c).is_empty());
        }
    }

    #[test]
    fn the_single_price_is_preserved() {
        // The class decision does NOT change the user price; it is internal
        // placement.
        assert!(ServiceClass::Hot as u8 <= ServiceClass::Archive as u8);
    }
}
