//! .bud economics - fee market, global dedup, Merkle trie integration
//! V6 advanced

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct BudEconomics {
    pub physical_usd: f64, // 0.23342
    pub expansion: f64,    // 1.286
    pub ratio: f64,
    pub device_only: bool,
}

impl BudEconomics {
    /// Monthly cost per TB. K38: an invalid ratio (<=0 or non-finite) -> +inf (it can NEVER
    /// hold the ceiling - an honest REFUSAL); IEEE division is not trusted. device_only -> 0 (free on device).
    pub fn cost_per_tb_month(&self) -> f64 {
        if self.device_only {
            return 0.0;
        }
        if !self.ratio.is_finite() || self.ratio <= 0.0 {
            return f64::INFINITY;
        }
        self.physical_usd * self.expansion / self.ratio
    }

    pub fn fee(&self, size_bytes: usize) -> f64 {
        // fee = base + size * per_byte + sig_len * per_sig
        let base = 0.0001;
        let per_byte = 0.000000001; // $ per byte per month
        let sig_cost = if self.ratio > 10.0 { 0.00002 } else { 0.00005 }; // PQ sig
        base + (size_bytes as f64) * per_byte + sig_cost
    }

    pub fn holds_price(&self, ceiling: f64) -> bool {
        self.cost_per_tb_month() <= ceiling + 1e-12
    }
}

/// The K60 zero-egress model (research: an R2-like zero-egress CDN, p.190):
/// IN-NETWORK access (the same B.U.D. network, a CDN cache, a peer) has ZERO egress; only
/// egress to the internet is charged. Egress is not added to the storage cost (a business model advantage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressZone {
    InNetwork, // the same network/CDN - zero egress (K60)
    Internet,  // external egress - charged at the rate
}

/// Egress cost: InNetwork is always 0 (the zero-egress guarantee, K60).
pub fn egress_cost(zone: EgressZone, tb: f64, rate_usd_per_tb: f64) -> f64 {
    match zone {
        EgressZone::InNetwork => 0.0,
        EgressZone::Internet => {
            if !rate_usd_per_tb.is_finite() || rate_usd_per_tb < 0.0 {
                f64::INFINITY // a broken ratio -> an honest REFUSAL (K38)
            } else {
                tb.max(0.0) * rate_usd_per_tb
            }
        }
    }
}

/// Gate: does egress hold the budget? InNetwork always holds (zero egress).
pub fn holds_egress(zone: EgressZone, tb: f64, rate_usd_per_tb: f64, budget: f64) -> bool {
    egress_cost(zone, tb, rate_usd_per_tb) <= budget + 1e-12
}

/// I6 RESIDUAL CLASS ECONOMICS (I6 of the ideas document; replacing pay-as-you-go):
/// the fee binds only to RESIDUAL bytes; the generatable part pays NO storage fee
/// (only a read fee through the generation market - I3).
/// The generatable class (residual = 0) -> zero monthly storage cost.
pub fn residual_price(
    residual_tb: f64,
    erasure_multiplier: f64,
    coldness: f64,
    physical_usd_per_tb_month: f64,
) -> f64 {
    if !residual_tb.is_finite()
        || residual_tb < 0.0
        || !erasure_multiplier.is_finite()
        || erasure_multiplier < 1.0
        || !coldness.is_finite()
        || coldness < 0.0
        || !physical_usd_per_tb_month.is_finite()
        || physical_usd_per_tb_month < 0.0
    {
        return f64::INFINITY;
    }
    if residual_tb == 0.0 {
        return 0.0;
    }
    let cold_discount = 1.0 - coldness * 0.5;
    residual_tb * erasure_multiplier * physical_usd_per_tb_month * cold_discount
}

/// The I6 gate: the generatable class (zero residual) always holds the commitment.
pub fn residual_holds_price(
    residual_tb: f64,
    erasure_multiplier: f64,
    coldness: f64,
    physical: f64,
    ceiling: f64,
) -> bool {
    residual_price(residual_tb, erasure_multiplier, coldness, physical) <= ceiling + 1e-12
}

/// Economic decision: A SINGLE PRICE.
/// There is one price; costs such as CPU are already borne by the validator.
/// The SINGLE line item the user sees is the storage price; generation/CPU/erasure repair cost
/// is the validator's burden and does not enter the price. Pay-as-you-go was already removed; the I6 residual
/// class economics was SIMPLIFIED by this decision too: every content class starts from the same base price.
/// Price = physical base * erasure multiplier / measured ratio (one formula, for everyone).
pub fn flat_price(
    physical_usd_per_tb_month: f64,
    erasure_multiplier: f64,
    measured_ratio: f64,
) -> f64 {
    if !physical_usd_per_tb_month.is_finite()
        || physical_usd_per_tb_month < 0.0
        || !erasure_multiplier.is_finite()
        || erasure_multiplier < 1.0
        || !measured_ratio.is_finite()
        || measured_ratio <= 0.0
    {
        return f64::INFINITY; // K38: broken input -> an honest REFUSAL
    }
    physical_usd_per_tb_month * erasure_multiplier / measured_ratio
}

/// The SINGLE PRICE gate: does it hold the ceiling? (K19 - with the measured ratio)
pub fn flat_holds_ceiling(physical: f64, erasure: f64, ratio: f64, ceiling: f64) -> bool {
    flat_price(physical, erasure, ratio) <= ceiling + 1e-12
}

// ===========================================================================
// PIPELINE ECONOMICS: a single price, up to the 0.016 USD/TB ceiling.
// ===========================================================================
// For each format class: pipeline_ratio = single_file * multiplier; the multipliers
// are kept inside MEASURED ceilings (bud_format_matrix::matrix_honesty_check).

/// Measured multiplier ceilings (the constants the matrix canary rests on).
pub const CORPUS_DEDUP_MEASURED: f64 = 9.67; // korpus geneli 16KB SHA256
pub const FLEET_DEDUP_MEASURED: f64 = 25.43; // 25 identical ELFs (intra-file chunking)
pub const CULLING_MULT_MEASURED: f64 = 2.52; // 1/(1-0.603), the access pattern

/// Measured media codec ratios (the bud_format_media canary).
pub const AVIF_LOSSLESS_BMP_MEASURED: f64 = 15.84;
pub const JXL_LOSSLESS_PNG_MEASURED: f64 = 4.20;
pub const AVIF_LOSSY_JPEG_MEASURED: f64 = 3.20;
pub const AVIF_LOSSY_GIF_MEASURED: f64 = 16.75;
pub const FLAC_WAV_MEASURED: f64 = 6.26;
pub const AV1_YUV_MEASURED: f64 = 904.0;

/// Pipeline ratio: transform * codec * dedup * culling (every component measured).
pub fn pipeline_ratio(transform: f64, codec: f64, dedup: f64, culling: f64) -> f64 {
    let p = transform.max(1.0) * codec.max(1.0) * dedup.max(1.0) * culling.max(1.0);
    if p.is_finite() && p > 0.0 {
        p
    } else {
        f64::INFINITY
    }
}

/// Pipeline USD/TB/month: 0.23342 * erasure / pipeline_ratio.
pub fn pipeline_price(
    physical_usd_per_tb_month: f64,
    erasure_multiplier: f64,
    transform: f64,
    codec: f64,
    dedup: f64,
    culling: f64,
) -> f64 {
    flat_price(
        physical_usd_per_tb_month,
        erasure_multiplier,
        pipeline_ratio(transform, codec, dedup, culling),
    )
}

/// The pipeline ceiling gate.
pub fn pipeline_holds_ceiling(
    physical: f64,
    erasure: f64,
    ceiling: f64,
    transform: f64,
    codec: f64,
    dedup: f64,
    culling: f64,
) -> bool {
    pipeline_price(physical, erasure, transform, codec, dedup, culling) <= ceiling + 1e-12
}
/// F3/F1151 TAPE ARCHIVE CLASS - cold content on tape (0 W idle):
/// LTO-9 is about 5 USD/TB (30 years); 1 PB over 10 years costs 30K USD versus 480K USD on disk; power/cooling about 1 percent.
/// 0.003 USD/GB/year = 0.00025 USD/TB/month. Access latency is accepted (tape takes minutes).
pub const TAPE_USD_PER_TB_MONTH: f64 = 0.00025; // the F3 measurement

/// Archive class cost: cold content on tape (per TB).
pub fn tape_cost_per_tb_month(tb: f64) -> f64 {
    if !tb.is_finite() || tb < 0.0 {
        return f64::INFINITY;
    }
    tb * TAPE_USD_PER_TB_MONTH
}

/// The archive gate: is cold content on tape below 0.016 USD/TB/month?
pub fn tape_holds_ceiling(tb: f64, ceiling: f64) -> bool {
    tape_cost_per_tb_month(tb) <= ceiling + 1e-12
}

/// The media ladder (F1153): hot NVMe -> QLC -> refurbished HDD -> tape (decreasing TCO).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveTier {
    HotNvme,   // expensive, low latency
    Qlc,       // the warm tier
    RefurbHdd, // $10/TB
    Tape,      // 5 USD/TB, 30 years
}

impl ArchiveTier {
    pub fn usd_per_tb_month(&self) -> f64 {
        match self {
            Self::HotNvme => 0.5,
            Self::Qlc => 0.05,
            Self::RefurbHdd => 0.02,
            Self::Tape => TAPE_USD_PER_TB_MONTH,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GlobalDedup {
    pub chunk_hashes: HashSet<[u8; 32]>,
    pub total_saved_bytes: u64,
}

impl Default for GlobalDedup {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalDedup {
    pub fn new() -> Self {
        Self {
            chunk_hashes: HashSet::new(),
            total_saved_bytes: 0,
        }
    }

    pub fn insert_chunk(&mut self, hash: [u8; 32], size: usize) -> bool {
        if self.chunk_hashes.contains(&hash) {
            self.total_saved_bytes += size as u64;
            false // duplicate, not inserted
        } else {
            self.chunk_hashes.insert(hash);
            true
        }
    }

    pub fn dedup_ratio(&self, original_bytes: u64) -> f64 {
        if original_bytes == 0 {
            return 1.0;
        }
        original_bytes as f64 / (original_bytes as f64 - self.total_saved_bytes as f64).max(1.0)
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTrie {
    pub root: [u8; 32],
    pub entries: HashMap<[u8; 32], Vec<u8>>,
}

impl Default for MerkleTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTrie {
    pub fn new() -> Self {
        Self {
            root: [0u8; 32],
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: [u8; 32], value: Vec<u8>) {
        self.entries.insert(key, value);
        // root = hash of all keys sorted
        let mut hashes: Vec<_> = self.entries.keys().cloned().collect();
        hashes.sort();
        let mut h = Sha3_256::new();
        h.update(b"BDLM_BUD_TRIE_V1");
        for hk in hashes {
            h.update(hk);
        }
        self.root = h.finalize().into();
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<&Vec<u8>> {
        self.entries.get(key)
    }
}

pub struct EconomicsGates;

impl EconomicsGates {
    pub fn k_bud_economics(econ: &BudEconomics, ceiling: f64) -> Result<(), &'static str> {
        if econ.holds_price(ceiling) {
            Ok(())
        } else {
            Err("KF: economics cost > ceiling")
        }
    }
    pub fn k_bud_global_dedup(
        dedup: &GlobalDedup,
        expected_saved: u64,
    ) -> Result<(), &'static str> {
        if dedup.total_saved_bytes >= expected_saved {
            Ok(())
        } else {
            Err("K-BUD-DEDUP: saved less than expected")
        }
    }
    pub fn k_bud_trie_root(trie: &MerkleTrie) -> Result<(), &'static str> {
        if trie.root != [0u8; 32] {
            Ok(())
        } else {
            Err("K-BUD-TRIE: root zero")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn economics_holds() {
        // JSON 17.19x with plain 7+1 (e=1.143) holds 0.016: 0.23342*1.143/17.19 = 0.01552 <= 0.016
        let econ = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.143,
            ratio: 17.19,
            device_only: false,
        };
        assert!(econ.holds_price(0.016));
        // With EVENODD (e=1.286) it does NOT hold: 0.23342*1.286/17.19 = 0.01747 > 0.016 - this is the real measurement (a canary)
        let econ2 = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 17.19,
            device_only: false,
        };
        assert!(!econ2.holds_price(0.016));
        let econ3 = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 2.53,
            device_only: false,
        };
        assert!(!econ3.holds_price(0.016));
        let econ4 = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 2.53,
            device_only: true,
        };
        assert!(econ4.holds_price(0.016));
    }
    #[test]
    fn k60_egress_zero_in_network() {
        // K60: in-network access has zero egress - even 10 TB is free
        assert_eq!(egress_cost(EgressZone::InNetwork, 10.0, 0.005), 0.0);
        assert!(
            holds_egress(EgressZone::InNetwork, 10.0, 0.005, 0.0),
            "InNetwork always holds the budget"
        );
        // Internet egress is charged
        assert!((egress_cost(EgressZone::Internet, 1.0, 0.005) - 0.005).abs() < 1e-12);
        assert!(
            !holds_egress(EgressZone::Internet, 1.0, 0.005, 0.001),
            "1 TB of internet egress does not hold a 0.001 budget"
        );
        // bozuk oran → +inf (K38)
        assert_eq!(egress_cost(EgressZone::Internet, 1.0, -1.0), f64::INFINITY);
        assert_eq!(
            egress_cost(EgressZone::Internet, 1.0, f64::NAN),
            f64::INFINITY
        );
        // negative TB -> zero egress (a sane bound)
        assert_eq!(egress_cost(EgressZone::Internet, -5.0, 0.005), 0.0);
    }

    #[test]
    fn tape_archive_tier_f3() {
        // F3/F1151: cold content on tape is 0.00025 USD/TB/month - the cold path of the 0.016 commitment
        assert!((TAPE_USD_PER_TB_MONTH - 0.00025).abs() < 0.00001);
        assert!(tape_holds_ceiling(1.0, 0.016), "tape is always below the ceiling");
        assert!(tape_holds_ceiling(10.0, 0.016), "10TB bant bile");
        // the media ladder: tape is cheapest, hot is most expensive
        assert!(ArchiveTier::Tape.usd_per_tb_month() < ArchiveTier::RefurbHdd.usd_per_tb_month());
        assert!(ArchiveTier::RefurbHdd.usd_per_tb_month() < ArchiveTier::Qlc.usd_per_tb_month());
        assert!(ArchiveTier::Qlc.usd_per_tb_month() < ArchiveTier::HotNvme.usd_per_tb_month());
        // broken input -> +inf
        assert_eq!(tape_cost_per_tb_month(-1.0), f64::INFINITY);
        assert_eq!(tape_cost_per_tb_month(f64::NAN), f64::INFINITY);
    }

    #[test]
    fn flat_single_price_user_decision() {
        // SINGLE PRICE: CPU/generation cost sits with the validator; the user sees one storage line item.
        // JSON OrderFree 12.07x + LRC 1.031x → tek fiyat
        let p = flat_price(0.23342, 1.031, 12.07);
        assert!((p - 0.0199).abs() < 0.001, "tek fiyat ~0.0199: {p}");
        // motion video at 101x -> far below
        let pv = flat_price(0.23342, 1.031, 101.0);
        assert!(pv < 0.005, "video tek fiyat: {pv}");
        // statik 1394x → ~0
        let ps = flat_price(0.23342, 1.031, 1394.0);
        assert!(ps < 0.0005, "statik: {ps}");
        // the ceiling: 12.07x + LRC does not hold 0.016 but does hold 0.02
        assert!(!flat_holds_ceiling(0.23342, 1.031, 12.07, 0.016));
        assert!(flat_holds_ceiling(0.23342, 1.031, 12.07, 0.02));
        // broken input -> +inf
        assert_eq!(flat_price(-1.0, 1.031, 12.07), f64::INFINITY);
        assert_eq!(flat_price(0.23342, 1.031, 0.0), f64::INFINITY);
    }
    #[test]
    fn residual_class_economy_i6() {
        // I6: the generatable class (zero residual) -> zero storage cost
        assert_eq!(
            residual_price(0.0, 1.143, 0.0, 0.23342),
            0.0,
            "generatable is free"
        );
        assert!(
            residual_holds_price(0.0, 1.143, 0.0, 0.23342, 0.016),
            "generatable always holds the ceiling"
        );
        // the residual class: size * erasure * coldness
        let p1 = residual_price(1.0, 1.143, 0.0, 0.23342);
        assert!((p1 - 0.2668).abs() < 0.01, "1 TB residual is about 0.267: {p1}");
        // the coldness discount: coldness 1 -> 50 percent lower
        let pcold = residual_price(1.0, 1.143, 1.0, 0.23342);
        assert!(
            (p1 / pcold - 2.0).abs() < 0.05,
            "cold is 50 percent cheaper: {p1} vs {pcold}"
        );
        // broken input -> +inf (K38)
        assert_eq!(residual_price(-1.0, 1.143, 0.0, 0.23342), f64::INFINITY);
        assert_eq!(residual_price(1.0, 0.5, 0.0, 0.23342), f64::INFINITY);
        assert_eq!(residual_price(f64::NAN, 1.143, 0.0, 0.23342), f64::INFINITY);
    }
    #[test]
    fn invalid_ratio_is_honest_inf() {
        // K38: oran <=0 / NaN → +inf (tavan asla tutmaz, panik/NaN yok)
        let zero = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 0.0,
            device_only: false,
        };
        assert_eq!(zero.cost_per_tb_month(), f64::INFINITY);
        assert!(!zero.holds_price(0.016));
        let nan = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: f64::NAN,
            device_only: false,
        };
        assert_eq!(nan.cost_per_tb_month(), f64::INFINITY);
        let neg = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: -3.0,
            device_only: false,
        };
        assert_eq!(neg.cost_per_tb_month(), f64::INFINITY);
        // device_only is always 0
        let d = BudEconomics {
            physical_usd: 0.23342,
            expansion: 1.286,
            ratio: 0.0,
            device_only: true,
        };
        assert_eq!(d.cost_per_tb_month(), 0.0);
    }
    #[test]
    fn global_dedup() {
        let mut dedup = GlobalDedup::new();
        let h1 = [1u8; 32];
        assert!(dedup.insert_chunk(h1, 100));
        assert!(!dedup.insert_chunk(h1, 100)); // duplicate
        assert_eq!(dedup.total_saved_bytes, 100);
    }
    #[test]
    fn merkle_trie() {
        let mut trie = MerkleTrie::new();
        let k = [1u8; 32];
        trie.insert(k, vec![1, 2, 3]);
        assert!(trie.get(&k).is_some());
        assert!(EconomicsGates::k_bud_trie_root(&trie).is_ok());
    }
}
