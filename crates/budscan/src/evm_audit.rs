//! The EVM contract audit core: dependency-free helpers for classifying the
//! risk of on-chain contracts.
//!
//! Scope: the function and event selectors of the common standard signatures,
//! ERC-20 and ERC-721, the EIP-1967 proxy slot addresses, and weighted risk
//! scoring. Deep bytecode analysis, meaning disassembly, is outside this
//! module; the aim is for a scanner to be able to produce fast, deterministic
//! risk hints at the level of the ABI and the storage slots.

use serde::{Deserialize, Serialize};

/// The ERC-20 standard function selectors, by signature name.
pub const ERC20_FUNCS: [&str; 6] = [
    "totalSupply",
    "balanceOf",
    "transfer",
    "approve",
    "allowance",
    "transferFrom",
];

/// The ERC-20 standard events.
pub const ERC20_EVENTS: [&str; 2] = ["Transfer", "Approval"];

/// The ERC-721 standard function selectors.
pub const ERC721_FUNCS: [&str; 7] = [
    "balanceOf",
    "ownerOf",
    "approve",
    "getApproved",
    "setApprovalForAll",
    "isApprovedForAll",
    "transferFrom",
];

/// The ERC-721 standard events.
pub const ERC721_EVENTS: [&str; 3] = ["Transfer", "Approval", "ApprovalForAll"];

/// The EIP-1967 proxy slot: `keccak256("eip1967.proxy.implementation") - 1`.
pub const EIP1967_IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
/// The EIP-1967 admin slot: `keccak256("eip1967.proxy.admin") - 1`.
pub const EIP1967_ADMIN_SLOT: &str =
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
/// The EIP-1967 beacon slot: `keccak256("eip1967.proxy.beacon") - 1`.
pub const EIP1967_BEACON_SLOT: &str =
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

/// The common administrative selector signatures, 4 bytes in hex.
pub const SELECTOR_OWNER: &str = "0x8da5cb5b"; // owner()
pub const SELECTOR_TRANSFER_OWNERSHIP: &str = "0xf2fde38b"; // transferOwnership(address)
pub const SELECTOR_RENOUNCE_OWNERSHIP: &str = "0x715018a6"; // renounceOwnership()
pub const SELECTOR_PAUSE: &str = "0x8456cb59"; // pause()
pub const SELECTOR_UNPAUSE: &str = "0x3f4ba83a"; // unpause()
pub const SELECTOR_PAUSED: &str = "0x5c97a5bb"; // paused()
pub const SELECTOR_MINT: &str = "0x40c10f19"; // mint(address,uint256)
pub const SELECTOR_SET_MINTER: &str = "0xa9070a1c"; // setMinter(address,bool)
pub const SELECTOR_BURN: &str = "0x42966c5e"; // burn(uint256)
pub const SELECTOR_TOTAL_SUPPLY: &str = "0x18160ddd"; // totalSupply()

/// The risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Info,
    Warn,
    High,
}

impl RiskLevel {
    /// The score contribution: Info is 80, Warn is 50 and High is 20.
    #[must_use]
    pub fn score(self) -> u8 {
        match self {
            RiskLevel::Info => 80,
            RiskLevel::Warn => 50,
            RiskLevel::High => 20,
        }
    }
}

/// A single risk item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskItem {
    pub level: RiskLevel,
    pub area: String,
    pub message: String,
    pub evidence: String,
}

/// A risk report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskReport {
    pub items: Vec<RiskItem>,
}

impl RiskReport {
    pub fn push(
        &mut self,
        level: RiskLevel,
        area: impl Into<String>,
        msg: impl Into<String>,
        evidence: impl Into<String>,
    ) {
        self.items.push(RiskItem {
            level,
            area: area.into(),
            message: msg.into(),
            evidence: evidence.into(),
        });
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// The weighted score components. The areas are weighted according to the
/// contract type, and the percentages must sum to 100. No floating point is
/// used, which keeps the determinism consensus-friendly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreWeights {
    pub onchain_pct: u16,
    pub static_analysis_pct: u16,
    pub behavior_pct: u16,
    pub metadata_pct: u16,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            onchain_pct: 40,
            static_analysis_pct: 30,
            behavior_pct: 20,
            metadata_pct: 10,
        }
    }
}

/// The interface used to score a list of items.
pub trait Scorable {
    /// Turns the items into `(score, area)` pairs.
    fn items_scored(&self) -> Vec<(u8, String)>;
}

impl Scorable for RiskReport {
    fn items_scored(&self) -> Vec<(u8, String)> {
        self.items
            .iter()
            .map(|it| (it.level.score(), it.area.to_lowercase()))
            .collect()
    }
}

/// The score combined per area: each area takes its lowest score, which is the
/// most pessimistic reading, then the areas are summed under their percentage
/// weights and divided by 100. All of the arithmetic is integer.
///
/// # Errors
///
/// If the weights do not sum to 100.
pub fn weighted_score(report: &RiskReport, weights: ScoreWeights) -> Result<u8, String> {
    let total_w = weights.onchain_pct
        + weights.static_analysis_pct
        + weights.behavior_pct
        + weights.metadata_pct;
    if total_w != 100 {
        return Err(format!(
            "the weights must sum to 100, but {total_w} was given"
        ));
    }

    let mut by_area: std::collections::BTreeMap<String, u8> = std::collections::BTreeMap::new();
    for (score, area) in report.items_scored() {
        by_area
            .entry(area)
            .and_modify(|s| *s = (*s).min(score))
            .or_insert(score);
    }

    let area_weight = |area: &str| -> u16 {
        match area {
            a if a.contains("onchain") => weights.onchain_pct,
            a if a.contains("static") => weights.static_analysis_pct,
            a if a.contains("behav") => weights.behavior_pct,
            _ => weights.metadata_pct,
        }
    };

    let mut acc: u64 = 0;
    for (area, score) in by_area {
        acc += u64::from(score) * u64::from(area_weight(&area));
    }
    // acc is at most 80*100 = 8000, and dividing by 100 gives 80, which fits a u8.
    let score = u8::try_from(acc / 100).unwrap_or(u8::MAX);
    Ok(score)
}

/// Turns a percentage score into a label.
#[must_use]
pub fn rating(score: u8) -> &'static str {
    match score {
        90..=100 => "excellent",
        75..=89 => "good",
        50..=74 => "fair",
        25..=49 => "weak",
        _ => "poor",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip1967_slots_are_nonempty_and_distinct() {
        assert_ne!(EIP1967_IMPLEMENTATION_SLOT, EIP1967_ADMIN_SLOT);
        assert_ne!(EIP1967_ADMIN_SLOT, EIP1967_BEACON_SLOT);
        assert!(EIP1967_IMPLEMENTATION_SLOT.starts_with("0x"));
        assert_eq!(EIP1967_IMPLEMENTATION_SLOT.len(), 66);
    }

    #[test]
    fn selectors_are_known() {
        assert_eq!(SELECTOR_OWNER, "0x8da5cb5b");
        assert_eq!(SELECTOR_TOTAL_SUPPLY, "0x18160ddd");
    }

    #[test]
    fn score_weights_round_to_expected() {
        let mut report = RiskReport::default();
        report.push(RiskLevel::High, "onchain", "unowned", "owner=0");
        report.push(RiskLevel::Warn, "static", "no pause", "-");
        let w = ScoreWeights::default();
        let s = weighted_score(&report, w).unwrap();
        // 20*40 + 50*30 = 800 + 1500 = 2300 / 100 = 23
        // The rating threshold: anything below 25 is "poor". The correctness of
        // the score calculation is proven here, and the label in a separate test.
        assert_eq!(s, 23);
        assert_eq!(rating(s), "poor");
    }

    #[test]
    fn empty_report_scores_zero() {
        let report = RiskReport::default();
        let s = weighted_score(&report, ScoreWeights::default()).unwrap();
        assert_eq!(s, 0);
        assert_eq!(rating(s), "poor");
    }

    #[test]
    fn invalid_weights_rejected() {
        let report = RiskReport::default();
        let w = ScoreWeights {
            onchain_pct: 50,
            static_analysis_pct: 50,
            behavior_pct: 50,
            metadata_pct: 50,
        };
        assert!(weighted_score(&report, w).is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let mut report = RiskReport::default();
        report.push(RiskLevel::High, "static", "msg", "ev");
        let json = serde_json::to_string(&report).unwrap();
        let back: RiskReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }
}
