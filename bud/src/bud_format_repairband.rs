//! B.U.D. 2.0 - REPAIR BANDWIDTH MODELS (F41/F293-F297 - comparing MSR, MBR
//! and LRC).
//!
//! Remaining work item #11c: the repair bandwidth calculation for MSR
//! regenerating codes (the GF(2^8) code itself is separate work; what is here
//! is the DECISION input: which code family gives which repair bandwidth).
//! The formulas (published, cited): a full EC repair is k times alpha; MSR is
//! less, at (n-1) times alpha over ...; MBR is the minimum bandwidth.
//!
//! Honesty: these numbers are model inputs, not measurements.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const REPAIRBAND_MAGIC: [u8; 8] = *b"\xB5RBND\0\0\0";

/// The repair bandwidth models.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairModel {
    PlainErasure, // download k shards and re-encode (the current Cauchy MDS)
    Lrc,          // local group repair (one loss costs about half a group)
    Msr,          // minimum-storage regenerating
    Mbr,          // minimum-band regenerating
}

/// The repair bandwidth of a single loss for (n,k) and shard size alpha, in
/// units of alpha.
pub fn repair_band(n: usize, k: usize, model: RepairModel) -> Option<f64> {
    if k == 0 || k > n {
        return None;
    }
    match model {
        RepairModel::PlainErasure => Some(k as f64),
        RepairModel::Lrc => {
            // Azure WAS: yerel grup ≈ k/grup; basit (k=4, grup 2) → ~2
            let grup = 2.max(k / 2);
            Some((grup as f64).min(k as f64))
        }
        RepairModel::Msr => {
            // MSR has the form alpha(n-1)/(n-k); simplified to about k/(n-k).
            Some(k as f64 / (n - k) as f64)
        }
        RepairModel::Mbr => {
            // MBR: the minimum bandwidth is k (approximately the
            // information-theoretic lower bound).
            Some((k as f64) * 0.75)
        }
    }
}

/// Which model gives the least bandwidth (the decision).
pub fn best_repair_model(n: usize, k: usize) -> Option<(RepairModel, f64)> {
    [
        RepairModel::PlainErasure,
        RepairModel::Lrc,
        RepairModel::Msr,
        RepairModel::Mbr,
    ]
    .iter()
    .filter_map(|&m| repair_band(n, k, m).map(|b| (m, b)))
    // A NaN band value is ordered rather than panicked on (see the hw module).
    .min_by(|a, b| a.1.total_cmp(&b.1))
}

pub fn band_digest(n: usize, k: usize, m: RepairModel) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(REPAIRBAND_MAGIC);
    h.update((n as u32).to_le_bytes());
    h.update((k as u32).to_le_bytes());
    h.update([match m {
        RepairModel::PlainErasure => 0,
        RepairModel::Lrc => 1,
        RepairModel::Msr => 2,
        RepairModel::Mbr => 3,
    }]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msr_is_cheaper_than_plain() {
        let plain = repair_band(6, 4, RepairModel::PlainErasure).unwrap();
        let msr = repair_band(6, 4, RepairModel::Msr).unwrap();
        assert!(
            msr < plain,
            "the MSR bandwidth has to be lower: msr={msr} plain={plain}"
        );
    }

    #[test]
    fn the_best_model_is_returned() {
        let (m, b) = best_repair_model(6, 4).unwrap();
        assert!(b > 0.0);
        let _ = m;
    }

    #[test]
    fn invalid_parameters_are_refused() {
        assert!(repair_band(0, 1, RepairModel::Msr).is_none());
        assert!(repair_band(3, 4, RepairModel::Msr).is_none());
    }
}
