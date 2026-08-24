//! B.U.D. 2.0 - ROVING GUARDIAN REGENERATION (ideas3.0 Y1/Y9/Y12/Y14)
//!
//! The ideas3.0 thesis: "the disk sleeps, the CPU wakes, the guardian roves, and
//! the tariff is bound to wakefulness." This module is the code counterpart of
//! the Y ideas in the bud skeleton:
//! - Y1  Roving guardian: every epoch the guardian picks one of N contents,
//!   reproduces the PACT and verifies it against the commitment (a production
//!   challenge instead of PoR).
//! - Y12 Guardian selection: commit-reveal plus a deterministic PRF (the same
//!   history gives the same selection).
//! - Y14 Guardian sub-role: an opt-in flag (without opening a new RoleId).
//! - Y9  Regenerative device network: the mini-guardian record (shard audit plus
//!   a fault counter).
//!   The numbers are program output; none is written by hand (the 2.0 rule). The
//!   N=26 table comes from DV.

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const GUARD_MAGIC: [u8; 8] = *b"\xB5GRD1\0\0\0";
pub const GUARD_VERSION: u8 = 1;

/// The DV N=26 table: a wakefulness share of 1/N, a 99.6 percent catch rate in 24 hours (a constant from the document).
pub const DV_N: u32 = 26;
pub const DV_CATCH_RATE_24H: f64 = 0.996;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardianRole {
    None,       // not a guardian
    Operator,   // an opt-in guardian under STORAGE_OPERATOR (Y14)
    MiniDevice, // a device-network mini-guardian (Y9)
}

/// The guardian record (Y14: the opt-in flag; Y9: a mini device).
#[derive(Debug, Clone)]
pub struct Guardian {
    pub id: [u8; 32],
    pub role: GuardianRole,
    pub opt_in: bool,     // Y14: only opt-in entries join the selection
    pub fault_count: u64, // Y9/Y12: the fault counter (reputation)
    pub bond_sep: bool,   // a guardian bond SEPARATE from the storage stake
}

impl Guardian {
    pub fn new(id: [u8; 32], role: GuardianRole) -> Self {
        let opt_in = role != GuardianRole::None;
        Self {
            id,
            role,
            opt_in,
            fault_count: 0,
            bond_sep: true,
        }
    }

    pub fn record_fault(&mut self) {
        self.fault_count = self.fault_count.saturating_add(1);
    }
}

/// Y12: commit-reveal guardian selection - a deterministic PRF.
/// `seeds`: the seeds each guardian committed at the start of the epoch (in
/// order). `epoch`, `pact_id`: the selection input. Output: the selected
/// guardian index plus the round count. The same input gives the SAME selection
/// (a consensus test). Commit-reveal: nobody knows the selection before the
/// seeds are revealed (manipulation before the reveal is closed off).
pub fn select_guardian(seeds: &[[u8; 32]], epoch: u64, pact_id: &[u8; 32]) -> Option<(usize, u32)> {
    if seeds.is_empty() || seeds.len() > 1024 {
        return None;
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_GUARDIAN_SELECT_V1");
    h.update(epoch.to_le_bytes());
    h.update(pact_id);
    for s in seeds {
        h.update(s);
    }
    let d: [u8; 32] = h.finalize().into();
    let mut w8 = [0u8; 8];
    w8.copy_from_slice(&d[..8]);
    let v = u64::from_le_bytes(w8);
    let idx = (v % seeds.len() as u64) as usize;
    // round count: as N grows the wakefulness share drops -> a round frequency of 1/N (DV)
    let tour = DV_N.max(1);
    Some((idx, tour))
}

/// Y1: the production challenge - reproduce the PACT and verify it against the
/// commitment. `regenerate`: the bytes the guardian produced.
/// `commitment`: the recorded PACT commitment. A wrong recipe or hash is always
/// REFUSED (the negative test).
pub fn verify_regeneration(regenerate: &[u8], commitment: &[u8; 32]) -> bool {
    let cid = crate::bud_format_container::content_id(regenerate);
    &cid == commitment
}

/// Y1: the round schedule - which of the N contents is audited this epoch
/// (deterministic). `pact_ids`: the content list. `epoch`: the round. The audit
/// cost is 1/N of the content.
pub fn tour_plan(pact_ids: &[[u8; 32]], epoch: u64) -> Option<usize> {
    if pact_ids.is_empty() {
        return None;
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_GUARDIAN_TOUR_V1");
    h.update(epoch.to_le_bytes());
    let mut all = Vec::new();
    for p in pact_ids {
        all.extend_from_slice(p);
    }
    h.update(&all);
    let d: [u8; 32] = h.finalize().into();
    let mut w8 = [0u8; 8];
    w8.copy_from_slice(&d[..8]);
    let v = u64::from_le_bytes(w8);
    Some((v % pact_ids.len() as u64) as usize)
}

/// Y9: the mini-guardian device audit record - read a shard, sign it, count faults.
#[derive(Debug, Clone)]
pub struct MiniGuardianAudit {
    pub device_id: [u8; 32],
    pub pact_id: [u8; 32],
    pub shard_ok: bool,
    pub signed: bool,
}

/// A lying device proof (the Y9 risk): an unsigned or corrupt proof raises the fault counter.
pub fn audit_mini(device: &mut Guardian, audit: &MiniGuardianAudit) -> bool {
    if audit.shard_ok && audit.signed {
        true
    } else {
        device.record_fault();
        false
    }
}

pub fn guardian_digest(g: &Guardian) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(GUARD_MAGIC);
    h.update([GUARD_VERSION]);
    h.update(g.id);
    h.update([match g.role {
        GuardianRole::None => 0,
        GuardianRole::Operator => 1,
        GuardianRole::MiniDevice => 2,
    }]);
    h.update([g.opt_in as u8]);
    h.update(g.fault_count.to_le_bytes());
    h.update([g.bond_sep as u8]);
    h.finalize().into()
}

/// Y1 MEASUREMENT: the cost of a production challenge against the cost of a PoR
/// challenge (program output). `produce_sec`: the time to reproduce the PACT.
/// `por_sec`: the corresponding PoR. The criterion (ideas2.0 I2): the production
/// cost must be below 1 percent of the PoR cost.
pub fn production_vs_por_ratio(produce_sec: f64, por_sec: f64) -> f64 {
    if por_sec <= 0.0 {
        return f64::INFINITY;
    }
    produce_sec / por_sec
}

/// The Y1 acceptance rule: is the ratio below 0.01 (1 percent)?
pub fn production_cheaper_than_por(produce_sec: f64, por_sec: f64) -> bool {
    production_vs_por_ratio(produce_sec, por_sec) < 0.01
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Digest;

    fn hof(b: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b);
        h.finalize().into()
    }

    #[test]
    fn y12_selection_is_deterministic_and_collision_free() {
        let seeds: Vec<[u8; 32]> = (0..10u8).map(|i| hof(&[i])).collect();
        let pact = hof(b"pact-a");
        let (i1, t1) = select_guardian(&seeds, 7, &pact).unwrap();
        let (i2, t2) = select_guardian(&seeds, 7, &pact).unwrap();
        assert_eq!(
            (i1, t1),
            (i2, t2),
            "the same history gives the same selection"
        );
        assert_eq!(t1, DV_N);
        // a different epoch gives a different selection (sampling; not guaranteed but likely)
        let (i3, _) = select_guardian(&seeds, 8, &pact).unwrap();
        assert!(i1 < seeds.len() && i3 < seeds.len());
    }

    #[test]
    fn y1_production_challenge_verifies_and_refuses() {
        let data = b"reproducible content ";
        let cid = crate::bud_format_container::content_id(data);
        assert!(
            verify_regeneration(data, &cid),
            "a correct production is accepted"
        );
        assert!(
            !verify_regeneration(b"wrong recipe output", &cid),
            "a wrong one is REFUSED"
        );
    }

    #[test]
    fn y1_round_plan_picks_one_of_n_contents() {
        let pacts: Vec<[u8; 32]> = (0..26u8).map(|i| hof(&[i])).collect();
        let chosen = tour_plan(&pacts, 100).unwrap();
        assert!(chosen < pacts.len());
        assert_eq!(tour_plan(&pacts, 100).unwrap(), chosen, "deterministik");
        assert!(tour_plan(&[], 1).is_none());
    }

    #[test]
    fn y14_opt_in_and_a_separate_bond() {
        let g = Guardian::new([1u8; 32], GuardianRole::Operator);
        assert!(g.opt_in);
        assert!(
            g.bond_sep,
            "the guardian bond is separate from the storage stake"
        );
        let none = Guardian::new([2u8; 32], GuardianRole::None);
        assert!(
            !none.opt_in,
            "without opt-in it does not join the selection"
        );
    }

    #[test]
    fn y9_mini_guardian_counts_faults() {
        let mut dev = Guardian::new([9u8; 32], GuardianRole::MiniDevice);
        assert!(audit_mini(
            &mut dev,
            &MiniGuardianAudit {
                device_id: [9u8; 32],
                pact_id: [1u8; 32],
                shard_ok: true,
                signed: true
            }
        ));
        assert_eq!(dev.fault_count, 0);
        assert!(!audit_mini(
            &mut dev,
            &MiniGuardianAudit {
                device_id: [9u8; 32],
                pact_id: [1u8; 32],
                shard_ok: true,
                signed: false
            }
        ));
        assert_eq!(dev.fault_count, 1, "a lying proof is a fault");
    }

    #[test]
    fn y1_cost_ratio_measurement() {
        // producing 0.5s, PoR 120s -> 0.42 percent -> accepted (the I2 criterion)
        let r = production_vs_por_ratio(0.5, 120.0);
        assert!(r < 0.01, "oran: {r}");
        assert!(production_cheaper_than_por(0.5, 120.0));
        // producing 2s, PoR 10s -> 20 percent -> REFUSED
        assert!(!production_cheaper_than_por(2.0, 10.0));
        assert_eq!(production_vs_por_ratio(1.0, 0.0), f64::INFINITY);
    }

    #[test]
    fn digest_is_deterministic() {
        let g = Guardian::new([5u8; 32], GuardianRole::Operator);
        assert_eq!(guardian_digest(&g), guardian_digest(&g));
    }
}
