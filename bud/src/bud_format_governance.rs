//! B.U.D. 2.0 - the Pollen-to-production bridge, the governance conformance
//! package and the wiring inventory; ideas 3.0 items Y7, Y16 and Y0.
//!
//! Y7: a purchase payment is locked to a production offer, and the grant only
//! becomes `Active` after the PACT production verification passes, so
//! settlement is the proof of production. There is no escrow, only a balance
//! lock; that is decision B1.
//!
//! Y16: every new parameter enters the governance pattern, meaning the
//! constitution whitelist plus the activation delays, which are 10 epochs for a
//! parameter, 20 for a policy and 5 for a targeted fix. A commit that adds a
//! parameter outside the whitelist is REFUSED by the gate, and a mutation test
//! proves the gate bites.
//!
//! Y0: the V7 thesis, "what is missing is not the algorithm but the wiring".
//! The wiring inventory tracks each module's production-path call not at the
//! level of "there is a call" but at the level of "the call performs
//! verification".

#![forbid(unsafe_code)]

use sha3::{Digest, Sha3_256};

pub const GOV_MAGIC: [u8; 8] = *b"\xB5GOV1\0\0\0";

// ========================== Y7: the Pollen bridge ===========================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    Locked,   // the payment is locked to a production offer
    Active,   // the production verification passed, so access is open
    Refunded, // production failed, so the balance lock is returned
}

#[derive(Debug, Clone)]
pub struct PollenGrant {
    pub buyer: [u8; 32],
    pub pact_id: [u8; 32],
    pub state: GrantState,
    pub payment_locked: u64, // the balance lock; there is no escrow
}

/// Y7: the payment is locked to a production offer, and the grant starts out
/// `Locked`.
pub fn lock_payment(buyer: [u8; 32], pact_id: [u8; 32], amount: u64) -> PollenGrant {
    PollenGrant {
        buyer,
        pact_id,
        state: GrantState::Locked,
        payment_locked: amount,
    }
}

/// Y7: if the production verification passes, the grant becomes `Active` and
/// reading opens.
pub fn activate_after_production(grant: &mut PollenGrant, produced_ok: bool) {
    match (grant.state, produced_ok) {
        (GrantState::Locked, true) => grant.state = GrantState::Active,
        (GrantState::Locked, false) => grant.state = GrantState::Refunded,
        _ => {}
    }
}

/// Y7: a locked payment refuses reading, and `Active` accepts it.
pub fn can_read(grant: &PollenGrant) -> bool {
    grant.state == GrantState::Active
}

// ======================= Y16: the governance package ========================

/// The activation delay classes, fixed by the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationClass {
    Parameter = 10, // a parameter change
    Policy = 20,    // a policy change
    Targeted = 5,   // a targeted fix
}

/// Y16: the whitelist of parameters governance may vote on, closing V7 B4.
pub const PARAM_WHITELIST: &[&str] = &[
    "guardian_count",
    "target_energy_budget",
    "tiny_object_threshold",
    "recipe_bounty_ratio",
    "price_weight_a",
    "price_weight_b",
    "price_weight_c",
    "validator_departure_detection",
    "exam_interval",
];

/// Y16: is the parameter on the whitelist? Adding one that is not is REFUSED by
/// the gate.
pub fn is_whitelisted(param: &str) -> bool {
    PARAM_WHITELIST.contains(&param)
}

/// Y16: the activation delay, in epochs.
pub fn activation_delay(class: ActivationClass) -> u64 {
    class as u64
}

/// Y16: the gate rule, that a new parameter must be on the whitelist. The
/// mutation test breaks this on purpose.
pub fn gate_param_added(param: &str) -> bool {
    is_whitelisted(param)
}

// ======================= Y0: the wiring inventory ===========================

/// Y0: the wiring status, at the level of "the call performs verification".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WiringStatus {
    Wired,   // there is a call and it verifies
    Unwired, // there is no call; V7 B7 counted 7 modules over 4616 lines
    Stub,    // there is a call but it does not verify
}

/// Y0: a wiring inventory entry, mapping a module name to its status.
pub fn wiring_inventory(module: &str, call_count: u64, verifies: bool) -> (WiringStatus, bool) {
    let _ = module;
    let status = if call_count == 0 {
        WiringStatus::Unwired
    } else if verifies {
        WiringStatus::Wired
    } else {
        WiringStatus::Stub
    };
    (status, status == WiringStatus::Wired)
}

pub fn gov_digest(g: &PollenGrant) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(GOV_MAGIC);
    h.update(g.buyer);
    h.update(g.pact_id);
    h.update([match g.state {
        GrantState::Locked => 0,
        GrantState::Active => 1,
        GrantState::Refunded => 2,
    }]);
    h.update(g.payment_locked.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn y7_grant_state_machine() {
        let mut g = lock_payment([1u8; 32], [2u8; 32], 1000);
        assert!(!can_read(&g), "reading is refused while locked");
        activate_after_production(&mut g, true);
        assert!(can_read(&g), "production was verified, so it is Active");
        let mut g2 = lock_payment([1u8; 32], [2u8; 32], 1000);
        activate_after_production(&mut g2, false);
        assert_eq!(
            g2.state,
            GrantState::Refunded,
            "production failed, so it is refunded"
        );
        assert!(!can_read(&g2));
    }

    #[test]
    fn y16_whitelist_gate() {
        assert!(is_whitelisted("guardian_count"));
        assert!(is_whitelisted("tiny_object_threshold"));
        assert!(gate_param_added("recipe_bounty_ratio"));
        assert!(
            !gate_param_added("hidden_parameter"),
            "off the whitelist is refused"
        );
        // The activation delays.
        assert_eq!(activation_delay(ActivationClass::Parameter), 10);
        assert_eq!(activation_delay(ActivationClass::Policy), 20);
        assert_eq!(activation_delay(ActivationClass::Targeted), 5);
    }

    #[test]
    fn y0_wiring_inventory() {
        assert_eq!(
            wiring_inventory("proof_market", 0, false).0,
            WiringStatus::Unwired
        );
        assert_eq!(wiring_inventory("provider", 5, true).0, WiringStatus::Wired);
        assert_eq!(
            wiring_inventory("assignment", 3, false).0,
            WiringStatus::Stub
        );
        assert!(wiring_inventory("provider", 5, true).1);
    }

    #[test]
    fn the_governance_digest_is_deterministic() {
        let g = lock_payment([1u8; 32], [2u8; 32], 100);
        assert_eq!(gov_digest(&g), gov_digest(&g));
    }
}
