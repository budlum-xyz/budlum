//! E1: K3/K4 durable alarm & quarantine ledger.
//!
//! A node-local, restart-surviving record of consensus-integrity events:
//! domains frozen for equivocation and offenders slashed through the
//! consensus path. It answers the "undeletable ledger" claim for the life of
//! the node's storage, which the previous in-memory shape did not: the
//! records were rebuilt from nothing on every restart.
//!
//! # Why this is not folded into the state root
//!
//! The ledger carries no wall clock and no per-node reporter, so its *content*
//! is deterministic; but the moment a freeze is first *observed* still
//! depends on when each node sees the conflicting commitment. Committing the
//! ledger would therefore fork honest nodes, which is the failure this file
//! exists to record rather than to cause. It persists through the storage
//! layer (`QUARANTINE_LEDGER`) instead, like the bridge state and the
//! universal relayer.

use crate::domain::types::{DomainId, Hash32};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

/// Reason for quarantining an entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuarantineReason {
    /// A domain committed two different blocks at the same height.
    Equivocation(String),
    /// An offender was slashed through the consensus-verified path.
    OperatorSlash(String),
}

/// A persistent quarantine entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineEntry {
    pub target_id: Hash32,
    pub reason: QuarantineReason,
    pub height: u64,
}

/// A persistent security alarm entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlarmEntry {
    pub alarm_id: Hash32,
    pub code: String,
    pub message: String,
    pub height: u64,
    /// 1=Info, 2=Warn, 3=Critical, 4=Fatal.
    pub severity: u8,
}

/// Persistent K3/K4 alarm & quarantine ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QuarantineLedger {
    #[serde(with = "crate::core::map_keys")]
    pub quarantined_entities: BTreeMap<Hash32, QuarantineEntry>,
    #[serde(with = "crate::core::map_keys")]
    pub alarms: BTreeMap<Hash32, AlarmEntry>,
}

impl QuarantineLedger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            quarantined_entities: BTreeMap::new(),
            alarms: BTreeMap::new(),
        }
    }

    /// The ledger key a frozen domain is recorded under.
    #[must_use]
    pub fn domain_target(domain_id: DomainId) -> Hash32 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"quarantine_domain_v1");
        hasher.update(domain_id.to_le_bytes());
        hasher.finalize().into()
    }

    /// Record a quarantine decision. Idempotent per `(target, reason, height)`;
    /// a later record for the same target overwrites the earlier one.
    pub fn quarantine_entity(&mut self, target_id: Hash32, reason: QuarantineReason, height: u64) {
        self.quarantined_entities.insert(
            target_id,
            QuarantineEntry {
                target_id,
                reason,
                height,
            },
        );
    }

    /// Record a security alarm and return its deterministic id.
    pub fn record_alarm(&mut self, code: &str, message: &str, height: u64, severity: u8) -> Hash32 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_BUDZERO_ALARMLOG_V1");
        hasher.update((code.len() as u64).to_le_bytes());
        hasher.update(code.as_bytes());
        hasher.update((message.len() as u64).to_le_bytes());
        hasher.update(message.as_bytes());
        hasher.update(height.to_le_bytes());
        hasher.update([severity]);
        let alarm_id: Hash32 = hasher.finalize().into();

        self.alarms.insert(
            alarm_id,
            AlarmEntry {
                alarm_id,
                code: code.to_string(),
                message: message.to_string(),
                height,
                severity,
            },
        );
        alarm_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_and_alarm_lifecycle_is_deterministic() {
        let mut ledger = QuarantineLedger::new();

        let target = QuarantineLedger::domain_target(7u32);
        assert_ne!(target, [0u8; 32]);

        ledger.quarantine_entity(
            target,
            QuarantineReason::Equivocation("conflict at height 100".into()),
            100,
        );
        assert!(ledger.quarantined_entities.contains_key(&target));
        assert_eq!(ledger.quarantined_entities[&target].height, 100);

        let alarm_id = ledger.record_alarm("DOMAIN_EQUIVOCATION", "domain 7 forked", 100, 4);
        assert_ne!(alarm_id, [0u8; 32]);

        // Same inputs -> same alarm id (determinism, no wall clock).
        let mut other = QuarantineLedger::new();
        let alarm_id_again = other.record_alarm("DOMAIN_EQUIVOCATION", "domain 7 forked", 100, 4);
        assert_eq!(alarm_id, alarm_id_again);

        assert_eq!(ledger.alarms[&alarm_id].severity, 4);
    }

    #[test]
    fn ledger_round_trips_through_bincode() {
        let mut ledger = QuarantineLedger::new();
        let target = QuarantineLedger::domain_target(3u32);
        ledger.quarantine_entity(target, QuarantineReason::OperatorSlash("role 2".into()), 9);
        ledger.record_alarm("OPERATOR_SLASH", "slashed", 9, 3);

        let bytes = bincode::serialize(&ledger).expect("bincode encode");
        let back: QuarantineLedger = bincode::deserialize(&bytes).expect("bincode decode");
        assert_eq!(ledger, back);
    }
}
