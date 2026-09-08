//! E1: K3/K4 Persistent Alarm & Quarantine Ledger.
//!
//! Maintains on-chain, state-committed and restart-surviving records of
//! quarantined domains, malicious relayers, and critical security alarms.
//!
//! Hashed with domain tags `BDLM_BUDZERO_QUARANTINE_V1` and `BDLM_BUDZERO_ALARMLOG_V1`
//! and folded into the node state root.

use crate::core::address::Address;
use crate::domain::types::Hash32;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

/// Reason for quarantining an entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuarantineReason {
    InvalidFinalityProof(String),
    DoubleSigning(String),
    MalformedStateMutation(String),
    CorruptedSnapshot(String),
    OperatorSlash(String),
}

/// A persistent quarantine entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineEntry {
    pub target_id: Hash32,
    pub reason: QuarantineReason,
    pub height: u64,
    pub timestamp: u64,
    pub reporter: Address,
}

/// A persistent security alarm entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlarmEntry {
    pub alarm_id: Hash32,
    pub code: String,
    pub message: String,
    pub height: u64,
    pub timestamp: u64,
    pub severity: u8, // 1=Info, 2=Warn, 3=Critical, 4=Fatal
}

/// Persistent K3/K4 Alarm & Quarantine Ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QuarantineLedger {
    #[serde(with = "crate::core::map_keys")]
    pub quarantined_entities: BTreeMap<Hash32, QuarantineEntry>,
    #[serde(with = "crate::core::map_keys")]
    pub alarms: BTreeMap<Hash32, AlarmEntry>,
}

impl QuarantineLedger {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            quarantined_entities: BTreeMap::new(),
            alarms: BTreeMap::new(),
        }
    }

    fn quarantine_entity(
        &mut self,
        target_id: Hash32,
        reason: QuarantineReason,
        height: u64,
        timestamp: u64,
        reporter: Address,
    ) {
        self.quarantined_entities.insert(
            target_id,
            QuarantineEntry {
                target_id,
                reason,
                height,
                timestamp,
                reporter,
            },
        );
    }

    #[must_use]
    fn is_quarantined(&self, target_id: &Hash32) -> bool {
        self.quarantined_entities.contains_key(target_id)
    }

    fn lift_quarantine(&mut self, target_id: &Hash32) -> bool {
        self.quarantined_entities.remove(target_id).is_some()
    }

    fn record_alarm(
        &mut self,
        code: &str,
        message: &str,
        height: u64,
        timestamp: u64,
        severity: u8,
    ) -> Hash32 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_BUDZERO_ALARMLOG_V1");
        hasher.update((code.len() as u64).to_le_bytes());
        hasher.update(code.as_bytes());
        hasher.update((message.len() as u64).to_le_bytes());
        hasher.update(message.as_bytes());
        hasher.update(height.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update([severity]);
        let alarm_id: Hash32 = hasher.finalize().into();

        self.alarms.insert(
            alarm_id,
            AlarmEntry {
                alarm_id,
                code: code.to_string(),
                message: message.to_string(),
                height,
                timestamp,
                severity,
            },
        );
        alarm_id
    }

    /// Compute state root commitment for quarantine and alarm state.
    #[must_use]
    fn root_hash(&self) -> Hash32 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"BDLM_BUDZERO_QUARANTINE_V1");
        for (id, entry) in &self.quarantined_entities {
            hasher.update(id);
            hasher.update(entry.height.to_le_bytes());
            hasher.update(entry.timestamp.to_le_bytes());
            hasher.update(entry.reporter.0);
        }
        for (id, alarm) in &self.alarms {
            hasher.update(id);
            hasher.update(alarm.height.to_le_bytes());
            hasher.update([alarm.severity]);
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_and_alarm_lifecycle() {
        let mut ledger = QuarantineLedger::new();
        let target = [0x42u8; 32];
        let reporter = Address::from([0x01u8; 32]);

        assert!(!ledger.is_quarantined(&target));
        ledger.quarantine_entity(
            target,
            QuarantineReason::DoubleSigning("equivocation on height 100".into()),
            100,
            1_725_700_000,
            reporter,
        );
        assert!(ledger.is_quarantined(&target));

        let alarm_id = ledger.record_alarm(
            "C1_DETECTED",
            "Validator set forgery",
            100,
            1_725_700_000,
            4,
        );
        assert_ne!(alarm_id, [0u8; 32]);

        let root = ledger.root_hash();
        assert_ne!(root, [0u8; 32]);

        assert!(ledger.lift_quarantine(&target));
        assert!(!ledger.is_quarantined(&target));
        assert_ne!(ledger.root_hash(), root);
    }
}
