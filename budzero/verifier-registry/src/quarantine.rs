//! Derived quarantine ledger (K4 of the BudZero regeneration design).
//!
//! When a proof alarms, the node must not only refuse it once - the code that
//! produced it must be refused every time it appears again, without a gossip
//! round or a trusted distributor. This module writes that refusal: the ban
//! rule is a pure function of the program itself, so every node derives the
//! *same* rule id for the *same* code and writes it locally. A ban is
//! therefore a deterministic consequence of the offence, not an operator
//! decision, and the ledger is the audit trail of those consequences.
//!
//! Bounded, not unbounded: a permissionless caller can mint distinct
//! non-canonical programs without limit, and a ledger that grew one entry per
//! offence would be an unbounded load. The ledger is capped at
//! [`MAX_QUARANTINE_ENTRIES`] (oldest dropped); the unbounded, deterministic
//! gate remains the canonical-set membership check the relay runs before it
//! ever consults this ledger.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Domain separator for derived ban rules.
pub const QUARANTINE_DOMAIN: &[u8] = b"BDLM_BUDZERO_QUARANTINE_V1";

/// Hard cap on ledger entries; the oldest entry is dropped beyond it.
pub const MAX_QUARANTINE_ENTRIES: usize = 4096;

/// Why a program was banned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReason {
    /// The program is outside the canonical set.
    NonCanonicalProgram,
    /// The program is canonical but its transfer events broke conservation.
    TransferViolation,
    /// The STARK verification failed.
    InvalidProof,
    /// Public inputs did not match the proof envelope.
    PublicInputsMismatch,
}

impl QuarantineReason {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::NonCanonicalProgram => 0,
            Self::TransferViolation => 1,
            Self::InvalidProof => 2,
            Self::PublicInputsMismatch => 3,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonCanonicalProgram => "non_canonical_program",
            Self::TransferViolation => "transfer_violation",
            Self::InvalidProof => "invalid_proof",
            Self::PublicInputsMismatch => "public_inputs_mismatch",
        }
    }
}

/// One quarantine entry: the banned program and the rule derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineEntry {
    pub program_hash: [u8; 32],
    pub reason: QuarantineReason,
    /// The derived rule id: a pure function of the program hash, so every
    /// node writes the same id for the same code.
    pub rule_id: [u8; 32],
    /// Insertion sequence, for oldest-first eviction at the cap.
    seq: u64,
}

/// The quarantine ledger. `Default` gives an empty ledger.
#[derive(Debug, Clone, Default)]
pub struct QuarantineLedger {
    entries: BTreeMap<[u8; 32], QuarantineEntry>,
    next_seq: u64,
}

impl QuarantineLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The ban rule for a program: a domain-separated digest of the program
    /// hash. Pure - no ledger state, no sequence - so two nodes banning the
    /// same code derive the same rule id.
    #[must_use]
    pub fn derive_rule_id(program_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::default();
        hasher.update(QUARANTINE_DOMAIN);
        hasher.update(program_hash);
        hasher.finalize().into()
    }

    /// Ban a program and return its rule id. Idempotent: banning an already
    /// banned hash returns the existing rule id and changes nothing.
    pub fn ban(&mut self, program_hash: [u8; 32], reason: QuarantineReason) -> [u8; 32] {
        let rule_id = Self::derive_rule_id(&program_hash);
        if let Some(entry) = self.entries.get(&program_hash) {
            return entry.rule_id;
        }
        self.evict_if_needed();
        self.entries.insert(
            program_hash,
            QuarantineEntry {
                program_hash,
                reason,
                rule_id,
                seq: self.next_seq,
            },
        );
        self.next_seq = self.next_seq.wrapping_add(1);
        rule_id
    }

    /// Whether the program is currently banned.
    #[must_use]
    pub fn is_banned(&self, program_hash: &[u8; 32]) -> bool {
        self.entries.contains_key(program_hash)
    }

    /// The entry for a banned program, if any.
    #[must_use]
    pub fn entry(&self, program_hash: &[u8; 32]) -> Option<&QuarantineEntry> {
        self.entries.get(program_hash)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() >= MAX_QUARANTINE_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.seq)
                .map(|(h, _)| *h);
            match oldest {
                Some(hash) => {
                    self.entries.remove(&hash);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(seed: usize) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&(seed as u64).to_le_bytes());
        h
    }

    #[test]
    fn rule_id_is_pure_and_domain_separated() {
        let h = hash_of(1);
        let a = QuarantineLedger::derive_rule_id(&h);
        let b = QuarantineLedger::derive_rule_id(&h);
        assert_eq!(a, b, "same program, same rule, independent of ledger state");
        assert_ne!(a, h, "the rule id must not be the program hash itself");
        assert_ne!(
            QuarantineLedger::derive_rule_id(&hash_of(1)),
            QuarantineLedger::derive_rule_id(&hash_of(2)),
            "different programs derive different rules"
        );
    }

    #[test]
    fn ban_is_idempotent() {
        let mut ledger = QuarantineLedger::new();
        let h = hash_of(7);
        let first = ledger.ban(h, QuarantineReason::InvalidProof);
        assert_eq!(ledger.len(), 1);
        let second = ledger.ban(h, QuarantineReason::TransferViolation);
        assert_eq!(first, second, "re-ban returns the same rule id");
        assert_eq!(ledger.len(), 1, "re-ban must not add an entry");
        // The first reason is kept; the ledger records the first offence.
        assert_eq!(
            ledger.entry(&h).map(|e| e.reason),
            Some(QuarantineReason::InvalidProof)
        );
    }

    #[test]
    fn ban_then_query() {
        let mut ledger = QuarantineLedger::new();
        let h = hash_of(3);
        assert!(!ledger.is_banned(&h));
        let rule = ledger.ban(h, QuarantineReason::NonCanonicalProgram);
        assert!(ledger.is_banned(&h));
        assert_eq!(ledger.entry(&h).map(|e| e.rule_id), Some(rule));
    }

    #[test]
    fn ledger_is_capped_and_evicts_the_oldest() {
        let mut ledger = QuarantineLedger::new();
        // Insert in order; seed 0 is the oldest entry.
        for seed in 0..(MAX_QUARANTINE_ENTRIES + 5) {
            ledger.ban(hash_of(seed), QuarantineReason::InvalidProof);
        }
        assert_eq!(ledger.len(), MAX_QUARANTINE_ENTRIES, "cap must hold");
        assert!(
            !ledger.is_banned(&hash_of(0)),
            "the oldest entry must be evicted first"
        );
        // The newest five entries must still be present.
        for seed in MAX_QUARANTINE_ENTRIES..(MAX_QUARANTINE_ENTRIES + 5) {
            assert!(ledger.is_banned(&hash_of(seed)), "seed {seed} must survive");
        }
    }

    #[test]
    fn empty_ledger_defaults() {
        let ledger = QuarantineLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert!(ledger.entry(&hash_of(9)).is_none());
    }
}
