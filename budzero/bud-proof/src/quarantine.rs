//! Derived quarantine ledger ( of the BudZero regeneration design).
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
const QUARANTINE_DOMAIN: &[u8] = b"BDLM_BUDZERO_QUARANTINE_V1";

/// Hard cap on ledger entries; the oldest entry is dropped beyond it.
const MAX_QUARANTINE_ENTRIES: usize = 4096;

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

    /// Inverse of [`Self::as_byte`]; `None` for an unknown byte.
    #[must_use]
    ///
    /// Convenience: the decoding half of the byte form, kept beside
    /// `as_byte` so the pair cannot drift; a stored-record reader is the
    /// caller, and the round-trip is pinned by this module's tests.
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::NonCanonicalProgram),
            1 => Some(Self::TransferViolation),
            2 => Some(Self::InvalidProof),
            3 => Some(Self::PublicInputsMismatch),
            _ => None,
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
    fn derive_rule_id(program_hash: &[u8; 32]) -> [u8; 32] {
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

    /// One line per entry, oldest first: `<program hash hex> <reason byte>`.
    /// Replaying the lines through [`Self::from_text`] rebuilds the same
    /// ledger, rule ids included, because the rule id is derived.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut rows: Vec<&QuarantineEntry> = self.entries.values().collect();
        rows.sort_by_key(|e| e.seq);
        let mut out = String::new();
        for e in rows {
            for byte in e.program_hash {
                out.push_str(&format!("{byte:02x}"));
            }
            out.push(' ');
            out.push_str(&e.reason.as_byte().to_string());
            out.push('\n');
        }
        out
    }

    /// Parse the text written by [`Self::to_text`]. A malformed line is an
    /// error: a ledger that silently dropped a ban would lift it.
    pub fn from_text(text: &str) -> Result<Self, String> {
        let mut ledger = Self::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let bad = || format!("quarantine line {} is malformed", index + 1);
            let (hash_hex, reason_text) = line.split_once(' ').ok_or_else(bad)?;
            if hash_hex.len() != 64 || !hash_hex.is_ascii() {
                return Err(bad());
            }
            let mut program_hash = [0u8; 32];
            for (slot, pair) in program_hash.iter_mut().zip(hash_hex.as_bytes().chunks(2)) {
                let digits = std::str::from_utf8(pair).map_err(|_| bad())?;
                *slot = u8::from_str_radix(digits, 16).map_err(|_| bad())?;
            }
            let reason_byte: u8 = reason_text.trim().parse().map_err(|_| bad())?;
            let reason = QuarantineReason::from_byte(reason_byte).ok_or_else(bad)?;
            ledger.ban(program_hash, reason);
        }
        Ok(ledger)
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
    fn text_round_trip_keeps_every_ban() {
        let mut ledger = QuarantineLedger::new();
        ledger.ban(hash_of(1), QuarantineReason::InvalidProof);
        ledger.ban(hash_of(2), QuarantineReason::TransferViolation);
        let restored = QuarantineLedger::from_text(&ledger.to_text()).unwrap();
        assert_eq!(restored.len(), 2);
        assert!(restored.is_banned(&hash_of(1)));
        assert_eq!(
            restored.entry(&hash_of(2)).map(|e| e.reason),
            Some(QuarantineReason::TransferViolation)
        );
        assert!(QuarantineLedger::from_text("zz 1\n").is_err());
        assert!(QuarantineLedger::from_text(&format!("{} 9\n", "00".repeat(32))).is_err());
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
