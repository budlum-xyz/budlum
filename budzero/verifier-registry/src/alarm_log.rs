//! Chained alarm log (K3 of the BudZero regeneration design).
//!
//! A relay report is single and signed; the chained log turns the warnings
//! into an un-erasable sequence. Every entry commits to the previous entry's
//! link, so a deleted, reordered, or duplicated alarm breaks the chain and a
//! verifier recomputes the links in one pass ([`AlarmLog::verify_integrity`]).
//! The same signed report can only ever produce one entry (replay is refused
//! the way a duplicate ban is in the quarantine ledger).
//!
//! Bounded, not unbounded: the log is capped at [`MAX_ALARM_LOG_ENTRIES`].
//! When the oldest entry is dropped the log advances its
//! [`AlarmLog::window_anchor`] to that entry's link, so the retained window
//! still verifies exactly - the "un-erasable" guarantee holds for the
//! retained window, and the full-history guarantee is recovered by pinning
//! [`AlarmLog::root`] into signed state (the same wiring the quarantine
//! ledger expects). The `report_sig` fields carried here are already-signed
//! relay artifacts; this log is their tamper-evident container, it does not
//! re-verify them.

use sha2::{Digest, Sha256};

/// Domain separator for alarm-chain links.
pub const ALARM_LOG_DOMAIN: &[u8] = b"BDLM_BUDZERO_ALARMLOG_V1";

/// Hard cap on retained entries; the oldest is dropped beyond it.
pub const MAX_ALARM_LOG_ENTRIES: usize = 4096;

/// Stored detail is truncated to this many characters.
pub const MAX_ALARM_DETAIL_LEN: usize = 256;

/// Why a proof alarmed. Mirrors the relay's alarm codes in a form the
/// verifier-registry can store without depending on the proof crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmKind {
    NonCanonicalProgram,
    InvalidProof,
    PublicInputsMismatch,
    InvalidEnvelope,
    DeserializationError,
    TransferViolation,
}

impl AlarmKind {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::NonCanonicalProgram => 0,
            Self::InvalidProof => 1,
            Self::PublicInputsMismatch => 2,
            Self::InvalidEnvelope => 3,
            Self::DeserializationError => 4,
            Self::TransferViolation => 5,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonCanonicalProgram => "non_canonical_program",
            Self::InvalidProof => "invalid_proof",
            Self::PublicInputsMismatch => "public_inputs_mismatch",
            Self::InvalidEnvelope => "invalid_envelope",
            Self::DeserializationError => "deserialization_error",
            Self::TransferViolation => "transfer_violation",
        }
    }
}

/// The chain's genesis link: the domain digest. No alarm ever has this link.
#[must_use]
pub fn genesis_link() -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(ALARM_LOG_DOMAIN);
    hasher.finalize().into()
}

/// One alarm in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmEntry {
    pub seq: u64,
    pub kind: AlarmKind,
    pub detail: String,
    /// The signed relay report the alarm was derived from.
    pub report_sig: [u8; 32],
    /// The hash-chain link: commits to the previous link, this report, the
    /// kind, the detail, and the sequence number.
    pub link: [u8; 32],
    pub prev_link: [u8; 32],
}

/// The chained alarm log. `Default` gives an empty log at the genesis link.
#[derive(Debug, Clone, Default)]
pub struct AlarmLog {
    entries: Vec<AlarmEntry>,
    /// The latest link, or `None` when the log is empty.
    head: Option<[u8; 32]>,
    /// The link the retained window starts from: genesis until the first
    /// eviction, then the last evicted entry's link.
    window_anchor: [u8; 32],
    next_seq: u64,
}

impl AlarmLog {
    #[must_use]
    pub fn new() -> Self {
        Self {
            window_anchor: genesis_link(),
            ..Self::default()
        }
    }

    /// The link for an alarm that follows `prev`. Pure: no log state, so a
    /// verifier recomputes it without trusting the log.
    #[must_use]
    pub fn link_of(
        prev: &[u8; 32],
        report_sig: &[u8; 32],
        kind: AlarmKind,
        detail: &str,
        seq: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::default();
        hasher.update(ALARM_LOG_DOMAIN);
        hasher.update(prev);
        hasher.update(report_sig);
        hasher.update([kind.as_byte()]);
        hasher.update(detail.as_bytes());
        hasher.update(seq.to_le_bytes());
        hasher.finalize().into()
    }

    /// Record an alarm and return its link. Idempotent: recording the same
    /// report signature twice returns the existing entry's link and appends
    /// nothing, so an alarm cannot be duplicated.
    pub fn record(&mut self, report_sig: [u8; 32], kind: AlarmKind, detail: &str) -> [u8; 32] {
        if let Some(entry) = self.entries.iter().find(|e| e.report_sig == report_sig) {
            return entry.link;
        }
        let detail: String = detail.chars().take(MAX_ALARM_DETAIL_LEN).collect();
        self.evict_if_needed();
        let prev = self.head.unwrap_or(self.window_anchor);
        let link = Self::link_of(&prev, &report_sig, kind, &detail, self.next_seq);
        self.entries.push(AlarmEntry {
            seq: self.next_seq,
            kind,
            detail,
            report_sig,
            link,
            prev_link: prev,
        });
        self.head = Some(link);
        self.next_seq = self.next_seq.wrapping_add(1);
        link
    }

    /// Walk the chain and recompute every link: `true` only when the retained
    /// window is contiguous from the window anchor and no entry was altered.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let mut expected_prev = self.window_anchor;
        let mut prev_seq: Option<u64> = None;
        for entry in &self.entries {
            if entry.prev_link != expected_prev {
                return false;
            }
            if let Some(seen) = prev_seq {
                if entry.seq <= seen {
                    return false;
                }
            }
            let link = Self::link_of(
                &entry.prev_link,
                &entry.report_sig,
                entry.kind,
                &entry.detail,
                entry.seq,
            );
            if link != entry.link {
                return false;
            }
            expected_prev = entry.link;
            prev_seq = Some(entry.seq);
        }
        true
    }

    /// The log's root: a single digest over the window anchor, the head, and
    /// the retained length. Pin this into signed state to make local
    /// rewriting of the history detectable from outside the node.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::default();
        hasher.update(ALARM_LOG_DOMAIN);
        hasher.update(self.window_anchor);
        hasher.update(self.head.unwrap_or(self.window_anchor));
        hasher.update((self.entries.len() as u64).to_le_bytes());
        hasher.finalize().into()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn head(&self) -> Option<[u8; 32]> {
        self.head
    }

    #[must_use]
    pub fn window_anchor(&self) -> [u8; 32] {
        self.window_anchor
    }

    pub fn iter(&self) -> impl Iterator<Item = &AlarmEntry> {
        self.entries.iter()
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() >= MAX_ALARM_LOG_ENTRIES {
            let Some(oldest) = self.entries.first().cloned() else {
                break;
            };
            self.entries.remove(0);
            // The window now starts at the dropped entry's link, so the
            // retained chain stays verifiable from the new anchor.
            self.window_anchor = oldest.link;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig_of(seed: usize) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&(seed as u64).to_le_bytes());
        s
    }

    #[test]
    fn chain_is_contiguous_and_verifiable() {
        let mut log = AlarmLog::new();
        let a = log.record(sig_of(1), AlarmKind::InvalidProof, "first");
        let b = log.record(sig_of(2), AlarmKind::TransferViolation, "second");
        let c = log.record(sig_of(3), AlarmKind::NonCanonicalProgram, "third");
        assert!(log.verify_integrity());
        assert_eq!(log.len(), 3);
        assert_eq!(log.head(), Some(c));
        assert_eq!(log.iter().next().map(|e| e.prev_link), Some(genesis_link()));
        assert_eq!(log.iter().nth(1).map(|e| e.prev_link), Some(a));
        assert_eq!(log.iter().nth(2).map(|e| e.prev_link), Some(b));
        assert_eq!(
            log.iter().map(|e| e.link).collect::<Vec<_>>(),
            vec![a, b, c]
        );
        assert_ne!(a, b, "distinct alarms give distinct links");
    }

    #[test]
    fn record_is_idempotent_on_the_same_report() {
        let mut log = AlarmLog::new();
        let first = log.record(sig_of(9), AlarmKind::InvalidProof, "again");
        let second = log.record(sig_of(9), AlarmKind::TransferViolation, "ignored");
        assert_eq!(first, second, "replay returns the existing link");
        assert_eq!(log.len(), 1, "replay must not append");
        assert_eq!(
            log.iter().next().map(|e| e.kind),
            Some(AlarmKind::InvalidProof)
        );
    }

    #[test]
    fn tampering_or_reordering_breaks_integrity() {
        let mut log = AlarmLog::new();
        log.record(sig_of(1), AlarmKind::InvalidProof, "one");
        log.record(sig_of(2), AlarmKind::InvalidProof, "two");
        log.record(sig_of(3), AlarmKind::InvalidProof, "three");
        assert!(log.verify_integrity());

        // A flipped detail byte must break the link recomputation.
        let mut altered = log.clone();
        altered.entries[1].detail.push('x');
        assert!(
            !altered.verify_integrity(),
            "altered detail must break the chain"
        );

        // A reorder must break contiguity.
        let mut reordered = log.clone();
        reordered.entries.swap(0, 2);
        assert!(
            !reordered.verify_integrity(),
            "reorder must break the chain"
        );
    }

    #[test]
    fn log_is_capped_and_evicts_with_a_window_anchor() {
        let mut log = AlarmLog::new();
        for seed in 0..(MAX_ALARM_LOG_ENTRIES + 5) {
            log.record(sig_of(seed), AlarmKind::InvalidProof, "bulk");
        }
        assert_eq!(log.len(), MAX_ALARM_LOG_ENTRIES, "cap must hold");
        assert!(
            log.verify_integrity(),
            "the retained window must stay verifiable after eviction"
        );
        // The window anchor is the dropped entry's link, and the first
        // retained entry continues from it.
        assert_eq!(
            log.entries.first().map(|e| e.prev_link),
            Some(log.window_anchor)
        );
        assert_ne!(
            log.window_anchor(),
            genesis_link(),
            "eviction advanced the anchor"
        );
        assert_eq!(
            log.entries.first().map(|e| e.seq),
            Some(5),
            "oldest five evicted"
        );
    }

    #[test]
    fn root_is_stable_and_changes_with_content() {
        let mut log = AlarmLog::new();
        let empty_root = log.root();
        assert_eq!(log.window_anchor(), genesis_link());
        log.record(sig_of(1), AlarmKind::InvalidProof, "hello");
        assert_ne!(log.root(), empty_root, "root moves when content is added");
        let one_root = log.root();
        log.record(sig_of(2), AlarmKind::TransferViolation, "world");
        assert_ne!(log.root(), one_root, "root moves again");
    }

    #[test]
    fn detail_is_truncated_to_the_bound() {
        let mut log = AlarmLog::new();
        let long = "x".repeat(MAX_ALARM_DETAIL_LEN + 64);
        log.record(sig_of(5), AlarmKind::InvalidProof, &long);
        assert_eq!(
            log.iter().next().map(|e| e.detail.len()),
            Some(MAX_ALARM_DETAIL_LEN),
            "detail must be truncated"
        );
        assert!(log.verify_integrity(), "the truncated detail must verify");
    }
}
