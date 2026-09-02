//! Transfer decision-vector extraction (K1 of the BudZero regeneration design).
//!
//! The canonical private-transfer program logs exactly two verdicts, in
//! order: conservation (Σinputs == Σoutputs) and the nullifier derivation
//! check. A proof is a STARK soundness claim; neither it nor the relay's
//! canonical-set check answers "did the transfer obey the law?" - a proof for
//! the canonical program can still carry a conservation flag of 0 if the
//! program was run over values that broke Σin == Σout. That is the semantic
//! gap this module names and closes on the decision side: the relay extracts
//! the flags from the events the program logged and turns a conservation of
//! anything but 1 into a hard violation, independent of proof validity.
//!
//! The nullifier flag is reported but *not* judged here: whether a derived
//! nullifier was already spent is the L1 note registry's question (S1), which
//! is a consensus-surface decision, not a shape check. Splitting the two keeps
//! this module pure - no state access, no set lookup - so every node derives
//! the same verdict from the same events.

/// The number of events the canonical transfer program logs. Any other event
/// shape is not the canonical transfer program and must not be read as one.
const CANONICAL_TRANSFER_EVENT_COUNT: usize = 2;

/// The two flags the canonical transfer program logs, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransferFlags {
    /// Σinputs == Σoutputs. The law of the transfer; must be exactly 1.
    pub conservation: u64,
    /// Derived-nullifier == claimed-nullifier. Reported, not judged here.
    pub nullifier: u64,
}

impl TransferFlags {
    /// Parse the canonical transfer events. Returns `None` when the event
    /// count is not [`CANONICAL_TRANSFER_EVENT_COUNT`], so a different
    /// program's log can never be misread as a transfer verdict.
    #[must_use]
    fn extract(events: &[u64]) -> Option<Self> {
        if events.len() != CANONICAL_TRANSFER_EVENT_COUNT {
            return None;
        }
        Some(Self {
            conservation: events[0],
            nullifier: events[1],
        })
    }
}

/// The verdict a relay derives from a transfer program's logged events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferVerdict {
    /// The event shape is not the canonical transfer program.
    NotCanonicalTransfer,
    /// The transfer broke conservation (S2). Refuse and alarm, regardless of
    /// whether the STARK proof itself verified.
    ConservationViolation { conservation: u64 },
    /// Conservation holds. The nullifier flag travels with the verdict; its
    /// spent-status is the L1 registry's question (S1).
    ConservationHolds { nullifier: u64 },
}

/// Derive the transfer verdict from the events the program logged.
#[must_use]
pub fn verdict_of(events: &[u64]) -> TransferVerdict {
    match TransferFlags::extract(events) {
        None => TransferVerdict::NotCanonicalTransfer,
        Some(flags) if flags.conservation == 1 => TransferVerdict::ConservationHolds {
            nullifier: flags.nullifier,
        },
        Some(flags) => TransferVerdict::ConservationViolation {
            conservation: flags.conservation,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_shape_extracts_both_flags() {
        assert_eq!(
            TransferFlags::extract(&[1, 0]),
            Some(TransferFlags {
                conservation: 1,
                nullifier: 0
            })
        );
    }

    #[test]
    fn wrong_event_count_is_not_a_transfer() {
        assert_eq!(TransferFlags::extract(&[]), None);
        assert_eq!(TransferFlags::extract(&[1]), None);
        assert_eq!(TransferFlags::extract(&[1, 0, 1]), None);
    }

    #[test]
    fn conservation_of_one_holds() {
        assert_eq!(
            verdict_of(&[1, 0]),
            TransferVerdict::ConservationHolds { nullifier: 0 }
        );
        assert_eq!(
            verdict_of(&[1, 1]),
            TransferVerdict::ConservationHolds { nullifier: 1 }
        );
    }

    #[test]
    fn conservation_of_anything_else_is_a_violation() {
        assert_eq!(
            verdict_of(&[0, 0]),
            TransferVerdict::ConservationViolation { conservation: 0 }
        );
        assert_eq!(
            verdict_of(&[5, 0]),
            TransferVerdict::ConservationViolation { conservation: 5 }
        );
        // A field-wrapped negative is also not 1.
        assert_eq!(
            verdict_of(&[u64::MAX, 0]),
            TransferVerdict::ConservationViolation {
                conservation: u64::MAX
            }
        );
    }

    #[test]
    fn non_transfer_shape_is_named() {
        assert_eq!(verdict_of(&[]), TransferVerdict::NotCanonicalTransfer);
        assert_eq!(
            verdict_of(&[1, 0, 0]),
            TransferVerdict::NotCanonicalTransfer
        );
    }
}
