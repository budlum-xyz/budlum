//! WIRING: unwired - staged for T-Expansion challenge-window rollout.
//! Verification levels of an AI result.
//!
//! WIRING: the AI registry records a level per finalized outcome and the
//! value-bearing doors (data market, application payments) ask
//! [`LevelRecord::may_carry_value`] once the challenge
//! window lands; until then the testnet AI layer runs at VL-1 or stays closed.
//!
//! | Level | Meaning |
//! |---|---|
//! | VL-0 | Receipt: a result was submitted. |
//! | VL-1 | A committee drawn by lottery agreed by commit and reveal. |
//! | VL-2 | The challenge window closed with no upheld challenge. |
//! | VL-3 | A full proof of the inference verified. |
//!
//! Two rules:
//!
//! * **A level only rises** (TAI8). A record never moves from VL-2 back to
//!   VL-1; an attempt to is refused, not ignored.
//! * **Refutation is a separate state.** An upheld challenge does not lower
//!   the level; it marks the result refuted, and a refuted result carries no
//!   value at any level.

use serde::{Deserialize, Serialize};

/// The four levels, ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VerificationLevel {
    Receipt,
    CommitteeAgreement,
    ChallengeWindowClosed,
    FullProof,
}

impl VerificationLevel {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Receipt => "VL-0",
            Self::CommitteeAgreement => "VL-1",
            Self::ChallengeWindowClosed => "VL-2",
            Self::FullProof => "VL-3",
        }
    }
}

/// TESTNET-DEFAULT: the lowest level at which an AI result may move value
/// (value-bearing AI use needs VL-2).
pub const MIN_LEVEL_FOR_VALUE: VerificationLevel = VerificationLevel::ChallengeWindowClosed;

/// Why a level change was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LevelRefusal {
    /// The new level is lower than the recorded one (TAI8).
    WouldLower {
        recorded: VerificationLevel,
        requested: VerificationLevel,
    },
    /// A refuted result does not rise again.
    Refuted,
}

/// The level history of one result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LevelRecord {
    level: VerificationLevel,
    refuted: bool,
}

impl Default for LevelRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl LevelRecord {
    /// A fresh record at VL-0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            level: VerificationLevel::Receipt,
            refuted: false,
        }
    }

    #[must_use]
    pub fn level(&self) -> VerificationLevel {
        self.level
    }

    /// WIRING: read by the RPC outcome view and the value doors.
    #[must_use]
    pub fn is_refuted(&self) -> bool {
        self.refuted
    }

    /// Raise the level. Raising to the current level is a no-op; lowering
    /// is refused; a refuted record does not rise.
    pub fn raise(&mut self, to: VerificationLevel) -> Result<(), LevelRefusal> {
        if self.refuted {
            return Err(LevelRefusal::Refuted);
        }
        if to < self.level {
            return Err(LevelRefusal::WouldLower {
                recorded: self.level,
                requested: to,
            });
        }
        self.level = to;
        Ok(())
    }

    /// An upheld challenge. The level stays what it was, for the record;
    /// the result carries no value from now on.
    /// WIRING: called by the challenge door when a challenge is upheld.
    pub fn refute(&mut self) {
        self.refuted = true;
    }

    /// Whether the result may move value: at least [`MIN_LEVEL_FOR_VALUE`]
    /// and not refuted.
    #[must_use]
    pub fn may_carry_value(&self) -> bool {
        !self.refuted && self.level >= MIN_LEVEL_FOR_VALUE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use VerificationLevel::{ChallengeWindowClosed, CommitteeAgreement, FullProof, Receipt};

    /// TAI8: the level does not drop; refutation is a separate state.
    #[test]
    fn tai8_level_only_rises_and_refutation_is_separate() {
        let mut r = LevelRecord::new();
        assert_eq!(r.level(), Receipt);
        r.raise(CommitteeAgreement).unwrap();
        r.raise(ChallengeWindowClosed).unwrap();
        assert_eq!(
            r.raise(CommitteeAgreement),
            Err(LevelRefusal::WouldLower {
                recorded: ChallengeWindowClosed,
                requested: CommitteeAgreement
            })
        );
        assert_eq!(r.level(), ChallengeWindowClosed);
        r.raise(ChallengeWindowClosed).unwrap();

        r.refute();
        assert!(r.is_refuted());
        assert_eq!(
            r.level(),
            ChallengeWindowClosed,
            "refutation keeps the level"
        );
        assert_eq!(r.raise(FullProof), Err(LevelRefusal::Refuted));
    }

    #[test]
    fn value_needs_vl2_and_no_refutation() {
        let mut r = LevelRecord::new();
        assert!(!r.may_carry_value());
        r.raise(CommitteeAgreement).unwrap();
        assert!(!r.may_carry_value(), "VL-1 does not move value");
        r.raise(ChallengeWindowClosed).unwrap();
        assert!(r.may_carry_value());
        r.raise(FullProof).unwrap();
        assert!(r.may_carry_value());
        r.refute();
        assert!(!r.may_carry_value());
    }

    #[test]
    fn labels_are_the_canonical_names() {
        let labels: Vec<_> = [
            Receipt,
            CommitteeAgreement,
            ChallengeWindowClosed,
            FullProof,
        ]
        .iter()
        .map(VerificationLevel::label)
        .collect();
        assert_eq!(labels, ["VL-0", "VL-1", "VL-2", "VL-3"]);
    }
}
