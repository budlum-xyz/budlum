//! The validator class and the per-class parameters both sides read.
//!
//! `ValidatorClass` moved here verbatim from `src/validators/mod.rs` (directive
//! section 7.2); the node re-exports it, so every existing path keeps working.
//! It moved because the mobile core has to put the class tag into the presence
//! message it signs (section 7.8) and pick its audit deadline from the class,
//! and it must not link the node to do so (section 7.9.5). A second enum on the
//! phone would agree with the node on every input until somebody reordered a
//! variant.
//!
//! The per-class windows below are written in hours where the directive writes
//! them in hours, and converted to epochs with section 6.21.3's formula, so no
//! consensus decision reads a wall clock (G-2, section 6.21.3 item 1).

use serde::{Deserialize, Serialize};

/// The custody quota ceiling of an iOS opportunistic validator: 8 GiB.
pub const MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Invalid consensus timing parameters or an unrepresentable epoch count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassParameterError {
    /// A zero-duration slot has no defined epoch cadence.
    ZeroSlotDuration,
    /// A zero-length epoch has no defined epoch cadence.
    ZeroEpochLength,
    /// The exact ceiling does not fit the consensus epoch integer.
    EpochOverflow,
}

impl std::fmt::Display for ClassParameterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::ZeroSlotDuration => "the slot duration is zero",
            Self::ZeroEpochLength => "the epoch length is zero",
            Self::EpochOverflow => "the epoch count exceeds u64",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ClassParameterError {}

/// The class of a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ValidatorClass {
    /// Runs every block, proposes, holds a finality seat.
    Full,
    /// A phone: stores content, answers audits, holds no seat.
    Mobile,
    /// An iPhone: the same duties, only while the app is open or charging.
    MobileOpportunistic,
}

impl ValidatorClass {
    /// Whether the class holds a consensus seat.
    #[must_use]
    pub const fn holds_seat(self) -> bool {
        matches!(self, Self::Full)
    }

    /// The byte written into signing preimages and the directory root.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Mobile => 1,
            Self::MobileOpportunistic => 2,
        }
    }

    /// The class a tag names, or `None` for a byte no class writes.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Full),
            1 => Some(Self::Mobile),
            2 => Some(Self::MobileOpportunistic),
            _ => None,
        }
    }

    /// The presence window, in epochs (section 7.8 item 1): one epoch for a
    /// Full validator, four for both phone classes (ten minutes on testnet).
    #[must_use]
    pub const fn presence_window_epochs(self) -> u64 {
        match self {
            Self::Full => 1,
            Self::Mobile | Self::MobileOpportunistic => 4,
        }
    }

    /// How long a validator may stay unseen before it is suspended (section
    /// 7.2): one day, 72 hours, seven days. Suspension is not a slash (V-4).
    #[must_use]
    pub const fn suspension_hours(self) -> u64 {
        match self {
            Self::Full => 24,
            Self::Mobile => 72,
            Self::MobileOpportunistic => 168,
        }
    }

    /// The suspension threshold in epochs (section 6.21.3).
    #[must_use]
    pub fn suspension_threshold_epochs(
        self,
        slot_ms: u64,
        epoch_len: u64,
    ) -> Result<u64, ClassParameterError> {
        hours_to_epochs(self.suspension_hours(), slot_ms, epoch_len)
    }

    /// The custody audit answer window (section 7.2): two epochs for a Full
    /// validator, 24 hours for an Android phone, 48 hours for an iPhone.
    #[must_use]
    pub const fn audit_window(self) -> AuditWindow {
        match self {
            Self::Full => AuditWindow::Epochs(2),
            Self::Mobile => AuditWindow::Hours(24),
            Self::MobileOpportunistic => AuditWindow::Hours(48),
        }
    }

    /// The audit answer window in epochs (section 6.21.3).
    #[must_use]
    pub fn audit_window_epochs(
        self,
        slot_ms: u64,
        epoch_len: u64,
    ) -> Result<u64, ClassParameterError> {
        validate_epoch_parameters(slot_ms, epoch_len)?;
        match self.audit_window() {
            AuditWindow::Epochs(epochs) => Ok(epochs),
            AuditWindow::Hours(hours) => hours_to_epochs(hours, slot_ms, epoch_len),
        }
    }

    /// The largest custody quota the class may declare, if the class has a
    /// ceiling. Only the iOS opportunistic class has one in consensus; the
    /// Android range of 1 to 64 GiB is the app's quota manager, not a chain
    /// rule.
    #[must_use]
    pub const fn max_custody_quota_bytes(self) -> Option<u64> {
        match self {
            Self::MobileOpportunistic => Some(MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES),
            Self::Full | Self::Mobile => None,
        }
    }
}

/// How the directive states an audit window: Full validators in epochs,
/// phones in hours (section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditWindow {
    Epochs(u64),
    Hours(u64),
}

/// Convert a window written in hours to epochs:
/// `ceil(hours * 3600 / (slot * epoch length))` (section 6.21.3 item 2).
///
/// `slot_ms` is the slot in milliseconds, as the node's consensus parameters
/// carry it, so the division is exact for every profile. Integer arithmetic
/// only (G-2). Invalid zero parameters and an unrepresentable result are
/// errors; silently substituting one would invent a consensus schedule.
///
/// # Errors
///
/// [`ClassParameterError`] identifies the invalid input or overflow.
pub fn hours_to_epochs(
    hours: u64,
    slot_ms: u64,
    epoch_len: u64,
) -> Result<u64, ClassParameterError> {
    validate_epoch_parameters(slot_ms, epoch_len)?;
    let epoch_ms = u128::from(slot_ms) * u128::from(epoch_len);
    let window_ms = u128::from(hours) * 3_600_000;
    let epochs = window_ms.div_ceil(epoch_ms);
    u64::try_from(epochs).map_err(|_| ClassParameterError::EpochOverflow)
}

fn validate_epoch_parameters(slot_ms: u64, epoch_len: u64) -> Result<(), ClassParameterError> {
    if slot_ms == 0 {
        return Err(ClassParameterError::ZeroSlotDuration);
    }
    if epoch_len == 0 {
        return Err(ClassParameterError::ZeroEpochLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{hours_to_epochs, AuditWindow, ClassParameterError, ValidatorClass};

    /// Testnet profile: 3 s slots, 50-slot epochs (`src/core/chain_config.rs`).
    const SLOT_MS: u64 = 3_000;
    const EPOCH_LEN: u64 = 50;

    /// The tags are wire bytes: they enter the presence message and the
    /// directory root, so they may never be renumbered.
    #[test]
    fn class_tags_are_fixed_wire_bytes() {
        assert_eq!(ValidatorClass::Full.tag(), 0);
        assert_eq!(ValidatorClass::Mobile.tag(), 1);
        assert_eq!(ValidatorClass::MobileOpportunistic.tag(), 2);
        for class in [
            ValidatorClass::Full,
            ValidatorClass::Mobile,
            ValidatorClass::MobileOpportunistic,
        ] {
            assert_eq!(ValidatorClass::from_tag(class.tag()), Some(class));
        }
        assert_eq!(ValidatorClass::from_tag(3), None);
    }

    #[test]
    fn only_full_holds_a_seat() {
        assert!(ValidatorClass::Full.holds_seat());
        assert!(!ValidatorClass::Mobile.holds_seat());
        assert!(!ValidatorClass::MobileOpportunistic.holds_seat());
    }

    /// Section 7.8 item 1: the Mobile window is four epochs, ten minutes on
    /// testnet.
    #[test]
    fn mobile_presence_window_is_ten_minutes_on_testnet() {
        let epochs = ValidatorClass::Mobile.presence_window_epochs();
        assert_eq!(epochs, 4);
        assert_eq!(epochs * SLOT_MS * EPOCH_LEN, 10 * 60 * 1_000);
        assert_eq!(ValidatorClass::Full.presence_window_epochs(), 1);
    }

    /// Section 7.2 thresholds, converted on the testnet profile.
    #[test]
    fn suspension_thresholds_follow_section_7_2() {
        assert_eq!(
            ValidatorClass::Full.suspension_threshold_epochs(SLOT_MS, EPOCH_LEN),
            Ok(576)
        );
        assert_eq!(
            ValidatorClass::Mobile.suspension_threshold_epochs(SLOT_MS, EPOCH_LEN),
            Ok(1_728)
        );
        assert_eq!(
            ValidatorClass::MobileOpportunistic.suspension_threshold_epochs(SLOT_MS, EPOCH_LEN),
            Ok(4_032)
        );
    }

    #[test]
    fn audit_windows_follow_section_7_2() {
        assert_eq!(ValidatorClass::Full.audit_window(), AuditWindow::Epochs(2));
        assert_eq!(
            ValidatorClass::Full.audit_window_epochs(SLOT_MS, EPOCH_LEN),
            Ok(2)
        );
        assert_eq!(
            ValidatorClass::Mobile.audit_window_epochs(SLOT_MS, EPOCH_LEN),
            Ok(576)
        );
        assert_eq!(
            ValidatorClass::MobileOpportunistic.audit_window_epochs(SLOT_MS, EPOCH_LEN),
            Ok(1_152)
        );
    }

    /// The conversion rounds up: a window never ends before its hours.
    #[test]
    fn hours_to_epochs_rounds_up_and_refuses_invalid_schedules() {
        assert_eq!(hours_to_epochs(1, 7_000, 50), Ok(11));
        assert_eq!(hours_to_epochs(0, SLOT_MS, EPOCH_LEN), Ok(0));
        assert_eq!(
            hours_to_epochs(1, 0, EPOCH_LEN),
            Err(ClassParameterError::ZeroSlotDuration)
        );
        assert_eq!(
            hours_to_epochs(1, SLOT_MS, 0),
            Err(ClassParameterError::ZeroEpochLength)
        );
        assert_eq!(
            hours_to_epochs(u64::MAX, 1, 1),
            Err(ClassParameterError::EpochOverflow)
        );
        assert_eq!(
            ValidatorClass::Full.audit_window_epochs(0, EPOCH_LEN),
            Err(ClassParameterError::ZeroSlotDuration)
        );
        assert_eq!(
            ValidatorClass::Full.audit_window_epochs(SLOT_MS, 0),
            Err(ClassParameterError::ZeroEpochLength)
        );
    }

    #[test]
    fn only_the_ios_class_has_a_consensus_quota_ceiling() {
        assert_eq!(
            ValidatorClass::MobileOpportunistic.max_custody_quota_bytes(),
            Some(8 * 1024 * 1024 * 1024)
        );
        assert_eq!(ValidatorClass::Mobile.max_custody_quota_bytes(), None);
        assert_eq!(ValidatorClass::Full.max_custody_quota_bytes(), None);
    }
}
