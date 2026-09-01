//! The closed-circuit source check.
//!
//! The principle: the source kinds the AI inference layer can read form a closed set (a Pollen
//! grant, a B.U.D. StorageDeal, or SocialFi). The permission **rules** are
//! queried from the chain and are not copied here (the K3 decision; the "the
//! second copy is the worst copy" principle from budlum).

use ai_inference_core::dataset::{SourceKind, SourceRef};

/// Data layer errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataError {
    /// A source kind outside the closed circuit (an unknown byte value).
    NotClosedLoop { found: u8 },
    /// The source is inside the closed circuit but is not the expected
    /// kind.
    UnexpectedSource {
        expected: SourceKind,
        got: SourceKind,
    },
    /// The SHA-256 verification failed - no data flows.
    HashMismatch { detail: String },
}

/// Verify that the source is one of the three closed-circuit channels.
///
/// # Errors
///
/// `NotClosedLoop` when the source kind is not one of the three channels.
pub fn assert_closed_loop(source: &SourceRef) -> Result<(), DataError> {
    match source.kind {
        SourceKind::PollenGrant | SourceKind::StorageDeal | SourceKind::SocialRef => Ok(()),
    }
}

/// Interpret the raw (byte) source kind and refuse unknown values.
///
/// # Errors
///
/// `NotClosedLoop` when `raw_kind` is outside 0..=2.
pub fn reject_unknown_source(raw_kind: u8) -> Result<SourceKind, DataError> {
    match raw_kind {
        0 => Ok(SourceKind::PollenGrant),
        1 => Ok(SourceKind::StorageDeal),
        2 => Ok(SourceKind::SocialRef),
        other => Err(DataError::NotClosedLoop { found: other }),
    }
}

/// Require the source to be a specific closed-circuit kind (for example a
/// training plan may accept only sets sourced from a `StorageDeal`).
///
/// # Errors
///
/// `UnexpectedSource` when the kind does not match.
pub fn require_source(source: &SourceRef, expected: SourceKind) -> Result<(), DataError> {
    assert_closed_loop(source)?;
    if source.kind == expected {
        Ok(())
    } else {
        Err(DataError::UnexpectedSource {
            expected,
            got: source.kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_closed_loop_kinds_pass() {
        assert!(assert_closed_loop(&SourceRef::pollen_grant([1; 32], 2)).is_ok());
        assert!(assert_closed_loop(&SourceRef::storage_deal([1; 32])).is_ok());
        assert!(assert_closed_loop(&SourceRef::social([1; 32])).is_ok());
    }

    #[test]
    fn unknown_raw_source_is_rejected() {
        assert_eq!(reject_unknown_source(0), Ok(SourceKind::PollenGrant));
        assert_eq!(
            reject_unknown_source(3),
            Err(DataError::NotClosedLoop { found: 3 })
        );
        assert_eq!(
            reject_unknown_source(255),
            Err(DataError::NotClosedLoop { found: 255 })
        );
    }

    #[test]
    fn require_source_enforces_exact_kind() {
        let grant = SourceRef::pollen_grant([1; 32], 1);
        assert!(require_source(&grant, SourceKind::PollenGrant).is_ok());
        assert_eq!(
            require_source(&grant, SourceKind::StorageDeal),
            Err(DataError::UnexpectedSource {
                expected: SourceKind::StorageDeal,
                got: SourceKind::PollenGrant
            })
        );
    }
}
